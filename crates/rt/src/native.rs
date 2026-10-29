use std::cell::RefCell;
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Waker;
use std::time::{self, Duration, SystemTime};

#[cfg(target_os = "linux")]
use sys::uring::{Done, Request, Ring};
use sys::{Event, Poller};

use crate::driver::{Completion, Driver, Handle, Op, OpId, OpenOptions, Stat, Unpark};
use crate::time::Instant;

#[cfg(target_os = "linux")]
const RING_ENTRIES: u32 = 256;
#[cfg(target_os = "linux")]
const RING_TOKEN: usize = usize::MAX;

enum Resource {
    File(Rc<fs::File>),
    Listener(TcpListener),
    Stream(TcpStream),
    Udp(UdpSocket),
}

enum Step {
    Run(Op),
    Connect(Handle, TcpStream),
}

struct Pending {
    step: Step,
    waker: Waker,
}

#[derive(Default)]
struct State {
    next_handle: u64,
    next_op: u64,
    resources: BTreeMap<Handle, Resource>,
    pending: BTreeMap<OpId, Pending>,
    done: BTreeMap<OpId, Completion>,
    events: Vec<Event>,
    #[cfg(target_os = "linux")]
    ring: Option<Ring>,
    #[cfg(target_os = "linux")]
    waiting: BTreeMap<OpId, Waker>,
    #[cfg(target_os = "linux")]
    backlog: VecDeque<(u64, Request)>,
    #[cfg(target_os = "linux")]
    finished: Vec<Done>,
}

pub struct Native {
    poller: Arc<Poller>,
    start: time::Instant,
    state: RefCell<State>,
}

struct Wake(Arc<Poller>);

impl Unpark for Wake {
    fn unpark(&self) {
        let _ = self.0.wake();
    }
}

fn bad_handle() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "unknown handle")
}

fn blocked(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn open(path: &Path, options: &OpenOptions) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(options.read)
        .write(options.write)
        .create(options.create)
        .create_new(options.create_new)
        .truncate(options.truncate)
        .open(path)
}

impl Native {
    pub fn new() -> io::Result<Self> {
        let native = Self::plain()?;
        #[cfg(target_os = "linux")]
        if let Ok(ring) = Ring::new(RING_ENTRIES) {
            native.poller.watch(ring.event(), RING_TOKEN)?;
            native.state.borrow_mut().ring = Some(ring);
        }
        Ok(native)
    }

    pub fn plain() -> io::Result<Self> {
        Ok(Self {
            poller: Arc::new(Poller::new()?),
            start: time::Instant::now(),
            state: RefCell::new(State::default()),
        })
    }

    pub fn uses_ring(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.state.borrow().ring.is_some();
        #[cfg(not(target_os = "linux"))]
        false
    }
}

impl State {
    fn add(&mut self, poller: &Poller, resource: Resource) -> io::Result<Handle> {
        self.next_handle += 1;
        let handle = Handle(self.next_handle);
        let token = usize::try_from(handle.0).expect("handle fits in usize");
        match &resource {
            Resource::File(_) => {}
            Resource::Listener(s) => poller.watch(s.as_fd(), token)?,
            Resource::Stream(s) => poller.watch(s.as_fd(), token)?,
            Resource::Udp(s) => poller.watch(s.as_fd(), token)?,
        }
        self.resources.insert(handle, resource);
        Ok(handle)
    }

    fn file(&self, handle: Handle) -> io::Result<&fs::File> {
        match self.resources.get(&handle) {
            Some(Resource::File(f)) => Ok(f.as_ref()),
            _ => Err(bad_handle()),
        }
    }

    fn stream(&self, handle: Handle) -> io::Result<&TcpStream> {
        match self.resources.get(&handle) {
            Some(Resource::Stream(s)) => Ok(s),
            _ => Err(bad_handle()),
        }
    }

    fn udp(&self, handle: Handle) -> io::Result<&UdpSocket> {
        match self.resources.get(&handle) {
            Some(Resource::Udp(s)) => Ok(s),
            _ => Err(bad_handle()),
        }
    }

    fn step(&mut self, poller: &Poller, step: Step) -> Result<Completion, Step> {
        match step {
            Step::Run(op) => self.run(poller, op),
            Step::Connect(handle, stream) => match stream.take_error() {
                Ok(None) => match stream.peer_addr() {
                    Ok(_) => {
                        self.resources.insert(handle, Resource::Stream(stream));
                        Ok(Completion::Handle(Ok(handle)))
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                        Err(Step::Connect(handle, stream))
                    }
                    Err(e) => Ok(Completion::Handle(Err(e))),
                },
                Ok(Some(e)) | Err(e) => Ok(Completion::Handle(Err(e))),
            },
        }
    }

    fn connect(&mut self, poller: &Poller, addr: SocketAddr) -> Result<Completion, Step> {
        let stream = match sys::net::connect(addr) {
            Ok(stream) => stream,
            Err(e) => return Ok(Completion::Handle(Err(e))),
        };
        self.next_handle += 1;
        let handle = Handle(self.next_handle);
        let token = usize::try_from(handle.0).expect("handle fits in usize");
        if let Err(e) = poller.watch(stream.as_fd(), token) {
            return Ok(Completion::Handle(Err(e)));
        }
        self.step(poller, Step::Connect(handle, stream))
    }

    fn run(&mut self, poller: &Poller, op: Op) -> Result<Completion, Step> {
        match op {
            Op::Open { .. }
            | Op::ReadAt { .. }
            | Op::WriteAt { .. }
            | Op::SyncData { .. }
            | Op::SyncDir { .. }
            | Op::Allocate { .. }
            | Op::Stat { .. } => Ok(self.run_file(poller, op)),
            op => self.run_net(poller, op),
        }
    }

    fn run_file(&mut self, poller: &Poller, op: Op) -> Completion {
        match op {
            Op::Open { path, options } => Completion::Handle(
                open(&path, &options).and_then(|f| self.add(poller, Resource::File(Rc::new(f)))),
            ),
            Op::ReadAt {
                handle,
                offset,
                mut buf,
            } => {
                buf.clear();
                let result = self
                    .file(handle)
                    .and_then(|f| f.read_at(buf.spare_mut(), offset));
                if let Ok(n) = result {
                    buf.set_len(n);
                }
                Completion::Bytes(result, buf)
            }
            Op::WriteAt {
                handle,
                offset,
                buf,
            } => {
                let result = self.file(handle).and_then(|f| f.write_at(&buf, offset));
                Completion::Bytes(result, buf)
            }
            Op::SyncData { handle } => {
                Completion::Unit(self.file(handle).and_then(sys::fs::full_sync))
            }
            Op::SyncDir { path } => {
                Completion::Unit(fs::File::open(path).and_then(|d| sys::fs::full_sync(&d)))
            }
            Op::Allocate { handle, len } => {
                Completion::Unit(self.file(handle).and_then(|f| sys::fs::allocate(f, len)))
            }
            Op::Stat { handle } => Completion::Stat(self.file(handle).and_then(|f| {
                Ok(Stat {
                    len: f.metadata()?.len(),
                    sector_size: sys::fs::sector_size(f)?,
                })
            })),
            other => Completion::Unit(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("not a file operation: {other:?}"),
            ))),
        }
    }

    fn run_net(&mut self, poller: &Poller, op: Op) -> Result<Completion, Step> {
        match op {
            Op::Listen { addr, backlog } => Ok(Completion::Handle(
                sys::net::listen(addr, backlog)
                    .and_then(|l| self.add(poller, Resource::Listener(l))),
            )),
            Op::Accept { handle } => {
                let accepted = match self.resources.get(&handle) {
                    Some(Resource::Listener(l)) => l.accept(),
                    _ => Err(bad_handle()),
                };
                match accepted {
                    Err(e) if blocked(&e) => Err(Step::Run(Op::Accept { handle })),
                    Err(e) => Ok(Completion::Accepted(Err(e))),
                    Ok((stream, addr)) => Ok(Completion::Accepted(
                        stream
                            .set_nonblocking(true)
                            .and_then(|()| self.add(poller, Resource::Stream(stream)))
                            .map(|h| (h, addr)),
                    )),
                }
            }
            Op::Connect { addr } => self.connect(poller, addr),
            Op::Recv { handle, mut buf } => {
                buf.clear();
                let result = self
                    .stream(handle)
                    .and_then(|mut s| s.read(buf.spare_mut()));
                match result {
                    Err(e) if blocked(&e) => Err(Step::Run(Op::Recv { handle, buf })),
                    result => {
                        if let Ok(n) = result {
                            buf.set_len(n);
                        }
                        Ok(Completion::Bytes(result, buf))
                    }
                }
            }
            Op::Send { handle, buf } => match self.stream(handle).and_then(|mut s| s.write(&buf)) {
                Err(e) if blocked(&e) => Err(Step::Run(Op::Send { handle, buf })),
                result => Ok(Completion::Bytes(result, buf)),
            },
            Op::Shutdown { handle } => Ok(Completion::Unit(
                self.stream(handle)
                    .and_then(|s| s.shutdown(Shutdown::Write)),
            )),
            Op::BindUdp { addr } => Ok(Completion::Handle(
                UdpSocket::bind(addr)
                    .and_then(|s| s.set_nonblocking(true).map(|()| s))
                    .and_then(|s| self.add(poller, Resource::Udp(s))),
            )),
            Op::SendTo { handle, buf, addr } => {
                match self.udp(handle).and_then(|s| s.send_to(&buf, addr)) {
                    Err(e) if blocked(&e) => Err(Step::Run(Op::SendTo { handle, buf, addr })),
                    result => Ok(Completion::Bytes(result, buf)),
                }
            }
            Op::RecvFrom { handle, mut buf } => {
                buf.clear();
                match self.udp(handle).and_then(|s| s.recv_from(buf.spare_mut())) {
                    Err(e) if blocked(&e) => Err(Step::Run(Op::RecvFrom { handle, buf })),
                    result => {
                        if let Ok((n, _)) = result {
                            buf.set_len(n);
                        }
                        Ok(Completion::From(result, buf))
                    }
                }
            }
            Op::LocalAddr { handle } => Ok(Completion::Addr(match self.resources.get(&handle) {
                Some(Resource::Listener(s)) => s.local_addr(),
                Some(Resource::Stream(s)) => s.local_addr(),
                Some(Resource::Udp(s)) => s.local_addr(),
                _ => Err(bad_handle()),
            })),
            other => Ok(Completion::Unit(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("not a socket operation: {other:?}"),
            )))),
        }
    }

    #[cfg(target_os = "linux")]
    fn ring_submit(&mut self, id: OpId, op: Op, waker: &Waker) -> Result<(), Op> {
        if self.ring.is_none() {
            return Err(op);
        }
        let file = match &op {
            Op::ReadAt { handle, .. } | Op::WriteAt { handle, .. } | Op::SyncData { handle } => {
                match self.resources.get(handle) {
                    Some(Resource::File(f)) => Rc::clone(f),
                    _ => return Err(op),
                }
            }
            _ => return Err(op),
        };
        let request = match op {
            Op::ReadAt {
                offset, mut buf, ..
            } => {
                buf.clear();
                Request::Read { file, offset, buf }
            }
            Op::WriteAt { offset, buf, .. } => Request::Write { file, offset, buf },
            _ => Request::SyncData { file },
        };
        if let Some(ring) = self.ring.as_mut()
            && let Err(request) = ring.push(id.0, request)
        {
            self.backlog.push_back((id.0, request));
        }
        self.waiting.insert(id, waker.clone());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::unused_self)]
    fn flush(&mut self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    fn flush(&mut self) -> bool {
        let Some(ring) = self.ring.as_mut() else {
            return false;
        };
        ring.submit(&mut self.finished);
        let delivered = self.reap_ring();
        let queued = self.ring.as_ref().is_some_and(|r| r.queued() > 0);
        delivered || queued
    }

    #[cfg(target_os = "linux")]
    fn reap_ring(&mut self) -> bool {
        let Some(ring) = self.ring.as_mut() else {
            return false;
        };
        ring.drain_event();
        ring.complete(&mut self.finished);
        while let Some((id, request)) = self.backlog.pop_front() {
            if let Err(request) = ring.push(id, request) {
                self.backlog.push_front((id, request));
                break;
            }
        }
        self.deliver()
    }

    #[cfg(target_os = "linux")]
    fn deliver(&mut self) -> bool {
        let mut any = false;
        for done in std::mem::take(&mut self.finished) {
            let id = OpId(done.id);
            let Some(waker) = self.waiting.remove(&id) else {
                continue;
            };
            let completion = match done.buf {
                Some(buf) => Completion::Bytes(done.result, buf),
                None => Completion::Unit(done.result.map(drop)),
            };
            self.done.insert(id, completion);
            waker.wake();
            any = true;
        }
        any
    }

    fn retry(&mut self, poller: &Poller) {
        for (id, pending) in std::mem::take(&mut self.pending) {
            match self.step(poller, pending.step) {
                Ok(completion) => {
                    self.done.insert(id, completion);
                    pending.waker.wake();
                }
                Err(step) => {
                    self.pending.insert(
                        id,
                        Pending {
                            step,
                            waker: pending.waker,
                        },
                    );
                }
            }
        }
    }
}

impl Driver for Native {
    fn now(&self) -> Instant {
        let nanos = self.start.elapsed().as_nanos();
        Instant::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    fn wall_ms(&self) -> u64 {
        let since = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    }

    fn submit(&self, op: Op, waker: &Waker) -> OpId {
        let mut state = self.state.borrow_mut();
        state.next_op += 1;
        let id = OpId(state.next_op);
        #[cfg(target_os = "linux")]
        let op = match state.ring_submit(id, op, waker) {
            Ok(()) => return id,
            Err(op) => op,
        };
        match state.step(&self.poller, Step::Run(op)) {
            Ok(completion) => {
                state.done.insert(id, completion);
            }
            Err(step) => {
                state.pending.insert(
                    id,
                    Pending {
                        step,
                        waker: waker.clone(),
                    },
                );
            }
        }
        id
    }

    fn poll(&self, id: OpId, waker: &Waker) -> Option<Completion> {
        let mut state = self.state.borrow_mut();
        if let Some(completion) = state.done.remove(&id) {
            return Some(completion);
        }
        if let Some(pending) = state.pending.get_mut(&id) {
            pending.waker.clone_from(waker);
        }
        #[cfg(target_os = "linux")]
        if let Some(waiting) = state.waiting.get_mut(&id) {
            waiting.clone_from(waker);
        }
        None
    }

    fn cancel(&self, id: OpId) {
        let mut state = self.state.borrow_mut();
        state.pending.remove(&id);
        #[cfg(target_os = "linux")]
        if state.waiting.remove(&id).is_some() {
            state.backlog.retain(|(queued, _)| *queued != id.0);
        }
        if let Some(Completion::Handle(Ok(handle)) | Completion::Accepted(Ok((handle, _)))) =
            state.done.remove(&id)
        {
            state.resources.remove(&handle);
        }
    }

    fn release(&self, handle: Handle) {
        self.state.borrow_mut().resources.remove(&handle);
    }

    fn park(&self, deadline: Option<Instant>) {
        let busy = self.state.borrow_mut().flush();
        let timeout = if busy {
            Some(Duration::ZERO)
        } else {
            deadline.map(|d| d.saturating_duration_since(self.now()))
        };
        let mut events = std::mem::take(&mut self.state.borrow_mut().events);
        events.clear();
        if self.poller.wait(&mut events, timeout).is_err() {
            events.clear();
        }
        let mut state = self.state.borrow_mut();
        state.events = events;
        #[cfg(target_os = "linux")]
        state.reap_ring();
        state.retry(&self.poller);
    }

    fn unparker(&self) -> Arc<dyn Unpark> {
        Arc::new(Wake(self.poller.clone()))
    }
}
