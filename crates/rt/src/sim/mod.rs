mod disk;
mod machine;
mod net;
mod rng;

use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::env;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::task::Waker;
use std::time::Duration;

pub use disk::Disk;
pub use machine::{Machine, Stalls};
pub use rng::Rng;

use crate::driver::{Completion, Driver, Handle, Op, OpId, Stat, Unpark};
use crate::time::Instant;
use net::{Delivery, Net, Socket};
use sys::buf::Buf;

#[derive(Clone, Debug)]
pub struct Faults {
    pub crash_keep: u32,
    pub torn_write: u32,
    pub lost_write: u32,
    pub misdirected_write: u32,
    pub read_error: u32,
    pub read_corruption: u32,
    pub sync_error: u32,
    pub packet_loss: u32,
    pub connection_reset: u32,
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            crash_keep: rng::MILLION / 2,
            torn_write: 0,
            lost_write: 0,
            misdirected_write: 0,
            read_error: 0,
            read_corruption: 0,
            sync_error: 0,
            packet_loss: 0,
            connection_reset: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub sector_size: u32,
    pub io_latency: (Duration, Duration),
    pub sync_latency: (Duration, Duration),
    pub net_latency: (Duration, Duration),
    pub wall_start_ms: u64,
    pub faults: Faults,
    pub halt_after: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sector_size: 4096,
            io_latency: (Duration::from_micros(5), Duration::from_micros(200)),
            sync_latency: (Duration::from_micros(20), Duration::from_millis(5)),
            net_latency: (Duration::from_micros(50), Duration::from_millis(20)),
            wall_start_ms: 1_800_000_000_000,
            faults: Faults::default(),
            halt_after: None,
        }
    }
}

enum Resource {
    File(PathBuf),
    Socket(u64),
}

enum Event {
    Run(OpId),
    Deliver(Delivery),
}

struct Pending {
    op: Option<Op>,
    waker: Waker,
}

struct State {
    seed: u64,
    rng: Rng,
    config: Config,
    now: u64,
    wall_offset_ms: i64,
    disk: Disk,
    net: Net,
    handles: BTreeMap<Handle, Resource>,
    next_handle: u64,
    next_op: u64,
    next_event: u64,
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    stream_clock: BTreeMap<u64, u64>,
    events: BTreeMap<u64, Event>,
    pending: BTreeMap<OpId, Pending>,
    waiting: BTreeSet<OpId>,
    done: BTreeMap<OpId, Completion>,
    disk_ops: u64,
    halted: bool,
}

fn bad_handle() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "unknown handle")
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

impl State {
    fn schedule(&mut self, delay: Duration, event: Event) {
        let at = self.now.saturating_add(nanos(delay));
        self.schedule_at(at, event);
    }

    fn schedule_at(&mut self, at: u64, event: Event) {
        self.next_event += 1;
        self.queue.push(Reverse((at, self.next_event)));
        self.events.insert(self.next_event, event);
    }

    fn deliver_in_order(&mut self, to: u64, delivery: Delivery) {
        let delay = self.net_delay();
        let earliest = self.now.saturating_add(nanos(delay));
        let last = self.stream_clock.get(&to).copied().unwrap_or(0);
        let at = earliest.max(last.saturating_add(1));
        self.stream_clock.insert(to, at);
        self.schedule_at(at, Event::Deliver(delivery));
    }

    fn net_delay(&mut self) -> Duration {
        let (low, high) = self.config.net_latency;
        self.rng.between(low, high)
    }

    fn delay_for(&mut self, op: &Op) -> Duration {
        let (low, high) = match op {
            Op::SyncData { .. } | Op::SyncDir { .. } => self.config.sync_latency,
            Op::Connect { .. } | Op::Send { .. } | Op::SendTo { .. } => self.config.net_latency,
            _ => self.config.io_latency,
        };
        self.rng.between(low, high)
    }

    fn add(&mut self, resource: Resource) -> Handle {
        self.next_handle += 1;
        let handle = Handle(self.next_handle);
        self.handles.insert(handle, resource);
        handle
    }

    fn file(&self, handle: Handle) -> Option<PathBuf> {
        match self.handles.get(&handle) {
            Some(Resource::File(path)) => Some(path.clone()),
            _ => None,
        }
    }

    fn socket(&self, handle: Handle) -> Option<u64> {
        match self.handles.get(&handle) {
            Some(Resource::Socket(id)) => Some(*id),
            _ => None,
        }
    }

    fn submit(&mut self, op: Op, waker: &Waker) -> OpId {
        self.next_op += 1;
        let id = OpId(self.next_op);
        let delay = self.delay_for(&op);
        self.pending.insert(
            id,
            Pending {
                op: Some(op),
                waker: waker.clone(),
            },
        );
        self.schedule(delay, Event::Run(id));
        id
    }

    fn run(&mut self, id: OpId) {
        if self.halted {
            return;
        }
        let Some(op) = self.pending.get_mut(&id).and_then(|p| p.op.take()) else {
            return;
        };
        if matches!(
            op,
            Op::WriteAt { .. } | Op::SyncData { .. } | Op::SyncDir { .. } | Op::Allocate { .. }
        ) {
            self.disk_ops += 1;
            self.halted = self.config.halt_after == Some(self.disk_ops);
        }
        match self.execute(op) {
            Ok(completion) => {
                if let Some(pending) = self.pending.remove(&id) {
                    self.done.insert(id, completion);
                    pending.waker.wake();
                }
            }
            Err(op) => {
                if let Some(pending) = self.pending.get_mut(&id) {
                    pending.op = Some(op);
                    self.waiting.insert(id);
                }
            }
        }
    }

    fn retry_waiting(&mut self) {
        loop {
            let mut progressed = false;
            for id in std::mem::take(&mut self.waiting) {
                let before = self.done.len();
                self.run(id);
                progressed |= self.done.len() > before;
            }
            if !progressed {
                break;
            }
        }
    }

    fn file_op(&mut self, op: Op) -> Completion {
        match op {
            Op::Open { path, options } => Completion::Handle(
                self.disk
                    .open(&path, &options)
                    .map(|()| self.add(Resource::File(path))),
            ),
            Op::ReadAt {
                handle,
                offset,
                mut buf,
            } => {
                let Some(path) = self.file(handle) else {
                    return Completion::Bytes(Err(bad_handle()), buf);
                };
                if self.rng.chance(self.config.faults.read_error) {
                    return Completion::Bytes(Err(io::Error::other("simulated read error")), buf);
                }
                buf.clear();
                let n = self.disk.read(&path, offset, buf.spare_mut());
                buf.set_len(n);
                if n > 0 && self.rng.chance(self.config.faults.read_corruption) {
                    let at = self.rng.index(n);
                    buf[at] ^= 1 << self.rng.below(8);
                }
                Completion::Bytes(Ok(n), buf)
            }
            Op::WriteAt {
                handle,
                offset,
                buf,
            } => match self.file(handle) {
                Some(path) => {
                    self.disk.write(&path, offset, &buf);
                    Completion::Bytes(Ok(buf.len()), buf)
                }
                None => Completion::Bytes(Err(bad_handle()), buf),
            },
            Op::SyncData { handle } => Completion::Unit(match self.file(handle) {
                Some(path) => self.disk.sync(&path, &mut self.rng, &self.config.faults),
                None => Err(bad_handle()),
            }),
            Op::SyncDir { path } => {
                self.disk.sync_dir(&path);
                Completion::Unit(Ok(()))
            }
            Op::Allocate { handle, len } => Completion::Unit(match self.file(handle) {
                Some(path) => {
                    self.disk.allocate(&path, len);
                    Ok(())
                }
                None => Err(bad_handle()),
            }),
            Op::Stat { handle } => Completion::Stat(match self.file(handle) {
                Some(path) => Ok(Stat {
                    len: self.disk.len(&path),
                    sector_size: self.disk.sector_size(),
                }),
                None => Err(bad_handle()),
            }),
            other => Completion::Unit(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("not a file operation: {other:?}"),
            ))),
        }
    }

    fn execute(&mut self, op: Op) -> Result<Completion, Op> {
        match op {
            Op::Listen { addr, .. } => {
                let addr = self.net.bind_addr(addr);
                if self.net.in_use(addr) {
                    return Ok(Completion::Handle(Err(io::ErrorKind::AddrInUse.into())));
                }
                let id = self.net.add(Socket::Listener {
                    addr,
                    backlog: std::collections::VecDeque::new(),
                });
                Ok(Completion::Handle(Ok(self.add(Resource::Socket(id)))))
            }
            Op::BindUdp { addr } => {
                let addr = self.net.bind_addr(addr);
                if self.net.in_use(addr) {
                    return Ok(Completion::Handle(Err(io::ErrorKind::AddrInUse.into())));
                }
                let id = self.net.add(Socket::Udp {
                    addr,
                    inbound: std::collections::VecDeque::new(),
                });
                Ok(Completion::Handle(Ok(self.add(Resource::Socket(id)))))
            }
            Op::Accept { handle } => {
                let Some(id) = self.socket(handle) else {
                    return Ok(Completion::Accepted(Err(bad_handle())));
                };
                let next = match self.net.sockets.get_mut(&id) {
                    Some(Socket::Listener { backlog, .. }) => backlog.pop_front(),
                    _ => return Ok(Completion::Accepted(Err(bad_handle()))),
                };
                match next {
                    Some((stream, peer)) => Ok(Completion::Accepted(Ok((
                        self.add(Resource::Socket(stream)),
                        peer,
                    )))),
                    None => Err(Op::Accept { handle }),
                }
            }
            Op::Connect { addr } => {
                if !self.net.reachable(addr) {
                    return Err(Op::Connect { addr });
                }
                let Some(listener) = self.net.listener_at(addr) else {
                    return Ok(Completion::Handle(Err(
                        io::ErrorKind::ConnectionRefused.into()
                    )));
                };
                let client = self.net.connect(listener, addr);
                Ok(Completion::Handle(Ok(self.add(Resource::Socket(client)))))
            }
            Op::Recv { handle, buf } => Ok(self.recv(handle, buf)?),
            Op::Send { handle, buf } => Ok(self.send(handle, buf)),
            Op::Shutdown { handle } => {
                let peer = match self.socket(handle).and_then(|id| self.net.sockets.get(&id)) {
                    Some(Socket::Stream { peer, .. }) => *peer,
                    _ => return Ok(Completion::Unit(Err(bad_handle()))),
                };
                self.deliver_in_order(peer, Delivery::Eof { to: peer });
                Ok(Completion::Unit(Ok(())))
            }
            udp @ (Op::SendTo { .. } | Op::RecvFrom { .. }) => self.udp(udp),
            Op::LocalAddr { handle } => {
                let addr = match self.socket(handle).and_then(|id| self.net.sockets.get(&id)) {
                    Some(Socket::Listener { addr, .. } | Socket::Udp { addr, .. }) => Ok(*addr),
                    Some(Socket::Stream { local, .. }) => Ok(*local),
                    None => Err(bad_handle()),
                };
                Ok(Completion::Addr(addr))
            }
            file => Ok(self.file_op(file)),
        }
    }

    fn udp(&mut self, op: Op) -> Result<Completion, Op> {
        match op {
            Op::SendTo { handle, buf, addr } => {
                let from = match self.socket(handle).and_then(|id| self.net.sockets.get(&id)) {
                    Some(Socket::Udp { addr, .. }) => *addr,
                    _ => return Ok(Completion::Bytes(Err(bad_handle()), buf)),
                };
                if self.net.reachable(addr) && !self.rng.chance(self.config.faults.packet_loss) {
                    let delay = self.net_delay();
                    let data = buf.to_vec();
                    self.schedule(
                        delay,
                        Event::Deliver(Delivery::Datagram {
                            to: addr,
                            from,
                            data,
                        }),
                    );
                }
                Ok(Completion::Bytes(Ok(buf.len()), buf))
            }
            Op::RecvFrom { handle, mut buf } => {
                let Some(id) = self.socket(handle) else {
                    return Ok(Completion::From(Err(bad_handle()), buf));
                };
                let next = match self.net.sockets.get_mut(&id) {
                    Some(Socket::Udp { inbound, .. }) => inbound.pop_front(),
                    _ => return Ok(Completion::From(Err(bad_handle()), buf)),
                };
                match next {
                    Some((data, from)) => {
                        buf.clear();
                        let n = buf.extend_from_slice(&data);
                        Ok(Completion::From(Ok((n, from)), buf))
                    }
                    None => Err(Op::RecvFrom { handle, buf }),
                }
            }
            other => Ok(self.file_op(other)),
        }
    }

    fn recv(&mut self, handle: Handle, mut buf: Buf) -> Result<Completion, Op> {
        let Some(id) = self.socket(handle) else {
            return Ok(Completion::Bytes(Err(bad_handle()), buf));
        };
        let Some(Socket::Stream {
            inbound,
            eof,
            reset,
            ..
        }) = self.net.sockets.get_mut(&id)
        else {
            return Ok(Completion::Bytes(Err(bad_handle()), buf));
        };
        if *reset {
            return Ok(Completion::Bytes(
                Err(io::ErrorKind::ConnectionReset.into()),
                buf,
            ));
        }
        if inbound.is_empty() {
            if *eof {
                buf.clear();
                return Ok(Completion::Bytes(Ok(0), buf));
            }
            return Err(Op::Recv { handle, buf });
        }
        buf.clear();
        let n = buf.capacity().min(inbound.len());
        let data: Vec<u8> = inbound.drain(..n).collect();
        buf.extend_from_slice(&data);
        Ok(Completion::Bytes(Ok(n), buf))
    }

    fn send(&mut self, handle: Handle, buf: Buf) -> Completion {
        let Some(id) = self.socket(handle) else {
            return Completion::Bytes(Err(bad_handle()), buf);
        };
        let (peer, reset) = match self.net.sockets.get(&id) {
            Some(Socket::Stream { peer, reset, .. }) => (*peer, *reset),
            _ => return Completion::Bytes(Err(bad_handle()), buf),
        };
        if reset || self.rng.chance(self.config.faults.connection_reset) {
            self.net.reset(id);
            return Completion::Bytes(Err(io::ErrorKind::ConnectionReset.into()), buf);
        }
        let data = buf.to_vec();
        self.deliver_in_order(peer, Delivery::Bytes { to: peer, data });
        Completion::Bytes(Ok(buf.len()), buf)
    }

    fn release(&mut self, handle: Handle) {
        let Some(Resource::Socket(id)) = self.handles.remove(&handle) else {
            return;
        };
        if let Some(Socket::Stream { peer, .. }) = self.net.sockets.remove(&id) {
            self.deliver_in_order(peer, Delivery::Eof { to: peer });
        }
    }

    fn advance(&mut self, deadline: Option<Instant>) {
        let next = self.queue.peek().map(|Reverse((at, _))| *at);
        let target = match (next, deadline.map(Instant::as_nanos)) {
            (Some(event), Some(deadline)) => event.min(deadline),
            (Some(at), None) | (None, Some(at)) => at,
            (None, None) => panic!(
                "simulation stalled with seed {}: every task waits and nothing is scheduled",
                self.seed
            ),
        };
        self.now = self.now.max(target);
        while let Some(Reverse((at, key))) = self.queue.peek().copied() {
            if at > self.now {
                break;
            }
            self.queue.pop();
            match self.events.remove(&key) {
                Some(Event::Run(id)) => self.run(id),
                Some(Event::Deliver(delivery)) => self.net.deliver(delivery),
                None => continue,
            }
            self.retry_waiting();
        }
    }
}

struct NoUnpark;

impl Unpark for NoUnpark {
    fn unpark(&self) {}
}

pub struct SimDriver {
    state: RefCell<State>,
}

impl SimDriver {
    pub fn new(seed: u64, config: Config) -> Self {
        let disk = Disk::new(config.sector_size);
        Self::with_disk(seed, config, disk)
    }

    pub fn with_disk(seed: u64, config: Config, disk: Disk) -> Self {
        Self {
            state: RefCell::new(State {
                seed,
                rng: Rng::new(seed),
                config,
                now: 0,
                wall_offset_ms: 0,
                disk,
                net: Net::default(),
                handles: BTreeMap::new(),
                next_handle: 0,
                next_op: 0,
                next_event: 0,
                queue: BinaryHeap::new(),
                stream_clock: BTreeMap::new(),
                events: BTreeMap::new(),
                pending: BTreeMap::new(),
                waiting: BTreeSet::new(),
                done: BTreeMap::new(),
                disk_ops: 0,
                halted: false,
            }),
        }
    }

    pub fn seed(&self) -> u64 {
        self.state.borrow().seed
    }

    pub fn random(&self) -> u64 {
        self.state.borrow_mut().rng.next_u64()
    }

    pub fn disk_ops(&self) -> u64 {
        self.state.borrow().disk_ops
    }

    pub fn is_halted(&self) -> bool {
        self.state.borrow().halted
    }

    pub fn disk(&self) -> Disk {
        self.state.borrow().disk.clone()
    }

    pub fn crash(&self) -> Disk {
        let mut state = self.state.borrow_mut();
        let state = &mut *state;
        let mut disk = state.disk.clone();
        disk.crash(&mut state.rng, &state.config.faults);
        disk
    }

    pub fn jump_wall_clock(&self, delta_ms: i64) {
        self.state.borrow_mut().wall_offset_ms += delta_ms;
    }

    pub fn set_reachable(&self, ip: IpAddr, reachable: bool) {
        let mut state = self.state.borrow_mut();
        state.net.set_reachable(ip, reachable);
        state.retry_waiting();
    }

    pub fn reset_connection(&self, local: SocketAddr) {
        let mut state = self.state.borrow_mut();
        let id = state
            .net
            .sockets
            .iter()
            .find_map(|(id, socket)| match socket {
                Socket::Stream { local: addr, .. } if *addr == local => Some(*id),
                _ => None,
            });
        if let Some(id) = id {
            state.net.reset(id);
            state.retry_waiting();
        }
    }
}

impl Driver for SimDriver {
    fn now(&self) -> Instant {
        Instant::from_nanos(self.state.borrow().now)
    }

    fn wall_ms(&self) -> u64 {
        let state = self.state.borrow();
        let elapsed = state.now / 1_000_000;
        let wall = state.config.wall_start_ms.saturating_add(elapsed);
        wall.saturating_add_signed(state.wall_offset_ms)
    }

    fn submit(&self, op: Op, waker: &Waker) -> OpId {
        self.state.borrow_mut().submit(op, waker)
    }

    fn poll(&self, id: OpId, waker: &Waker) -> Option<Completion> {
        let mut state = self.state.borrow_mut();
        if let Some(pending) = state.pending.get_mut(&id) {
            pending.waker.clone_from(waker);
            return None;
        }
        state.done.remove(&id)
    }

    fn cancel(&self, id: OpId) {
        let mut state = self.state.borrow_mut();
        state.pending.remove(&id);
        state.waiting.remove(&id);
        state.done.remove(&id);
    }

    fn release(&self, handle: Handle) {
        self.state.borrow_mut().release(handle);
    }

    fn park(&self, deadline: Option<Instant>) {
        self.state.borrow_mut().advance(deadline);
    }

    fn unparker(&self) -> Arc<dyn Unpark> {
        Arc::new(NoUnpark)
    }
}

pub fn check(seeds: Range<u64>, test: impl Fn(u64)) {
    let replay = env::var("SIM_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let number = |name| env::var(name).ok().and_then(|s| s.parse::<u64>().ok());
    let scale = number("SIM_SCALE").unwrap_or(1);
    let start = seeds.start + number("SIM_OFFSET").unwrap_or(0);
    let seeds = start..start + (seeds.end - seeds.start) * scale;
    let seeds: Vec<u64> = replay.map_or_else(|| seeds.collect(), |seed| vec![seed]);
    for seed in seeds {
        if let Err(failure) = panic::catch_unwind(AssertUnwindSafe(|| test(seed))) {
            eprintln!("simulation failed with seed {seed}; replay with SIM_SEED={seed}");
            panic::resume_unwind(failure);
        }
    }
}
