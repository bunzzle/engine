use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::task::Waker;

use rt::{Completion, Driver, Handle, Instant, Op, OpId, Stat, Unpark};

#[derive(Default)]
pub struct Wakeup {
    flag: Mutex<bool>,
    cond: Condvar,
}

impl Wakeup {
    fn wait(&self) {
        let mut flag = self.flag.lock().unwrap_or_else(PoisonError::into_inner);
        while !*flag {
            flag = self.cond.wait(flag).unwrap_or_else(PoisonError::into_inner);
        }
        *flag = false;
    }
}

impl Unpark for Wakeup {
    fn unpark(&self) {
        *self.flag.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.cond.notify_one();
    }
}

#[derive(Default)]
struct State {
    now: u64,
    next_op: u64,
    next_handle: u64,
    files: HashMap<PathBuf, Rc<RefCell<Vec<u8>>>>,
    open: HashMap<Handle, Rc<RefCell<Vec<u8>>>>,
    listeners: HashMap<Handle, SocketAddr>,
    done: HashMap<OpId, Completion>,
    pending: HashMap<OpId, Waker>,
    pub cancelled: Vec<OpId>,
    pub released: Vec<Handle>,
}

#[derive(Default)]
pub struct MemDriver {
    state: RefCell<State>,
    wakeup: Arc<Wakeup>,
}

impl MemDriver {
    pub fn cancelled(&self) -> usize {
        self.state.borrow().cancelled.len()
    }

    pub fn released(&self) -> usize {
        self.state.borrow().released.len()
    }

    pub fn pending(&self) -> usize {
        self.state.borrow().pending.len()
    }

    fn complete(state: &mut State, op: Op) -> Option<Completion> {
        Some(match op {
            Op::Open { path, options } => {
                state.next_handle += 1;
                let handle = Handle(state.next_handle);
                let exists = state.files.contains_key(&path);
                if !exists && !options.create {
                    return Some(Completion::Handle(Err(io::ErrorKind::NotFound.into())));
                }
                let data = state.files.entry(path).or_default().clone();
                if options.truncate {
                    data.borrow_mut().clear();
                }
                state.open.insert(handle, data);
                Completion::Handle(Ok(handle))
            }
            Op::ReadAt {
                handle,
                offset,
                mut buf,
            } => {
                let data = state.open[&handle].borrow();
                let at = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(data.len());
                buf.clear();
                let n = buf.extend_from_slice(&data[at..]);
                Completion::Bytes(Ok(n), buf)
            }
            Op::WriteAt {
                handle,
                offset,
                buf,
            } => {
                let mut data = state.open[&handle].borrow_mut();
                let at = usize::try_from(offset).unwrap_or(usize::MAX);
                if data.len() < at + buf.len() {
                    data.resize(at + buf.len(), 0);
                }
                data[at..at + buf.len()].copy_from_slice(&buf);
                let n = buf.len();
                drop(data);
                Completion::Bytes(Ok(n), buf)
            }
            Op::SyncData { .. } | Op::SyncDir { .. } | Op::Shutdown { .. } => {
                Completion::Unit(Ok(()))
            }
            Op::Allocate { handle, len } => {
                let mut data = state.open[&handle].borrow_mut();
                let len = usize::try_from(len).unwrap_or(usize::MAX);
                if data.len() < len {
                    data.resize(len, 0);
                }
                Completion::Unit(Ok(()))
            }
            Op::Stat { handle } => {
                let len = state.open[&handle].borrow().len() as u64;
                Completion::Stat(Ok(Stat {
                    len,
                    sector_size: 4096,
                }))
            }
            Op::Listen { addr, .. } => {
                state.next_handle += 1;
                let handle = Handle(state.next_handle);
                state.listeners.insert(handle, addr);
                Completion::Handle(Ok(handle))
            }
            Op::LocalAddr { handle } => Completion::Addr(
                state
                    .listeners
                    .get(&handle)
                    .copied()
                    .ok_or_else(|| io::ErrorKind::NotConnected.into()),
            ),
            Op::Accept { .. } | Op::Recv { .. } => return None,
            Op::Connect { .. } | Op::BindUdp { .. } => {
                Completion::Handle(Err(io::ErrorKind::Unsupported.into()))
            }
            Op::Send { buf, .. } | Op::SendTo { buf, .. } => Completion::Bytes(Ok(buf.len()), buf),
            Op::RecvFrom { buf, .. } => {
                Completion::From(Ok((0, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))), buf)
            }
        })
    }
}

impl Driver for MemDriver {
    fn now(&self) -> Instant {
        Instant::from_nanos(self.state.borrow().now)
    }

    fn wall_ms(&self) -> u64 {
        1_000_000 + self.state.borrow().now / 1_000_000
    }

    fn submit(&self, op: Op, waker: &Waker) -> OpId {
        let mut state = self.state.borrow_mut();
        state.next_op += 1;
        let id = OpId(state.next_op);
        match Self::complete(&mut state, op) {
            Some(completion) => {
                state.done.insert(id, completion);
                waker.wake_by_ref();
            }
            None => {
                state.pending.insert(id, waker.clone());
            }
        }
        id
    }

    fn poll(&self, id: OpId, waker: &Waker) -> Option<Completion> {
        let mut state = self.state.borrow_mut();
        if let Some(pending) = state.pending.get_mut(&id) {
            pending.clone_from(waker);
            return None;
        }
        state.done.remove(&id)
    }

    fn cancel(&self, id: OpId) {
        let mut state = self.state.borrow_mut();
        state.pending.remove(&id);
        state.done.remove(&id);
        state.cancelled.push(id);
    }

    fn release(&self, handle: Handle) {
        let mut state = self.state.borrow_mut();
        state.open.remove(&handle);
        state.listeners.remove(&handle);
        state.released.push(handle);
    }

    fn park(&self, deadline: Option<Instant>) {
        match deadline {
            Some(deadline) => {
                let mut state = self.state.borrow_mut();
                state.now = state.now.max(deadline.as_nanos());
            }
            None => self.wakeup.wait(),
        }
    }

    fn unparker(&self) -> Arc<dyn Unpark> {
        self.wakeup.clone()
    }
}
