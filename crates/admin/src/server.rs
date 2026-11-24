use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

use rt::{Buf, JoinHandle, Notify, UnixListener, UnixStream, sleep, spawn, timeout};

use crate::proto::{Code, Frames, Reply, Request};

const SESSIONS: usize = 4;
const IDLE: Duration = Duration::from_secs(60);
const READ: usize = 4096;
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

pub trait Handler {
    fn handle(&self, request: Request) -> impl Future<Output = Reply>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub accepted: u64,
    pub refused: u64,
    pub full: u64,
    pub requests: u64,
    pub malformed: u64,
}

#[derive(Default)]
struct Shared {
    stop: Notify,
    closing: Cell<bool>,
    sessions: RefCell<BTreeMap<u64, Rc<Notify>>>,
    idle: Notify,
    stats: Cell<Stats>,
}

impl Shared {
    fn count(&self, change: impl FnOnce(&mut Stats)) {
        let mut stats = self.stats.get();
        change(&mut stats);
        self.stats.set(stats);
    }
}

pub struct Admin {
    shared: Rc<Shared>,
    task: JoinHandle<()>,
}

pub fn serve<H: Handler + 'static>(
    listener: UnixListener,
    peers: Vec<u32>,
    handler: Rc<H>,
) -> Admin {
    let shared = Rc::new(Shared::default());
    let state = Rc::clone(&shared);
    let task = spawn(async move {
        let mut count = 0u64;
        loop {
            let Some(accepted) = stoppable(&state.stop, &state.closing, listener.accept()).await
            else {
                return;
            };
            let Ok((stream, uid)) = accepted else {
                sleep(ACCEPT_PAUSE).await;
                continue;
            };
            if !peers.contains(&uid) {
                drop(stream);
                state.count(|s| s.refused += 1);
                continue;
            }
            if state.sessions.borrow().len() >= SESSIONS {
                drop(stream);
                state.count(|s| s.full += 1);
                continue;
            }
            state.count(|s| s.accepted += 1);
            count += 1;
            let stop = Rc::new(Notify::default());
            state.sessions.borrow_mut().insert(count, Rc::clone(&stop));
            let (handler, state) = (Rc::clone(&handler), Rc::clone(&state));
            spawn(async move {
                stoppable(&stop, &state.closing, session(&stream, &*handler, &state)).await;
                let mut sessions = state.sessions.borrow_mut();
                sessions.remove(&count);
                if sessions.is_empty() {
                    state.idle.notify();
                }
            });
        }
    });
    Admin { shared, task }
}

impl Admin {
    pub fn stats(&self) -> Stats {
        self.shared.stats.get()
    }

    pub fn sessions(&self) -> usize {
        self.shared.sessions.borrow().len()
    }

    pub async fn close(self) {
        let shared = self.shared;
        shared.closing.set(true);
        shared.stop.notify();
        self.task.await;
        for stop in shared.sessions.borrow().values() {
            stop.notify();
        }
        while !shared.sessions.borrow().is_empty() {
            shared.idle.wait().await;
        }
    }
}

async fn session<H: Handler>(stream: &UnixStream, handler: &H, state: &Shared) {
    let mut frames = Frames::default();
    loop {
        let Ok(Some(body)) = timeout(IDLE, frame(stream, &mut frames, state)).await else {
            return;
        };
        let reply = match Request::decode(&body) {
            Ok(request) => {
                state.count(|s| s.requests += 1);
                handler.handle(request).await
            }
            Err(error) => {
                state.count(|s| s.malformed += 1);
                Reply::new(Code::Refused, error.to_string())
            }
        };
        let written = timeout(IDLE, stream.write_all(Buf::from_slice(&reply.encode()))).await;
        if !matches!(written, Ok((Ok(()), _))) {
            return;
        }
    }
}

async fn frame(stream: &UnixStream, frames: &mut Frames, state: &Shared) -> Option<Vec<u8>> {
    loop {
        match frames.pop() {
            Ok(Some(body)) => return Some(body),
            Ok(None) => {}
            Err(_) => {
                state.count(|s| s.malformed += 1);
                return None;
            }
        }
        let (read, buf) = stream.read(Buf::new(READ)).await;
        match read {
            Ok(0) | Err(_) => return None,
            Ok(n) => frames.push(&buf[..n]),
        }
    }
}

async fn stoppable<F: Future>(stop: &Notify, closing: &Cell<bool>, work: F) -> Option<F::Output> {
    let mut work = pin!(work);
    loop {
        if closing.get() {
            return None;
        }
        let mut wait = pin!(stop.wait());
        let done = poll_fn(|cx| {
            if let Poll::Ready(value) = work.as_mut().poll(cx) {
                return Poll::Ready(Some(value));
            }
            wait.as_mut().poll(cx).map(|()| None)
        })
        .await;
        if done.is_some() {
            return done;
        }
    }
}
