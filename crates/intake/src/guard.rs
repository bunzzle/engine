use std::cell::{Cell, OnceCell, RefCell};
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::IpAddr;
use std::rc::Rc;
use std::task::{Poll, Waker};

use control::siphash;
use rt::{Ends, JoinHandle, Peers, now, timeout};

use crate::owner::{Limits, Opened, Owner, OwnerStats, Prefix};

pub struct Ask(Message);

enum Message {
    Ask { ticket: u64, request: Request },
    Answer { ticket: u64, answer: Answer },
}

#[derive(Clone, Copy)]
enum Request {
    Open { net: Prefix, wide: Prefix },
    Close { net: Prefix },
    Failed { net: Prefix, wide: Prefix },
    OpenTenant { tenant: u32, limit: u32 },
    CloseTenant { tenant: u32 },
}

enum Answer {
    Opened(Opened),
    Failed(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Full,
    Banned,
    Unanswered,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuardStats {
    pub sessions: usize,
    pub refused: u64,
    pub reserved: usize,
    pub peak: usize,
    pub busy: u64,
    pub unanswered: u64,
    pub waiting: usize,
    pub owner: OwnerStats,
}

struct Once<T>(Rc<RefCell<(Option<T>, Option<Waker>)>>);

impl<T> Once<T> {
    fn new() -> Self {
        Self(Rc::new(RefCell::new((None, None))))
    }

    fn handle(&self) -> Self {
        Self(Rc::clone(&self.0))
    }

    fn put(self, value: T) {
        let waker = {
            let mut cell = self.0.borrow_mut();
            cell.0 = Some(value);
            cell.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    async fn get(self) -> T {
        poll_fn(|cx| {
            let mut cell = self.0.borrow_mut();
            if let Some(value) = cell.0.take() {
                return Poll::Ready(value);
            }
            cell.1 = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

enum Waiter {
    Slot {
        reply: Once<Result<Slot, Refused>>,
        owner: u16,
        close: Request,
    },
    Failed(Once<bool>),
}

struct Inner {
    key: [u8; 16],
    limits: Limits,
    cores: u16,
    owner: RefCell<Owner>,
    peers: OnceCell<Peers<Ask>>,
    waiting: RefCell<BTreeMap<u64, Waiter>>,
    tickets: Cell<u64>,
    sessions: Cell<usize>,
    refused: Cell<u64>,
    reserved: Cell<usize>,
    peak: Cell<usize>,
    busy: Cell<u64>,
    unanswered: Cell<u64>,
}

#[derive(Clone)]
pub struct Guard {
    inner: Rc<Inner>,
}

pub struct Admitted {
    inner: Rc<Inner>,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        self.inner.sessions.set(self.inner.sessions.get() - 1);
    }
}

pub struct Reserved {
    inner: Rc<Inner>,
    bytes: usize,
}

impl Drop for Reserved {
    fn drop(&mut self) {
        self.inner
            .reserved
            .set(self.inner.reserved.get() - self.bytes);
    }
}

pub struct Slot {
    inner: Rc<Inner>,
    owner: u16,
    close: Request,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.inner.send(self.owner, self.close);
    }
}

impl Guard {
    pub fn start(ends: Ends<Ask>, key: [u8; 16], limits: Limits) -> (Self, JoinHandle<()>) {
        let inner = Rc::new(Inner {
            key,
            limits,
            cores: ends.cores(),
            owner: RefCell::new(Owner::new(limits)),
            peers: OnceCell::new(),
            waiting: RefCell::new(BTreeMap::new()),
            tickets: Cell::new(0),
            sessions: Cell::new(0),
            refused: Cell::new(0),
            reserved: Cell::new(0),
            peak: Cell::new(0),
            busy: Cell::new(0),
            unanswered: Cell::new(0),
        });
        let guard = Self { inner };
        let handler = Rc::clone(&guard.inner);
        let (peers, done) = ends.start(move |from, Ask(message)| handle(&handler, from, message));
        let _ = guard.inner.peers.set(peers);
        (guard, done)
    }

    pub fn close(&self) {
        self.inner.waiting.borrow_mut().clear();
        if let Some(peers) = self.inner.peers.get() {
            peers.close();
        }
    }

    pub fn limits(&self) -> Limits {
        self.inner.limits
    }

    pub fn admit(&self) -> Option<Admitted> {
        let inner = &self.inner;
        if inner.sessions.get() >= inner.limits.sessions {
            inner.refused.set(inner.refused.get() + 1);
            return None;
        }
        inner.sessions.set(inner.sessions.get() + 1);
        Some(Admitted {
            inner: Rc::clone(inner),
        })
    }

    pub fn reserve(&self, bytes: usize) -> Option<Reserved> {
        let inner = &self.inner;
        let total = inner.reserved.get() + bytes;
        if total > inner.limits.budget {
            inner.busy.set(inner.busy.get() + 1);
            return None;
        }
        inner.reserved.set(total);
        inner.peak.set(inner.peak.get().max(total));
        Some(Reserved {
            inner: Rc::clone(inner),
            bytes,
        })
    }

    pub async fn open(&self, ip: IpAddr) -> Result<Slot, Refused> {
        let (net, wide) = Prefix::of(ip);
        let owner = self.owner(&wide.hashed());
        self.slot(owner, Request::Open { net, wide }, Request::Close { net })
            .await
    }

    pub async fn open_tenant(&self, tenant: u32, limit: u32) -> Result<Slot, Refused> {
        let owner = self.owner(&tenant_bytes(tenant));
        self.slot(
            owner,
            Request::OpenTenant { tenant, limit },
            Request::CloseTenant { tenant },
        )
        .await
    }

    pub async fn failed(&self, ip: IpAddr) -> Result<bool, Refused> {
        let (net, wide) = Prefix::of(ip);
        let owner = self.owner(&wide.hashed());
        let reply = Once::new();
        let ticket = self.inner.wait(Waiter::Failed(reply.handle()));
        self.inner
            .send_ticket(owner, ticket, Request::Failed { net, wide });
        self.answer(reply).await
    }

    pub fn stats(&self) -> GuardStats {
        let inner = &self.inner;
        GuardStats {
            sessions: inner.sessions.get(),
            refused: inner.refused.get(),
            reserved: inner.reserved.get(),
            peak: inner.peak.get(),
            busy: inner.busy.get(),
            unanswered: inner.unanswered.get(),
            waiting: inner.waiting.borrow().len(),
            owner: inner.owner.borrow().stats(),
        }
    }

    async fn slot(&self, owner: u16, open: Request, close: Request) -> Result<Slot, Refused> {
        let reply = Once::new();
        let ticket = self.inner.wait(Waiter::Slot {
            reply: reply.handle(),
            owner,
            close,
        });
        self.inner.send_ticket(owner, ticket, open);
        self.answer(reply).await?
    }

    async fn answer<T>(&self, reply: Once<T>) -> Result<T, Refused> {
        if let Ok(value) = timeout(self.inner.limits.ask, reply.get()).await {
            return Ok(value);
        }
        self.inner.unanswered.set(self.inner.unanswered.get() + 1);
        Err(Refused::Unanswered)
    }

    fn owner(&self, bytes: &[u8]) -> u16 {
        let cores = u64::from(self.inner.cores.max(1));
        u16::try_from(siphash(&self.inner.key, bytes) % cores).expect("core fits in u16")
    }
}

impl Inner {
    fn wait(&self, waiter: Waiter) -> u64 {
        let ticket = self.tickets.get().wrapping_add(1);
        self.tickets.set(ticket);
        self.waiting.borrow_mut().insert(ticket, waiter);
        ticket
    }

    fn send_ticket(&self, owner: u16, ticket: u64, request: Request) {
        if let Some(peers) = self.peers.get() {
            peers.send(owner, Ask(Message::Ask { ticket, request }));
        }
    }

    fn send(&self, owner: u16, request: Request) {
        self.send_ticket(owner, 0, request);
    }
}

fn handle(inner: &Rc<Inner>, from: u16, message: Message) {
    match message {
        Message::Ask { ticket, request } => {
            let answer = {
                let mut owner = inner.owner.borrow_mut();
                let at = now();
                match request {
                    Request::Open { net, wide } => Some(Answer::Opened(owner.open(net, wide, at))),
                    Request::Close { net } => {
                        owner.close(net, at);
                        None
                    }
                    Request::Failed { net, wide } => {
                        Some(Answer::Failed(owner.failed(net, wide, at)))
                    }
                    Request::OpenTenant { tenant, limit } => {
                        Some(Answer::Opened(owner.open_tenant(tenant, limit)))
                    }
                    Request::CloseTenant { tenant } => {
                        owner.close_tenant(tenant);
                        None
                    }
                }
            };
            if let (Some(answer), Some(peers)) = (answer, inner.peers.get()) {
                peers.send(from, Ask(Message::Answer { ticket, answer }));
            }
        }
        Message::Answer { ticket, answer } => {
            let waiter = inner.waiting.borrow_mut().remove(&ticket);
            match (waiter, answer) {
                (
                    Some(Waiter::Slot {
                        reply,
                        owner,
                        close,
                    }),
                    Answer::Opened(opened),
                ) => reply.put(match opened {
                    Opened::Ok => Ok(Slot {
                        inner: Rc::clone(inner),
                        owner,
                        close,
                    }),
                    Opened::Full => Err(Refused::Full),
                    Opened::Banned => Err(Refused::Banned),
                }),
                (Some(Waiter::Failed(reply)), Answer::Failed(banned)) => reply.put(banned),
                _ => {}
            }
        }
    }
}

fn tenant_bytes(tenant: u32) -> [u8; 5] {
    let mut out = [2; 5];
    out[1..].copy_from_slice(&tenant.to_le_bytes());
    out
}
