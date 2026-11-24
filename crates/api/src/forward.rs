use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};

use control::Grant;
use http::{Request, Response};
use intake::End;
use rt::{Ends, JoinHandle, Notify, Peers};

use crate::handler::Source;
use crate::server::{Route, Stop};

pub struct Forward(Message);

enum Message {
    Open { ticket: u64, open: Box<Open> },
    Ahead { ticket: u64, ahead: Ahead },
    Back { ticket: u64, back: Back },
}

pub(crate) struct Open {
    pub(crate) route: Route,
    pub(crate) request: Request,
    pub(crate) grant: Grant,
    pub(crate) id: String,
    pub(crate) secure: bool,
    pub(crate) shard: u16,
}

pub(crate) enum Ahead {
    Chunk(Vec<u8>),
    End,
    Abort,
}

pub(crate) enum Back {
    Start(u64),
    Credit,
    Reply(Box<Response>),
}

pub(crate) struct Pipe<M> {
    queue: RefCell<VecDeque<M>>,
    notify: Notify,
    closed: Cell<bool>,
}

impl<M> Pipe<M> {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            queue: RefCell::new(VecDeque::new()),
            notify: Notify::default(),
            closed: Cell::new(false),
        })
    }

    fn put(&self, message: M) {
        self.queue.borrow_mut().push_back(message);
        self.notify.notify();
    }

    fn close(&self) {
        self.closed.set(true);
        self.notify.notify();
    }

    pub(crate) fn try_take(&self) -> Option<M> {
        self.queue.borrow_mut().pop_front()
    }

    pub(crate) async fn take(&self) -> Option<M> {
        loop {
            if let Some(message) = self.try_take() {
                return Some(message);
            }
            if self.closed.get() {
                return None;
            }
            self.notify.wait().await;
        }
    }
}

type Inbounds = BTreeMap<(u16, u64), Rc<Pipe<Ahead>>>;

pub(crate) type Serve = Box<dyn Fn(Rc<Inbound>, Box<Open>) -> JoinHandle<()>>;

pub(crate) struct Forwarder {
    cores: u16,
    peers: OnceCell<Peers<Forward>>,
    tickets: Cell<u64>,
    outbound: RefCell<BTreeMap<u64, Rc<Pipe<Back>>>>,
    inbound: RefCell<Inbounds>,
    serve: RefCell<Option<Serve>>,
    closing: Cell<bool>,
    serving: Cell<usize>,
    idle: Notify,
    waiting: RefCell<BTreeMap<(u16, u64), Waker>>,
    aborted: RefCell<BTreeSet<(u16, u64)>>,
    stopped: Cell<bool>,
    forwarded: Cell<u64>,
    served: Cell<u64>,
}

impl Forwarder {
    pub(crate) fn start(ends: Ends<Forward>) -> (Rc<Self>, JoinHandle<()>) {
        let forwarder = Rc::new(Self {
            cores: ends.cores(),
            peers: OnceCell::new(),
            tickets: Cell::new(0),
            outbound: RefCell::new(BTreeMap::new()),
            inbound: RefCell::new(BTreeMap::new()),
            serve: RefCell::new(None),
            closing: Cell::new(false),
            serving: Cell::new(0),
            idle: Notify::default(),
            waiting: RefCell::new(BTreeMap::new()),
            aborted: RefCell::new(BTreeSet::new()),
            stopped: Cell::new(false),
            forwarded: Cell::new(0),
            served: Cell::new(0),
        });
        let handler = Rc::clone(&forwarder);
        let (peers, done) = ends.start(move |from, Forward(message)| handler.handle(from, message));
        let _ = forwarder.peers.set(peers);
        (forwarder, done)
    }

    pub(crate) fn serve_with(&self, serve: Serve) {
        self.serve.replace(Some(serve));
    }

    pub(crate) fn index(&self) -> u16 {
        self.peers.get().map_or(0, Peers::index)
    }

    pub(crate) fn owner(&self, shard: u16) -> u16 {
        shard % self.cores.max(1)
    }

    pub(crate) fn forwarded(&self) -> u64 {
        self.forwarded.get()
    }

    pub(crate) fn served(&self) -> u64 {
        self.served.get()
    }

    pub(crate) fn serving(&self) -> usize {
        self.serving.get()
    }

    pub(crate) fn open(self: &Rc<Self>, owner: u16, open: Open) -> Link {
        let ticket = self.tickets.get().wrapping_add(1);
        self.tickets.set(ticket);
        let pipe = Pipe::new();
        if self.closing.get() {
            pipe.close();
        } else {
            self.outbound.borrow_mut().insert(ticket, Rc::clone(&pipe));
            self.forwarded.set(self.forwarded.get() + 1);
            self.send(
                owner,
                Message::Open {
                    ticket,
                    open: Box::new(open),
                },
            );
        }
        Link {
            forwarder: Rc::clone(self),
            owner,
            ticket,
            pipe,
            done: false,
        }
    }

    fn send(&self, to: u16, message: Message) {
        if let Some(peers) = self.peers.get() {
            peers.send(to, Forward(message));
        }
    }

    fn handle(self: &Rc<Self>, from: u16, message: Message) {
        match message {
            Message::Open { ticket, open } => self.accept(from, ticket, open),
            Message::Ahead { ticket, ahead } => {
                let key = (from, ticket);
                if let Some(pipe) = self.inbound.borrow().get(&key) {
                    if matches!(ahead, Ahead::Abort) {
                        self.aborted.borrow_mut().insert(key);
                        if let Some(waker) = self.waiting.borrow_mut().remove(&key) {
                            waker.wake();
                        }
                    }
                    pipe.put(ahead);
                }
            }
            Message::Back { ticket, back } => {
                if let Some(pipe) = self.outbound.borrow().get(&ticket) {
                    pipe.put(back);
                }
            }
        }
    }

    fn accept(self: &Rc<Self>, from: u16, ticket: u64, open: Box<Open>) {
        let serve = self.serve.borrow();
        let Some(serve) = serve.as_ref().filter(|_| !self.closing.get()) else {
            self.send(
                from,
                Message::Back {
                    ticket,
                    back: Back::Reply(Box::new(unavailable(&open.id))),
                },
            );
            return;
        };
        let pipe = Pipe::new();
        self.inbound
            .borrow_mut()
            .insert((from, ticket), Rc::clone(&pipe));
        self.serving.set(self.serving.get() + 1);
        self.served.set(self.served.get() + 1);
        let inbound = Rc::new(Inbound {
            forwarder: Rc::clone(self),
            from,
            ticket,
            pipe,
            secure: open.secure,
            id: open.id.clone(),
            replied: Cell::new(false),
        });
        drop(serve(inbound, open));
    }

    pub(crate) async fn until_stopped<F: Future<Output = ()>>(
        &self,
        key: (u16, u64),
        abortable: bool,
        work: F,
    ) {
        let mut work = std::pin::pin!(work);
        poll_fn(|cx| {
            if self.stopped.get() || (abortable && self.aborted.borrow().contains(&key)) {
                return Poll::Ready(());
            }
            if work.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            self.waiting.borrow_mut().insert(key, cx.waker().clone());
            Poll::Pending
        })
        .await;
        self.waiting.borrow_mut().remove(&key);
        self.aborted.borrow_mut().remove(&key);
    }

    pub(crate) async fn close(&self, drain: std::time::Duration) {
        self.closing.set(true);
        self.serve.replace(None);
        if rt::timeout(drain, self.idle()).await.is_err() {
            self.stopped.set(true);
            for waker in std::mem::take(&mut *self.waiting.borrow_mut()).into_values() {
                waker.wake();
            }
            self.idle().await;
        }
        for pipe in std::mem::take(&mut *self.outbound.borrow_mut()).into_values() {
            pipe.close();
        }
        if let Some(peers) = self.peers.get() {
            peers.close();
        }
    }

    async fn idle(&self) {
        while self.serving.get() > 0 {
            self.idle.wait().await;
        }
    }
}

fn unavailable(id: &str) -> Response {
    crate::problem::Problem::unavailable().response(id)
}

pub(crate) struct Link {
    forwarder: Rc<Forwarder>,
    owner: u16,
    ticket: u64,
    pipe: Rc<Pipe<Back>>,
    done: bool,
}

impl Link {
    pub(crate) fn send(&self, ahead: Ahead) {
        self.forwarder.send(
            self.owner,
            Message::Ahead {
                ticket: self.ticket,
                ahead,
            },
        );
    }

    pub(crate) fn pipe(&self) -> &Pipe<Back> {
        &self.pipe
    }

    pub(crate) fn replied(&self) -> bool {
        self.pipe.closed.get()
            || self
                .pipe
                .queue
                .borrow()
                .iter()
                .any(|back| matches!(back, Back::Reply(_)))
    }

    pub(crate) async fn reply(&self) {
        while !self.replied() {
            self.pipe.notify.wait().await;
        }
    }

    pub(crate) fn done(&mut self) {
        self.done = true;
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.forwarder.outbound.borrow_mut().remove(&self.ticket);
        if !self.done && !self.pipe.closed.get() {
            self.send(Ahead::Abort);
        }
    }
}

pub(crate) struct Inbound {
    forwarder: Rc<Forwarder>,
    from: u16,
    ticket: u64,
    pipe: Rc<Pipe<Ahead>>,
    secure: bool,
    id: String,
    replied: Cell<bool>,
}

impl Inbound {
    pub(crate) fn key(&self) -> (u16, u64) {
        (self.from, self.ticket)
    }

    pub(crate) fn secure(&self) -> bool {
        self.secure
    }

    pub(crate) fn pipe(&self) -> &Pipe<Ahead> {
        &self.pipe
    }

    pub(crate) fn reply(&self, response: Response) {
        self.replied.set(true);
        self.send(Back::Reply(Box::new(response)));
    }

    pub(crate) fn send(&self, back: Back) {
        self.forwarder.send(
            self.from,
            Message::Back {
                ticket: self.ticket,
                back,
            },
        );
    }
}

impl Drop for Inbound {
    fn drop(&mut self) {
        if !self.replied.get() {
            self.reply(unavailable(&self.id));
        }
        let forwarder = &self.forwarder;
        forwarder
            .inbound
            .borrow_mut()
            .remove(&(self.from, self.ticket));
        forwarder
            .aborted
            .borrow_mut()
            .remove(&(self.from, self.ticket));
        forwarder.serving.set(forwarder.serving.get() - 1);
        if forwarder.serving.get() == 0 {
            forwarder.idle.notify();
        }
    }
}

pub(crate) struct Remote {
    inbound: Rc<Inbound>,
    owed: bool,
    wait: std::time::Duration,
}

impl Remote {
    pub(crate) fn new(inbound: Rc<Inbound>, wait: std::time::Duration) -> Self {
        Self {
            inbound,
            owed: false,
            wait,
        }
    }
}

impl Source for Remote {
    fn start(&mut self, _request: &Request, max: u64) -> Result<(), Stop> {
        self.inbound.send(Back::Start(max));
        Ok(())
    }

    async fn next(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        if std::mem::take(&mut self.owed) {
            self.inbound.send(Back::Credit);
        }
        match rt::timeout(self.wait, self.inbound.pipe().take()).await {
            Ok(Some(Ahead::Chunk(bytes))) => {
                self.owed = true;
                Ok(Some(bytes))
            }
            Ok(Some(Ahead::End)) => Ok(None),
            Ok(Some(Ahead::Abort) | None) => Err(Stop::End(End::Dropped)),
            Err(_) => Err(Stop::End(End::Timeout)),
        }
    }

    fn secure(&self) -> bool {
        self.inbound.secure()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;
    use std::time::Duration;

    use control::Grant;
    use http::{Framing, Headers, Request, Status};
    use rt::sim::{Config, Machine, SimDriver, Stalls};
    use rt::{Mesh, sleep, spawn};

    use super::{Ahead, Back, Forwarder, Link, Open};
    use crate::server::Route;

    struct Held(Rc<Cell<bool>>);

    impl Drop for Held {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    struct Waiting {
        machine: Machine,
        owner: Rc<Forwarder>,
        link: Link,
        dropped: Rc<Cell<bool>>,
    }

    fn open(method: &str) -> Open {
        Open {
            route: Route::Status,
            request: Request {
                method: method.into(),
                path: "/v1/messages/m".into(),
                query: None,
                headers: Headers::default(),
                body: Framing::None,
                expect: false,
                close: false,
            },
            grant: Grant {
                access: 1,
                tenant: 1,
                generation: 1,
                pool: 0,
            },
            id: "r1".into(),
            secure: false,
            shard: 1,
        }
    }

    async fn until(what: impl Fn() -> bool) {
        for _ in 0..1000 {
            if what() {
                return;
            }
            sleep(Duration::from_millis(1)).await;
        }
        panic!("not reached");
    }

    fn aborted_while_waiting(method: &'static str) -> Waiting {
        let machine = Machine::new(
            Rc::new(SimDriver::new(7, Config::default())),
            2,
            Stalls::default(),
        );
        let mesh = Mesh::new(2);
        let front = mesh.take(0).expect("ends");
        let owner = mesh.take(1).expect("ends");
        let dropped = Rc::new(Cell::new(false));
        let started = Rc::new(Cell::new(false));
        let (held, began) = (Rc::clone(&dropped), Rc::clone(&started));
        let owner = machine.block_on(1, async move {
            let (owner, done) = Forwarder::start(owner);
            drop(done);
            owner.serve_with(Box::new(move |inbound, open| {
                let abortable = open.request.method == "GET";
                let (held, began) = (Held(Rc::clone(&held)), Rc::clone(&began));
                spawn(async move {
                    let forwarder = Rc::clone(&inbound.forwarder);
                    let work = async move {
                        let _held = held;
                        began.set(true);
                        std::future::pending::<()>().await;
                    };
                    forwarder
                        .until_stopped(inbound.key(), abortable, work)
                        .await;
                    drop(inbound);
                })
            }));
            owner
        });
        let watched = Rc::clone(&owner);
        let link = machine.block_on(0, async move {
            let (front, done) = Forwarder::start(front);
            drop(done);
            let link = front.open(1, open(method));
            until(|| started.get()).await;
            assert_eq!(watched.waiting.borrow().len(), 1);
            link.send(Ahead::Abort);
            link
        });
        Waiting {
            machine,
            owner,
            link,
            dropped,
        }
    }

    async fn unavailable(link: Link) {
        link.reply().await;
        let Some(Back::Reply(reply)) = link.pipe().try_take() else {
            panic!("no reply");
        };
        assert_eq!(reply.status(), Status::UNAVAILABLE);
    }

    #[test]
    fn an_abort_ends_a_forwarded_read_already_waiting_on_the_owner() {
        let Waiting {
            machine,
            owner,
            link,
            dropped,
        } = aborted_while_waiting("GET");
        let watched = Rc::clone(&owner);
        machine.block_on(0, async move {
            unavailable(link).await;
            assert!(dropped.get());
            until(|| watched.serving() == 0).await;
        });
        assert!(owner.aborted.borrow().is_empty());
        assert!(owner.waiting.borrow().is_empty());
        assert!(owner.inbound.borrow().is_empty());
    }

    #[test]
    fn an_abort_leaves_a_forwarded_write_running_until_close() {
        let Waiting {
            machine,
            owner,
            link,
            dropped,
        } = aborted_while_waiting("POST");
        let (watched, held) = (Rc::clone(&owner), Rc::clone(&dropped));
        let link = machine.block_on(0, async move {
            sleep(Duration::from_secs(5)).await;
            assert!(!held.get());
            assert_eq!(watched.serving(), 1);
            assert!(!link.replied());
            link
        });
        let closing = Rc::clone(&owner);
        machine.block_on(1, async move {
            closing.close(Duration::from_millis(100)).await;
        });
        machine.block_on(0, async move {
            unavailable(link).await;
        });
        assert!(dropped.get());
        assert_eq!(owner.serving(), 0);
        assert!(owner.aborted.borrow().is_empty());
        assert!(owner.waiting.borrow().is_empty());
    }
}
