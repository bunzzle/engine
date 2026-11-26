use std::cell::{Cell, OnceCell, RefCell};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::rc::{Rc, Weak};
use std::time::Duration;

use control::{Queue, State};
use rt::{Ends, JoinHandle, Peers, Sender, channel, spawn, timeout};

use crate::lanes::{QueueId, Waiting};
use crate::node::queue_core;
use crate::start::{Inner, Node};
use crate::transport::{SiteRow, Transport};

pub const QUEUE_PAGE: usize = 200;
pub const SITE_PAGE: usize = 500;
const ANSWER: Duration = Duration::from_secs(60);

pub struct Desk(Message);

enum Message {
    Ask { ticket: u64, request: Request },
    Answer { ticket: u64, answer: Answer },
}

enum Request {
    List {
        tenant: u32,
        from: u32,
        limit: usize,
    },
    Retry {
        tenant: u32,
        queue: QueueId,
    },
    Rebind {
        tenant: u32,
        queue: QueueId,
        pool: u32,
    },
    Sites {
        from: Option<(Box<str>, IpAddr)>,
        limit: usize,
    },
}

enum Answer {
    Listed(Vec<Row>),
    Done(Result<Done, QueueRefusal>),
    Sites(Vec<SiteRow>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub id: QueueId,
    pub domain: Box<str>,
    pub generation: u32,
    pub pool: u32,
    pub draining: bool,
    pub waiting: Waiting,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueuePage {
    pub rows: Vec<Row>,
    pub next: Option<QueueId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SitePage {
    pub rows: Vec<SiteRow>,
    pub next: Option<(Box<str>, IpAddr)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Done {
    Retried(u64),
    Rebound(QueueId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueueRefusal {
    NotFound,
    Tenant,
    Pool,
    Draining,
    Unanswered,
    Failed(Box<str>),
}

pub(crate) struct Desks<T> {
    cores: u16,
    shards: u32,
    node: OnceCell<Weak<Inner<T>>>,
    peers: OnceCell<Peers<Desk>>,
    waiting: RefCell<BTreeMap<u64, Sender<Answer>>>,
    tickets: Cell<u64>,
    closed: Cell<bool>,
}

impl<T: Transport + 'static> Desks<T> {
    pub(crate) fn start(ends: Ends<Desk>, shards: u32) -> (Rc<Self>, JoinHandle<()>) {
        let desks = Rc::new(Self {
            cores: ends.cores(),
            shards,
            node: OnceCell::new(),
            peers: OnceCell::new(),
            waiting: RefCell::new(BTreeMap::new()),
            tickets: Cell::new(0),
            closed: Cell::new(false),
        });
        let handler = Rc::clone(&desks);
        let (peers, done) = ends.start(move |from, Desk(message)| handler.handle(from, message));
        let _ = desks.peers.set(peers);
        (desks, done)
    }

    pub(crate) fn use_node(&self, node: Weak<Inner<T>>) {
        let _ = self.node.set(node);
    }

    pub(crate) fn close(&self) {
        self.closed.set(true);
        self.waiting.borrow_mut().clear();
        if let Some(peers) = self.peers.get() {
            peers.close();
        }
    }

    fn send(&self, core: u16, request: Request) -> (u64, rt::Receiver<Answer>) {
        let (reply, answer) = channel();
        let ticket = self.tickets.get();
        self.tickets.set(ticket + 1);
        if self.closed.get() {
            return (ticket, answer);
        }
        self.waiting.borrow_mut().insert(ticket, reply);
        if let Some(peers) = self.peers.get() {
            peers.send(core, Desk(Message::Ask { ticket, request }));
        }
        (ticket, answer)
    }

    async fn answer(&self, (ticket, mut answer): (u64, rt::Receiver<Answer>)) -> Option<Answer> {
        let got = timeout(ANSWER, answer.recv()).await.ok().flatten();
        self.waiting.borrow_mut().remove(&ticket);
        got
    }

    fn handle(self: &Rc<Self>, from: u16, message: Message) {
        match message {
            Message::Ask { ticket, request } => {
                let desks = Rc::clone(self);
                drop(spawn(async move {
                    let answer = if desks.closed.get() {
                        Answer::Done(Err(QueueRefusal::Unanswered))
                    } else {
                        desks.serve(request).await
                    };
                    if let Some(peers) = desks.peers.get() {
                        peers.send(from, Desk(Message::Answer { ticket, answer }));
                    }
                }));
            }
            Message::Answer { ticket, answer } => {
                if let Some(reply) = self.waiting.borrow_mut().remove(&ticket) {
                    let _ = reply.send(answer);
                }
            }
        }
    }

    async fn serve(&self, request: Request) -> Answer {
        let Some(node) = self
            .node
            .get()
            .and_then(Weak::upgrade)
            .map(|inner| Node { inner })
        else {
            return Answer::Done(Err(QueueRefusal::Unanswered));
        };
        match request {
            Request::List {
                tenant,
                from,
                limit,
            } => Answer::Listed(listed(&node, tenant, from, limit)),
            Request::Retry { tenant, queue } => Answer::Done(retried(&node, tenant, queue)),
            Request::Rebind {
                tenant,
                queue,
                pool,
            } => Answer::Done(rebound(&node, tenant, queue, pool).await),
            Request::Sites { from, limit } => Answer::Sites(sited(&node, from.as_ref(), limit)),
        }
    }
}

fn sited<T: Transport + 'static>(
    node: &Node<T>,
    from: Option<&(Box<str>, IpAddr)>,
    limit: usize,
) -> Vec<SiteRow> {
    let mut rows = node.inner.sched.transport().sites();
    rows.retain(|row| from.is_none_or(|(site, egress)| (&row.site, row.egress) >= (site, *egress)));
    rows.sort_by(|a, b| (&a.site, a.egress).cmp(&(&b.site, b.egress)));
    rows.truncate(limit);
    rows
}

fn listed<T: Transport + 'static>(
    node: &Node<T>,
    tenant: u32,
    from: u32,
    limit: usize,
) -> Vec<Row> {
    let table = Rc::clone(&node.inner.table);
    let live = move |queue: &Queue| !table.borrow().gone(tenant, queue.name.generation);
    node.inner
        .queues
        .tenant_queues(tenant, from, limit, &live)
        .into_iter()
        .map(|queue| Row {
            waiting: node
                .inner
                .sched
                .waiting(queue.id, tenant)
                .unwrap_or_default(),
            id: queue.id,
            domain: queue.name.domain,
            generation: queue.name.generation,
            pool: queue.name.pool,
            draining: queue.draining,
        })
        .collect()
}

fn owned<T: Transport + 'static>(
    node: &Node<T>,
    tenant: u32,
    queue: QueueId,
) -> Result<Queue, QueueRefusal> {
    let found = node
        .inner
        .queues
        .queue(queue)
        .filter(|q| q.name.tenant == tenant)
        .ok_or(QueueRefusal::NotFound)?;
    let table = node.inner.table.borrow();
    if table.gone(tenant, found.name.generation) {
        return Err(QueueRefusal::NotFound);
    }
    let current = table
        .tenant(tenant)
        .filter(|t| t.generation == found.name.generation)
        .ok_or(QueueRefusal::NotFound)?;
    if current.state != State::Active {
        return Err(QueueRefusal::Tenant);
    }
    Ok(found)
}

fn retried<T: Transport + 'static>(
    node: &Node<T>,
    tenant: u32,
    queue: QueueId,
) -> Result<Done, QueueRefusal> {
    owned(node, tenant, queue)?;
    let waiting = node
        .inner
        .sched
        .waiting(queue, tenant)
        .unwrap_or_default()
        .recipients;
    node.inner.sched.retry_queue(queue, tenant);
    Ok(Done::Retried(waiting))
}

async fn rebound<T: Transport + 'static>(
    node: &Node<T>,
    tenant: u32,
    queue: QueueId,
    pool: u32,
) -> Result<Done, QueueRefusal> {
    let found = owned(node, tenant, queue)?;
    if found.draining {
        return Err(QueueRefusal::Draining);
    }
    let allowed = {
        let table = node.inner.table.borrow();
        table.pool(pool).is_some()
            && table
                .tenant(tenant)
                .is_some_and(|t| t.pools.contains(&pool))
    };
    if !allowed {
        return Err(QueueRefusal::Pool);
    }
    match node
        .inner
        .queues
        .rebind_queue(queue, &found.name, pool)
        .await
    {
        Ok(id) => Ok(Done::Rebound(id)),
        Err(control::Error::Invalid("queue")) => Err(QueueRefusal::NotFound),
        Err(error) => Err(QueueRefusal::Failed(error.to_string().into())),
    }
}

impl<T: Transport + 'static> Node<T> {
    pub async fn queue_list(&self, tenant: u32, from: u32) -> Result<QueuePage, QueueRefusal> {
        let desks = &self.inner.desks;
        let asked: Vec<_> = (0..desks.cores)
            .map(|core| {
                desks.send(
                    core,
                    Request::List {
                        tenant,
                        from,
                        limit: QUEUE_PAGE + 1,
                    },
                )
            })
            .collect();
        let mut rows = Vec::new();
        let mut failed = false;
        for asked in asked {
            match desks.answer(asked).await {
                Some(Answer::Listed(found)) => rows.extend(found),
                _ => failed = true,
            }
        }
        if failed {
            return Err(QueueRefusal::Unanswered);
        }
        rows.sort_by_key(|row| row.id);
        let next = rows.get(QUEUE_PAGE).map(|row| row.id);
        rows.truncate(QUEUE_PAGE);
        Ok(QueuePage { rows, next })
    }

    pub async fn queue_retry(&self, tenant: u32, queue: QueueId) -> Result<Done, QueueRefusal> {
        self.ask_owner(queue, Request::Retry { tenant, queue })
            .await
    }

    pub async fn queue_rebind(
        &self,
        tenant: u32,
        queue: QueueId,
        pool: u32,
    ) -> Result<Done, QueueRefusal> {
        self.ask_owner(
            queue,
            Request::Rebind {
                tenant,
                queue,
                pool,
            },
        )
        .await
    }

    pub async fn site_list(
        &self,
        from: Option<(Box<str>, IpAddr)>,
    ) -> Result<SitePage, QueueRefusal> {
        let desks = &self.inner.desks;
        let asked: Vec<_> = (0..desks.cores)
            .map(|core| {
                desks.send(
                    core,
                    Request::Sites {
                        from: from.clone(),
                        limit: SITE_PAGE + 1,
                    },
                )
            })
            .collect();
        let mut rows = Vec::new();
        let mut failed = false;
        for asked in asked {
            match desks.answer(asked).await {
                Some(Answer::Sites(found)) => rows.extend(found),
                _ => failed = true,
            }
        }
        if failed {
            return Err(QueueRefusal::Unanswered);
        }
        rows.sort_by(|a, b| (&a.site, a.egress).cmp(&(&b.site, b.egress)));
        let next = rows
            .get(SITE_PAGE)
            .map(|row| (row.site.clone(), row.egress));
        rows.truncate(SITE_PAGE);
        Ok(SitePage { rows, next })
    }

    pub fn site_pause(&self, egress: IpAddr, site: &str, on: bool) -> bool {
        self.inner.sched.transport().pause_site(egress, site, on)
    }

    async fn ask_owner(&self, queue: QueueId, request: Request) -> Result<Done, QueueRefusal> {
        let desks = &self.inner.desks;
        let core = queue_core(queue, desks.shards, desks.cores);
        match desks.answer(desks.send(core, request)).await {
            Some(Answer::Done(done)) => done,
            _ => Err(QueueRefusal::Unanswered),
        }
    }
}
