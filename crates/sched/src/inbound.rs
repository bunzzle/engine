use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;

use control::Table;
use rt::{Ends, JoinHandle, Peers, Sender, channel, spawn, timeout};
use spool::{MessageId, Spool};
use store::{Changes, Claim};

use crate::clock::Clock;
use crate::error::Refusal;
use crate::events::{self, Body, Event, Kind};
use crate::finder::{self, Query, SEARCH_LIMIT, Scan};
use crate::gate::Gate;
use crate::normal::normalize;
use crate::requests::DAY;
use crate::sealing::{Keys, Opener, Unsealable, event_opener};
use crate::search::{self, DayKeys, Field};
use crate::start::Node;
use crate::suppress::Suppressions;
use crate::transport::Transport;

const DEADLINE: Duration = Duration::from_secs(30);
const DONE_LIMIT: usize = 1024;
const SKEW: u64 = 3_600_000;
const RUNNING: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportKind {
    Bounce,
    Complaint,
}

impl ReportKind {
    fn event(self) -> Kind {
        match self {
            Self::Bounce => Kind::Bounced,
            Self::Complaint => Kind::Complained,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub address: Option<String>,
    pub status: (u8, u16, u16),
    pub diagnostic: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    pub tenant: u32,
    pub generation: u32,
    pub message: MessageId,
    pub recipient: u32,
    pub kind: ReportKind,
    pub blocks: Vec<Block>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Written(usize),
    Duplicate,
    Unmatched,
}

pub(crate) struct Inputs {
    pub keys: Rc<dyn Keys>,
    pub changes: Changes,
    pub table: Rc<RefCell<Table>>,
    pub clock: Clock,
    pub spool: Spool,
    pub suppressions: Suppressions,
}

pub(crate) struct Ask(Message);

enum Message {
    Ask {
        ticket: u64,
        inbound: Inbound,
    },
    Answer {
        ticket: u64,
        outcome: Result<Outcome, Refusal>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Done {
    tenant: u32,
    message: MessageId,
    recipient: u32,
    kind: ReportKind,
}

struct Inner {
    parts: Inputs,
    cores: u16,
    peers: OnceCell<Peers<Ask>>,
    waiting: RefCell<BTreeMap<u64, Sender<Result<Outcome, Refusal>>>>,
    tickets: Cell<u64>,
    running: Cell<usize>,
    locks: Gate<(u32, MessageId)>,
    done: RefCell<VecDeque<Done>>,
}

#[derive(Clone)]
pub(crate) struct Reports {
    inner: Rc<Inner>,
}

impl Reports {
    pub fn start(ends: Ends<Ask>, parts: Inputs) -> (Self, JoinHandle<()>) {
        let reports = Self {
            inner: Rc::new(Inner {
                parts,
                cores: ends.cores(),
                peers: OnceCell::new(),
                waiting: RefCell::new(BTreeMap::new()),
                tickets: Cell::new(0),
                running: Cell::new(0),
                locks: Gate::default(),
                done: RefCell::new(VecDeque::new()),
            }),
        };
        let handler = reports.clone();
        let (peers, done) = ends.start(move |from, Ask(message)| handler.handle(from, message));
        let _ = reports.inner.peers.set(peers);
        (reports, done)
    }

    pub fn close(&self) {
        self.inner.waiting.borrow_mut().clear();
        if let Some(peers) = self.inner.peers.get() {
            peers.close();
        }
    }

    async fn report(&self, inbound: Inbound) -> Result<Outcome, Refusal> {
        let core = inbound.message.shard % self.inner.cores;
        let (reply, mut answer) = channel();
        let ticket = self.inner.tickets.get();
        self.inner.tickets.set(ticket + 1);
        self.inner.waiting.borrow_mut().insert(ticket, reply);
        if let Some(peers) = self.inner.peers.get() {
            peers.send(core, Ask(Message::Ask { ticket, inbound }));
        }
        answer.recv().await.ok_or(Refusal::Failed)?
    }

    fn handle(&self, from: u16, message: Message) {
        match message {
            Message::Ask { ticket, inbound } => {
                let reports = self.clone();
                let running = &self.inner.running;
                if running.get() >= RUNNING {
                    if let Some(peers) = self.inner.peers.get() {
                        let outcome = Err(Refusal::Busy);
                        peers.send(from, Ask(Message::Answer { ticket, outcome }));
                    }
                    return;
                }
                running.set(running.get() + 1);
                drop(spawn(async move {
                    let outcome = reports.serve(inbound).await;
                    let running = &reports.inner.running;
                    running.set(running.get() - 1);
                    if let Some(peers) = reports.inner.peers.get() {
                        peers.send(from, Ask(Message::Answer { ticket, outcome }));
                    }
                }));
            }
            Message::Answer { ticket, outcome } => {
                if let Some(reply) = self.inner.waiting.borrow_mut().remove(&ticket) {
                    let _ = reply.send(outcome);
                }
            }
        }
    }

    async fn serve(&self, inbound: Inbound) -> Result<Outcome, Refusal> {
        let done = Done {
            tenant: inbound.tenant,
            message: inbound.message,
            recipient: inbound.recipient,
            kind: inbound.kind,
        };
        let cache = inbound.recipient != crypto::ANY;
        if cache && self.cached(done) {
            return Ok(Outcome::Duplicate);
        }
        let lock = self.inner.locks.lock((inbound.tenant, inbound.message));
        let _guard = timeout(DEADLINE, lock).await.map_err(|_| Refusal::Busy)?;
        if cache && self.cached(done) {
            return Ok(Outcome::Duplicate);
        }
        let outcome = self.process(&inbound).await?;
        if cache && outcome != Outcome::Unmatched {
            self.done(done);
        }
        Ok(outcome)
    }

    fn cached(&self, done: Done) -> bool {
        self.inner.done.borrow().contains(&done)
    }

    fn done(&self, done: Done) {
        let mut completed = self.inner.done.borrow_mut();
        if completed.contains(&done) {
            return;
        }
        if completed.len() == DONE_LIMIT {
            completed.pop_front();
        }
        completed.push_back(done);
    }

    fn holds(&self, tenant: u32, generation: u32) -> Result<(), Refusal> {
        self.inner
            .parts
            .table
            .borrow()
            .tenant(tenant)
            .filter(|tenant| tenant.generation == generation && !tenant.state.deleted())
            .map(|_| ())
            .ok_or(Refusal::Tenant)
    }

    async fn process(&self, inbound: &Inbound) -> Result<Outcome, Refusal> {
        self.holds(inbound.tenant, inbound.generation)?;
        let now = self.inner.parts.clock.now();
        let today = u32::try_from(now / DAY).map_err(|_| Refusal::Failed)?;
        let days = self
            .inner
            .parts
            .keys
            .search(inbound.tenant, inbound.generation)
            .await
            .map_err(|_| Refusal::Keys)?;
        if days.get(today).is_none() {
            return Err(Refusal::Failed);
        }
        let from = u64::from(events::retired(today)) * DAY;
        let to = now.saturating_add(SKEW);
        let mut written = 0;
        let mut duplicate = false;
        if inbound.recipient == crypto::ANY {
            for block in &inbound.blocks {
                let Some(address) = block.address.as_deref() else {
                    continue;
                };
                let Some(query) = Query::new(Field::Recipient, address.as_bytes(), &[], from, to)
                else {
                    continue;
                };
                match self.find(inbound, &query, &days).await? {
                    Some(Found::Matched(matched)) => {
                        self.write(inbound, block, matched).await?;
                        written += 1;
                    }
                    Some(Found::Duplicate) => duplicate = true,
                    None => {}
                }
            }
        } else {
            if inbound.blocks.is_empty() {
                return Ok(Outcome::Unmatched);
            }
            let query = Query::new(Field::Message, &inbound.message.bytes(), &[], from, to)
                .ok_or(Refusal::Failed)?;
            match self.find(inbound, &query, &days).await? {
                Some(Found::Matched(matched)) => {
                    let Some(block) = selected(inbound, &matched) else {
                        return Ok(Outcome::Unmatched);
                    };
                    self.write(inbound, block, matched).await?;
                    written = 1;
                }
                Some(Found::Duplicate) => duplicate = true,
                None => {}
            }
        }
        if written != 0 {
            Ok(Outcome::Written(written))
        } else if duplicate {
            Ok(Outcome::Duplicate)
        } else {
            Ok(Outcome::Unmatched)
        }
    }

    async fn find(
        &self,
        inbound: &Inbound,
        query: &Query,
        days: &DayKeys,
    ) -> Result<Option<Found>, Refusal> {
        let hashes = query
            .days()
            .filter_map(|day| {
                days.get(day)
                    .map(|key| (day, search::hash(key, query.field(), query.value())))
            })
            .collect::<Vec<_>>();
        let mut after = 0;
        let mut matched = None;
        loop {
            let scan = Scan {
                tenant: inbound.tenant,
                generation: inbound.generation,
                query: query.clone(),
                hashes: hashes.clone(),
                after,
                limit: SEARCH_LIMIT,
            };
            let hits = finder::serve(&self.inner.parts.changes, &scan)
                .await
                .map_err(|_| Refusal::Failed)?;
            for hit in hits.found {
                if hit.event.message != inbound.message {
                    continue;
                }
                if query.field() == Field::Message && hit.event.recipient != inbound.recipient {
                    continue;
                }
                if hit.event.kind == inbound.kind.event() {
                    return Ok(Some(Found::Duplicate));
                }
                if matches!(hit.event.kind, Kind::Bounced | Kind::Complained) {
                    continue;
                }
                if matched.is_some() {
                    continue;
                }
                let Some((opener, body)) =
                    self.open(inbound.tenant, &hit.event, &hit.payload).await?
                else {
                    continue;
                };
                if !query.verified(&hit.event, &body.address) {
                    continue;
                }
                matched = Some(Matched {
                    opener,
                    address: body.address,
                    recipient: hit.event.recipient,
                });
            }
            if !hits.full {
                return Ok(matched.map(Found::Matched));
            }
            if hits.scanned <= after {
                return Err(Refusal::Failed);
            }
            after = hits.scanned;
        }
    }

    async fn open(
        &self,
        tenant: u32,
        event: &Event,
        payload: &[u8],
    ) -> Result<Option<(Opener, Body)>, Refusal> {
        let Some((wrap, inner)) = events::sealed(payload) else {
            return Ok(None);
        };
        let opener = match event_opener(self.inner.parts.keys.as_ref(), tenant, event, wrap).await {
            Ok(opener) => opener,
            Err(Unsealable::Unavailable | Unsealable::Failed) => return Err(Refusal::Failed),
            Err(_) => return Ok(None),
        };
        let Ok(clear) = opener.open_event(event.recipient, event.stamp, inner) else {
            return Ok(None);
        };
        Ok(Body::decode(&clear)
            .filter(|body| event.checked(body))
            .map(|body| (opener, body)))
    }

    async fn write(
        &self,
        inbound: &Inbound,
        block: &Block,
        matched: Matched,
    ) -> Result<(), Refusal> {
        self.holds(inbound.tenant, inbound.generation)?;
        let ours = std::str::from_utf8(&matched.address)
            .ok()
            .and_then(normalize);
        let theirs = block.address.as_deref().and_then(normalize);
        if inbound.recipient != crypto::ANY && ours.is_some() && ours == theirs {
            let address = ours.as_deref().expect("checked");
            match inbound.kind {
                ReportKind::Bounce if suppresses(block.status) => {
                    self.inner
                        .parts
                        .suppressions
                        .bounce(inbound.tenant, inbound.generation, address)
                        .await?;
                }
                ReportKind::Complaint => {
                    self.inner
                        .parts
                        .suppressions
                        .complain(inbound.tenant, inbound.generation, address)
                        .await?;
                }
                ReportKind::Bounce => {}
            }
        }
        let now = self.inner.parts.clock.now();
        let body = Body {
            kind: inbound.kind.event(),
            time: now,
            address: matched.address,
            reply: reply(inbound.kind, &block.diagnostic),
            attempts: 0,
            class: 0,
        };
        let stamp = self
            .inner
            .parts
            .spool
            .stamp(inbound.message.shard)
            .map_err(|_| Refusal::Failed)?;
        let mut event = matched
            .opener
            .event(matched.recipient, stamp, &body)
            .map_err(|_| Refusal::Failed)?;
        let decoded = Event::decode(&event.record.entry.value).ok_or(Refusal::Failed)?;
        let partition = decoded.partition();
        let days = self
            .inner
            .parts
            .keys
            .search(inbound.tenant, inbound.generation)
            .await
            .map_err(|_| Refusal::Keys)?;
        let key = days.get(partition).ok_or(Refusal::Failed)?;
        event.search = search::records(inbound.tenant, &decoded, &body.address, key).to_vec();
        let mut records = Vec::with_capacity(1 + event.search.len());
        records.push(event.record);
        records.extend(event.search);
        self.inner
            .parts
            .changes
            .index(inbound.message.shard, Claim::Control, records)
            .await
            .map_err(|error| crate::suppress::refusal(&error))
    }
}

enum Found {
    Matched(Matched),
    Duplicate,
}

struct Matched {
    opener: Opener,
    address: Vec<u8>,
    recipient: u32,
}

fn selected<'a>(inbound: &'a Inbound, matched: &Matched) -> Option<&'a Block> {
    let ours = std::str::from_utf8(&matched.address)
        .ok()
        .and_then(normalize);
    ours.as_deref()
        .and_then(|ours| {
            inbound
                .blocks
                .iter()
                .find(|block| block.address.as_deref().and_then(normalize).as_deref() == Some(ours))
        })
        .or_else(|| inbound.blocks.first())
}

fn suppresses(status: (u8, u16, u16)) -> bool {
    matches!(status, (5, 1, 1 | 6 | 10) | (5, 2, 1))
}

fn reply(kind: ReportKind, diagnostic: &str) -> Vec<u8> {
    if diagnostic.is_empty() {
        return match kind {
            ReportKind::Bounce => Vec::new(),
            ReportKind::Complaint => b"abuse".to_vec(),
        };
    }
    let mut end = diagnostic.len().min(events::MAX_REPLY);
    while !diagnostic.is_char_boundary(end) {
        end -= 1;
    }
    diagnostic.as_bytes()[..end].to_vec()
}

impl<T: Transport + 'static> Node<T> {
    pub async fn report(&self, inbound: Inbound) -> Result<Outcome, Refusal> {
        match timeout(DEADLINE, self.inner.reports.report(inbound)).await {
            Ok(outcome) => outcome,
            Err(_) => Err(Refusal::Failed),
        }
    }
}
