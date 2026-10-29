use std::collections::{BTreeMap, BTreeSet};
use std::mem;

use rt::{Sender, channel, spawn};
use store::{
    Batch, Change, Delivery, HEAD_ITEM, INDEX_SIZE, Keeper, MAX_PAYLOAD, Op, fits, record_size,
};

use crate::error::Error;
use crate::intake::{MessageId, Spool};
use crate::items::{HeadClear, STATE_BASE, STATE_CLEAR, Stamp, StateClear, state_item};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ready,
    Deferred,
    Delivered,
    Failed,
}

impl Status {
    fn code(self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::Deferred => 1,
            Self::Delivered => 2,
            Self::Failed => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Deferred),
            2 => Some(Self::Delivered),
            3 => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn is_final(self) -> bool {
        matches!(self, Self::Delivered | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub status: Status,
    pub attempts: u16,
    pub due: u64,
    pub class: u8,
    pub notified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Deferred { due: u64, class: u8, notified: bool },
    Delivered,
    Failed,
}

impl Outcome {
    fn is_final(self) -> bool {
        !matches!(self, Self::Deferred { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub stamp: Stamp,
    pub sealed: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub recipient: u32,
    pub outcome: Outcome,
    pub reply: Option<Reply>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Done {
    Kept,
    Dropped,
}

type Waiter = Sender<Result<Done, Error>>;

struct Call {
    reports: Vec<Report>,
    waiter: Waiter,
}

struct Entry {
    tenant: u32,
    recipients: u32,
    ready: u64,
    expiry: u64,
    finals: u32,
    states: BTreeMap<u32, Recipient>,
    claimed: BTreeSet<u32>,
    reported: BTreeSet<u32>,
    pending: Vec<Call>,
    ending: Vec<Waiter>,
    flushing: bool,
}

impl Entry {
    fn new(tenant: u32, head: &HeadClear, expiry: u64) -> Self {
        Self {
            tenant,
            recipients: head.recipients,
            ready: head.accepted.max(head.not_before),
            expiry,
            finals: 0,
            states: BTreeMap::new(),
            claimed: BTreeSet::new(),
            reported: BTreeSet::new(),
            pending: Vec::new(),
            ending: Vec::new(),
            flushing: false,
        }
    }

    fn recipient(&self, recipient: u32) -> Option<Recipient> {
        if recipient >= self.recipients {
            return None;
        }
        Some(self.states.get(&recipient).copied().unwrap_or(Recipient {
            status: Status::Ready,
            attempts: 0,
            due: self.ready,
            class: 0,
            notified: false,
        }))
    }

    fn next(&self, report: &Report) -> Recipient {
        let current = self.recipient(report.recipient).expect("claimed recipient");
        let attempts = current.attempts.saturating_add(1);
        let (status, due, class, notified) = match report.outcome {
            Outcome::Deferred {
                due,
                class,
                notified,
            } => (Status::Deferred, due, class, notified),
            Outcome::Delivered => (Status::Delivered, 0, current.class, current.notified),
            Outcome::Failed => (Status::Failed, 0, current.class, current.notified),
        };
        Recipient {
            status,
            attempts,
            due,
            class,
            notified,
        }
    }
}

struct Merge {
    batch: Batch,
    calls: Vec<Call>,
    ending: Vec<Waiter>,
    completing: bool,
}

#[derive(Default)]
pub(crate) struct Table {
    messages: BTreeMap<(u16, u64), Entry>,
    writes: BTreeMap<u16, u64>,
}

impl Table {
    pub(crate) fn rebuild(keeper: &Keeper, shards: &[u16]) -> Result<Self, Error> {
        let mut table = Self::default();
        for &shard in shards {
            let state = keeper.state(shard).ok_or(store::Error::Invalid("owner"))?;
            for (key, item) in state.entries() {
                if key.item == HEAD_ITEM {
                    let head = HeadClear::decode(&item.clear).ok_or(Error::State("head"))?;
                    let entry = Entry::new(item.tenant, &head, item.delivery.due);
                    table.messages.insert((shard, key.message), entry);
                    continue;
                }
                if key.item < STATE_BASE {
                    continue;
                }
                let entry = table
                    .messages
                    .get_mut(&(shard, key.message))
                    .ok_or(Error::State("state without head"))?;
                let recipient = key.item - STATE_BASE;
                let status = Status::from_code(item.delivery.status);
                let clear = StateClear::decode(&item.clear);
                let (Some(status), Some(clear)) = (status, clear) else {
                    return Err(Error::State("state"));
                };
                if recipient >= entry.recipients {
                    return Err(Error::State("state"));
                }
                if status.is_final() {
                    entry.finals += 1;
                }
                entry.states.insert(
                    recipient,
                    Recipient {
                        status,
                        attempts: item.delivery.attempts,
                        due: item.delivery.due,
                        class: clear.class,
                        notified: clear.notified,
                    },
                );
            }
        }
        Ok(table)
    }

    pub(crate) fn insert(
        &mut self,
        shard: u16,
        message: u64,
        tenant: u32,
        head: &HeadClear,
        expiry: u64,
    ) {
        self.messages
            .insert((shard, message), Entry::new(tenant, head, expiry));
    }
}

fn state_bytes(report: &Report) -> usize {
    let sealed = report.reply.as_ref().map_or(0, |r| r.sealed.len());
    record_size(INDEX_SIZE + STATE_CLEAR + sealed)
}

impl Spool {
    pub fn stamp(&self, shard: u16) -> Result<Stamp, Error> {
        let boot = self
            .inner
            .ids
            .borrow()
            .boot(shard)
            .ok_or(store::Error::Invalid("owner"))?;
        let mut table = self.inner.table.borrow_mut();
        let next = table.writes.entry(shard).or_default();
        let write = *next;
        *next += 1;
        Ok(Stamp { boot, write })
    }

    pub fn recipient(&self, id: MessageId, recipient: u32) -> Option<Recipient> {
        let table = self.inner.table.borrow();
        table
            .messages
            .get(&(id.shard, id.key))?
            .recipient(recipient)
    }

    pub fn messages(&self) -> Vec<MessageId> {
        let table = self.inner.table.borrow();
        table
            .messages
            .keys()
            .map(|&(shard, key)| self.message_id(shard, key))
            .collect()
    }

    pub fn expired(&self, now: u64) -> Vec<MessageId> {
        let table = self.inner.table.borrow();
        table
            .messages
            .iter()
            .filter(|(_, entry)| entry.expiry <= now)
            .map(|(&(shard, key), _)| self.message_id(shard, key))
            .collect()
    }

    fn message_id(&self, shard: u16, key: u64) -> MessageId {
        MessageId {
            node: self.inner.node,
            shard,
            key,
        }
    }

    pub fn claim(&self, id: MessageId, recipient: u32) -> Result<Recipient, Error> {
        let mut table = self.inner.table.borrow_mut();
        let entry = table
            .messages
            .get_mut(&(id.shard, id.key))
            .ok_or(Error::State("message"))?;
        if !entry.ending.is_empty() {
            return Err(Error::State("ending"));
        }
        let current = entry
            .recipient(recipient)
            .ok_or(Error::State("recipient"))?;
        if current.status.is_final() {
            return Err(Error::State("final"));
        }
        if !entry.claimed.insert(recipient) {
            return Err(Error::State("claimed"));
        }
        Ok(current)
    }

    pub async fn report(&self, id: MessageId, reports: Vec<Report>) -> Result<Done, Error> {
        let (waiter, mut answer) = channel();
        {
            let mut table = self.inner.table.borrow_mut();
            let written = table.writes.get(&id.shard).copied().unwrap_or(0);
            let entry = table
                .messages
                .get_mut(&(id.shard, id.key))
                .ok_or(Error::State("message"))?;
            let mut seen = BTreeSet::new();
            for report in &reports {
                let r = report.recipient;
                if !seen.insert(r) || !entry.claimed.contains(&r) || entry.reported.contains(&r) {
                    return Err(Error::State("not claimed"));
                }
                if report
                    .reply
                    .as_ref()
                    .is_some_and(|r| r.stamp.write >= written)
                {
                    return Err(Error::State("stamp"));
                }
            }
            let bytes: usize = reports.iter().map(state_bytes).sum();
            let large = reports.iter().any(|report| {
                let sealed = report.reply.as_ref().map_or(0, |r| r.sealed.len());
                INDEX_SIZE + STATE_CLEAR + sealed > MAX_PAYLOAD
            });
            if reports.is_empty()
                || large
                || bytes as u64 > self.inner.region_size
                || !fits(1, 1, reports.len(), reports.len())
            {
                return Err(Error::Limit("report"));
            }
            entry.reported.extend(seen);
            entry.pending.push(Call { reports, waiter });
            self.start(entry, id);
        }
        answer
            .recv()
            .await
            .unwrap_or(Err(Error::Store(store::Error::Failed)))
    }

    pub async fn cancel(&self, id: MessageId) -> Result<(), Error> {
        self.end(id, None).await
    }

    pub async fn expire(&self, id: MessageId, now: u64) -> Result<(), Error> {
        self.end(id, Some(now)).await
    }

    async fn end(&self, id: MessageId, now: Option<u64>) -> Result<(), Error> {
        let (waiter, mut answer) = channel();
        {
            let mut table = self.inner.table.borrow_mut();
            let entry = table
                .messages
                .get_mut(&(id.shard, id.key))
                .ok_or(Error::State("message"))?;
            if now.is_some_and(|now| entry.expiry > now) {
                return Err(Error::State("not expired"));
            }
            entry.ending.push(waiter);
            self.start(entry, id);
        }
        match answer.recv().await {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(Error::Store(store::Error::Failed)),
        }
    }

    fn start(&self, entry: &mut Entry, id: MessageId) {
        if entry.flushing {
            return;
        }
        entry.flushing = true;
        let spool = self.clone();
        drop(spawn(async move { spool.flush(id.shard, id.key).await }));
    }

    fn merge(&self, shard: u16, message: u64) -> Option<Merge> {
        let mut table = self.inner.table.borrow_mut();
        let entry = table.messages.get_mut(&(shard, message))?;
        let mut calls = Vec::new();
        let mut bytes = 0u64;
        let mut count = 0;
        while let Some(call) = entry.pending.first() {
            let more: u64 = call.reports.iter().map(|r| state_bytes(r) as u64).sum();
            let n = count + call.reports.len();
            if !calls.is_empty() && (bytes + more > self.inner.region_size || !fits(1, 1, n, n)) {
                break;
            }
            bytes += more;
            count = n;
            calls.push(entry.pending.remove(0));
        }
        let ends = !entry.ending.is_empty() && entry.claimed.len() == count;
        if calls.is_empty() && !ends {
            entry.flushing = false;
            return None;
        }
        let reports = || calls.iter().flat_map(|c| c.reports.iter());
        let finals = reports().filter(|r| r.outcome.is_final()).count();
        let completing = ends || entry.finals as usize + finals == entry.recipients as usize;
        let ops = if completing {
            vec![Op {
                item: HEAD_ITEM,
                change: Change::Drop,
                clear: Vec::new(),
                bodies: Vec::new(),
                sealed: Vec::new(),
            }]
        } else {
            reports()
                .map(|report| {
                    let next = entry.next(report);
                    let reply = report.reply.as_ref();
                    let clear = StateClear {
                        class: next.class,
                        notified: next.notified,
                        stamp: reply.map(|r| r.stamp).unwrap_or_default(),
                    };
                    Op {
                        item: state_item(report.recipient),
                        change: Change::Put(Delivery {
                            status: next.status.code(),
                            attempts: next.attempts,
                            due: next.due,
                        }),
                        clear: clear.encode(),
                        bodies: Vec::new(),
                        sealed: reply.map(|r| r.sealed.clone()).unwrap_or_default(),
                    }
                })
                .collect()
        };
        let ending = if completing {
            mem::take(&mut entry.ending)
        } else {
            Vec::new()
        };
        let batch = Batch {
            shard,
            message,
            tenant: entry.tenant,
            ops,
        };
        Some(Merge {
            batch,
            calls,
            ending,
            completing,
        })
    }

    async fn flush(&self, shard: u16, message: u64) {
        while let Some(merge) = self.merge(shard, message) {
            let result = self.inner.changes.apply(merge.batch).await;
            let mut table = self.inner.table.borrow_mut();
            let key = (shard, message);
            let answer = match result {
                Ok(_) if merge.completing => {
                    table.messages.remove(&key);
                    Ok(Done::Dropped)
                }
                Ok(_) => {
                    let entry = table.messages.get_mut(&key).expect("flushed message");
                    for report in merge.calls.iter().flat_map(|c| c.reports.iter()) {
                        let next = entry.next(report);
                        if next.status.is_final() {
                            entry.finals += 1;
                        }
                        entry.states.insert(report.recipient, next);
                    }
                    Ok(Done::Kept)
                }
                Err(e) => Err(e),
            };
            if let Some(entry) = table.messages.get_mut(&key) {
                for report in merge.calls.iter().flat_map(|c| c.reports.iter()) {
                    entry.claimed.remove(&report.recipient);
                    entry.reported.remove(&report.recipient);
                }
            }
            drop(table);
            let waiters = merge.calls.iter().map(|c| &c.waiter).chain(&merge.ending);
            for waiter in waiters {
                let _ = waiter.send(clone_answer(&answer));
            }
            if matches!(answer, Ok(Done::Dropped)) {
                return;
            }
        }
    }
}

fn clone_answer(answer: &Result<Done, store::Error>) -> Result<Done, Error> {
    match answer {
        Ok(done) => Ok(*done),
        Err(store::Error::Invalid(what)) => Err(Error::Store(store::Error::Invalid(what))),
        Err(store::Error::NotFound) => Err(Error::Store(store::Error::NotFound)),
        Err(store::Error::Reserve) => Err(Error::Store(store::Error::Reserve)),
        Err(store::Error::Full) => Err(Error::Store(store::Error::Full)),
        Err(_) => Err(Error::Store(store::Error::Failed)),
    }
}
