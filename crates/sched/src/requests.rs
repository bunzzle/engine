use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;

use control::{Naming, State, Table};
use index::{Entry, Op, Shape};
use rt::{JoinHandle, Notify, Sender, channel, sleep_until, spawn};
use spool::MessageId;
use store::{Changes, IndexRecord};

use crate::clock::Clock;
use crate::error::Refusal;
use crate::suppress::{Hash, Hasher, owner_shard, refusal};

pub const KIND_REQUEST: u8 = 2;
pub const DAY: u64 = 86_400_000;
pub const REQUEST_SHAPE: Shape = Shape { value: 61 };
pub const INLINE_IDS: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Value {
    generation: u32,
    accepted: u64,
    digest: Hash,
    ids: Vec<MessageId>,
}

impl Value {
    fn encode(&self) -> (Vec<u8>, Vec<u8>) {
        let mut value = Vec::with_capacity(usize::from(REQUEST_SHAPE.value));
        value.extend_from_slice(&self.generation.to_le_bytes());
        value.extend_from_slice(&self.accepted.to_le_bytes());
        value.extend_from_slice(&self.digest);
        value.push(u8::try_from(self.ids.len()).expect("ids fit in u8"));
        let (inline, rest) = self.ids.split_at(self.ids.len().min(INLINE_IDS));
        for slot in 0..INLINE_IDS {
            value.extend_from_slice(&inline.get(slot).map_or([0; 16], MessageId::bytes));
        }
        let payload = rest.iter().flat_map(MessageId::bytes).collect();
        (value, payload)
    }

    fn decode(value: &[u8], payload: &[u8]) -> Option<Self> {
        if value.len() != usize::from(REQUEST_SHAPE.value) {
            return None;
        }
        let count = usize::from(value[28]);
        let inline = count.min(INLINE_IDS);
        if payload.len() != (count - inline) * 16 {
            return None;
        }
        let mut ids: Vec<MessageId> = value[29..]
            .as_chunks::<16>()
            .0
            .iter()
            .take(inline)
            .map(|c| MessageId::from_bytes(*c))
            .collect();
        ids.extend(
            payload
                .as_chunks::<16>()
                .0
                .iter()
                .map(|c| MessageId::from_bytes(*c)),
        );
        Some(Self {
            generation: u32::from_le_bytes(value[..4].try_into().ok()?),
            accepted: u64::from_le_bytes(value[4..12].try_into().ok()?),
            digest: value[12..28].try_into().ok()?,
            ids,
        })
    }
}

pub fn retain_request(table: &Table, now: u64, entry: &Entry) -> bool {
    if entry.op == Op::Delete || entry.value.len() != usize::from(REQUEST_SHAPE.value) {
        return true;
    }
    let generation = u32::from_le_bytes(entry.value[..4].try_into().expect("4 bytes"));
    let accepted = u64::from_le_bytes(entry.value[4..12].try_into().expect("8 bytes"));
    let tenant = index::tenant(&entry.key);
    let older = table
        .tenant(tenant)
        .is_some_and(|t| generation < t.generation);
    !older && accepted.saturating_add(DAY) > now
}

pub enum Begun {
    Fresh(Ticket),
    Replay(Vec<MessageId>),
}

pub struct Ticket {
    requests: Requests,
    tenant: u32,
    hash: Hash,
    digest: Hash,
    shard: u16,
}

impl Ticket {
    pub fn tenant(&self) -> u32 {
        self.tenant
    }

    pub fn shard(&self) -> u16 {
        self.shard
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.requests.release(self.tenant, self.hash);
    }
}

pub struct RequestInputs {
    pub hasher: Rc<dyn Hasher>,
    pub changes: Changes,
    pub table: Rc<RefCell<Table>>,
    pub clock: Clock,
    pub naming: Naming,
    pub shards: Vec<u16>,
}

struct Flight {
    digest: Hash,
    waiters: Vec<Sender<()>>,
}

struct Inner {
    parts: RequestInputs,
    flights: RefCell<BTreeMap<(u32, Hash), Flight>>,
    day: Cell<u32>,
    closed: Cell<bool>,
    wake: Notify,
}

#[derive(Clone)]
pub struct Requests {
    inner: Rc<Inner>,
}

impl Requests {
    pub async fn start(parts: RequestInputs) -> Result<(Self, JoinHandle<()>), store::Error> {
        let kept = parts.changes.partitions(KIND_REQUEST).await?;
        let last = kept.iter().map(|(_, day)| *day).max().unwrap_or(0);
        let requests = Self {
            inner: Rc::new(Inner {
                parts,
                flights: RefCell::new(BTreeMap::new()),
                day: Cell::new(last),
                closed: Cell::new(false),
                wake: Notify::default(),
            }),
        };
        let retiring = requests.clone();
        let done = spawn(async move { retiring.retire().await });
        Ok((requests, done))
    }

    pub fn close(&self) {
        self.inner.closed.set(true);
        self.inner.wake.notify();
        for (_, flight) in std::mem::take(&mut *self.inner.flights.borrow_mut()) {
            drop(flight.waiters);
        }
    }

    pub fn today(&self) -> u32 {
        let now = self.inner.parts.clock.now() / DAY;
        let day = u32::try_from(now)
            .unwrap_or(u32::MAX)
            .max(self.inner.day.get());
        self.inner.day.set(day);
        day
    }

    pub fn shard(&self, tenant: u32, key: &[u8]) -> u16 {
        let hash = self.inner.parts.hasher.hash(tenant, key);
        owner_shard(&self.inner.parts.naming, tenant, &hash)
    }

    pub fn in_flight(&self) -> usize {
        self.inner.flights.borrow().len()
    }

    pub async fn begin(&self, tenant: u32, key: &[u8], digest: Hash) -> Result<Begun, Refusal> {
        let parts = &self.inner.parts;
        let hash = parts.hasher.hash(tenant, key);
        let shard = owner_shard(&parts.naming, tenant, &hash);
        if !parts.shards.contains(&shard) {
            return Err(Refusal::Message);
        }
        loop {
            if self.inner.closed.get() {
                return Err(Refusal::Failed);
            }
            if let Some(mut woken) = self.wait(tenant, hash, digest)? {
                woken.recv().await;
                continue;
            }
            match self.find(tenant, shard, hash).await? {
                Some(found) if found.digest == digest => return Ok(Begun::Replay(found.ids)),
                Some(_) => return Err(Refusal::Conflict),
                None => {}
            }
            let mut flights = self.inner.flights.borrow_mut();
            if flights.contains_key(&(tenant, hash)) {
                continue;
            }
            flights.insert(
                (tenant, hash),
                Flight {
                    digest,
                    waiters: Vec::new(),
                },
            );
            return Ok(Begun::Fresh(Ticket {
                requests: self.clone(),
                tenant,
                hash,
                digest,
                shard,
            }));
        }
    }

    pub fn record(
        &self,
        ticket: &Ticket,
        generation: u32,
        ids: &[MessageId],
    ) -> Result<IndexRecord, Refusal> {
        let value = Value {
            generation,
            accepted: self.inner.parts.clock.now(),
            digest: ticket.digest,
            ids: ids.to_vec(),
        };
        if ids.is_empty() || ids.len() > usize::from(u8::MAX) {
            return Err(Refusal::Message);
        }
        let (value, payload) = value.encode();
        if payload.len() > index::MAX_PAYLOAD {
            return Err(Refusal::Message);
        }
        Ok(IndexRecord {
            kind: KIND_REQUEST,
            partition: self.today(),
            entry: Entry::put(index::key(ticket.tenant, ticket.hash), value, payload),
        })
    }

    fn wait(
        &self,
        tenant: u32,
        hash: Hash,
        digest: Hash,
    ) -> Result<Option<rt::Receiver<()>>, Refusal> {
        let mut flights = self.inner.flights.borrow_mut();
        let Some(flight) = flights.get_mut(&(tenant, hash)) else {
            return Ok(None);
        };
        if flight.digest != digest {
            return Err(Refusal::Conflict);
        }
        let (wake, woken) = channel();
        flight.waiters.push(wake);
        Ok(Some(woken))
    }

    fn release(&self, tenant: u32, hash: Hash) {
        let flight = self.inner.flights.borrow_mut().remove(&(tenant, hash));
        for waiter in flight.into_iter().flat_map(|f| f.waiters) {
            let _ = waiter.send(());
        }
    }

    fn generation(&self, tenant: u32) -> Result<u32, Refusal> {
        self.inner
            .parts
            .table
            .borrow()
            .tenant(tenant)
            .filter(|t| t.state == State::Active)
            .map(|t| t.generation)
            .ok_or(Refusal::Tenant)
    }

    async fn find(&self, tenant: u32, shard: u16, hash: Hash) -> Result<Option<Value>, Refusal> {
        let generation = self.generation(tenant)?;
        let parts = &self.inner.parts;
        let today = self.today();
        let key = index::key(tenant, hash);
        let mut days = vec![today];
        if today > 0 {
            days.push(today - 1);
        }
        for day in days {
            let found = parts
                .changes
                .lookup((KIND_REQUEST, day), vec![(shard, key)])
                .await
                .map_err(|e| refusal(&e))?;
            let Some(Some((Op::Put, value))) = found.into_iter().next() else {
                continue;
            };
            let inline = value.get(28).is_some_and(|&n| usize::from(n) <= INLINE_IDS);
            let decoded = if inline {
                Value::decode(&value, &[])
            } else {
                let scanned = parts
                    .changes
                    .scan(shard, (KIND_REQUEST, day), key..next(key), 1)
                    .await
                    .map_err(|e| refusal(&e))?;
                scanned
                    .first()
                    .filter(|e| e.key == key && e.op == Op::Put)
                    .and_then(|e| Value::decode(&e.value, &e.payload))
            };
            let now = parts.clock.now();
            let live = decoded
                .filter(|v| v.generation == generation && v.accepted.saturating_add(DAY) > now);
            if live.is_some() {
                return Ok(live);
            }
        }
        Ok(None)
    }

    async fn retire(&self) {
        let inner = &self.inner;
        while !inner.closed.get() {
            let day = self.today();
            let _ = inner
                .parts
                .changes
                .retire(KIND_REQUEST, day, day.saturating_sub(1))
                .await;
            let next = u64::from(day + 1) * DAY;
            let mut wake = pin!(inner.wake.wait());
            let mut timer = pin!(sleep_until(inner.parts.clock.instant(next)));
            poll_fn(|cx| {
                if wake.as_mut().poll(cx).is_ready() || timer.as_mut().poll(cx).is_ready() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    }
}

fn next(mut key: index::Key) -> index::Key {
    for byte in key.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    key
}
