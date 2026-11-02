use std::cell::{Cell, OnceCell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use control::{Label, Naming, Sealer, State, Table, siphash};
use index::{Entry, Key, Op, Shape};
use rt::{Ends, JoinHandle, Peers, Sender, channel, spawn};
use store::{Changes, Claim, IndexRecord};

use crate::clock::Clock;
use crate::error::Refusal;
use crate::normal::normalize;

pub const KIND_SUPPRESS: u8 = 1;
pub const SEAL_SUPPRESS: u8 = 0x81;
pub const SHAPE: Shape = Shape { value: 21 };

const PARTITION: (u8, u32) = (KIND_SUPPRESS, 0);

pub type Hash = [u8; 16];

pub trait Hasher {
    fn hash(&self, tenant: u32, data: &[u8]) -> Hash;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Bounce,
    Complaint,
    Unsubscribe,
    Manual,
}

impl Reason {
    fn code(self) -> u8 {
        match self {
            Self::Bounce => 1,
            Self::Complaint => 2,
            Self::Unsubscribe => 3,
            Self::Manual => 4,
        }
    }

    fn of(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Bounce),
            2 => Some(Self::Complaint),
            3 => Some(Self::Unsubscribe),
            4 => Some(Self::Manual),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suppression {
    pub reason: Reason,
    pub created: u64,
    pub until: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub address: String,
    pub suppression: Suppression,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    pub listed: Vec<Listed>,
    pub next: Option<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Value {
    generation: u32,
    suppression: Suppression,
}

impl Value {
    fn encode(&self) -> Vec<u8> {
        let s = &self.suppression;
        let mut out = Vec::with_capacity(usize::from(SHAPE.value));
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.push(s.reason.code());
        out.extend_from_slice(&s.created.to_le_bytes());
        out.extend_from_slice(&s.until.unwrap_or(0).to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != usize::from(SHAPE.value) {
            return None;
        }
        let until = u64::from_le_bytes(bytes[13..21].try_into().ok()?);
        Some(Self {
            generation: u32::from_le_bytes(bytes[..4].try_into().ok()?),
            suppression: Suppression {
                reason: Reason::of(bytes[4])?,
                created: u64::from_le_bytes(bytes[5..13].try_into().ok()?),
                until: (until != 0).then_some(until),
            },
        })
    }

    fn live(&self, generation: u32, now: u64) -> bool {
        self.generation == generation && self.suppression.until.is_none_or(|until| until > now)
    }
}

pub fn retain(table: &Table, now: u64, entry: &Entry, oldest: bool) -> bool {
    if entry.op == Op::Delete {
        return true;
    }
    let Some(value) = Value::decode(&entry.value) else {
        return true;
    };
    let tenant = index::tenant(&entry.key);
    if table
        .tenant(tenant)
        .is_some_and(|t| value.generation < t.generation)
    {
        return false;
    }
    !(oldest && value.suppression.until.is_some_and(|until| until <= now))
}

enum Request {
    Check {
        tenant: u32,
        keys: Vec<(u16, Hash)>,
    },
    Add {
        tenant: u32,
        shard: u16,
        hash: Hash,
        address: Box<str>,
        reason: Reason,
        until: Option<u64>,
    },
    Remove {
        tenant: u32,
        shard: u16,
        hash: Hash,
    },
    Get {
        tenant: u32,
        shard: u16,
        hash: Hash,
    },
    List {
        tenant: u32,
        after: Option<Hash>,
        limit: usize,
    },
}

enum Answer {
    Checked(Result<Vec<bool>, Refusal>),
    Added(Result<(), Refusal>),
    Removed(Result<bool, Refusal>),
    Got(Result<Option<Suppression>, Refusal>),
    Listed(Result<Vec<(Hash, Listed)>, Refusal>),
}

pub struct Ask(Message);

enum Message {
    Ask { ticket: u64, request: Request },
    Answer { ticket: u64, answer: Answer },
}

pub struct Inputs {
    pub hasher: Rc<dyn Hasher>,
    pub sealer: Rc<dyn Sealer>,
    pub changes: Changes,
    pub table: Rc<RefCell<Table>>,
    pub clock: Clock,
    pub naming: Naming,
    pub shards: Vec<u16>,
}

struct Inner {
    parts: Inputs,
    cores: u16,
    peers: OnceCell<Peers<Ask>>,
    waiting: RefCell<BTreeMap<u64, Sender<Answer>>>,
    tickets: Cell<u64>,
}

#[derive(Clone)]
pub struct Suppressions {
    inner: Rc<Inner>,
}

impl Suppressions {
    pub fn start(ends: Ends<Ask>, parts: Inputs) -> (Self, JoinHandle<()>) {
        let inner = Rc::new(Inner {
            parts,
            cores: ends.cores(),
            peers: OnceCell::new(),
            waiting: RefCell::new(BTreeMap::new()),
            tickets: Cell::new(0),
        });
        let suppressions = Self { inner };
        let handler = suppressions.clone();
        let (peers, done) = ends.start(move |from, Ask(message)| handler.handle(from, message));
        let _ = suppressions.inner.peers.set(peers);
        (suppressions, done)
    }

    pub fn close(&self) {
        self.inner.waiting.borrow_mut().clear();
        if let Some(peers) = self.inner.peers.get() {
            peers.close();
        }
    }

    pub fn owner(&self, tenant: u32, hash: &Hash) -> u16 {
        let naming = &self.inner.parts.naming;
        let mut data = [0; 20];
        data[..4].copy_from_slice(&tenant.to_le_bytes());
        data[4..].copy_from_slice(hash);
        u16::try_from(siphash(&naming.key, &data) % u64::from(naming.shards))
            .expect("shard fits in u16")
    }

    pub fn hash(&self, tenant: u32, address: &str) -> Option<Hash> {
        let normal = normalize(address)?;
        Some(self.inner.parts.hasher.hash(tenant, normal.as_bytes()))
    }

    pub async fn check(&self, tenant: u32, addresses: &[&str]) -> Result<Vec<bool>, Refusal> {
        let mut by_core: BTreeMap<u16, Vec<(usize, u16, Hash)>> = BTreeMap::new();
        for (at, address) in addresses.iter().enumerate() {
            let hash = self.hash(tenant, address).ok_or(Refusal::Address)?;
            let shard = self.owner(tenant, &hash);
            by_core
                .entry(shard % self.inner.cores)
                .or_default()
                .push((at, shard, hash));
        }
        let mut asked = Vec::new();
        for (core, keys) in by_core {
            let request = Request::Check {
                tenant,
                keys: keys.iter().map(|&(_, s, h)| (s, h)).collect(),
            };
            asked.push((keys, self.send(core, request)));
        }
        let mut out = vec![false; addresses.len()];
        for (keys, mut answer) in asked {
            let Some(Answer::Checked(found)) = answer.recv().await else {
                return Err(Refusal::Failed);
            };
            let found = found?;
            if found.len() != keys.len() {
                return Err(Refusal::Failed);
            }
            for ((at, _, _), suppressed) in keys.into_iter().zip(found) {
                out[at] = suppressed;
            }
        }
        Ok(out)
    }

    pub async fn add(
        &self,
        tenant: u32,
        address: &str,
        reason: Reason,
        until: Option<u64>,
    ) -> Result<(), Refusal> {
        let address = normalize(address).ok_or(Refusal::Address)?;
        let hash = self.inner.parts.hasher.hash(tenant, address.as_bytes());
        let shard = self.owner(tenant, &hash);
        let request = Request::Add {
            tenant,
            shard,
            hash,
            address: address.into(),
            reason,
            until,
        };
        match self.ask(shard, request).await? {
            Answer::Added(result) => result,
            _ => Err(Refusal::Failed),
        }
    }

    pub async fn remove(&self, tenant: u32, address: &str) -> Result<bool, Refusal> {
        let hash = self.hash(tenant, address).ok_or(Refusal::Address)?;
        let shard = self.owner(tenant, &hash);
        match self
            .ask(
                shard,
                Request::Remove {
                    tenant,
                    shard,
                    hash,
                },
            )
            .await?
        {
            Answer::Removed(result) => result,
            _ => Err(Refusal::Failed),
        }
    }

    pub async fn get(&self, tenant: u32, address: &str) -> Result<Option<Suppression>, Refusal> {
        let hash = self.hash(tenant, address).ok_or(Refusal::Address)?;
        let shard = self.owner(tenant, &hash);
        match self
            .ask(
                shard,
                Request::Get {
                    tenant,
                    shard,
                    hash,
                },
            )
            .await?
        {
            Answer::Got(result) => result,
            _ => Err(Refusal::Failed),
        }
    }

    pub async fn list(
        &self,
        tenant: u32,
        after: Option<Hash>,
        limit: usize,
    ) -> Result<Page, Refusal> {
        if limit == 0 {
            return Ok(Page::default());
        }
        let mut asked = Vec::new();
        for core in 0..self.inner.cores {
            let request = Request::List {
                tenant,
                after,
                limit,
            };
            asked.push(self.send(core, request));
        }
        let mut all = Vec::new();
        let mut full = false;
        for mut answer in asked {
            let Some(Answer::Listed(found)) = answer.recv().await else {
                return Err(Refusal::Failed);
            };
            let found = found?;
            full |= found.len() >= limit;
            all.extend(found);
        }
        all.sort_by_key(|(hash, _)| *hash);
        full |= all.len() > limit;
        all.truncate(limit);
        let next = all.last().filter(|_| full).map(|(hash, _)| *hash);
        Ok(Page {
            listed: all.into_iter().map(|(_, listed)| listed).collect(),
            next,
        })
    }

    async fn ask(&self, shard: u16, request: Request) -> Result<Answer, Refusal> {
        let mut answer = self.send(shard % self.inner.cores, request);
        answer.recv().await.ok_or(Refusal::Failed)
    }

    fn send(&self, core: u16, request: Request) -> rt::Receiver<Answer> {
        let (reply, answer) = channel();
        let ticket = self.inner.tickets.get();
        self.inner.tickets.set(ticket + 1);
        self.inner.waiting.borrow_mut().insert(ticket, reply);
        if let Some(peers) = self.inner.peers.get() {
            peers.send(core, Ask(Message::Ask { ticket, request }));
        }
        answer
    }

    fn handle(&self, from: u16, message: Message) {
        match message {
            Message::Ask { ticket, request } => {
                let owner = self.clone();
                drop(spawn(async move {
                    let answer = owner.serve(request).await;
                    if let Some(peers) = owner.inner.peers.get() {
                        peers.send(from, Ask(Message::Answer { ticket, answer }));
                    }
                }));
            }
            Message::Answer { ticket, answer } => {
                if let Some(reply) = self.inner.waiting.borrow_mut().remove(&ticket) {
                    let _ = reply.send(answer);
                }
            }
        }
    }

    async fn serve(&self, request: Request) -> Answer {
        match request {
            Request::Check { tenant, keys } => Answer::Checked(self.checked(tenant, keys).await),
            Request::Add {
                tenant,
                shard,
                hash,
                address,
                reason,
                until,
            } => Answer::Added(
                self.added(tenant, shard, hash, &address, reason, until)
                    .await,
            ),
            Request::Remove {
                tenant,
                shard,
                hash,
            } => Answer::Removed(self.removed(tenant, shard, hash).await),
            Request::Get {
                tenant,
                shard,
                hash,
            } => Answer::Got(self.found(tenant, shard, hash).await),
            Request::List {
                tenant,
                after,
                limit,
            } => Answer::Listed(self.listed(tenant, after, limit).await),
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

    async fn values(
        &self,
        tenant: u32,
        keys: &[(u16, Hash)],
    ) -> Result<Vec<Option<Value>>, Refusal> {
        let generation = self.generation(tenant)?;
        let asked = keys
            .iter()
            .map(|&(shard, hash)| (shard, index::key(tenant, hash)))
            .collect();
        let found = self
            .inner
            .parts
            .changes
            .lookup(PARTITION, asked)
            .await
            .map_err(|e| refusal(&e))?;
        let now = self.inner.parts.clock.now();
        Ok(found
            .into_iter()
            .map(|found| {
                found
                    .filter(|(op, _)| *op == Op::Put)
                    .and_then(|(_, value)| Value::decode(&value))
                    .filter(|value| value.live(generation, now))
            })
            .collect())
    }

    async fn checked(&self, tenant: u32, keys: Vec<(u16, Hash)>) -> Result<Vec<bool>, Refusal> {
        let values = self.values(tenant, &keys).await?;
        Ok(values.iter().map(Option::is_some).collect())
    }

    async fn found(
        &self,
        tenant: u32,
        shard: u16,
        hash: Hash,
    ) -> Result<Option<Suppression>, Refusal> {
        let values = self.values(tenant, &[(shard, hash)]).await?;
        Ok(values[0].map(|v| v.suppression))
    }

    async fn added(
        &self,
        tenant: u32,
        shard: u16,
        hash: Hash,
        address: &str,
        reason: Reason,
        until: Option<u64>,
    ) -> Result<(), Refusal> {
        let generation = self.generation(tenant)?;
        let parts = &self.inner.parts;
        let value = Value {
            generation,
            suppression: Suppression {
                reason,
                created: parts.clock.now(),
                until: until.filter(|&u| u != 0),
            },
        };
        let sealed = parts
            .sealer
            .seal(&label(tenant, generation), address.as_bytes());
        if sealed.len() > index::MAX_PAYLOAD {
            return Err(Refusal::Address);
        }
        let record = IndexRecord {
            kind: KIND_SUPPRESS,
            partition: PARTITION.1,
            entry: Entry::put(index::key(tenant, hash), value.encode(), sealed),
        };
        parts
            .changes
            .index(shard, Claim::Control, vec![record])
            .await
            .map_err(|e| refusal(&e))
    }

    async fn removed(&self, tenant: u32, shard: u16, hash: Hash) -> Result<bool, Refusal> {
        let found = self.found(tenant, shard, hash).await?.is_some();
        let record = IndexRecord {
            kind: KIND_SUPPRESS,
            partition: PARTITION.1,
            entry: Entry::delete(index::key(tenant, hash), SHAPE),
        };
        self.inner
            .parts
            .changes
            .index(shard, Claim::Control, vec![record])
            .await
            .map_err(|e| refusal(&e))?;
        Ok(found)
    }

    async fn listed(
        &self,
        tenant: u32,
        after: Option<Hash>,
        limit: usize,
    ) -> Result<Vec<(Hash, Listed)>, Refusal> {
        let generation = self.generation(tenant)?;
        let parts = &self.inner.parts;
        let label = label(tenant, generation);
        let from = match after {
            Some(hash) => next(index::key(tenant, hash)),
            None => Some(index::key(tenant, [0; 16])),
        };
        let Some(from) = from else {
            return Ok(Vec::new());
        };
        let to = tenant
            .checked_add(1)
            .map_or([0xff; 20], |t| index::key(t, [0; 16]));
        let mut out = Vec::new();
        for &shard in &parts.shards {
            let mut at = from;
            let mut found = 0;
            while found < limit && at < to {
                let page = parts
                    .changes
                    .scan(shard, PARTITION, at..to, limit)
                    .await
                    .map_err(|e| refusal(&e))?;
                let now = parts.clock.now();
                for entry in &page {
                    let live = (entry.op == Op::Put)
                        .then(|| Value::decode(&entry.value))
                        .flatten()
                        .filter(|v| v.live(generation, now));
                    let opened = live.and_then(|v| {
                        let address = parts.sealer.open(&label, &entry.payload)?;
                        Some((v, String::from_utf8(address).ok()?))
                    });
                    if let Some((value, address)) = opened {
                        let hash = entry.key[4..].try_into().expect("16 bytes");
                        out.push((
                            hash,
                            Listed {
                                address,
                                suppression: value.suppression,
                            },
                        ));
                        found += 1;
                    }
                }
                let Some(last) = page.last().filter(|_| page.len() >= limit) else {
                    break;
                };
                match next(last.key) {
                    Some(key) => at = key,
                    None => break,
                }
            }
        }
        out.sort_by_key(|(hash, _)| *hash);
        out.truncate(limit);
        Ok(out)
    }
}

fn label(tenant: u32, generation: u32) -> Label {
    Label {
        tenant,
        generation,
        kind: SEAL_SUPPRESS,
        id: 0,
    }
}

fn next(mut key: Key) -> Option<Key> {
    for byte in key.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return Some(key);
        }
    }
    None
}

fn refusal(error: &store::Error) -> Refusal {
    match error {
        store::Error::Busy => Refusal::Busy,
        _ => Refusal::Failed,
    }
}
