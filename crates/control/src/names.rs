use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;

use crypto::TenantKeys;

use rt::{Ends, JoinHandle, Notify, Peers, Sender, channel, spawn};
use store::{
    Batch, CONTROL_BOOT, Change, Changes, Core, Delivery, HEAD_ITEM, Index, Location, Op, Owner,
    Record, control_key, is_control, split_key,
};

use crate::cache::{Cache, CacheStats};
use crate::error::Error;
use crate::queue::{
    Head, KeyError, KeySource, Label, Name, Queue, Tenancy, naming_shard, queue_shard, tenant_keys,
};
use crate::record::{KIND_FLOOR, KIND_QUEUE, SYSTEM};

const FLOOR: usize = 16;
const FLOOR_FORMAT: u8 = 1;

pub enum Call {
    Name(Name),
    Named {
        name: Name,
        id: Result<u32, Unnamed>,
    },
    Forget {
        tenant: u32,
        domain: Box<str>,
        ticket: u64,
    },
    ForgetTenant {
        tenant: u32,
        ticket: u64,
    },
    Forgot {
        ticket: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Naming {
    pub key: [u8; 16],
    pub shards: u32,
    pub cache: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unnamed {
    Refused,
    Failed,
    Keys(KeyError),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NamingStats {
    pub cache: CacheStats,
    pub allocated: u64,
    pub failed: u64,
    pub keys: u64,
    pub refused: u64,
    pub skipped: u64,
}

type Lock = (u32, Box<str>);
type Named = Result<u32, Unnamed>;

struct Ready {
    name: Name,
    from: u16,
    shard: u16,
    id: u32,
}

enum Job {
    Name { name: Name, from: u16 },
    Wake(Sender<()>),
}

#[derive(Default)]
struct Owned {
    names: BTreeMap<Name, u32>,
    queues: BTreeMap<u32, Queue>,
    next: BTreeMap<u16, u64>,
    ids: BTreeMap<u16, u32>,
    floors: BTreeMap<u16, u64>,
    leftovers: BTreeMap<u32, Leftover>,
    busy: BTreeMap<Lock, VecDeque<Job>>,
}

#[derive(Clone, Copy)]
struct Leftover {
    shard: u16,
    tenant: u32,
    generation: u32,
}

fn encode_floor(next: u64) -> Vec<u8> {
    let mut out = vec![0; FLOOR];
    out[0] = FLOOR_FORMAT;
    out[1] = KIND_FLOOR;
    out[8..].copy_from_slice(&next.to_le_bytes());
    out
}

fn decode_floor(clear: &[u8]) -> Option<u64> {
    let ok = clear.len() == FLOOR
        && clear[0] == FLOOR_FORMAT
        && clear[1] == KIND_FLOOR
        && clear[2..8] == [0; 6];
    ok.then(|| u64::from_le_bytes(clear[8..].try_into().expect("8 bytes")))
}

impl Owned {
    fn take_id(&mut self, shard: u16, shards: u32) -> Option<u32> {
        let next = self.next.get_mut(&shard)?;
        while let Ok(id) = u32::try_from(*next) {
            *next += 1;
            if queue_shard(id, shards) == shard {
                *self.ids.entry(shard).or_default() += 1;
                return Some(id);
            }
        }
        None
    }

    fn floor(&mut self, shard: u16, id: u32, clear: &[u8]) -> bool {
        let Some(floor) = decode_floor(clear).filter(|_| id == u32::from(shard)) else {
            return false;
        };
        self.floors.insert(shard, floor);
        if let Some(next) = self.next.get_mut(&shard) {
            *next = (*next).max(floor);
        }
        true
    }

    fn insert(&mut self, queue: Queue) {
        if !queue.draining {
            self.names.entry(queue.name.clone()).or_insert(queue.id);
        }
        self.queues.insert(queue.id, queue);
    }
}

pub(crate) struct Fixed;

struct Stored {
    head: Head,
    tenant: u32,
    clear: Vec<u8>,
    hidden: Vec<u8>,
}

const KEY_WAIT: Duration = Duration::from_millis(100);
const KEY_WAIT_MAX: Duration = Duration::from_secs(5);

pub(crate) async fn wait_keys(
    keys: &dyn KeySource,
    tenant: u32,
    generation: u32,
) -> Result<(Option<TenantKeys>, u64), Error> {
    let mut pause = KEY_WAIT;
    let mut waits = 0;
    loop {
        match tenant_keys(keys, tenant, generation).await {
            Ok(found) => return Ok((Some(found), waits)),
            Err(KeyError::Unknown) => return Ok((None, waits)),
            Err(KeyError::Unavailable | KeyError::Busy) => {
                waits += 1;
                rt::sleep(pause).await;
                pause = (pause * 2).min(KEY_WAIT_MAX);
            }
            Err(error) => {
                return Err(Error::Keys {
                    tenant,
                    generation,
                    error,
                });
            }
        }
    }
}

impl Owner for Fixed {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        std::future::ready(None)
    }
}

pub struct Loaded {
    naming: Naming,
    owned: Owned,
    skipped: u64,
    waited: u64,
}

impl Loaded {
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    pub fn waited(&self) -> u64 {
        self.waited
    }

    pub fn queues(&self) -> usize {
        self.owned.queues.len()
    }

    pub fn start(
        self,
        ends: Ends<Call>,
        changes: Changes,
        keys: Rc<dyn KeySource>,
    ) -> (Queues, JoinHandle<()>) {
        let inner = Rc::new(Inner {
            naming: self.naming,
            cores: ends.cores(),
            keys,
            changes,
            owned: RefCell::new(self.owned),
            cache: RefCell::new(Cache::new(self.naming.cache)),
            waiting: RefCell::new(BTreeMap::new()),
            forgetting: RefCell::new(BTreeMap::new()),
            tickets: Cell::new(0),
            peers: OnceCell::new(),
            stats: Cell::new(NamingStats {
                skipped: self.skipped,
                ..NamingStats::default()
            }),
            ready: RefCell::new(VecDeque::new()),
            work: Notify::default(),
            closed: Cell::new(false),
        });
        let queues = Queues { inner };
        let handler = queues.clone();
        let (peers, mesh) = ends.start(move |from, call| handler.handle(from, call));
        let _ = queues.inner.peers.set(peers);
        let worker = queues.clone();
        let work = spawn(async move { worker.work().await });
        let done = spawn(async move {
            work.await;
            mesh.await;
        });
        (queues, done)
    }
}

struct Inner {
    naming: Naming,
    cores: u16,
    keys: Rc<dyn KeySource>,
    changes: Changes,
    owned: RefCell<Owned>,
    cache: RefCell<Cache>,
    waiting: RefCell<BTreeMap<Name, Vec<Sender<Named>>>>,
    forgetting: RefCell<BTreeMap<u64, (u16, Sender<()>)>>,
    tickets: Cell<u64>,
    peers: OnceCell<Peers<Call>>,
    stats: Cell<NamingStats>,
    ready: RefCell<VecDeque<Ready>>,
    work: Notify,
    closed: Cell<bool>,
}

#[derive(Clone)]
pub struct Queues {
    inner: Rc<Inner>,
}

struct Held<'a> {
    queues: &'a Queues,
    lock: Option<Lock>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Some(lock) = self.lock.take() {
            self.queues.release(&lock);
        }
    }
}

impl Queues {
    pub async fn load(
        core: &Core,
        naming: Naming,
        keys: &dyn KeySource,
        gone: &dyn Fn(u32, u32) -> bool,
    ) -> Result<Loaded, Error> {
        let reader = core.file.reader();
        let mut owned = Owned::default();
        let mut skipped = 0;
        let mut waited = 0;
        for &shard in &core.shards {
            let state = core.keeper.state(shard).ok_or(Error::Invalid("shard"))?;
            owned.next.insert(shard, 1);
            owned.ids.insert(shard, 0);
            let mut found: BTreeMap<(u32, u32), Vec<Stored>> = BTreeMap::new();
            for (key, item) in state.entries() {
                if !is_control(key.message) || key.item != HEAD_ITEM {
                    continue;
                }
                let (boot, id) = split_key(key.message);
                let kind = CONTROL_BOOT - boot;
                if kind == u32::from(KIND_FLOOR) {
                    if !owned.floor(shard, id, &item.clear) {
                        skipped += 1;
                    }
                    continue;
                }
                if kind != u32::from(KIND_QUEUE) {
                    continue;
                }
                if let Some(next) = owned.next.get_mut(&shard) {
                    *next = (*next).max(u64::from(id) + 1);
                }
                *owned.ids.entry(shard).or_default() += 1;
                let buf = reader.read(item.location, item.tenant, &Fixed).await?;
                let stored = Record::decode(&buf).ok().and_then(|record| {
                    let parts = Index::parts(record.payload())?;
                    let head = Head::decode(parts.clear)?;
                    Some(Stored {
                        head,
                        tenant: item.tenant,
                        clear: parts.clear.to_vec(),
                        hidden: parts.sealed.to_vec(),
                    })
                });
                let fits = |head: &Head| {
                    head.id == id
                        && head.tenant == item.tenant
                        && queue_shard(id, naming.shards) == shard
                };
                match stored {
                    Some(stored) if fits(&stored.head) => found
                        .entry((stored.head.tenant, stored.head.generation))
                        .or_default()
                        .push(stored),
                    _ => skipped += 1,
                }
            }
            for ((tenant, generation), group) in found {
                if gone(tenant, generation) {
                    skipped += group.len() as u64;
                    for stored in group {
                        owned.leftovers.insert(
                            stored.head.id,
                            Leftover {
                                shard,
                                tenant,
                                generation,
                            },
                        );
                    }
                    continue;
                }
                let (sealing, waits) = wait_keys(keys, tenant, generation).await?;
                waited += waits;
                let Some(sealing) = sealing else {
                    skipped += group.len() as u64;
                    continue;
                };
                for stored in group {
                    let queue = open(&stored.clear, &stored.hidden, &sealing).filter(|q| {
                        q.name.tenant == stored.tenant
                            && queue_shard(q.id, naming.shards) == shard
                            && naming_shard(
                                &naming.key,
                                q.name.tenant,
                                &q.name.domain,
                                naming.shards,
                            ) == shard
                    });
                    match queue {
                        Some(queue) => owned.insert(queue),
                        None => skipped += 1,
                    }
                }
            }
        }
        Ok(Loaded {
            naming,
            owned,
            skipped,
            waited,
        })
    }

    pub fn naming_core(&self, tenant: u32, domain: &str) -> u16 {
        let naming = &self.inner.naming;
        naming_shard(&naming.key, tenant, domain, naming.shards) % self.inner.cores
    }

    pub async fn name(&self, name: &Name) -> Result<u32, Error> {
        name.check()?;
        if let Some(id) = self.inner.cache.borrow_mut().get(name) {
            return Ok(id);
        }
        let (reply, mut answer) = channel();
        let first = {
            let mut waiting = self.inner.waiting.borrow_mut();
            let list = waiting.entry(name.clone()).or_default();
            list.push(reply);
            list.len() == 1
        };
        if first {
            let core = self.naming_core(name.tenant, &name.domain);
            self.send(core, Call::Name(name.clone()));
        }
        match answer.recv().await {
            Some(Ok(id)) => Ok(id),
            Some(Err(Unnamed::Keys(error))) => Err(Error::Keys {
                tenant: name.tenant,
                generation: name.generation,
                error,
            }),
            _ => Err(Error::Refused),
        }
    }

    pub async fn rebind(&self, name: &Name, pool: u32) -> Result<u32, Error> {
        name.check()?;
        let naming = self.inner.naming;
        let shard = naming_shard(&naming.key, name.tenant, &name.domain, naming.shards);
        if !self.inner.owned.borrow().next.contains_key(&shard) {
            return Err(Error::Invalid("core"));
        }
        let held = self.lock((name.tenant, name.domain.clone())).await;
        let (id, target) = {
            let owned = self.inner.owned.borrow();
            let id = *owned.names.get(name).ok_or(Error::Invalid("queue"))?;
            if pool == name.pool {
                return Ok(id);
            }
            let target = owned.names.get(&Name {
                pool,
                ..name.clone()
            });
            (id, target.copied())
        };
        let mut queue = self.inner.owned.borrow().queues[&id].clone();
        queue.name.pool = pool;
        queue.draining = target.is_some();
        self.write(shard, &queue).await?;
        {
            let mut owned = self.inner.owned.borrow_mut();
            owned.names.remove(name);
            owned.insert(queue);
        }
        let mut answer = self.forget_everywhere(|ticket| Call::Forget {
            tenant: name.tenant,
            domain: name.domain.clone(),
            ticket,
        });
        drop(held);
        answer.recv().await.ok_or(Error::Refused)?;
        Ok(target.unwrap_or(id))
    }

    pub async fn sweep(
        &self,
        tenant: u32,
        swept: &dyn Fn(u32, u32) -> bool,
    ) -> Result<usize, Error> {
        let shards = self.inner.naming.shards;
        let mut removed = 0;
        loop {
            let busy: Vec<Lock> = self
                .inner
                .owned
                .borrow()
                .busy
                .keys()
                .filter(|lock| lock.0 == tenant)
                .cloned()
                .collect();
            for lock in busy {
                drop(self.lock(lock).await);
            }
            let found: Vec<(u32, Option<Lock>)> = {
                let owned = self.inner.owned.borrow();
                let queues = owned
                    .queues
                    .values()
                    .filter(|q| q.name.tenant == tenant && swept(tenant, q.name.generation))
                    .map(|q| (q.id, Some((tenant, q.name.domain.clone()))));
                let leftovers = owned
                    .leftovers
                    .iter()
                    .filter(|(_, l)| l.tenant == tenant && swept(tenant, l.generation))
                    .map(|(&id, _)| (id, None));
                queues.chain(leftovers).collect()
            };
            if found.is_empty() {
                break;
            }
            for (id, lock) in found {
                let held = match lock {
                    Some(lock) => Some(self.lock(lock).await),
                    None => None,
                };
                let shard = {
                    let owned = self.inner.owned.borrow();
                    let queue = owned
                        .queues
                        .get(&id)
                        .filter(|q| swept(tenant, q.name.generation))
                        .map(|_| queue_shard(id, shards));
                    let leftover = owned
                        .leftovers
                        .get(&id)
                        .filter(|l| swept(tenant, l.generation))
                        .map(|l| l.shard);
                    queue.or(leftover)
                };
                if let Some(shard) = shard {
                    self.raise_floor(shard).await?;
                    self.drop_queue(shard, id, tenant).await?;
                    removed += 1;
                }
                drop(held);
            }
        }
        if removed > 0 {
            let mut answer = self.forget_everywhere(|ticket| Call::ForgetTenant { tenant, ticket });
            answer.recv().await.ok_or(Error::Refused)?;
        }
        Ok(removed)
    }

    pub fn leftovers(&self) -> usize {
        self.inner.owned.borrow().leftovers.len()
    }

    fn forget_everywhere(&self, call: impl Fn(u64) -> Call) -> rt::Receiver<()> {
        let (reply, answer) = channel();
        let ticket = self.inner.tickets.get();
        self.inner.tickets.set(ticket + 1);
        self.inner
            .forgetting
            .borrow_mut()
            .insert(ticket, (self.inner.cores, reply));
        for core in 0..self.inner.cores {
            self.send(core, call(ticket));
        }
        answer
    }

    async fn raise_floor(&self, shard: u16) -> Result<(), Error> {
        let (next, floor) = {
            let owned = self.inner.owned.borrow();
            let next = owned
                .next
                .get(&shard)
                .copied()
                .ok_or(Error::Invalid("shard"))?;
            (next, owned.floors.get(&shard).copied().unwrap_or(0))
        };
        if floor >= next {
            return Ok(());
        }
        let batch = Batch {
            shard,
            message: control_key(KIND_FLOOR, u32::from(shard)),
            tenant: SYSTEM,
            ops: vec![Op {
                item: HEAD_ITEM,
                change: Change::Put(Delivery {
                    status: 0,
                    attempts: 0,
                    due: 0,
                }),
                clear: encode_floor(next),
                bodies: Vec::new(),
                sealed: Vec::new(),
            }],
        };
        self.inner.changes.apply(batch).await?;
        let mut owned = self.inner.owned.borrow_mut();
        let floor = owned.floors.entry(shard).or_default();
        *floor = (*floor).max(next);
        Ok(())
    }

    async fn drop_queue(&self, shard: u16, id: u32, tenant: u32) -> Result<(), Error> {
        let batch = Batch {
            shard,
            message: control_key(KIND_QUEUE, id),
            tenant,
            ops: vec![Op {
                item: HEAD_ITEM,
                change: Change::Drop,
                clear: Vec::new(),
                bodies: Vec::new(),
                sealed: Vec::new(),
            }],
        };
        self.inner.changes.apply(batch).await?;
        let mut owned = self.inner.owned.borrow_mut();
        if let Some(queue) = owned.queues.remove(&id)
            && owned.names.get(&queue.name) == Some(&id)
        {
            owned.names.remove(&queue.name);
        }
        owned.leftovers.remove(&id);
        if let Some(count) = owned.ids.get_mut(&shard) {
            *count = count.saturating_sub(1);
        }
        Ok(())
    }

    pub fn entry(&self, id: u32) -> Option<Queue> {
        self.inner.owned.borrow().queues.get(&id).cloned()
    }

    pub fn owned(&self, name: &Name) -> Option<u32> {
        self.inner.owned.borrow().names.get(name).copied()
    }

    pub fn ids(&self) -> Vec<(u16, u32)> {
        self.inner
            .owned
            .borrow()
            .ids
            .iter()
            .map(|(s, n)| (*s, *n))
            .collect()
    }

    pub fn crowded(&self) -> bool {
        let half = (1_u64 << 32) / u64::from(self.inner.naming.shards) / 2;
        self.inner
            .owned
            .borrow()
            .ids
            .values()
            .any(|n| u64::from(*n) >= half)
    }

    pub fn stats(&self) -> NamingStats {
        NamingStats {
            cache: self.inner.cache.borrow().stats(),
            ..self.inner.stats.get()
        }
    }

    pub fn cached(&self) -> usize {
        self.inner.cache.borrow().len()
    }

    pub fn close(&self) {
        self.inner.closed.set(true);
        self.inner.work.notify();
        self.inner.waiting.borrow_mut().clear();
        self.inner.forgetting.borrow_mut().clear();
        if let Some(peers) = self.inner.peers.get() {
            peers.close();
        }
    }

    fn send(&self, core: u16, call: Call) {
        if let Some(peers) = self.inner.peers.get() {
            peers.send(core, call);
        }
    }

    fn count(&self, change: impl FnOnce(&mut NamingStats)) {
        let mut stats = self.inner.stats.get();
        change(&mut stats);
        self.inner.stats.set(stats);
    }

    fn handle(&self, from: u16, call: Call) {
        match call {
            Call::Name(name) => self.asked(name, from),
            Call::Named { name, id } => {
                if let Ok(id) = id {
                    self.inner.cache.borrow_mut().put(name.clone(), id);
                }
                let waiting = self.inner.waiting.borrow_mut().remove(&name);
                for reply in waiting.into_iter().flatten() {
                    let _ = reply.send(id);
                }
            }
            Call::Forget {
                tenant,
                domain,
                ticket,
            } => {
                self.inner.cache.borrow_mut().forget(tenant, &domain);
                self.send(from, Call::Forgot { ticket });
            }
            Call::ForgetTenant { tenant, ticket } => {
                self.inner.cache.borrow_mut().forget_tenant(tenant);
                self.send(from, Call::Forgot { ticket });
            }
            Call::Forgot { ticket } => {
                let mut forgetting = self.inner.forgetting.borrow_mut();
                let Some(entry) = forgetting.get_mut(&ticket) else {
                    return;
                };
                entry.0 -= 1;
                if entry.0 == 0
                    && let Some((_, reply)) = forgetting.remove(&ticket)
                {
                    let _ = reply.send(());
                }
            }
        }
    }

    fn asked(&self, name: Name, from: u16) {
        let lock = (name.tenant, name.domain.clone());
        {
            let mut owned = self.inner.owned.borrow_mut();
            if let Some(jobs) = owned.busy.get_mut(&lock) {
                jobs.push_back(Job::Name { name, from });
                return;
            }
            owned.busy.insert(lock.clone(), VecDeque::new());
        }
        if !self.serve(name, from) {
            self.release(&lock);
        }
    }

    fn serve(&self, name: Name, from: u16) -> bool {
        let naming = self.inner.naming;
        let id = {
            let mut owned = self.inner.owned.borrow_mut();
            if let Some(&id) = owned.names.get(&name) {
                drop(owned);
                self.send(from, Call::Named { name, id: Ok(id) });
                return false;
            }
            let shard = naming_shard(&naming.key, name.tenant, &name.domain, naming.shards);
            if name.check().is_err() || !owned.next.contains_key(&shard) {
                None
            } else {
                owned.take_id(shard, naming.shards).map(|id| (shard, id))
            }
        };
        let Some((shard, id)) = id else {
            self.count(|s| s.refused += 1);
            self.send(
                from,
                Call::Named {
                    name,
                    id: Err(Unnamed::Refused),
                },
            );
            return false;
        };
        self.inner.ready.borrow_mut().push_back(Ready {
            name,
            from,
            shard,
            id,
        });
        self.inner.work.notify();
        true
    }

    fn release(&self, lock: &Lock) {
        loop {
            let job = self
                .inner
                .owned
                .borrow_mut()
                .busy
                .get_mut(lock)
                .and_then(VecDeque::pop_front);
            match job {
                None => {
                    self.inner.owned.borrow_mut().busy.remove(lock);
                    return;
                }
                Some(Job::Wake(wake)) => {
                    if wake.send(()).is_ok() {
                        return;
                    }
                }
                Some(Job::Name { name, from }) => {
                    if self.serve(name, from) {
                        return;
                    }
                }
            }
        }
    }

    async fn work(&self) {
        while !self.inner.closed.get() {
            while let Some(ready) = self.inner.ready.borrow_mut().pop_front() {
                let queues = self.clone();
                drop(spawn(async move { queues.allocate(ready).await }));
            }
            self.inner.work.wait().await;
        }
    }

    async fn allocate(&self, ready: Ready) {
        let Ready {
            name,
            from,
            shard,
            id,
        } = ready;
        let held = Held {
            queues: self,
            lock: Some((name.tenant, name.domain.clone())),
        };
        let queue = Queue {
            id,
            name: name.clone(),
            draining: false,
        };
        let id = match self.write(shard, &queue).await {
            Ok(()) => {
                self.inner.owned.borrow_mut().insert(queue);
                self.count(|s| s.allocated += 1);
                Ok(id)
            }
            Err(Error::Keys { error, .. }) => {
                self.count(|s| s.keys += 1);
                Err(Unnamed::Keys(error))
            }
            Err(_) => {
                self.count(|s| s.failed += 1);
                Err(Unnamed::Failed)
            }
        };
        self.send(from, Call::Named { name, id });
        drop(held);
    }

    async fn lock(&self, lock: Lock) -> Held<'_> {
        let wait = {
            let mut owned = self.inner.owned.borrow_mut();
            if let Some(jobs) = owned.busy.get_mut(&lock) {
                let (wake, woken) = channel();
                jobs.push_back(Job::Wake(wake));
                Some(woken)
            } else {
                owned.busy.insert(lock.clone(), VecDeque::new());
                None
            }
        };
        let held = Held {
            queues: self,
            lock: Some(lock),
        };
        if let Some(mut woken) = wait {
            woken.recv().await;
        }
        held
    }

    async fn write(&self, shard: u16, queue: &Queue) -> Result<(), Error> {
        let (tenant, generation) = (queue.name.tenant, queue.name.generation);
        let label = Label {
            tenant,
            generation,
            kind: KIND_QUEUE,
            id: queue.id,
            hash: None,
        };
        let sealing = tenant_keys(self.inner.keys.as_ref(), tenant, generation)
            .await
            .map_err(|error| Error::Keys {
                tenant,
                generation,
                error,
            })?;
        let sealed = sealing
            .seal(&label.bytes(), queue.name.domain.as_bytes())
            .map_err(|_| Error::Invalid("seal"))?;
        let batch = Batch {
            shard,
            message: control_key(KIND_QUEUE, queue.id),
            tenant: queue.name.tenant,
            ops: vec![Op {
                item: HEAD_ITEM,
                change: Change::Put(Delivery {
                    status: 0,
                    attempts: 0,
                    due: 0,
                }),
                clear: queue.encode(),
                bodies: Vec::new(),
                sealed,
            }],
        };
        self.inner.changes.apply(batch).await?;
        Ok(())
    }
}

impl Tenancy for Queues {
    fn holder(&self, queue: u32) -> Option<(u32, u32)> {
        let owned = self.inner.owned.borrow();
        let queue = owned.queues.get(&queue)?;
        Some((queue.name.tenant, queue.name.generation))
    }

    fn name(&self, queue: u32) -> Option<Name> {
        let owned = self.inner.owned.borrow();
        owned.queues.get(&queue).map(|q| q.name.clone())
    }
}

fn open(clear: &[u8], hidden: &[u8], keys: &TenantKeys) -> Option<Queue> {
    let head = Head::decode(clear)?;
    let label = Label {
        tenant: head.tenant,
        generation: head.generation,
        kind: KIND_QUEUE,
        id: head.id,
        hash: None,
    };
    let domain = String::from_utf8(keys.open(&label.bytes(), hidden).ok()?).ok()?;
    Queue::decode(clear, domain.into())
}
