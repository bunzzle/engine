use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use rt::{Ends, JoinHandle, Notify, Peers, Sender, channel, spawn};
use store::{
    Batch, CONTROL_BOOT, Change, Changes, Core, Delivery, HEAD_ITEM, Index, Location, Op, Owner,
    Record, control_key, is_control, split_key,
};

use crate::cache::{Cache, CacheStats};
use crate::error::Error;
use crate::queue::{Head, Label, Name, Queue, Sealer, Tenancy, naming_shard, queue_shard};
use crate::record::KIND_QUEUE;

pub enum Call {
    Name(Name),
    Named {
        name: Name,
        id: Option<u32>,
    },
    Forget {
        tenant: u32,
        domain: Box<str>,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NamingStats {
    pub cache: CacheStats,
    pub allocated: u64,
    pub failed: u64,
    pub refused: u64,
    pub skipped: u64,
}

type Lock = (u32, Box<str>);

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
    busy: BTreeMap<Lock, VecDeque<Job>>,
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

    fn insert(&mut self, queue: Queue) {
        if !queue.draining {
            self.names.entry(queue.name.clone()).or_insert(queue.id);
        }
        self.queues.insert(queue.id, queue);
    }
}

struct Fixed;

impl Owner for Fixed {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        std::future::ready(None)
    }
}

pub struct Loaded {
    naming: Naming,
    owned: Owned,
    skipped: u64,
}

impl Loaded {
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    pub fn queues(&self) -> usize {
        self.owned.queues.len()
    }

    pub fn start(
        self,
        ends: Ends<Call>,
        changes: Changes,
        sealer: Rc<dyn Sealer>,
    ) -> (Queues, JoinHandle<()>) {
        let inner = Rc::new(Inner {
            naming: self.naming,
            cores: ends.cores(),
            sealer,
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
    sealer: Rc<dyn Sealer>,
    changes: Changes,
    owned: RefCell<Owned>,
    cache: RefCell<Cache>,
    waiting: RefCell<BTreeMap<Name, Vec<Sender<Option<u32>>>>>,
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
    pub async fn load(core: &Core, naming: Naming, sealer: &dyn Sealer) -> Result<Loaded, Error> {
        let reader = core.file.reader();
        let mut owned = Owned::default();
        let mut skipped = 0;
        for &shard in &core.shards {
            let state = core.keeper.state(shard).ok_or(Error::Invalid("shard"))?;
            owned.next.insert(shard, 1);
            owned.ids.insert(shard, 0);
            for (key, item) in state.entries() {
                if !is_control(key.message) || key.item != HEAD_ITEM {
                    continue;
                }
                let (boot, id) = split_key(key.message);
                if CONTROL_BOOT - boot != u32::from(KIND_QUEUE) {
                    continue;
                }
                if let Some(next) = owned.next.get_mut(&shard) {
                    *next = (*next).max(u64::from(id) + 1);
                }
                *owned.ids.entry(shard).or_default() += 1;
                let buf = reader.read(item.location, item.tenant, &Fixed).await?;
                let queue = Record::decode(&buf)
                    .ok()
                    .and_then(|record| {
                        let parts = Index::parts(record.payload())?;
                        open(parts.clear, parts.sealed, sealer)
                    })
                    .filter(|q| {
                        q.id == id
                            && q.name.tenant == item.tenant
                            && queue_shard(id, naming.shards) == shard
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
        Ok(Loaded {
            naming,
            owned,
            skipped,
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
        answer.recv().await.flatten().ok_or(Error::Refused)
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
        let (reply, mut answer) = channel();
        let ticket = self.inner.tickets.get();
        self.inner.tickets.set(ticket + 1);
        self.inner
            .forgetting
            .borrow_mut()
            .insert(ticket, (self.inner.cores, reply));
        for core in 0..self.inner.cores {
            self.send(
                core,
                Call::Forget {
                    tenant: name.tenant,
                    domain: name.domain.clone(),
                    ticket,
                },
            );
        }
        drop(held);
        answer.recv().await.ok_or(Error::Refused)?;
        Ok(target.unwrap_or(id))
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
                if let Some(id) = id {
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
                self.send(from, Call::Named { name, id: Some(id) });
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
            self.send(from, Call::Named { name, id: None });
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
        let id = if self.write(shard, &queue).await.is_ok() {
            self.inner.owned.borrow_mut().insert(queue);
            self.count(|s| s.allocated += 1);
            Some(id)
        } else {
            self.count(|s| s.failed += 1);
            None
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
        let label = Label {
            tenant: queue.name.tenant,
            generation: queue.name.generation,
            kind: KIND_QUEUE,
            id: queue.id,
        };
        let sealed = self.inner.sealer.seal(&label, queue.name.domain.as_bytes());
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
}

fn open(clear: &[u8], hidden: &[u8], sealer: &dyn Sealer) -> Option<Queue> {
    let head = Head::decode(clear)?;
    let label = Label {
        tenant: head.tenant,
        generation: head.generation,
        kind: KIND_QUEUE,
        id: head.id,
    };
    let domain = String::from_utf8(sealer.open(&label, hidden)?).ok()?;
    Queue::decode(clear, domain.into())
}
