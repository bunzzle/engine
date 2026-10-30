use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;

use rt::{Ends, Instant, JoinHandle, Notify, Peers, Sender, channel, spawn, timeout};

use crate::error::Error;
use crate::queue::queue_shard;
use crate::record::Limits;

pub const LIFETIME: Duration = Duration::from_millis(100);
pub const WAIT: Duration = Duration::from_millis(50);
pub const IDLE: Duration = Duration::from_secs(1);

const SECOND: u64 = 1_000_000_000;

pub fn limit_core(tenant: u32, shards: u32, cores: u16) -> u16 {
    queue_shard(tenant, shards) % cores
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tokens {
    pub count: u32,
    pub until: Instant,
    pub next: Option<Instant>,
}

pub enum Ask<K> {
    Want {
        key: K,
        tokens: u32,
        slots: u64,
    },
    Grant {
        key: K,
        tokens: Option<Tokens>,
        slots: Option<u64>,
    },
    Recall {
        key: K,
    },
    Return {
        key: K,
        slots: u64,
    },
    Open {
        key: K,
        slots: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Taken {
    pub token: Option<Instant>,
    pub slot: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeaseStats {
    pub granted: u64,
    pub lapsed: u64,
    pub busy: u64,
    pub recalls: u64,
    pub returned: u64,
}

struct Lease {
    batches: VecDeque<(Instant, u32)>,
    free: u64,
    used: u64,
    token_size: u32,
    slot_size: u64,
    token_ask: Option<Instant>,
    token_next: Option<Instant>,
    slot_ask: Option<Instant>,
    recalled: bool,
    touched: Instant,
    waiters: Vec<Sender<()>>,
}

impl Lease {
    fn new(now: Instant) -> Self {
        Self {
            batches: VecDeque::new(),
            free: 0,
            used: 0,
            token_size: 1,
            slot_size: 1,
            token_ask: None,
            token_next: None,
            slot_ask: None,
            recalled: false,
            touched: now,
            waiters: Vec::new(),
        }
    }

    fn lapse(&mut self, now: Instant) -> u64 {
        let mut lapsed = 0;
        while let Some(&(until, count)) = self.batches.front() {
            if until > now {
                break;
            }
            self.batches.pop_front();
            lapsed += u64::from(count);
        }
        if lapsed > 0 {
            self.token_size = (self.token_size / 2).max(1);
        }
        lapsed
    }

    fn wake_at(&self, now: Instant) -> Option<Instant> {
        [
            self.token_next,
            self.token_ask.map(|at| at + LIFETIME),
            self.slot_ask.map(|at| at + LIFETIME),
            self.batches.front().map(|b| b.0),
        ]
        .into_iter()
        .flatten()
        .filter(|at| *at > now)
        .min()
    }

    fn tokens(&self) -> u32 {
        self.batches.iter().map(|b| b.1).sum()
    }

    fn idle(&self) -> bool {
        self.batches.is_empty()
            && self.free == 0
            && self.used == 0
            && self.token_ask.is_none()
            && self.slot_ask.is_none()
            && self.waiters.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gcra {
    tat: u64,
}

impl Gcra {
    pub fn grant(&mut self, limits: Limits, want: u32, now: Instant) -> Tokens {
        let period = (SECOND / u64::from(limits.rate.max(1))).max(1);
        let burst = u64::from(limits.burst.max(1));
        let now_ns = now.as_nanos();
        let base = self.tat.max(now_ns);
        let edge = now_ns + (burst - 1) * period;
        if base > edge {
            return Tokens {
                count: 0,
                until: now,
                next: Some(Instant::from_nanos(base - (burst - 1) * period)),
            };
        }
        let cap = (limits.rate / 10).max(1);
        let most = (edge - base) / period + 1;
        let count = u32::try_from(most.min(u64::from(want.min(cap)))).expect("fits in u32");
        self.tat = base + u64::from(count) * period;
        Tokens {
            count,
            until: now + LIFETIME,
            next: None,
        }
    }
}

#[derive(Default)]
struct Owned {
    gcra: Gcra,
    held: BTreeMap<u16, u64>,
    granted: u64,
    waiting: VecDeque<(u16, u64)>,
}

type Route<K> = Rc<dyn Fn(&K) -> u16>;
type Rules<K> = Rc<dyn Fn(&K) -> Option<Limits>>;

struct Inner<K> {
    owner: Route<K>,
    limits: Rules<K>,
    leases: RefCell<BTreeMap<K, Lease>>,
    owned: RefCell<BTreeMap<K, Owned>>,
    peers: OnceCell<Peers<Ask<K>>>,
    stats: Cell<LeaseStats>,
    closed: Cell<bool>,
    tick: Notify,
}

pub struct Leases<K> {
    inner: Rc<Inner<K>>,
}

impl<K> Clone for Leases<K> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<K: Ord + Clone + Send + 'static> Leases<K> {
    pub fn start(
        ends: Ends<Ask<K>>,
        owner: impl Fn(&K) -> u16 + 'static,
        limits: impl Fn(&K) -> Option<Limits> + 'static,
    ) -> (Self, JoinHandle<()>) {
        let inner = Rc::new(Inner {
            owner: Rc::new(owner),
            limits: Rc::new(limits),
            leases: RefCell::new(BTreeMap::new()),
            owned: RefCell::new(BTreeMap::new()),
            peers: OnceCell::new(),
            stats: Cell::new(LeaseStats::default()),
            closed: Cell::new(false),
            tick: Notify::default(),
        });
        let leases = Self { inner };
        let handler = leases.clone();
        let (peers, mesh) = ends.start(move |from, ask| handler.handle(from, ask));
        let _ = leases.inner.peers.set(peers);
        let ticker = leases.clone();
        let idle = spawn(async move { ticker.idle().await });
        let done = spawn(async move {
            idle.await;
            mesh.await;
        });
        (leases, done)
    }

    pub fn restore(&self, counts: impl IntoIterator<Item = (K, u64)>) {
        let now = rt::now();
        for (key, slots) in counts {
            if slots == 0 {
                continue;
            }
            self.inner
                .leases
                .borrow_mut()
                .entry(key.clone())
                .or_insert_with(|| Lease::new(now))
                .used += slots;
            self.send((self.inner.owner)(&key), Ask::Open { key, slots });
        }
    }

    pub async fn take(&self, key: &K) -> Result<Taken, Error> {
        let limits = (self.inner.limits)(key).ok_or(Error::Invalid("key"))?;
        let deadline = rt::now() + WAIT;
        loop {
            let now = rt::now();
            if let Some(taken) = self.try_take(key, limits, now) {
                return Ok(taken);
            }
            let (wake, mut woken) = channel();
            self.ask(key, limits, now);
            let until = {
                let mut leases = self.inner.leases.borrow_mut();
                let lease = leases.get_mut(key).expect("lease made by try_take");
                lease.waiters.push(wake);
                lease.wake_at(now).map_or(deadline, |at| at.min(deadline))
            };
            let wait = until.saturating_duration_since(now);
            if now >= deadline || (timeout(wait, woken.recv()).await.is_err() && until >= deadline)
            {
                self.count(|s| s.busy += 1);
                return Err(Error::Busy);
            }
        }
    }

    pub fn give_back(&self, key: &K, taken: Taken) {
        let now = rt::now();
        let mut leases = self.inner.leases.borrow_mut();
        let Some(lease) = leases.get_mut(key) else {
            return;
        };
        if let Some(until) = taken.token
            && until > now
            && let Some(batch) = lease.batches.iter_mut().find(|b| b.0 == until)
        {
            batch.1 += 1;
        }
        if taken.slot {
            lease.used = lease.used.saturating_sub(1);
            lease.free += 1;
        }
    }

    pub fn free(&self, key: &K, slots: u64) {
        let back = {
            let mut leases = self.inner.leases.borrow_mut();
            let Some(lease) = leases.get_mut(key) else {
                return;
            };
            let slots = slots.min(lease.used);
            lease.used -= slots;
            lease.free += slots;
            if lease.recalled && lease.free > 0 {
                lease.recalled = false;
                std::mem::take(&mut lease.free)
            } else {
                0
            }
        };
        if back > 0 {
            self.give_slots(key.clone(), back);
        }
    }

    pub fn used(&self, key: &K) -> u64 {
        self.inner.leases.borrow().get(key).map_or(0, |l| l.used)
    }

    pub fn held(&self, key: &K) -> u64 {
        self.inner
            .leases
            .borrow()
            .get(key)
            .map_or(0, |l| l.used + l.free)
    }

    pub fn granted(&self, key: &K) -> u64 {
        self.inner.owned.borrow().get(key).map_or(0, |o| o.granted)
    }

    pub fn stats(&self) -> LeaseStats {
        self.inner.stats.get()
    }

    pub fn close(&self) {
        self.inner.closed.set(true);
        self.inner.tick.notify();
        for lease in self.inner.leases.borrow_mut().values_mut() {
            lease.waiters.clear();
        }
        if let Some(peers) = self.inner.peers.get() {
            peers.close();
        }
    }

    fn send(&self, core: u16, ask: Ask<K>) {
        if let Some(peers) = self.inner.peers.get() {
            peers.send(core, ask);
        }
    }

    fn count(&self, change: impl FnOnce(&mut LeaseStats)) {
        let mut stats = self.inner.stats.get();
        change(&mut stats);
        self.inner.stats.set(stats);
    }

    fn try_take(&self, key: &K, limits: Limits, now: Instant) -> Option<Taken> {
        let mut leases = self.inner.leases.borrow_mut();
        let lease = leases.entry(key.clone()).or_insert_with(|| Lease::new(now));
        lease.touched = now;
        let lapsed = lease.lapse(now);
        let need_token = limits.rate > 0;
        let need_slot = limits.queued > 0;
        let short_tokens = need_token && lease.batches.is_empty();
        let short_slots = need_slot && lease.free == 0;
        let low = (need_token && lease.tokens() <= lease.token_size / 2)
            || (need_slot && lease.free <= lease.slot_size / 2);
        let taken = if short_tokens || short_slots {
            None
        } else {
            let token = need_token.then(|| {
                let batch = lease.batches.front_mut().expect("tokens present");
                batch.1 -= 1;
                let until = batch.0;
                if batch.1 == 0 {
                    lease.batches.pop_front();
                }
                until
            });
            if need_slot {
                lease.free -= 1;
                lease.used += 1;
                if lease.free == 0 {
                    lease.slot_size = lease.slot_size.saturating_mul(2);
                }
            }
            if need_token && lease.batches.is_empty() {
                lease.token_size = lease.token_size.saturating_mul(2);
            }
            Some(Taken {
                token,
                slot: need_slot,
            })
        };
        drop(leases);
        if lapsed > 0 {
            self.count(|s| s.lapsed += lapsed);
        }
        if taken.is_none() || low {
            self.ask(key, limits, now);
        }
        taken
    }

    fn ask(&self, key: &K, limits: Limits, now: Instant) {
        let open = |sent: Option<Instant>| sent.is_none_or(|at| at + LIFETIME <= now);
        let (tokens, slots) = {
            let mut leases = self.inner.leases.borrow_mut();
            let Some(lease) = leases.get_mut(key) else {
                return;
            };
            lease.token_size = lease.token_size.min((limits.rate / 10).max(1));
            lease.slot_size = lease.slot_size.min((limits.queued / 8).max(1));
            let have = lease.tokens();
            let tokens = if limits.rate > 0
                && open(lease.token_ask)
                && lease.token_next.is_none_or(|n| n <= now)
                && have <= lease.token_size / 2
            {
                (lease.token_size - have).max(1)
            } else {
                0
            };
            let slots =
                if limits.queued > 0 && open(lease.slot_ask) && lease.free <= lease.slot_size / 2 {
                    (lease.slot_size - lease.free).max(1)
                } else {
                    0
                };
            if tokens > 0 {
                lease.token_ask = Some(now);
            }
            if slots > 0 {
                lease.slot_ask = Some(now);
            }
            (tokens, slots)
        };
        if tokens > 0 || slots > 0 {
            self.send(
                (self.inner.owner)(key),
                Ask::Want {
                    key: key.clone(),
                    tokens,
                    slots,
                },
            );
        }
    }

    fn give_slots(&self, key: K, slots: u64) {
        self.count(|s| s.returned += slots);
        self.send((self.inner.owner)(&key), Ask::Return { key, slots });
    }

    fn handle(&self, from: u16, ask: Ask<K>) {
        match ask {
            Ask::Want { key, tokens, slots } => self.want(from, key, tokens, slots),
            Ask::Grant { key, tokens, slots } => self.granted_to_me(&key, tokens, slots),
            Ask::Recall { key } => self.recall(key),
            Ask::Return { key, slots } => {
                {
                    let mut owned = self.inner.owned.borrow_mut();
                    let entry = owned.entry(key.clone()).or_default();
                    let held = entry.held.entry(from).or_default();
                    let slots = slots.min(*held);
                    *held -= slots;
                    entry.granted -= slots;
                }
                self.serve(&key);
            }
            Ask::Open { key, slots } => {
                let mut owned = self.inner.owned.borrow_mut();
                let entry = owned.entry(key).or_default();
                *entry.held.entry(from).or_default() += slots;
                entry.granted += slots;
            }
        }
    }

    fn want(&self, from: u16, key: K, tokens: u32, slots: u64) {
        let Some(limits) = (self.inner.limits)(&key) else {
            return;
        };
        self.serve(&key);
        let now = rt::now();
        let mut recall = false;
        let grant = {
            let mut owned = self.inner.owned.borrow_mut();
            let entry = owned.entry(key.clone()).or_default();
            let tokens = (tokens > 0).then(|| entry.gcra.grant(limits, tokens, now));
            let slots = if slots > 0 {
                let room = limits.queued.saturating_sub(entry.granted);
                let given = slots.min(room);
                if given == 0 {
                    if !entry.waiting.iter().any(|w| w.0 == from) {
                        entry.waiting.push_back((from, slots));
                    }
                    recall = true;
                    None
                } else {
                    *entry.held.entry(from).or_default() += given;
                    entry.granted += given;
                    Some(given)
                }
            } else {
                None
            };
            (tokens, slots)
        };
        if recall {
            self.count(|s| s.recalls += 1);
            let holders: Vec<u16> = self.inner.owned.borrow()[&key]
                .held
                .iter()
                .filter(|(core, held)| **core != from && **held > 0)
                .map(|(core, _)| *core)
                .collect();
            for core in holders {
                self.send(core, Ask::Recall { key: key.clone() });
            }
        }
        if let Some(t) = grant.0 {
            self.count(|s| s.granted += u64::from(t.count));
        }
        if grant.0.is_some() || grant.1.is_some() {
            self.send(
                from,
                Ask::Grant {
                    key,
                    tokens: grant.0,
                    slots: grant.1,
                },
            );
        }
    }

    fn serve(&self, key: &K) {
        let Some(limits) = (self.inner.limits)(key) else {
            return;
        };
        let mut grants = Vec::new();
        {
            let mut owned = self.inner.owned.borrow_mut();
            let Some(entry) = owned.get_mut(key) else {
                return;
            };
            while let Some(&(core, want)) = entry.waiting.front() {
                let room = limits.queued.saturating_sub(entry.granted);
                let given = want.min(room);
                if given == 0 {
                    break;
                }
                entry.waiting.pop_front();
                *entry.held.entry(core).or_default() += given;
                entry.granted += given;
                grants.push((core, given));
            }
        }
        for (core, given) in grants {
            self.send(
                core,
                Ask::Grant {
                    key: key.clone(),
                    tokens: None,
                    slots: Some(given),
                },
            );
        }
    }

    fn granted_to_me(&self, key: &K, tokens: Option<Tokens>, slots: Option<u64>) {
        let waiters = {
            let mut leases = self.inner.leases.borrow_mut();
            let now = rt::now();
            let lease = leases.entry(key.clone()).or_insert_with(|| Lease::new(now));
            if let Some(t) = tokens {
                lease.token_ask = None;
                lease.token_next = t.next;
                if t.count > 0 {
                    lease.batches.push_back((t.until, t.count));
                }
            }
            if let Some(slots) = slots {
                lease.slot_ask = None;
                lease.free += slots;
            }
            std::mem::take(&mut lease.waiters)
        };
        for wake in waiters {
            let _ = wake.send(());
        }
    }

    fn recall(&self, key: K) {
        let back = {
            let mut leases = self.inner.leases.borrow_mut();
            let Some(lease) = leases.get_mut(&key) else {
                return;
            };
            lease.slot_size = (lease.slot_size / 2).max(1);
            if lease.free == 0 {
                lease.recalled = true;
            }
            std::mem::take(&mut lease.free)
        };
        if back > 0 {
            self.give_slots(key, back);
        }
    }

    async fn idle(&self) {
        while !self.inner.closed.get() {
            let _ = timeout(IDLE, self.inner.tick.wait()).await;
            if self.inner.closed.get() {
                return;
            }
            let now = rt::now();
            let mut back = Vec::new();
            let mut lapsed = 0;
            {
                let mut leases = self.inner.leases.borrow_mut();
                for (key, lease) in leases.iter_mut() {
                    lapsed += lease.lapse(now);
                    if lease.free > 0 && now.saturating_duration_since(lease.touched) >= IDLE {
                        back.push((key.clone(), std::mem::take(&mut lease.free)));
                        lease.slot_size = 1;
                    }
                }
                leases.retain(|_, lease| !lease.idle());
            }
            if lapsed > 0 {
                self.count(|s| s.lapsed += lapsed);
            }
            for (key, slots) in back {
                self.give_slots(key, slots);
            }
        }
    }
}
