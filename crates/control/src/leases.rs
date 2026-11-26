use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use rt::{Ends, Instant, JoinHandle, Notify, Peers, Sender, channel, spawn, timeout};

use crate::error::Error;
use crate::queue::queue_shard;
use crate::record::Limits;

pub const LIFETIME: Duration = Duration::from_millis(100);
pub const WAIT: Duration = Duration::from_millis(50);
pub const IDLE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rate {
    period: u64,
}

impl Rate {
    pub const NONE: Self = Self { period: 0 };

    pub fn per(count: u32, span: Duration) -> Self {
        if count == 0 {
            return Self::NONE;
        }
        let period = span.as_nanos() / u128::from(count);
        Self {
            period: u64::try_from(period).unwrap_or(u64::MAX).max(1),
        }
    }

    pub fn per_second(count: u32) -> Self {
        Self::per(count, Duration::from_secs(1))
    }

    pub fn per_minute(count: u32) -> Self {
        Self::per(count, Duration::from_secs(60))
    }

    pub fn per_hour(count: u32) -> Self {
        Self::per(count, Duration::from_secs(3_600))
    }

    pub fn period(self) -> Option<Duration> {
        (self.period > 0).then(|| Duration::from_nanos(self.period))
    }

    fn limited(self) -> bool {
        self.period > 0
    }

    fn per_lifetime(self) -> u32 {
        let life = u64::try_from(LIFETIME.as_nanos()).expect("fits in u64");
        let count = life / self.period.max(1);
        u32::try_from(count).unwrap_or(u32::MAX).max(1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    initial: u32,
    cool: Duration,
    dead: Duration,
}

impl Window {
    pub fn new(initial: u32, cool: Duration, dead: Duration) -> Self {
        Self {
            initial,
            cool,
            dead,
        }
    }
}

impl Default for Window {
    fn default() -> Self {
        Self {
            initial: 5,
            cool: Duration::from_secs(60),
            dead: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Success,
    Throttle,
    Failure,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quota {
    pub rate: Rate,
    pub burst: u32,
    pub queued: u64,
    pub window: Option<Window>,
}

impl From<Limits> for Quota {
    fn from(limits: Limits) -> Self {
        Self {
            rate: Rate::per_second(limits.rate),
            burst: limits.burst,
            queued: limits.queued,
            window: None,
        }
    }
}

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
    Opened,
    Block {
        key: K,
        on: bool,
    },
    Blocked {
        key: K,
        on: bool,
    },
    Feedback {
        key: K,
        signal: Signal,
        used: u64,
    },
    Shed {
        key: K,
        slots: u64,
    },
    Dead {
        egress: IpAddr,
        remote: IpAddr,
        until: Instant,
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
    pub cuts: u64,
    pub deaths: u64,
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
    blocked: bool,
    owe: u64,
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
            blocked: false,
            owe: 0,
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
            && !self.blocked
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gcra {
    tat: u128,
}

impl Gcra {
    pub fn grant(&mut self, quota: Quota, want: u32, now: Instant) -> Tokens {
        let period = u128::from(quota.rate.period.max(1));
        let gap = u128::from(quota.burst.max(1) - 1) * period;
        let now_ns = u128::from(now.as_nanos());
        let base = self.tat.max(now_ns);
        let edge = now_ns + gap;
        if base > edge {
            let next = u64::try_from(base - gap).unwrap_or(u64::MAX);
            return Tokens {
                count: 0,
                until: now,
                next: Some(Instant::from_nanos(next)),
            };
        }
        let cap = quota.rate.per_lifetime();
        let most = (edge - base) / period + 1;
        let count = u32::try_from(most.min(u128::from(want.min(cap)))).expect("fits in u32");
        self.tat = base + u128::from(count) * period;
        Tokens {
            count,
            until: now + LIFETIME,
            next: None,
        }
    }
}

const SCALE: u64 = 1024;
const STALE: Duration = Duration::from_mins(10);
const OWNED_MOST: usize = 100_000;
const DEAD_MOST: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SiteState {
    Normal,
    Dead { until: Instant },
    Probe,
}

enum Effect {
    None,
    Serve,
    Cut,
    Dead,
}

#[derive(Clone, Copy, Debug)]
struct SiteWindow {
    window: u64,
    cool_until: Instant,
    failures: u64,
    state: SiteState,
    probing: bool,
    touched: Instant,
}

impl SiteWindow {
    fn hear(&mut self, signal: Signal, in_use: u64, limits: &Quota, now: Instant) -> Effect {
        self.touched = now;
        self.window = self
            .window
            .min(limits.queued.saturating_mul(SCALE))
            .max(SCALE);
        let window = limits.window.expect("site has a window");
        match signal {
            Signal::Success => {
                self.failures = 0;
                match self.state {
                    SiteState::Probe => {
                        self.state = SiteState::Normal;
                        self.window = u64::from(window.initial).min(limits.queued).max(1) * SCALE;
                    }
                    SiteState::Normal => {
                        let busy = in_use.saturating_add(u64::from(window.initial));
                        if now >= self.cool_until
                            && self.window < busy.saturating_mul(SCALE)
                            && self.window < limits.queued.saturating_mul(SCALE)
                        {
                            self.window += (SCALE * SCALE / self.window).max(1);
                        }
                    }
                    SiteState::Dead { .. } => return Effect::None,
                }
                Effect::Serve
            }
            Signal::Throttle => {
                self.window = if self.state == SiteState::Probe {
                    SCALE
                } else {
                    (self.window / 2).max(SCALE)
                };
                self.cool_until = now + window.cool;
                self.failures = 0;
                self.state = SiteState::Normal;
                Effect::Cut
            }
            Signal::Failure => {
                let cohort = (self.window / SCALE).max(1);
                self.window = self
                    .window
                    .saturating_sub(SCALE * SCALE / self.window)
                    .max(SCALE);
                self.failures += 1;
                if self.state == SiteState::Probe || self.failures >= cohort {
                    self.failures = 0;
                    self.state = SiteState::Dead {
                        until: now + window.dead,
                    };
                    Effect::Dead
                } else {
                    Effect::None
                }
            }
        }
    }

    fn new(limits: &Quota, now: Instant) -> Self {
        let window = limits.window.expect("window checked");
        Self {
            window: u64::from(window.initial).min(limits.queued).max(1) * SCALE,
            cool_until: now,
            failures: 0,
            state: SiteState::Normal,
            probing: false,
            touched: now,
        }
    }
}

#[derive(Default)]
struct Owned {
    gcra: Gcra,
    held: BTreeMap<u16, u64>,
    granted: u64,
    waiting: VecDeque<(u16, u64)>,
    blocked: bool,
    window: Option<SiteWindow>,
    used: BTreeMap<u16, u64>,
}

impl Owned {
    fn in_use(&self) -> u64 {
        self.used
            .iter()
            .map(|(core, used)| (*used).min(self.held.get(core).copied().unwrap_or(0)))
            .sum()
    }

    fn sheds(&self, limits: &Quota) -> Vec<(u16, u64)> {
        let excess = self.granted.saturating_sub(self.ceiling(limits));
        let mut left = excess;
        self.held
            .iter()
            .filter(|(_, held)| **held > 0)
            .map(|(core, held)| {
                let share = (held * excess).div_ceil(self.granted.max(1));
                let n = share.min(*held).min(left);
                left -= n;
                (*core, n)
            })
            .collect()
    }

    fn probed(&mut self, given: u64) {
        if let Some(site) = &mut self.window
            && site.state == SiteState::Probe
            && given > 0
        {
            site.probing = true;
        }
    }

    fn site(&mut self, limits: &Quota, now: Instant) -> Option<&mut SiteWindow> {
        if limits.window.is_some() && limits.queued > 0 {
            Some(
                self.window
                    .get_or_insert_with(|| SiteWindow::new(limits, now)),
            )
        } else {
            None
        }
    }

    fn ceiling(&self, limits: &Quota) -> u64 {
        match &self.window {
            Some(site) => match site.state {
                SiteState::Normal => (site.window / SCALE).max(1).min(limits.queued),
                SiteState::Probe => 1,
                SiteState::Dead { .. } => 0,
            },
            None => limits.queued,
        }
    }

    fn dead(&self) -> bool {
        matches!(&self.window, Some(site) if matches!(site.state, SiteState::Dead { .. }))
    }

    fn stale(&self, now: Instant, aged: Duration) -> bool {
        self.granted == 0
            && self.waiting.is_empty()
            && !self.blocked
            && self.gcra.tat <= u128::from(now.as_nanos())
            && matches!(&self.window, Some(site)
                if (site.state == SiteState::Probe
                    || (site.state == SiteState::Normal && now >= site.cool_until))
                    && now.saturating_duration_since(site.touched) >= aged)
    }
}

type Route<K> = Rc<dyn Fn(&K) -> u16>;
type Rules<K> = Rc<dyn Fn(&K) -> Option<Quota>>;

struct Inner<K> {
    owner: Route<K>,
    limits: Rules<K>,
    leases: RefCell<BTreeMap<K, Lease>>,
    owned: RefCell<BTreeMap<K, Owned>>,
    peers: OnceCell<Peers<Ask<K>>>,
    stats: Cell<LeaseStats>,
    closed: Cell<bool>,
    tick: Notify,
    cores: u16,
    core: u16,
    dead: RefCell<BTreeMap<(IpAddr, IpAddr), Instant>>,
    opened: Cell<u16>,
    opening: Notify,
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
        limits: impl Fn(&K) -> Option<Quota> + 'static,
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
            cores: ends.cores(),
            core: ends.index(),
            dead: RefCell::new(BTreeMap::new()),
            opened: Cell::new(0),
            opening: Notify::default(),
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
        for core in 0..self.inner.cores {
            self.send(core, Ask::Opened);
        }
    }

    pub async fn opened(&self) {
        while self.inner.opened.get() < self.inner.cores && !self.inner.closed.get() {
            self.inner.opening.wait().await;
        }
    }

    pub async fn take(&self, key: &K) -> Result<Taken, Error> {
        self.take_within(key, WAIT).await
    }

    pub async fn take_within(&self, key: &K, wait: Duration) -> Result<Taken, Error> {
        self.take_as(key, wait, true).await
    }

    pub async fn take_token(&self, key: &K) -> Result<Taken, Error> {
        self.take_token_within(key, WAIT).await
    }

    pub async fn take_token_within(&self, key: &K, wait: Duration) -> Result<Taken, Error> {
        self.take_as(key, wait, false).await
    }

    pub fn block(&self, key: &K) {
        self.send(
            (self.inner.owner)(key),
            Ask::Block {
                key: key.clone(),
                on: true,
            },
        );
    }

    pub fn unblock(&self, key: &K) {
        self.send(
            (self.inner.owner)(key),
            Ask::Block {
                key: key.clone(),
                on: false,
            },
        );
    }

    pub fn blocked(&self, key: &K) -> bool {
        self.inner
            .leases
            .borrow()
            .get(key)
            .is_some_and(|l| l.blocked)
    }

    pub fn feedback(&self, key: &K, signal: Signal) {
        self.send(
            (self.inner.owner)(key),
            Ask::Feedback {
                key: key.clone(),
                signal,
                used: self.used(key),
            },
        );
    }

    pub fn sites(&self) -> (u64, u64) {
        let owned = self.inner.owned.borrow();
        let mut tracked = 0;
        let mut dead = 0;
        for entry in owned.values() {
            if let Some(site) = &entry.window {
                tracked += 1;
                dead += u64::from(matches!(site.state, SiteState::Dead { .. }));
            }
        }
        (tracked, dead)
    }

    pub fn is_dead(&self, egress: IpAddr, remote: IpAddr) -> bool {
        let now = rt::now();
        let mut dead = self.inner.dead.borrow_mut();
        match dead.get(&(egress, remote)) {
            Some(until) if *until > now => true,
            Some(_) => {
                dead.remove(&(egress, remote));
                false
            }
            None => false,
        }
    }

    pub fn mark_dead(&self, egress: IpAddr, remote: IpAddr, until: Instant) {
        {
            let now = rt::now();
            let mut dead = self.inner.dead.borrow_mut();
            if dead.get(&(egress, remote)).is_some_and(|at| *at > now) {
                return;
            }
            if dead.len() >= DEAD_MOST {
                dead.retain(|_, at| *at > now);
            }
            if dead.len() >= DEAD_MOST {
                return;
            }
            dead.insert((egress, remote), until);
        }
        for core in 0..self.inner.cores {
            if core != self.inner.core {
                self.send(
                    core,
                    Ask::Dead {
                        egress,
                        remote,
                        until,
                    },
                );
            }
        }
    }

    pub fn dead_hosts(&self) -> usize {
        self.inner.dead.borrow().len()
    }

    async fn take_as(&self, key: &K, wait: Duration, slot: bool) -> Result<Taken, Error> {
        let limits = (self.inner.limits)(key).ok_or(Error::Invalid("key"))?;
        let deadline = rt::now() + wait;
        loop {
            if self.blocked(key) {
                return Err(Error::Blocked);
            }
            let now = rt::now();
            if let Some(taken) = self.try_take(key, limits, now, slot) {
                return Ok(taken);
            }
            let (wake, mut woken) = channel();
            self.ask(key, limits, now, slot);
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
        {
            let mut leases = self.inner.leases.borrow_mut();
            let Some(lease) = leases.get_mut(key) else {
                return;
            };
            if let Some(until) = taken.token
                && let Some(batch) = lease.batches.iter_mut().find(|b| b.0 == until)
            {
                batch.1 += 1;
            }
        }
        if taken.slot {
            self.free(key, 1);
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
            let pay = lease.owe.min(lease.free);
            lease.owe = (lease.owe - pay).min(lease.used);
            lease.free -= pay;
            if (lease.recalled || lease.blocked) && lease.free > 0 {
                lease.recalled = false;
                pay + std::mem::take(&mut lease.free)
            } else {
                pay
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
        self.inner.opening.notify();
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

    fn try_take(&self, key: &K, limits: Quota, now: Instant, slot: bool) -> Option<Taken> {
        let mut leases = self.inner.leases.borrow_mut();
        let lease = leases.entry(key.clone()).or_insert_with(|| Lease::new(now));
        lease.touched = now;
        let lapsed = lease.lapse(now);
        let need_token = limits.rate.limited();
        let need_slot = slot && limits.queued > 0;
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
            self.ask(key, limits, now, slot);
        }
        taken
    }

    fn ask(&self, key: &K, limits: Quota, now: Instant, slot: bool) {
        let open = |sent: Option<Instant>| sent.is_none_or(|at| at + LIFETIME <= now);
        let (tokens, slots) = {
            let mut leases = self.inner.leases.borrow_mut();
            let Some(lease) = leases.get_mut(key) else {
                return;
            };
            lease.token_size = lease.token_size.min(limits.rate.per_lifetime());
            lease.slot_size = lease.slot_size.min((limits.queued / 8).max(1));
            let have = lease.tokens();
            let tokens = if limits.rate.limited()
                && open(lease.token_ask)
                && lease.token_next.is_none_or(|n| n <= now)
                && have <= lease.token_size / 2
            {
                (lease.token_size - have).max(1)
            } else {
                0
            };
            let slots = if slot
                && limits.queued > 0
                && open(lease.slot_ask)
                && lease.free <= lease.slot_size / 2
            {
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
            Ask::Opened => {
                self.inner.opened.set(self.inner.opened.get() + 1);
                self.inner.opening.notify();
            }
            Ask::Block { key, on } => self.block_all(&key, on),
            Ask::Blocked { key, on } => self.mark(key, on),
            Ask::Feedback { key, signal, used } => self.heard(from, &key, signal, used),
            Ask::Shed { key, slots } => self.shed(key, slots),
            Ask::Dead {
                egress,
                remote,
                until,
            } => self.heard_dead(egress, remote, until),
        }
    }

    fn heard_dead(&self, egress: IpAddr, remote: IpAddr, until: Instant) {
        let now = rt::now();
        let mut dead = self.inner.dead.borrow_mut();
        if let Some(at) = dead.get_mut(&(egress, remote)) {
            *at = (*at).max(until);
        } else {
            if dead.len() >= DEAD_MOST {
                dead.retain(|_, at| *at > now);
            }
            if dead.len() < DEAD_MOST {
                dead.insert((egress, remote), until);
            }
        }
    }

    fn heard(&self, from: u16, key: &K, signal: Signal, used: u64) {
        let Some(limits) = (self.inner.limits)(key) else {
            return;
        };
        if limits.window.is_none() || limits.queued == 0 {
            return;
        }
        let now = rt::now();
        let effect = {
            let mut owned = self.inner.owned.borrow_mut();
            let entry = owned.entry(key.clone()).or_default();
            entry.used.insert(from, used);
            let in_use = entry.in_use();
            let Some(site) = entry.site(&limits, now) else {
                return;
            };
            if matches!(site.state, SiteState::Dead { .. })
                || (site.state == SiteState::Probe && !site.probing)
            {
                return;
            }
            site.hear(signal, in_use, &limits, now)
        };
        match effect {
            Effect::None => {}
            Effect::Serve => self.serve(key),
            Effect::Cut => {
                self.count(|s| s.cuts += 1);
                let sheds = self
                    .inner
                    .owned
                    .borrow()
                    .get(key)
                    .map(|entry| entry.sheds(&limits))
                    .unwrap_or_default();
                for (core, slots) in sheds {
                    self.send(
                        core,
                        Ask::Shed {
                            key: key.clone(),
                            slots,
                        },
                    );
                }
            }
            Effect::Dead => {
                self.count(|s| s.deaths += 1);
                for core in 0..self.inner.cores {
                    self.send(
                        core,
                        Ask::Blocked {
                            key: key.clone(),
                            on: true,
                        },
                    );
                }
            }
        }
    }

    fn block_all(&self, key: &K, on: bool) {
        let dead = {
            let mut owned = self.inner.owned.borrow_mut();
            let entry = owned.entry(key.clone()).or_default();
            entry.blocked = on;
            if on {
                entry.waiting.clear();
            }
            entry.dead()
        };
        if dead {
            return;
        }
        for core in 0..self.inner.cores {
            self.send(
                core,
                Ask::Blocked {
                    key: key.clone(),
                    on,
                },
            );
        }
        if !on {
            self.serve(key);
        }
    }

    fn mark(&self, key: K, on: bool) {
        let (back, waiters) = {
            let mut leases = self.inner.leases.borrow_mut();
            let lease = leases
                .entry(key.clone())
                .or_insert_with(|| Lease::new(rt::now()));
            lease.blocked = on;
            lease.token_ask = None;
            lease.slot_ask = None;
            let back = if on {
                lease.recalled = false;
                lease.slot_size = 1;
                std::mem::take(&mut lease.free)
            } else {
                0
            };
            (back, std::mem::take(&mut lease.waiters))
        };
        if back > 0 {
            self.give_slots(key, back);
        }
        for wake in waiters {
            let _ = wake.send(());
        }
    }

    fn want(&self, from: u16, key: K, tokens: u32, slots: u64) {
        let Some(limits) = (self.inner.limits)(&key) else {
            return;
        };
        if self
            .inner
            .owned
            .borrow()
            .get(&key)
            .is_some_and(|o| o.blocked || o.dead())
        {
            self.send(from, Ask::Blocked { key, on: true });
            return;
        }
        self.serve(&key);
        let now = rt::now();
        let mut recall = false;
        let grant = {
            let mut owned = self.inner.owned.borrow_mut();
            let entry = owned.entry(key.clone()).or_default();
            if let Some(site) = entry.site(&limits, now) {
                site.touched = now;
            }
            let tokens = (tokens > 0).then(|| entry.gcra.grant(limits, tokens, now));
            let slots = if slots > 0 {
                let room = entry.ceiling(&limits).saturating_sub(entry.granted);
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
                    entry.probed(given);
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
                let room = entry.ceiling(&limits).saturating_sub(entry.granted);
                let given = want.min(room);
                if given == 0 {
                    break;
                }
                entry.waiting.pop_front();
                *entry.held.entry(core).or_default() += given;
                entry.granted += given;
                entry.probed(given);
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

    fn shed(&self, key: K, slots: u64) {
        let back = {
            let mut leases = self.inner.leases.borrow_mut();
            let Some(lease) = leases.get_mut(&key) else {
                return;
            };
            lease.slot_size = (lease.slot_size / 2).max(1);
            lease.owe = (lease.owe + slots.saturating_sub(lease.free)).min(lease.used);
            std::mem::take(&mut lease.free)
        };
        if back > 0 {
            self.give_slots(key, back);
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
            let mut probe = Vec::new();
            {
                let mut owned = self.inner.owned.borrow_mut();
                for (key, entry) in owned.iter_mut() {
                    let Some(site) = &mut entry.window else {
                        continue;
                    };
                    if let SiteState::Dead { until } = site.state
                        && until <= now
                    {
                        site.state = SiteState::Probe;
                        site.probing = false;
                        site.touched = now;
                        probe.push((key.clone(), entry.blocked));
                    }
                }
                owned.retain(|_, entry| !entry.stale(now, STALE));
                let over = owned.len().saturating_sub(OWNED_MOST);
                if over > 0 {
                    let mut oldest: Vec<(Instant, K)> = owned
                        .iter()
                        .filter(|(_, entry)| entry.stale(now, Duration::ZERO))
                        .map(|(key, entry)| {
                            (
                                entry.window.as_ref().expect("stale has a window").touched,
                                key.clone(),
                            )
                        })
                        .collect();
                    oldest.sort_unstable();
                    for (_, key) in oldest.into_iter().take(over) {
                        owned.remove(&key);
                    }
                }
            }
            for (key, blocked) in probe {
                if !blocked {
                    for core in 0..self.inner.cores {
                        self.send(
                            core,
                            Ask::Blocked {
                                key: key.clone(),
                                on: false,
                            },
                        );
                    }
                }
                self.serve(&key);
            }
        }
    }
}
