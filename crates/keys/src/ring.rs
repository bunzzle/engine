use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use crypto::{DkimAlg, Secret, TenantKeys, Wrap};
use rt::{Instant, Sender};

use crate::cache::{Cache, CacheStats};
use crate::proto::{Answer, Request};
use crate::{Client, Error};

pub type Connecting = Pin<Box<dyn Future<Output = Result<Client, Error>>>>;
pub type Connect = Rc<dyn Fn() -> Connecting>;
const REFRESH: Duration = Duration::from_secs(600);
const DAY_MS: u64 = 86_400_000;

type Waiters = Vec<Sender<Result<Working, Fault>>>;
type Unwrapping = (Wrap, Vec<Sender<Result<Secret<32>, Fault>>>);
type Loading = (DkimAlg, Vec<u8>, Vec<Sender<Result<(), Fault>>>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingSettings {
    pub node: u32,
    pub deadline: Duration,
    pub slow: Duration,
    pub retry: Duration,
    pub retry_max: Duration,
    pub tenants: usize,
}

impl RingSettings {
    pub fn new(node: u32) -> Self {
        Self {
            node,
            deadline: Duration::from_secs(2),
            slow: Duration::from_secs(30),
            retry: Duration::from_millis(100),
            retry_max: Duration::from_secs(5),
            tenants: 65_536,
        }
    }
}

#[derive(Clone)]
pub struct Working {
    pub keys: TenantKeys,
    pub day: u32,
    pub oldest: u32,
    pub today: [u8; 32],
    pub tomorrow: [u8; 32],
    pub seen: u32,
}

impl Working {
    #[must_use]
    pub fn next_day(&self) -> Self {
        Self {
            day: self.day + 1,
            today: self.tomorrow,
            ..self.clone()
        }
    }
}

pub fn wall_day() -> u32 {
    u32::try_from(rt::wall_ms() / DAY_MS).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Unavailable,
    Busy,
    Unknown,
    Failed,
    Conflict,
    Gone,
    Bad,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingStats {
    pub connects: u64,
    pub drops: u64,
    pub slow: u64,
    pub refused: u64,
    pub opens: u64,
    pub unknown: u64,
    pub unavailable: u64,
    pub busy: u64,
    pub failed: u64,
    pub unwraps: u64,
    pub gone: u64,
    pub bad: u64,
    pub refreshes: u64,
    pub dkim_new: u64,
    pub loads: u64,
    pub signs: u64,
    pub behind: u32,
    pub settled: u32,
    pub tenants: CacheStats,
}

enum Link {
    Down { retry_at: Instant, pause: Duration },
    Connecting,
    Up(Rc<Client>),
}

#[derive(Clone)]
pub struct Ring {
    inner: Rc<Inner>,
}

struct Inner {
    settings: RingSettings,
    connect: Connect,
    link: RefCell<Link>,
    joining: RefCell<Vec<Sender<()>>>,
    naming: RefCell<Option<(Secret<16>, Secret<16>)>>,
    day: Cell<u32>,
    failed: Cell<bool>,
    tenants: RefCell<Cache<(u32, u32), Working>>,
    opening: RefCell<HashMap<(u32, u32), Waiters>>,
    unwrapping: RefCell<HashMap<(u32, u32, u16, u64), Unwrapping>>,
    loading: RefCell<HashMap<(u32, u32, u32), Loading>>,
    refreshed: RefCell<HashMap<(u32, u32), Instant>>,
    gone: RefCell<HashMap<u32, u32>>,
    settled: Cell<u32>,
    settling: Cell<bool>,
    stats: Cell<RingStats>,
}

struct Pending<'a> {
    ring: &'a Ring,
    pause: Duration,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        let inner = &self.ring.inner;
        {
            let mut link = inner.link.borrow_mut();
            if matches!(*link, Link::Connecting) {
                *link = Link::Down {
                    retry_at: rt::now(),
                    pause: self.pause,
                };
            }
        }
        for joined in inner.joining.borrow_mut().drain(..) {
            let _ = joined.send(());
        }
    }
}

impl Ring {
    pub fn new(connect: Connect, settings: RingSettings) -> Self {
        Self {
            inner: Rc::new(Inner {
                settings,
                connect,
                link: RefCell::new(Link::Down {
                    retry_at: rt::now(),
                    pause: settings.retry,
                }),
                joining: RefCell::new(Vec::new()),
                naming: RefCell::new(None),
                day: Cell::new(0),
                failed: Cell::new(false),
                tenants: RefCell::new(Cache::new(settings.tenants)),
                opening: RefCell::new(HashMap::new()),
                unwrapping: RefCell::new(HashMap::new()),
                loading: RefCell::new(HashMap::new()),
                refreshed: RefCell::new(HashMap::new()),
                gone: RefCell::new(HashMap::new()),
                settled: Cell::new(0),
                settling: Cell::new(false),
                stats: Cell::new(RingStats::default()),
            }),
        }
    }

    pub fn failed(&self) -> bool {
        self.inner.failed.get()
    }

    pub fn day(&self) -> u32 {
        self.inner.day.get()
    }

    pub fn naming(&self) -> Option<[u8; 16]> {
        self.inner
            .naming
            .borrow()
            .as_ref()
            .map(|(key, _)| *key.expose())
    }

    pub fn ids(&self) -> Option<Secret<16>> {
        self.inner
            .naming
            .borrow()
            .as_ref()
            .map(|(_, ids)| ids.copy())
    }

    pub fn stats(&self) -> RingStats {
        RingStats {
            tenants: self.inner.tenants.borrow().stats(),
            ..self.inner.stats.get()
        }
    }

    pub async fn hello(&self) -> Result<(), Error> {
        self.client().await.map(drop)
    }

    pub fn forget(&self, tenant: u32, generation: u32) {
        let mut gone = self.inner.gone.borrow_mut();
        let through = gone.entry(tenant).or_insert(generation);
        *through = (*through).max(generation);
        drop(gone);
        let key = (tenant, generation);
        self.inner.tenants.borrow_mut().remove(&key);
        self.inner.refreshed.borrow_mut().remove(&key);
    }

    pub fn forgotten(&self, tenant: u32, generation: u32) -> bool {
        self.inner
            .gone
            .borrow()
            .get(&tenant)
            .is_some_and(|through| generation <= *through)
    }

    fn live(&self, tenant: u32, generation: u32) -> Result<(), Fault> {
        if self.forgotten(tenant, generation) {
            self.count(|s| s.gone += 1);
            return Err(Fault::Gone);
        }
        Ok(())
    }

    pub fn get(&self, tenant: u32, generation: u32) -> Option<Working> {
        if self.failed() || self.forgotten(tenant, generation) {
            return None;
        }
        self.inner.tenants.borrow_mut().get(&(tenant, generation))
    }

    pub async fn open(&self, tenant: u32, generation: u32) -> Result<Working, Fault> {
        self.live(tenant, generation)?;
        if let Some(found) = self.get(tenant, generation) {
            return Ok(found);
        }
        if self.failed() {
            self.count(|s| s.refused += 1);
            return Err(Fault::Failed);
        }
        let key = (tenant, generation);
        let (reply, mut answer) = rt::channel();
        let first = {
            let mut opening = self.inner.opening.borrow_mut();
            let waiting = opening.entry(key).or_default();
            waiting.push(reply);
            waiting.len() == 1
        };
        if first {
            let ring = self.clone();
            rt::spawn(async move {
                let mut result = ring.fetch(tenant, generation).await;
                if ring.forgotten(tenant, generation) {
                    result = Err(Fault::Gone);
                } else if let Ok(working) = &result
                    && !ring.failed()
                {
                    ring.inner.tenants.borrow_mut().put(key, working.clone());
                }
                let waiting = ring.inner.opening.borrow_mut().remove(&key);
                for waiter in waiting.unwrap_or_default() {
                    let _ = waiter.send(result.clone());
                }
            });
        }
        answer.recv().await.unwrap_or(Err(Fault::Unavailable))
    }

    pub async fn call(&self, request: &Request) -> Result<Answer, Error> {
        let client = self.client().await?;
        let settings = self.inner.settings;
        let limit = match request {
            Request::Hello { .. }
            | Request::Open { .. }
            | Request::Unwrap { .. }
            | Request::Sign { .. } => settings.deadline,
            _ => settings.slow,
        };
        match client.call_within(request, limit).await {
            Err(Error::Timeout) => {
                self.count(|s| s.slow += 1);
                let hello = Request::Hello {
                    node: settings.node,
                };
                if client.call_within(&hello, settings.deadline).await.is_err() {
                    self.drop_link(&client);
                }
                Err(Error::Timeout)
            }
            Err(Error::Closed) => {
                self.drop_link(&client);
                Err(Error::Closed)
            }
            other => other,
        }
    }

    pub async fn sealing(&self, tenant: u32, generation: u32) -> Result<Working, Fault> {
        let mut working = self.open(tenant, generation).await?;
        let wall = wall_day();
        self.count(|s| s.behind = wall.saturating_sub(working.seen));
        if wall > working.seen.saturating_add(1) {
            working = self.fresh(tenant, generation).await?;
        } else if wall > working.seen {
            self.refresh(tenant, generation);
        }
        if wall > working.seen {
            return Ok(working.next_day());
        }
        Ok(working)
    }

    pub async fn fresh(&self, tenant: u32, generation: u32) -> Result<Working, Fault> {
        self.live(tenant, generation)?;
        self.inner
            .tenants
            .borrow_mut()
            .remove(&(tenant, generation));
        self.open(tenant, generation).await
    }

    pub fn settled(&self, day: u32) {
        if self.failed() || self.inner.settling.get() || day <= self.inner.settled.get() {
            return;
        }
        self.inner.settling.set(true);
        let ring = self.clone();
        rt::spawn(async move {
            let answer = ring.call(&Request::Settled { day }).await;
            ring.inner.settling.set(false);
            if let Ok(Answer::Done) = answer {
                ring.inner.settled.set(ring.inner.settled.get().max(day));
                ring.count(|s| s.settled = s.settled.max(day));
            }
        });
    }

    pub fn refresh(&self, tenant: u32, generation: u32) {
        if self.forgotten(tenant, generation) {
            return;
        }
        let now = rt::now();
        {
            let mut refreshed = self.inner.refreshed.borrow_mut();
            let key = (tenant, generation);
            if refreshed
                .get(&key)
                .is_some_and(|at| now.saturating_duration_since(*at) < REFRESH)
            {
                return;
            }
            if refreshed.len() >= self.inner.settings.tenants {
                refreshed.retain(|_, at| now.saturating_duration_since(*at) < REFRESH);
            }
            refreshed.insert(key, now);
        }
        self.count(|s| s.refreshes += 1);
        let ring = self.clone();
        rt::spawn(async move {
            match ring.fetch(tenant, generation).await {
                Ok(working) if !ring.failed() && !ring.forgotten(tenant, generation) => ring
                    .inner
                    .tenants
                    .borrow_mut()
                    .put((tenant, generation), working),
                Ok(_) => {}
                Err(_) => {
                    ring.inner
                        .refreshed
                        .borrow_mut()
                        .remove(&(tenant, generation));
                }
            }
        });
    }

    pub async fn unwrap(
        &self,
        tenant: u32,
        generation: u32,
        shard: u16,
        id: u64,
        wrap: &Wrap,
    ) -> Result<Secret<32>, Fault> {
        if (wrap.generation, wrap.shard) != (generation, shard) {
            self.count(|s| s.bad += 1);
            return Err(Fault::Bad);
        }
        self.live(tenant, generation)?;
        if self.failed() {
            self.count(|s| s.refused += 1);
            return Err(Fault::Failed);
        }
        let key = (tenant, generation, shard, id);
        let (reply, mut answer) = rt::channel();
        let first = {
            let mut unwrapping = self.inner.unwrapping.borrow_mut();
            let (asked, waiting) = unwrapping
                .entry(key)
                .or_insert_with(|| (wrap.clone(), Vec::new()));
            if asked != wrap {
                drop(unwrapping);
                self.count(|s| s.bad += 1);
                return Err(Fault::Bad);
            }
            waiting.push(reply);
            waiting.len() == 1
        };
        if first {
            let ring = self.clone();
            let request = Request::Unwrap {
                tenant,
                batch: id,
                wrap: wrap.clone(),
            };
            rt::spawn(async move {
                ring.count(|s| s.unwraps += 1);
                let result = match ring.call(&request).await {
                    Ok(Answer::Key(_)) if ring.forgotten(tenant, generation) => Err(Fault::Gone),
                    Ok(Answer::Key(secret)) => Ok(secret),
                    Ok(Answer::Refused(refused)) => Err(ring.fault(None, Some(refused))),
                    Ok(_) => Err(ring.fault(None, None)),
                    Err(error) => Err(ring.fault(Some(error), None)),
                };
                let waiting = ring.inner.unwrapping.borrow_mut().remove(&key);
                for waiter in waiting.map(|(_, waiting)| waiting).unwrap_or_default() {
                    let copy = match &result {
                        Ok(secret) => Ok(secret.copy()),
                        Err(fault) => Err(*fault),
                    };
                    let _ = waiter.send(copy);
                }
            });
        }
        answer.recv().await.unwrap_or(Err(Fault::Unavailable))
    }

    pub async fn create(&self, tenant: u32, generation: u32, retention: u16) -> Result<(), Fault> {
        self.live(tenant, generation)?;
        let request = Request::Create {
            tenant,
            generation,
            retention,
        };
        let working = self.answered(tenant, generation, self.call(&request).await)?;
        let request = Request::Retention {
            tenant,
            generation,
            days: retention,
        };
        match self.call(&request).await {
            Ok(Answer::Done) => {}
            Ok(Answer::Refused(refused)) => return Err(self.fault(None, Some(refused))),
            Ok(_) => return Err(self.fault(None, None)),
            Err(error) => return Err(self.fault(Some(error), None)),
        }
        self.live(tenant, generation)?;
        if !self.failed() {
            self.inner
                .tenants
                .borrow_mut()
                .put((tenant, generation), working);
        }
        Ok(())
    }

    pub async fn dkim_new(
        &self,
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
    ) -> Result<(Vec<u8>, Vec<u8>), Fault> {
        self.live(tenant, generation)?;
        self.count(|s| s.dkim_new += 1);
        let request = Request::DkimNew {
            tenant,
            generation,
            key,
            alg,
        };
        match self.checked(&request).await? {
            Answer::Dkim { public, blob } => Ok((public, blob)),
            _ => Err(self.fault(None, None)),
        }
    }

    pub async fn load(
        &self,
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
        blob: &[u8],
    ) -> Result<(), Fault> {
        self.live(tenant, generation)?;
        let id = (tenant, generation, key);
        let (reply, mut answer) = rt::channel();
        let first = {
            let mut loading = self.inner.loading.borrow_mut();
            let (asked, asked_blob, waiting) = loading
                .entry(id)
                .or_insert_with(|| (alg, blob.to_vec(), Vec::new()));
            if (*asked, asked_blob.as_slice()) != (alg, blob) {
                drop(loading);
                self.count(|s| s.bad += 1);
                return Err(Fault::Conflict);
            }
            waiting.push(reply);
            waiting.len() == 1
        };
        if first {
            let ring = self.clone();
            let request = Request::Load {
                tenant,
                generation,
                key,
                alg,
                blob: blob.to_vec(),
            };
            rt::spawn(async move {
                ring.count(|s| s.loads += 1);
                let result = match ring.checked(&request).await {
                    Ok(Answer::Done) => Ok(()),
                    Ok(_) => Err(ring.fault(None, None)),
                    Err(fault) => Err(fault),
                };
                let waiting = ring.inner.loading.borrow_mut().remove(&id);
                for waiter in waiting.map(|(_, _, waiting)| waiting).unwrap_or_default() {
                    let _ = waiter.send(result);
                }
            });
        }
        answer.recv().await.unwrap_or(Err(Fault::Unavailable))
    }

    pub async fn sign(
        &self,
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
        digest: [u8; 32],
    ) -> Result<Vec<u8>, Fault> {
        self.live(tenant, generation)?;
        self.count(|s| s.signs += 1);
        let request = Request::Sign {
            tenant,
            generation,
            key,
            alg,
            digest,
        };
        match self.checked(&request).await? {
            Answer::Signature(signature) => Ok(signature),
            _ => Err(self.fault(None, None)),
        }
    }

    pub async fn delete(&self, tenant: u32, generation: u32) -> Result<(), Fault> {
        self.forget(tenant, generation);
        match self
            .checked(&Request::Delete { tenant, generation })
            .await?
        {
            Answer::Done => Ok(()),
            _ => Err(self.fault(None, None)),
        }
    }

    async fn checked(&self, request: &Request) -> Result<Answer, Fault> {
        if self.failed() {
            self.count(|s| s.refused += 1);
            return Err(Fault::Failed);
        }
        match self.call(request).await {
            Ok(Answer::Refused(refused)) => Err(self.fault(None, Some(refused))),
            Ok(answer) => Ok(answer),
            Err(error) => Err(self.fault(Some(error), None)),
        }
    }

    async fn fetch(&self, tenant: u32, generation: u32) -> Result<Working, Fault> {
        self.count(|s| s.opens += 1);
        let answer = self.call(&Request::Open { tenant, generation }).await;
        self.answered(tenant, generation, answer)
    }

    fn answered(
        &self,
        tenant: u32,
        generation: u32,
        answer: Result<Answer, Error>,
    ) -> Result<Working, Fault> {
        match answer {
            Ok(Answer::Keys {
                day,
                oldest,
                version,
                data,
                hash,
                today,
                tomorrow,
            }) => {
                self.saw_day(day);
                Ok(Working {
                    keys: TenantKeys::new(tenant, generation, &data, version, hash),
                    day,
                    oldest,
                    today,
                    tomorrow,
                    seen: wall_day(),
                })
            }
            Ok(Answer::Refused(refused)) => Err(self.fault(None, Some(refused))),
            Ok(_) => Err(self.fault(None, None)),
            Err(error) => Err(self.fault(Some(error), None)),
        }
    }

    fn fault(&self, error: Option<Error>, refused: Option<Error>) -> Fault {
        let fault = match (error, refused) {
            (_, Some(Error::Unknown)) => Fault::Unknown,
            (_, Some(Error::Generation | Error::Conflict)) => Fault::Conflict,
            (_, Some(Error::Gone)) => Fault::Gone,
            (_, Some(Error::Busy)) => Fault::Busy,
            (_, Some(Error::Open)) => Fault::Bad,
            (_, Some(Error::Failed | Error::Unreadable))
            | (Some(Error::Failed | Error::Changed), _) => Fault::Failed,
            _ => Fault::Unavailable,
        };
        self.count(|s| match fault {
            Fault::Unknown | Fault::Conflict => s.unknown += 1,
            Fault::Failed => s.failed += 1,
            Fault::Unavailable => s.unavailable += 1,
            Fault::Busy => s.busy += 1,
            Fault::Gone => s.gone += 1,
            Fault::Bad => s.bad += 1,
        });
        fault
    }

    async fn client(&self) -> Result<Rc<Client>, Error> {
        if self.failed() {
            self.count(|s| s.refused += 1);
            return Err(Error::Failed);
        }
        let pause = match &*self.inner.link.borrow() {
            Link::Up(client) if !client.is_closed() => return Ok(Rc::clone(client)),
            Link::Up(_) => Some(self.inner.settings.retry),
            Link::Connecting => None,
            Link::Down { retry_at, pause } => {
                if rt::now() < *retry_at {
                    return Err(Error::Closed);
                }
                Some(*pause)
            }
        };
        let Some(pause) = pause else {
            return self.join().await;
        };
        *self.inner.link.borrow_mut() = Link::Connecting;
        let pending = Pending { ring: self, pause };
        let connected = self.connect().await;
        let next = match &connected {
            Ok(client) => {
                self.count(|s| s.connects += 1);
                Link::Up(Rc::clone(client))
            }
            Err(_) => Link::Down {
                retry_at: rt::now() + pause,
                pause: (pause * 2).min(self.inner.settings.retry_max),
            },
        };
        *self.inner.link.borrow_mut() = next;
        drop(pending);
        connected
    }

    async fn join(&self) -> Result<Rc<Client>, Error> {
        let (joined, mut connected) = rt::channel();
        self.inner.joining.borrow_mut().push(joined);
        let settings = self.inner.settings;
        let _ = rt::timeout(settings.deadline * 2 + settings.retry, connected.recv()).await;
        match &*self.inner.link.borrow() {
            Link::Up(client) if !client.is_closed() => Ok(Rc::clone(client)),
            _ => Err(Error::Closed),
        }
    }

    async fn connect(&self) -> Result<Rc<Client>, Error> {
        let settings = self.inner.settings;
        let client = rt::timeout(settings.deadline, (self.inner.connect)())
            .await
            .map_err(|_| Error::Timeout)??;
        let hello = Request::Hello {
            node: settings.node,
        };
        let answer = client.call_within(&hello, settings.deadline).await;
        let Ok(Answer::Hello { day, naming, ids }) = answer else {
            client.close();
            return Err(answer.err().unwrap_or(Error::Bad));
        };
        let changed = {
            let mut known = self.inner.naming.borrow_mut();
            if let Some((key, known_ids)) = known.as_ref() {
                !(*key == naming && *known_ids == ids)
            } else {
                *known = Some((naming, ids));
                false
            }
        };
        if changed {
            client.close();
            self.inner.failed.set(true);
            self.inner.tenants.borrow_mut().clear();
            return Err(Error::Changed);
        }
        self.saw_day(day);
        Ok(Rc::new(client))
    }

    fn drop_link(&self, client: &Rc<Client>) {
        let mut link = self.inner.link.borrow_mut();
        if matches!(&*link, Link::Up(current) if Rc::ptr_eq(current, client)) {
            client.close();
            *link = Link::Down {
                retry_at: rt::now(),
                pause: self.inner.settings.retry,
            };
            self.count(|s| s.drops += 1);
        }
    }

    fn saw_day(&self, day: u32) {
        self.inner.day.set(self.inner.day.get().max(day));
    }

    fn count(&self, change: impl FnOnce(&mut RingStats)) {
        let mut stats = self.inner.stats.get();
        change(&mut stats);
        self.inner.stats.set(stats);
    }
}
