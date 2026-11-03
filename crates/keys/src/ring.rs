use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use crypto::{Secret, TenantKeys};
use rt::{Instant, Sender};

use crate::cache::{Cache, CacheStats};
use crate::proto::{Answer, Request};
use crate::{Client, Error};

pub type Connecting = Pin<Box<dyn Future<Output = Result<Client, Error>>>>;
pub type Connect = Rc<dyn Fn() -> Connecting>;
type Waiters = Vec<Sender<Result<Working, Fault>>>;

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Unavailable,
    Unknown,
    Failed,
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
    pub failed: u64,
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
    naming: RefCell<Option<Secret<16>>>,
    day: Cell<u32>,
    failed: Cell<bool>,
    tenants: RefCell<Cache<(u32, u32), Working>>,
    opening: RefCell<HashMap<(u32, u32), Waiters>>,
    stats: Cell<RingStats>,
}

struct Pending<'a> {
    ring: &'a Ring,
    pause: Duration,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        let mut link = self.ring.inner.link.borrow_mut();
        if matches!(*link, Link::Connecting) {
            *link = Link::Down {
                retry_at: rt::now(),
                pause: self.pause,
            };
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
                naming: RefCell::new(None),
                day: Cell::new(0),
                failed: Cell::new(false),
                tenants: RefCell::new(Cache::new(settings.tenants)),
                opening: RefCell::new(HashMap::new()),
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
        self.inner.naming.borrow().as_ref().map(|key| *key.expose())
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

    pub fn get(&self, tenant: u32, generation: u32) -> Option<Working> {
        if self.failed() {
            return None;
        }
        self.inner.tenants.borrow_mut().get(&(tenant, generation))
    }

    pub async fn open(&self, tenant: u32, generation: u32) -> Result<Working, Fault> {
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
                let result = ring.fetch(tenant, generation).await;
                if let Ok(working) = &result
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
            Request::Hello { .. } | Request::Open { .. } | Request::Unwrap { .. } => {
                settings.deadline
            }
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

    async fn fetch(&self, tenant: u32, generation: u32) -> Result<Working, Fault> {
        self.count(|s| s.opens += 1);
        match self.call(&Request::Open { tenant, generation }).await {
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
                })
            }
            Ok(Answer::Refused(Error::Unknown | Error::Generation)) => {
                self.count(|s| s.unknown += 1);
                Err(Fault::Unknown)
            }
            Ok(Answer::Refused(Error::Failed | Error::Unreadable))
            | Err(Error::Failed | Error::Changed) => {
                self.count(|s| s.failed += 1);
                Err(Fault::Failed)
            }
            _ => {
                self.count(|s| s.unavailable += 1);
                Err(Fault::Unavailable)
            }
        }
    }

    async fn client(&self) -> Result<Rc<Client>, Error> {
        if self.failed() {
            self.count(|s| s.refused += 1);
            return Err(Error::Failed);
        }
        let pause = match &*self.inner.link.borrow() {
            Link::Up(client) if !client.is_closed() => return Ok(Rc::clone(client)),
            Link::Up(_) => self.inner.settings.retry,
            Link::Connecting => return Err(Error::Closed),
            Link::Down { retry_at, pause } => {
                if rt::now() < *retry_at {
                    return Err(Error::Closed);
                }
                *pause
            }
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

    async fn connect(&self) -> Result<Rc<Client>, Error> {
        let settings = self.inner.settings;
        let client = rt::timeout(settings.deadline, (self.inner.connect)())
            .await
            .map_err(|_| Error::Timeout)??;
        let hello = Request::Hello {
            node: settings.node,
        };
        let answer = client.call_within(&hello, settings.deadline).await;
        let Ok(Answer::Hello { day, naming }) = answer else {
            client.close();
            return Err(answer.err().unwrap_or(Error::Bad));
        };
        let changed = {
            let mut known = self.inner.naming.borrow_mut();
            if let Some(key) = known.as_ref() {
                !(*key == naming)
            } else {
                *known = Some(naming);
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
