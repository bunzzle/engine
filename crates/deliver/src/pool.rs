use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use control::{Ask, Leases, Quota, Rate, Window, siphash};
use dns::Name;
use rt::{Ends, JoinHandle, sleep, spawn};
use smtp::client::Capabilities;

use crate::conn::Conn;
use crate::settings::Site;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Remote {
    Site(IpAddr, Box<str>),
    Send(IpAddr, Box<str>),
}

pub fn limits(
    ends: Ends<Ask<Remote>>,
    connections: u32,
    sites: &[Site],
    key: [u8; 16],
) -> (Leases<Remote>, JoinHandle<()>) {
    let cores = ends.cores();
    let rules: Vec<Site> = sites.to_vec();
    Leases::start(
        ends,
        move |remote| owner(&key, remote, cores),
        move |remote| match remote {
            Remote::Site(_, name) => Some(Quota {
                rate: rules
                    .iter()
                    .find(|rule| rule.name == **name)
                    .and_then(|rule| rule.connect_rate)
                    .map_or(Rate::NONE, Rate::per_minute),
                burst: 1,
                queued: u64::from(connections),
                window: Some(Window::default()),
            }),
            Remote::Send(_, name) => {
                let rule = rules.iter().find(|rule| rule.name == **name)?;
                let rate = rule.rate?;
                Some(Quota {
                    rate: Rate::per_hour(rate),
                    burst: rule.burst.max(1),
                    queued: 0,
                    window: None,
                })
            }
        },
    )
}

fn owner(key: &[u8; 16], remote: &Remote, cores: u16) -> u16 {
    let (tag, ip, site) = match remote {
        Remote::Site(ip, site) => (0u8, ip, site),
        Remote::Send(ip, site) => (1u8, ip, site),
    };
    let mut data = vec![tag];
    match ip {
        IpAddr::V4(v4) => data.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => data.extend_from_slice(&v6.octets()),
    }
    data.extend_from_slice(site.as_bytes());
    u16::try_from(siphash(key, &data) % u64::from(cores.max(1))).unwrap_or(0)
}

pub(crate) struct Slot {
    leases: Leases<Remote>,
    remote: Remote,
}

impl Slot {
    pub(crate) fn new(leases: Leases<Remote>, remote: Remote) -> Self {
        Self { leases, remote }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.leases.free(&self.remote, 1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Any,
    Encrypt,
    Sts,
    Dane,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Key {
    pub(crate) egress: IpAddr,
    pub(crate) domain: Box<str>,
    pub(crate) site: Box<str>,
    pub(crate) host: Name,
    pub(crate) remote: IpAddr,
    pub(crate) level: Level,
}

pub(crate) struct Link {
    pub(crate) conn: Conn,
    pub(crate) caps: Capabilities,
    pub(crate) used: u32,
    pub(crate) _slot: Option<Slot>,
}

#[derive(Default)]
struct Parked {
    links: BTreeMap<Key, Vec<(u64, Link)>>,
    count: usize,
    next: u64,
}

impl Parked {
    fn remove(&mut self, key: &Key, id: u64) -> Option<Link> {
        let list = self.links.get_mut(key)?;
        let at = list.iter().position(|(n, _)| *n == id)?;
        let (_, link) = list.remove(at);
        if list.is_empty() {
            self.links.remove(key);
        }
        self.count -= 1;
        Some(link)
    }
}

pub(crate) struct Pool {
    parked: Rc<RefCell<Parked>>,
    idle: Duration,
    most: usize,
}

impl Pool {
    pub(crate) fn new(idle: Duration, most: usize) -> Self {
        Self {
            parked: Rc::default(),
            idle,
            most,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.parked.borrow().count
    }

    pub(crate) fn take(&self, key: &Key) -> Option<Link> {
        let mut parked = self.parked.borrow_mut();
        let id = parked.links.get(key)?.last()?.0;
        parked.remove(key, id)
    }

    pub(crate) async fn close(&self, egress: IpAddr, site: &str) {
        let links = {
            let mut parked = self.parked.borrow_mut();
            let keys: Vec<Key> = parked
                .links
                .keys()
                .filter(|key| key.egress == egress && &*key.site == site)
                .cloned()
                .collect();
            let mut links = Vec::new();
            for key in keys {
                if let Some(list) = parked.links.remove(&key) {
                    parked.count -= list.len();
                    links.extend(list.into_iter().map(|(_, link)| link));
                }
            }
            links
        };
        for link in links {
            link.conn.quit().await;
        }
    }

    pub(crate) fn egress(&self, domain: &str, allowed: &[(IpAddr, u16)]) -> Option<IpAddr> {
        self.parked
            .borrow()
            .links
            .keys()
            .find(|key| {
                &*key.domain == domain
                    && allowed
                        .iter()
                        .any(|(ip, weight)| *weight > 0 && *ip == key.egress)
            })
            .map(|key| key.egress)
    }

    pub(crate) async fn park(&self, key: Key, link: Link) {
        let id = {
            let mut parked = self.parked.borrow_mut();
            if parked.count >= self.most {
                None
            } else {
                let id = parked.next;
                parked.next += 1;
                parked.count += 1;
                Some(id)
            }
        };
        let Some(id) = id else {
            link.conn.quit().await;
            return;
        };
        self.parked
            .borrow_mut()
            .links
            .entry(key.clone())
            .or_default()
            .push((id, link));
        let parked = Rc::downgrade(&self.parked);
        let idle = self.idle;
        drop(spawn(async move {
            sleep(idle).await;
            let link = parked
                .upgrade()
                .and_then(|parked| parked.borrow_mut().remove(&key, id));
            if let Some(link) = link {
                link.conn.quit().await;
            }
        }));
    }
}
