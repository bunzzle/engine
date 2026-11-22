use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rt::UdpSocket;

use crate::mx;

const OWN: usize = 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnStats {
    pub ipv4_off: bool,
    pub ipv6_off: bool,
    pub unclear: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Self> {
        let (ip, prefix) = match text.split_once('/') {
            Some((ip, prefix))
                if !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()) =>
            {
                (ip.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?)
            }
            Some(_) => return None,
            None => {
                let ip = text.parse::<IpAddr>().ok()?;
                (ip, if ip.is_ipv4() { 32 } else { 128 })
            }
        };
        let most = if ip.is_ipv4() { 32 } else { 128 };
        (prefix <= most).then_some(Self { ip, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let (net, ip, bits) = match (self.ip, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => (
                u128::from(u32::from(net)) << 96,
                u128::from(u32::from(*ip)) << 96,
                self.prefix,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => (u128::from(net), u128::from(*ip), self.prefix),
            _ => return false,
        };
        let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
        net & mask == ip & mask
    }
}

pub trait Local {
    fn bound(&self, ip: IpAddr) -> impl Future<Output = Option<bool>>;
}

pub struct Bind;

impl Local for Bind {
    async fn bound(&self, ip: IpAddr) -> Option<bool> {
        match UdpSocket::bind(SocketAddr::new(ip, 0)).await {
            Ok(_) => Some(true),
            Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => Some(false),
            Err(_) => None,
        }
    }
}

pub(crate) struct Own<L> {
    local: L,
    cache: RefCell<BTreeMap<IpAddr, bool>>,
    ipv4: Cell<Option<bool>>,
    ipv6: Cell<Option<bool>>,
    unclear: Cell<u64>,
}

impl<L> Own<L> {
    pub(crate) fn new(local: L) -> Self {
        Self {
            local,
            cache: RefCell::default(),
            ipv4: Cell::new(None),
            ipv6: Cell::new(None),
            unclear: Cell::new(0),
        }
    }

    pub(crate) fn stats(&self) -> OwnStats {
        OwnStats {
            ipv4_off: self.ipv4.get() == Some(true),
            ipv6_off: self.ipv6.get() == Some(true),
            unclear: self.unclear.get(),
        }
    }

    fn unclear(&self) {
        self.unclear.set(self.unclear.get().saturating_add(1));
    }
}

impl<L: Local> Own<L> {
    pub(crate) async fn own(&self, ip: IpAddr) -> bool {
        for ip in std::iter::once(ip).chain(embedded(ip).map(IpAddr::V4)) {
            match self.probe(ip.is_ipv6()).await {
                Some(true) => continue,
                Some(false) => {}
                None => return true,
            }
            let known = self.cache.borrow().get(&ip).copied();
            let own = if let Some(own) = known {
                own
            } else {
                let Some(own) = self.local.bound(ip).await else {
                    self.unclear();
                    return true;
                };
                let mut cache = self.cache.borrow_mut();
                if cache.len() >= OWN {
                    cache.clear();
                }
                cache.insert(ip, own);
                own
            };
            if own {
                return true;
            }
        }
        false
    }

    async fn probe(&self, v6: bool) -> Option<bool> {
        let (state, sentinel) = if v6 {
            (
                &self.ipv6,
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            )
        } else {
            (&self.ipv4, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        };
        if let Some(bound) = state.get() {
            return Some(bound);
        }
        let bound = self.local.bound(sentinel).await;
        match bound {
            Some(bound) => state.set(Some(bound)),
            None => self.unclear(),
        }
        bound
    }
}

pub(crate) fn keep(ip: &IpAddr, allow: &[Cidr]) -> bool {
    if floor(ip) {
        return false;
    }
    mx::global(ip) || (embedded(*ip).is_none() && allow.iter().any(|cidr| cidr.contains(ip)))
}

fn floor(ip: &IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(v6) => embedded(IpAddr::V6(*v6)),
    };
    let link = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    !mx::usable(ip)
        || link
        || v4.is_some_and(|v4| !mx::usable(&IpAddr::V4(v4)) || v4.is_link_local())
}

fn embedded(ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else {
        return None;
    };
    let segments = v6.segments();
    let pair = match segments {
        [0, 0, 0, 0, 0, 0 | 0xffff, ..]
            if v6 != Ipv6Addr::UNSPECIFIED && v6 != Ipv6Addr::LOCALHOST =>
        {
            (segments[6], segments[7])
        }
        [0x64, 0xff9b, 0, 0, 0, 0, ..] | [0x64, 0xff9b, 1, ..] => (segments[6], segments[7]),
        [0x2002, high, low, ..] => (high, low),
        _ => return None,
    };
    let [first, second] = pair.0.to_be_bytes();
    let [third, fourth] = pair.1.to_be_bytes();
    Some(Ipv4Addr::new(first, second, third, fourth))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use rt::Runtime;
    use rt::sim::{Config, SimDriver};

    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    fn run(future: impl Future<Output = ()> + 'static) {
        let driver = Rc::new(SimDriver::new(3, Config::default()));
        Runtime::new(driver).block_on(future);
    }

    #[derive(Default)]
    struct Never {
        calls: Rc<Cell<usize>>,
    }

    impl Local for Never {
        fn bound(&self, _ip: IpAddr) -> impl Future<Output = Option<bool>> {
            self.calls.set(self.calls.get() + 1);
            std::future::ready(Some(false))
        }
    }

    #[derive(Default)]
    struct Everything {
        calls: Rc<Cell<usize>>,
    }

    impl Local for Everything {
        fn bound(&self, _ip: IpAddr) -> impl Future<Output = Option<bool>> {
            self.calls.set(self.calls.get() + 1);
            std::future::ready(Some(true))
        }
    }

    #[test]
    fn non_local_bind_disables_own_probes_once_per_family() {
        run(async {
            let local = Everything::default();
            let calls = Rc::clone(&local.calls);
            let own = Own::new(local);
            for text in ["11.0.1.1", "11.0.1.2", "2606:4700::1111", "2a00:1450::1"] {
                assert!(!own.own(ip(text)).await);
            }
            assert_eq!(calls.get(), 2);
            assert_eq!(
                own.stats(),
                OwnStats {
                    ipv4_off: true,
                    ipv6_off: true,
                    unclear: 0,
                }
            );
            assert!(own.cache.borrow().is_empty());
        });
    }

    #[test]
    fn own_cache_stays_bounded() {
        run(async {
            let own = Own::new(Never::default());
            for n in 0..OWN {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    10,
                    u8::try_from(n >> 8).expect("octet"),
                    u8::try_from(n & 0xff).expect("octet"),
                    1,
                ));
                assert!(!own.own(ip).await);
            }
            assert_eq!(own.cache.borrow().len(), OWN);
            own.own(ip("10.255.255.1")).await;
            assert_eq!(own.cache.borrow().len(), 1);
        });
    }

    #[test]
    fn allowed_addresses_never_pass_the_floor() {
        let allow = [
            Cidr::parse("10.0.0.0/8").expect("cidr"),
            Cidr::parse("fd00::/8").expect("cidr"),
            Cidr::parse("127.0.0.0/8").expect("cidr"),
            Cidr::parse("169.254.0.0/16").expect("cidr"),
            Cidr::parse("::/0").expect("cidr"),
        ];
        for good in ["8.8.8.8", "10.1.2.3", "fd00::1", "64:ff9b::8.8.8.8"] {
            assert!(keep(&ip(good), &allow), "{good}");
        }
        for bad in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:169.254.169.254",
            "64:ff9b::10.0.0.1",
            "64:ff9b::127.0.0.1",
            "2002:7f00:0001::1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!keep(&ip(bad), &allow), "{bad}");
        }
        assert!(!keep(&ip("10.1.2.3"), &[]));
        assert!(!keep(&ip("fd00::1"), &[]));
    }

    #[test]
    fn cidrs_match_by_prefix() {
        let net = Cidr::parse("192.168.4.0/22").expect("cidr");
        assert!(net.contains(&ip("192.168.7.255")));
        assert!(!net.contains(&ip("192.168.8.0")));
        assert!(!net.contains(&ip("::ffff:192.168.4.1")));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .expect("all")
                .contains(&ip("1.2.3.4"))
        );
        assert_eq!(Cidr::parse("10.0.0.1").map(|c| c.prefix), Some(32));
        for bad in ["10.0.0.0/33", "::/129", "x/8", "10.0.0.0/", "10.0.0.0/+8"] {
            assert!(Cidr::parse(bad).is_none(), "{bad}");
        }
    }
}
