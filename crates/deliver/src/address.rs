use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rt::UdpSocket;
use sched::OwnStats;

use crate::mx;

const OWN: usize = 1024;

const METADATA: [IpAddr; 5] = [
    IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
    IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16)),
    IpAddr::V4(Ipv4Addr::new(192, 0, 0, 192)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
    IpAddr::V6(Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254)),
];

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

    pub fn nat64(text: &str) -> Option<Self> {
        Self::parse(text)
            .filter(|cidr| cidr.ip.is_ipv6() && matches!(cidr.prefix, 32 | 40 | 48 | 56 | 64 | 96))
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
    pub(crate) async fn probe_families(&self) {
        self.probe(false).await;
        self.probe(true).await;
    }

    pub(crate) async fn own(&self, ip: IpAddr, nat64: &[Cidr]) -> bool {
        for ip in std::iter::once(ip).chain(embedded(ip, nat64).map(IpAddr::V4)) {
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

pub(crate) struct Rule<'a, L> {
    pub(crate) allow: &'a [Cidr],
    pub(crate) nat64: &'a [Cidr],
    pub(crate) own: &'a Own<L>,
}

impl<L: Local> Rule<'_, L> {
    pub(crate) fn keep(&self, ip: &IpAddr) -> bool {
        keep(ip, self.allow, self.nat64)
    }

    pub(crate) async fn own(&self, ip: IpAddr) -> bool {
        self.own.own(ip, self.nat64).await
    }
}

pub(crate) fn keep(ip: &IpAddr, allow: &[Cidr], nat64: &[Cidr]) -> bool {
    let inner = embedded(*ip, nat64);
    if floor(ip) || inner.is_some_and(|v4| floor(&IpAddr::V4(v4))) {
        return false;
    }
    match inner {
        Some(v4) if nat64.iter().any(|net| net.contains(ip)) => mx::global(&IpAddr::V4(v4)),
        Some(_) => mx::global(ip),
        None => mx::global(ip) || allow.iter().any(|cidr| cidr.contains(ip)),
    }
}

fn floor(ip: &IpAddr) -> bool {
    let link = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    !mx::usable(ip) || link || METADATA.contains(ip)
}

fn embedded(ip: IpAddr, nat64: &[Cidr]) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else {
        return None;
    };
    if let Some(net) = nat64
        .iter()
        .filter(|net| net.contains(&ip))
        .max_by_key(|net| net.prefix)
    {
        return Some(translated(v6, net.prefix));
    }
    let segments = v6.segments();
    let pair = match segments {
        [0, 0, 0, 0, 0, 0 | 0xffff, ..]
            if v6 != Ipv6Addr::UNSPECIFIED && v6 != Ipv6Addr::LOCALHOST =>
        {
            (segments[6], segments[7])
        }
        [0, 0, 0, 0, 0xffff, 0, ..] | [0x64, 0xff9b, 0, 0, 0, 0, ..] | [0x64, 0xff9b, 1, ..] => {
            (segments[6], segments[7])
        }
        [0x2002, high, low, ..] => (high, low),
        [0x2001, 0, ..] => (!segments[6], !segments[7]),
        _ => return None,
    };
    let [first, second] = pair.0.to_be_bytes();
    let [third, fourth] = pair.1.to_be_bytes();
    Some(Ipv4Addr::new(first, second, third, fourth))
}

fn translated(v6: Ipv6Addr, prefix: u8) -> Ipv4Addr {
    let bytes = v6.octets();
    if prefix < 96 && bytes[8] != 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mut out = [0; 4];
    let mut at = usize::from(prefix / 8);
    for byte in &mut out {
        if at == 8 {
            at += 1;
        }
        *byte = bytes[at];
        at += 1;
    }
    Ipv4Addr::from(out)
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
                assert!(!own.own(ip(text), &[]).await);
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
                assert!(!own.own(ip, &[]).await);
            }
            assert_eq!(own.cache.borrow().len(), OWN);
            own.own(ip("10.255.255.1"), &[]).await;
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
            assert!(keep(&ip(good), &allow, &[]), "{good}");
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
            "::ffff:0:127.0.0.1",
            "::ffff:0:10.1.2.3",
            "::ffff:0:8.8.8.8",
            "2001:0:4136:e378:8000:63bf:80ff:fffe",
            "2001:0:4136:e378:8000:63bf:f7f7:f7f7",
            "2001::1",
            "100.100.100.200",
            "168.63.129.16",
            "192.0.0.192",
            "fd00:ec2::254",
            "fd20:ce::254",
            "::ffff:168.63.129.16",
            "64:ff9b::168.63.129.16",
        ] {
            assert!(!keep(&ip(bad), &allow, &[]), "{bad}");
        }
        assert!(!keep(&ip("10.1.2.3"), &[], &[]));
        assert!(!keep(&ip("fd00::1"), &[], &[]));
    }

    #[test]
    fn network_nat64_prefixes_judge_the_embedded_address() {
        let nat64 = [
            Cidr::nat64("2001:db8:64::/96").expect("prefix"),
            Cidr::nat64("2001:db8:100::/40").expect("prefix"),
            Cidr::nat64("2001:db8:122:300::/56").expect("prefix"),
            Cidr::nat64("2001:db8:122::/48").expect("prefix"),
            Cidr::nat64("2001:db8:122:344::/64").expect("prefix"),
            Cidr::nat64("2001:db9::/32").expect("prefix"),
        ];
        let allow = [Cidr::parse("::/0").expect("cidr")];
        for (text, v4) in [
            ("2001:db8:64::808:808", "8.8.8.8"),
            ("2001:db8:64::a00:1", "10.0.0.1"),
            ("2001:db8:1c0:2:21::", "192.0.2.33"),
            ("2001:db8:122:3c0:0:221::", "192.0.2.33"),
            ("2001:db8:122:c000:2:2100::", "192.0.2.33"),
            ("2001:db8:122:344:c0:2:2100:0", "192.0.2.33"),
            ("2001:db9:c000:221::", "192.0.2.33"),
        ] {
            assert_eq!(
                embedded(ip(text), &nat64),
                Some(v4.parse().expect("v4")),
                "{text}"
            );
        }
        assert!(keep(&ip("2001:db8:64::808:808"), &[], &nat64));
        assert!(keep(&ip("2001:db9:808:808::"), &[], &nat64));
        for bad in [
            "2001:db8:64::a00:1",
            "2001:db8:64::7f00:1",
            "2001:db8:64::a9fe:a9fe",
            "2001:db8:64::a83f:8110",
            "2001:db8:64::6464:64c8",
            "2001:db9:7f00:1::",
            "2001:db9:808:808:100::",
            "2001:db8:122:344:1c0:2:2100:0",
            "2001::1",
            "::ffff:0:127.0.0.1",
        ] {
            assert!(!keep(&ip(bad), &allow, &nat64), "{bad}");
        }
        for bad in ["2001:db8::/33", "10.0.0.0/8", "64:ff9b::/95", "::/0", "x"] {
            assert!(Cidr::nat64(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn own_checks_the_nat64_embedded_address() {
        struct Only(IpAddr);
        impl Local for Only {
            fn bound(&self, ip: IpAddr) -> impl Future<Output = Option<bool>> {
                std::future::ready(Some(ip == self.0))
            }
        }
        run(async {
            let nat64 = [Cidr::nat64("2001:db8:64::/96").expect("prefix")];
            let own = Own::new(Only(ip("8.8.4.4")));
            assert!(own.own(ip("2001:db8:64::808:404"), &nat64).await);
            assert!(!own.own(ip("2001:db8:64::808:808"), &nat64).await);
            assert!(!own.own(ip("2001:db8:64::808:404"), &[]).await);
            assert!(own.own(ip("::ffff:0:8.8.4.4"), &[]).await);
            assert!(
                own.own(ip("2001:0:4136:e378:8000:63bf:f7f7:fbfb"), &[])
                    .await
            );
        });
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
