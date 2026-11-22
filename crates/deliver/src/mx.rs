use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

use dns::{Error, Found, Lookup, Name, Record, Resolver, Type};

const PER_HOST: usize = 4;

pub trait Dns {
    fn lookup(&self, name: &Name, kind: Type) -> impl Future<Output = Result<Rc<Lookup>, Error>>;
}

impl Dns for Resolver {
    fn lookup(&self, name: &Name, kind: Type) -> impl Future<Output = Result<Rc<Lookup>, Error>> {
        Resolver::lookup(self, name, kind)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hosts {
    Found(Vec<Name>, bool),
    NullMx,
    NoDomain,
    Failed,
}

pub(crate) async fn hosts<D: Dns>(
    dns: &D,
    domain: &Name,
    pick: &mut impl FnMut(usize) -> usize,
) -> Hosts {
    let Ok(lookup) = dns.lookup(domain, Type::Mx).await else {
        return Hosts::Failed;
    };
    let records = match &lookup.found {
        Found::NxDomain => return Hosts::NoDomain,
        Found::NoData => return Hosts::Found(vec![domain.clone()], lookup.secure),
        Found::Records(records) => records,
    };
    let mut mx: Vec<(u16, &Name)> = records
        .iter()
        .filter_map(|record| match record {
            Record::Mx {
                preference,
                exchange,
            } => Some((*preference, exchange)),
            _ => None,
        })
        .collect();
    if mx.is_empty() {
        return Hosts::Failed;
    }
    if mx.len() == 1 && mx[0].1.is_root() {
        return Hosts::NullMx;
    }
    mx.retain(|(_, name)| !name.is_root() && !literal(name));
    mx.sort_by_key(|(preference, _)| *preference);
    let mut start = 0;
    while start < mx.len() {
        let preference = mx[start].0;
        let end = start + mx[start..].iter().take_while(|m| m.0 == preference).count();
        for i in (start + 1..end).rev() {
            mx.swap(i, start + pick(i - start + 1));
        }
        start = end;
    }
    let mut names: Vec<Name> = Vec::with_capacity(mx.len());
    for (_, name) in mx {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    Hosts::Found(names, lookup.secure)
}

fn literal(name: &Name) -> bool {
    let labels: Vec<&[u8]> = name.labels().collect();
    name.wire().contains(&b'[')
        || (labels.len() == 4 && labels.iter().all(|l| l.iter().all(u8::is_ascii_digit)))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Addresses {
    Found {
        ips: Vec<IpAddr>,
        secure: bool,
        target: Name,
    },
    Failed,
}

pub(crate) async fn public<D: Dns>(dns: &D, host: &Name, v6: bool) -> Addresses {
    resolve(dns, host, v6, global).await
}

pub(crate) async fn filtered<D: Dns>(
    dns: &D,
    host: &Name,
    v6: bool,
    keep: impl Fn(&IpAddr) -> bool,
) -> Addresses {
    resolve(dns, host, v6, keep).await
}

async fn resolve<D: Dns>(
    dns: &D,
    host: &Name,
    v6: bool,
    keep: impl Fn(&IpAddr) -> bool,
) -> Addresses {
    let kind = if v6 { Type::Aaaa } else { Type::A };
    let Ok(lookup) = dns.lookup(host, kind).await else {
        return Addresses::Failed;
    };
    let Found::Records(records) = &lookup.found else {
        return Addresses::Found {
            ips: Vec::new(),
            secure: lookup.secure,
            target: lookup.name.clone(),
        };
    };
    let ips = records
        .iter()
        .filter_map(|record| match record {
            Record::A(ip) if !v6 => Some(IpAddr::V4(*ip)),
            Record::Aaaa(ip) if v6 => Some(IpAddr::V6(*ip)),
            _ => None,
        })
        .filter(|ip| keep(ip))
        .take(PER_HOST)
        .collect();
    Addresses::Found {
        ips,
        secure: lookup.secure,
        target: lookup.name.clone(),
    }
}

pub(crate) fn usable(ip: &IpAddr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
        || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())))
}

pub(crate) fn global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => global_v4(*v4),
        IpAddr::V6(v6) => global_v6(*v6),
    }
}

fn global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0 | 10 | 127 | 224..=255, _, _)
            | (100, 64..=127, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0 | 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
    )
}

fn global_v6(ip: Ipv6Addr) -> bool {
    let embedded = |high: u16, low: u16| {
        let [first, second] = high.to_be_bytes();
        let [third, fourth] = low.to_be_bytes();
        global_v4(Ipv4Addr::new(first, second, third, fourth))
    };
    match ip.segments() {
        [0x64, 0xff9b, 0, 0, 0, 0, high, low] => embedded(high, low),
        [0, 0, 0, 0, 0, 0 | 0xffff, _, _]
        | [0x2002 | 0x5f00, ..]
        | [0x0064, 0xff9b, 1, ..]
        | [0x0100, 0, 0, 0, ..]
        | [0x2001, 0x0000..=0x01ff | 0x0db8, ..]
        | [0x3fff, 0x0000..=0x0fff, ..] => false,
        [first, ..] => (0x2000..=0x3fff).contains(&first),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::global;

    #[test]
    fn only_global_addresses_pass() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.0.1.1",
            "198.17.0.1",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700::1111",
            "2a00:1450::1",
            "64:ff9b::8.8.8.8",
            "2001:200::1",
        ] {
            let ip: IpAddr = ip.parse().expect("address");
            assert!(global(&ip), "{ip}");
        }
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:8.8.8.8",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:169.254.169.254",
            "64:ff9b::10.0.0.1",
            "64:ff9b:1::1",
            "2002:0808:0808::1",
            "2002:7f00:0001::1",
            "2002:c0a8:0101::1",
            "100::1",
            "2001::1",
            "2001:10::1",
            "2001:1ff::1",
            "2001:db8::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            let ip: IpAddr = ip.parse().expect("address");
            assert!(!global(&ip), "{ip}");
        }
    }
}
