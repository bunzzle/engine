use std::net::IpAddr;
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
    Found(Vec<Name>),
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
        Found::NoData => return Hosts::Found(vec![domain.clone()]),
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
    Hosts::Found(names)
}

fn literal(name: &Name) -> bool {
    let labels: Vec<&[u8]> = name.labels().collect();
    name.wire().contains(&b'[')
        || (labels.len() == 4 && labels.iter().all(|l| l.iter().all(u8::is_ascii_digit)))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Addresses {
    Found(Vec<IpAddr>),
    Failed,
}

pub(crate) async fn addresses<D: Dns>(dns: &D, host: &Name, v6: bool) -> Addresses {
    let kind = if v6 { Type::Aaaa } else { Type::A };
    let Ok(lookup) = dns.lookup(host, kind).await else {
        return Addresses::Failed;
    };
    let Found::Records(records) = &lookup.found else {
        return Addresses::Found(Vec::new());
    };
    let found = records
        .iter()
        .filter_map(|record| match record {
            Record::A(ip) if !v6 => Some(IpAddr::V4(*ip)),
            Record::Aaaa(ip) if v6 => Some(IpAddr::V6(*ip)),
            _ => None,
        })
        .filter(|ip| !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()))
        .filter(|ip| !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast()))
        .take(PER_HOST)
        .collect();
    Addresses::Found(found)
}
