use control::{Domain, Verification};
use dns::{Found, Name, Record, Resolver, Type};
use sched::{Error, Node, RETURN_PREFIX, Transport};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Name,
    Dns,
    Mx,
    Cname,
    Spf,
}

pub async fn check(resolver: &Resolver, name: &str, hosts: &[Name]) -> Result<(), Refused> {
    let name = Name::parse(name).map_err(|_| Refused::Name)?;
    if name.is_root() {
        return Err(Refused::Name);
    }
    let name = name.prefixed(RETURN_PREFIX).map_err(|_| Refused::Name)?;
    let mx = resolver
        .lookup(&name, Type::Mx)
        .await
        .map_err(|_| Refused::Dns)?;
    if !matches!(&mx.found, Found::Records(records) if records.iter().any(|r| matches!(r, Record::Mx { .. })))
    {
        return Err(Refused::Mx);
    }
    if mx.name == name || !hosts.contains(&mx.name) {
        return Err(Refused::Cname);
    }
    let txt = resolver
        .lookup(&name, Type::Txt)
        .await
        .map_err(|_| Refused::Dns)?;
    let prefix = b"v=spf1";
    match &txt.found {
        Found::Records(records) if records.iter().any(|record| {
            matches!(record, Record::Txt(text) if text.get(..prefix.len()).is_some_and(|start| start.eq_ignore_ascii_case(prefix)))
        }) => Ok(()),
        _ => Err(Refused::Spf),
    }
}

pub async fn enable<T: Transport + 'static>(
    node: &Node<T>,
    resolver: &Resolver,
    hosts: &[Name],
    tenant: u32,
    id: u32,
) -> Result<Domain, Error> {
    let domain = read_domain(node, tenant, id)?;
    if domain.state != Verification::Verified {
        return Err(control::Error::Invalid("return path").into());
    }
    check(resolver, &domain.name, hosts)
        .await
        .map_err(|_| control::Error::Invalid("return path"))?;
    let current = read_domain(node, tenant, id)?;
    if current.name != domain.name || current.generation != domain.generation {
        return Err(control::Error::Refused.into());
    }
    node.domain_write(Domain {
        return_path: true,
        ..current
    })
    .await
}

pub async fn disable<T: Transport + 'static>(
    node: &Node<T>,
    tenant: u32,
    id: u32,
) -> Result<Domain, Error> {
    let domain = read_domain(node, tenant, id)?;
    node.domain_write(Domain {
        return_path: false,
        ..domain
    })
    .await
}

fn read_domain<T: Transport + 'static>(
    node: &Node<T>,
    tenant: u32,
    id: u32,
) -> Result<Domain, Error> {
    node.table()
        .domain(tenant, id)
        .cloned()
        .ok_or_else(|| control::Error::Refused.into())
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;
    use std::time::Duration;

    use super::{Refused, check};

    #[test]
    fn invalid_names_are_refused_before_dns() {
        let driver = Rc::new(rt::sim::SimDriver::new(1, rt::sim::Config::default()));
        rt::Runtime::new(driver).block_on(async {
            rt::timeout(Duration::from_secs(1), async {
                let resolver = dns::Resolver::new(
                    dns::Settings::new(Vec::new()),
                    &crypto::Secret::new([1; 32]),
                );
                assert_eq!(check(&resolver, "", &[]).await, Err(Refused::Name));
                assert_eq!(
                    check(&resolver, "a..example", &[]).await,
                    Err(Refused::Name)
                );
                let long = ["a".repeat(62).as_str(); 4].join(".");
                assert_eq!(check(&resolver, &long, &[]).await, Err(Refused::Name));
                assert_eq!(resolver.sent(), 0);
            })
            .await
            .expect("check in time");
        });
    }
}
