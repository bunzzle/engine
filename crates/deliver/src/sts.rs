use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use dns::{Found, Name, Record, Type};
use rt::{Instant, TcpStream, now, timeout};
use tls::{Connector, Verify};

use crate::conn::left;
use crate::https::{self, Parsed};
use crate::mx::{self, Addresses, Dns};

const MAX_AGE: u64 = 31_557_600;
const BODY: usize = 64 * 1024;
const READ: usize = 4096;
const FETCH: Duration = Duration::from_secs(60);
const FETCHES: usize = 8;
const CACHED: usize = 10_000;
const PATH: &str = "/.well-known/mta-sts.txt";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) mode: Mode,
    mx: Vec<String>,
    max_age: u64,
}

impl Policy {
    pub(crate) fn parse(text: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(text).ok()?;
        let mut version = None;
        let mut mode = None;
        let mut max_age = None;
        let mut mx = Vec::new();
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.trim().is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':')?;
            let value = value.trim();
            match name {
                "version" if version.is_none() => version = Some(value),
                "mode" if mode.is_none() => {
                    mode = Some(match value {
                        "enforce" => Mode::Enforce,
                        "testing" => Mode::Testing,
                        "none" => Mode::None,
                        _ => return None,
                    });
                }
                "max_age" if max_age.is_none() => {
                    if value.is_empty() || value.len() > 10 {
                        return None;
                    }
                    max_age = Some(value.parse::<u64>().ok()?.min(MAX_AGE));
                }
                "mx" => {
                    let pattern = value.trim_end_matches('.').to_ascii_lowercase();
                    let bare = pattern.strip_prefix("*.").unwrap_or(&pattern);
                    if bare.is_empty() || bare.contains('*') || Name::parse(bare).is_err() {
                        return None;
                    }
                    mx.push(pattern);
                }
                "version" | "mode" | "max_age" => return None,
                _ => {}
            }
        }
        let mode = mode?;
        if version != Some("STSv1") || (mode != Mode::None && mx.is_empty()) {
            return None;
        }
        Some(Self {
            mode,
            mx,
            max_age: max_age?,
        })
    }

    pub(crate) fn allows(&self, host: &Name) -> bool {
        let host = host.to_string().trim_end_matches('.').to_ascii_lowercase();
        self.mx
            .iter()
            .any(|pattern| match pattern.strip_prefix("*.") {
                Some(parent) => host
                    .split_once('.')
                    .is_some_and(|(label, rest)| !label.is_empty() && rest == parent),
                None => *pattern == host,
            })
    }
}

pub(crate) fn id(records: &[Record]) -> Option<String> {
    let mut found = None;
    for record in records {
        let Record::Txt(text) = record else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(text) else {
            continue;
        };
        let mut fields = text.split(';').map(|f| f.trim_matches([' ', '\t']));
        if fields.next() != Some("v=STSv1") {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(fields.collect::<Vec<_>>());
    }
    let fields = found?;
    let mut id = None;
    for (at, field) in fields.iter().enumerate() {
        if field.is_empty() && at + 1 == fields.len() {
            continue;
        }
        let (name, value) = field.split_once('=')?;
        if name.is_empty() || value.is_empty() {
            return None;
        }
        if name == "id" {
            let valid = value.len() <= 32 && value.bytes().all(|b| b.is_ascii_alphanumeric());
            if !valid || id.is_some() {
                return None;
            }
            id = Some(value.to_owned());
        }
    }
    id
}

pub(crate) enum Got {
    None,
    Policy(Rc<Policy>),
    Busy,
}

struct Cached {
    id: String,
    policy: Rc<Policy>,
    expires: Instant,
}

#[derive(Default)]
pub(crate) struct Sts {
    cache: RefCell<BTreeMap<Name, Cached>>,
    fetching: Rc<Cell<usize>>,
}

struct Fetching(Rc<Cell<usize>>);

impl Drop for Fetching {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

impl Sts {
    pub(crate) fn len(&self) -> usize {
        self.cache.borrow().len()
    }

    pub(crate) async fn policy<D: Dns>(
        &self,
        dns: &D,
        tls: &Connector,
        egress: IpAddr,
        domain: &Name,
        end: Instant,
    ) -> Got {
        let Ok(name) = domain.prefixed("_mta-sts") else {
            return Got::None;
        };
        let id = match timeout(left(end, FETCH), dns.lookup(&name, Type::Txt)).await {
            Ok(Ok(lookup)) => match &lookup.found {
                Found::Records(records) => id(records),
                _ => None,
            },
            _ => None,
        };
        let cached = self.cached(domain);
        let Some(id) = id else {
            return cached.map_or(Got::None, |(_, policy)| Got::Policy(policy));
        };
        if let Some((known, policy)) = &cached
            && *known == id
        {
            return Got::Policy(Rc::clone(policy));
        }
        if self.fetching.get() >= FETCHES {
            return cached.map_or(Got::Busy, |(_, policy)| Got::Policy(policy));
        }
        self.fetching.set(self.fetching.get() + 1);
        let guard = Fetching(Rc::clone(&self.fetching));
        let fetched = timeout(left(end, FETCH), fetch(dns, tls, egress, domain)).await;
        drop(guard);
        match fetched {
            Ok(Some(policy)) => {
                let policy = Rc::new(policy);
                self.store(domain, id, Rc::clone(&policy));
                Got::Policy(policy)
            }
            _ => cached.map_or(Got::None, |(_, policy)| Got::Policy(policy)),
        }
    }

    fn cached(&self, domain: &Name) -> Option<(String, Rc<Policy>)> {
        let mut cache = self.cache.borrow_mut();
        let entry = cache.get(domain)?;
        if entry.expires <= now() {
            cache.remove(domain);
            return None;
        }
        Some((entry.id.clone(), Rc::clone(&entry.policy)))
    }

    fn store(&self, domain: &Name, id: String, policy: Rc<Policy>) {
        let now = now();
        let mut cache = self.cache.borrow_mut();
        if cache.len() >= CACHED && !cache.contains_key(domain) {
            cache.retain(|_, entry| entry.expires > now);
            if cache.len() >= CACHED {
                cache.pop_first();
            }
        }
        let expires = now + Duration::from_secs(policy.max_age);
        cache.insert(
            domain.clone(),
            Cached {
                id,
                policy,
                expires,
            },
        );
    }
}

async fn fetch<D: Dns>(dns: &D, tls: &Connector, egress: IpAddr, domain: &Name) -> Option<Policy> {
    let host = domain.prefixed("mta-sts").ok()?;
    let Addresses::Found { ips, .. } = mx::addresses(dns, &host, egress.is_ipv6()).await else {
        return None;
    };
    let name = host.to_string();
    for ip in ips {
        if let Some(policy) = get(tls, egress, ip, &name).await {
            return Policy::parse(&policy);
        }
    }
    None
}

async fn get(tls: &Connector, egress: IpAddr, ip: IpAddr, name: &str) -> Option<Vec<u8>> {
    let io = TcpStream::connect_from(egress, SocketAddr::new(ip, 443))
        .await
        .ok()?;
    let mut stream = tls.connect(io, name, Verify::WebPki).await.ok()?;
    stream.write_all(&https::request(name, PATH)).await.ok()?;
    let mut bytes = Vec::new();
    let mut buf = [0; READ];
    loop {
        let n = stream.read(&mut buf).await.ok()?;
        bytes.extend_from_slice(&buf[..n]);
        match https::parse(&bytes, n == 0, BODY) {
            Parsed::Done(body) => return Some(body),
            Parsed::Bad => return None,
            Parsed::More => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use dns::{Name, Record};

    use super::{Mode, Policy, id};

    fn txt(texts: &[&str]) -> Vec<Record> {
        texts
            .iter()
            .map(|t| Record::Txt(t.as_bytes().to_vec()))
            .collect()
    }

    fn host(name: &str) -> Name {
        Name::parse(name).expect("name")
    }

    #[test]
    fn reads_the_record_id() {
        assert_eq!(
            id(&txt(&["v=STSv1; id=20160831085700Z;"])).as_deref(),
            Some("20160831085700Z")
        );
        assert_eq!(
            id(&txt(&["v=STSv1;id=a1 ;\tx=y", "other"])).as_deref(),
            Some("a1")
        );
        let none = [
            vec!["v=STSv1; id=a", "v=STSv1; id=b"],
            vec!["v=STSv1"],
            vec!["v=STSv1; id="],
            vec!["v=STSv1; id=a-b"],
            vec!["v=STSv1x; id=a"],
            vec!["v=STSv1; id=a; id=b"],
            vec!["v=STSv1; id=a;; x=y"],
            vec!["id=a; v=STSv1"],
        ];
        for case in none {
            assert_eq!(id(&txt(&case)), None, "{case:?}");
        }
        let long = format!("v=STSv1; id={}", "a".repeat(33));
        assert_eq!(id(&txt(&[&long])), None);
    }

    #[test]
    fn reads_a_policy() {
        let policy = Policy::parse(
            b"version: STSv1\r\nmode: enforce\nmx: mail.example.com.\nmx: *.Example.net\nmax_age: 604800\nother: x\n",
        )
        .expect("policy");
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.max_age, 604_800);
        assert!(policy.allows(&host("MAIL.example.com")));
        assert!(policy.allows(&host("mx1.example.net")));
        assert!(!policy.allows(&host("example.net")));
        assert!(!policy.allows(&host("a.b.example.net")));
        assert!(!policy.allows(&host("mail.example.org")));
        let long = Policy::parse(b"version: STSv1\nmode: none\nmax_age: 99999999999\n");
        assert_eq!(long, None);
        let capped = Policy::parse(b"version: STSv1\nmode: none\nmax_age: 9999999999\n");
        assert_eq!(capped.map(|p| p.max_age), Some(31_557_600));
        let bad = [
            "mode: enforce\nmx: a.example\nmax_age: 1\n",
            "version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: strict\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: a.example\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -1\n",
            "version: STSv1\nmode: enforce\nmode: none\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: a.*.example\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 1\njunk\n",
        ];
        for case in bad {
            assert_eq!(Policy::parse(case.as_bytes()), None, "{case}");
        }
    }
}
