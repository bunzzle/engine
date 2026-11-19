use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Duration;

use dns::{Found, Name, Record, Type};
use rt::{Instant, TcpStream, now, timeout, wall_ms};
use sched::Restore;
use tls::{Connector, Verify};

use crate::conn::left;
use crate::https::{self, Parsed};
use crate::mx::{self, Addresses, Dns};
use crate::report::{Applied, ResultType};
use crate::saver::{Saver, Slot};

const MAX_AGE: u64 = 31_557_600;
const BODY: usize = 64 * 1024;
const READ: usize = 4096;
const FETCH: Duration = Duration::from_secs(60);
const FETCHES: usize = 8;
const CACHED: usize = 10_000;
const PATH: &str = "/.well-known/mta-sts.txt";
const FORMAT: u8 = 1;
const FIXED: usize = 21;
const DAY_MS: u64 = 86_400_000;
const ROUND: Duration = Duration::from_hours(24);
const BUSY: Duration = Duration::from_mins(1);
const SPREAD_MS: u64 = 3 * 3_600_000;
const STALE_MS: u64 = 12 * 3_600_000;
const RECENT_MS: u64 = 30 * DAY_MS;
const UNUSED_MS: u64 = 180 * DAY_MS;

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
    lines: Vec<String>,
}

impl Policy {
    pub(crate) fn parse(text: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(text).ok()?;
        let mut version = None;
        let mut mode = None;
        let mut max_age = None;
        let mut mx = Vec::new();
        let mut lines = Vec::new();
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.trim().is_empty() {
                continue;
            }
            lines.push(line.trim().to_owned());
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
            lines,
        })
    }

    pub(crate) fn applied(&self) -> Applied {
        match self.mode {
            Mode::None => Applied::None,
            Mode::Enforce | Mode::Testing => Applied::Sts {
                lines: self.lines.clone(),
                mx: self.mx.clone(),
            },
        }
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
    Failed(ResultType),
    Busy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicyStats {
    pub loaded: u64,
    pub dropped: u64,
    pub unread: u64,
    pub unsaved: u64,
}

struct Cached {
    id: String,
    policy: Rc<Policy>,
    text: Rc<[u8]>,
    expires: Instant,
    fetched: u64,
    until: u64,
    used: u64,
    saved_day: u64,
    slot: Option<Slot>,
}

impl Cached {
    fn encode(&self, domain: &Name) -> Vec<u8> {
        let domain = domain.to_string();
        let mut out = Vec::with_capacity(FIXED + domain.len() + self.id.len() + self.text.len());
        out.push(FORMAT);
        out.extend_from_slice(&self.fetched.to_le_bytes());
        out.extend_from_slice(&self.until.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(self.used / DAY_MS)
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        out.push(u8::try_from(domain.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(domain.as_bytes());
        out.push(u8::try_from(self.id.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.text);
        out
    }

    fn decode(data: &[u8], slot: Slot, at: Instant, wall: u64) -> Option<(Name, Self)> {
        let fixed = data.get(..FIXED)?;
        if fixed[0] != FORMAT {
            return None;
        }
        let fetched = u64::from_le_bytes(fixed[1..9].try_into().ok()?);
        let until = u64::from_le_bytes(fixed[9..17].try_into().ok()?);
        let saved_day = u64::from(u32::from_le_bytes(fixed[17..21].try_into().ok()?));
        let (domain, rest) = field(&data[FIXED..])?;
        let (id, text) = field(rest)?;
        let domain = Name::parse(std::str::from_utf8(domain).ok()?).ok()?;
        let id = std::str::from_utf8(id).ok()?.to_owned();
        if until <= wall || text.len() > BODY {
            return None;
        }
        let policy = Policy::parse(text)?;
        let cached = Self {
            id,
            expires: at + Duration::from_millis((until - wall).min(max_age_ms(&policy))),
            policy: Rc::new(policy),
            text: Rc::from(text),
            fetched,
            until,
            used: saved_day * DAY_MS,
            saved_day,
            slot: Some(slot),
        };
        Some((domain, cached))
    }
}

fn max_age_ms(policy: &Policy) -> u64 {
    policy.max_age.saturating_mul(1000)
}

fn field(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = data.split_first()?;
    let len = usize::from(len);
    (rest.len() >= len).then(|| rest.split_at(len))
}

pub(crate) struct Sts {
    cache: RefCell<BTreeMap<Name, Cached>>,
    fetching: Rc<Cell<usize>>,
    joined: RefCell<BTreeMap<Name, Rc<Joined>>>,
    bound: usize,
    saver: Rc<Saver>,
    stats: Cell<PolicyStats>,
    egress: Cell<Option<IpAddr>>,
    round: Cell<Option<Instant>>,
    due: RefCell<BTreeSet<(Instant, Name)>>,
}

enum Fetched {
    Policy(Rc<Policy>),
    Failed(ResultType),
    Busy,
}

#[derive(Default)]
struct Joined {
    done: RefCell<Option<Result<Rc<Policy>, ResultType>>>,
    wakers: RefCell<Vec<Waker>>,
}

impl Joined {
    fn finish(&self, fetched: Result<Rc<Policy>, ResultType>) {
        if self.done.borrow().is_some() {
            return;
        }
        *self.done.borrow_mut() = Some(fetched);
        for waker in self.wakers.take() {
            waker.wake();
        }
    }

    async fn wait(&self) -> Result<Rc<Policy>, ResultType> {
        poll_fn(|cx| {
            if let Some(fetched) = &*self.done.borrow() {
                return Poll::Ready(fetched.clone());
            }
            let mut wakers = self.wakers.borrow_mut();
            if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                wakers.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await
    }
}

struct Leading<'a> {
    joined: &'a RefCell<BTreeMap<Name, Rc<Joined>>>,
    domain: Name,
    done: Rc<Joined>,
}

impl Drop for Leading<'_> {
    fn drop(&mut self) {
        self.joined.borrow_mut().remove(&self.domain);
        self.done.finish(Err(ResultType::StsPolicyFetchError));
    }
}

impl Default for Sts {
    fn default() -> Self {
        Self::new(CACHED)
    }
}

struct Fetching(Rc<Cell<usize>>);

impl Drop for Fetching {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

impl Sts {
    pub(crate) fn new(bound: usize) -> Self {
        Self {
            cache: RefCell::default(),
            fetching: Rc::default(),
            joined: RefCell::default(),
            bound,
            saver: Rc::default(),
            stats: Cell::new(PolicyStats::default()),
            egress: Cell::new(None),
            round: Cell::new(None),
            due: RefCell::default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.cache.borrow().len()
    }

    pub(crate) fn stats(&self) -> PolicyStats {
        PolicyStats {
            unsaved: self.saver.unsaved(),
            ..self.stats.get()
        }
    }

    pub(crate) fn restore(&self, restore: Restore) {
        let Restore {
            saved,
            unread,
            dropped,
            records,
            ..
        } = restore;
        let (at, wall) = (now(), wall_ms());
        let mut loaded: BTreeMap<Name, Cached> = BTreeMap::new();
        let mut removed = Vec::new();
        for one in saved {
            let slot = (one.shard, one.id);
            let Some((domain, cached)) = Cached::decode(&one.data, slot, at, wall) else {
                removed.push(slot);
                continue;
            };
            match loaded.get(&domain) {
                Some(kept) if kept.fetched >= cached.fetched => removed.push(slot),
                _ => {
                    if let Some(old) = loaded.insert(domain, cached) {
                        removed.extend(old.slot);
                    }
                }
            }
        }
        if loaded.len() > self.bound {
            let mut by_use: Vec<(u64, Name)> =
                loaded.iter().map(|(d, c)| (c.used, d.clone())).collect();
            by_use.sort_unstable_by_key(|(used, _)| std::cmp::Reverse(*used));
            for (_, domain) in by_use.into_iter().skip(self.bound) {
                if let Some(old) = loaded.remove(&domain) {
                    removed.extend(old.slot);
                }
            }
        }
        self.saver
            .attach(records, loaded.values().filter_map(|c| c.slot).collect());
        let mut stats = self.stats.get();
        stats.loaded += loaded.len() as u64;
        stats.dropped += dropped + removed.len() as u64;
        stats.unread += unread;
        self.stats.set(stats);
        for slot in removed {
            self.saver.save(slot, None);
        }
        self.cache.borrow_mut().extend(loaded);
    }

    pub(crate) async fn policy<D: Dns>(
        &self,
        dns: &D,
        tls: &Connector,
        egress: IpAddr,
        domain: &Name,
        end: Instant,
    ) -> Got {
        self.egress.set(Some(egress));
        let id = txt_id(dns, domain, end).await;
        let cached = self.cached(domain);
        let Some(id) = id else {
            return cached.map_or(Got::None, |(_, policy)| Got::Policy(policy));
        };
        if let Some((known, policy)) = &cached
            && *known == id
        {
            return Got::Policy(Rc::clone(policy));
        }
        match self.fetch(dns, tls, egress, domain, id, end).await {
            Fetched::Policy(policy) => Got::Policy(policy),
            Fetched::Busy => cached.map_or(Got::Busy, |(_, policy)| Got::Policy(policy)),
            Fetched::Failed(result) => {
                cached.map_or(Got::Failed(result), |(_, policy)| Got::Policy(policy))
            }
        }
    }

    async fn fetch<D: Dns>(
        &self,
        dns: &D,
        tls: &Connector,
        egress: IpAddr,
        domain: &Name,
        id: String,
        end: Instant,
    ) -> Fetched {
        let running = self.joined.borrow().get(domain).cloned();
        if let Some(joined) = running {
            return match timeout(left(end, FETCH), joined.wait()).await {
                Ok(Ok(policy)) => Fetched::Policy(policy),
                Ok(Err(result)) => Fetched::Failed(result),
                Err(_) => Fetched::Failed(ResultType::StsPolicyFetchError),
            };
        }
        if self.fetching.get() >= FETCHES {
            return Fetched::Busy;
        }
        self.fetching.set(self.fetching.get() + 1);
        let counted = Fetching(Rc::clone(&self.fetching));
        let joined = Rc::new(Joined::default());
        self.joined
            .borrow_mut()
            .insert(domain.clone(), Rc::clone(&joined));
        let leading = Leading {
            joined: &self.joined,
            domain: domain.clone(),
            done: Rc::clone(&joined),
        };
        let fetched = timeout(left(end, FETCH), get_policy(dns, tls, egress, domain)).await;
        drop(counted);
        let fetched = match fetched {
            Ok(Ok((policy, text))) => {
                let policy = Rc::new(policy);
                self.store(domain, id, Rc::clone(&policy), text);
                Ok(policy)
            }
            Ok(Err(result)) => Err(result),
            Err(_) => Err(ResultType::StsPolicyFetchError),
        };
        joined.finish(fetched.clone());
        drop(leading);
        match fetched {
            Ok(policy) => Fetched::Policy(policy),
            Err(result) => Fetched::Failed(result),
        }
    }

    pub(crate) async fn refresh<D: Dns>(
        &self,
        dns: &D,
        tls: &Connector,
        fixed: Option<IpAddr>,
        jitter: impl Fn(u64) -> u64,
    ) {
        let at = now();
        if self.round.get().is_none_or(|round| round <= at) {
            self.plan(at, jitter);
            self.round.set(Some(at + ROUND));
        }
        loop {
            let next = {
                let mut due = self.due.borrow_mut();
                match due.first() {
                    Some((when, _)) if *when <= now() => due.pop_first(),
                    _ => None,
                }
            };
            let Some((_, domain)) = next else {
                return;
            };
            self.refresh_one(dns, tls, fixed, &domain).await;
        }
    }

    fn plan(&self, at: Instant, jitter: impl Fn(u64) -> u64) {
        let wall = wall_ms();
        let mut cache = self.cache.borrow_mut();
        let unused: Vec<Name> = cache
            .iter()
            .filter(|(_, entry)| entry.expires <= at || entry.used.saturating_add(UNUSED_MS) < wall)
            .map(|(domain, _)| domain.clone())
            .collect();
        for domain in unused {
            if let Some(slot) = cache.remove(&domain).and_then(|entry| entry.slot) {
                self.saver.save(slot, None);
            }
        }
        let mut due = self.due.borrow_mut();
        due.clear();
        for (domain, entry) in cache.iter() {
            let recent = entry.used.saturating_add(RECENT_MS) >= wall;
            let stale = entry.fetched.saturating_add(STALE_MS) <= wall;
            if recent && stale {
                let delay = Duration::from_millis(jitter(SPREAD_MS));
                due.insert((at + delay, domain.clone()));
            }
        }
    }

    async fn refresh_one<D: Dns>(
        &self,
        dns: &D,
        tls: &Connector,
        fixed: Option<IpAddr>,
        domain: &Name,
    ) {
        let end = now() + FETCH;
        let Some(id) = txt_id(dns, domain, end).await else {
            return;
        };
        let wall = wall_ms();
        let needed = self.cache.borrow().get(domain).is_some_and(|entry| {
            let left = entry.until.saturating_sub(wall);
            entry.id != id || left < max_age_ms(&entry.policy) / 4
        });
        if let (true, Some(egress)) = (needed, fixed.or(self.egress.get()))
            && let Fetched::Busy = self.fetch(dns, tls, egress, domain, id, end).await
        {
            self.due.borrow_mut().insert((now() + BUSY, domain.clone()));
        }
    }

    fn cached(&self, domain: &Name) -> Option<(String, Rc<Policy>)> {
        let mut cache = self.cache.borrow_mut();
        let entry = cache.get_mut(domain)?;
        if entry.expires <= now() {
            let slot = entry.slot;
            cache.remove(domain);
            if let Some(slot) = slot {
                self.saver.save(slot, None);
            }
            return None;
        }
        let wall = wall_ms();
        entry.used = entry.used.max(wall);
        if wall / DAY_MS > entry.saved_day {
            entry.saved_day = wall / DAY_MS;
            if let Some(slot) = entry.slot {
                self.saver.save(slot, Some(entry.encode(domain)));
            }
        }
        Some((entry.id.clone(), Rc::clone(&entry.policy)))
    }

    fn store(&self, domain: &Name, id: String, policy: Rc<Policy>, text: Vec<u8>) {
        let at = now();
        let wall = wall_ms();
        let mut cache = self.cache.borrow_mut();
        let (slot, used, saved_day) = if let Some(old) = cache.get(domain) {
            (old.slot, old.used, old.saved_day)
        } else {
            if cache.len() >= self.bound {
                self.make_room(&mut cache, at);
            }
            (self.saver.take(self.bound), wall, wall / DAY_MS)
        };
        let entry = Cached {
            id,
            text: Rc::from(text),
            expires: at + Duration::from_secs(policy.max_age),
            fetched: wall,
            until: wall.saturating_add(max_age_ms(&policy)),
            used,
            saved_day,
            policy,
            slot,
        };
        if let Some(slot) = slot {
            self.saver.save(slot, Some(entry.encode(domain)));
        }
        cache.insert(domain.clone(), entry);
    }

    fn make_room(&self, cache: &mut BTreeMap<Name, Cached>, at: Instant) {
        let mut gone: Vec<Name> = cache
            .iter()
            .filter(|(_, entry)| entry.expires <= at)
            .map(|(domain, _)| domain.clone())
            .collect();
        if cache.len() - gone.len() >= self.bound
            && let Some((domain, _)) = cache.iter().min_by_key(|(_, entry)| entry.used)
        {
            gone.push(domain.clone());
        }
        for domain in gone {
            if let Some(slot) = cache.remove(&domain).and_then(|entry| entry.slot) {
                self.saver.save(slot, None);
            }
        }
    }
}

async fn txt_id<D: Dns>(dns: &D, domain: &Name, end: Instant) -> Option<String> {
    let name = domain.prefixed("_mta-sts").ok()?;
    match timeout(left(end, FETCH), dns.lookup(&name, Type::Txt)).await {
        Ok(Ok(lookup)) => match &lookup.found {
            Found::Records(records) => id(records),
            _ => None,
        },
        _ => None,
    }
}

async fn get_policy<D: Dns>(
    dns: &D,
    tls: &Connector,
    egress: IpAddr,
    domain: &Name,
) -> Result<(Policy, Vec<u8>), ResultType> {
    let host = domain
        .prefixed("mta-sts")
        .map_err(|_| ResultType::StsPolicyFetchError)?;
    let Addresses::Found { ips, .. } = mx::addresses(dns, &host, egress.is_ipv6()).await else {
        return Err(ResultType::StsPolicyFetchError);
    };
    let name = host.to_string();
    let mut failed = ResultType::StsPolicyFetchError;
    for ip in ips {
        match get(tls, egress, ip, &name).await {
            Ok(text) => {
                return Policy::parse(&text)
                    .map(|policy| (policy, text))
                    .ok_or(ResultType::StsPolicyInvalid);
            }
            Err(result) => failed = result,
        }
    }
    Err(failed)
}

async fn get(
    tls: &Connector,
    egress: IpAddr,
    ip: IpAddr,
    name: &str,
) -> Result<Vec<u8>, ResultType> {
    let fetch = ResultType::StsPolicyFetchError;
    let io = TcpStream::connect_from(egress, SocketAddr::new(ip, 443))
        .await
        .map_err(|_| fetch)?;
    let mut stream = tls
        .connect(io, name, Verify::WebPki)
        .await
        .map_err(|_| ResultType::StsWebpkiInvalid)?;
    stream
        .write_all(&https::request(name, PATH))
        .await
        .map_err(|_| fetch)?;
    let mut bytes = Vec::new();
    let mut buf = [0; READ];
    loop {
        let n = stream.read(&mut buf).await.map_err(|_| fetch)?;
        bytes.extend_from_slice(&buf[..n]);
        match https::parse(&bytes, n == 0, BODY) {
            Parsed::Done(body) => return Ok(body),
            Parsed::Bad => return Err(fetch),
            Parsed::More => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use std::time::Duration;

    use dns::{Name, Record};
    use rt::sim::{Config, SimDriver};
    use rt::{Runtime, sleep};
    use sched::{Done, Records, Restore, Saved};

    use super::{Cached, Mode, Policy, Sts, id};

    const HOME: u16 = 3;
    const TEXT: &str = "version: STSv1\nmode: enforce\nmx: mx.example\nmax_age: 86400\n";

    #[derive(Default)]
    struct Memory {
        rows: RefCell<BTreeMap<(u16, u32), Vec<u8>>>,
    }

    impl Records for Memory {
        fn home(&self) -> u16 {
            HOME
        }

        fn put(&self, shard: u16, id: u32, data: Vec<u8>) -> Done<'_> {
            self.rows.borrow_mut().insert((shard, id), data);
            Box::pin(std::future::ready(Ok(())))
        }

        fn remove(&self, shard: u16, id: u32) -> Done<'_> {
            self.rows.borrow_mut().remove(&(shard, id));
            Box::pin(std::future::ready(Ok(())))
        }
    }

    impl Memory {
        fn saved(&self) -> Vec<Saved> {
            self.rows
                .borrow()
                .iter()
                .map(|(&(shard, id), data)| Saved {
                    shard,
                    id,
                    data: data.clone(),
                })
                .collect()
        }
    }

    fn restored(sts: &Sts, saved: Vec<Saved>, records: &Rc<Memory>) {
        sts.restore(Restore {
            kind: control::KIND_STS,
            naming: [0; 16],
            saved,
            unread: 0,
            dropped: 0,
            records: Rc::clone(records) as Rc<dyn Records>,
        });
    }

    fn put(sts: &Sts, domain: &str, id: &str) {
        let policy = Policy::parse(TEXT.as_bytes()).expect("policy");
        sts.store(
            &host(domain),
            id.to_owned(),
            Rc::new(policy),
            TEXT.as_bytes().to_vec(),
        );
    }

    fn domains(sts: &Sts) -> Vec<String> {
        sts.cache.borrow().keys().map(ToString::to_string).collect()
    }

    fn run(future: impl Future<Output = ()> + 'static) {
        let driver = Rc::new(SimDriver::new(3, Config::default()));
        Runtime::new(driver).block_on(future);
    }

    #[test]
    fn saved_policies_evict_by_last_use_and_come_back() {
        run(async {
            let memory = Rc::new(Memory::default());
            let sts = Sts::new(3);
            restored(&sts, Vec::new(), &memory);
            put(&sts, "a.example", "1");
            sleep(Duration::from_secs(1)).await;
            put(&sts, "b.example", "1");
            sleep(Duration::from_secs(1)).await;
            put(&sts, "c.example", "1");
            sleep(Duration::from_secs(1)).await;
            assert!(sts.cached(&host("a.example")).is_some());
            put(&sts, "d.example", "1");
            sleep(Duration::from_millis(1)).await;
            assert_eq!(domains(&sts), ["a.example", "c.example", "d.example"]);
            let rows: Vec<(u16, u32)> = memory.rows.borrow().keys().copied().collect();
            assert_eq!(rows, [(HOME, 0), (HOME, 1), (HOME, 2)]);

            let again = Sts::new(3);
            restored(&again, memory.saved(), &memory);
            assert_eq!(domains(&again), domains(&sts));
            assert_eq!(again.stats().loaded, 3);
            let (known, policy) = again.cached(&host("d.example")).expect("restored");
            assert_eq!(known, "1");
            assert_eq!(policy.mode, Mode::Enforce);
        });
    }

    #[test]
    fn a_clock_set_back_keeps_a_policy_no_longer_than_max_age() {
        run(async {
            let memory = Rc::new(Memory::default());
            let sts = Sts::new(2);
            restored(&sts, Vec::new(), &memory);
            put(&sts, "a.example", "1");
            sleep(Duration::from_millis(1)).await;
            let mut far = memory.rows.borrow()[&(HOME, 0)].clone();
            far[9..17].copy_from_slice(&u64::MAX.to_le_bytes());
            let (at, wall) = (rt::now(), rt::wall_ms());
            let (_, cached) = Cached::decode(&far, (HOME, 0), at, wall).expect("decoded");
            assert_eq!(cached.expires, at + Duration::from_hours(24));
        });
    }

    #[test]
    fn restore_drops_bad_expired_and_older_copies() {
        run(async {
            let memory = Rc::new(Memory::default());
            let sts = Sts::new(2);
            restored(&sts, Vec::new(), &memory);
            put(&sts, "a.example", "old");
            sleep(Duration::from_secs(1)).await;
            let old = memory.rows.borrow()[&(HOME, 0)].clone();
            put(&sts, "a.example", "new");
            put(&sts, "b.example", "1");
            sleep(Duration::from_millis(1)).await;
            let mut saved = memory.saved();
            saved.push(Saved {
                shard: 5,
                id: 0,
                data: old,
            });
            saved.push(Saved {
                shard: 5,
                id: 1,
                data: b"junk".to_vec(),
            });
            let mut expired = memory.rows.borrow()[&(HOME, 1)].clone();
            expired[9..17].copy_from_slice(&1u64.to_le_bytes());
            saved.push(Saved {
                shard: 5,
                id: 2,
                data: expired,
            });
            let again = Sts::new(2);
            restored(&again, saved, &memory);
            sleep(Duration::from_millis(1)).await;
            assert_eq!(domains(&again), ["a.example", "b.example"]);
            assert_eq!(again.cached(&host("a.example")).expect("a").0, "new");
            assert_eq!(again.stats().dropped, 3);
            assert_eq!(again.stats().loaded, 2);

            let small = Sts::new(1);
            restored(&small, memory.saved(), &memory);
            sleep(Duration::from_millis(1)).await;
            assert_eq!(small.len(), 1);
            assert_eq!(memory.rows.borrow().len(), 1);
        });
    }

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
