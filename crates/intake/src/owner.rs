use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use rt::Instant;

const SCAN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prefix {
    v6: bool,
    bytes: [u8; 8],
}

impl Prefix {
    pub fn of(ip: IpAddr) -> (Self, Self) {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                (Self::new(false, &octets), Self::new(false, &octets[..3]))
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                (Self::new(true, &octets[..8]), Self::new(true, &octets[..6]))
            }
        }
    }

    fn new(v6: bool, part: &[u8]) -> Self {
        let mut bytes = [0; 8];
        bytes[..part.len()].copy_from_slice(part);
        Self { v6, bytes }
    }

    pub(crate) fn hashed(self) -> [u8; 9] {
        let mut out = [0; 9];
        out[0] = u8::from(self.v6);
        out[1..].copy_from_slice(&self.bytes);
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub sessions: usize,
    pub per_net: u16,
    pub net_failures: u32,
    pub wide_failures: u32,
    pub ban: Duration,
    pub leak: Duration,
    pub entries: usize,
    pub budget: usize,
    pub ask: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sessions: 1024,
            per_net: 16,
            net_failures: 10,
            wide_failures: 30,
            ban: Duration::from_secs(600),
            leak: Duration::from_secs(60),
            entries: 65_536,
            budget: 64 << 20,
            ask: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    Ok,
    Full,
    Banned,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnerStats {
    pub nets: usize,
    pub wides: usize,
    pub tenants: usize,
    pub open: u64,
    pub tenant_open: u64,
    pub bans: u64,
    pub banned: u64,
    pub full: u64,
    pub table_full: u64,
    pub evicted: u64,
    pub failures: u64,
}

#[derive(Clone, Copy)]
struct Entry {
    open: u16,
    milli: u64,
    at: Instant,
    until: Option<Instant>,
    used: bool,
}

impl Entry {
    fn new(now: Instant) -> Self {
        Self {
            open: 0,
            milli: 0,
            at: now,
            until: None,
            used: true,
        }
    }

    fn banned(&self, now: Instant) -> bool {
        self.until.is_some_and(|until| now < until)
    }

    fn level(&self, now: Instant, leak: Duration) -> u64 {
        let gone =
            now.saturating_duration_since(self.at).as_nanos() * 1000 / leak.as_nanos().max(1);
        self.milli
            .saturating_sub(u64::try_from(gone).unwrap_or(u64::MAX))
    }

    fn fail(&mut self, now: Instant, limits: &Limits, limit: u32) -> bool {
        self.milli = self.level(now, limits.leak) + 1000;
        self.at = now;
        self.used = true;
        if self.milli > u64::from(limit) * 1000 {
            self.milli = 0;
            self.until = Some(now + limits.ban);
            return true;
        }
        false
    }

    fn evictable(&self, now: Instant) -> bool {
        self.open == 0 && !self.banned(now)
    }

    fn idle(&self, now: Instant, leak: Duration) -> bool {
        self.evictable(now) && self.level(now, leak) == 0
    }
}

struct Table {
    index: HashMap<Prefix, usize>,
    slots: Vec<Option<(Prefix, Entry)>>,
    free: Vec<usize>,
    hand: usize,
    cap: usize,
}

impl Table {
    fn new(cap: usize) -> Self {
        Self {
            index: HashMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            hand: 0,
            cap,
        }
    }

    fn len(&self) -> usize {
        self.index.len()
    }

    fn get(&self, key: Prefix) -> Option<&Entry> {
        let at = *self.index.get(&key)?;
        self.slots[at].as_ref().map(|(_, entry)| entry)
    }

    fn get_mut(&mut self, key: Prefix) -> Option<&mut Entry> {
        let at = *self.index.get(&key)?;
        self.slots[at].as_mut().map(|(_, entry)| entry)
    }

    fn remove(&mut self, key: Prefix) {
        if let Some(at) = self.index.remove(&key) {
            self.slots[at] = None;
            self.free.push(at);
        }
    }

    fn insert(&mut self, key: Prefix, now: Instant, evicted: &mut u64) -> Option<&mut Entry> {
        let at = if let Some(at) = self.free.pop() {
            at
        } else if self.slots.len() < self.cap {
            self.slots.push(None);
            self.slots.len() - 1
        } else {
            let at = self.victim(now)?;
            *evicted += 1;
            at
        };
        self.slots[at] = Some((key, Entry::new(now)));
        self.index.insert(key, at);
        self.slots[at].as_mut().map(|(_, entry)| entry)
    }

    fn victim(&mut self, now: Instant) -> Option<usize> {
        let len = self.slots.len();
        for _ in 0..SCAN.min(len * 2) {
            let at = self.hand;
            self.hand = (self.hand + 1) % len;
            let Some((key, entry)) = self.slots[at].as_mut() else {
                return Some(at);
            };
            if !entry.evictable(now) {
                continue;
            }
            if entry.used {
                entry.used = false;
                continue;
            }
            let key = *key;
            self.index.remove(&key);
            self.slots[at] = None;
            return Some(at);
        }
        None
    }
}

pub struct Owner {
    limits: Limits,
    nets: Table,
    wides: Table,
    tenants: HashMap<u32, u32>,
    stats: OwnerStats,
}

impl Owner {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            nets: Table::new(limits.entries),
            wides: Table::new(limits.entries),
            tenants: HashMap::new(),
            stats: OwnerStats::default(),
        }
    }

    pub fn open(&mut self, net: Prefix, wide: Prefix, now: Instant) -> Opened {
        let opened = self.try_open(net, wide, now);
        match opened {
            Opened::Ok => self.stats.open += 1,
            Opened::Full => self.stats.full += 1,
            Opened::Banned => self.stats.banned += 1,
        }
        opened
    }

    fn try_open(&mut self, net: Prefix, wide: Prefix, now: Instant) -> Opened {
        if self.wides.get(wide).is_some_and(|entry| entry.banned(now)) {
            return Opened::Banned;
        }
        if let Some(entry) = self.nets.get_mut(net) {
            if entry.banned(now) {
                return Opened::Banned;
            }
            if entry.open >= self.limits.per_net {
                return Opened::Full;
            }
            entry.open += 1;
            entry.used = true;
            return Opened::Ok;
        }
        if self.limits.per_net == 0 {
            return Opened::Full;
        }
        if let Some(entry) = self.nets.insert(net, now, &mut self.stats.evicted) {
            entry.open = 1;
            return Opened::Ok;
        }
        self.stats.table_full += 1;
        Opened::Full
    }

    pub fn close(&mut self, net: Prefix, now: Instant) {
        let leak = self.limits.leak;
        let Some(entry) = self.nets.get_mut(net) else {
            return;
        };
        if entry.open == 0 {
            return;
        }
        entry.open -= 1;
        self.stats.open -= 1;
        if entry.idle(now, leak) {
            self.nets.remove(net);
        }
    }

    pub fn failed(&mut self, net: Prefix, wide: Prefix, now: Instant) -> bool {
        self.stats.failures += 1;
        let limits = self.limits;
        let mut banned = false;
        for (table, key, limit) in [
            (&mut self.nets, net, limits.net_failures),
            (&mut self.wides, wide, limits.wide_failures),
        ] {
            let entry = match table.get_mut(key) {
                Some(entry) => Some(entry),
                None => table.insert(key, now, &mut self.stats.evicted),
            };
            let Some(entry) = entry else {
                self.stats.table_full += 1;
                continue;
            };
            if entry.fail(now, &limits, limit) {
                self.stats.bans += 1;
            }
            banned |= entry.banned(now);
        }
        banned
    }

    pub fn open_tenant(&mut self, tenant: u32, limit: u32) -> Opened {
        let open = self.tenants.entry(tenant).or_insert(0);
        if *open >= limit {
            if *open == 0 {
                self.tenants.remove(&tenant);
            }
            self.stats.full += 1;
            return Opened::Full;
        }
        *open += 1;
        self.stats.tenant_open += 1;
        Opened::Ok
    }

    pub fn close_tenant(&mut self, tenant: u32) {
        let Some(open) = self.tenants.get_mut(&tenant) else {
            return;
        };
        *open -= 1;
        self.stats.tenant_open -= 1;
        if *open == 0 {
            self.tenants.remove(&tenant);
        }
    }

    pub fn stats(&self) -> OwnerStats {
        OwnerStats {
            nets: self.nets.len(),
            wides: self.wides.len(),
            tenants: self.tenants.len(),
            ..self.stats
        }
    }
}
