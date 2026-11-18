use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::Duration;

use control::siphash;
use rt::{Ends, Instant, JoinHandle, Peers, now, wall_ms};
use sched::Restore;

use crate::report::{Applied, Applies, Detail, ResultType};
use crate::results::{DETAILS, POLICIES, Taken};
use crate::saver::{Saver, Slot};

pub(crate) const SLOTS: usize = 20_000;
const FLUSH: Duration = Duration::from_mins(10);
const KEPT_DAYS: u64 = 2;
const DAY_MS: u64 = 86_400_000;
const FORMAT: u8 = 1;

type Day = (u64, String);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnerStats {
    pub owned: u64,
    pub dropped: u64,
    pub forwarded: u64,
    pub unsaved: u64,
}

struct Owned {
    slot: Option<Slot>,
    policies: Vec<Applies>,
}

#[derive(Default)]
struct Table {
    owned: RefCell<BTreeMap<Day, Owned>>,
    saver: Rc<Saver>,
    restored: Cell<bool>,
    waiting: RefCell<Vec<Taken>>,
    stats: Cell<OwnerStats>,
}

impl Table {
    fn count(&self, change: impl FnOnce(&mut OwnerStats)) {
        let mut stats = self.stats.get();
        change(&mut stats);
        self.stats.set(stats);
    }

    fn merge(&self, taken: Taken) {
        if !self.restored.get() {
            let mut waiting = self.waiting.borrow_mut();
            if waiting.len() < SLOTS {
                waiting.push(taken);
            } else {
                self.count(|s| s.dropped += 1);
            }
            return;
        }
        let key = (taken.day, taken.domain);
        let mut owned = self.owned.borrow_mut();
        if !owned.contains_key(&key) {
            if owned.len() >= SLOTS {
                self.count(|s| s.dropped += 1);
                return;
            }
            let slot = self.saver.take(SLOTS);
            owned.insert(
                key.clone(),
                Owned {
                    slot,
                    policies: Vec::new(),
                },
            );
        }
        let entry = owned.get_mut(&key).expect("inserted above");
        for applies in taken.policies {
            if !add(&mut entry.policies, applies) {
                self.count(|s| s.dropped += 1);
            }
        }
        if let Some(slot) = entry.slot {
            self.saver.save(slot, Some(encode(&key, &entry.policies)));
        }
    }

    fn prune(&self, today: u64) {
        let mut owned = self.owned.borrow_mut();
        let old: Vec<Day> = owned
            .keys()
            .filter(|(day, _)| day + KEPT_DAYS <= today)
            .cloned()
            .collect();
        for key in old {
            if let Some(slot) = owned.remove(&key).and_then(|entry| entry.slot) {
                self.saver.save(slot, None);
            }
        }
    }
}

fn add(policies: &mut Vec<Applies>, applies: Applies) -> bool {
    let at = match policies.iter().position(|p| p.policy == applies.policy) {
        Some(at) => at,
        None if policies.len() < POLICIES => {
            policies.push(Applies {
                policy: applies.policy.clone(),
                success: 0,
                failure: 0,
                details: Vec::new(),
            });
            policies.len() - 1
        }
        None => return false,
    };
    let kept = &mut policies[at];
    kept.success += applies.success;
    kept.failure += applies.failure;
    for detail in applies.details {
        let same = |d: &Detail| {
            (d.result, d.sending, &d.mx, d.receiving)
                == (detail.result, detail.sending, &detail.mx, detail.receiving)
        };
        match kept.details.iter().position(same) {
            Some(at) => kept.details[at].count += detail.count,
            None if kept.details.len() < DETAILS => kept.details.push(detail),
            None => {}
        }
    }
    true
}

#[derive(Default)]
pub(crate) struct Owners {
    table: Rc<Table>,
    peers: Option<Peers<Taken>>,
    cores: u16,
    naming: Cell<[u8; 16]>,
    last: Cell<Option<(Instant, u64)>>,
}

impl Owners {
    pub(crate) fn start(&mut self, ends: Ends<Taken>) -> JoinHandle<()> {
        let table = Rc::clone(&self.table);
        self.cores = ends.cores();
        let (peers, done) = ends.start(move |_, taken| table.merge(taken));
        self.peers = Some(peers);
        done
    }

    fn owner(&self, domain: &str) -> Option<u16> {
        let peers = self.peers.as_ref()?;
        let cores = u64::from(self.cores.max(1));
        let owner = u16::try_from(siphash(&self.naming.get(), domain.as_bytes()) % cores).ok()?;
        (owner != peers.index()).then_some(owner)
    }

    fn send(&self, taken: Taken) {
        match (self.owner(&taken.domain), &self.peers) {
            (Some(owner), Some(peers)) => {
                self.table.count(|s| s.forwarded += 1);
                peers.send(owner, taken);
            }
            _ => self.table.merge(taken),
        }
    }

    pub(crate) fn due(&self) -> bool {
        let (at, day) = (now(), wall_ms() / DAY_MS);
        match self.last.get() {
            Some((last, last_day)) if last_day == day && at < last + FLUSH => false,
            Some(_) => {
                self.last.set(Some((at, day)));
                true
            }
            None => {
                self.last.set(Some((at, day)));
                false
            }
        }
    }

    pub(crate) fn flush(&self, taken: Vec<Taken>) {
        for one in taken {
            self.send(one);
        }
    }

    pub(crate) fn prune(&self) {
        self.table.prune(wall_ms() / DAY_MS);
    }

    pub(crate) fn restore(&self, restore: Restore) {
        self.naming.set(restore.naming);
        let today = wall_ms() / DAY_MS;
        let mut loaded: BTreeMap<Day, Owned> = BTreeMap::new();
        let mut removed = Vec::new();
        for saved in restore.saved {
            let slot = (saved.shard, saved.id);
            let Some((key, policies)) = decode(&saved.data) else {
                removed.push(slot);
                continue;
            };
            if key.0 + KEPT_DAYS <= today {
                removed.push(slot);
                continue;
            }
            if self.owner(&key.1).is_some() {
                removed.push(slot);
                self.send(Taken {
                    day: key.0,
                    domain: key.1,
                    policies,
                });
                continue;
            }
            let full = loaded.len() >= SLOTS;
            match loaded.get_mut(&key) {
                Some(kept) => {
                    for applies in policies {
                        add(&mut kept.policies, applies);
                    }
                    removed.push(slot);
                }
                None if full => {
                    removed.push(slot);
                    self.table.count(|s| s.dropped += 1);
                }
                None => {
                    loaded.insert(
                        key,
                        Owned {
                            slot: Some(slot),
                            policies,
                        },
                    );
                }
            }
        }
        let taken: BTreeSet<Slot> = loaded.values().filter_map(|o| o.slot).collect();
        self.table.saver.attach(restore.records, taken);
        for slot in removed {
            self.table.saver.save(slot, None);
        }
        self.table.owned.borrow_mut().extend(loaded);
        self.table.restored.set(true);
        let waiting = std::mem::take(&mut *self.table.waiting.borrow_mut());
        for taken in waiting {
            self.table.merge(taken);
        }
    }

    pub(crate) fn owned(&self) -> Vec<Taken> {
        self.table
            .owned
            .borrow()
            .iter()
            .map(|((day, domain), owned)| Taken {
                day: *day,
                domain: domain.clone(),
                policies: owned.policies.clone(),
            })
            .collect()
    }

    pub(crate) fn stats(&self) -> OwnerStats {
        OwnerStats {
            owned: self.table.owned.borrow().len() as u64,
            unsaved: self.table.saver.unsaved(),
            ..self.table.stats.get()
        }
    }
}

fn encode((day, domain): &Day, policies: &[Applies]) -> Vec<u8> {
    let mut out = vec![FORMAT];
    out.extend_from_slice(&day.to_le_bytes());
    text(&mut out, domain);
    out.push(u8::try_from(policies.len()).unwrap_or(u8::MAX));
    for applies in policies {
        let (tag, lines, mx): (u8, &[String], &[String]) = match &applies.policy {
            Applied::None => (0, &[], &[]),
            Applied::Sts { lines, mx } => (1, lines, mx),
            Applied::Tlsa { records } => (2, records, &[]),
        };
        out.push(tag);
        texts(&mut out, lines);
        texts(&mut out, mx);
        out.extend_from_slice(&applies.success.to_le_bytes());
        out.extend_from_slice(&applies.failure.to_le_bytes());
        out.push(u8::try_from(applies.details.len()).unwrap_or(u8::MAX));
        for detail in &applies.details {
            out.push(detail.result.code());
            ip(&mut out, Some(detail.sending));
            match &detail.mx {
                Some(mx) => {
                    out.push(1);
                    text(&mut out, mx);
                }
                None => out.push(0),
            }
            ip(&mut out, detail.receiving);
            out.extend_from_slice(&detail.count.to_le_bytes());
        }
    }
    out
}

fn text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn texts(out: &mut Vec<u8>, values: &[String]) {
    out.extend_from_slice(&u16::try_from(values.len()).unwrap_or(0).to_le_bytes());
    for value in values {
        text(out, value);
    }
}

fn ip(out: &mut Vec<u8>, value: Option<IpAddr>) {
    match value {
        None => out.push(0),
        Some(IpAddr::V4(v4)) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let (head, rest) = (self.0.len() >= n).then(|| self.0.split_at(n))?;
        self.0 = rest;
        Some(head)
    }

    fn byte(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(8)?.try_into().ok()?))
    }

    fn text(&mut self) -> Option<String> {
        let len = u32::from_le_bytes(self.bytes(4)?.try_into().ok()?);
        let bytes = self.bytes(usize::try_from(len).ok()?)?;
        String::from_utf8(bytes.to_vec()).ok()
    }

    fn texts(&mut self) -> Option<Vec<String>> {
        let count = u16::from_le_bytes(self.bytes(2)?.try_into().ok()?);
        (0..count).map(|_| self.text()).collect()
    }

    fn ip(&mut self, out: &mut Option<IpAddr>) -> Option<()> {
        *out = match self.byte()? {
            0 => None,
            4 => {
                let octets: [u8; 4] = self.bytes(4)?.try_into().ok()?;
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            6 => {
                let octets: [u8; 16] = self.bytes(16)?.try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => return None,
        };
        Some(())
    }
}

fn decode(data: &[u8]) -> Option<(Day, Vec<Applies>)> {
    let mut at = Cursor(data);
    if at.byte()? != FORMAT {
        return None;
    }
    let day = at.u64()?;
    let domain = at.text()?;
    let count = at.byte()?;
    let mut policies = Vec::new();
    for _ in 0..count {
        let tag = at.byte()?;
        let lines = at.texts()?;
        let mx = at.texts()?;
        let policy = match tag {
            0 => Applied::None,
            1 => Applied::Sts { lines, mx },
            2 => Applied::Tlsa { records: lines },
            _ => return None,
        };
        let success = at.u64()?;
        let failure = at.u64()?;
        let rows = at.byte()?;
        let mut details = Vec::new();
        for _ in 0..rows {
            let result = ResultType::from_code(at.byte()?)?;
            let mut sending = None;
            at.ip(&mut sending)?;
            let sending = sending?;
            let mx = match at.byte()? {
                0 => None,
                1 => Some(at.text()?),
                _ => return None,
            };
            let mut receiving = None;
            at.ip(&mut receiving)?;
            let count = at.u64()?;
            details.push(Detail {
                result,
                sending,
                mx,
                receiving,
                count,
                reason: None,
            });
        }
        policies.push(Applies {
            policy,
            success,
            failure,
            details,
        });
    }
    at.0.is_empty().then_some(((day, domain), policies))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{add, decode, encode};
    use crate::report::{Applied, Applies, Detail, ResultType};
    use crate::results::{DETAILS, POLICIES};

    fn applies(policy: Applied, rows: u32) -> Applies {
        Applies {
            policy,
            success: 3,
            failure: u64::from(rows),
            details: (0..rows)
                .map(|n| Detail {
                    result: ResultType::CertificateExpired,
                    sending: IpAddr::from([10, 0, 0, u8::try_from(n % 250).expect("small")]),
                    mx: (n % 2 == 0).then(|| format!("mx{n}.example")),
                    receiving: (n % 3 == 0)
                        .then(|| IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])),
                    count: 1,
                    reason: None,
                })
                .collect(),
        }
    }

    #[test]
    fn records_round_trip() {
        let policies = vec![
            applies(Applied::None, 2),
            applies(
                Applied::Sts {
                    lines: vec!["version: STSv1".into(), "mode: enforce".into()],
                    mx: vec!["*.example".into()],
                },
                5,
            ),
            applies(
                Applied::Tlsa {
                    records: vec!["3 1 1 ab".into()],
                },
                0,
            ),
        ];
        let key = (20_000, "a.example".to_owned());
        let data = encode(&key, &policies);
        assert_eq!(decode(&data), Some((key, policies)));
        assert_eq!(decode(&data[..data.len() - 1]), None);
        let mut longer = data.clone();
        longer.push(0);
        assert_eq!(decode(&longer), None);
    }

    #[test]
    fn merging_adds_counts_within_bounds() {
        let mut kept = Vec::new();
        assert!(add(&mut kept, applies(Applied::None, 20)));
        assert!(add(&mut kept, applies(Applied::None, 20)));
        assert_eq!((kept[0].success, kept[0].failure), (6, 40));
        assert_eq!(kept[0].details.len(), 20);
        assert_eq!(kept[0].details[0].count, 2);
        assert!(add(&mut kept, applies(Applied::None, 40)));
        assert_eq!(kept[0].details.len(), DETAILS);
        for n in 1..POLICIES {
            let records = vec![n.to_string()];
            assert!(add(&mut kept, applies(Applied::Tlsa { records }, 0)));
        }
        let records = vec!["late".to_owned()];
        assert!(!add(&mut kept, applies(Applied::Tlsa { records }, 0)));
        assert_eq!(kept.len(), POLICIES);
    }
}
