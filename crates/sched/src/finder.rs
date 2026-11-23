use index::Op;
use store::{Budget, Changes};

use crate::events::{Event, KIND_EVENT, Kind};
use crate::reader::{PAGE_BYTES, ReadError, kept};
use crate::requests::DAY;
use crate::search::{self, Field, Found, KIND_SEARCH, SEARCH_HASH, domain_of, value_of};

pub const SEARCH_LIMIT: usize = 100;
pub const SEARCH_DAYS: u64 = 8;
const SCAN_ENTRIES: usize = 1024;
const SCAN_BLOCKS: usize = 256;
const HIT_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    field: Field,
    value: Vec<u8>,
    kinds: u8,
    from: u64,
    to: u64,
}

impl Query {
    pub fn new(field: Field, raw: &[u8], kinds: &[Kind], from: u64, to: u64) -> Option<Self> {
        let value = match field {
            Field::Recipient => value_of(raw),
            Field::Domain => {
                let mut address = b"x@".to_vec();
                address.extend_from_slice(raw);
                domain_of(&value_of(&address)).to_vec()
            }
            Field::Message if raw.len() == 16 => raw.to_vec(),
            Field::Message => return None,
        };
        let days = to.checked_sub(1)? / DAY + 1 - from / DAY;
        if value.is_empty() || value.len() > 512 || from >= to || days > SEARCH_DAYS {
            return None;
        }
        let kinds = if kinds.is_empty() {
            u8::MAX
        } else {
            kinds.iter().fold(0, |mask, kind| mask | bit(*kind))
        };
        Some(Self {
            field,
            value,
            kinds,
            from,
            to,
        })
    }

    pub fn field(&self) -> Field {
        self.field
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub(crate) fn days(&self) -> impl Iterator<Item = u32> {
        let first = u32::try_from(self.from / DAY).unwrap_or(u32::MAX);
        let last = u32::try_from((self.to - 1) / DAY).unwrap_or(u32::MAX);
        first..=last
    }

    pub(crate) fn shard(&self) -> Option<u16> {
        (self.field == Field::Message).then(|| u16::from_le_bytes([self.value[4], self.value[5]]))
    }

    pub(crate) fn label(&self, out: &mut Vec<u8>) {
        out.push(self.field.code());
        out.push(self.kinds);
        out.extend_from_slice(&self.from.to_le_bytes());
        out.extend_from_slice(&self.to.to_le_bytes());
        out.extend_from_slice(&u16::try_from(self.value.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&self.value);
    }

    pub(crate) fn wants(&self, found: &Found) -> bool {
        (self.from..self.to).contains(&found.time) && self.kinds & bit(found.kind) != 0
    }

    pub(crate) fn verified(&self, event: &Event, address: &[u8]) -> bool {
        match self.field {
            Field::Recipient => value_of(address) == self.value,
            Field::Domain => domain_of(&value_of(address)) == self.value.as_slice(),
            Field::Message => event.message.bytes() == self.value.as_slice(),
        }
    }
}

fn bit(kind: Kind) -> u8 {
    1 << kind.code()
}

#[derive(Clone, Debug)]
pub(crate) struct Scan {
    pub tenant: u32,
    pub generation: u32,
    pub query: Query,
    pub hashes: Vec<(u32, [u8; SEARCH_HASH])>,
    pub after: u64,
    pub limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Hit {
    pub shard: u16,
    pub tail: u64,
    pub event: Event,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Hits {
    pub found: Vec<Hit>,
    pub scanned: u64,
    pub full: bool,
}

pub(crate) fn tail(key: &index::Key) -> u64 {
    u64::from_be_bytes(key[12..20].try_into().expect("8"))
}

fn at(mut key: index::Key, tail: u64) -> index::Key {
    key[12..20].copy_from_slice(&tail.to_be_bytes());
    key
}

pub(crate) async fn serve(changes: &Changes, scan: &Scan) -> Result<Hits, ReadError> {
    let parts = scan
        .hashes
        .iter()
        .map(|(day, hash)| {
            let base = search::key(scan.tenant, scan.query.field, hash);
            (*day, at(base, scan.after)..at(base, u64::MAX))
        })
        .collect();
    let budget = Budget {
        entries: SCAN_ENTRIES,
        blocks: SCAN_BLOCKS,
    };
    let tails = changes
        .scan_parts(KIND_SEARCH, parts, budget)
        .await
        .map_err(|_| ReadError::Failed)?;
    let mut full = tails.more;
    let mut scanned = scan.after;
    let mut wanted: Vec<(u16, u64, u32, index::Key, Found)> = Vec::new();
    for (shard, part, entry) in tails.entries {
        let tail = tail(&entry.key);
        if wanted.len() >= scan.limit {
            full = true;
            break;
        }
        scanned = tail.saturating_add(1);
        if entry.op != Op::Put {
            continue;
        }
        let Some(found) = Found::decode(&entry.value) else {
            continue;
        };
        if found.generation != scan.generation || !scan.query.wants(&found) {
            continue;
        }
        let Some(key) = search::event_key(scan.tenant, &entry.key, &found) else {
            continue;
        };
        wanted.push((shard, tail, scan.hashes[part].0, key, found));
    }
    let mut events = vec![None; wanted.len()];
    let mut days: Vec<u32> = wanted.iter().map(|w| w.2).collect();
    days.sort_unstable();
    days.dedup();
    for day in days {
        let (at, keys): (Vec<usize>, Vec<(u16, index::Key)>) = wanted
            .iter()
            .enumerate()
            .filter(|(_, w)| w.2 == day)
            .map(|(n, w)| (n, (w.0, w.3)))
            .unzip();
        let fetched = changes
            .fetch((KIND_EVENT, day), keys)
            .await
            .map_err(|_| ReadError::Failed)?;
        for (n, entry) in at.into_iter().zip(fetched) {
            events[n] = entry;
        }
    }
    let mut hits = Vec::with_capacity(wanted.len());
    let mut bytes = 0usize;
    for ((shard, tail, _, _, found), entry) in wanted.into_iter().zip(events) {
        let Some(entry) = entry else {
            continue;
        };
        let Some(event) = kept(&entry, scan.generation).filter(|e| found.matches(e)) else {
            continue;
        };
        let size = entry.payload.len() + HIT_BYTES;
        if !hits.is_empty() && bytes + size > PAGE_BYTES {
            full = true;
            scanned = tail;
            break;
        }
        bytes += size;
        hits.push(Hit {
            shard,
            tail,
            event,
            payload: entry.payload,
        });
    }
    Ok(Hits {
        found: hits,
        scanned,
        full,
    })
}

pub(crate) fn merge(
    parts: Vec<Option<Hits>>,
    positions: &[u64],
    limit: usize,
) -> (Vec<Hit>, Vec<u64>, bool) {
    let mut next = positions.to_vec();
    let mut heads: Vec<_> = parts
        .into_iter()
        .map(|part| part.map(|p| (p.found.into_iter().peekable(), p.scanned, p.full)))
        .collect();
    let mut taken = Vec::new();
    let mut bytes = 0usize;
    loop {
        let pick = heads
            .iter_mut()
            .enumerate()
            .filter_map(|(core, head)| {
                let hit = head.as_mut()?.0.peek()?;
                Some(((std::cmp::Reverse(hit.event.time), core, hit.tail), core))
            })
            .min()
            .map(|(_, core)| core);
        let Some(core) = pick else {
            break;
        };
        let hits = &mut heads[core].as_mut().expect("picked").0;
        let size = hits.peek().map_or(0, |hit| hit.payload.len() + HIT_BYTES);
        if taken.len() >= limit || (!taken.is_empty() && bytes + size > PAGE_BYTES) {
            break;
        }
        let hit = hits.next().expect("peeked");
        bytes += size;
        next[core] = hit.tail.saturating_add(1);
        taken.push(hit);
    }
    let mut more = false;
    for (core, head) in heads.iter_mut().enumerate() {
        let Some((hits, scanned, full)) = head else {
            continue;
        };
        if hits.peek().is_none() {
            next[core] = next[core].max(*scanned);
            more |= *full;
        } else {
            more = true;
        }
    }
    (taken, next, more)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spool::{MessageId, Stamp};

    fn event(time: u64) -> Event {
        Event {
            generation: 1,
            time,
            kind: Kind::Delivered,
            lost: 0,
            message: MessageId::from_bytes([1; 16]),
            recipient: 0,
            stamp: Stamp { boot: 1, write: 1 },
            batch: 1,
            day: 1,
        }
    }

    fn part(entries: &[(u64, u64)], scanned: u64, full: bool) -> Hits {
        Hits {
            found: entries
                .iter()
                .map(|&(tail, time)| Hit {
                    shard: 0,
                    tail,
                    event: event(time),
                    payload: Vec::new(),
                })
                .collect(),
            scanned,
            full,
        }
    }

    #[test]
    fn merges_take_newest_first_and_keep_each_core_a_prefix() {
        let parts = vec![
            Some(part(&[(5, 30), (9, 10)], 12, false)),
            Some(part(&[(7, 20)], 8, false)),
        ];
        let (taken, next, more) = merge(parts, &[1, 2], 2);
        let order: Vec<u64> = taken.iter().map(|h| h.tail).collect();
        assert_eq!(order, [5, 7]);
        assert_eq!(next, [6, 8]);
        assert!(more);
        let parts = vec![Some(part(&[], 40, false)), Some(part(&[(8, 1)], 9, true))];
        let (taken, next, more) = merge(parts, &[3, 4], 10);
        assert_eq!(taken.len(), 1);
        assert_eq!(next, [40, 9]);
        assert!(more);
    }

    #[test]
    fn cores_not_asked_keep_their_position() {
        let parts = vec![None, Some(part(&[(4, 1)], 5, false)), None];
        let (taken, next, more) = merge(parts, &[7, 0, 9], 10);
        assert_eq!(taken.len(), 1);
        assert_eq!(next, [7, 5, 9]);
        assert!(!more);
    }

    #[test]
    fn queries_normalize_and_bound_their_range() {
        let query = Query::new(Field::Recipient, b"Bob@Example.COM", &[], 0, DAY).expect("query");
        assert_eq!(query.value(), b"bob@example.com");
        assert_eq!(query.days().collect::<Vec<_>>(), [0]);
        let query = Query::new(Field::Domain, b"Example.COM", &[], DAY - 1, DAY + 1).expect("q");
        assert_eq!(query.value(), b"example.com");
        assert_eq!(query.days().collect::<Vec<_>>(), [0, 1]);
        assert!(Query::new(Field::Recipient, b"a@b.c", &[], 0, 8 * DAY).is_some());
        assert!(Query::new(Field::Recipient, b"a@b.c", &[], 0, 8 * DAY + 1).is_none());
        assert!(Query::new(Field::Recipient, b"a@b.c", &[], 5, 5).is_none());
        assert!(Query::new(Field::Recipient, b"", &[], 0, 5).is_none());
        assert!(Query::new(Field::Message, &[0; 15], &[], 0, 5).is_none());
        let id = MessageId::from_bytes([3; 16]);
        let query = Query::new(Field::Message, &id.bytes(), &[], 0, 5).expect("message");
        assert_eq!(query.shard(), Some(id.shard));
    }

    #[test]
    fn queries_filter_by_type_and_time_and_verify_the_opened_address() {
        let query =
            Query::new(Field::Domain, b"example.com", &[Kind::Failed], 10, 20).expect("query");
        let found = |time, kind| Found {
            back: 1,
            time,
            kind,
            generation: 1,
        };
        assert!(query.wants(&found(10, Kind::Failed)));
        assert!(!query.wants(&found(20, Kind::Failed)));
        assert!(!query.wants(&found(15, Kind::Delivered)));
        assert!(query.verified(&event(1), b"Bob@EXAMPLE.com"));
        assert!(!query.verified(&event(1), b"bob@example.org"));
        let all = Query::new(Field::Domain, b"example.com", &[], 10, 20).expect("query");
        assert!(all.wants(&found(15, Kind::Suppressed)));
    }

    #[test]
    fn tails_round_trip_through_keys() {
        let base = search::key(3, Field::Recipient, &[9; SEARCH_HASH]);
        assert_eq!(tail(&at(base, 77)), 77);
        assert_eq!(at(base, 77)[..12], base[..12]);
    }
}
