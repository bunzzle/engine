use std::rc::Rc;

use crypto::Secret;
use index::{Entry, Shape};
use store::{IndexRecord, IndexStamp};

use crate::events::{Event, Kind};
use crate::normal::normalize;

pub const KIND_SEARCH: u8 = 4;
pub const SEARCH_SHAPE: Shape = Shape { value: 14 };
pub const SEARCH_VALUE: usize = SEARCH_SHAPE.value as usize;
pub const SEARCH_HASH: usize = 7;
pub const SEARCH_FIELDS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    Recipient,
    Domain,
    Message,
}

impl Field {
    pub fn code(self) -> u8 {
        match self {
            Self::Recipient => 1,
            Self::Domain => 2,
            Self::Message => 3,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Recipient,
            2 => Self::Domain,
            3 => Self::Message,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub back: u8,
    pub time: u64,
    pub kind: Kind,
    pub generation: u32,
}

impl Found {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEARCH_VALUE);
        out.push(self.back);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.push(self.kind.code());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out
    }

    pub fn decode(value: &[u8]) -> Option<Self> {
        if value.len() != SEARCH_VALUE || !(1..=SEARCH_FIELDS).contains(&usize::from(value[0])) {
            return None;
        }
        Some(Self {
            back: value[0],
            time: u64::from_le_bytes(value[1..9].try_into().expect("8")),
            kind: Kind::from_code(value[9])?,
            generation: u32::from_le_bytes(value[10..14].try_into().expect("4")),
        })
    }

    pub fn matches(&self, event: &Event) -> bool {
        (self.time, self.kind, self.generation) == (event.time, event.kind, event.generation)
    }
}

#[derive(Clone, Default)]
pub struct DayKeys(Rc<Vec<(u32, Secret<16>)>>);

impl DayKeys {
    pub fn new(keys: Vec<(u32, Secret<16>)>) -> Self {
        Self(Rc::new(keys))
    }

    pub fn get(&self, day: u32) -> Option<&Secret<16>> {
        self.0.iter().find(|(d, _)| *d == day).map(|(_, key)| key)
    }
}

pub fn value_of(address: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(address) else {
        return address.to_ascii_lowercase();
    };
    normalize(text).map_or_else(
        || text.to_ascii_lowercase().into_bytes(),
        String::into_bytes,
    )
}

pub fn domain_of(normal: &[u8]) -> &[u8] {
    normal
        .iter()
        .rposition(|&b| b == b'@')
        .map_or(&[][..], |at| &normal[at + 1..])
}

pub fn hash(key: &Secret<16>, field: Field, value: &[u8]) -> [u8; SEARCH_HASH] {
    let mut data = Vec::with_capacity(1 + value.len());
    data.push(field.code());
    data.extend_from_slice(value);
    let full = control::siphash(key.expose(), &data).to_be_bytes();
    full[..SEARCH_HASH].try_into().expect("7")
}

pub fn key(tenant: u32, field: Field, hash: &[u8; SEARCH_HASH]) -> index::Key {
    let mut rest = [0u8; 16];
    rest[0] = field.code();
    rest[1..=SEARCH_HASH].copy_from_slice(hash);
    index::key(tenant, rest)
}

pub fn records(
    tenant: u32,
    event: &Event,
    address: &[u8],
    day_key: &Secret<16>,
) -> [IndexRecord; SEARCH_FIELDS] {
    let normal = value_of(address);
    let message = event.message.bytes();
    let fields: [(Field, &[u8]); SEARCH_FIELDS] = [
        (Field::Recipient, &normal),
        (Field::Domain, domain_of(&normal)),
        (Field::Message, &message),
    ];
    let mut back = 0u8;
    fields.map(|(field, value)| {
        back += 1;
        let found = Found {
            back,
            time: event.time,
            kind: event.kind,
            generation: event.generation,
        };
        IndexRecord {
            stamp: IndexStamp::Tail,
            kind: KIND_SEARCH,
            partition: event.partition(),
            entry: Entry::put(
                key(tenant, field, &hash(day_key, field, value)),
                found.encode(),
                Vec::new(),
            ),
        }
    })
}

pub fn sequence(key: &index::Key) -> u64 {
    u64::MAX - u64::from_be_bytes(key[12..20].try_into().expect("8"))
}

pub fn event_key(tenant: u32, key: &index::Key, found: &Found) -> Option<index::Key> {
    let sequence = sequence(key).checked_sub(u64::from(found.back))?;
    let mut rest = [0u8; 16];
    rest[..8].copy_from_slice(&sequence.to_be_bytes());
    Some(index::key(tenant, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requests::DAY;
    use spool::{MessageId, Stamp};

    fn event() -> Event {
        Event {
            generation: 2,
            time: 20_000 * DAY + 5,
            kind: Kind::Delivered,
            lost: 0,
            message: MessageId::from_bytes([7; 16]),
            recipient: 0,
            stamp: Stamp { boot: 1, write: 1 },
            batch: 1,
            day: 20_000,
        }
    }

    #[test]
    fn search_hash_known_answer() {
        let key = Secret::new([1u8; 16]);
        assert_eq!(
            hash(&key, Field::Recipient, b"a@example.com"),
            [0x5e, 0xec, 0x10, 0xad, 0xf3, 0x89, 0xaa]
        );
        let reference: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let message: Vec<u8> = (0..15).collect();
        assert_eq!(
            control::siphash(&reference, &message),
            0xa129_ca61_49be_45e5
        );
    }

    #[test]
    fn records_name_their_event_by_distance() {
        let day_key = Secret::new([1u8; 16]);
        let event = event();
        let records = records(9, &event, b"Bob@Example.COM", &day_key);
        let normal = b"bob@example.com";
        let message = event.message.bytes();
        let expected = [
            (Field::Recipient, &normal[..]),
            (Field::Domain, &b"example.com"[..]),
            (Field::Message, &message[..]),
        ];
        for (n, (record, (field, value))) in records.iter().zip(expected).enumerate() {
            assert_eq!(record.kind, KIND_SEARCH);
            assert_eq!(record.stamp, IndexStamp::Tail);
            assert_eq!(record.partition, 20_000);
            assert_eq!(
                record.entry.key,
                key(9, field, &hash(&day_key, field, value))
            );
            assert_eq!(record.entry.key[12..20], [0; 8]);
            assert_eq!(record.entry.value.len(), SEARCH_VALUE);
            let found = Found::decode(&record.entry.value).expect("value");
            assert_eq!(usize::from(found.back), n + 1);
            assert!(found.matches(&event));
            let stamped = record.clone().stamped(100 + n as u64 + 1);
            assert_eq!(
                event_key(9, &stamped.entry.key, &found).map(|k| crate::events::sequence(&k)),
                Some(100)
            );
        }
    }

    #[test]
    fn values_with_a_zero_distance_or_unknown_type_are_refused() {
        let mut value = Found {
            back: 1,
            time: 3,
            kind: Kind::Failed,
            generation: 4,
        }
        .encode();
        assert!(Found::decode(&value).is_some());
        value[9] = 0;
        assert!(Found::decode(&value).is_none());
        value[9] = 3;
        value[0] = 0;
        assert!(Found::decode(&value).is_none());
        value[0] = 4;
        assert!(Found::decode(&value).is_none());
        value[0] = 3;
        assert!(Found::decode(&value).is_some());
        assert!(Found::decode(&value[1..]).is_none());
    }

    #[test]
    fn hashes_differ_by_field_and_key() {
        let one = Secret::new([1u8; 16]);
        let two = Secret::new([2u8; 16]);
        let a = hash(&one, Field::Domain, b"example.com");
        assert_ne!(a, hash(&one, Field::Recipient, b"example.com"));
        assert_ne!(a, hash(&two, Field::Domain, b"example.com"));
        assert_eq!(a, hash(&one, Field::Domain, b"example.com"));
    }
}
