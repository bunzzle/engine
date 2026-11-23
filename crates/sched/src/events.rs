use index::{Entry, Shape};
use spool::{MessageId, Stamp, WRAP};
use store::{IndexRecord, IndexStamp};

use crate::policy::Answer;
use crate::requests::DAY;

pub const KIND_EVENT: u8 = 3;
pub const EVENT_SHAPE: Shape = Shape { value: 61 };
pub const EVENT_VALUE: usize = EVENT_SHAPE.value as usize;
pub const MAX_REPLY: usize = 1024;
pub const EVENT_DAYS: u32 = keys::EVENT_DAYS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Delivered,
    Deferred,
    Failed,
    Expired,
    Canceled,
    Suppressed,
}

impl Kind {
    pub fn of(answer: Answer) -> Option<Self> {
        match answer {
            Answer::Delivered => Some(Self::Delivered),
            Answer::Failed => Some(Self::Failed),
            Answer::Deferred(_) | Answer::Later(_) => Some(Self::Deferred),
            Answer::Unopened { .. } => None,
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Delivered => 1,
            Self::Deferred => 2,
            Self::Failed => 3,
            Self::Expired => 4,
            Self::Canceled => 5,
            Self::Suppressed => 6,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Delivered,
            2 => Self::Deferred,
            3 => Self::Failed,
            4 => Self::Expired,
            5 => Self::Canceled,
            6 => Self::Suppressed,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub generation: u32,
    pub time: u64,
    pub kind: Kind,
    pub lost: u32,
    pub message: MessageId,
    pub recipient: u32,
    pub stamp: Stamp,
    pub batch: u64,
    pub day: u32,
}

impl Event {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EVENT_VALUE);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.push(self.kind.code());
        out.extend_from_slice(&self.lost.to_le_bytes());
        out.extend_from_slice(&self.message.bytes());
        out.extend_from_slice(&self.recipient.to_le_bytes());
        out.extend_from_slice(&self.stamp.boot.to_le_bytes());
        out.extend_from_slice(&self.stamp.write.to_le_bytes());
        out.extend_from_slice(&self.batch.to_le_bytes());
        out.extend_from_slice(&self.day.to_le_bytes());
        out
    }

    pub fn decode(value: &[u8]) -> Option<Self> {
        if value.len() != EVENT_VALUE {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes(value[at..at + 4].try_into().expect("4"));
        let u64_at = |at: usize| u64::from_le_bytes(value[at..at + 8].try_into().expect("8"));
        Some(Self {
            generation: u32_at(0),
            time: u64_at(4),
            kind: Kind::from_code(value[12])?,
            lost: u32_at(13),
            message: MessageId::from_bytes(value[17..33].try_into().expect("16")),
            recipient: u32_at(33),
            stamp: Stamp {
                boot: u32_at(37),
                write: u64_at(41),
            },
            batch: u64_at(49),
            day: u32_at(57),
        })
    }

    pub fn partition(&self) -> u32 {
        u32::try_from(self.time / DAY).unwrap_or(u32::MAX)
    }

    pub fn checked(&self, body: &Body) -> bool {
        (self.kind, self.time) == (body.kind, body.time)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub record: IndexRecord,
    pub search: Vec<IndexRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub kind: Kind,
    pub time: u64,
    pub address: Vec<u8>,
    pub reply: Vec<u8>,
    pub attempts: u16,
    pub class: u8,
}

impl Body {
    pub fn encode(&self) -> Vec<u8> {
        let address = &self.address[..self.address.len().min(usize::from(u16::MAX))];
        let reply = &self.reply[..self.reply.len().min(MAX_REPLY)];
        let mut out = Vec::with_capacity(16 + address.len() + reply.len());
        out.push(self.kind.code());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.attempts.to_le_bytes());
        out.push(self.class);
        for part in [address, reply] {
            out.extend_from_slice(&u16::try_from(part.len()).expect("capped").to_le_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (head, mut rest) = bytes.split_at_checked(12)?;
        let mut parts = Vec::with_capacity(2);
        for _ in 0..2 {
            let (length, tail) = rest.split_first_chunk::<2>()?;
            let (part, tail) = tail.split_at_checked(usize::from(u16::from_le_bytes(*length)))?;
            parts.push(part.to_vec());
            rest = tail;
        }
        if !rest.is_empty() || parts[1].len() > MAX_REPLY {
            return None;
        }
        let reply = parts.pop().expect("two parts");
        let address = parts.pop().expect("two parts");
        Some(Self {
            kind: Kind::from_code(head[0])?,
            time: u64::from_le_bytes(head[1..9].try_into().expect("8")),
            address,
            reply,
            attempts: u16::from_le_bytes([head[9], head[10]]),
            class: head[11],
        })
    }
}

pub fn record(tenant: u32, event: &Event, wrap: &[u8; WRAP], sealed: &[u8]) -> Option<IndexRecord> {
    let mut payload = Vec::with_capacity(WRAP + sealed.len());
    payload.extend_from_slice(wrap);
    payload.extend_from_slice(sealed);
    if payload.len() > index::MAX_PAYLOAD {
        return None;
    }
    Some(IndexRecord {
        stamp: IndexStamp::Head,
        kind: KIND_EVENT,
        partition: event.partition(),
        entry: Entry::put(index::key(tenant, [0; 16]), event.encode(), payload),
    })
}

pub(crate) fn add_lost(record: &mut IndexRecord, lost: u32) -> bool {
    let Some(event) = Event::decode(&record.entry.value) else {
        return false;
    };
    if lost == 0 {
        return false;
    }
    let lost = event.lost.saturating_add(lost);
    record.entry.value = Event { lost, ..event }.encode();
    true
}

pub fn retain(table: &control::Table, entry: &Entry) -> bool {
    if entry.op == index::Op::Delete {
        return true;
    }
    let Some(event) = Event::decode(&entry.value) else {
        return true;
    };
    !table.gone(index::tenant(&entry.key), event.generation)
}

pub fn retired(today: u32) -> u32 {
    today.saturating_sub(EVENT_DAYS - 1)
}

pub fn sealed(payload: &[u8]) -> Option<(&[u8; WRAP], &[u8])> {
    payload.split_first_chunk::<WRAP>()
}

pub fn sequence(key: &[u8; index::KEY]) -> u64 {
    u64::from_be_bytes(key[4..12].try_into().expect("8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_counts_add_to_the_value_only() {
        let event = Event {
            generation: 1,
            time: 2,
            kind: Kind::Deferred,
            lost: 3,
            message: MessageId::from_bytes([1; 16]),
            recipient: 0,
            stamp: Stamp { boot: 1, write: 1 },
            batch: 4,
            day: 5,
        };
        let mut record = record(9, &event, &[0; WRAP], b"sealed").expect("record");
        let payload = record.entry.payload.clone();
        assert!(!add_lost(&mut record, 0));
        assert!(add_lost(&mut record, 4));
        assert_eq!(Event::decode(&record.entry.value).map(|e| e.lost), Some(7));
        assert_eq!(record.entry.payload, payload);
        record.entry.value.pop();
        assert!(!add_lost(&mut record, 1));
    }
}
