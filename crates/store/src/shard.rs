use std::collections::BTreeMap;

use crate::committer::Location;
use crate::layout::{Fields, FieldsMut};
use crate::run::Run;

pub const INDEX_SIZE: usize = 72;
pub const KIND_STATE: u8 = 4;
pub const HEAD_ITEM: u32 = 0;

const OP: usize = 0;
const STATUS: usize = 1;
const ATTEMPTS: usize = 2;
const TENANT: usize = 4;
const MESSAGE: usize = 8;
const DUE: usize = 16;
const ITEM: usize = 24;
const CLEAR: usize = 28;
const OLD_REGION: usize = 32;
const OLD_SIZE: usize = 36;
const OLD_EPOCH: usize = 40;
const OLD_OFFSET: usize = 48;
const OLD_SEQUENCE: usize = 56;
const RESERVED: usize = 64;

const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;
const OP_MOVE: u8 = 3;
const OP_DROP: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub message: u64,
    pub item: u32,
}

impl Key {
    pub const fn new(message: u64, item: u32) -> Self {
        Self { message, item }
    }

    pub const fn head(message: u64) -> Self {
        Self::new(message, HEAD_ITEM)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub status: u8,
    pub attempts: u16,
    pub due: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Put(Delivery),
    Delete,
    Move { old: Location },
    Drop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Index {
    pub key: Key,
    pub tenant: u32,
    pub change: Change,
}

impl Index {
    fn encode(&self, clear: usize, out: &mut [u8]) {
        let out = &mut out[..INDEX_SIZE];
        out.fill(0);
        let mut fields = FieldsMut::new(out);
        fields.put_u32(TENANT, self.tenant);
        fields.put_u64(MESSAGE, self.key.message);
        fields.put_u32(ITEM, self.key.item);
        fields.put_u32(CLEAR, u32::try_from(clear).expect("clear part fits in u32"));
        match self.change {
            Change::Put(delivery) => {
                fields.put_u8(OP, OP_PUT);
                fields.put_u8(STATUS, delivery.status);
                fields.put_u16(ATTEMPTS, delivery.attempts);
                fields.put_u64(DUE, delivery.due);
            }
            Change::Delete => fields.put_u8(OP, OP_DELETE),
            Change::Move { old } => {
                fields.put_u8(OP, OP_MOVE);
                fields.put_u32(OLD_REGION, old.region);
                fields.put_u32(OLD_SIZE, old.size);
                fields.put_u64(OLD_EPOCH, old.epoch);
                fields.put_u64(OLD_OFFSET, old.offset);
                fields.put_u64(OLD_SEQUENCE, old.sequence);
            }
            Change::Drop => fields.put_u8(OP, OP_DROP),
        }
    }

    pub fn decode(payload: &[u8]) -> Option<Self> {
        Self::parts(payload).map(|(index, _, _)| index)
    }

    pub fn parts(payload: &[u8]) -> Option<(Self, &[u8], &[u8])> {
        let bytes = payload.get(..INDEX_SIZE)?;
        let fields = Fields::new(bytes);
        if fields.u64(RESERVED) != 0 {
            return None;
        }
        let change = match fields.u8(OP) {
            OP_PUT => Change::Put(Delivery {
                status: fields.u8(STATUS),
                attempts: fields.u16(ATTEMPTS),
                due: fields.u64(DUE),
            }),
            OP_DELETE => Change::Delete,
            OP_MOVE => Change::Move {
                old: Location {
                    region: fields.u32(OLD_REGION),
                    epoch: fields.u64(OLD_EPOCH),
                    offset: fields.u64(OLD_OFFSET),
                    sequence: fields.u64(OLD_SEQUENCE),
                    size: fields.u32(OLD_SIZE),
                },
            },
            OP_DROP => Change::Drop,
            _ => return None,
        };
        let rest = &payload[INDEX_SIZE..];
        let clear = usize::try_from(fields.u32(CLEAR)).ok()?;
        if clear > rest.len() {
            return None;
        }
        let index = Self {
            key: Key::new(fields.u64(MESSAGE), fields.u32(ITEM)),
            tenant: fields.u32(TENANT),
            change,
        };
        let (clear, sealed) = rest.split_at(clear);
        Some((index, clear, sealed))
    }

    pub fn payload(&self, sealed: &[u8]) -> Vec<u8> {
        self.record(&[], sealed)
    }

    pub fn record(&self, clear: &[u8], sealed: &[u8]) -> Vec<u8> {
        let mut out = vec![0; INDEX_SIZE + clear.len() + sealed.len()];
        self.encode(clear.len(), &mut out);
        out[INDEX_SIZE..INDEX_SIZE + clear.len()].copy_from_slice(clear);
        out[INDEX_SIZE + clear.len()..].copy_from_slice(sealed);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub tenant: u32,
    pub delivery: Delivery,
    pub location: Location,
    pub clear: Box<[u8]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delta {
    pub changes: BTreeMap<Key, Option<Item>>,
    pub covered: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardState {
    entries: BTreeMap<Key, Item>,
    delta: BTreeMap<Key, Option<Item>>,
    covered: u64,
}

impl ShardState {
    pub fn apply(&mut self, index: &Index, clear: &[u8], location: Location, commit: u64) {
        self.covered = self.covered.max(commit);
        match index.change {
            Change::Put(delivery) => {
                let entry = Item {
                    tenant: index.tenant,
                    delivery,
                    location,
                    clear: clear.into(),
                };
                self.delta.insert(index.key, Some(entry.clone()));
                self.entries.insert(index.key, entry);
            }
            Change::Delete => {
                self.entries.remove(&index.key);
                self.delta.insert(index.key, None);
            }
            Change::Move { old } => {
                if let Some(entry) = self.entries.get_mut(&index.key)
                    && entry.location == old
                {
                    entry.location = location;
                    entry.clear = clear.into();
                    self.delta.insert(index.key, Some(entry.clone()));
                }
            }
            Change::Drop => {
                let keys: Vec<Key> = self.message(index.key.message).map(|(&k, _)| k).collect();
                for key in keys {
                    self.entries.remove(&key);
                    self.delta.insert(key, None);
                }
            }
        }
    }

    pub fn message(&self, message: u64) -> impl Iterator<Item = (&Key, &Item)> {
        self.entries
            .range(Key::new(message, 0)..=Key::new(message, u32::MAX))
    }

    pub fn load_run(&mut self, run: Run) {
        if run.base {
            self.entries.clear();
        }
        for (key, item) in run.changes {
            match item {
                Some(item) => self.entries.insert(key, item),
                None => self.entries.remove(&key),
            };
        }
        self.covered = self.covered.max(run.covered);
    }

    pub fn freeze(&mut self, covered: u64) -> Delta {
        self.covered = self.covered.max(covered);
        Delta {
            changes: std::mem::take(&mut self.delta),
            covered: self.covered,
        }
    }

    pub fn restore(&mut self, delta: Delta) {
        let mut newer = std::mem::replace(&mut self.delta, delta.changes);
        self.delta.append(&mut newer);
    }

    pub fn get(&self, key: Key) -> Option<&Item> {
        self.entries.get(&key)
    }

    pub fn entries(&self) -> &BTreeMap<Key, Item> {
        &self.entries
    }

    pub fn covered(&self) -> u64 {
        self.covered
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
