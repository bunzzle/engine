use std::collections::BTreeMap;

use crate::committer::Location;
use crate::layout::{Fields, FieldsMut};
use crate::run::Run;

pub const INDEX_SIZE: usize = 64;
pub const KIND_STATE: u8 = 4;

const OP: usize = 0;
const STATUS: usize = 1;
const ATTEMPTS: usize = 2;
const TENANT: usize = 4;
const KEY: usize = 8;
const DUE: usize = 16;
const OLD_REGION: usize = 24;
const OLD_SIZE: usize = 28;
const OLD_EPOCH: usize = 32;
const OLD_OFFSET: usize = 40;
const OLD_SEQUENCE: usize = 48;
const RESERVED: usize = 56;

const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;
const OP_MOVE: u8 = 3;

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Index {
    pub key: u64,
    pub tenant: u32,
    pub change: Change,
}

impl Index {
    pub fn encode(&self, out: &mut [u8]) {
        let out = &mut out[..INDEX_SIZE];
        out.fill(0);
        let mut fields = FieldsMut::new(out);
        fields.put_u32(TENANT, self.tenant);
        fields.put_u64(KEY, self.key);
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
        }
    }

    pub fn decode(payload: &[u8]) -> Option<Self> {
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
            _ => return None,
        };
        Some(Self {
            key: fields.u64(KEY),
            tenant: fields.u32(TENANT),
            change,
        })
    }

    pub fn payload(&self, sealed: &[u8]) -> Vec<u8> {
        let mut out = vec![0; INDEX_SIZE + sealed.len()];
        self.encode(&mut out);
        out[INDEX_SIZE..].copy_from_slice(sealed);
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub tenant: u32,
    pub delivery: Delivery,
    pub location: Location,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delta {
    pub changes: BTreeMap<u64, Option<Item>>,
    pub covered: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardState {
    entries: BTreeMap<u64, Item>,
    delta: BTreeMap<u64, Option<Item>>,
    covered: u64,
}

impl ShardState {
    pub fn apply(&mut self, index: &Index, location: Location, commit: u64) {
        self.covered = self.covered.max(commit);
        match index.change {
            Change::Put(delivery) => {
                let entry = Item {
                    tenant: index.tenant,
                    delivery,
                    location,
                };
                self.entries.insert(index.key, entry);
                self.delta.insert(index.key, Some(entry));
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
                    self.delta.insert(index.key, Some(*entry));
                }
            }
        }
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

    pub fn get(&self, key: u64) -> Option<&Item> {
        self.entries.get(&key)
    }

    pub fn entries(&self) -> &BTreeMap<u64, Item> {
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
