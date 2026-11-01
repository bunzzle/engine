use std::collections::BTreeMap;

use crate::entry::{Entry, Key, Shape};
use crate::error::Error;

pub const OVERHEAD: usize = 56;

pub struct Memtable {
    shape: Shape,
    map: BTreeMap<Key, Entry>,
    bytes: usize,
}

impl Memtable {
    pub fn new(shape: Shape) -> Self {
        Self {
            shape,
            map: BTreeMap::new(),
            bytes: 0,
        }
    }

    pub fn shape(&self) -> Shape {
        self.shape
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn get(&self, key: &Key) -> Option<&Entry> {
        self.map.get(key)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.map.values()
    }

    pub fn put(&mut self, entry: Entry) -> Result<(), Error> {
        self.shape.check(&entry)?;
        self.bytes += self.size(&entry);
        if let Some(old) = self.map.insert(entry.key, entry) {
            self.bytes -= self.size(&old);
        }
        Ok(())
    }

    pub fn take(&mut self) -> Vec<Entry> {
        self.bytes = 0;
        std::mem::take(&mut self.map).into_values().collect()
    }

    pub fn restore(&mut self, older: Vec<Entry>) {
        for entry in older {
            if !self.map.contains_key(&entry.key) {
                self.bytes += self.size(&entry);
                self.map.insert(entry.key, entry);
            }
        }
    }

    fn size(&self, entry: &Entry) -> usize {
        self.shape.entry() + entry.payload.len() + OVERHEAD
    }
}
