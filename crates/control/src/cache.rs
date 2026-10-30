use std::collections::BTreeMap;
use std::ops::Bound;

use crate::queue::Name;

struct Slot {
    name: Name,
    id: u32,
    used: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evicted: u64,
}

pub struct Cache {
    capacity: usize,
    slots: Vec<Option<Slot>>,
    index: BTreeMap<Name, usize>,
    free: Vec<usize>,
    hand: usize,
    stats: CacheStats,
}

impl Cache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            slots: Vec::new(),
            index: BTreeMap::new(),
            free: Vec::new(),
            hand: 0,
            stats: CacheStats::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn stats(&self) -> CacheStats {
        self.stats
    }

    pub fn get(&mut self, name: &Name) -> Option<u32> {
        let found = self.index.get(name).and_then(|&at| self.slots[at].as_mut());
        if let Some(slot) = found {
            slot.used = true;
            self.stats.hits += 1;
            Some(slot.id)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    pub fn put(&mut self, name: Name, id: u32) {
        if let Some(&at) = self.index.get(&name) {
            if let Some(slot) = self.slots[at].as_mut() {
                slot.id = id;
            }
            return;
        }
        let at = if let Some(at) = self.free.pop() {
            at
        } else if self.slots.len() < self.capacity {
            self.slots.push(None);
            self.slots.len() - 1
        } else {
            self.evict()
        };
        self.index.insert(name.clone(), at);
        self.slots[at] = Some(Slot {
            name,
            id,
            used: false,
        });
    }

    pub fn forget(&mut self, tenant: u32, domain: &str) -> usize {
        let low = Name {
            tenant,
            domain: domain.into(),
            generation: 0,
            pool: 0,
        };
        let high = Name {
            generation: u32::MAX,
            pool: u32::MAX,
            ..low.clone()
        };
        let found: Vec<(Name, usize)> = self
            .index
            .range((Bound::Included(low), Bound::Included(high)))
            .map(|(name, &at)| (name.clone(), at))
            .collect();
        for (name, at) in &found {
            self.index.remove(name);
            self.slots[*at] = None;
            self.free.push(*at);
        }
        found.len()
    }

    fn evict(&mut self) -> usize {
        loop {
            let at = self.hand;
            self.hand = (self.hand + 1) % self.slots.len();
            match self.slots[at].as_mut() {
                Some(slot) if slot.used => slot.used = false,
                Some(_) => {
                    let slot = self.slots[at].take().expect("slot present");
                    self.index.remove(&slot.name);
                    self.stats.evicted += 1;
                    return at;
                }
                None => return at,
            }
        }
    }
}
