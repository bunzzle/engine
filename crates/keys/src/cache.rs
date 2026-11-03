use std::collections::HashMap;
use std::hash::Hash;

struct Slot<K, V> {
    key: K,
    value: V,
    used: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evicted: u64,
}

pub struct Cache<K, V> {
    capacity: usize,
    slots: Vec<Option<Slot<K, V>>>,
    index: HashMap<K, usize>,
    free: Vec<usize>,
    hand: usize,
    stats: CacheStats,
}

impl<K: Copy + Eq + Hash, V: Clone> Cache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            slots: Vec::new(),
            index: HashMap::new(),
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

    pub fn get(&mut self, key: &K) -> Option<V> {
        let found = self.index.get(key).and_then(|&at| self.slots[at].as_mut());
        if let Some(slot) = found {
            slot.used = true;
            self.stats.hits += 1;
            Some(slot.value.clone())
        } else {
            self.stats.misses += 1;
            None
        }
    }

    pub fn peek(&self, key: &K) -> Option<&V> {
        let at = *self.index.get(key)?;
        self.slots[at].as_ref().map(|slot| &slot.value)
    }

    pub fn put(&mut self, key: K, value: V) {
        if let Some(&at) = self.index.get(&key) {
            if let Some(slot) = self.slots[at].as_mut() {
                slot.value = value;
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
        self.index.insert(key, at);
        self.slots[at] = Some(Slot {
            key,
            value,
            used: false,
        });
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let at = self.index.remove(key)?;
        let slot = self.slots[at].take()?;
        self.free.push(at);
        Some(slot.value)
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        for at in 0..self.slots.len() {
            let drop = self.slots[at]
                .as_ref()
                .is_some_and(|slot| !keep(&slot.key, &slot.value));
            if drop {
                let slot = self.slots[at].take().expect("slot present");
                self.index.remove(&slot.key);
                self.free.push(at);
            }
        }
    }

    pub fn clear(&mut self) {
        self.slots.clear();
        self.index.clear();
        self.free.clear();
        self.hand = 0;
    }

    fn evict(&mut self) -> usize {
        loop {
            let at = self.hand;
            self.hand = (self.hand + 1) % self.slots.len();
            match self.slots[at].as_mut() {
                Some(slot) if slot.used => slot.used = false,
                Some(_) => {
                    let slot = self.slots[at].take().expect("slot present");
                    self.index.remove(&slot.key);
                    self.stats.evicted += 1;
                    return at;
                }
                None => return at,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cache;

    #[test]
    fn keeps_used_entries_and_evicts_the_others() {
        let mut cache = Cache::new(3);
        for n in 0..3u32 {
            cache.put(n, n * 10);
        }
        assert_eq!(cache.get(&0), Some(0));
        assert_eq!(cache.get(&2), Some(20));
        cache.put(3, 30);
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&0), Some(0));
        assert_eq!(cache.get(&3), Some(30));
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.stats().evicted, 1);
        assert_eq!(cache.remove(&0), Some(0));
        cache.put(4, 40);
        assert_eq!(cache.len(), 3);
        cache.retain(|&key, _| key != 4);
        assert_eq!(cache.get(&4), None);
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }
}
