use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use crypto::{BatchKey, Secret, WRAP, seal_batch};
use rt::Instant;

use crate::Working;
use crate::cache::{Cache, CacheStats};

const SWEEP: Duration = Duration::from_secs(1);

pub struct Batch {
    pub id: u64,
    pub tenant: u32,
    pub generation: u32,
    pub day: u32,
    pub shard: u16,
    pub wrap: [u8; WRAP],
    pub key: Rc<BatchKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchSettings {
    pub seals: u32,
    pub age: Duration,
    pub cache: usize,
}

impl Default for BatchSettings {
    fn default() -> Self {
        Self {
            seals: 1_024,
            age: Duration::from_secs(60),
            cache: 65_536,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatchStats {
    pub created: u64,
    pub full: u64,
    pub aged: u64,
    pub day: u64,
    pub mismatched: u64,
    pub cache: CacheStats,
}

struct Opened {
    batch: Rc<Batch>,
    seals: u32,
    since: Instant,
}

#[derive(Clone)]
struct Cached {
    tenant: u32,
    generation: u32,
    key: Rc<BatchKey>,
}

pub struct Batches {
    settings: BatchSettings,
    next_sweep: Option<Instant>,
    open: HashMap<(u32, u32, u16), Opened>,
    cache: Cache<(u16, u64), Cached>,
    stats: BatchStats,
}

impl Batches {
    pub fn new(settings: BatchSettings) -> Self {
        Self {
            settings,
            next_sweep: None,
            open: HashMap::new(),
            cache: Cache::new(settings.cache),
            stats: BatchStats::default(),
        }
    }

    pub fn stats(&self) -> BatchStats {
        BatchStats {
            cache: self.cache.stats(),
            ..self.stats
        }
    }

    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    pub fn seal(
        &mut self,
        working: &Working,
        shard: u16,
        first: u64,
        now: Instant,
    ) -> Result<Rc<Batch>, crypto::Error> {
        if self.next_sweep.is_none_or(|next| now >= next) {
            self.sweep(now);
        }
        let (tenant, generation) = (working.keys.tenant(), working.keys.generation());
        let slot = (tenant, generation, shard);
        if let Some(opened) = self.open.get_mut(&slot) {
            if now.saturating_duration_since(opened.since) >= self.settings.age {
                self.stats.aged += 1;
            } else if opened.batch.day != working.day {
                self.stats.day += 1;
            } else if opened.seals >= self.settings.seals {
                self.stats.full += 1;
            } else {
                opened.seals += 1;
                return Ok(Rc::clone(&opened.batch));
            }
        }
        let secret = Secret::<32>::random()?;
        let wrap = seal_batch(
            &working.today,
            tenant,
            generation,
            working.day,
            shard,
            first,
            &secret,
        )?;
        let batch = Rc::new(Batch {
            id: first,
            tenant,
            generation,
            day: working.day,
            shard,
            wrap: wrap.encode(),
            key: Rc::new(BatchKey::new(&secret)),
        });
        self.remember(tenant, generation, shard, first, Rc::clone(&batch.key));
        self.open.insert(
            slot,
            Opened {
                batch: Rc::clone(&batch),
                seals: 1,
                since: now,
            },
        );
        self.stats.created += 1;
        Ok(batch)
    }

    pub fn cached(
        &mut self,
        tenant: u32,
        generation: u32,
        shard: u16,
        id: u64,
    ) -> Option<Rc<BatchKey>> {
        if let Some(opened) = self.open.get(&(tenant, generation, shard))
            && opened.batch.id == id
        {
            return Some(Rc::clone(&opened.batch.key));
        }
        let found = self.cache.get(&(shard, id))?;
        if (found.tenant, found.generation) == (tenant, generation) {
            Some(found.key)
        } else {
            self.stats.mismatched += 1;
            None
        }
    }

    pub fn remember(
        &mut self,
        tenant: u32,
        generation: u32,
        shard: u16,
        id: u64,
        key: Rc<BatchKey>,
    ) {
        if let Some(held) = self.cache.peek(&(shard, id))
            && (held.tenant, held.generation) != (tenant, generation)
        {
            self.stats.mismatched += 1;
            return;
        }
        self.cache.put(
            (shard, id),
            Cached {
                tenant,
                generation,
                key,
            },
        );
    }

    pub fn sweep(&mut self, now: Instant) {
        self.next_sweep = Some(now + SWEEP);
        let age = self.settings.age;
        let mut closed = Vec::new();
        self.open.retain(|_, opened| {
            let young = now.saturating_duration_since(opened.since) < age;
            if !young {
                closed.push(Rc::clone(&opened.batch));
            }
            young
        });
        self.stats.aged += closed.len() as u64;
        for batch in closed {
            self.remember(
                batch.tenant,
                batch.generation,
                batch.shard,
                batch.id,
                Rc::clone(&batch.key),
            );
        }
    }

    pub fn forget(&mut self, tenant: u32, generation: u32) {
        self.open
            .retain(|&(t, g, _), _| (t, g) != (tenant, generation));
        self.cache
            .retain(|_, cached| (cached.tenant, cached.generation) != (tenant, generation));
    }
}
