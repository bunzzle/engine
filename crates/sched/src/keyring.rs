use std::cell::RefCell;
use std::rc::Rc;

use control::{Created, KeyError, KeySource, Ready};
use crypto::{BatchKey, DkimAlg, Secret, TenantKeys, Wrap};
use keys::{BatchSettings, BatchStats, Batches, Fault, Ring};

use crate::sealing::{
    Batched, Deleted, HookSecret, Keys, Loaded, Made, Oldest, Searched, Signed, Unsealable,
    Unwrapped,
};
use crate::search::DayKeys;

pub struct Keyring {
    ring: Ring,
    retention: u16,
    batches: RefCell<Batches>,
}

impl Keyring {
    pub fn new(ring: Ring, retention: u16, batches: BatchSettings) -> Self {
        Self {
            ring,
            retention,
            batches: RefCell::new(Batches::new(batches)),
        }
    }

    pub fn batch_stats(&self) -> BatchStats {
        self.batches.borrow().stats()
    }

    pub fn ring(&self) -> &Ring {
        &self.ring
    }

    fn advance(&self, tenant: u32, generation: u32) {
        let wall = keys::wall_day();
        let retention = u32::from(self.retention);
        let floor = match self.ring.get(tenant, generation) {
            Some(working) => {
                if working.seen < wall {
                    self.ring.refresh(tenant, generation);
                }
                let latest = latest_day(working.day, working.seen, wall);
                working.oldest.max(latest.saturating_sub(retention))
            }
            None if self.ring.day() == 0 => return,
            None => {
                latest_day(self.ring.day(), self.ring.day_seen(), wall).saturating_sub(retention)
            }
        };
        self.batches.borrow_mut().advance(tenant, generation, floor);
    }
}

fn latest_day(day: u32, seen: u32, wall: u32) -> u32 {
    day.saturating_add(wall.saturating_sub(seen))
        .saturating_add(1)
        .min(wall.max(seen))
}

fn key_error(fault: Fault) -> KeyError {
    match fault {
        Fault::Unknown | Fault::Gone => KeyError::Unknown,
        Fault::Unavailable => KeyError::Unavailable,
        Fault::Busy => KeyError::Busy,
        Fault::Failed | Fault::Bad => KeyError::Failed,
        Fault::Conflict => KeyError::Conflict,
    }
}

fn unsealable(fault: Fault) -> Unsealable {
    match fault {
        Fault::Unavailable | Fault::Busy => Unsealable::Unavailable,
        Fault::Gone => Unsealable::Gone,
        Fault::Unknown | Fault::Conflict => Unsealable::Unknown,
        Fault::Bad => Unsealable::Bad,
        Fault::Failed => Unsealable::Failed,
    }
}

impl KeySource for Keyring {
    fn get(&self, tenant: u32, generation: u32) -> Option<TenantKeys> {
        self.ring
            .get(tenant, generation)
            .map(|working| working.keys)
    }

    fn ready(&self, tenant: u32, generation: u32) -> Ready<'_> {
        Box::pin(async move {
            self.ring
                .open(tenant, generation)
                .await
                .map(|working| working.keys)
                .map_err(key_error)
        })
    }

    fn create(&self, tenant: u32, generation: u32) -> Created<'_> {
        Box::pin(async move {
            self.ring
                .create(tenant, generation, self.retention)
                .await
                .map_err(key_error)
        })
    }
}

impl Keys for Keyring {
    fn ids(&self) -> Option<Secret<16>> {
        self.ring.ids()
    }

    fn search(&self, tenant: u32, generation: u32) -> Searched<'_> {
        Box::pin(async move {
            let working = self
                .ring
                .sealing(tenant, generation)
                .await
                .map_err(key_error)?;
            let wall = keys::wall_day();
            Ok(DayKeys::new(
                working
                    .search
                    .days()
                    .filter_map(|day| working.search_key(day, wall).map(|key| (day, key.copy())))
                    .collect(),
            ))
        })
    }

    fn system(&self) -> Ready<'_> {
        Box::pin(async move {
            if let Some(keys) = self.ring.system() {
                return Ok(keys);
            }
            self.ring.hello().await.map_err(|error| match error {
                keys::Error::Failed => KeyError::Failed,
                _ => KeyError::Unavailable,
            })?;
            self.ring.system().ok_or(KeyError::Unavailable)
        })
    }

    fn tick(&self) {
        self.batches.borrow_mut().sweep(rt::now());
    }

    fn settled(&self, day: u32) {
        self.ring.settled(day);
    }

    fn forget(&self, tenant: u32, generation: u32) {
        self.ring.forget(tenant, generation);
        self.batches.borrow_mut().forget(tenant, generation);
    }

    fn forgotten(&self, tenant: u32, generation: u32) -> bool {
        self.ring.forgotten(tenant, generation)
    }

    fn forget_hook(&self, tenant: u32, hook: u32) {
        self.ring.forget_hook(tenant, hook);
    }

    fn hook_secret(&self, tenant: u32, generation: u32, hook: u32, version: u8) -> HookSecret<'_> {
        Box::pin(async move {
            self.ring
                .hook_secret(tenant, generation, hook, version)
                .await
                .map_err(key_error)
        })
    }

    fn delete(&self, tenant: u32, generation: u32) -> Deleted<'_> {
        Box::pin(async move {
            self.forget(tenant, generation);
            self.ring
                .delete(tenant, generation)
                .await
                .map_err(key_error)
        })
    }

    fn oldest(&self, tenant: u32, generation: u32) -> Oldest<'_> {
        Box::pin(async move {
            self.ring
                .fresh(tenant, generation)
                .await
                .map(|working| working.oldest)
                .map_err(key_error)
        })
    }

    fn dkim_new(&self, tenant: u32, generation: u32, key: u32, alg: DkimAlg) -> Made<'_> {
        Box::pin(async move {
            self.ring
                .dkim_new(tenant, generation, key, alg)
                .await
                .map_err(key_error)
        })
    }

    fn dkim_load<'a>(
        &'a self,
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
        blob: &'a [u8],
    ) -> Loaded<'a> {
        Box::pin(async move {
            self.ring
                .load(tenant, generation, key, alg, blob)
                .await
                .map_err(key_error)
        })
    }

    fn sign(
        &self,
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
        digest: [u8; 32],
    ) -> Signed<'_> {
        Box::pin(async move {
            self.ring
                .sign(tenant, generation, key, alg, digest)
                .await
                .map_err(key_error)
        })
    }

    fn batch(&self, tenant: u32, generation: u32, shard: u16, first: u64) -> Batched<'_> {
        Box::pin(async move {
            let working = self
                .ring
                .sealing(tenant, generation)
                .await
                .map_err(key_error)?;
            self.batches
                .borrow_mut()
                .seal(&working, shard, first, rt::now())
                .map_err(|_| KeyError::Unavailable)
        })
    }

    fn batch_key(
        &self,
        tenant: u32,
        generation: u32,
        shard: u16,
        id: u64,
        wrap: Wrap,
    ) -> Unwrapped<'_> {
        Box::pin(async move {
            if self.ring.forgotten(tenant, generation) {
                return Err(Unsealable::Gone);
            }
            self.advance(tenant, generation);
            if let Some(key) = self
                .batches
                .borrow_mut()
                .cached(tenant, generation, shard, id)
            {
                return Ok(key);
            }
            let secret = self
                .ring
                .unwrap(tenant, generation, shard, id, &wrap)
                .await
                .map_err(unsealable)?;
            if self.ring.forgotten(tenant, generation) {
                return Err(Unsealable::Gone);
            }
            self.advance(tenant, generation);
            let mut batches = self.batches.borrow_mut();
            if let Some(key) = batches.cached(tenant, generation, shard, id) {
                return Ok(key);
            }
            let key = Rc::new(BatchKey::new(&secret));
            batches.remember(tenant, generation, shard, id, wrap.day, Rc::clone(&key));
            Ok(key)
        })
    }
}
