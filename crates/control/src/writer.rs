use std::collections::BTreeMap;

use store::{
    Batch, CONTROL_BOOT, Change, Changes, Delivery, HEAD_ITEM, Keeper, Op, control_key, is_control,
    split_key,
};

use crate::error::Error;
use crate::record::{KIND_POOL, KIND_TENANT, Object, Update};
use crate::table::Snapshot;

pub const ENTRY: usize = 64;

pub fn entry_size(clear: usize) -> usize {
    ENTRY + clear.next_multiple_of(8)
}

pub struct Loaded {
    shard: u16,
    version: u64,
    budget: usize,
    sizes: BTreeMap<(u8, u32), usize>,
    used: usize,
    skipped: u64,
}

impl Loaded {
    pub fn writer(self, changes: Changes) -> Writer {
        Writer {
            changes,
            loaded: self,
        }
    }

    fn track(&mut self, kind: u8, id: u32, clear: usize) {
        let size = entry_size(clear);
        let old = self.sizes.insert((kind, id), size).unwrap_or(0);
        self.used = self.used - old + size;
    }
}

pub struct Writer {
    changes: Changes,
    loaded: Loaded,
}

impl Writer {
    pub fn load(keeper: &Keeper, shard: u16, budget: usize) -> Result<(Loaded, Snapshot), Error> {
        let state = keeper.state(shard).ok_or(Error::Invalid("shard"))?;
        let mut loaded = Loaded {
            shard,
            version: 0,
            budget,
            sizes: BTreeMap::new(),
            used: 0,
            skipped: 0,
        };
        let mut objects = Vec::new();
        for (key, item) in state.entries() {
            if !is_control(key.message) || key.item != HEAD_ITEM {
                continue;
            }
            let (boot, id) = split_key(key.message);
            let kind = u8::try_from(CONTROL_BOOT - boot).unwrap_or(u8::MAX);
            if kind != KIND_TENANT && kind != KIND_POOL {
                continue;
            }
            let decoded = Update::decode(&item.clear).filter(|u| {
                u.object.kind() == kind && u.object.id() == id && u.object.tenant() == item.tenant
            });
            let Some(update) = decoded else {
                loaded.skipped += 1;
                continue;
            };
            loaded.version = loaded.version.max(update.version);
            loaded.track(kind, id, item.clear.len());
            objects.push(update.object);
        }
        let snapshot = Snapshot {
            version: loaded.version,
            objects,
        };
        Ok((loaded, snapshot))
    }

    pub fn version(&self) -> u64 {
        self.loaded.version
    }

    pub fn used(&self) -> usize {
        self.loaded.used
    }

    pub fn skipped(&self) -> u64 {
        self.loaded.skipped
    }

    pub async fn write(&mut self, object: Object) -> Result<Update, Error> {
        object.check()?;
        let update = Update {
            version: self.loaded.version + 1,
            object,
        };
        let clear = update.encode();
        let (kind, id) = (update.object.kind(), update.object.id());
        let old = self.loaded.sizes.get(&(kind, id)).copied().unwrap_or(0);
        if self.loaded.used - old + entry_size(clear.len()) > self.loaded.budget {
            return Err(Error::Full);
        }
        let batch = Batch {
            shard: self.loaded.shard,
            message: control_key(kind, id),
            tenant: update.object.tenant(),
            ops: vec![Op {
                item: HEAD_ITEM,
                change: Change::Put(Delivery {
                    status: 0,
                    attempts: 0,
                    due: 0,
                }),
                clear: clear.clone(),
                bodies: Vec::new(),
                sealed: Vec::new(),
            }],
        };
        self.changes.apply(batch).await?;
        self.loaded.version = update.version;
        self.loaded.track(kind, id, clear.len());
        Ok(update)
    }
}
