use std::collections::BTreeMap;

use crypto::TenantKeys;
use store::{
    Batch, CONTROL_BOOT, Change, Changes, CoreFile, Delivery, HEAD_ITEM, Index, Keeper, Location,
    Op, Record, control_key, is_control, split_key,
};

use crate::error::Error;
use crate::names::{Fixed, wait_keys};
use crate::queue::KeySource;
use crate::record::{
    KIND_ACCESS, KIND_DKIM, KIND_DOMAIN, KIND_NODE, KIND_POOL, KIND_TENANT, Object, SYSTEM, Update,
    peek, sealed_label,
};
use crate::siphash::siphash;
use crate::table::{Removal, Snapshot};

pub const ENTRY: usize = 64;

const CHECK: usize = 16;
const CHECK_FORMAT: u8 = 1;
const NAMING_CHECK: u32 = 0;
const DKIM_IDS: u32 = 1;
const ACCESS_IDS: u32 = 2;
const DOMAIN_IDS: u32 = 3;

pub fn naming_check(key: &[u8; 16]) -> u64 {
    siphash(key, b"bunzzle naming check")
}

fn encode_check(value: u64) -> Vec<u8> {
    let mut out = vec![0; CHECK];
    out[0] = CHECK_FORMAT;
    out[8..].copy_from_slice(&value.to_le_bytes());
    out
}

fn decode_check(clear: &[u8]) -> Option<u64> {
    let ok = clear.len() == CHECK && clear[0] == CHECK_FORMAT && clear[1..8] == [0; 7];
    ok.then(|| u64::from_le_bytes(clear[8..].try_into().expect("8 bytes")))
}

pub fn entry_size(clear: usize) -> usize {
    ENTRY + clear.next_multiple_of(8)
}

struct Hidden {
    location: Location,
    tenant: u32,
    clear: Box<[u8]>,
}

pub struct Loaded {
    shard: u16,
    version: u64,
    budget: usize,
    sizes: BTreeMap<(u8, u32), usize>,
    used: usize,
    skipped: u64,
    waited: u64,
    naming: Option<u64>,
    dkim_next: u32,
    access_next: u32,
    domain_next: u32,
    owners: BTreeMap<(u8, u32), (u32, u32)>,
    hidden: Vec<Hidden>,
}

impl Loaded {
    pub fn naming_check(&self) -> Option<u64> {
        self.naming
    }

    pub fn waited(&self) -> u64 {
        self.waited
    }

    pub async fn open(
        &mut self,
        snapshot: &mut Snapshot,
        file: &CoreFile,
        keys: &dyn KeySource,
    ) -> Result<(), Error> {
        let current: BTreeMap<u32, (u32, bool)> = snapshot
            .objects
            .iter()
            .filter_map(|object| match object {
                Object::Tenant(t) => Some((t.id, (t.generation, t.state.deleted()))),
                Object::Pool(_) | Object::Dkim(_) | Object::Access(_) | Object::Domain(_) => None,
            })
            .collect();
        let gone = |tenant: u32, generation: u32| {
            current
                .get(&tenant)
                .is_some_and(|&(g, deleted)| generation < g || (generation == g && deleted))
        };
        let reader = file.reader();
        let mut groups: BTreeMap<(u32, u32), Vec<Hidden>> = BTreeMap::new();
        for hidden in std::mem::take(&mut self.hidden) {
            match sealed_label(&hidden.clear) {
                Some(label) if !gone(label.tenant, label.generation) => groups
                    .entry((label.tenant, label.generation))
                    .or_default()
                    .push(hidden),
                _ => self.skipped += 1,
            }
        }
        for ((tenant, generation), group) in groups {
            let (sealing, waits) = wait_keys(keys, tenant, generation).await?;
            self.waited += waits;
            let Some(sealing) = sealing else {
                self.skipped += group.len() as u64;
                continue;
            };
            for hidden in group {
                let buf = reader.read(hidden.location, hidden.tenant, &Fixed).await?;
                let opened = Record::decode(&buf).ok().and_then(|record| {
                    let parts = Index::parts(record.payload())?;
                    if parts.clear != &*hidden.clear {
                        return None;
                    }
                    let label = sealed_label(parts.clear)?;
                    let secret = sealing.open(&label.bytes(), parts.sealed).ok()?;
                    Update::decode_sealed(parts.clear, &secret)
                });
                match opened {
                    Some(update) if update.object.tenant() == hidden.tenant => {
                        snapshot.objects.push(update.object);
                    }
                    _ => self.skipped += 1,
                }
            }
        }
        Ok(())
    }

    pub fn writer(self, changes: Changes) -> Writer {
        Writer {
            changes,
            loaded: self,
        }
    }

    fn bump(&mut self, kind: u8, id: u32) {
        let next = match kind {
            KIND_DKIM => &mut self.dkim_next,
            KIND_ACCESS => &mut self.access_next,
            KIND_DOMAIN => &mut self.domain_next,
            _ => return,
        };
        *next = (*next).max(id.saturating_add(1));
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
            waited: 0,
            naming: None,
            dkim_next: 1,
            access_next: 1,
            domain_next: 1,
            owners: BTreeMap::new(),
            hidden: Vec::new(),
        };
        let mut objects = Vec::new();
        for (key, item) in state.entries() {
            if !is_control(key.message) || key.item != HEAD_ITEM {
                continue;
            }
            let (boot, id) = split_key(key.message);
            let kind = u8::try_from(CONTROL_BOOT - boot).unwrap_or(u8::MAX);
            if kind == KIND_NODE {
                match (id, decode_check(&item.clear)) {
                    (NAMING_CHECK, Some(check)) => loaded.naming = Some(check),
                    (DKIM_IDS, Some(next)) => {
                        let next = u32::try_from(next).unwrap_or(u32::MAX);
                        loaded.dkim_next = loaded.dkim_next.max(next);
                    }
                    (ACCESS_IDS, Some(next)) => {
                        let next = u32::try_from(next).unwrap_or(u32::MAX);
                        loaded.access_next = loaded.access_next.max(next);
                    }
                    (DOMAIN_IDS, Some(next)) => {
                        let next = u32::try_from(next).unwrap_or(u32::MAX);
                        loaded.domain_next = loaded.domain_next.max(next);
                    }
                    _ => {
                        loaded.skipped += 1;
                        continue;
                    }
                }
                loaded.track(kind, id, item.clear.len());
                continue;
            }
            if kind == KIND_DKIM || kind == KIND_DOMAIN {
                match peek(&item.clear).filter(|&(k, i, _)| k == kind && i == id) {
                    Some((_, _, version)) => {
                        loaded.version = loaded.version.max(version);
                        loaded.bump(kind, id);
                        loaded.track(kind, id, item.clear.len());
                        match sealed_label(&item.clear).filter(|l| l.tenant == item.tenant) {
                            Some(label) => {
                                loaded
                                    .owners
                                    .insert((kind, id), (label.tenant, label.generation));
                                loaded.hidden.push(Hidden {
                                    location: item.location,
                                    tenant: item.tenant,
                                    clear: item.clear.clone(),
                                });
                            }
                            None => loaded.skipped += 1,
                        }
                    }
                    None => loaded.skipped += 1,
                }
                continue;
            }
            if ![KIND_TENANT, KIND_POOL, KIND_ACCESS].contains(&kind) {
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
            loaded.bump(kind, id);
            loaded.track(kind, id, item.clear.len());
            if let Some(owner) = update.object.owner() {
                loaded.owners.insert((kind, id), owner);
            }
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

    pub fn naming_check(&self) -> Option<u64> {
        self.loaded.naming
    }

    pub async fn set_naming_check(&mut self, check: u64) -> Result<(), Error> {
        self.put_node(NAMING_CHECK, check).await?;
        self.loaded.naming = Some(check);
        Ok(())
    }

    pub fn dkim_next(&self) -> u32 {
        self.loaded.dkim_next
    }

    pub async fn reserve_dkim(&mut self) -> Result<u32, Error> {
        let id = self.loaded.dkim_next;
        let next = id.checked_add(1).ok_or(Error::Full)?;
        self.put_node(DKIM_IDS, u64::from(next)).await?;
        self.loaded.dkim_next = next;
        Ok(id)
    }

    pub fn access_next(&self) -> u32 {
        self.loaded.access_next
    }

    pub async fn reserve_access(&mut self) -> Result<u32, Error> {
        let id = self.loaded.access_next;
        let next = id.checked_add(1).ok_or(Error::Full)?;
        self.put_node(ACCESS_IDS, u64::from(next)).await?;
        self.loaded.access_next = next;
        Ok(id)
    }

    pub fn domain_next(&self) -> u32 {
        self.loaded.domain_next
    }

    pub async fn reserve_domain(&mut self) -> Result<u32, Error> {
        let id = self.loaded.domain_next;
        let next = id.checked_add(1).ok_or(Error::Full)?;
        self.put_node(DOMAIN_IDS, u64::from(next)).await?;
        self.loaded.domain_next = next;
        Ok(id)
    }

    pub async fn remove(&mut self, object: &Object) -> Result<Removal, Error> {
        if object.owner().is_none() {
            return Err(Error::Invalid("kind"));
        }
        self.drop_record(object.kind(), object.id(), object.tenant())
            .await
    }

    pub async fn sweep(
        &mut self,
        swept: &dyn Fn(u32, u32) -> bool,
        removed: &mut Vec<Removal>,
    ) -> Result<(), Error> {
        let found: Vec<(u8, u32, u32)> = self
            .loaded
            .owners
            .iter()
            .filter(|(_, (tenant, generation))| swept(*tenant, *generation))
            .map(|(&(kind, id), &(tenant, _))| (kind, id, tenant))
            .collect();
        for (kind, id, tenant) in found {
            removed.push(self.drop_record(kind, id, tenant).await?);
        }
        Ok(())
    }

    pub fn owned_records(&self) -> usize {
        self.loaded.owners.len()
    }

    async fn drop_record(&mut self, kind: u8, id: u32, tenant: u32) -> Result<Removal, Error> {
        let size = self
            .loaded
            .sizes
            .get(&(kind, id))
            .copied()
            .ok_or(Error::Refused)?;
        let batch = Batch {
            shard: self.loaded.shard,
            message: control_key(kind, id),
            tenant,
            ops: vec![Op {
                item: HEAD_ITEM,
                change: Change::Drop,
                clear: Vec::new(),
                bodies: Vec::new(),
                sealed: Vec::new(),
            }],
        };
        self.changes.apply(batch).await?;
        self.loaded.sizes.remove(&(kind, id));
        self.loaded.owners.remove(&(kind, id));
        self.loaded.used -= size;
        self.loaded.version += 1;
        Ok(Removal {
            version: self.loaded.version,
            kind,
            id,
        })
    }

    async fn put_node(&mut self, id: u32, value: u64) -> Result<(), Error> {
        let clear = encode_check(value);
        let old = self
            .loaded
            .sizes
            .get(&(KIND_NODE, id))
            .copied()
            .unwrap_or(0);
        if old == 0 && self.loaded.used + entry_size(clear.len()) > self.loaded.budget {
            return Err(Error::Full);
        }
        let batch = Batch {
            shard: self.loaded.shard,
            message: control_key(KIND_NODE, id),
            tenant: SYSTEM,
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
        self.loaded.track(KIND_NODE, id, clear.len());
        Ok(())
    }

    pub async fn write(&mut self, object: Object) -> Result<Update, Error> {
        if object.sealed().is_some() {
            return Err(Error::Invalid("kind"));
        }
        self.put(object, None).await
    }

    pub async fn write_sealed(
        &mut self,
        object: Object,
        keys: &TenantKeys,
    ) -> Result<Update, Error> {
        if object.sealed().is_none() {
            return Err(Error::Invalid("kind"));
        }
        self.put(object, Some(keys)).await
    }

    async fn put(&mut self, object: Object, keys: Option<&TenantKeys>) -> Result<Update, Error> {
        object.check()?;
        let update = Update {
            version: self.loaded.version + 1,
            object,
        };
        let clear = update.encode();
        let sealed = match (update.object.sealed(), keys) {
            (Some(label), Some(keys)) => keys
                .seal(&label.bytes(), &update.secret())
                .map_err(|_| Error::Invalid("seal"))?,
            _ => Vec::new(),
        };
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
                sealed,
            }],
        };
        self.changes.apply(batch).await?;
        self.loaded.version = update.version;
        self.loaded.bump(kind, id);
        self.loaded.track(kind, id, clear.len());
        if let Some(owner) = update.object.owner() {
            self.loaded.owners.insert((kind, id), owner);
        }
        Ok(update)
    }
}
