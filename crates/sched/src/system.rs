use std::cell::Cell;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use control::{KeyError, Label, SYSTEM};
use crypto::TenantKeys;
use store::{
    Batch, CONTROL_BOOT, Change, Changes, Core, Delivery, HEAD_ITEM, Index, Location, Op, Owner,
    Record, control_key, is_control, split_key,
};

use crate::sealing::Keys;
use crate::start::{CONTROL_SHARD, Parts};
use crate::transport::Transport;

const FORMAT: u8 = 1;
const CLEAR: usize = 6;
const KEY_WAIT: Duration = Duration::from_millis(100);
const KEY_WAIT_MAX: Duration = Duration::from_secs(5);
const KEY_TRIES: usize = 10;

pub struct Saved {
    pub shard: u16,
    pub id: u32,
    pub data: Vec<u8>,
}

pub struct Restore {
    pub kind: u8,
    pub naming: [u8; 16],
    pub saved: Vec<Saved>,
    pub unread: u64,
    pub dropped: u64,
    pub records: Rc<dyn Records>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsaved {
    Keys(KeyError),
    Seal,
    Store,
}

pub type Done<'a> = Pin<Box<dyn Future<Output = Result<(), Unsaved>> + 'a>>;

pub trait Records {
    fn home(&self) -> u16;
    fn put(&self, shard: u16, id: u32, data: Vec<u8>) -> Done<'_>;
    fn remove(&self, shard: u16, id: u32) -> Done<'_>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordStats {
    pub put: u64,
    pub removed: u64,
    pub failed: u64,
}

pub(crate) struct Stored {
    kind: u8,
    home: u16,
    changes: Changes,
    keys: Rc<dyn Keys>,
    stats: Cell<RecordStats>,
}

impl Stored {
    pub(crate) fn new(kind: u8, shards: &[u16], changes: Changes, keys: Rc<dyn Keys>) -> Self {
        let home = shards
            .iter()
            .copied()
            .find(|&shard| shard != CONTROL_SHARD)
            .or_else(|| shards.first().copied())
            .unwrap_or(CONTROL_SHARD);
        Self {
            kind,
            home,
            changes,
            keys,
            stats: Cell::new(RecordStats::default()),
        }
    }

    pub(crate) fn stats(&self) -> RecordStats {
        self.stats.get()
    }

    fn count(
        &self,
        done: Result<(), Unsaved>,
        ok: impl Fn(&mut RecordStats),
    ) -> Result<(), Unsaved> {
        let mut stats = self.stats.get();
        match done {
            Ok(()) => ok(&mut stats),
            Err(_) => stats.failed += 1,
        }
        self.stats.set(stats);
        done
    }

    async fn write(&self, shard: u16, id: u32, data: Vec<u8>) -> Result<(), Unsaved> {
        let keys = self.keys.system().await.map_err(Unsaved::Keys)?;
        let sealed = keys
            .seal(&label(&keys, self.kind, id), &data)
            .map_err(|_| Unsaved::Seal)?;
        let batch = Batch {
            shard,
            message: control_key(self.kind, id),
            tenant: SYSTEM,
            ops: vec![Op {
                item: HEAD_ITEM,
                change: Change::Put(Delivery {
                    status: 0,
                    attempts: 0,
                    due: 0,
                }),
                clear: clear(self.kind, id).to_vec(),
                bodies: Vec::new(),
                sealed,
            }],
        };
        self.changes
            .apply(batch)
            .await
            .map(drop)
            .map_err(|_| Unsaved::Store)
    }

    async fn drop_record(&self, shard: u16, id: u32, tenant: u32) -> Result<(), Unsaved> {
        let batch = Batch {
            shard,
            message: control_key(self.kind, id),
            tenant,
            ops: vec![Op {
                item: HEAD_ITEM,
                change: Change::Drop,
                clear: Vec::new(),
                bodies: Vec::new(),
                sealed: Vec::new(),
            }],
        };
        match self.changes.apply(batch).await {
            Ok(_) | Err(store::Error::NotFound) => Ok(()),
            Err(_) => Err(Unsaved::Store),
        }
    }
}

impl Records for Stored {
    fn home(&self) -> u16 {
        self.home
    }

    fn put(&self, shard: u16, id: u32, data: Vec<u8>) -> Done<'_> {
        Box::pin(async move {
            let done = self.write(shard, id, data).await;
            self.count(done, |s| s.put += 1)
        })
    }

    fn remove(&self, shard: u16, id: u32) -> Done<'_> {
        Box::pin(async move {
            let done = self.drop_record(shard, id, SYSTEM).await;
            self.count(done, |s| s.removed += 1)
        })
    }
}

fn label(keys: &TenantKeys, kind: u8, id: u32) -> [u8; control::LABEL_SIZE] {
    Label {
        tenant: SYSTEM,
        generation: keys.generation(),
        kind,
        id,
        hash: None,
    }
    .bytes()
}

fn clear(kind: u8, id: u32) -> [u8; CLEAR] {
    let mut out = [0; CLEAR];
    out[0] = FORMAT;
    out[1] = kind;
    out[2..].copy_from_slice(&id.to_le_bytes());
    out
}

struct Fixed;

impl Owner for Fixed {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        std::future::ready(None)
    }
}

pub(crate) struct Found {
    kind: u8,
    shards: Vec<u16>,
    pub(crate) saved: Vec<Saved>,
    pub(crate) unread: u64,
    pub(crate) bad: Vec<(u16, u32, u32)>,
}

async fn system_keys(keys: &dyn Keys) -> Option<TenantKeys> {
    let mut pause = KEY_WAIT;
    for _ in 0..KEY_TRIES {
        match keys.system().await {
            Ok(found) => return Some(found),
            Err(KeyError::Unavailable | KeyError::Busy) => {
                rt::sleep(pause).await;
                pause = (pause * 2).min(KEY_WAIT_MAX);
            }
            Err(_) => return None,
        }
    }
    None
}

async fn load(core: &Core, kind: u8, keys: &dyn Keys) -> Result<Found, control::Error> {
    let reader = core.file.reader();
    let mut listed = Vec::new();
    for &shard in &core.shards {
        let Some(state) = core.keeper.state(shard) else {
            continue;
        };
        for (key, item) in state.entries() {
            if !is_control(key.message) || key.item != HEAD_ITEM {
                continue;
            }
            let (boot, id) = split_key(key.message);
            if CONTROL_BOOT - boot != u32::from(kind) {
                continue;
            }
            let fits = item.tenant == SYSTEM && *item.clear == clear(kind, id);
            listed.push((shard, id, item.tenant, fits.then_some(item.location)));
        }
    }
    let mut found = Found {
        kind,
        shards: core.shards.clone(),
        saved: Vec::new(),
        unread: 0,
        bad: Vec::new(),
    };
    if listed.is_empty() {
        return Ok(found);
    }
    let Some(system) = system_keys(keys).await else {
        found.unread = listed.len() as u64;
        return Ok(found);
    };
    for (shard, id, tenant, location) in listed {
        let opened = match location {
            Some(location) => {
                let buf = reader.read(location, SYSTEM, &Fixed).await?;
                Record::decode(&buf).ok().and_then(|record| {
                    let parts = Index::parts(record.payload())?;
                    system.open(&label(&system, kind, id), parts.sealed).ok()
                })
            }
            None => None,
        };
        match opened {
            Some(data) => found.saved.push(Saved { shard, id, data }),
            None => found.bad.push((shard, id, tenant)),
        }
    }
    Ok(found)
}

pub(crate) struct Loaded {
    pub(crate) shards: Vec<u16>,
    naming: [u8; 16],
    found: Vec<Found>,
    cursored: BTreeMap<u32, (u32, u32)>,
}

pub(crate) async fn load_all(
    core: &Core,
    keys: &dyn Keys,
    naming: [u8; 16],
) -> Result<Loaded, control::Error> {
    let mut found = Vec::new();
    for kind in [control::KIND_STS, control::KIND_RPT] {
        found.push(load(core, kind, keys).await?);
    }
    Ok(Loaded {
        shards: core.shards.clone(),
        naming,
        found,
        cursored: crate::cursor::listed(core),
    })
}

pub(crate) async fn restore_all<T: Transport>(
    parts: &Parts<T>,
    loaded: Loaded,
    changes: &Changes,
) -> (Vec<Rc<Stored>>, BTreeMap<u32, (u32, u32)>) {
    let mut all = Vec::new();
    for found in loaded.found {
        let restored = restore(&parts.transport, found, changes, &parts.keys, loaded.naming);
        all.push(restored.await);
    }
    (all, loaded.cursored)
}

async fn restore<T: Transport>(
    transport: &T,
    found: Found,
    changes: &Changes,
    keys: &Rc<dyn Keys>,
    naming: [u8; 16],
) -> Rc<Stored> {
    let records = Rc::new(Stored::new(
        found.kind,
        &found.shards,
        changes.clone(),
        Rc::clone(keys),
    ));
    for &(shard, id, tenant) in &found.bad {
        let done = records.drop_record(shard, id, tenant).await;
        let _ = records.count(done, |s| s.removed += 1);
    }
    transport
        .restore(Restore {
            kind: found.kind,
            naming,
            saved: found.saved,
            unread: found.unread,
            dropped: found.bad.len() as u64,
            records: Rc::clone(&records) as Rc<dyn Records>,
        })
        .await;
    records
}
