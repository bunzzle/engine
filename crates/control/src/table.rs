use std::collections::BTreeMap;

use rt::Peers;

use crate::record::{Object, Pool, Tenant, Update};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    Snapshot(Snapshot),
    Update(Update),
}

pub fn broadcast(peers: &Peers<Note>, cores: u16, note: &Note) {
    for core in 0..cores {
        peers.send(core, note.clone());
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u64,
    pub objects: Vec<Object>,
}

#[derive(Debug, Default)]
pub struct Table {
    loaded: bool,
    version: u64,
    tenants: BTreeMap<u32, Tenant>,
    pools: BTreeMap<u32, Pool>,
    waiting: BTreeMap<u64, Object>,
}

impl Table {
    pub fn load(&mut self, snapshot: Snapshot) {
        self.loaded = true;
        self.version = snapshot.version;
        self.tenants.clear();
        self.pools.clear();
        for object in snapshot.objects {
            self.set(object);
        }
        self.waiting = self.waiting.split_off(&(self.version + 1));
        self.drain();
    }

    pub fn take(&mut self, note: Note) {
        match note {
            Note::Snapshot(snapshot) => self.load(snapshot),
            Note::Update(update) => self.apply(update),
        }
    }

    pub fn apply(&mut self, update: Update) {
        if update.version > self.version {
            self.waiting.insert(update.version, update.object);
        }
        self.drain();
    }

    pub fn loaded(&self) -> bool {
        self.loaded
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    pub fn tenant(&self, id: u32) -> Option<&Tenant> {
        self.tenants.get(&id)
    }

    pub fn pool(&self, id: u32) -> Option<&Pool> {
        self.pools.get(&id)
    }

    pub fn tenants(&self) -> impl Iterator<Item = &Tenant> {
        self.tenants.values()
    }

    pub fn pools(&self) -> impl Iterator<Item = &Pool> {
        self.pools.values()
    }

    fn drain(&mut self) {
        if !self.loaded {
            return;
        }
        while let Some(object) = self.waiting.remove(&(self.version + 1)) {
            self.set(object);
            self.version += 1;
        }
    }

    fn set(&mut self, object: Object) {
        match object {
            Object::Tenant(t) => {
                self.tenants.insert(t.id, t);
            }
            Object::Pool(p) => {
                self.pools.insert(p.id, p);
            }
        }
    }
}
