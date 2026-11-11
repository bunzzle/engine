use std::collections::BTreeMap;

use crypto::{Secret, sha256};
use rt::Peers;

use crate::access::{Grant, Scope, Token};
use crate::record::{Access, Dkim, KIND_ACCESS, Object, Pool, State, Tenant, Update};

const DUMMY: [u8; 32] = [0; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    Snapshot(Snapshot),
    Update(Update),
    Remove(Removal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Removal {
    pub version: u64,
    pub kind: u8,
    pub id: u32,
}

#[derive(Debug)]
enum Pending {
    Set(Object),
    Remove(u8, u32),
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
    dkims: BTreeMap<u32, Dkim>,
    accesses: BTreeMap<u32, Access>,
    waiting: BTreeMap<u64, Pending>,
}

impl Table {
    pub fn load(&mut self, snapshot: Snapshot) {
        self.loaded = true;
        self.version = snapshot.version;
        self.tenants.clear();
        self.pools.clear();
        self.dkims.clear();
        self.accesses.clear();
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
            Note::Remove(removal) => self.remove(removal),
        }
    }

    pub fn apply(&mut self, update: Update) {
        self.wait(update.version, Pending::Set(update.object));
    }

    pub fn remove(&mut self, removal: Removal) {
        self.wait(removal.version, Pending::Remove(removal.kind, removal.id));
    }

    fn wait(&mut self, version: u64, pending: Pending) {
        if version > self.version {
            self.waiting.insert(version, pending);
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

    pub fn gone(&self, tenant: u32, generation: u32) -> bool {
        self.tenants.get(&tenant).is_some_and(|t| {
            generation < t.generation || (generation == t.generation && t.state.deleted())
        })
    }

    pub fn pool(&self, id: u32) -> Option<&Pool> {
        self.pools.get(&id)
    }

    pub fn dkim(&self, tenant: u32, id: u32) -> Option<&Dkim> {
        self.dkims.get(&id).filter(|d| d.tenant == tenant)
    }

    pub fn dkims(&self, tenant: u32) -> impl Iterator<Item = &Dkim> {
        self.dkims.values().filter(move |d| d.tenant == tenant)
    }

    pub fn access(&self, id: u32) -> Option<&Access> {
        self.accesses.get(&id)
    }

    pub fn accesses(&self, tenant: u32) -> impl Iterator<Item = &Access> {
        self.accesses.values().filter(move |a| a.tenant == tenant)
    }

    pub fn check(&self, token: &[u8], scope: Scope) -> Option<Grant> {
        let token = Token::parse(token);
        let (id, presented) = match &token {
            Some(token) => (token.id(), token.hash()),
            None => (0, sha256(&DUMMY)),
        };
        let found = self
            .accesses
            .get(&id)
            .filter(|a| a.scopes.has(scope))
            .and_then(|a| {
                let tenant = self.tenants.get(&a.tenant)?;
                (tenant.generation == a.generation).then_some((a, tenant))
            });
        let expected = found.map_or(DUMMY, |(a, _)| a.hash);
        let same = Secret::new(presented) == Secret::new(expected);
        let (access, tenant) = found.filter(|_| same)?;
        (tenant.state == State::Active).then_some(Grant {
            access: access.id,
            tenant: access.tenant,
            generation: access.generation,
            pool: match access.pool {
                0 => tenant.default_pool,
                pool => pool,
            },
        })
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
        while let Some(pending) = self.waiting.remove(&(self.version + 1)) {
            match pending {
                Pending::Set(object) => self.set(object),
                Pending::Remove(kind, id) => self.unset(kind, id),
            }
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
            Object::Dkim(d) => {
                self.dkims.insert(d.id, d);
            }
            Object::Access(a) => {
                self.accesses.insert(a.id, a);
            }
        }
    }

    fn unset(&mut self, kind: u8, id: u32) {
        if kind == KIND_ACCESS {
            self.accesses.remove(&id);
        }
    }
}
