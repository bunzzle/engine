use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crypto::{Secret, Tenant, Wrap, day_public, day_secret, next_day, open_batch, ratchet};
use rt::{Buf, File, OpenOptions};

use crate::file::{self, MASTER, Master};
use crate::{Entry, Error, State};

pub const VERSION: u8 = 1;
pub const MAX_RETENTION: u16 = 3660;
pub const MODE: u32 = 0o600;
const MASTERS: [&str; 2] = ["master.0", "master.1"];
const SLOTS: [&str; 2] = ["keys.0", "keys.1"];
const PHASE: &str = "phase";
const CHAINS: usize = 1024;
const DONE: u8 = 0;
const INIT: u8 = 1;
const RESTORE: u8 = 2;

pub struct Keys {
    pub day: u32,
    pub oldest: u32,
    pub data: Secret<32>,
    pub version: u8,
    pub hash: Secret<16>,
    pub today: [u8; 32],
    pub tomorrow: [u8; 32],
}

pub struct Vault {
    dir: PathBuf,
    masters: [File; 2],
    slots: [File; 2],
    master: Master,
    master_slot: usize,
    slot: usize,
    sequence: u64,
    last: Vec<u8>,
    state: State,
    pending: BTreeSet<u32>,
    chains: RefCell<BTreeMap<u32, Vec<Secret<32>>>>,
    dirty: bool,
    failed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Create {
    No,
    New,
    Over,
}

fn options(create: Create) -> OpenOptions {
    OpenOptions {
        read: true,
        write: true,
        create_new: create == Create::New,
        create: create == Create::Over,
        truncate: create == Create::Over,
        mode: Some(MODE),
    }
}

async fn open_pair(dir: &Path, names: [&str; 2], create: Create) -> Result<[File; 2], Error> {
    Ok([
        File::open(dir.join(names[0]), &options(create)).await?,
        File::open(dir.join(names[1]), &options(create)).await?,
    ])
}

async fn phase(dir: &Path) -> Result<(File, Option<u8>), Error> {
    let options = OpenOptions {
        read: true,
        write: true,
        create: true,
        mode: Some(MODE),
        ..OpenOptions::default()
    };
    let file = File::open(dir.join(PHASE), &options).await?;
    let bytes = read_all(&file).await?;
    Ok((file, bytes.first().copied()))
}

async fn set_phase(dir: &Path, file: &File, value: u8) -> Result<(), Error> {
    write(file, &[value]).await?;
    rt::sync_dir(dir).await?;
    Ok(())
}

async fn read_all(file: &File) -> Result<Buf, Error> {
    let len = usize::try_from(file.stat().await?.len).map_err(|_| Error::Corrupt("size"))?;
    let (read, buf) = file.read_at(Buf::new(len), 0).await;
    if read? != len {
        return Err(Error::Corrupt("short read"));
    }
    Ok(buf)
}

async fn write(file: &File, bytes: &[u8]) -> Result<(), Error> {
    let (written, mut buf) = file.write_all_at(Buf::from_slice(bytes), 0).await;
    sys::mem::wipe(&mut buf);
    written?;
    file.sync_data().await?;
    Ok(())
}

impl Vault {
    pub async fn init(dir: &Path, day: u32) -> Result<Self, Error> {
        let (marker, current) = phase(dir).await?;
        let create = match current {
            None => Create::New,
            Some(INIT) => Create::Over,
            Some(_) => return Err(Error::Exists),
        };
        set_phase(dir, &marker, INIT).await?;
        let masters = open_pair(dir, MASTERS, create).await?;
        let slots = open_pair(dir, SLOTS, create).await?;
        let master = Master::generate(1)?;
        write(&masters[0], &master.encode()).await?;
        let state = State {
            day,
            naming: Secret::random()?,
            tenants: BTreeMap::new(),
        };
        let last = file::seal(&master, 1, &state.encode())?;
        write(&slots[0], &last).await?;
        rt::sync_dir(dir).await?;
        let mut vault = Self {
            dir: dir.to_path_buf(),
            masters,
            slots,
            master,
            master_slot: 0,
            slot: 0,
            sequence: 1,
            last,
            state,
            pending: BTreeSet::new(),
            chains: RefCell::new(BTreeMap::new()),
            dirty: false,
            failed: false,
        };
        vault.export().await?;
        set_phase(dir, &marker, DONE).await?;
        Ok(vault)
    }

    pub async fn open(dir: &Path) -> Result<Self, Error> {
        let (marker, current) = phase(dir).await?;
        if current == Some(INIT) || current.is_none() {
            return Err(Error::Interrupted);
        }
        let masters = open_pair(dir, MASTERS, Create::No).await?;
        let slots = open_pair(dir, SLOTS, Create::No).await?;
        let mut found: [Option<Master>; 2] = [None, None];
        let mut written = [false; 2];
        for (i, file) in masters.iter().enumerate() {
            let mut buf = read_all(file).await?;
            found[i] = Master::decode(&buf);
            written[i] = buf.iter().any(|&b| b != 0);
            sys::mem::wipe(&mut buf);
        }
        let mut best: Option<(u64, usize, usize, State, Vec<u8>)> = None;
        for (i, file) in slots.iter().enumerate() {
            let bytes = read_all(file).await?;
            let Some(header) = file::Header::decode(&bytes) else {
                continue;
            };
            if best.as_ref().is_some_and(|b| b.0 >= header.sequence) {
                continue;
            }
            for (m, master) in found.iter().enumerate() {
                let Some(master) = master.as_ref().filter(|m| m.id == header.master) else {
                    continue;
                };
                let Ok(clear) = file::open(master, &bytes) else {
                    continue;
                };
                let Ok(state) = State::decode(&clear) else {
                    continue;
                };
                let end = file::sealed_len(&bytes).ok_or(Error::Corrupt("header"))?;
                best = Some((header.sequence, i, m, state, bytes[..end].to_vec()));
            }
        }
        let Some((sequence, slot, master_slot, state, last)) = best else {
            return Err(Error::Unreadable);
        };
        let master = found[master_slot].take().ok_or(Error::Unreadable)?;
        let other = 1 - master_slot;
        if written[other] {
            write(&masters[other], &[0; MASTER]).await?;
        }
        let mut vault = Self {
            dir: dir.to_path_buf(),
            masters,
            slots,
            master,
            master_slot,
            slot,
            sequence,
            last,
            state,
            pending: BTreeSet::new(),
            chains: RefCell::new(BTreeMap::new()),
            dirty: false,
            failed: false,
        };
        if current == Some(RESTORE) {
            vault.rotate().await?;
            set_phase(dir, &marker, DONE).await?;
        } else {
            vault.export().await?;
        }
        Ok(vault)
    }

    pub async fn restore(dir: &Path, master: &Master, export: &[u8]) -> Result<Self, Error> {
        State::decode(&file::open(master, export)?)?;
        let (marker, current) = phase(dir).await?;
        let create = match current {
            None => Create::New,
            Some(INIT | RESTORE) => Create::Over,
            Some(_) => return Err(Error::Exists),
        };
        set_phase(dir, &marker, RESTORE).await?;
        let masters = open_pair(dir, MASTERS, create).await?;
        let slots = open_pair(dir, SLOTS, create).await?;
        write(&masters[0], &master.encode()).await?;
        write(&slots[0], export).await?;
        rt::sync_dir(dir).await?;
        drop((masters, slots, marker));
        Self::open(dir).await
    }

    pub fn day(&self) -> u32 {
        self.state.day
    }

    pub fn naming(&self) -> &Secret<16> {
        &self.state.naming
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn create(&mut self, tenant: u32, generation: u32, retention: u16) -> Result<(), Error> {
        self.check()?;
        if retention == 0 || retention > MAX_RETENTION {
            return Err(Error::Retention);
        }
        if let Some(entry) = self.state.tenants.get(&tenant) {
            return if entry.generation == generation {
                Ok(())
            } else {
                Err(Error::Generation)
            };
        }
        let entry = Entry {
            generation,
            retention,
            oldest: self.state.day,
            key: Secret::random()?,
            ratchet: Secret::random()?,
        };
        self.state.tenants.insert(tenant, entry);
        self.pending.insert(tenant);
        self.dirty = true;
        Ok(())
    }

    pub async fn set_retention(
        &mut self,
        tenant: u32,
        generation: u32,
        days: u16,
    ) -> Result<(), Error> {
        self.check()?;
        if days == 0 || days > MAX_RETENTION {
            return Err(Error::Retention);
        }
        let entry = self.entry_mut(tenant, generation)?;
        if entry.retention != days {
            entry.retention = days;
            self.dirty = true;
        }
        self.flush().await
    }

    pub fn keys(&self, tenant: u32, generation: u32) -> Result<Keys, Error> {
        let entry = self.durable(tenant, generation)?;
        let day = self.state.day;
        let root = Tenant::new(&entry.key);
        let today = self.with_day(tenant, entry, day, day_public)?;
        let tomorrow = self.with_day(tenant, entry, day + 1, day_public)?;
        Ok(Keys {
            day,
            oldest: entry.oldest,
            data: root.data_secret(generation, VERSION),
            version: VERSION,
            hash: root.hash_key(generation),
            today,
            tomorrow,
        })
    }

    pub fn unwrap(&self, tenant: u32, batch: u64, wrap: &Wrap) -> Result<Secret<32>, Error> {
        let entry = self.durable(tenant, wrap.generation)?;
        self.with_day(tenant, entry, wrap.day, |secret| {
            open_batch(secret, tenant, batch, wrap).map_err(|_| Error::Open)
        })
    }

    fn durable(&self, tenant: u32, generation: u32) -> Result<&Entry, Error> {
        let entry = self.entry(tenant, generation)?;
        if self.pending.contains(&tenant) {
            return Err(Error::Pending);
        }
        Ok(entry)
    }

    fn with_day<T, E: Into<Error>>(
        &self,
        tenant: u32,
        entry: &Entry,
        day: u32,
        use_key: impl FnOnce(&Secret<32>) -> Result<T, E>,
    ) -> Result<T, Error> {
        let span = usize::try_from(self.state.day + 2 - entry.oldest)
            .map_err(|_| Error::Corrupt("day span"))?;
        let index = day
            .checked_sub(entry.oldest)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|&index| index < span)
            .ok_or(Error::Gone)?;
        let mut chains = self.chains.borrow_mut();
        if chains.get(&tenant).is_none_or(|chain| chain.len() != span) {
            if chains.len() >= CHAINS {
                chains.pop_first();
            }
            let mut state = ratchet(&entry.ratchet, 0);
            let mut chain = Vec::with_capacity(span);
            for _ in 0..span {
                chain.push(day_secret(&state));
                state = next_day(&state);
            }
            chains.insert(tenant, chain);
        }
        use_key(&chains[&tenant][index]).map_err(Into::into)
    }

    pub async fn delete(&mut self, tenant: u32, generation: u32) -> Result<(), Error> {
        self.check()?;
        if self
            .state
            .tenants
            .get(&tenant)
            .is_none_or(|entry| entry.generation != generation)
        {
            return Ok(());
        }
        self.state.tenants.remove(&tenant);
        self.pending.remove(&tenant);
        self.chains.borrow_mut().remove(&tenant);
        self.rotate().await
    }

    pub async fn flush(&mut self) -> Result<(), Error> {
        self.check()?;
        if !self.dirty {
            return Ok(());
        }
        self.commit(None).await?;
        self.export().await
    }

    pub async fn new_day(&mut self, settled: Option<u32>, force: bool) -> Result<(), Error> {
        self.check()?;
        self.state.day += 1;
        self.chains.borrow_mut().clear();
        self.advance(settled, force);
        self.rotate().await
    }

    pub async fn shred(&mut self, settled: Option<u32>, force: bool) -> Result<bool, Error> {
        self.check()?;
        if !self.advance(settled, force) {
            return Ok(false);
        }
        self.chains.borrow_mut().clear();
        self.rotate().await?;
        Ok(true)
    }

    fn advance(&mut self, settled: Option<u32>, force: bool) -> bool {
        let day = self.state.day;
        let mut moved = false;
        for entry in self.state.tenants.values_mut() {
            let target = day.saturating_sub(u32::from(entry.retention));
            let allowed = if force {
                target
            } else {
                settled.map_or(entry.oldest, |settled| {
                    target.min(settled.saturating_add(1))
                })
            };
            if allowed > entry.oldest {
                entry.ratchet = ratchet(&entry.ratchet, allowed - entry.oldest);
                entry.oldest = allowed;
                moved = true;
            }
        }
        moved
    }

    fn check(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Failed)
        } else {
            Ok(())
        }
    }

    fn entry(&self, tenant: u32, generation: u32) -> Result<&Entry, Error> {
        self.check()?;
        match self.state.tenants.get(&tenant) {
            Some(entry) if entry.generation == generation => Ok(entry),
            _ => Err(Error::Unknown),
        }
    }

    fn entry_mut(&mut self, tenant: u32, generation: u32) -> Result<&mut Entry, Error> {
        match self.state.tenants.get_mut(&tenant) {
            Some(entry) if entry.generation == generation => Ok(entry),
            _ => Err(Error::Unknown),
        }
    }

    async fn commit(&mut self, next: Option<&Master>) -> Result<(), Error> {
        let sequence = self.sequence + 1;
        let bytes = file::seal(next.unwrap_or(&self.master), sequence, &self.state.encode())?;
        let target = 1 - self.slot;
        let written = write(&self.slots[target], &bytes).await;
        self.guard(written)?;
        self.slot = target;
        self.sequence = sequence;
        self.last = bytes;
        self.dirty = false;
        self.pending.clear();
        Ok(())
    }

    async fn rotate(&mut self) -> Result<(), Error> {
        let next = Master::generate(self.master.id + 1)?;
        let free = 1 - self.master_slot;
        let written = write(&self.masters[free], &next.encode()).await;
        self.guard(written)?;
        self.commit(Some(&next)).await?;
        let zeroed = write(&self.masters[self.master_slot], &[0; MASTER]).await;
        self.guard(zeroed)?;
        self.master = next;
        self.master_slot = free;
        self.export().await
    }

    async fn export(&mut self) -> Result<(), Error> {
        let temp = self.dir.join("export.tmp");
        let options = OpenOptions {
            write: true,
            create: true,
            truncate: true,
            mode: Some(MODE),
            ..OpenOptions::default()
        };
        let result = async {
            let file = File::open(&temp, &options).await?;
            write(&file, &self.last).await?;
            rt::rename(&temp, self.dir.join("export")).await?;
            rt::sync_dir(&self.dir).await?;
            Ok(())
        }
        .await;
        self.guard(result)
    }

    fn guard<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.failed = true;
            self.chains.borrow_mut().clear();
        }
        result
    }
}
