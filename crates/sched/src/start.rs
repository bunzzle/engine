use std::cell::{Cell, Ref, RefCell};
use std::rc::{Rc, Weak};
use std::time::Duration;

use control::{
    Ask, Call, KeyError, KeySource, Leases, Name, Naming, Object, Queues, State, Table, Update,
    Writer, broadcast, limit_core,
};
use rt::{Ends, JoinHandle, Mesh, Notify, Peers, spawn};
use spool::Pending;
use store::Tiering;
use store::{Changes, Core, Keeper};

use crate::clock::Clock;
use crate::delete::sweep_queues;
use crate::error::Error;
use crate::node::{Config, Note, Sched};
use crate::requests::{KIND_REQUEST, RequestInputs, Requests, retain_request};
use crate::sealing::{Holds, Keys};
use crate::suppress::{self, Inputs, KIND_SUPPRESS, Suppressions};
use crate::transport::Transport;

pub const CONTROL_SHARD: u16 = 0;

pub struct Meshes {
    config: Mesh<control::Note>,
    names: Mesh<Call>,
    leases: Mesh<Ask<u32>>,
    sched: Mesh<Note>,
    suppress: Mesh<suppress::Ask>,
    steps: Mesh<()>,
}

impl Meshes {
    pub fn new(cores: u16) -> Self {
        Self {
            config: Mesh::new(cores),
            names: Mesh::new(cores),
            leases: Mesh::new(cores),
            sched: Mesh::new(cores),
            suppress: Mesh::new(cores),
            steps: Mesh::new(cores),
        }
    }

    pub fn take(&self, core: u16) -> Option<Links> {
        Some(Links {
            config: self.config.take(core)?,
            names: self.names.take(core)?,
            leases: self.leases.take(core)?,
            sched: self.sched.take(core)?,
            suppress: self.suppress.take(core)?,
            steps: self.steps.take(core)?,
        })
    }
}

pub struct Links {
    config: Ends<control::Note>,
    names: Ends<Call>,
    leases: Ends<Ask<u32>>,
    sched: Ends<Note>,
    suppress: Ends<suppress::Ask>,
    steps: Ends<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub node: u32,
    pub spool: spool::Limits,
    pub naming: Naming,
    pub sched: Config,
    pub budget: usize,
}

pub struct Parts<T> {
    pub keys: Rc<dyn Keys>,
    pub transport: T,
    pub clock: Clock,
}

pub(crate) struct Inner<T> {
    pub(crate) settings: Settings,
    keys: Rc<dyn Keys>,
    pub(crate) holds: Holds,
    pub(crate) ticker: Rc<Ticker>,
    cores: u16,
    pub(crate) spool: spool::Spool,
    pub(crate) sched: Sched<T>,
    pub(crate) queues: Queues,
    pub(crate) leases: Leases<u32>,
    pub(crate) table: Rc<RefCell<Table>>,
    pub(crate) suppressions: Suppressions,
    pub(crate) requests: Requests,
    config: Peers<control::Note>,
    writer: RefCell<Option<Writer>>,
    writing: Cell<bool>,
    restored: u64,
    pub(crate) dropped: Cell<u64>,
    pub(crate) delete_retries: Cell<u64>,
}

pub struct Node<T> {
    pub(crate) inner: Rc<Inner<T>>,
}

impl<T> Clone for Node<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

pub(crate) struct Held<'a> {
    slot: &'a RefCell<Option<Writer>>,
    writing: &'a Cell<bool>,
    writer: Option<Writer>,
}

impl Held<'_> {
    pub(crate) fn writer(&mut self) -> &mut Writer {
        self.writer.as_mut().expect("held until drop")
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        *self.slot.borrow_mut() = self.writer.take();
        self.writing.set(false);
    }
}

pub struct Running {
    done: Vec<JoinHandle<()>>,
    owner: JoinHandle<Keeper>,
    changes: Changes,
}

impl Running {
    pub async fn stop(self) -> Keeper {
        for done in self.done {
            done.await;
        }
        self.changes.close();
        self.owner.await
    }
}

impl<T: Transport + 'static> Node<T> {
    pub async fn start(
        mut core: Core,
        links: Links,
        settings: Settings,
        parts: Parts<T>,
    ) -> Result<(Self, Running), Error> {
        let cores = links.config.cores();
        let control = load_control(&core, settings.budget, &*parts.keys).await?;
        let check = naming(control.as_ref().map(|(loaded, _)| loaded), &settings)?;
        let table = Rc::new(RefCell::new(Table::default()));
        let clock = parts.clock;
        retain_current(&mut core, &table, clock);

        let applied = Rc::new(Notify::default());
        let (config, config_done, deletions) =
            start_config(links.config, &table, &applied, &parts.keys);
        let control = control.map(|(loaded, snapshot)| {
            broadcast(&config, cores, &control::Note::Snapshot(snapshot));
            loaded
        });
        while !table.borrow().loaded() {
            applied.wait().await;
        }
        let loaded = {
            let gone = |tenant, generation| table.borrow().gone(tenant, generation);
            Queues::load(&core, settings.naming, &*parts.keys, &gone).await?
        };
        let kept = core.shards.clone();
        let (spool, shards, pending) =
            spool::Spool::open(core, settings.node, settings.spool).await?;
        let owner = spawn(shards.run());
        let changes = spool.changes().clone();

        let writer = match control {
            Some(loaded) => {
                let writer = control_writer(loaded, changes.clone(), check, settings.node).await?;
                Some(sweep_at_start(writer, &table, &config, cores).await?)
            }
            None => None,
        };

        let inputs = Inputs {
            keys: Rc::clone(&parts.keys) as Rc<dyn KeySource>,
            changes: changes.clone(),
            table: Rc::clone(&table),
            clock,
            naming: settings.naming,
            shards: kept,
        };
        let (suppressions, requests, mut index_done) =
            index_services(links.suppress, inputs).await?;
        let (queues, names_done) = loaded.start(
            links.names,
            changes.clone(),
            Rc::clone(&parts.keys) as Rc<dyn KeySource>,
        );

        let (leases, leases_done) =
            start_leases(links.leases, &table, &spool, settings.naming.shards);

        let (sched, sched_done) = Sched::start(
            links.sched,
            spool.clone(),
            parts.transport,
            Rc::new(queues.clone()),
            parts.clock,
            settings.sched,
        );
        sched.use_keys(Rc::clone(&parts.keys));
        sched.use_table(Rc::clone(&table));
        let restored = pending.len() as u64;
        restore_live(&sched, pending, &table);

        leases.opened().await;
        barrier(links.steps).await;

        let ticker = Rc::new(Ticker::default());
        let inner = Rc::new(Inner {
            settings,
            keys: Rc::clone(&parts.keys),
            holds: Holds::default(),
            ticker: Rc::clone(&ticker),
            cores,
            spool,
            sched,
            queues,
            leases,
            table,
            suppressions,
            requests,
            config,
            writer: RefCell::new(writer),
            writing: Cell::new(false),
            restored,
            dropped: Cell::new(0),
            delete_retries: Cell::new(0),
        });
        let ticks = maintain(Rc::downgrade(&inner), ticker);
        let drops = drop_deleted(Rc::downgrade(&inner), deletions);
        index_done.extend([config_done, names_done, leases_done, sched_done]);
        index_done.extend([ticks, drops]);
        let running = Running {
            done: index_done,
            owner,
            changes,
        };
        let node = Self { inner };
        node.resume_deletes();
        Ok((node, running))
    }
}

impl<T: Transport + 'static> Node<T> {
    pub fn spool(&self) -> &spool::Spool {
        &self.inner.spool
    }

    pub(crate) fn keys(&self) -> &dyn Keys {
        &*self.inner.keys
    }

    pub fn ids(&self) -> Option<crypto::Secret<16>> {
        self.inner.keys.ids()
    }

    pub fn sched(&self) -> &Sched<T> {
        &self.inner.sched
    }

    pub fn queues(&self) -> &Queues {
        &self.inner.queues
    }

    pub fn leases(&self) -> &Leases<u32> {
        &self.inner.leases
    }

    pub fn requests(&self) -> &Requests {
        &self.inner.requests
    }

    pub fn suppressions(&self) -> &Suppressions {
        &self.inner.suppressions
    }

    pub fn table(&self) -> Ref<'_, Table> {
        self.inner.table.borrow()
    }

    pub fn settings(&self) -> Settings {
        self.inner.settings
    }

    pub fn restored(&self) -> u64 {
        self.inner.restored
    }

    pub fn controls(&self) -> bool {
        self.inner.writer.borrow().is_some()
    }

    pub fn control_records(&self) -> Option<usize> {
        self.inner
            .writer
            .borrow()
            .as_ref()
            .map(Writer::owned_records)
    }

    pub(crate) async fn write_state(
        &self,
        tenant: u32,
        generation: u32,
        state: State,
    ) -> Result<Update, Error> {
        let node = self.clone();
        spawn(async move {
            let mut held = node.hold()?;
            let current = node
                .table()
                .tenant(tenant)
                .filter(|t| t.generation == generation)
                .cloned()
                .ok_or(control::Error::Refused)?;
            let allowed = match state {
                State::Deleting => !current.state.deleted(),
                State::Deleted => current.state == State::Deleting,
                State::Active | State::Suspended => false,
            };
            if !allowed {
                return Err(control::Error::Refused.into());
            }
            let object = Object::Tenant(control::Tenant { state, ..current });
            let update = held.writer().write(object).await?;
            node.apply(&update);
            drop(held);
            node.broadcast(&update);
            Ok(update)
        })
        .await
    }

    pub(crate) fn apply(&self, update: &Update) {
        self.inner.table.borrow_mut().apply(update.clone());
    }

    pub(crate) fn note(&self, note: control::Note) {
        self.inner.table.borrow_mut().take(note);
    }

    pub async fn write(&self, object: Object) -> Result<Update, Error> {
        if matches!(
            object,
            Object::Dkim(_) | Object::Access(_) | Object::Domain(_)
        ) {
            return Err(control::Error::Invalid("kind").into());
        }
        let node = self.clone();
        spawn(async move { node.write_held(object).await }).await
    }

    async fn write_held(&self, object: Object) -> Result<Update, Error> {
        let mut held = self.hold()?;
        self.create_keys(&object).await?;
        let update = held.writer().write(object).await?;
        self.apply(&update);
        drop(held);
        self.broadcast(&update);
        Ok(update)
    }

    pub(crate) fn hold(&self) -> Result<Held<'_>, Error> {
        let inner = &self.inner;
        if inner.writing.replace(true) {
            return Err(control::Error::Busy.into());
        }
        let Some(writer) = inner.writer.borrow_mut().take() else {
            inner.writing.set(false);
            return Err(control::Error::Invalid("core").into());
        };
        Ok(Held {
            slot: &inner.writer,
            writing: &inner.writing,
            writer: Some(writer),
        })
    }

    pub(crate) fn broadcast(&self, update: &Update) {
        self.send(&control::Note::Update(update.clone()));
    }

    pub(crate) fn send(&self, note: &control::Note) {
        broadcast(&self.inner.config, self.inner.cores, note);
    }

    async fn create_keys(&self, object: &Object) -> Result<(), control::Error> {
        let Object::Tenant(tenant) = object else {
            return Ok(());
        };
        let (id, generation) = (tenant.id, tenant.generation);
        if tenant.state.deleted() {
            return Err(control::Error::Refused);
        }
        let known = self
            .inner
            .table
            .borrow()
            .tenant(id)
            .map(|t| (t.generation, t.state));
        match known {
            Some((current, state)) if current == generation && !state.deleted() => return Ok(()),
            Some((current, State::Deleted))
                if generation == current + 1 && !tenant.state.deleted() => {}
            Some(_) => return Err(control::Error::Refused),
            None if generation != 1 || tenant.state.deleted() => {
                return Err(control::Error::Refused);
            }
            None => {}
        }
        self.inner
            .keys
            .create(id, generation)
            .await
            .map_err(|error| match error {
                KeyError::Conflict => control::Error::Refused,
                error => control::Error::Keys {
                    tenant: id,
                    generation,
                    error,
                },
            })
    }

    pub async fn rebind(&self, name: &Name, pool: u32) -> Result<u32, Error> {
        Ok(self.inner.queues.rebind(name, pool).await?)
    }

    pub fn holds_kept(&self) -> u64 {
        self.inner.holds.kept()
    }

    pub fn ticks_late(&self) -> u64 {
        self.inner.ticker.late.get()
    }

    pub fn close(&self) {
        let inner = &self.inner;
        inner.ticker.stopped.set(true);
        inner.ticker.wake.notify();
        inner.sched.close();
        inner.queues.close();
        inner.leases.close();
        inner.suppressions.close();
        inner.requests.close();
        inner.config.close();
    }
}

async fn index_services(
    ends: Ends<suppress::Ask>,
    inputs: Inputs,
) -> Result<(Suppressions, Requests, Vec<JoinHandle<()>>), Error> {
    let request_inputs = RequestInputs {
        keys: Rc::clone(&inputs.keys),
        changes: inputs.changes.clone(),
        table: Rc::clone(&inputs.table),
        clock: inputs.clock,
        naming: inputs.naming,
        shards: inputs.shards.clone(),
    };
    let (suppressions, lists_done) = Suppressions::start(ends, inputs);
    let (requests, requests_done) = Requests::start(request_inputs)
        .await
        .map_err(spool::Error::from)?;
    Ok((suppressions, requests, vec![lists_done, requests_done]))
}

const TICK: Duration = Duration::from_secs(1);
const LOW_EVERY: Duration = Duration::from_secs(60);

fn drop_deleted<T: Transport + 'static>(
    inner: Weak<Inner<T>>,
    mut deletions: rt::Receiver<(u32, bool)>,
) -> JoinHandle<()> {
    spawn(async move {
        while let Some((tenant, now)) = deletions.recv().await {
            let Some(strong) = inner.upgrade() else {
                return;
            };
            if now {
                Node { inner: strong }.drop_tenant(tenant).await;
            } else {
                drop(strong);
            }
            sweep_queues(&inner, tenant).await;
        }
    })
}

#[derive(Default)]
pub(crate) struct Ticker {
    pub(crate) stopped: Cell<bool>,
    wake: Notify,
    late: Cell<u64>,
}

fn maintain<T: Transport + 'static>(inner: Weak<Inner<T>>, ticker: Rc<Ticker>) -> JoinHandle<()> {
    spawn(async move {
        let mut last = rt::now();
        let mut low_at = last;
        loop {
            let woken = rt::timeout(TICK, ticker.wake.wait()).await.is_ok();
            if ticker.stopped.get() {
                return;
            }
            if woken {
                continue;
            }
            let Some(inner) = inner.upgrade() else {
                return;
            };
            let now = rt::now();
            if now.saturating_duration_since(last) > TICK * 2 {
                ticker.late.set(ticker.late.get() + 1);
            }
            last = now;
            inner.keys.tick();
            if now >= low_at {
                low_at = now + LOW_EVERY;
                settle(&inner);
            }
        }
    })
}

fn settle<T: Transport + 'static>(inner: &Inner<T>) {
    let low = [inner.spool.oldest_day(), inner.holds.oldest()]
        .into_iter()
        .flatten()
        .fold(keys::wall_day(), u32::min);
    inner.sched.report_low(low);
    if let Some(low) = inner.sched.settled_low()
        && low > 0
    {
        inner.keys.settled(low - 1);
    }
}

fn start_leases(
    ends: Ends<Ask<u32>>,
    table: &Rc<RefCell<Table>>,
    spool: &spool::Spool,
    shards: u32,
) -> (Leases<u32>, JoinHandle<()>) {
    let cores = ends.cores();
    let rules = Rc::clone(table);
    let (leases, done) = Leases::start(
        ends,
        move |tenant| limit_core(*tenant, shards, cores),
        move |tenant| rules.borrow().tenant(*tenant).map(|t| t.limits),
    );
    leases.restore(spool.open_counts());
    let freed = leases.clone();
    spool.on_close(move |tenant, count| freed.free(&tenant, count));
    (leases, done)
}

async fn load_control(
    core: &Core,
    budget: usize,
    keys: &dyn KeySource,
) -> Result<Option<(control::Loaded, control::Snapshot)>, Error> {
    if !core.shards.contains(&CONTROL_SHARD) {
        return Ok(None);
    }
    let (mut loaded, mut snapshot) = Writer::load(&core.keeper, CONTROL_SHARD, budget)?;
    loaded.open(&mut snapshot, &core.file, keys).await?;
    Ok(Some((loaded, snapshot)))
}

async fn sweep_at_start(
    mut writer: Writer,
    table: &RefCell<Table>,
    config: &Peers<control::Note>,
    cores: u16,
) -> Result<Writer, Error> {
    let mut removed = Vec::new();
    let swept = |tenant, generation| table.borrow().swept(tenant, generation);
    let result = writer.sweep(&swept, &mut removed).await;
    for removal in removed {
        broadcast(config, cores, &control::Note::Remove(removal));
    }
    result?;
    Ok(writer)
}

async fn control_writer(
    loaded: control::Loaded,
    changes: Changes,
    check: u64,
    node: u32,
) -> Result<Writer, Error> {
    let mut writer = loaded.writer(changes);
    if writer.naming_check().is_none() {
        writer.set_naming_check(check).await?;
    }
    if writer.node_id().is_none() {
        writer.set_node_id(u64::from(node)).await?;
    }
    Ok(writer)
}

fn naming(control: Option<&control::Loaded>, settings: &Settings) -> Result<u64, Error> {
    let check = control::naming_check(&settings.naming.key);
    if control
        .and_then(control::Loaded::naming_check)
        .is_some_and(|found| found != check)
    {
        return Err(Error::Naming);
    }
    if control
        .and_then(control::Loaded::node_id)
        .is_some_and(|found| found != u64::from(settings.node))
    {
        return Err(Error::Node);
    }
    Ok(check)
}

fn restore_live<T: Transport + 'static>(
    sched: &Sched<T>,
    pending: Vec<Pending>,
    table: &Rc<RefCell<Table>>,
) {
    let table = table.borrow();
    let live = pending
        .into_iter()
        .filter(|m| !table.tenant(m.tenant).is_some_and(|t| t.state.deleted()))
        .collect();
    sched.restore(live, |tenant| table.tenant(tenant).map(|t| t.generation));
}

type Started = (
    Peers<control::Note>,
    JoinHandle<()>,
    rt::Receiver<(u32, bool)>,
);

fn start_config(
    ends: Ends<control::Note>,
    table: &Rc<RefCell<Table>>,
    applied: &Rc<Notify>,
    keys: &Rc<dyn Keys>,
) -> Started {
    let (deleting, deletions) = rt::channel();
    let table = Rc::clone(table);
    let applied = Rc::clone(applied);
    let keys = Rc::clone(keys);
    let (config, done) = ends.start(move |_, note| {
        for (tenant, generation, now) in deleted(&note) {
            keys.forget(tenant, generation);
            let _ = deleting.send((tenant, now));
        }
        table.borrow_mut().take(note);
        applied.notify();
    });
    (config, done, deletions)
}

fn deleted(note: &control::Note) -> Vec<(u32, u32, bool)> {
    let gone = |object: &Object| match object {
        Object::Tenant(t) if t.state.deleted() => Some((t.id, t.generation, true)),
        Object::Tenant(t) if t.generation > 1 => Some((t.id, t.generation - 1, false)),
        _ => None,
    };
    match note {
        control::Note::Snapshot(snapshot) => snapshot.objects.iter().filter_map(gone).collect(),
        control::Note::Update(update) => gone(&update.object).into_iter().collect(),
        control::Note::Remove(_) => Vec::new(),
    }
}

fn retain_current(core: &mut Core, table: &Rc<RefCell<Table>>, clock: Clock) {
    let rules = Rc::clone(table);
    core.keeper.set_tiering(Tiering {
        retain: Rc::new(move |kind, entry, oldest| {
            let table = rules.borrow();
            match kind {
                KIND_SUPPRESS => suppress::retain(&table, clock.now(), entry, oldest),
                KIND_REQUEST => retain_request(&table, clock.now(), entry),
                _ => true,
            }
        }),
        ..core.keeper.tiering().clone()
    });
}

async fn barrier(ends: Ends<()>) {
    let cores = ends.cores();
    let arrived = Rc::new(Cell::new(0_u16));
    let wake = Rc::new(Notify::default());
    let (peers, done) = {
        let arrived = Rc::clone(&arrived);
        let wake = Rc::clone(&wake);
        ends.start(move |_, ()| {
            arrived.set(arrived.get() + 1);
            wake.notify();
        })
    };
    for core in 0..cores {
        peers.send(core, ());
    }
    while arrived.get() < cores {
        wake.wait().await;
    }
    peers.close();
    done.await;
}
