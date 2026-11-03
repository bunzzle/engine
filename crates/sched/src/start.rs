use std::cell::{Cell, Ref, RefCell};
use std::rc::Rc;

use control::{
    Ask, Call, KeyError, KeySource, Leases, Name, Naming, Object, Queues, Table, Update, Writer,
    broadcast, limit_core,
};
use rt::{Ends, JoinHandle, Mesh, Notify, Peers, spawn};
use store::Tiering;
use store::{Changes, Core, Keeper};

use crate::clock::Clock;
use crate::error::Error;
use crate::node::{Config, Note, Sched};
use crate::requests::{KIND_REQUEST, RequestInputs, Requests, retain_request};
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
    pub keys: Rc<dyn KeySource>,
    pub transport: T,
    pub clock: Clock,
}

pub(crate) struct Inner<T> {
    pub(crate) settings: Settings,
    keys: Rc<dyn KeySource>,
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
        let control = if core.shards.contains(&CONTROL_SHARD) {
            Some(Writer::load(&core.keeper, CONTROL_SHARD, settings.budget)?)
        } else {
            None
        };
        let check = naming(control.as_ref().map(|(loaded, _)| loaded), &settings)?;
        let loaded = Queues::load(&core, settings.naming, parts.keys.as_ref()).await?;
        let table = Rc::new(RefCell::new(Table::default()));
        let clock = parts.clock;
        retain_current(&mut core, &table, clock);
        let kept = core.shards.clone();
        let (spool, shards, pending) =
            spool::Spool::open(core, settings.node, settings.spool).await?;
        let owner = spawn(shards.run());
        let changes = spool.changes().clone();

        let applied = Rc::new(Notify::default());
        let (config, config_done) = {
            let table = Rc::clone(&table);
            let applied = Rc::clone(&applied);
            links.config.start(move |_, note| {
                table.borrow_mut().take(note);
                applied.notify();
            })
        };
        let writer = match control {
            Some((loaded, snapshot)) => {
                broadcast(&config, cores, &control::Note::Snapshot(snapshot));
                Some(control_writer(loaded, changes.clone(), check).await?)
            }
            None => None,
        };

        let inputs = Inputs {
            keys: Rc::clone(&parts.keys),
            changes: changes.clone(),
            table: Rc::clone(&table),
            clock,
            naming: settings.naming,
            shards: kept,
        };
        let (suppressions, requests, mut index_done) =
            index_services(links.suppress, inputs).await?;
        let (queues, names_done) =
            loaded.start(links.names, changes.clone(), Rc::clone(&parts.keys));

        let (leases, leases_done) =
            start_leases(links.leases, &table, &spool, settings.naming.shards);

        while !table.borrow().loaded() {
            applied.wait().await;
        }

        let (sched, sched_done) = Sched::start(
            links.sched,
            spool.clone(),
            parts.transport,
            Rc::new(queues.clone()),
            parts.clock,
            settings.sched,
        );
        let restored = pending.len() as u64;
        sched.restore(pending, |tenant| {
            table.borrow().tenant(tenant).map(|t| t.generation)
        });

        leases.opened().await;
        barrier(links.steps).await;

        let inner = Inner {
            settings,
            keys: Rc::clone(&parts.keys),
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
        };
        let running = Running {
            done: {
                index_done.extend([config_done, names_done, leases_done, sched_done]);
                index_done
            },
            owner,
            changes,
        };
        Ok((
            Self {
                inner: Rc::new(inner),
            },
            running,
        ))
    }
}

impl<T: Transport + 'static> Node<T> {
    pub fn spool(&self) -> &spool::Spool {
        &self.inner.spool
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

    pub async fn write(&self, object: Object) -> Result<Update, Error> {
        let inner = &self.inner;
        if inner.writing.replace(true) {
            return Err(control::Error::Busy.into());
        }
        let taken = inner.writer.borrow_mut().take();
        let Some(mut writer) = taken else {
            inner.writing.set(false);
            return Err(control::Error::Invalid("core").into());
        };
        if let Err(error) = self.create_keys(&object).await {
            *inner.writer.borrow_mut() = Some(writer);
            inner.writing.set(false);
            return Err(error.into());
        }
        let written = writer.write(object).await;
        *inner.writer.borrow_mut() = Some(writer);
        inner.writing.set(false);
        let update = written?;
        broadcast(
            &inner.config,
            inner.cores,
            &control::Note::Update(update.clone()),
        );
        Ok(update)
    }

    async fn create_keys(&self, object: &Object) -> Result<(), control::Error> {
        let Object::Tenant(tenant) = object else {
            return Ok(());
        };
        let (id, generation) = (tenant.id, tenant.generation);
        let known = self.inner.table.borrow().tenant(id).map(|t| t.generation);
        match known {
            Some(current) if current == generation => return Ok(()),
            None if generation != 1 => return Err(control::Error::Refused),
            _ => {}
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

    pub fn close(&self) {
        let inner = &self.inner;
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

async fn control_writer(
    loaded: control::Loaded,
    changes: Changes,
    check: u64,
) -> Result<Writer, Error> {
    let mut writer = loaded.writer(changes);
    if writer.naming_check().is_none() {
        writer.set_naming_check(check).await?;
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
    Ok(check)
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
