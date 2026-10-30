use std::cell::{Cell, Ref, RefCell};
use std::rc::Rc;

use control::{
    Ask, Call, Leases, Name, Naming, Object, Queues, Sealer, Table, Update, Writer, broadcast,
    limit_core,
};
use rt::{Ends, JoinHandle, Mesh, Notify, Peers, spawn};
use store::{Changes, Core, Keeper};

use crate::clock::Clock;
use crate::error::Error;
use crate::intake::Suppressions;
use crate::node::{Config, Note, Sched};
use crate::transport::Transport;

pub const CONTROL_SHARD: u16 = 0;

pub struct Meshes {
    config: Mesh<control::Note>,
    names: Mesh<Call>,
    leases: Mesh<Ask<u32>>,
    sched: Mesh<Note>,
    steps: Mesh<()>,
}

impl Meshes {
    pub fn new(cores: u16) -> Self {
        Self {
            config: Mesh::new(cores),
            names: Mesh::new(cores),
            leases: Mesh::new(cores),
            sched: Mesh::new(cores),
            steps: Mesh::new(cores),
        }
    }

    pub fn take(&self, core: u16) -> Option<Links> {
        Some(Links {
            config: self.config.take(core)?,
            names: self.names.take(core)?,
            leases: self.leases.take(core)?,
            sched: self.sched.take(core)?,
            steps: self.steps.take(core)?,
        })
    }
}

pub struct Links {
    config: Ends<control::Note>,
    names: Ends<Call>,
    leases: Ends<Ask<u32>>,
    sched: Ends<Note>,
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
    pub sealer: Rc<dyn Sealer>,
    pub suppressions: Rc<dyn Suppressions>,
    pub transport: T,
    pub clock: Clock,
}

pub(crate) struct Inner<T> {
    pub(crate) settings: Settings,
    cores: u16,
    pub(crate) spool: spool::Spool,
    pub(crate) sched: Sched<T>,
    pub(crate) queues: Queues,
    pub(crate) leases: Leases<u32>,
    pub(crate) table: Rc<RefCell<Table>>,
    pub(crate) suppressions: Rc<dyn Suppressions>,
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
        core: Core,
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
        let loaded = Queues::load(&core, settings.naming, parts.sealer.as_ref()).await?;
        let (spool, shards, pending) =
            spool::Spool::open(core, settings.node, settings.spool).await?;
        let owner = spawn(shards.run());
        let changes = spool.changes().clone();

        let table = Rc::new(RefCell::new(Table::default()));
        let applied = Rc::new(Notify::default());
        let (config, config_done) = {
            let table = Rc::clone(&table);
            let applied = Rc::clone(&applied);
            links.config.start(move |_, note| {
                table.borrow_mut().take(note);
                applied.notify();
            })
        };
        let writer = control.map(|(loaded, snapshot)| {
            broadcast(&config, cores, &control::Note::Snapshot(snapshot));
            loaded.writer(changes.clone())
        });

        let (queues, names_done) = loaded.start(links.names, changes.clone(), parts.sealer);

        let shards = settings.naming.shards;
        let rules = Rc::clone(&table);
        let (leases, leases_done) = Leases::start(
            links.leases,
            move |tenant| limit_core(*tenant, shards, cores),
            move |tenant| rules.borrow().tenant(*tenant).map(|t| t.limits),
        );
        leases.restore(spool.open_counts());
        let freed = leases.clone();
        spool.on_close(move |tenant, count| freed.free(&tenant, count));

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
            cores,
            spool,
            sched,
            queues,
            leases,
            table,
            suppressions: parts.suppressions,
            config,
            writer: RefCell::new(writer),
            writing: Cell::new(false),
            restored,
        };
        let running = Running {
            done: vec![config_done, names_done, leases_done, sched_done],
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

    pub async fn rebind(&self, name: &Name, pool: u32) -> Result<u32, Error> {
        Ok(self.inner.queues.rebind(name, pool).await?)
    }

    pub fn close(&self) {
        let inner = &self.inner;
        inner.sched.close();
        inner.queues.close();
        inner.leases.close();
        inner.config.close();
    }
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
