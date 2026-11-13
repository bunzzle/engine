use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use control::Naming;
use intake::{Ask, Guard, Listener, listen, watch};
use keys::{BatchSettings, Client, Connect, Ring, RingSettings};
use rt::{JoinHandle, Mesh, Notify, Signal, Signals, TcpListener, spawn, timeout};
use sched::{Clock, Keyring, Meshes, Node, Parts, Running, Settings, Transport};
use store::Core;
use tls::rustls::crypto::CryptoProvider;
use tls::{Acceptor, Certs};

use crate::{Config, Error};

const BACKLOG: u32 = 1024;
const NAMES: usize = 65_536;
const RETENTION: u16 = 30;
const STOP: [Signal; 3] = [Signal::Hangup, Signal::Interrupt, Signal::Terminate];

enum Order {
    Started(Result<(), String>),
    Go,
    Stop,
}

pub struct Plan {
    config: Config,
    certs: Arc<Certs>,
    provider: Arc<CryptoProvider>,
    naming: [u8; 16],
    guard: [u8; 16],
    meshes: Meshes,
    guards: Mesh<Ask>,
    orders: Mesh<Order>,
}

impl Plan {
    pub fn new(
        config: Config,
        certs: Arc<Certs>,
        provider: Arc<CryptoProvider>,
        naming: [u8; 16],
        guard: [u8; 16],
    ) -> Self {
        let cores = config.cores;
        Self {
            config,
            certs,
            provider,
            naming,
            guard,
            meshes: Meshes::new(cores),
            guards: Mesh::new(cores),
            orders: Mesh::new(cores),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}

pub async fn naming(config: &Config) -> Result<[u8; 16], Error> {
    let ring = ring(config);
    ring.hello().await.map_err(Error::Keys)?;
    ring.naming().ok_or(Error::Keys(keys::Error::Bad))
}

fn ring(config: &Config) -> Ring {
    let socket = config.keys.socket.clone();
    let server = config.keys.server;
    let connect: Connect = Rc::new(move || {
        let socket = socket.clone();
        Box::pin(async move { Client::connect(&socket, server).await })
    });
    Ring::new(connect, RingSettings::new(config.id))
}

#[derive(Default)]
struct Orders {
    ready: Cell<u16>,
    failed: RefCell<Option<(u16, String)>>,
    go: Cell<bool>,
    stop: Cell<bool>,
    changed: Notify,
}

impl Orders {
    fn note(&self, from: u16, order: Order) {
        match order {
            Order::Started(Ok(())) => self.ready.set(self.ready.get() + 1),
            Order::Started(Err(message)) => {
                self.failed.borrow_mut().get_or_insert((from, message));
            }
            Order::Go => self.go.set(true),
            Order::Stop => self.stop.set(true),
        }
        self.changed.notify();
    }

    async fn until(&self, done: impl Fn(&Self) -> bool) {
        while !done(self) {
            self.changed.wait().await;
        }
    }

    async fn started(&self, cores: u16) -> Result<(), Error> {
        self.until(|o| o.failed.borrow().is_some() || o.ready.get() == cores)
            .await;
        match self.failed.borrow_mut().take() {
            Some((core, message)) => Err(Error::Core(core, message)),
            None => Ok(()),
        }
    }
}

struct Up<T> {
    node: Node<T>,
    running: Running,
    guard: Guard,
    guarding: JoinHandle<()>,
    acceptor: Rc<Acceptor>,
    sockets: Vec<(TcpListener, bool)>,
}

pub async fn run<T: Transport + 'static>(
    core: Core,
    plan: Arc<Plan>,
    transport: T,
) -> Result<(), Error> {
    let index = core.index;
    let cores = plan.config.cores;
    let orders = Rc::new(Orders::default());
    let ends = plan.orders.take(index).expect("orders of each core");
    let (peers, _) = {
        let orders = Rc::clone(&orders);
        ends.start(move |from, order| orders.note(from, order))
    };
    let starting = {
        let (plan, peers) = (Arc::clone(&plan), peers.clone());
        spawn(async move {
            let started = start(core, &plan, transport).await;
            let report = started.as_ref().map(drop).map_err(ToString::to_string);
            peers.send(0, Order::Started(report));
            started
        })
    };
    let mut watched = None;
    if index == 0 {
        timeout(plan.config.boot, orders.started(cores))
            .await
            .map_err(|_| Error::Deadline)??;
        let signals = Signals::listen(&STOP).await.map_err(Error::Io)?;
        let tls = &plan.config.tls;
        watched = Some(watch(
            signals,
            Arc::clone(&plan.certs),
            tls.chain.clone(),
            tls.key.clone(),
        ));
        for core in 0..cores {
            peers.send(core, Order::Go);
        }
    }
    let up = starting.await?;
    orders.until(|o| o.go.get() || o.stop.get()).await;
    let session = Rc::new(plan.config.session.clone());
    let listeners: Vec<Listener> = up
        .sockets
        .into_iter()
        .map(|(socket, implicit)| {
            listen(
                up.node.clone(),
                socket,
                Rc::clone(&up.acceptor),
                Rc::clone(&session),
                up.guard.clone(),
                implicit,
            )
        })
        .collect();
    let stopped = if let Some(watched) = watched {
        let requested = watched.stop_requested().await;
        watched.close().await;
        for core in 1..cores {
            peers.send(core, Order::Stop);
        }
        requested.map(drop).map_err(Error::Io)
    } else {
        orders.until(|o| o.stop.get()).await;
        Ok(())
    };
    let closing: Vec<_> = listeners
        .into_iter()
        .map(|listener| spawn(listener.close()))
        .collect();
    for closed in closing {
        closed.await;
    }
    up.guard.close();
    up.node.close();
    drop(up.running.stop().await);
    drop(up.guarding);
    peers.close();
    stopped
}

async fn start<T: Transport + 'static>(
    core: Core,
    plan: &Plan,
    transport: T,
) -> Result<Up<T>, Error> {
    let index = core.index;
    let config = &plan.config;
    let superblock = core.file.superblock();
    let shards = superblock.shards();
    let settings = Settings {
        node: config.id,
        spool: spool::Limits::default(),
        naming: Naming {
            key: plan.naming,
            shards,
            cache: NAMES,
        },
        sched: sched::Config::new(shards),
        budget: usize::try_from(superblock.region_size() / 2).unwrap_or(usize::MAX),
    };
    let links = plan.meshes.take(index).expect("links of each core");
    let keys = Keyring::new(ring(config), RETENTION, BatchSettings::default());
    let parts = Parts {
        keys: Rc::new(keys),
        transport,
        clock: Clock::at(rt::wall_ms(), rt::now()),
    };
    let (node, running) = Node::start(core, links, settings, parts)
        .await
        .map_err(Error::Start)?;
    let acceptor =
        Acceptor::new(Arc::clone(&plan.provider), Arc::clone(&plan.certs)).map_err(Error::Tls)?;
    let ends = plan.guards.take(index).expect("guard of each core");
    let (guard, guarding) = Guard::start(ends, plan.guard, config.limits);
    let mut sockets = Vec::with_capacity(config.listen.len());
    for listen in &config.listen {
        let socket = TcpListener::bind_shared(listen.address, BACKLOG)
            .await
            .map_err(|e| Error::Bind(listen.address, e))?;
        sockets.push((socket, listen.implicit));
    }
    Ok(Up {
        node,
        running,
        guard,
        guarding,
        acceptor: Rc::new(acceptor),
        sockets,
    })
}
