use std::cell::{Cell, RefCell};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;

use api::Forward;
use control::Naming;
use crypto::Secret;
use deliver::Hooks;
use dns::Resolver;
use intake::{Ask, Guard, Listener, Watch, listen, watch};
use keys::{BatchSettings, Client, Connect, Ring, RingSettings};
use rt::{JoinHandle, Mesh, Notify, Peers, Signal, Signals, TcpListener, spawn, timeout};
use sched::{Clock, Keyring, Meshes, Node, Parts, Running, Settings, Transport};
use store::Core;
use tls::rustls::crypto::CryptoProvider;
use tls::{Acceptor, Certs, Connector};

use crate::report;
use crate::scrape;
use crate::{Config, Error};

const BACKLOG: u32 = 1024;
const NAMES: usize = 65_536;
const RETENTION: u16 = 30;
const STOP: [Signal; 3] = [Signal::Hangup, Signal::Interrupt, Signal::Terminate];

#[derive(Clone)]
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
    roots: Option<Vec<u8>>,
    meshes: Meshes,
    guards: Mesh<Ask>,
    orders: Mesh<Order>,
    forwards: Mesh<Forward>,
    board: Option<Arc<metrics::Board>>,
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
        let board = config
            .metrics
            .as_ref()
            .map(|m| scrape::board(cores, &m.tenants));
        Self {
            config,
            certs,
            provider,
            naming,
            guard,
            roots: None,
            meshes: Meshes::new(cores),
            guards: Mesh::new(cores),
            orders: Mesh::new(cores),
            forwards: Mesh::new(cores),
            board,
        }
    }

    #[must_use]
    pub fn with_roots(mut self, roots: Option<Vec<u8>>) -> Self {
        self.roots = roots;
        self
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn metrics(&self) -> Option<&metrics::Board> {
        self.board.as_deref()
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
    hooks: Rc<dyn sched::Deliver>,
    keys: Rc<Keyring>,
    sockets: Vec<(TcpListener, bool)>,
    apis: Vec<(TcpListener, bool, bool)>,
    scrapes: Vec<TcpListener>,
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
    let (watched, failed) = if index == 0 {
        lead(&plan, &orders, &peers).await
    } else {
        (None, None)
    };
    let up = match ready(starting, &orders, failed).await {
        Ok(up) => up,
        Err(e) => {
            peers.close();
            return Err(e);
        }
    };
    report::start(&up.node, &plan.config);
    let hooking = up.node.start_hooks(Rc::clone(&up.hooks));
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
    let apis: Option<api::Api> = plan.config.api.as_ref().map(|settings| {
        let sockets = up
            .apis
            .into_iter()
            .map(|(socket, secure, loopback)| api::Socket {
                socket,
                acceptor: secure.then(|| Rc::clone(&up.acceptor)),
                loopback,
            })
            .collect();
        let ends = plan.forwards.take(index).expect("forwards of each core");
        api::start(
            up.node.clone(),
            sockets,
            Rc::new(settings.settings.clone()),
            &up.guard,
            ends,
        )
    });
    let metrics = plan.board.as_ref().zip(plan.config.metrics.as_ref());
    let scrapes = scrape::listeners(metrics, up.scrapes);
    let sources = scrape::Sources {
        node: &up.node,
        smtp: &listeners,
        guard: &up.guard,
        keys: &up.keys,
        api: apis.as_ref(),
    };
    let publishing = scrape::publishing(metrics, index, sources);
    let stopping = stop(watched, &orders, &peers, cores);
    let stopped = scrape::alongside(stopping, publishing).await;
    let mut closing: Vec<_> = listeners
        .into_iter()
        .map(|listener| spawn(listener.close()))
        .collect();
    closing.extend(apis.into_iter().map(|api| spawn(api.close())));
    closing.extend(scrapes.into_iter().map(|scrape| spawn(scrape.close())));
    for closed in closing {
        closed.await;
    }
    halt(&up.guard, &up.node, up.running, up.guarding).await;
    drop(hooking);
    peers.close();
    stopped
}

async fn stop(
    watched: Option<Watch>,
    orders: &Orders,
    peers: &Peers<Order>,
    cores: u16,
) -> Result<(), Error> {
    if let Some(watched) = watched {
        let requested = watched.stop_requested().await;
        watched.close().await;
        for core in 1..cores {
            peers.send(core, Order::Stop);
        }
        requested.map(drop).map_err(Error::Io)
    } else {
        orders.until(|o| o.stop.get()).await;
        Ok(())
    }
}

async fn halt<T: Transport + 'static>(
    guard: &Guard,
    node: &Node<T>,
    running: Running,
    guarding: JoinHandle<()>,
) {
    guard.close();
    node.close();
    drop(running.stop().await);
    drop(guarding);
}

async fn ready<T: Transport + 'static>(
    starting: JoinHandle<Result<Up<T>, Error>>,
    orders: &Orders,
    failed: Option<Error>,
) -> Result<Up<T>, Error> {
    let up = started_or_stopped(starting, orders).await;
    if let Some(e) = failed {
        if let Some(Ok(up)) = up {
            halt(&up.guard, &up.node, up.running, up.guarding).await;
        }
        return Err(e);
    }
    let up = up.ok_or(Error::Stopped)??;
    orders.until(|o| o.go.get() || o.stop.get()).await;
    if !orders.go.get() {
        halt(&up.guard, &up.node, up.running, up.guarding).await;
        return Err(Error::Stopped);
    }
    Ok(up)
}

async fn started_or_stopped<T>(
    starting: JoinHandle<Result<Up<T>, Error>>,
    orders: &Orders,
) -> Option<Result<Up<T>, Error>> {
    let mut starting = pin!(starting);
    let mut stopped = pin!(orders.until(|o| o.stop.get()));
    poll_fn(|cx| match starting.as_mut().poll(cx) {
        Poll::Ready(up) => Poll::Ready(Some(up)),
        Poll::Pending => stopped.as_mut().poll(cx).map(|()| None),
    })
    .await
}

async fn lead(
    plan: &Plan,
    orders: &Orders,
    peers: &Peers<Order>,
) -> (Option<Watch>, Option<Error>) {
    let led = boot(plan, orders).await;
    let order = if led.is_ok() { Order::Go } else { Order::Stop };
    for core in 0..plan.config.cores {
        peers.send(core, order.clone());
    }
    match led {
        Ok(watching) => (Some(watching), None),
        Err(e) => (None, Some(e)),
    }
}

async fn boot(plan: &Plan, orders: &Orders) -> Result<Watch, Error> {
    timeout(plan.config.boot, orders.started(plan.config.cores))
        .await
        .map_err(|_| Error::Deadline)??;
    let signals = Signals::listen(&STOP).await.map_err(Error::Io)?;
    let tls = &plan.config.tls;
    Ok(watch(
        signals,
        Arc::clone(&plan.certs),
        tls.chain.clone(),
        tls.key.clone(),
    ))
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
        watched: config
            .metrics
            .as_ref()
            .map(|m| m.tenants.clone())
            .unwrap_or_default(),
    };
    let links = plan.meshes.take(index).expect("links of each core");
    let keys = Rc::new(Keyring::new(
        ring(config),
        RETENTION,
        BatchSettings::default(),
    ));
    let parts = Parts {
        keys: Rc::clone(&keys) as Rc<dyn sched::Keys>,
        transport,
        clock: Clock::at(rt::wall_ms(), rt::now()),
    };
    let (node, running) = Node::start(core, links, settings, parts)
        .await
        .map_err(Error::Start)?;
    let own = node.sched().transport().probe_own().await;
    if index == 0 {
        eprintln!(
            "bunzzle: own-address probing ipv4 {}, ipv6 {}, unclear {}",
            if own.ipv4_off { "off" } else { "on" },
            if own.ipv6_off { "off" } else { "on" },
            own.unclear,
        );
    }
    let acceptor =
        Acceptor::new(Arc::clone(&plan.provider), Arc::clone(&plan.certs)).map_err(Error::Tls)?;
    let hooks = hooks(&node, plan)?;
    let ends = plan.guards.take(index).expect("guard of each core");
    let (guard, guarding) = Guard::start(ends, plan.guard, config.limits);
    let mut sockets = Vec::with_capacity(config.listen.len());
    for listen in &config.listen {
        let socket = TcpListener::bind_shared(listen.address, BACKLOG)
            .await
            .map_err(|e| Error::Bind(listen.address, e))?;
        sockets.push((socket, listen.implicit));
    }
    let mut apis = Vec::new();
    if let Some(api) = &config.api {
        let tls = api.listen.iter().map(|a| (*a, true));
        let clear = api.plain.iter().map(|a| (*a, false));
        for (address, secure) in tls.chain(clear) {
            let socket = TcpListener::bind_shared(address, BACKLOG)
                .await
                .map_err(|e| Error::Bind(address, e))?;
            apis.push((socket, secure, address.ip().is_loopback()));
        }
    }
    let mut scrapes = Vec::new();
    if let Some(metrics) = &config.metrics {
        for address in &metrics.listen {
            let socket = TcpListener::bind_shared(*address, BACKLOG)
                .await
                .map_err(|e| Error::Bind(*address, e))?;
            scrapes.push(socket);
        }
    }
    Ok(Up {
        node,
        running,
        guard,
        guarding,
        acceptor: Rc::new(acceptor),
        hooks,
        keys,
        sockets,
        apis,
        scrapes,
    })
}

fn hooks<T: Transport + 'static>(
    node: &Node<T>,
    plan: &Plan,
) -> Result<Rc<dyn sched::Deliver>, Error> {
    let seed = Secret::<32>::random().map_err(|_| Error::Random)?;
    let resolver = Resolver::new(plan.config.dns.clone(), &seed);
    let tls =
        Connector::new(Arc::clone(&plan.provider), plan.roots.as_deref()).map_err(Error::Tls)?;
    let turn = Secret::<8>::random().map_err(|_| Error::Random)?;
    Ok(Rc::new(Hooks::new(
        node.clone(),
        resolver,
        tls,
        plan.config.webhooks.clone(),
        u64::from_le_bytes(*turn.expose()),
    )))
}
