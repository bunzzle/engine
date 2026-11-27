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
use intake::{Ask, Guard, LOADS, Listener, Reports, Watch, listen, watch};
use keys::{BatchSettings, Client, Connect, Ring, RingSettings};
use rt::{
    JoinHandle, Mesh, Notify, Peers, Signal, Signals, TcpListener, UnixListener, spawn, timeout,
};
use sched::{Clock, Keyring, Meshes, Node, Parts, Running, Settings, Transport};
use store::Core;
use tls::rustls::crypto::CryptoProvider;
use tls::{Acceptor, Certs, Connector};

use crate::ops;
use crate::report;
use crate::scrape;
use crate::{Config, Error, Listen};

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
    mx_guards: Mesh<Ask>,
    orders: Mesh<Order>,
    forwards: Mesh<Forward>,
    board: Option<Arc<metrics::Board>>,
    engine: u32,
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
            mx_guards: Mesh::new(cores),
            orders: Mesh::new(cores),
            forwards: Mesh::new(cores),
            board,
            engine: sys::process::euid(),
        }
    }

    #[must_use]
    pub fn with_roots(mut self, roots: Option<Vec<u8>>) -> Self {
        self.roots = roots;
        self
    }

    #[must_use]
    pub fn with_engine(mut self, uid: u32) -> Self {
        self.engine = uid;
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
    mx: Guard,
    mx_guarding: JoinHandle<()>,
    acceptor: Rc<Acceptor>,
    hooks: Rc<dyn sched::Deliver>,
    keys: Rc<Keyring>,
    sockets: Vec<(TcpListener, bool, bool)>,
    apis: Vec<(TcpListener, bool, bool)>,
    scrapes: Vec<TcpListener>,
    admin: Option<UnixListener>,
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
    let listeners = smtp_listeners(
        &up.node,
        up.sockets,
        &up.acceptor,
        &plan.config.session,
        [&up.guard, &up.mx],
    );
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
    let admin = ops::serve(up.admin, &up.node, cores, plan.engine);
    let sources = scrape::Sources {
        node: &up.node,
        smtp: &listeners,
        guard: &up.guard,
        keys: &up.keys,
        api: apis.as_ref(),
        admin: admin.as_ref(),
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
    closing.extend(admin.into_iter().map(|admin| spawn(admin.close())));
    for closed in closing {
        closed.await;
    }
    halt(
        &up.node,
        up.running,
        [(up.guard, up.guarding), (up.mx, up.mx_guarding)],
    )
    .await;
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
    node: &Node<T>,
    running: Running,
    guards: [(Guard, JoinHandle<()>); 2],
) {
    for (guard, _) in &guards {
        guard.close();
    }
    node.close();
    drop(running.stop().await);
    drop(guards);
}

async fn ready<T: Transport + 'static>(
    starting: JoinHandle<Result<Up<T>, Error>>,
    orders: &Orders,
    failed: Option<Error>,
) -> Result<Up<T>, Error> {
    let up = started_or_stopped(starting, orders).await;
    if let Some(e) = failed {
        if let Some(Ok(up)) = up {
            halt(
                &up.node,
                up.running,
                [(up.guard, up.guarding), (up.mx, up.mx_guarding)],
            )
            .await;
        }
        return Err(e);
    }
    let up = up.ok_or(Error::Stopped)??;
    orders.until(|o| o.go.get() || o.stop.get()).await;
    if !orders.go.get() {
        halt(
            &up.node,
            up.running,
            [(up.guard, up.guarding), (up.mx, up.mx_guarding)],
        )
        .await;
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
    let ends = plan.mx_guards.take(index).expect("mx guard of each core");
    let (mx, mx_guarding) = Guard::start(ends, plan.guard, config.mx);
    let sockets = bind_smtp(&config.listen).await?;
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
    let admin = match &config.admin {
        Some(admin) if node.controls() => Some(
            UnixListener::bind(&admin.socket)
                .await
                .map_err(|e| Error::BindUnix(admin.socket.clone(), e))?,
        ),
        _ => None,
    };
    Ok(Up {
        node,
        running,
        guard,
        guarding,
        mx,
        mx_guarding,
        acceptor: Rc::new(acceptor),
        hooks,
        keys,
        sockets,
        apis,
        scrapes,
        admin,
    })
}

fn smtp_listeners<T: Transport + 'static>(
    node: &Node<T>,
    sockets: Vec<(TcpListener, bool, bool)>,
    acceptor: &Rc<Acceptor>,
    session: &intake::Config,
    [submission, mx]: [&Guard; 2],
) -> Vec<Listener> {
    let session = Rc::new(session.clone());
    let reports = Rc::new(Reports::new(LOADS));
    sockets
        .into_iter()
        .map(|(socket, implicit, is_mx)| {
            let (guard, reports) = if is_mx {
                (mx.clone(), Some(Rc::clone(&reports)))
            } else {
                (submission.clone(), None)
            };
            listen(
                node.clone(),
                socket,
                Rc::clone(acceptor),
                Rc::clone(&session),
                guard,
                implicit,
                reports,
            )
        })
        .collect()
}

async fn bind_smtp(listens: &[Listen]) -> Result<Vec<(TcpListener, bool, bool)>, Error> {
    let mut sockets = Vec::with_capacity(listens.len());
    for listen in listens {
        let socket = TcpListener::bind_shared(listen.address, BACKLOG)
            .await
            .map_err(|e| Error::Bind(listen.address, e))?;
        sockets.push((socket, listen.implicit, listen.mx));
    }
    Ok(sockets)
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
