use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

use control::{Label, Limits as TenantLimits, Name, Naming, Object, Pool, Sealer, State, Tenant};
use rt::sim::{Config, Disk, Faults, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, sleep, spawn, timeout};
use sched::{
    Answer, Answered, Attempt, Clock, Draft, Kind, Limits, Meshes, Node, Parts, Refusal, Running,
    Settings, Suppressions, Transport,
};
use spool::{Body, Head, HeadClear, Message, MessageId, SLICE, Slice};
use store::{Client, DataFile, Options, SLOT_SIZE, Setup, boot};

const PATH: &str = "/data/store";
const SHARDS: u16 = 8;
const MESSAGES: u64 = 12;
const SLACK: u64 = 1_000;
const HORIZON: Duration = Duration::from_hours(7 * 24);
const FIRST: Duration = Duration::from_mins(30);
const MILLION: u32 = 1_000_000;
const MOST: u32 = 1_373;
const TENANTS: [u32; 3] = [1, 2, 3];
const QUEUED_TWO: u64 = 1_500;
const QUEUED_THREE: u64 = 60;
const CHANGES: u32 = 30;

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 160,
    shards: SHARDS as u32,
};

const DOMAINS: [&str; 10] = [
    "example.org",
    "example.net",
    "mail.example.com",
    "a.example",
    "b.example",
    "xn--bcher-kva.example",
    "d-1.example",
    "f.g.h.example",
    "test",
    "z.example",
];

const REBOUND: [&str; 2] = ["example.org", "a.example"];

type Key = (u16, u64, u32);
type Named = (u32, Box<str>, u32);

#[derive(Default)]
struct World {
    nodes: Vec<Node<Simulated>>,
    cores: u16,
    accepted: BTreeMap<Key, (u32, Box<str>, u32)>,
    tenants: BTreeMap<(u16, u64), u32>,
    names: BTreeMap<Named, u32>,
    clashes: u64,
    finals: BTreeSet<Key>,
    misrouted: u64,
    wrong: u64,
    over: u64,
    refusals: BTreeMap<String, u64>,
    attempts: u64,
    restored: u64,
    writes: u64,
    rebinds: u64,
}

type Shared = Rc<RefCell<World>>;

fn key(id: MessageId, r: u32) -> Key {
    (id.shard, id.key, r)
}

fn queued_limit(tenant: u32) -> u64 {
    match tenant {
        2 => QUEUED_TWO,
        3 => QUEUED_THREE,
        _ => 0,
    }
}

fn tenant(id: u32, rate: u32, state: State) -> Object {
    let limits = match id {
        2 => TenantLimits {
            rate,
            burst: 500,
            queued: QUEUED_TWO,
        },
        3 => TenantLimits {
            rate: 100,
            burst: 20,
            queued: QUEUED_THREE,
        },
        _ => TenantLimits::default(),
    };
    Object::Tenant(Tenant {
        id,
        generation: 1,
        state,
        default_pool: 1,
        pools: vec![1, 2],
        limits,
    })
}

fn pool(id: u32) -> Object {
    let octet = u8::try_from(id).expect("small");
    Object::Pool(Pool {
        id,
        addresses: vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), 1)],
    })
}

struct Toy;

fn label_bytes(label: &Label) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&label.tenant.to_le_bytes());
    out.extend_from_slice(&label.generation.to_le_bytes());
    out.push(label.kind);
    out.extend_from_slice(&label.id.to_le_bytes());
    out
}

impl Sealer for Toy {
    fn seal(&self, label: &Label, clear: &[u8]) -> Vec<u8> {
        let mut out = label_bytes(label);
        out.extend(clear.iter().map(|b| b ^ 0x5a));
        out
    }

    fn open(&self, label: &Label, sealed: &[u8]) -> Option<Vec<u8>> {
        let rest = sealed.strip_prefix(label_bytes(label).as_slice())?;
        Some(rest.iter().map(|b| b ^ 0x5a).collect())
    }
}

struct Blocked;

impl Suppressions for Blocked {
    fn suppressed(&self, _: u32, address: &str) -> bool {
        address.starts_with("blocked")
    }
}

struct Simulated {
    world: Shared,
    driver: Rc<SimDriver>,
    core: u16,
}

impl Simulated {
    fn below(&self, n: u64) -> u64 {
        self.driver.random() % n
    }

    fn answer(&self) -> Answer {
        match self.below(20) {
            0..=10 => Answer::Delivered,
            11..=12 => Answer::Failed,
            13..=15 => Answer::Deferred(Kind::Temporary),
            16 => Answer::Deferred(Kind::Greylisted),
            17 => Answer::Deferred(Kind::Throttled),
            _ => Answer::Deferred(Kind::RetryAfter(self.below(600_000))),
        }
    }
}

impl Transport for Simulated {
    async fn send(&self, attempt: Attempt) -> Vec<Answered> {
        {
            let mut world = self.world.borrow_mut();
            world.attempts += 1;
            let entry = world.nodes[usize::from(self.core)]
                .queues()
                .entry(attempt.queue);
            for c in &attempt.recipients {
                let k = key(attempt.message, c.recipient);
                let Some((tenant, domain, queue)) = world.accepted.get(&k).cloned() else {
                    world.misrouted += 1;
                    continue;
                };
                if queue != attempt.queue || tenant != attempt.tenant {
                    world.misrouted += 1;
                }
                let right = entry.as_ref().is_some_and(|e| {
                    e.name.tenant == tenant && e.name.domain == domain && e.name.generation == 1
                });
                if !right {
                    world.wrong += 1;
                }
            }
        }
        sleep(Duration::from_millis(1 + self.below(2_000))).await;
        let mut world = self.world.borrow_mut();
        attempt
            .recipients
            .iter()
            .map(|c| {
                let answer = self.answer();
                if matches!(answer, Answer::Delivered | Answer::Failed) {
                    world.finals.insert(key(attempt.message, c.recipient));
                }
                Answered {
                    recipient: c.recipient,
                    answer,
                    reply: Vec::new(),
                }
            })
            .collect()
    }
}

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

fn settings() -> Settings {
    Settings {
        node: 3,
        spool: spool::Limits {
            recipients: MOST,
            inline: 2048,
            body: 512 * 1024,
        },
        naming: Naming {
            key: *b"naming key 16 by",
            shards: u32::from(SHARDS),
            cache: 16,
        },
        sched: sched::Config {
            limits: Limits {
                active: 60,
                queue: 12,
                batch: 25,
                ..Limits::default()
            },
            slack: SLACK,
            ..sched::Config::new(u32::from(SHARDS))
        },
        budget: usize::try_from(OPTIONS.region_size / 2).expect("fits"),
    }
}

fn refused(world: &Shared, refusal: Refusal) {
    *world
        .borrow_mut()
        .refusals
        .entry(format!("{refusal:?}"))
        .or_default() += 1;
}

fn open_total(world: &World, tenant: u32) -> u64 {
    world
        .nodes
        .iter()
        .flat_map(|n| n.spool().open_counts())
        .filter(|(t, _)| *t == tenant)
        .map(|(_, n)| n)
        .sum()
}

fn note_name(world: &mut World, tenant: u32, domain: &str, pool: u32, queue: u32) {
    if REBOUND.contains(&domain) {
        return;
    }
    let name = (tenant, Box::from(domain), pool);
    if let Some(old) = world.names.insert(name, queue)
        && old != queue
    {
        world.clashes += 1;
    }
}

async fn recipients(
    node: &Node<Simulated>,
    draft: &mut Draft,
    count: u32,
    driver: &SimDriver,
    world: &Shared,
) -> Option<Vec<Box<str>>> {
    let mut domains = Vec::new();
    for r in 0..count {
        let domain = DOMAINS[usize::try_from(driver.random() % 10).expect("small")];
        let address = if driver.random().is_multiple_of(50) {
            format!("blocked{r}@{domain}")
        } else {
            format!("r{r}@{}", domain.to_ascii_uppercase())
        };
        let mut tries = 0;
        loop {
            match node.recipient(draft, &address).await {
                Ok(queue) => {
                    note_name(
                        &mut world.borrow_mut(),
                        draft.tenant(),
                        domain,
                        draft.pool(),
                        queue,
                    );
                    domains.push(Box::from(domain));
                    break;
                }
                Err(Refusal::Suppressed) => {
                    refused(world, Refusal::Suppressed);
                    break;
                }
                Err(Refusal::Busy) if tries < 40 => {
                    refused(world, Refusal::Busy);
                    tries += 1;
                    sleep(Duration::from_millis(50 + driver.random() % 400)).await;
                }
                Err(refusal) => {
                    refused(world, refusal);
                    return None;
                }
            }
        }
    }
    Some(domains)
}

fn message(id: MessageId, draft: &Draft, now: u64) -> Message {
    let queues = draft.queues();
    let slices = queues
        .chunks(SLICE as usize)
        .map(|chunk| Slice {
            queues: chunk.to_vec(),
            sealed: vec![6; 4 * chunk.len()],
        })
        .collect();
    Message {
        id,
        tenant: draft.tenant(),
        head: Head {
            clear: HeadClear {
                recipients: u32::try_from(queues.len()).expect("fits"),
                accepted: now,
                ..HeadClear::default()
            },
            expiry: u64::MAX / 2,
            sealed: vec![1; 64],
        },
        body: Body::Inline(vec![2; 300]),
        slices,
    }
}

async fn intake(node: Node<Simulated>, shards: Vec<u16>, driver: Rc<SimDriver>, world: Shared) {
    for n in 0..MESSAGES {
        let shard = shards[usize::try_from(n).expect("small") % shards.len()];
        let tenant = TENANTS[usize::try_from(driver.random() % 3).expect("small")];
        let count = if tenant == 1 && driver.random().is_multiple_of(8) {
            MOST - u32::try_from(driver.random() % 40).expect("small")
        } else {
            1 + u32::try_from(driver.random() % 40).expect("small")
        };
        let pool = driver.random().is_multiple_of(3).then_some(2);
        let mut draft = match node.draft(tenant, pool) {
            Ok(draft) => draft,
            Err(refusal) => {
                refused(&world, refusal);
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let Some(domains) = recipients(&node, &mut draft, count, &driver, &world).await else {
            continue;
        };
        if domains.is_empty() {
            continue;
        }
        let Ok(id) = node.spool().id(shard).await else {
            return;
        };
        let message = message(id, &draft, node.sched().clock().now());
        let queues = draft.queues().to_vec();
        world
            .borrow_mut()
            .tenants
            .insert((id.shard, id.key), tenant);
        match node.accept(draft, message).await {
            Ok(()) => {
                let mut world = world.borrow_mut();
                for (r, (domain, queue)) in (0..).zip(domains.into_iter().zip(queues)) {
                    world.accepted.insert(key(id, r), (tenant, domain, queue));
                }
                let limit = queued_limit(tenant);
                if limit > 0 && open_total(&world, tenant) > limit {
                    world.over += 1;
                }
            }
            Err(refusal) => refused(&world, refusal),
        }
        if driver.random().is_multiple_of(3) {
            sleep(Duration::from_millis(driver.random() % 500)).await;
        }
    }
}

async fn admin(
    node: Node<Simulated>,
    driver: Rc<SimDriver>,
    world: Shared,
    running: Rc<Cell<bool>>,
) {
    let mut suspended = false;
    for _ in 0..CHANGES {
        if !running.get() {
            break;
        }
        sleep(Duration::from_millis(500 + driver.random() % 2_000)).await;
        let change = if driver.random().is_multiple_of(2) {
            suspended = !suspended;
            let state = if suspended {
                State::Suspended
            } else {
                State::Active
            };
            tenant(3, 500, state)
        } else {
            let rate = 1_000 + u32::try_from(driver.random() % 9_000).expect("small");
            tenant(2, rate, State::Active)
        };
        if node.write(change).await.is_ok() {
            world.borrow_mut().writes += 1;
        }
    }
    if suspended && node.write(tenant(3, 500, State::Active)).await.is_ok() {
        world.borrow_mut().writes += 1;
    }
}

async fn rebinder(
    node: Node<Simulated>,
    core: u16,
    driver: Rc<SimDriver>,
    world: Shared,
    running: Rc<Cell<bool>>,
) {
    for _ in 0..CHANGES {
        if !running.get() {
            break;
        }
        sleep(Duration::from_millis(300 + driver.random() % 3_000)).await;
        let tenant = TENANTS[usize::try_from(driver.random() % 3).expect("small")];
        let domain = REBOUND[usize::try_from(driver.random() % 2).expect("small")];
        if node.queues().naming_core(tenant, domain) != core {
            continue;
        }
        let from = 1 + u32::try_from(driver.random() % 2).expect("small");
        let name = Name {
            tenant,
            domain: domain.into(),
            generation: 1,
            pool: from,
        };
        if node.rebind(&name, 3 - from).await.is_ok() {
            world.borrow_mut().rebinds += 1;
        }
    }
}

async fn setup(node: &Node<Simulated>, world: &Shared) -> bool {
    let missing: Vec<Object> = {
        let table = node.table();
        let mut objects = Vec::new();
        for id in [1, 2] {
            if table.pool(id).is_none() {
                objects.push(pool(id));
            }
        }
        for id in TENANTS {
            if table.tenant(id).is_none_or(|t| t.state != State::Active) {
                objects.push(tenant(id, 5_000, State::Active));
            }
        }
        objects
    };
    for object in missing {
        if node.write(object).await.is_err() {
            return false;
        }
        world.borrow_mut().writes += 1;
    }
    true
}

async fn ready(node: &Node<Simulated>) {
    loop {
        let all = {
            let table = node.table();
            TENANTS
                .iter()
                .all(|t| table.tenant(*t).is_some_and(|t| t.state == State::Active))
        };
        if all {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn settle(world: &Shared) {
    loop {
        sleep(Duration::from_secs(10)).await;
        let empty = world
            .borrow()
            .nodes
            .iter()
            .all(|n| n.spool().messages().is_empty());
        if empty {
            return;
        }
    }
}

fn ticker(client: Client, running: Rc<Cell<bool>>) -> JoinHandle<()> {
    spawn(async move {
        while running.get() {
            sleep(Duration::from_secs(20)).await;
            if client.checkpoint().await.is_err() {
                return;
            }
        }
    })
}

async fn halted(driver: Rc<SimDriver>) {
    while !driver.is_halted() {
        sleep(Duration::from_secs(1)).await;
    }
}

#[derive(Default)]
struct Session {
    finished: bool,
    refused: u64,
    versions: BTreeSet<u64>,
    tables: BTreeSet<String>,
    leaked: u64,
}

fn start(
    machine: &Machine,
    starts: Vec<store::Start>,
    driver: &Rc<SimDriver>,
    world: &Shared,
    cores: u16,
) -> Option<(Vec<Running>, Vec<Vec<u16>>)> {
    let meshes = std::sync::Arc::new(Meshes::new(cores));
    let mut tasks = Vec::new();
    for start in starts {
        let index = start.index();
        let links = meshes.take(index).expect("links");
        let transport = Simulated {
            world: Rc::clone(world),
            driver: Rc::clone(driver),
            core: index,
        };
        tasks.push(machine.spawn_on(usize::from(index) + 1, async move {
            let core = timeout(Duration::from_secs(60), start.open())
                .await
                .ok()?
                .ok()?;
            let shards = core.shards.clone();
            let parts = Parts {
                sealer: Rc::new(Toy),
                suppressions: Rc::new(Blocked),
                transport,
                clock: Clock::start(),
            };
            let started = Node::start(core, links, settings(), parts);
            let (node, running) = timeout(Duration::from_secs(60), started).await.ok()?.ok()?;
            Some((node, running, shards))
        }));
    }
    let started = machine.block_on(0, async move {
        let mut started = Vec::new();
        for task in tasks {
            started.push(task.await);
        }
        started
    });
    let mut runnings = Vec::new();
    let mut shards = Vec::new();
    let mut world = world.borrow_mut();
    world.nodes.clear();
    world.cores = cores;
    for one in started {
        let (node, running, owned) = one?;
        world.restored += node.restored();
        world.nodes.push(node);
        runnings.push(running);
        shards.push(owned);
    }
    Some((runnings, shards))
}

struct Tasks {
    work: Vec<JoinHandle<()>>,
    side: Vec<JoinHandle<()>>,
}

fn spawn_tasks(
    machine: &Machine,
    shards: &[Vec<u16>],
    driver: &Rc<SimDriver>,
    world: &Shared,
    running: &Rc<Cell<bool>>,
) -> Tasks {
    let nodes = world.borrow().nodes.clone();
    let mut tasks = Tasks {
        work: Vec::new(),
        side: Vec::new(),
    };
    for (index, node) in nodes.iter().enumerate() {
        let core = index + 1;
        let waited = node.clone();
        tasks
            .work
            .push(machine.spawn_on(core, async move { ready(&waited).await }));
        let at = u16::try_from(index).expect("small");
        let rebinds = rebinder(
            node.clone(),
            at,
            Rc::clone(driver),
            Rc::clone(world),
            Rc::clone(running),
        );
        tasks.side.push(machine.spawn_on(core, rebinds));
        let feed = intake(
            node.clone(),
            shards[index].clone(),
            Rc::clone(driver),
            Rc::clone(world),
        );
        tasks.work.push(machine.spawn_on(core, feed));
    }
    let changes = admin(
        nodes[0].clone(),
        Rc::clone(driver),
        Rc::clone(world),
        Rc::clone(running),
    );
    tasks.side.push(machine.spawn_on(1, changes));
    tasks
}

fn observe(nodes: &[Node<Simulated>], finished: bool) -> Session {
    let mut session = Session {
        finished,
        ..Session::default()
    };
    for node in nodes {
        session.refused += node.sched().refused();
        let table = node.table();
        session.versions.insert(table.version());
        session
            .tables
            .insert(format!("{:?}", table.tenants().collect::<Vec<_>>()));
        for (tenant, open) in node.spool().open_counts() {
            if node.leases().used(&tenant) != open && queued_limit(tenant) > 0 {
                session.leaked += 1;
            }
        }
        for tenant in TENANTS {
            let open = node.spool().open_counts().iter().any(|(t, _)| *t == tenant);
            if !open && node.leases().used(&tenant) > 0 {
                session.leaked += 1;
            }
        }
    }
    session
}

fn session(
    driver: &Rc<SimDriver>,
    world: &Shared,
    cores: u16,
    limit: Duration,
    started: impl FnOnce(&World),
) -> Session {
    let stalls = Stalls {
        per_mille: 50,
        max: Duration::from_millis(5),
    };
    let machine = Machine::new(Rc::clone(driver), usize::from(cores) + 1, stalls);
    let setup_store = Setup {
        cores,
        credits: 4,
        reserve: 4,
    };
    let Ok(Ok(booted)) = machine.block_on(0, async move {
        timeout(Duration::from_secs(60), boot(PATH, setup_store)).await
    }) else {
        return Session::default();
    };
    let committer = machine.spawn_on(0, booted.committer.run());
    let Some((runnings, shards)) = start(&machine, booted.starts, driver, world, cores) else {
        return Session::default();
    };
    started(&world.borrow());
    let running = Rc::new(Cell::new(true));
    let nodes = world.borrow().nodes.clone();
    let configured = {
        let node = nodes[0].clone();
        let world = Rc::clone(world);
        machine.block_on(1, async move {
            timeout(Duration::from_secs(60), setup(&node, &world))
                .await
                .unwrap_or(false)
        })
    };
    if !configured {
        return Session::default();
    }
    let Tasks { work, side } = spawn_tasks(&machine, &shards, driver, world, &running);
    let client = booted.client;
    let watched = Rc::clone(world);
    let power = Rc::clone(driver);
    machine.block_on(0, async move {
        let ticker = ticker(client.clone(), Rc::clone(&running));
        let settled = Rc::clone(&watched);
        let mut all = pin!(async move {
            for task in work {
                task.await;
            }
            settle(&settled).await;
        });
        let mut halt = pin!(halted(Rc::clone(&power)));
        let race = poll_fn(|cx| {
            if all.as_mut().poll(cx).is_ready() {
                return Poll::Ready(true);
            }
            halt.as_mut().poll(cx).map(|()| false)
        });
        let finished = matches!(timeout(limit, race).await, Ok(true));
        running.set(false);
        if power.is_halted() {
            return Session::default();
        }
        let wind = async {
            for task in side {
                task.await;
            }
            sleep(Duration::from_secs(1)).await;
        };
        let _ = timeout(Duration::from_secs(600), wind).await;
        let session = observe(&nodes, finished);
        let stop = async move {
            ticker.await;
            for node in &nodes {
                node.close();
            }
            for running in runnings {
                drop(running.stop().await);
            }
            drop(nodes);
            watched.borrow_mut().nodes.clear();
            drop(client);
            drop(committer.await);
        };
        let _ = timeout(Duration::from_secs(600), stop).await;
        session
    })
}

fn verify(seed: u64, world: &World, run: &Session) {
    assert!(run.finished, "seed {seed}: not every message finished");
    assert_eq!(run.refused, 0, "seed {seed}: enqueue refused");
    assert_eq!(run.leaked, 0, "seed {seed}: slots not freed");
    assert_eq!(run.versions.len(), 1, "seed {seed}: versions differ");
    assert_eq!(run.tables.len(), 1, "seed {seed}: tables differ");
    assert_eq!(
        world.misrouted, 0,
        "seed {seed}: attempt in the wrong queue"
    );
    assert_eq!(world.wrong, 0, "seed {seed}: queue entry does not match");
    assert_eq!(world.clashes, 0, "seed {seed}: one name, two ids");
    assert_eq!(world.over, 0, "seed {seed}: queued over the limit");
    assert!(world.attempts > 0, "seed {seed}: nothing attempted");
    assert!(
        world.refusals.contains_key("Suppressed"),
        "seed {seed}: no suppressed recipient"
    );
}

fn names_survive(seed: u64, world: &World) {
    for ((tenant, domain, pool), id) in &world.names {
        let name = Name {
            tenant: *tenant,
            domain: domain.clone(),
            generation: 1,
            pool: *pool,
        };
        let core = world.nodes[0].queues().naming_core(*tenant, domain);
        let owned = world.nodes[usize::from(core)].queues().owned(&name);
        assert_eq!(owned, Some(*id), "seed {seed}: {name:?} changed id");
    }
}

fn one_session(seed: u64, cores: u16) {
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let world: Shared = Rc::default();
    let run = session(&driver, &world, cores, HORIZON, |_| {});
    verify(seed, &world.borrow(), &run);
    assert_eq!(
        run.versions.first().copied(),
        Some(world.borrow().writes),
        "seed {seed}: version gap"
    );
}

fn restart(seed: u64, cores: u16) {
    let world: Shared = Rc::default();
    let config = Config {
        halt_after: Some(2_000 + seed * 7_919 % 6_000),
        faults: Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        },
        ..Config::default()
    };
    let first = Rc::new(SimDriver::with_disk(seed, config, created(seed)));
    session(&first, &world, cores, FIRST, |_| {});
    let second = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        first.crash(),
    ));
    let run = session(&second, &world, cores, HORIZON, |world| {
        names_survive(seed, world);
    });
    verify(seed, &world.borrow(), &run);
    assert!(world.borrow().restored > 0, "seed {seed}: nothing restored");
}

#[test]
fn intake_names_limits_and_delivers_on_two_cores() {
    check(0..4, |seed| one_session(seed, 2));
}

#[test]
fn intake_names_limits_and_delivers_on_four_cores() {
    check(0..4, |seed| one_session(seed, 4));
}

#[test]
fn start_order_restores_everything_after_a_crash() {
    check(0..6, |seed| restart(seed, 2 + 2 * u16::from(seed % 2 == 1)));
}

async fn refusals(nodes: Vec<Node<Simulated>>, shard: u16) {
    let node = &nodes[0];
    assert_eq!(node.draft(9, None).err(), Some(Refusal::Tenant));
    assert_eq!(node.draft(1, Some(7)).err(), Some(Refusal::Pool));
    let mut draft = node.draft(1, None).expect("draft");
    assert_eq!(draft.pool(), 1);
    for bad in [
        "nobody",
        "@example.org",
        "a@-bad.example",
        "a@exa mple.org",
        "a@",
    ] {
        assert_eq!(node.recipient(&mut draft, bad).await, Err(Refusal::Address));
    }
    assert_eq!(
        node.recipient(&mut draft, "blocked@example.org").await,
        Err(Refusal::Suppressed)
    );
    let queue = node
        .recipient(&mut draft, "Someone@Example.ORG")
        .await
        .expect("named");
    let core = usize::from(node.queues().naming_core(1, "example.org"));
    let entry = nodes[core].queues().entry(queue).expect("entry");
    assert_eq!((entry.name.tenant, &*entry.name.domain), (1, "example.org"));
    assert_eq!(draft.queues(), &[queue]);
    let id = node.spool().id(shard).await.expect("id");
    let mut wrong = message(id, &draft, 0);
    wrong.tenant = 2;
    assert_eq!(node.accept(draft, wrong).await, Err(Refusal::Message));
    let mut draft = node.draft(1, None).expect("draft");
    node.recipient(&mut draft, "b@example.org")
        .await
        .expect("named");
    let mut wrong = message(id, &draft, 0);
    wrong.slices[0].queues[0] += 1;
    assert_eq!(node.accept(draft, wrong).await, Err(Refusal::Message));

    let mut draft = node.draft(2, Some(2)).expect("draft");
    for r in 0..10 {
        node.recipient(&mut draft, &format!("r{r}@a.example"))
            .await
            .expect("taken");
    }
    assert_eq!(node.leases().used(&2), 10);
    drop(draft);
    assert_eq!(node.leases().used(&2), 0);

    let mut draft = node.draft(3, None).expect("draft");
    node.write(tenant(3, 100, State::Suspended))
        .await
        .expect("suspend");
    while node
        .table()
        .tenant(3)
        .is_some_and(|t| t.state == State::Active)
    {
        sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        node.recipient(&mut draft, "x@b.example").await,
        Err(Refusal::Tenant)
    );
    assert_eq!(node.draft(3, None).err(), Some(Refusal::Tenant));
    assert!(!Refusal::Tenant.temporary() && Refusal::Busy.temporary());
}

#[test]
fn intake_refuses_what_the_rules_forbid() {
    let seed = 5;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let world: Shared = Rc::default();
    let machine = Machine::new(Rc::clone(&driver), 3, Stalls::default());
    let setup_store = Setup {
        cores: 2,
        credits: 4,
        reserve: 4,
    };
    let booted = machine.block_on(0, boot(PATH, setup_store)).expect("boot");
    let committer = machine.spawn_on(0, booted.committer.run());
    let (runnings, shards) = start(&machine, booted.starts, &driver, &world, 2).expect("start");
    let nodes = world.borrow().nodes.clone();
    let configured = {
        let node = nodes[0].clone();
        let world = Rc::clone(&world);
        machine.block_on(1, async move { setup(&node, &world).await })
    };
    assert!(configured);
    let checked = nodes.clone();
    let shard = shards[0][0];
    machine.block_on(1, async move {
        ready(&checked[0]).await;
        refusals(checked, shard).await;
    });
    let client = booted.client;
    machine.block_on(0, async move {
        for node in &nodes {
            node.close();
        }
        for running in runnings {
            drop(running.stop().await);
        }
        drop(nodes);
        world.borrow_mut().nodes.clear();
        drop(client);
        drop(committer.await);
    });
}
