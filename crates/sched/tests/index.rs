use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

use aws_lc_rs::signature::{ED25519, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use control::{
    Created, Dkim, KeyError, KeySource, Naming, Object, Pool, Ready, State, Table, Tenant,
};
use crypto::{BatchKey, DkimAlg, Secret, Tenant as Root, TenantKeys, Wrap, day_public, open_batch};
use index::{Entry, Op};
use keys::{
    Audit, BatchSettings, Batches, Client as KeyClient, Connect, Ring, RingSettings, Server,
    Settings as KeySettings, Vault, Working,
};
use rt::sim::{Config, Disk, Faults, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, TcpListener, TcpStream, sleep, spawn, timeout};
use sched::{
    Answered, Attempt, Batched, Begun, Clock, DAY, Draft, Hash, KIND_REQUEST, KIND_SUPPRESS,
    Keyring, Keys, Meshes, Node, Parts, Reason, Refusal, Running, SHAPE, Settings, Suppression,
    Ticket, Transport, Unsealable, Unwrapped, normalize, punycode, retain, retain_request,
};
use spool::{Body, Head, HeadClear, Message, MessageId, SLICE, Slice, Stamp};
use store::{Client, Committer, DataFile, Options, SLOT_SIZE, Setup, Tiering, boot};

const PATH: &str = "/data/store";
const SHARDS: u16 = 8;

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 96,
    shards: SHARDS as u32,
};

struct Toy {
    batches: RefCell<Batches>,
}

impl Default for Toy {
    fn default() -> Self {
        Self {
            batches: RefCell::new(Batches::new(BatchSettings::default())),
        }
    }
}

const KEYLESS: u32 = 199;
const NO_CREATE: u32 = 198;

impl KeySource for Toy {
    fn get(&self, tenant: u32, generation: u32) -> Option<TenantKeys> {
        if tenant == KEYLESS {
            return None;
        }
        let root = Root::new(&Secret::new(
            [u8::try_from(tenant % 200).expect("small"); 32],
        ));
        Some(TenantKeys::derive(tenant, generation, &root, 1))
    }

    fn create(&self, tenant: u32, _: u32) -> Created<'_> {
        let created = if tenant == NO_CREATE {
            Err(KeyError::Unavailable)
        } else {
            Ok(())
        };
        Box::pin(std::future::ready(created))
    }

    fn ready(&self, tenant: u32, generation: u32) -> Ready<'_> {
        let missing = if tenant == KEYLESS {
            KeyError::Unavailable
        } else {
            KeyError::Unknown
        };
        Box::pin(std::future::ready(
            self.get(tenant, generation).ok_or(missing),
        ))
    }
}

const TOY_DAY: u32 = 20_000;

fn toy_day_secret(tenant: u32, day: u32) -> Secret<32> {
    let mut bytes = [9; 32];
    bytes[..4].copy_from_slice(&tenant.to_le_bytes());
    bytes[4..8].copy_from_slice(&day.to_le_bytes());
    Secret::new(bytes)
}

impl Keys for Toy {
    fn batch(&self, tenant: u32, generation: u32, shard: u16, first: u64) -> Batched<'_> {
        let batch = match self.get(tenant, generation) {
            Some(keys) => {
                let public = |day| day_public(&toy_day_secret(tenant, day)).expect("public");
                let working = Working {
                    keys,
                    day: TOY_DAY,
                    oldest: TOY_DAY,
                    today: public(TOY_DAY),
                    tomorrow: public(TOY_DAY + 1),
                    seen: TOY_DAY,
                };
                self.batches
                    .borrow_mut()
                    .seal(&working, shard, first, rt::now())
                    .map_err(|_| KeyError::Unavailable)
            }
            None => Err(KeyError::Unavailable),
        };
        Box::pin(std::future::ready(batch))
    }

    fn batch_key(
        &self,
        tenant: u32,
        generation: u32,
        shard: u16,
        id: u64,
        wrap: Wrap,
    ) -> Unwrapped<'_> {
        let key = if (wrap.generation, wrap.shard) == (generation, shard) {
            open_batch(&toy_day_secret(tenant, wrap.day), tenant, id, &wrap)
                .map(|secret| Rc::new(BatchKey::new(&secret)))
                .map_err(|_| Unsealable::Bad)
        } else {
            Err(Unsealable::Bad)
        };
        Box::pin(std::future::ready(key))
    }
}

struct Idle;

impl Transport for Idle {
    fn send(&self, _: Attempt) -> impl Future<Output = Vec<Answered>> {
        std::future::ready(Vec::new())
    }
}

struct Cluster {
    machine: Machine,
    nodes: Vec<Node<Idle>>,
    runnings: Vec<Running>,
    client: Client,
    committer: JoinHandle<Committer>,
}

impl Cluster {
    fn run<T: 'static>(&self, future: impl Future<Output = T> + 'static) -> T {
        self.machine.block_on(1, future)
    }

    fn stop(self) {
        let Self {
            machine,
            nodes,
            runnings,
            client,
            committer,
        } = self;
        machine.block_on(0, async move {
            for node in &nodes {
                node.close();
            }
            for running in runnings {
                drop(running.stop().await);
            }
            drop(nodes);
            drop(client);
            drop(committer.await);
        });
    }
}

fn created(seed: u64) -> Disk {
    created_with(seed, OPTIONS)
}

fn created_with(seed: u64, options: Options) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async move {
        DataFile::create(PATH, &options).await.expect("create");
    });
    setup.crash()
}

const SMALL: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 24,
    shards: SHARDS as u32,
};

const NAMING: [u8; 16] = *b"naming key 16 by";

fn settings_named(key: [u8; 16]) -> Settings {
    Settings {
        node: 3,
        spool: spool::Limits {
            recipients: 100,
            inline: 2048,
            body: 64 * 1024,
        },
        naming: Naming {
            key,
            shards: u32::from(SHARDS),
            cache: 16,
        },
        sched: sched::Config::new(u32::from(SHARDS)),
        budget: usize::try_from(OPTIONS.region_size / 2).expect("fits"),
    }
}

fn tenant(id: u32, generation: u32, state: State) -> Object {
    Object::Tenant(Tenant {
        id,
        generation,
        state,
        default_pool: 1,
        pools: vec![1],
        limits: control::Limits::default(),
    })
}

fn started(driver: &Rc<SimDriver>, cores: u16) -> Cluster {
    started_behind(driver, cores, 0)
}

fn started_behind(driver: &Rc<SimDriver>, cores: u16, behind: u64) -> Cluster {
    started_tuned(driver, cores, behind, None)
}

fn started_tuned(
    driver: &Rc<SimDriver>,
    cores: u16,
    behind: u64,
    tuning: Option<(u64, usize)>,
) -> Cluster {
    try_started(driver, cores, behind, tuning, false, NAMING).expect("start")
}

fn started_with_keys(driver: &Rc<SimDriver>, cores: u16) -> Cluster {
    try_started(driver, cores, 0, None, true, NAMING).expect("start")
}

const KEYS_DIR: &str = "/keys";
const KEYS_AT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 7000);

fn keys_up(machine: &Machine) {
    drop(machine.spawn_on(0, async {
        let dir = Path::new(KEYS_DIR);
        let vault = match Vault::open(dir).await {
            Ok(vault) => vault,
            Err(_) => Vault::init(dir, 20_000).await.expect("init"),
        };
        let audit = Audit::open(dir).await.expect("audit");
        let server = Rc::new(Server::start(vault, audit, KeySettings::default()));
        let listener = TcpListener::bind(KEYS_AT, 16).await.expect("bind");
        while let Ok((stream, _)) = listener.accept().await {
            server.serve(stream);
        }
    }));
}

fn keyring() -> Rc<dyn Keys> {
    let connect: Connect =
        Rc::new(|| Box::pin(async { Ok(KeyClient::new(TcpStream::connect(KEYS_AT).await?)) }));
    Rc::new(Keyring::new(
        Ring::new(connect, RingSettings::new(1)),
        30,
        BatchSettings::default(),
    ))
}

async fn keys_listening() {
    for _ in 0..100 {
        if TcpStream::connect(KEYS_AT).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("keys not listening");
}

fn try_started(
    driver: &Rc<SimDriver>,
    cores: u16,
    behind: u64,
    tuning: Option<(u64, usize)>,
    real_keys: bool,
    naming: [u8; 16],
) -> Option<Cluster> {
    let machine = Machine::new(Rc::clone(driver), usize::from(cores) + 1, Stalls::default());
    let setup = Setup {
        cores,
        credits: 4,
        reserve: 4,
        flush: 1,
    };
    let booted = machine
        .block_on(0, async move {
            timeout(Duration::from_secs(60), boot(PATH, setup)).await
        })
        .ok()?
        .ok()?;
    let committer = machine.spawn_on(0, booted.committer.run());
    if real_keys {
        keys_up(&machine);
    }
    let meshes = std::sync::Arc::new(Meshes::new(cores));
    let mut tasks = Vec::new();
    for start in booted.starts {
        let index = start.index();
        let links = meshes.take(index).expect("links");
        tasks.push(machine.spawn_on(usize::from(index) + 1, async move {
            let mut core = timeout(Duration::from_secs(60), start.open())
                .await
                .ok()?
                .ok()?;
            if let Some((flush_size, fan_in)) = tuning {
                core.keeper.set_tiering(Tiering {
                    flush_size,
                    fan_in,
                    bytes_per_tick: 64 * 1024,
                    tick: Duration::from_millis(1),
                    ..Tiering::default()
                });
            }
            let keys: Rc<dyn Keys> = if real_keys {
                keyring()
            } else {
                Rc::new(Toy::default())
            };
            let parts = Parts {
                keys,
                transport: Idle,
                clock: Clock::at(rt::wall_ms().saturating_sub(behind), rt::now()),
            };
            let started = Node::start(core, links, settings_named(naming), parts);
            timeout(Duration::from_secs(60), started).await.ok()?.ok()
        }));
    }
    let started = machine.block_on(0, async move {
        let mut started = Vec::new();
        for task in tasks {
            started.push(task.await);
        }
        started
    });
    let (nodes, runnings) = started
        .into_iter()
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .unzip();
    Some(Cluster {
        machine,
        nodes,
        runnings,
        client: booted.client,
        committer,
    })
}

async fn configure(nodes: &[Node<Idle>], objects: Vec<Object>) {
    let control = nodes.iter().find(|n| n.controls()).expect("control core");
    for object in objects {
        control.write(object).await.expect("write");
    }
}

async fn regenerate(nodes: &[Node<Idle>], id: u32) {
    let control = nodes.iter().find(|n| n.controls()).expect("control core");
    let generation = control.table().tenant(id).expect("tenant").generation;
    control.delete_tenant(id).await.expect("delete");
    wait_for(nodes, id, generation, State::Deleted).await;
    configure(nodes, vec![tenant(id, generation + 1, State::Active)]).await;
}

async fn wait_for(nodes: &[Node<Idle>], tenant: u32, generation: u32, state: State) {
    for node in nodes {
        while !node
            .table()
            .tenant(tenant)
            .is_some_and(|t| t.generation == generation && t.state == state)
        {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

async fn ready(nodes: &[Node<Idle>]) {
    let pool = Object::Pool(Pool {
        id: 1,
        addresses: vec![(IpAddr::from([192, 0, 2, 1]), 1)],
    });
    let missing: Vec<Object> = {
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let table = control.table();
        let mut objects = Vec::new();
        if table.pool(1).is_none() {
            objects.push(pool);
        }
        for id in [1, 2] {
            if table.tenant(id).is_none() {
                objects.push(tenant(id, 1, State::Active));
            }
        }
        objects
    };
    configure(nodes, missing).await;
    wait_for(nodes, 1, 1, State::Active).await;
    wait_for(nodes, 2, 1, State::Active).await;
}

#[test]
fn punycode_matches_known_labels() {
    for (label, encoded) in [
        ("bücher", "bcher-kva"),
        ("münchen", "mnchen-3ya"),
        ("例え", "r8jz45g"),
        ("テスト", "zckzah"),
        ("ドメイン名例", "eckwd4c7cu47r2wf"),
        ("abc", "abc-"),
    ] {
        assert_eq!(punycode(label).as_deref(), Some(encoded), "{label}");
    }
}

#[test]
fn normalize_lowercases_ascii_and_encodes_non_ascii_domains() {
    for (given, normal) in [
        ("User@Example.ORG", Some("user@example.org")),
        ("a.b+tag@example.org", Some("a.b+tag@example.org")),
        ("Jörg@Bücher.Example", Some("jörg@xn--bcher-kva.example")),
        ("x@例え.テスト", Some("x@xn--r8jz45g.xn--zckzah")),
        ("quoted@local@example.org", Some("quoted@local@example.org")),
        ("@example.org", None),
        ("nobody", None),
        ("a@-bad.example", None),
        ("a@exa mple.org", None),
        ("a@", None),
    ] {
        assert_eq!(normalize(given).as_deref(), normal, "{given}");
    }
    let long = format!("{}@example.org", "a".repeat(250));
    assert_eq!(normalize(&long), None);
}

#[test]
fn retain_drops_old_generations_and_expired_entries_only_at_the_oldest_run() {
    let mut table = Table::default();
    table.take(control::Note::Snapshot(control::Snapshot {
        version: 1,
        objects: vec![tenant(1, 2, State::Active)],
    }));
    let value = |generation: u32, until: u64| {
        let mut out = generation.to_le_bytes().to_vec();
        out.push(4);
        out.extend_from_slice(&5u64.to_le_bytes());
        out.extend_from_slice(&until.to_le_bytes());
        out
    };
    let entry = |tenant: u32, generation: u32, until: u64| {
        Entry::put(
            index::key(tenant, [1; 16]),
            value(generation, until),
            Vec::new(),
        )
    };
    assert!(!retain(&table, 100, &entry(1, 1, 0), false));
    assert!(retain(&table, 100, &entry(1, 2, 0), true));
    assert!(retain(&table, 100, &entry(1, 2, 50), false));
    assert!(!retain(&table, 100, &entry(1, 2, 50), true));
    assert!(retain(&table, 100, &entry(1, 2, 150), true));
    assert!(retain(&table, 100, &entry(9, 1, 50), false));
    assert!(!retain(&table, 100, &entry(9, 1, 50), true));
    assert!(retain(&table, 100, &entry(9, 0, 0), true));
    let tombstone = Entry::delete(index::key(1, [1; 16]), SHAPE);
    assert_eq!(tombstone.op, Op::Delete);
    assert!(retain(&table, 100, &tombstone, true));
    assert_eq!(KIND_SUPPRESS, 1);
}

#[test]
fn suppressions_add_get_remove_and_refuse_at_intake() {
    let driver = Rc::new(SimDriver::with_disk(1, Config::default(), created(1)));
    let cluster = started(&driver, 4);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let lists = nodes[0].suppressions();
        lists
            .add(1, "Bounced@Example.ORG", Reason::Bounce, None)
            .await
            .expect("add");
        lists
            .add(1, "jörg@bücher.example", Reason::Complaint, None)
            .await
            .expect("add");
        let found = nodes[3]
            .suppressions()
            .get(1, "bounced@example.org")
            .await
            .expect("get")
            .expect("found");
        assert_eq!(found.reason, Reason::Bounce);
        assert_eq!(found.until, None);
        assert!(found.created > 0);
        let other = nodes[2]
            .suppressions()
            .get(2, "bounced@example.org")
            .await
            .expect("get");
        assert_eq!(other, None);
        let ascii = lists
            .get(1, "JÖRG@xn--bcher-kva.example")
            .await
            .expect("get");
        assert_eq!(ascii, None, "non-ASCII local parts keep their case");
        let same = lists
            .get(1, "jörg@XN--BCHER-KVA.example")
            .await
            .expect("get");
        assert_eq!(same.map(|s| s.reason), Some(Reason::Complaint));

        let node = &nodes[1];
        let mut draft = node.draft(1, None).expect("draft");
        let added = node
            .recipients(
                &mut draft,
                &[
                    "fine@example.org",
                    "BOUNCED@example.org",
                    "bad",
                    "other@example.net",
                ],
            )
            .await;
        assert!(added[0].is_ok());
        assert_eq!(added[1], Err(Refusal::Suppressed));
        assert_eq!(added[2], Err(Refusal::Address));
        assert!(added[3].is_ok());
        assert_eq!(draft.queues().len(), 2);
        drop(draft);
        let mut draft = node.draft(2, None).expect("draft");
        assert!(
            node.recipient(&mut draft, "bounced@example.org")
                .await
                .is_ok()
        );
        drop(draft);

        assert_eq!(
            lists.remove(1, "bounced@EXAMPLE.org").await,
            Ok(true),
            "removed"
        );
        assert_eq!(lists.remove(1, "bounced@example.org").await, Ok(false));
        assert_eq!(lists.get(1, "bounced@example.org").await, Ok(None));
        let mut draft = node.draft(1, None).expect("draft");
        assert!(
            node.recipient(&mut draft, "bounced@example.org")
                .await
                .is_ok()
        );
        drop(draft);

        assert_eq!(
            lists.add(1, "nobody", Reason::Manual, None).await,
            Err(Refusal::Address)
        );
        assert_eq!(lists.get(9, "a@example.org").await, Err(Refusal::Tenant));
        assert_eq!(
            lists.add(9, "a@example.org", Reason::Manual, None).await,
            Err(Refusal::Tenant)
        );
    });
    cluster.stop();
}

#[test]
fn suppressions_expire_and_end_with_a_new_generation() {
    let driver = Rc::new(SimDriver::with_disk(2, Config::default(), created(2)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let lists = nodes[0].suppressions();
        let now = Clock::start().now();
        lists
            .add(1, "brief@example.org", Reason::Bounce, Some(now + 1_000))
            .await
            .expect("add");
        lists
            .add(1, "kept@example.org", Reason::Unsubscribe, None)
            .await
            .expect("add");
        let checked = lists
            .check(
                1,
                1,
                &["brief@example.org", "kept@example.org", "free@example.org"],
            )
            .await;
        assert_eq!(checked, Ok(vec![true, true, false]));
        let found = lists.get(1, "brief@example.org").await.expect("get");
        assert_eq!(found.and_then(|s| s.until), Some(now + 1_000));
        sleep(Duration::from_millis(1_500)).await;
        let checked = lists
            .check(1, 1, &["brief@example.org", "kept@example.org"])
            .await;
        assert_eq!(checked, Ok(vec![false, true]));
        let page = lists.list(1, None, 10).await.expect("list");
        let listed: Vec<&str> = page.listed.iter().map(|l| l.address.as_str()).collect();
        assert_eq!(listed, vec!["kept@example.org"]);

        regenerate(&nodes, 1).await;
        wait_for(&nodes, 1, 2, State::Active).await;
        assert_eq!(
            lists.check(1, 1, &["kept@example.org"]).await,
            Err(Refusal::Tenant)
        );
        let checked = lists.check(1, 2, &["kept@example.org"]).await;
        assert_eq!(checked, Ok(vec![false]));
        let page = lists.list(1, None, 10).await.expect("list");
        assert_eq!(page.listed, Vec::new());
        lists
            .add(1, "kept@example.org", Reason::Manual, None)
            .await
            .expect("add again");
        let checked = lists.check(1, 2, &["kept@example.org"]).await;
        assert_eq!(checked, Ok(vec![true]));

        configure(&nodes, vec![tenant(2, 1, State::Suspended)]).await;
        wait_for(&nodes, 2, 1, State::Suspended).await;
        assert_eq!(
            lists.check(2, 1, &["kept@example.org"]).await,
            Err(Refusal::Tenant)
        );
    });
    cluster.stop();
}

#[test]
fn missing_keys_refuse_for_now_and_never_answer_not_suppressed() {
    let driver = Rc::new(SimDriver::with_disk(21, Config::default(), created(21)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        configure(&nodes, vec![tenant(KEYLESS, 1, State::Active)]).await;
        wait_for(&nodes, KEYLESS, 1, State::Active).await;
        let lists = nodes[0].suppressions();
        let address = "a@example.org";
        assert_eq!(
            lists.check(KEYLESS, 1, &[address]).await,
            Err(Refusal::Keys)
        );
        assert_eq!(
            lists.add(KEYLESS, address, Reason::Manual, None).await,
            Err(Refusal::Keys)
        );
        assert_eq!(lists.get(KEYLESS, address).await, Err(Refusal::Keys));
        assert_eq!(lists.remove(KEYLESS, address).await, Err(Refusal::Keys));
        assert_eq!(
            nodes[0].request_shard(KEYLESS, b"key").await,
            Err(Refusal::Keys)
        );
        assert_eq!(
            nodes[0].begin(KEYLESS, b"key", [1; 16]).await.err(),
            Some(Refusal::Keys)
        );
        let mut draft = nodes[0].draft(KEYLESS, None).expect("draft");
        assert_eq!(
            nodes[0].recipient(&mut draft, address).await,
            Err(Refusal::Keys)
        );
        assert!(Refusal::Keys.temporary());
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        assert!(matches!(
            control.write(tenant(NO_CREATE, 1, State::Active)).await,
            Err(sched::Error::Control(control::Error::Keys {
                tenant: NO_CREATE,
                generation: 1,
                error: KeyError::Unavailable,
            }))
        ));
        assert!(control.table().tenant(NO_CREATE).is_none());
        assert!(matches!(
            control.write(tenant(7, 3, State::Active)).await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
    });
    cluster.stop();
}

#[test]
fn suppressions_and_queues_use_keys_from_the_keys_process() {
    let driver = Rc::new(SimDriver::with_disk(31, Config::default(), created(31)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    let queue = cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let lists = nodes[0].suppressions();
        lists
            .add(1, "kept@example.org", Reason::Manual, None)
            .await
            .expect("add");
        assert_eq!(
            lists
                .check(1, 1, &["kept@example.org", "free@example.org"])
                .await,
            Ok(vec![true, false])
        );
        assert_eq!(
            lists.check(2, 1, &["kept@example.org"]).await,
            Ok(vec![false])
        );
        let page = lists.list(1, None, 10).await.expect("list");
        assert_eq!(page.listed[0].address, "kept@example.org");
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        assert!(matches!(
            control.write(tenant(1, 2, State::Active)).await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
        assert!(matches!(
            control.write(tenant(5, 2, State::Active)).await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
        assert_eq!(control.table().tenant(1).map(|t| t.generation), Some(1));
        assert!(control.table().tenant(5).is_none());
        configure(&nodes, vec![tenant(3, 1, State::Active)]).await;
        wait_for(&nodes, 3, 1, State::Active).await;
        assert_eq!(lists.check(3, 1, &["a@example.org"]).await, Ok(vec![false]));
        let mut draft = nodes[0].draft(1, None).expect("draft");
        nodes[0]
            .recipient(&mut draft, "to@example.org")
            .await
            .expect("recipient")
    });
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(32, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        let lists = nodes[1].suppressions();
        assert_eq!(
            lists.check(1, 1, &["kept@example.org"]).await,
            Ok(vec![true])
        );
        let page = lists.list(1, None, 10).await.expect("list");
        assert_eq!(page.listed.len(), 1);
        assert_eq!(page.listed[0].address, "kept@example.org");
        let mut draft = nodes[1].draft(1, None).expect("draft");
        let again = nodes[1]
            .recipient(&mut draft, "other@example.org")
            .await
            .expect("recipient");
        assert_eq!(again, queue);
    });
    restarted.stop();
}

#[test]
fn a_different_naming_key_refuses_to_start() {
    let driver = Rc::new(SimDriver::with_disk(33, Config::default(), created(33)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move { ready(&nodes).await });
    cluster.stop();
    let disk = driver.crash();
    let other = Rc::new(SimDriver::with_disk(34, Config::default(), disk.clone()));
    assert!(try_started(&other, 2, 0, None, false, *b"another key 16 b").is_none());
    let same = Rc::new(SimDriver::with_disk(35, Config::default(), disk));
    let restarted = started(&same, 2);
    restarted.stop();
}

struct Sealed {
    id: MessageId,
    clear: HeadClear,
    wrap: [u8; spool::WRAP],
    head: Vec<u8>,
    body: Vec<u8>,
    slice: Vec<u8>,
}

async fn owned_shard(node: &Node<Idle>) -> u16 {
    for shard in 0..SHARDS {
        if node.spool().id(shard).await.is_ok() {
            return shard;
        }
    }
    panic!("no shard on this core");
}

async fn seal_one(node: &Node<Idle>, shard: u16, n: u8) -> Sealed {
    seal_for(node, 1, shard, n).await
}

async fn seal_for(node: &Node<Idle>, tenant: u32, shard: u16, n: u8) -> Sealed {
    let mut draft = node.draft(tenant, None).expect("draft");
    let address = format!("s{n}@example.org");
    node.recipient(&mut draft, &address)
        .await
        .expect("recipient");
    let mut sealing = node.sealing(&mut draft, shard).await.expect("sealing");
    let clear = HeadClear {
        recipients: 1,
        accepted: 5,
        ..HeadClear::default()
    };
    let head = sealing
        .head(clear, u64::MAX / 2, &[n; 10], b"Subject: hi\r\n")
        .expect("head");
    let body = sealing.inline_body(&[n; 300]).expect("body");
    let slice = sealing
        .slice(0, draft.queues().to_vec(), address.as_bytes())
        .expect("slice");
    let sealed = Sealed {
        id: sealing.id(),
        clear: head.clear,
        wrap: head.wrap,
        head: head.sealed.clone(),
        body: match &body {
            Body::Inline(bytes) => bytes.clone(),
            Body::Chain(_) => panic!("inline"),
        },
        slice: slice.sealed.clone(),
    };
    let message = Message {
        id: sealing.id(),
        tenant,
        head,
        body,
        slices: vec![slice],
    };
    node.accept(draft, message).await.expect("accept");
    sealed
}

async fn opens(node: &Node<Idle>, sealed: &Sealed, n: u8) {
    opens_for(node, 1, sealed, n).await;
}

async fn opens_for(node: &Node<Idle>, tenant: u32, sealed: &Sealed, n: u8) {
    let opener = node
        .opener(tenant, 1, sealed.id, &sealed.clear, &sealed.wrap)
        .await
        .expect("opener");
    let (envelope, headers) = opener.head(&sealed.head).expect("head");
    assert_eq!(
        (envelope, headers),
        (vec![n; 10], b"Subject: hi\r\n".to_vec())
    );
    assert_eq!(
        opener.inline_body(&sealed.body).expect("body"),
        vec![n; 300]
    );
    let address = format!("s{n}@example.org");
    assert_eq!(
        opener.slice(0, &sealed.slice).expect("slice"),
        address.as_bytes()
    );
}

#[test]
fn sealed_items_open_only_under_their_own_message_and_item() {
    let driver = Rc::new(SimDriver::with_disk(36, Config::default(), created(36)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let mut draft = node.draft(1, None).expect("draft");
        let first = node.sealing(&mut draft, shard).await.expect("sealing");
        let second = node.sealing(&mut draft, shard).await.expect("sealing");
        assert_ne!(first.id(), second.id());
        let mut once = second;
        let clear = HeadClear::default();
        assert!(once.head(clear, 1, b"e", b"h").is_ok());
        assert_eq!(
            once.head(clear, 1, b"e", b"h").err(),
            Some(Refusal::Message)
        );
        assert!(once.inline_body(b"b").is_ok());
        assert!(once.body_chunks().is_err());
        assert!(once.slice(0, vec![1], b"r").is_ok());
        assert_eq!(once.slice(0, vec![1], b"r").err(), Some(Refusal::Message));
        assert!(once.slice(1, vec![1], b"r").is_ok());
        let mut large = node.sealing(&mut draft, shard).await.expect("sealing");
        let big = vec![0; store::MAX_PAYLOAD];
        assert_eq!(
            large.head(clear, 1, b"e", &big).err(),
            Some(Refusal::Message)
        );
        drop(first);

        let sealed = seal_one(node, shard, 7).await;
        opens(node, &sealed, 7).await;
        opens(&nodes[1], &sealed, 7).await;
        let opener = |tenant, generation, clear: HeadClear| {
            let (node, wrap, id) = (node.clone(), sealed.wrap, sealed.id);
            async move {
                node.opener(tenant, generation, id, &clear, &wrap)
                    .await
                    .err()
            }
        };
        let bad = Some(Unsealable::Bad);
        assert_eq!(opener(1, 2, sealed.clear).await, bad);
        assert_eq!(opener(2, 1, sealed.clear).await, bad);
        let mut day = sealed.clear;
        day.day += 1;
        assert_eq!(opener(1, 1, day).await, bad);
        let mut batch = sealed.clear;
        batch.batch_key += 1;
        assert_eq!(opener(1, 1, batch).await, bad);
        let mut wrap = sealed.wrap;
        wrap[50] ^= 1;
        assert_eq!(
            node.opener(1, 1, sealed.id, &sealed.clear, &wrap)
                .await
                .err(),
            bad
        );
        let other = MessageId {
            key: sealed.id.key + 1,
            ..sealed.id
        };
        let moved = node
            .opener(1, 1, other, &sealed.clear, &sealed.wrap)
            .await
            .expect("opener");
        assert_eq!(moved.head(&sealed.head).err(), bad);
        let right = node
            .opener(1, 1, sealed.id, &sealed.clear, &sealed.wrap)
            .await
            .expect("opener");
        assert_eq!(right.inline_body(&sealed.head).err(), bad);
        assert_eq!(right.slice(1, &sealed.slice).err(), bad);
        assert_eq!(right.head(&sealed.body).err(), bad);
    });
    cluster.stop();
}

#[test]
fn replies_seal_once_per_stamp_and_open_only_under_it() {
    let driver = Rc::new(SimDriver::with_disk(42, Config::default(), created(42)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let sealed = seal_one(node, shard, 0).await;
        let opener = node
            .opener(1, 1, sealed.id, &sealed.clear, &sealed.wrap)
            .await
            .expect("opener");
        let stamp = node.spool().stamp(shard).expect("stamp");
        let reply = opener.seal_reply(0, stamp, b"250 ok").expect("seal");
        assert_eq!(
            opener.seal_reply(0, stamp, b"250 ok").err(),
            Some(Unsealable::Bad)
        );
        let again = node
            .opener(1, 1, sealed.id, &sealed.clear, &sealed.wrap)
            .await
            .expect("opener");
        assert_eq!(again.open_reply(0, stamp, &reply).expect("open"), b"250 ok");
        let later = Stamp {
            write: stamp.write + 1,
            ..stamp
        };
        let rebooted = Stamp {
            boot: stamp.boot + 1,
            ..stamp
        };
        let bad = Some(Unsealable::Bad);
        assert_eq!(again.open_reply(0, later, &reply).err(), bad);
        assert_eq!(again.open_reply(0, rebooted, &reply).err(), bad);
        assert_eq!(again.open_reply(1, stamp, &reply).err(), bad);
        assert_eq!(again.slice(0, &reply).err(), bad);
        let other = opener.seal_reply(0, later, b"250 ok").expect("seal");
        assert_ne!(other, reply);
    });
    cluster.stop();
}

#[test]
fn body_chunks_open_in_order_and_a_cut_stream_is_refused() {
    let driver = Rc::new(SimDriver::with_disk(39, Config::default(), created(39)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let mut draft = node.draft(1, None).expect("draft");
        let clear = HeadClear::default();
        let mut chunked = node.sealing(&mut draft, shard).await.expect("sealing");
        let head = chunked.head(clear, 1, b"e", b"h").expect("head");
        let mut chunks = chunked.body_chunks().expect("chunks");
        let mut parts = [vec![1; 64], vec![2; 64], vec![3; 10]];
        for part in &mut parts[..2] {
            chunks.seal(part).expect("seal");
        }
        chunks.seal_last(&mut parts[2]);
        let opener = node
            .opener(1, 1, chunked.id(), &head.clear, &head.wrap)
            .await
            .expect("opener");
        let mut cut = parts[..2].to_vec();
        let mut short = opener.body_chunks();
        for part in &mut cut {
            short.open(false, part).expect("chunk");
        }
        assert!(short.finish().is_err());
        let mut stream = opener.body_chunks();
        let mut whole = Vec::new();
        for (n, part) in parts.iter_mut().enumerate() {
            whole.extend_from_slice(stream.open(n == 2, part).expect("chunk"));
        }
        stream.finish().expect("finish");
        assert_eq!(whole, [vec![1; 64], vec![2; 64], vec![3; 10]].concat());
    });
    cluster.stop();
}

fn unwraps(driver: &SimDriver) -> u64 {
    audited(driver, "unwrap")
}

fn audited(driver: &SimDriver, op: &str) -> u64 {
    let disk = driver.disk();
    let Some(audit) = disk.contents(&Path::new(KEYS_DIR).join("audit")) else {
        return 0;
    };
    String::from_utf8(audit.to_vec())
        .expect("text")
        .lines()
        .filter(|line| line.contains(&format!(" {op} 1 1 ")))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

#[test]
fn sealed_messages_open_after_a_restart_with_one_unwrap_per_batch() {
    let driver = Rc::new(SimDriver::with_disk(37, Config::default(), created(37)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    let sealed = cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let mut sealed = Vec::new();
        for n in 0..5 {
            sealed.push(seal_one(node, shard, n).await);
        }
        assert!(sealed.iter().all(|s| s.clear.batch_key == sealed[0].id.key));
        for (n, one) in (0..).zip(&sealed) {
            opens(node, one, n).await;
        }
        sleep(Duration::from_millis(300)).await;
        sealed
    });
    assert_eq!(unwraps(&driver), 0);
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(38, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        for (n, one) in (0..).zip(&sealed) {
            opens(&nodes[0], one, n).await;
        }
        sleep(Duration::from_millis(300)).await;
    });
    assert_eq!(unwraps(&driver), 1);
    restarted.stop();
}

const DAY_MS: i64 = 86_400_000;

#[test]
fn a_day_change_starts_a_new_batch_and_both_days_open_after_a_restart() {
    let driver = Rc::new(SimDriver::with_disk(39, Config::default(), created(39)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    let jumps = Rc::clone(&driver);
    let sealed = cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let first = seal_one(node, shard, 0).await;
        jumps.jump_wall_clock(DAY_MS);
        let second = seal_one(node, shard, 1).await;
        assert_eq!(second.clear.day, first.clear.day + 1);
        assert_ne!(second.clear.batch_key, first.clear.batch_key);
        opens(node, &first, 0).await;
        opens(node, &second, 1).await;
        sleep(Duration::from_millis(300)).await;
        vec![first, second]
    });
    assert_eq!(unwraps(&driver), 0);
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(40, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        for (n, one) in (0..).zip(&sealed) {
            opens(&nodes[0], one, n).await;
        }
        sleep(Duration::from_millis(300)).await;
    });
    assert_eq!(unwraps(&driver), 2);
    restarted.stop();
}

#[test]
fn settled_waits_for_live_and_sealing_mail_on_every_core() {
    let driver = Rc::new(SimDriver::with_disk(41, Config::default(), created(41)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        sleep(Duration::from_secs(2)).await;
        let today = keys::wall_day();
        assert_eq!(nodes[0].sched().settled_low(), Some(today));
        assert_eq!(nodes[1].sched().settled_low(), None);

        let shard = owned_shard(&nodes[0]).await;
        let live = seal_one(&nodes[0], shard, 0).await;
        let day = live.clear.day;
        assert!(day < today);
        assert_eq!(nodes[0].spool().oldest_day(), Some(day));
        sleep(Duration::from_secs(61)).await;
        assert_eq!(nodes[0].sched().settled_low(), Some(day));
        nodes[0].spool().cancel(live.id).await.expect("cancel");
        assert_eq!(nodes[0].spool().oldest_day(), None);
        sleep(Duration::from_secs(61)).await;
        assert_eq!(nodes[0].sched().settled_low(), Some(today));

        let other = owned_shard(&nodes[1]).await;
        let mut draft = nodes[1].draft(1, None).expect("draft");
        nodes[1]
            .recipient(&mut draft, "held@example.org")
            .await
            .expect("recipient");
        drop(nodes[1].sealing(&mut draft, other).await.expect("sealing"));
        sleep(Duration::from_secs(61)).await;
        assert_eq!(nodes[0].sched().settled_low(), Some(day));
        drop(draft);
        sleep(Duration::from_secs(61)).await;
        assert_eq!(nodes[0].sched().settled_low(), Some(today));
    });
    cluster.stop();
}

#[test]
fn listing_pages_through_every_core_in_hash_order() {
    listing(3, 4);
    listing(6, 1);
}

fn listing(case: u64, cores: u16) {
    let driver = Rc::new(SimDriver::with_disk(case, Config::default(), created(case)));
    let cluster = started(&driver, cores);
    let nodes = cluster.nodes.clone();
    let client = cluster.client.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let lists = nodes[nodes.len() - 1].suppressions();
        let mut expected = BTreeSet::new();
        for n in 0..90 {
            let address = format!("user{n}@d{}.example", n % 7);
            lists
                .add(1, &address, Reason::Manual, None)
                .await
                .expect("add");
            expected.insert(address);
            if n % 30 == 29 {
                client.checkpoint().await.expect("checkpoint");
            }
        }
        lists
            .add(2, "elsewhere@example.org", Reason::Manual, None)
            .await
            .expect("other tenant");
        for n in (0..90).step_by(9) {
            let address = format!("user{n}@d{}.example", n % 7);
            assert_eq!(lists.remove(1, &address).await, Ok(true));
            expected.remove(&address);
        }
        for size in [1, 7, 25, 200] {
            let mut seen = Vec::new();
            let mut hashes = Vec::new();
            let mut after = None;
            loop {
                let page = lists.list(1, after, size).await.expect("list");
                assert!(page.listed.len() <= size);
                for listed in &page.listed {
                    let hash = lists.hash(1, 1, &listed.address).await.expect("hash");
                    hashes.push(hash);
                    assert_eq!(listed.suppression.reason, Reason::Manual);
                }
                seen.extend(page.listed.into_iter().map(|l| l.address));
                match page.next {
                    Some(next) => after = Some(next),
                    None => break,
                }
            }
            let mut sorted = hashes.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(hashes, sorted, "page size {size}: hash order");
            let seen: BTreeSet<String> = seen.into_iter().collect();
            assert_eq!(seen, expected, "page size {size}");
        }
        let empty = lists.list(1, None, 0).await.expect("list");
        assert!(empty.listed.is_empty() && empty.next.is_none());
    });
    cluster.stop();
}

#[test]
fn acknowledged_suppressions_survive_a_crash() {
    let driver = Rc::new(SimDriver::with_disk(4, Config::default(), created(4)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    let client = cluster.client.clone();
    let kept: Vec<(String, Suppression)> = cluster.run(async move {
        ready(&nodes).await;
        let lists = nodes[0].suppressions();
        let mut kept = Vec::new();
        for n in 0..40 {
            let address = format!("crash{n}@example.org");
            let reason = if n % 2 == 0 {
                Reason::Bounce
            } else {
                Reason::Complaint
            };
            lists.add(1, &address, reason, None).await.expect("add");
            if n == 20 {
                client.checkpoint().await.expect("checkpoint");
            }
            if n % 5 == 4 {
                assert_eq!(lists.remove(1, &address).await, Ok(true));
                continue;
            }
            let found = lists.get(1, &address).await.expect("get").expect("found");
            kept.push((address, found));
        }
        kept
    });
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(5, Config::default(), driver.crash()));
    let restarted = started(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        let lists = nodes[1].suppressions();
        for (address, suppression) in &kept {
            let found = lists.get(1, address).await.expect("get");
            assert_eq!(found.as_ref(), Some(suppression), "{address}");
        }
        for n in (4..40).step_by(5) {
            let found = lists.get(1, &format!("crash{n}@example.org")).await;
            assert_eq!(found, Ok(None));
        }
        let page = lists.list(1, None, 100).await.expect("list");
        assert_eq!(page.listed.len(), kept.len());
    });
    restarted.stop();
}

fn message(id: MessageId, draft: &Draft) -> Message {
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
                ..HeadClear::default()
            },
            expiry: u64::MAX / 2,
            wrap: [3; spool::WRAP],
            sealed: vec![1; 64],
        },
        body: Body::Inline(vec![2; 300]),
        slices,
    }
}

async fn owner<'a>(nodes: &'a [Node<Idle>], tenant: u32, key: &[u8]) -> (&'a Node<Idle>, u16) {
    let shard = nodes[0].request_shard(tenant, key).await.expect("shard");
    let core = usize::from(shard) % nodes.len();
    (&nodes[core], shard)
}

async fn fresh(node: &Node<Idle>, tenant: u32, key: &[u8], digest: Hash) -> Ticket {
    match node.begin(tenant, key, digest).await {
        Ok(Begun::Fresh(ticket)) => ticket,
        Ok(Begun::Replay(ids)) => panic!("replayed {ids:?}"),
        Err(refusal) => panic!("refused {refusal:?}"),
    }
}

async fn replayed(node: &Node<Idle>, tenant: u32, key: &[u8], digest: Hash) -> Vec<MessageId> {
    match node.begin(tenant, key, digest).await {
        Ok(Begun::Replay(ids)) => ids,
        Ok(Begun::Fresh(_)) => panic!("fresh"),
        Err(refusal) => panic!("refused {refusal:?}"),
    }
}

async fn accept(node: &Node<Idle>, ticket: Ticket, shard: u16, address: &str) -> MessageId {
    let mut draft = node.draft(ticket.tenant(), None).expect("draft");
    node.recipient(&mut draft, address)
        .await
        .expect("recipient");
    let id = node.spool().id(shard).await.expect("id");
    let built = message(id, &draft);
    node.accept_once(ticket, draft, built)
        .await
        .expect("accept");
    id
}

#[test]
fn a_retry_gets_the_first_answer_and_another_request_is_refused() {
    let driver = Rc::new(SimDriver::with_disk(11, Config::default(), created(11)));
    let cluster = started(&driver, 4);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let key = b"order-1".as_slice();
        let (node, shard) = owner(&nodes, 1, key).await;
        let ticket = fresh(node, 1, key, [1; 16]).await;
        let id = accept(node, ticket, shard, "a@example.org").await;
        assert_eq!(replayed(node, 1, key, [1; 16]).await, vec![id]);
        assert_eq!(
            node.begin(1, key, [2; 16]).await.err(),
            Some(Refusal::Conflict)
        );
        let (other, _) = owner(&nodes, 2, key).await;
        drop(fresh(other, 2, key, [1; 16]).await);
        let (elsewhere, _) = owner(&nodes, 1, b"order-2").await;
        let wrong = nodes
            .iter()
            .find(|n| !std::ptr::eq(*n, elsewhere))
            .expect("another core");
        assert_eq!(
            wrong.begin(1, b"order-2", [1; 16]).await.err(),
            Some(Refusal::Message)
        );
        let (node, shard) = owner(&nodes, 1, b"order-3").await;
        let ticket = fresh(node, 1, b"order-3", [3; 16]).await;
        let mut draft = node.draft(1, None).expect("draft");
        node.recipient(&mut draft, "b@example.org")
            .await
            .expect("recipient");
        let foreign = (0..SHARDS).find(|s| *s != shard).expect("shard");
        let id = node.spool().id(shard).await.expect("id");
        let mut moved = message(id, &draft);
        moved.id.shard = foreign;
        assert_eq!(
            node.accept_once(ticket, draft, moved).await,
            Err(Refusal::Message)
        );
        let _ = fresh(node, 1, b"order-3", [3; 16]).await;
        assert_eq!(node.requests().in_flight(), 0);
    });
    cluster.stop();
}

#[test]
fn concurrent_requests_with_one_key_are_accepted_once() {
    let driver = Rc::new(SimDriver::with_disk(12, Config::default(), created(12)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let key = b"same".as_slice();
        let (node, shard) = owner(&nodes, 1, key).await;
        let first = fresh(node, 1, key, [5; 16]).await;
        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let node = node.clone();
                spawn(async move { node.begin(1, b"same", [5; 16]).await })
            })
            .collect();
        sleep(Duration::from_millis(5)).await;
        assert_eq!(node.requests().in_flight(), 1);
        assert_eq!(
            node.begin(1, key, [6; 16]).await.err(),
            Some(Refusal::Conflict)
        );
        let id = accept(node, first, shard, "c@example.org").await;
        for waiter in waiters {
            match waiter.await {
                Ok(Begun::Replay(ids)) => assert_eq!(ids, vec![id]),
                Ok(Begun::Fresh(_)) => panic!("accepted twice"),
                Err(refusal) => panic!("refused {refusal:?}"),
            }
        }

        let racer = owner(&nodes, 1, b"race").await.0.clone();
        let racers: Vec<_> = (0..3)
            .map(|n| {
                let node = racer.clone();
                spawn(async move {
                    match node.begin(1, b"race", [2; 16]).await {
                        Ok(Begun::Fresh(ticket)) => {
                            let shard = ticket.shard();
                            let address = format!("race{n}@example.org");
                            (true, vec![accept(&node, ticket, shard, &address).await])
                        }
                        Ok(Begun::Replay(ids)) => (false, ids),
                        Err(refusal) => panic!("refused {refusal:?}"),
                    }
                })
            })
            .collect();
        let mut answers = Vec::new();
        for racer in racers {
            answers.push(racer.await);
        }
        assert_eq!(answers.iter().filter(|(fresh, _)| *fresh).count(), 1);
        assert!(answers.iter().all(|(_, ids)| *ids == answers[0].1));

        let key = b"failing".as_slice();
        let (node, shard) = owner(&nodes, 1, key).await;
        let first = fresh(node, 1, key, [7; 16]).await;
        let waiter = {
            let node = node.clone();
            spawn(async move { node.begin(1, b"failing", [7; 16]).await })
        };
        sleep(Duration::from_millis(5)).await;
        drop(first);
        let Ok(Begun::Fresh(second)) = waiter.await else {
            panic!("waiter did not run as a new request");
        };
        let id = accept(node, second, shard, "d@example.org").await;
        assert_eq!(replayed(node, 1, key, [7; 16]).await, vec![id]);
        assert_eq!(node.requests().in_flight(), 0);
    });
    cluster.stop();
}

async fn at_day_offset(offset: u64) {
    let now = Clock::start().now();
    let mut target = now / DAY * DAY + offset;
    if target <= now {
        target += DAY;
    }
    sleep(Duration::from_millis(target - now)).await;
}

#[test]
fn records_last_a_day_and_old_days_are_dropped() {
    let driver = Rc::new(SimDriver::with_disk(13, Config::default(), created(13)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    let client = cluster.client.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let early = b"early".as_slice();
        let late = b"late".as_slice();
        at_day_offset(1_000).await;
        let (node, shard) = owner(&nodes, 1, early).await;
        let first = accept(
            node,
            fresh(node, 1, early, [8; 16]).await,
            shard,
            "e@example.org",
        )
        .await;
        let day = node.requests().today();
        let kept = node
            .spool()
            .changes()
            .partitions(KIND_REQUEST)
            .await
            .expect("partitions");
        assert!(kept.contains(&(shard, day)));
        sleep(Duration::from_millis(DAY / 2)).await;
        assert_eq!(replayed(node, 1, early, [8; 16]).await, vec![first]);
        at_day_offset(DAY - 1_800_000).await;
        let (late_node, late_shard) = owner(&nodes, 1, late).await;
        let ticket = fresh(late_node, 1, late, [3; 16]).await;
        let second = accept(late_node, ticket, late_shard, "g@example.org").await;
        at_day_offset(60_000).await;
        assert_eq!(late_node.requests().today(), day + 1);
        assert_eq!(replayed(late_node, 1, late, [3; 16]).await, vec![second]);
        drop(fresh(node, 1, early, [9; 16]).await);
        client.checkpoint().await.expect("checkpoint");
        at_day_offset(60_000).await;
        for _ in 0..2 {
            client.checkpoint().await.expect("checkpoint");
        }
        for node in &nodes {
            let today = node.requests().today();
            let kept = node
                .spool()
                .changes()
                .partitions(KIND_REQUEST)
                .await
                .expect("partitions");
            assert!(kept.iter().all(|(_, d)| *d + 1 >= today), "{kept:?}");
        }
        assert_eq!(late_node.begin(1, late, [4; 16]).await.err(), None);
    });
    cluster.stop();
}

#[test]
fn a_new_generation_forgets_old_requests() {
    let driver = Rc::new(SimDriver::with_disk(14, Config::default(), created(14)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let key = b"gen".as_slice();
        let (node, shard) = owner(&nodes, 1, key).await;
        let ticket = fresh(node, 1, key, [4; 16]).await;
        accept(node, ticket, shard, "f@example.org").await;
        let stale = fresh(node, 1, b"stale", [5; 16]).await;
        regenerate(&nodes, 1).await;
        wait_for(&nodes, 1, 2, State::Active).await;
        let mut draft = node.draft(1, None).expect("draft");
        node.recipient(&mut draft, "s@example.org")
            .await
            .expect("recipient");
        let id = node.spool().id(stale.shard()).await.expect("id");
        let built = message(id, &draft);
        assert_eq!(
            node.accept_once(stale, draft, built).await,
            Err(Refusal::Message)
        );
        let (node, _) = owner(&nodes, 1, key).await;
        drop(fresh(node, 1, key, [4; 16]).await);
        configure(&nodes, vec![tenant(1, 2, State::Suspended)]).await;
        wait_for(&nodes, 1, 2, State::Suspended).await;
        assert_eq!(
            node.begin(1, key, [4; 16]).await.err(),
            Some(Refusal::Tenant)
        );
    });
    cluster.stop();
}

#[test]
fn accepted_requests_survive_a_crash_with_the_same_answer() {
    let driver = Rc::new(SimDriver::with_disk(15, Config::default(), created(15)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    let client = cluster.client.clone();
    let answers: Vec<(Vec<u8>, MessageId)> = cluster.run(async move {
        ready(&nodes).await;
        let mut answers = Vec::new();
        for n in 0..12u8 {
            let key = vec![b'k', n];
            let (node, shard) = owner(&nodes, 1, &key).await;
            let ticket = fresh(node, 1, &key, [n; 16]).await;
            let id = accept(node, ticket, shard, &format!("r{n}@example.org")).await;
            answers.push((key, id));
            if n == 5 {
                client.checkpoint().await.expect("checkpoint");
            }
        }
        answers
    });
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(16, Config::default(), driver.crash()));
    let restarted = started_behind(&driver, 2, 2 * DAY);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        for (n, (key, id)) in (0u8..).zip(&answers) {
            let (node, _) = owner(&nodes, 1, key).await;
            assert_eq!(replayed(node, 1, key, [n; 16]).await, vec![*id]);
            assert_eq!(
                node.begin(1, key, [n + 100; 16]).await.err(),
                Some(Refusal::Conflict)
            );
        }
    });
    restarted.stop();
}

#[test]
fn retain_request_drops_old_generations_and_records_past_a_day() {
    let mut table = Table::default();
    table.take(control::Note::Snapshot(control::Snapshot {
        version: 1,
        objects: vec![tenant(1, 2, State::Active)],
    }));
    let entry = |tenant: u32, generation: u32, accepted: u64| {
        let mut value = generation.to_le_bytes().to_vec();
        value.extend_from_slice(&accepted.to_le_bytes());
        value.extend_from_slice(&[0; 16]);
        value.push(1);
        value.extend_from_slice(&[0; 32]);
        Entry::put(index::key(tenant, [2; 16]), value, Vec::new())
    };
    let now = 3 * DAY;
    assert!(retain_request(&table, now, &entry(1, 2, now - 10)));
    assert!(!retain_request(&table, now, &entry(1, 1, now - 10)));
    assert!(!retain_request(&table, now, &entry(1, 2, now - DAY)));
    assert!(retain_request(&table, now, &entry(9, 1, now - 10)));
    assert!(retain_request(
        &table,
        now,
        &Entry::delete(index::key(1, [2; 16]), sched::REQUEST_SHAPE)
    ));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    Present(Reason),
    Absent,
    Unknown,
}

#[derive(Default)]
struct Model {
    lists: BTreeMap<(u32, String), Want>,
    accepted: BTreeMap<Vec<u8>, Vec<MessageId>>,
    doubtful: BTreeSet<Vec<u8>>,
    refused: BTreeSet<MessageId>,
    acked: u64,
    accepts: u64,
    replays: u64,
}

type Shared = Rc<RefCell<Model>>;

const REASONS: [Reason; 4] = [
    Reason::Bounce,
    Reason::Complaint,
    Reason::Unsubscribe,
    Reason::Manual,
];

fn digest(key: &[u8]) -> Hash {
    [key[1]; 16]
}

async fn change_list(node: &Node<Idle>, model: &Shared, driver: &SimDriver, worker: u64) {
    let tenant = 1 + u32::try_from(driver.random() % 2).expect("small");
    let n = driver.random() % 12;
    let address = format!("w{worker}a{n}@d{}.example", n % 3);
    let slot = (tenant, address.clone());
    let lists = node.suppressions();
    if driver.random().is_multiple_of(5) {
        let checked = lists.check(tenant, 1, &[address.as_str()]).await;
        let want = model.borrow().lists.get(&slot).copied();
        match (want, checked) {
            (Some(Want::Present(_)), Ok(found)) => assert_eq!(found, vec![true], "{address}"),
            (None | Some(Want::Absent), Ok(found)) => assert_eq!(found, vec![false], "{address}"),
            _ => {}
        }
        return;
    }
    model.borrow_mut().lists.insert(slot.clone(), Want::Unknown);
    let (want, result) = if driver.random().is_multiple_of(3) {
        (Want::Absent, lists.remove(tenant, &address).await.map(drop))
    } else {
        let reason = REASONS[usize::try_from(driver.random() % 4).expect("small")];
        (
            Want::Present(reason),
            lists.add(tenant, &address, reason, None).await,
        )
    };
    let mut model = model.borrow_mut();
    if result.is_ok() {
        model.lists.insert(slot, want);
        model.acked += 1;
    }
}

async fn request(nodes: &[Node<Idle>], model: &Shared, driver: &SimDriver) {
    let key = vec![b'k', u8::try_from(driver.random() % 40).expect("small")];
    let right = digest(&key);
    let honest = !driver.random().is_multiple_of(8);
    let digest = if honest { right } else { [0xee; 16] };
    let (node, shard) = owner(nodes, 1, &key).await;
    let begun = node.begin(1, &key, digest).await;
    let known = model.borrow().accepted.get(&key).cloned();
    let ticket = match begun {
        Ok(Begun::Replay(ids)) => {
            assert!(honest, "replayed another digest");
            let mut model = model.borrow_mut();
            assert!(
                ids.iter().all(|id| !model.refused.contains(id)),
                "refused ids came back"
            );
            if let Some(first) = known {
                assert_eq!(ids, first, "another answer");
            } else {
                assert!(model.doubtful.contains(&key), "a record from nowhere");
                model.accepted.insert(key.clone(), ids);
            }
            model.replays += 1;
            return;
        }
        Ok(Begun::Fresh(ticket)) => {
            assert!(known.is_none(), "a second accept for one key");
            ticket
        }
        Err(_) => return,
    };
    if !honest {
        drop(ticket);
        return;
    }
    let Ok(mut draft) = node.draft(1, None) else {
        return;
    };
    if node.recipient(&mut draft, "to@example.org").await.is_err() {
        return;
    }
    let Ok(id) = node.spool().id(shard).await else {
        return;
    };
    let built = message(id, &draft);
    model.borrow_mut().doubtful.insert(key.clone());
    let result = node.accept_once(ticket, draft, built).await;
    let mut model = model.borrow_mut();
    match result {
        Ok(()) => {
            assert!(
                model.accepted.insert(key.clone(), vec![id]).is_none(),
                "accepted twice"
            );
            model.doubtful.remove(&key);
            model.accepts += 1;
        }
        Err(Refusal::Failed) => {}
        Err(_) => {
            model.refused.insert(id);
            model.doubtful.remove(&key);
        }
    }
}

async fn work(
    nodes: Vec<Node<Idle>>,
    model: Shared,
    driver: Rc<SimDriver>,
    worker: u64,
    steps: u64,
) {
    for step in 0..steps {
        if driver.is_halted() {
            return;
        }
        let node = &nodes[usize::try_from((worker + step) % nodes.len() as u64).expect("small")];
        let op = async {
            if driver.random().is_multiple_of(2) {
                change_list(node, &model, &driver, worker).await;
            } else {
                request(&nodes, &model, &driver).await;
            }
        };
        if timeout(Duration::from_secs(120), op).await.is_err() {
            return;
        }
        sleep(Duration::from_millis(driver.random() % 3)).await;
    }
}

async fn verify_model(nodes: &[Node<Idle>], model: &Shared) {
    let (lists, accepted) = {
        let model = model.borrow();
        (model.lists.clone(), model.accepted.clone())
    };
    for ((tenant, address), want) in lists {
        let found = nodes[0]
            .suppressions()
            .get(tenant, &address)
            .await
            .expect("get");
        match want {
            Want::Present(reason) => {
                assert_eq!(found.map(|s| s.reason), Some(reason), "{address}");
            }
            Want::Absent => assert_eq!(found, None, "{address}"),
            Want::Unknown => {
                let settled = found.map_or(Want::Absent, |s| Want::Present(s.reason));
                model.borrow_mut().lists.insert((tenant, address), settled);
            }
        }
    }
    for (key, ids) in accepted {
        let (node, _) = owner(nodes, 1, &key).await;
        assert_eq!(replayed(node, 1, &key, digest(&key)).await, ids);
    }
}

async fn unless_halted<T>(driver: &Rc<SimDriver>, work: impl Future<Output = T>) -> Option<T> {
    let mut work = pin!(work);
    let watched = Rc::clone(driver);
    let mut halt = pin!(async move {
        while !watched.is_halted() {
            sleep(Duration::from_millis(100)).await;
        }
    });
    poll_fn(|cx| {
        if let Poll::Ready(value) = work.as_mut().poll(cx) {
            return Poll::Ready(Some(value));
        }
        halt.as_mut().poll(cx).map(|()| None)
    })
    .await
}

fn index_session(
    driver: &Rc<SimDriver>,
    model: &Shared,
    cores: u16,
    tuning: (u64, usize),
    second: bool,
) -> bool {
    let Some(cluster) = try_started(driver, cores, 0, Some(tuning), false, NAMING) else {
        return false;
    };
    let nodes = cluster.nodes.clone();
    let client = cluster.client.clone();
    let model = Rc::clone(model);
    let power = Rc::clone(driver);
    let finished = cluster.run(async move {
        if unless_halted(&power, ready(&nodes)).await.is_none() {
            return false;
        }
        if second {
            verify_model(&nodes, &model).await;
        }
        let ticking = Rc::clone(&power);
        let running = Rc::new(Cell::new(true));
        let still = Rc::clone(&running);
        let ticker = spawn(async move {
            while still.get() && !ticking.is_halted() {
                if client.checkpoint().await.is_err() {
                    return;
                }
                sleep(Duration::from_millis(4)).await;
            }
        });
        let workers: Vec<_> = (0..3)
            .map(|w| {
                spawn(work(
                    nodes.clone(),
                    Rc::clone(&model),
                    Rc::clone(&power),
                    w,
                    150,
                ))
            })
            .collect();
        let all = async move {
            for worker in workers {
                worker.await;
            }
        };
        if unless_halted(&power, all).await.is_none() {
            return false;
        }
        running.set(false);
        if unless_halted(&power, ticker).await.is_none() {
            return false;
        }
        unless_halted(&power, verify_model(&nodes, &model))
            .await
            .is_some()
    });
    if second && finished {
        cluster.stop();
    }
    finished
}

fn index_crash(seed: u64, cores: u16) {
    let small = seed % 4 == 3;
    let tuning = if seed.is_multiple_of(2) || small {
        (1, 2)
    } else {
        (1, 64)
    };
    let model: Shared = Rc::default();
    let config = Config {
        halt_after: Some(200 + seed * 7_919 % 1_200),
        faults: Faults {
            torn_write: 250_000,
            ..Faults::default()
        },
        ..Config::default()
    };
    let options = if small { SMALL } else { OPTIONS };
    let first = Rc::new(SimDriver::with_disk(
        seed,
        config,
        created_with(seed, options),
    ));
    index_session(&first, &model, cores, tuning, false);
    let second = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        first.crash(),
    ));
    assert!(
        index_session(&second, &model, cores, tuning, true),
        "seed {seed}: second session did not finish"
    );
    let model = model.borrow();
    assert!(
        model.acked > 0,
        "seed {seed}: no suppression change acknowledged"
    );
    assert!(model.accepts > 0, "seed {seed}: nothing accepted");
    assert!(model.replays > 0, "seed {seed}: nothing replayed");
}

#[test]
fn index_survives_crashes_on_two_cores() {
    check(0..4, |seed| index_crash(seed, 2));
}

#[test]
fn index_survives_crashes_on_four_cores() {
    check(0..4, |seed| index_crash(seed, 4));
}

async fn dkim_everywhere(nodes: &[Node<Idle>], tenant: u32, id: u32) {
    for node in nodes {
        while node.table().dkim(tenant, id).is_none() {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

fn digest_of(message: &[u8]) -> [u8; 32] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, message)
        .as_ref()
        .try_into()
        .expect("32 bytes")
}

fn verifies(dkim: &Dkim, message: &[u8], signed: &[u8]) {
    match dkim.alg {
        DkimAlg::Ed25519Sha256 => {
            UnparsedPublicKey::new(&ED25519, &dkim.public).verify(&digest_of(message), signed)
        }
        DkimAlg::RsaSha256 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &dkim.public)
            .verify(message, signed),
    }
    .expect("verify");
}

async fn dropped_calls_land_and_bursts_get_busy(
    nodes: &[Node<Idle>],
    control: &Node<Idle>,
    rsa: &Dkim,
) {
    let message = b"burst";
    let digest = digest_of(message);
    let dropped = timeout(
        Duration::ZERO,
        control.dkim_new(1, DkimAlg::Ed25519Sha256, "example.org", "s4"),
    )
    .await;
    assert!(dropped.is_err());
    dkim_everywhere(nodes, 1, 4).await;
    let dropped = timeout(Duration::ZERO, control.write(tenant(3, 1, State::Active))).await;
    assert!(dropped.is_err());
    wait_for(nodes, 3, 1, State::Active).await;
    control
        .write(tenant(3, 1, State::Suspended))
        .await
        .expect("writer returned");
    let burst: Vec<_> = (0..8)
        .map(|_| {
            let (node, id) = (control.clone(), rsa.id);
            spawn(async move { node.sign(1, id, digest).await })
        })
        .collect();
    let mut busy = 0;
    for task in burst {
        match task.await {
            Ok(signed) => verifies(rsa, message, &signed),
            Err(refusal) => {
                assert_eq!(refusal, Refusal::Busy);
                busy += 1;
            }
        }
    }
    assert!(busy > 0 && busy < 8);
}

#[test]
fn dkim_keys_are_made_on_the_control_core_and_sign_on_every_core_after_a_restart() {
    let driver = Rc::new(SimDriver::with_disk(41, Config::default(), created(41)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    let made = cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let other = nodes.iter().find(|n| !n.controls()).expect("other core");
        let ed = DkimAlg::Ed25519Sha256;
        assert!(matches!(
            other.dkim_new(1, ed, "example.org", "s1").await,
            Err(sched::Error::Control(control::Error::Invalid("core")))
        ));
        assert!(matches!(
            control.dkim_new(1, ed, "example.org", "s_1").await,
            Err(sched::Error::Control(control::Error::Invalid("selector")))
        ));
        assert!(matches!(
            control.dkim_new(7, ed, "example.org", "s1").await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
        let first = control
            .dkim_new(1, ed, "example.org", "s1")
            .await
            .expect("new");
        let second = control
            .dkim_new(1, DkimAlg::RsaSha256, "example.org", "s2")
            .await
            .expect("new");
        assert_eq!((first.id, second.id), (1, 2));
        assert!(second.txt().starts_with("v=DKIM1; k=rsa; p=MIIBIjAN"));
        assert!(matches!(
            control.write(Object::Dkim(first.clone())).await,
            Err(sched::Error::Control(control::Error::Invalid("kind")))
        ));
        dkim_everywhere(&nodes, 1, 2).await;
        let message = b"from:a@example.org";
        let digest = digest_of(message);
        for node in &nodes {
            for made in [&first, &second] {
                let signed = node.sign(1, made.id, digest).await.expect("sign");
                verifies(made, message, &signed);
            }
            assert_eq!(node.sign(2, first.id, digest).await, Err(Refusal::Signer));
            assert_eq!(node.sign(1, 9, digest).await, Err(Refusal::Signer));
            assert_eq!(node.sign(5, first.id, digest).await, Err(Refusal::Tenant));
        }
        configure(&nodes, vec![tenant(2, 1, State::Suspended)]).await;
        wait_for(&nodes, 2, 1, State::Suspended).await;
        assert!(matches!(
            control.dkim_new(2, ed, "example.org", "s1").await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
        vec![first, second]
    });
    assert_eq!(audited(&driver, "load"), 0);
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(42, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        keys_listening().await;
        wait_for(&nodes, 1, 1, State::Active).await;
        dkim_everywhere(&nodes, 1, 2).await;
        let message = b"to:b@example.org";
        let digest = digest_of(message);
        for node in &nodes {
            for made in &made {
                let tasks: Vec<_> = (0..4)
                    .map(|_| {
                        let (node, id) = (node.clone(), made.id);
                        spawn(async move { node.sign(1, id, digest).await })
                    })
                    .collect();
                for task in tasks {
                    verifies(made, message, &task.await.expect("sign"));
                }
            }
        }
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let third = control
            .dkim_new(1, DkimAlg::Ed25519Sha256, "example.org", "s3")
            .await
            .expect("new");
        assert_eq!(third.id, 3);
        dropped_calls_land_and_bursts_get_busy(&nodes, control, &made[1]).await;
        sleep(Duration::from_millis(300)).await;
    });
    assert_eq!(audited(&driver, "load"), 2);
    restarted.stop();
}

fn control_of(nodes: &[Node<Idle>]) -> &Node<Idle> {
    nodes.iter().find(|n| n.controls()).expect("control core")
}

async fn never_opens(nodes: &[Node<Idle>], sealed: &Sealed) {
    for node in nodes {
        assert!(
            node.opener(1, 1, sealed.id, &sealed.clear, &sealed.wrap)
                .await
                .is_err()
        );
    }
}

fn refused(result: &Result<control::Update, sched::Error>) {
    assert!(
        matches!(result, Err(sched::Error::Control(control::Error::Refused))),
        "{result:?}"
    );
}

#[test]
fn a_deleted_tenant_is_refused_loses_its_mail_and_never_opens_again() {
    let driver = Rc::new(SimDriver::with_disk(43, Config::default(), created(43)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    let sealed = cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let gone = seal_for(node, 1, shard, 1).await;
        let kept = seal_for(node, 2, shard, 2).await;
        assert_eq!(node.spool().messages_of(1).len(), 1);
        for node in &nodes {
            opens_for(node, 1, &gone, 1).await;
        }
        let control = control_of(&nodes);
        control.delete_tenant(1).await.expect("delete");
        wait_for(&nodes, 1, 1, State::Deleted).await;
        refused(&control.delete_tenant(1).await);
        for object in [
            tenant(1, 1, State::Active),
            tenant(1, 1, State::Deleted),
            tenant(1, 3, State::Active),
            tenant(2, 1, State::Deleting),
            tenant(2, 1, State::Deleted),
        ] {
            refused(&control.write(object).await);
        }
        for node in &nodes {
            assert!(matches!(node.draft(1, None), Err(Refusal::Tenant)));
            while !node.spool().messages_of(1).is_empty() {
                sleep(Duration::from_millis(1)).await;
            }
        }
        assert_eq!(nodes.iter().map(Node::tenant_drops).sum::<u64>(), 1);
        never_opens(&nodes, &gone).await;
        opens_for(node, 2, &kept, 2).await;
        sleep(Duration::from_millis(300)).await;
        (gone, kept)
    });
    assert_eq!(audited(&driver, "delete"), 1);
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(44, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        keys_listening().await;
        wait_for(&nodes, 1, 1, State::Deleted).await;
        let (gone, kept) = sealed;
        never_opens(&nodes, &gone).await;
        opens_for(&nodes[0], 2, &kept, 2).await;
        for node in &nodes {
            assert_eq!(node.spool().messages_of(1), Vec::new());
        }
        configure(&nodes, vec![tenant(1, 2, State::Active)]).await;
        wait_for(&nodes, 1, 2, State::Active).await;
        never_opens(&nodes, &gone).await;
        let shard = owned_shard(&nodes[0]).await;
        let mut draft = nodes[0]
            .draft(1, None)
            .expect("draft at the new generation");
        nodes[0]
            .recipient(&mut draft, "back@example.org")
            .await
            .expect("recipient");
        nodes[0].sealing(&mut draft, shard).await.expect("sealing");
    });
    restarted.stop();
}

#[test]
fn a_delete_cut_by_a_crash_finishes_after_a_restart() {
    let driver = Rc::new(SimDriver::with_disk(45, Config::default(), created(45)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        control_of(&nodes).delete_tenant(2).await.expect("delete");
    });
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(46, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        assert_eq!(
            nodes[0].table().tenant(2).map(|t| t.state),
            Some(State::Deleting)
        );
        keys_listening().await;
        wait_for(&nodes, 2, 1, State::Deleted).await;
        for node in &nodes {
            assert!(matches!(node.draft(2, None), Err(Refusal::Tenant)));
        }
        wait_for(&nodes, 1, 1, State::Active).await;
        nodes[0].draft(1, None).expect("tenant 1 untouched");
    });
    restarted.stop();
}
