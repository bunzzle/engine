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
    ALL_EVENTS, Created, Dkim, Domain, Hook, HookState, KeyError, KeySource, Naming, Object, Pool,
    Ready, Scope, Scopes, State, Table, Tenant, Verification,
};
use crypto::{
    ANY, BatchKey, DkimAlg, Ids, Secret, Tenant as Root, TenantKeys, Token, Wrap, day_public,
    open_batch,
};
use index::{Entry, Op};
use keys::{
    Audit, BatchSettings, Batches, Client as KeyClient, Connect, Ring, RingSettings, SearchKeys,
    Server, Settings as KeySettings, Vault, Working,
};
use rt::sim::{Config, Disk, Faults, Machine, Rng, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, TcpListener, TcpStream, sleep, spawn, timeout};
use sched::{
    Answer, Answered, Attempt, Batched, Begun, Call, CallStats, Clock, Cursor, DAY, DayKeys,
    Deliver, Draft, EVENT_DAYS, EVENT_SHAPE, EVENT_VALUE, Envelope, Event, EventBody, EventKind,
    Fault, Found, Hash, HookChange, HookStats, KIND_EVENT, KIND_REQUEST, KIND_SEARCH,
    KIND_SUPPRESS, Keyring, Keys, MAX_HOOKS, MAX_REPLY, Made, Meshes, Node, Outcome, Parts,
    ROTATION_MS, ReadError, Reason, Recipient, Refusal, Restore, Running, SEARCH_VALUE, SHAPE,
    SearchField, SearchQuery, Searched, Sending, Settings, Signed, Suppression, Ticket, Transport,
    Unsealable, Unwrapped, drop_cursor, encode_slice, event_record, event_sealed, event_sequence,
    normalize, punycode, read_cursor, retain, retain_event, retain_request, retain_search,
    retired_events, search_event_key, search_hash, search_key, write_cursor,
};
use spool::{Body, Head, HeadClear, Message, MessageId, SLICE, Slice, Stamp};
use store::{Client, Committer, DataFile, IndexStamp, Options, SLOT_SIZE, Setup, Tiering, boot};

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
        RETURN_PROBE.with_borrow_mut(|probe| {
            if let Some(probe) = probe {
                probe.lookups.cached += 1;
            }
        });
        if tenant == KEYLESS || HOOK_KEYS_DOWN.with(Cell::get) {
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
        RETURN_PROBE.with_borrow_mut(|probe| {
            if let Some(probe) = probe {
                probe.lookups.ready += 1;
            }
        });
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

const SEARCH_DAYS: std::ops::RangeInclusive<u32> = 0..=10;

fn search_days() -> impl Iterator<Item = u32> {
    let wall = keys::wall_day();
    SEARCH_DAYS.chain(wall.saturating_sub(1)..=wall.saturating_add(1))
}

fn toy_search_key(tenant: u32, day: u32) -> Secret<16> {
    let mut bytes = [5; 16];
    bytes[..4].copy_from_slice(&tenant.to_le_bytes());
    bytes[4..8].copy_from_slice(&day.to_le_bytes());
    Secret::new(bytes)
}

fn search_entries(
    tenant: u32,
    message: MessageId,
    address: &str,
    day: u32,
) -> [(SearchField, [u8; 20]); 3] {
    let key = toy_search_key(tenant, day);
    let message = message.bytes();
    let domain = address.rsplit_once('@').expect("domain").1;
    [
        (SearchField::Recipient, address.as_bytes()),
        (SearchField::Domain, domain.as_bytes()),
        (SearchField::Message, &message[..]),
    ]
    .map(|(field, value)| {
        (
            field,
            search_key(tenant, field, &search_hash(&key, field, value)),
        )
    })
}

impl Keys for Toy {
    fn ids(&self) -> Option<Secret<16>> {
        RETURN_PROBE.with_borrow_mut(|probe| {
            probe.as_mut().map(|probe| {
                probe.lookups.ids += 1;
                Secret::new(RETURN_IDS)
            })
        })
    }

    fn dkim_new(&self, _: u32, _: u32, _: u32, _: DkimAlg) -> Made<'_> {
        let made =
            RETURN_PROBE.with_borrow(|probe| probe.as_ref().map(|_| (vec![1; 32], vec![2; 16])));
        Box::pin(std::future::ready(made.ok_or(KeyError::Unavailable)))
    }

    fn sign(&self, _: u32, _: u32, _: u32, _: DkimAlg, _: [u8; 32]) -> Signed<'_> {
        let signature = RETURN_PROBE.with_borrow(|probe| probe.as_ref().map(|_| vec![3; 64]));
        Box::pin(std::future::ready(signature.ok_or(KeyError::Unavailable)))
    }

    fn search(&self, tenant: u32, generation: u32) -> Searched<'_> {
        let keys = self.get(tenant, generation).map(|_| {
            DayKeys::new(
                search_days()
                    .map(|day| (day, toy_search_key(tenant, day)))
                    .collect(),
            )
        });
        Box::pin(std::future::ready(keys.ok_or(KeyError::Unavailable)))
    }

    fn system(&self) -> Ready<'_> {
        Box::pin(std::future::ready(Ok(TenantKeys::derive(
            0,
            0,
            &Root::new(&Secret::new([42; 32])),
            1,
        ))))
    }

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
                    search: SearchKeys::default(),
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
        let key = if UNWRAP_DOWN.with(Cell::get) {
            Err(Unsealable::Unavailable)
        } else if (wrap.generation, wrap.shard) == (generation, shard) {
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

thread_local! {
    static RESTORED: RefCell<Option<Vec<Restore>>> = const { RefCell::new(None) };
    static TICKS: Cell<u32> = const { Cell::new(0) };
    static ANSWERS: RefCell<Option<Answers>> = const { RefCell::new(None) };
    static HOOK_KEYS_DOWN: Cell<bool> = const { Cell::new(false) };
    static KEYS_DOWN_ON_GONE: Cell<bool> = const { Cell::new(false) };
    static UNWRAP_DOWN: Cell<bool> = const { Cell::new(false) };
    static LISTED: RefCell<BTreeMap<[u8; 16], Vec<String>>> = const { RefCell::new(BTreeMap::new()) };
    static RETURN_PROBE: RefCell<Option<ReturnProbe>> = const { RefCell::new(None) };
}

type Given = (MessageId, u32, u16, EventKind);

struct Answers {
    clock: Clock,
    given: Vec<Given>,
}

const RETURN_IDS: [u8; 16] = [27; 16];

#[derive(Debug, Default, PartialEq, Eq)]
struct ReturnLookups {
    cached: u32,
    ready: u32,
    ids: u32,
}

struct ReturnProbe {
    prepared: rt::Sender<PreparedReturn>,
    lookups: ReturnLookups,
}

#[derive(Debug)]
struct PreparedReturn {
    message: MessageId,
    sender: String,
    recipients: Vec<u32>,
    lookups: ReturnLookups,
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

async fn answer(attempt: Attempt) -> Vec<Answered> {
    let Some(clock) = ANSWERS.with_borrow(|a| a.as_ref().map(|a| a.clock)) else {
        return Vec::new();
    };
    RETURN_PROBE.with_borrow_mut(|probe| {
        if let Some(probe) = probe {
            probe.lookups = ReturnLookups::default();
        }
    });
    let prepared = attempt.outgoing.prepare().await;
    if let Some(probe) = RETURN_PROBE.with_borrow_mut(Option::take) {
        let Ok(prepared) = &prepared else {
            panic!("return-path message failed to prepare");
        };
        let recipients = prepared
            .recipients
            .iter()
            .map(|(index, _)| *index)
            .collect();
        probe
            .prepared
            .send(PreparedReturn {
                message: attempt.message,
                sender: prepared.envelope.sender.clone(),
                recipients,
                lookups: probe.lookups,
            })
            .expect("return-path observer");
    }
    let opener = match prepared {
        Ok(prepared) => prepared.opener,
        Err(Fault::Format(opener) | Fault::Recipients(opener) | Fault::Signer(opener)) => opener,
        Err(_) => return Vec::new(),
    };
    let mut answered = Vec::new();
    for c in &attempt.recipients {
        let attempts = c.attempts.saturating_add(1);
        let roll =
            mix(attempt.message.key ^ u64::from(c.recipient) << 32 ^ u64::from(attempts)) % 4;
        let (answer, kind) = match roll {
            0 | 1 => (Answer::Delivered, EventKind::Delivered),
            2 => (Answer::Failed, EventKind::Failed),
            _ if attempts >= 3 => (Answer::Delivered, EventKind::Delivered),
            _ => (
                Answer::Deferred(sched::Kind::RetryAfter(1000)),
                EventKind::Deferred,
            ),
        };
        let body = EventBody {
            kind,
            time: clock.now(),
            address: LISTED.with_borrow(|l| {
                l.get(&attempt.message.bytes())
                    .and_then(|a| a.get(usize::try_from(c.recipient).ok()?))
                    .map(|a| a.as_bytes().to_vec())
                    .unwrap_or_default()
            }),
            reply: b"250 ok".to_vec(),
            attempts,
            class: c.class,
        };
        ANSWERS.with_borrow_mut(|a| {
            if let Some(a) = a {
                a.given.push((attempt.message, c.recipient, attempts, kind));
            }
        });
        answered.push(Answered {
            recipient: c.recipient,
            answer,
            reply: Vec::new(),
            event: opener.event(c.recipient, c.stamp, &body).ok(),
            bounced: None,
        });
    }
    answered
}

impl Transport for Idle {
    fn send(&self, attempt: Attempt) -> impl Future<Output = Vec<Answered>> {
        answer(attempt)
    }

    fn restore(&self, restore: Restore) -> impl Future<Output = ()> {
        RESTORED.with_borrow_mut(|kept| {
            if let Some(kept) = kept {
                kept.push(restore);
            }
        });
        std::future::ready(())
    }

    fn tick(&self) -> impl Future<Output = ()> {
        TICKS.set(TICKS.get() + 1);
        std::future::ready(())
    }
}

fn keep_restores() {
    RESTORED.with_borrow_mut(|kept| *kept = Some(Vec::new()));
}

fn restores() -> Vec<Restore> {
    let mut restores =
        RESTORED.with_borrow_mut(|kept| kept.replace(Vec::new()).expect("keeping restores"));
    restores.retain(|r| r.kind == control::KIND_STS);
    restores.sort_by_key(|r| r.records.home());
    restores
}

fn saved(restores: &[Restore]) -> BTreeSet<(u16, u32, Vec<u8>)> {
    restores
        .iter()
        .flat_map(|r| &r.saved)
        .map(|s| (s.shard, s.id, s.data.clone()))
        .collect()
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
            read: 1024 * 1024,
        },
        naming: Naming {
            key,
            shards: u32::from(SHARDS),
            cache: 16,
        },
        sched: sched::Config::new(u32::from(SHARDS)),
        budget: usize::try_from(OPTIONS.region_size / 2).expect("fits"),
        watched: Vec::new(),
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
    try_started(
        driver,
        cores,
        behind,
        tuning,
        false,
        &settings_named(NAMING),
    )
    .expect("start")
}

fn started_with_keys(driver: &Rc<SimDriver>, cores: u16) -> Cluster {
    try_started(driver, cores, 0, None, true, &settings_named(NAMING)).expect("start")
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
    settings: &Settings,
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
        let settings = settings.clone();
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
            let started = Node::start(core, links, settings, parts);
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
fn event_retention_keeps_a_week_and_drops_old_generations() {
    let mut table = Table::default();
    table.take(control::Note::Snapshot(control::Snapshot {
        version: 1,
        objects: vec![tenant(1, 2, State::Active)],
    }));
    let entry = |tenant: u32, generation: u32| {
        let event = Event {
            generation,
            time: 1,
            kind: EventKind::Delivered,
            lost: 0,
            message: MessageId::from_bytes([1; 16]),
            recipient: 0,
            stamp: Stamp { boot: 1, write: 1 },
            batch: 1,
            day: 1,
        };
        Entry::put(index::key(tenant, [0; 16]), event.encode(), Vec::new())
    };
    assert!(!retain_event(&table, &entry(1, 1)));
    assert!(retain_event(&table, &entry(1, 2)));
    assert!(retain_event(&table, &entry(9, 1)));
    let mut short = entry(1, 1);
    short.value.pop();
    assert!(retain_event(&table, &short));
    assert!(retain_event(
        &table,
        &Entry::delete(index::key(1, [0; 16]), EVENT_SHAPE)
    ));
    let found = |tenant: u32, generation: u32| {
        let found = Found {
            back: 1,
            time: 1,
            kind: EventKind::Delivered,
            generation,
        };
        Entry::put(index::key(tenant, [0; 16]), found.encode(), Vec::new())
    };
    table.take(control::Note::Snapshot(control::Snapshot {
        version: 2,
        objects: vec![tenant(1, 2, State::Active), tenant(2, 1, State::Active)],
    }));
    assert!(retain_search(&table, &found(2, 1)));
    assert!(!retain_search(&table, &found(1, 1)));
    assert!(retain_search(&table, &found(1, 2)));
    assert!(retain_search(&table, &found(9, 1)));
    let mut short = found(1, 1);
    short.value.pop();
    assert!(retain_search(&table, &short));
    assert!(retain_search(
        &table,
        &Entry::delete(index::key(1, [0; 16]), sched::SEARCH_SHAPE)
    ));
    assert_eq!(EVENT_DAYS, 7);
    assert_eq!(retired_events(20), 14);
    assert_eq!(retired_events(3), 0);
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
fn bounces_keep_live_suppressions_and_follow_the_generation() {
    let driver = Rc::new(SimDriver::with_disk(3, Config::default(), created(3)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let lists = nodes[0].suppressions();
        lists
            .add(1, "said@example.org", Reason::Complaint, None)
            .await
            .expect("add");
        lists
            .bounce(1, 1, "said@example.org")
            .await
            .expect("bounce");
        lists
            .bounce(1, 1, "gone@example.org")
            .await
            .expect("bounce");
        let said = lists.get(1, "said@example.org").await.expect("get");
        assert_eq!(said.map(|s| s.reason), Some(Reason::Complaint));
        let gone = lists.get(1, "gone@example.org").await.expect("get");
        assert_eq!(
            gone.map(|s| (s.reason, s.until)),
            Some((Reason::Bounce, None))
        );
        assert_eq!(
            lists.bounce(1, 2, "ahead@example.org").await,
            Err(Refusal::Tenant)
        );
        assert_eq!(lists.get(2, "gone@example.org").await, Ok(None));

        configure(&nodes, vec![tenant(2, 1, State::Suspended)]).await;
        wait_for(&nodes, 2, 1, State::Suspended).await;
        lists
            .bounce(2, 1, "paused@example.org")
            .await
            .expect("bounce while suspended");
        configure(&nodes, vec![tenant(2, 1, State::Active)]).await;
        wait_for(&nodes, 2, 1, State::Active).await;
        let paused = lists.get(2, "paused@example.org").await.expect("get");
        assert_eq!(paused.map(|s| s.reason), Some(Reason::Bounce));

        regenerate(&nodes, 1).await;
        wait_for(&nodes, 1, 2, State::Active).await;
        assert_eq!(
            lists.bounce(1, 1, "late@example.org").await,
            Err(Refusal::Tenant)
        );
        assert_eq!(lists.get(1, "gone@example.org").await, Ok(None));
        assert_eq!(lists.get(1, "late@example.org").await, Ok(None));
        lists
            .bounce(1, 2, "new@example.org")
            .await
            .expect("bounce in the new generation");
        assert_eq!(
            lists.check(1, 2, &["new@example.org"]).await,
            Ok(vec![true])
        );

        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        control.delete_tenant(2).await.expect("delete");
        while nodes
            .iter()
            .any(|n| n.table().tenant(2).is_some_and(|t| !t.state.deleted()))
        {
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            lists.bounce(2, 1, "end@example.org").await,
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
    assert!(
        try_started(
            &other,
            2,
            0,
            None,
            false,
            &settings_named(*b"another key 16 b")
        )
        .is_none()
    );
    let same = Rc::new(SimDriver::with_disk(35, Config::default(), disk));
    let restarted = started(&same, 2);
    restarted.stop();
}

#[test]
fn a_different_node_id_refuses_to_start() {
    let driver = Rc::new(SimDriver::with_disk(36, Config::default(), created(36)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move { ready(&nodes).await });
    cluster.stop();
    let disk = driver.crash();
    let moved = Settings {
        node: 4,
        ..settings_named(NAMING)
    };
    let other = Rc::new(SimDriver::with_disk(37, Config::default(), disk.clone()));
    assert!(try_started(&other, 2, 0, None, false, &moved).is_none());
    let same = Rc::new(SimDriver::with_disk(38, Config::default(), disk));
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
fn events_seal_under_their_message_and_open_from_the_record() {
    let driver = Rc::new(SimDriver::with_disk(43, Config::default(), created(43)));
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
        let body = EventBody {
            kind: EventKind::Delivered,
            time: 3 * DAY + 5,
            address: b"a@example.com".to_vec(),
            reply: vec![b'x'; MAX_REPLY + 10],
            attempts: 3,
            class: 2,
        };
        let sealed_body = opener.seal_event(0, stamp, &body.encode()).expect("seal");
        assert_eq!(
            opener.seal_event(0, stamp, &body.encode()).err(),
            Some(Unsealable::Bad)
        );
        let reply = opener.seal_reply(0, stamp, b"250 ok").expect("reply");
        let event = Event {
            generation: 1,
            time: 3 * DAY + 5,
            kind: EventKind::Delivered,
            lost: 2,
            message: sealed.id,
            recipient: 0,
            stamp,
            batch: sealed.clear.batch_key,
            day: sealed.clear.day,
        };
        let record = event_record(1, &event, &sealed.wrap, &sealed_body).expect("record");
        assert_eq!(record.stamp, IndexStamp::Head);
        assert_eq!((record.kind, record.partition), (KIND_EVENT, 3));
        assert_eq!(record.entry.key, index::key(1, [0; 16]));
        let decoded = Event::decode(&record.entry.value).expect("value");
        assert_eq!(decoded, event);
        let (wrap, inner) = event_sealed(&record.entry.payload).expect("payload");
        let reader = node
            .event_opener(1, &decoded, wrap)
            .await
            .expect("event opener");
        let clear = reader.open_event(0, stamp, inner).expect("open");
        let capped = EventBody {
            reply: vec![b'x'; MAX_REPLY],
            ..body
        };
        assert_eq!(EventBody::decode(&clear).as_ref(), Some(&capped));
        assert!(decoded.checked(&capped));
        let edited = Event {
            kind: EventKind::Failed,
            ..decoded
        };
        assert!(!edited.checked(&capped));
        let bad = Some(Unsealable::Bad);
        assert_eq!(reader.open_reply(0, stamp, inner).err(), bad);
        assert_eq!(reader.open_event(0, stamp, &reply).err(), bad);
        assert_eq!(reader.open_event(1, stamp, inner).err(), bad);
        let moved = Event {
            day: event.day + 1,
            ..event
        };
        assert!(node.event_opener(1, &moved, wrap).await.is_err());
        let older = Event {
            generation: 2,
            ..event
        };
        assert!(node.event_opener(1, &older, wrap).await.is_err());
        let next = node.spool().stamp(shard).expect("stamp");
        let built = opener.event(1, next, &capped).expect("event");
        assert_eq!(built.search, []);
        let value = Event::decode(&built.record.entry.value).expect("value");
        assert_eq!(
            value,
            Event {
                recipient: 1,
                stamp: next,
                lost: 0,
                ..event
            }
        );
        let (wrap, inner) = event_sealed(&built.record.entry.payload).expect("payload");
        assert_eq!(wrap, &sealed.wrap);
        let clear = reader.open_event(1, next, inner).expect("open");
        assert_eq!(EventBody::decode(&clear), Some(capped.clone()));
        assert_eq!(opener.event(1, next, &capped).err(), Some(Unsealable::Bad));
    });
    cluster.stop();
}

async fn accept_listed(
    node: &Node<Idle>,
    shard: u16,
    addresses: &[&str],
    expiry: u64,
) -> (MessageId, [u8; spool::WRAP]) {
    accept_listed_with_head(node, shard, addresses, expiry, &[1; 10], b"Subject: hi\r\n").await
}

async fn accept_listed_with_head(
    node: &Node<Idle>,
    shard: u16,
    addresses: &[&str],
    expiry: u64,
    envelope: &[u8],
    headers: &[u8],
) -> (MessageId, [u8; spool::WRAP]) {
    let mut draft = node.draft(1, None).expect("draft");
    for address in addresses {
        node.recipient(&mut draft, address)
            .await
            .expect("recipient");
    }
    let mut sealing = node.sealing(&mut draft, shard).await.expect("sealing");
    let clear = HeadClear {
        recipients: u32::try_from(addresses.len()).expect("fits"),
        accepted: 5,
        ..HeadClear::default()
    };
    let head = sealing
        .head(clear, expiry, envelope, headers)
        .expect("head");
    let wrap = head.wrap;
    let body = sealing.inline_body(&[1; 30]).expect("body");
    let listed: Vec<Recipient> = addresses
        .iter()
        .map(|a| Recipient {
            address: (*a).to_owned(),
            orcpt: Vec::new(),
            notify: 0,
        })
        .collect();
    let plain = encode_slice(&listed).expect("slice");
    let slice = sealing
        .slice(0, draft.queues().to_vec(), &plain)
        .expect("slice");
    let id = sealing.id();
    let message = Message {
        id,
        tenant: 1,
        head,
        body,
        slices: vec![slice],
    };
    let listed = addresses.iter().map(|a| (*a).to_owned()).collect();
    LISTED.with_borrow_mut(|l| l.insert(id.bytes(), listed));
    node.accept(draft, message).await.expect("accept");
    (id, wrap)
}

const RETURN_SENDER: &str = "sender@news.example.org";

fn prepared_return(return_path: bool, addresses: &'static [&'static str]) -> PreparedReturn {
    let driver = Rc::new(SimDriver::with_disk(47, Config::default(), created(47)));
    let cluster = started(&driver, 1);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        timeout(Duration::from_secs(30), async move {
            ready(&nodes).await;
            let node = &nodes[0];
            let (observe, mut observed) = rt::channel();
            RETURN_PROBE.with_borrow_mut(|probe| {
                *probe = Some(ReturnProbe {
                    prepared: observe,
                    lookups: ReturnLookups::default(),
                });
            });
            let name = "example.org";
            let selector = "s1";
            let alg = DkimAlg::Ed25519Sha256;
            let key = node.dkim_new(1, alg, name, selector).await.expect("dkim");
            let domain = node.domain_new(1, name).await.expect("domain");
            node.domain_write(Domain {
                return_path,
                state: Verification::Verified,
                ed25519: key.id,
                ..domain
            })
            .await
            .expect("verify domain");
            let envelope = Envelope {
                sender: RETURN_SENDER.into(),
                signatures: vec![(key.id, alg)],
                ..Envelope::default()
            }
            .encode()
            .expect("envelope");
            let received = b"Received: by test\r\n";
            let from = b"From: sender@news.example.org\r\n";
            let signature = dkim::unsigned(
                &dkim::Template {
                    alg,
                    domain: name,
                    selector,
                    time: 1,
                    expiry: 2,
                },
                &dkim::parse(from).expect("from"),
                &[0; 32],
            )
            .expect("unsigned signature");
            let headers = [received.as_slice(), &signature, from].concat();
            let shard = owned_shard(node).await;
            answering(&nodes);
            let (id, _) =
                accept_listed_with_head(node, shard, addresses, u64::MAX / 2, &envelope, &headers)
                    .await;
            let prepared = observed.recv().await.expect("prepared return path");
            assert_eq!(prepared.message, id);
            prepared
        })
        .await
        .expect("timed out preparing return path")
    })
}

fn verified_return(prepared: &PreparedReturn) -> Token {
    let (local, domain) = prepared.sender.split_once('@').expect("sender address");
    assert_eq!(domain, "bounce.example.org");
    let text = local.strip_prefix('b').expect("token prefix");
    let token = Token::parse(text.as_bytes()).expect("token");
    let keys = Toy::default().get(1, 1).expect("tenant keys");
    assert!(token.verify(&keys));
    let ids = Ids::new(&Secret::new(RETURN_IDS)).expect("node ids");
    assert_eq!(ids.reveal(&token.id), Some(prepared.message.bytes()));
    token
}

#[test]
fn return_path_binds_the_only_recipient() {
    let prepared = prepared_return(true, &["one@example.net"]);
    assert_eq!(prepared.recipients, [0]);
    assert_eq!(verified_return(&prepared).recipient, 0);
}

#[test]
fn return_path_uses_any_for_a_batch() {
    let prepared = prepared_return(true, &["one@example.net", "two@example.net"]);
    assert_eq!(prepared.recipients, [0, 1]);
    assert_eq!(verified_return(&prepared).recipient, ANY);
}

#[test]
fn return_path_skips_key_lookups_for_an_unflagged_domain() {
    let prepared = prepared_return(false, &["one@example.net"]);
    assert_eq!(prepared.sender, RETURN_SENDER);
    assert_eq!(
        prepared.lookups,
        ReturnLookups {
            cached: 1,
            ..ReturnLookups::default()
        }
    );
}

#[test]
fn events_carry_search_entries_under_their_day_key() {
    let driver = Rc::new(SimDriver::with_disk(47, Config::default(), created(47)));
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
            .expect("opener")
            .searching(&Toy::default())
            .await;
        let body = EventBody {
            kind: EventKind::Failed,
            time: 3 * DAY + 5,
            address: b"A@Example.COM".to_vec(),
            reply: b"550 no".to_vec(),
            attempts: 1,
            class: 0,
        };
        let stamp = node.spool().stamp(shard).expect("stamp");
        let built = opener.event(0, stamp, &body).expect("event");
        let event = Event::decode(&built.record.entry.value).expect("event");
        let wanted = search_entries(1, sealed.id, "a@example.com", 3);
        assert_eq!(built.search.len(), 3);
        for (n, (record, (_, key))) in built.search.iter().zip(wanted).enumerate() {
            assert_eq!(record.stamp, IndexStamp::Tail);
            assert_eq!((record.kind, record.partition), (KIND_SEARCH, 3));
            assert_eq!(record.entry.key, key);
            assert_eq!(record.entry.payload, []);
            assert_eq!(record.entry.value.len(), SEARCH_VALUE);
            let found = Found::decode(&record.entry.value).expect("value");
            assert_eq!(usize::from(found.back), n + 1);
            assert!(found.matches(&event));
        }
        let far = EventBody {
            time: 100 * DAY,
            ..body
        };
        let later = node.spool().stamp(shard).expect("stamp");
        let alone = opener.event(1, later, &far).expect("event");
        assert_eq!(alone.search, []);
    });
    cluster.stop();
}

#[test]
fn expiry_events_name_each_open_recipient() {
    let driver = Rc::new(SimDriver::with_disk(44, Config::default(), created(44)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let addresses = ["x@example.org", "y@example.org"];
        let (id, wrap) = accept_listed(node, shard, &addresses, u64::MAX / 2).await;
        let events = node.expiry_events(id, 7 * DAY).await.expect("events");
        assert_eq!(events.len(), 2);
        for (event, address) in events.iter().zip(addresses) {
            let value = Event::decode(&event.record.entry.value).expect("value");
            let keys: Vec<[u8; 20]> = event.search.iter().map(|r| r.entry.key).collect();
            let wanted = search_entries(1, id, address, 7).map(|(_, key)| key);
            assert_eq!(keys, wanted);
            for record in &event.search {
                let found = Found::decode(&record.entry.value).expect("value");
                assert_eq!(
                    (found.time, found.kind, found.generation),
                    (value.time, value.kind, value.generation)
                );
            }
            assert_eq!(
                (value.kind, value.time, value.message),
                (EventKind::Expired, 7 * DAY, id)
            );
            assert_eq!(
                (value.recipient, value.stamp),
                (event.recipient, event.stamp)
            );
            let (kept, inner) = event_sealed(&event.record.entry.payload).expect("payload");
            assert_eq!(kept, &wrap);
            let opener = node.event_opener(1, &value, kept).await.expect("opener");
            let clear = opener
                .open_event(value.recipient, value.stamp, inner)
                .expect("open");
            let body = EventBody::decode(&clear).expect("body");
            assert!(value.checked(&body));
            assert_eq!(body.address, address.as_bytes());
        }
        assert_ne!(events[0].stamp, events[1].stamp);
    });
    cluster.stop();
}

#[test]
fn an_expired_message_leaves_an_expired_event() {
    let driver = Rc::new(SimDriver::with_disk(45, Config::default(), created(45)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let (gone, _) = accept_listed(node, shard, &["z@example.org"], 1).await;
        for _ in 0..200 {
            if node.spool().tenant(gone).is_none() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(node.spool().tenant(gone), None);
        let changes = node.spool().changes();
        let mut found = Vec::new();
        for (owner, partition) in changes.partitions(KIND_EVENT).await.expect("partitions") {
            let entries = changes
                .scan(
                    owner,
                    (KIND_EVENT, partition),
                    [0; 20]..[0xff; 20],
                    usize::MAX,
                )
                .await
                .expect("scan");
            found.extend(entries.iter().filter_map(|e| Event::decode(&e.value)));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].kind, found[0].message),
            (EventKind::Expired, gone)
        );
        let day = u32::try_from(found[0].time / DAY).expect("day");
        let wanted = search_entries(1, gone, "z@example.org", day);
        let mut hits = 0;
        for (owner, partition) in changes.partitions(KIND_SEARCH).await.expect("partitions") {
            assert_eq!(partition, day);
            for (field, key) in wanted {
                let mut end = key;
                end[12..].fill(0xff);
                let entries = changes
                    .scan(owner, (KIND_SEARCH, partition), key..end, usize::MAX)
                    .await
                    .expect("scan");
                assert_eq!(entries.len(), 1, "{field:?}");
                let value = Found::decode(&entries[0].value).expect("value");
                let event_key = search_event_key(1, &entries[0].key, &value).expect("key");
                let event = changes
                    .scan(owner, (KIND_EVENT, partition), event_key..end, 1)
                    .await
                    .expect("scan");
                assert_eq!(event[0].key, event_key);
                let event = Event::decode(&event[0].value).expect("event");
                assert!(value.matches(&event));
                hits += 1;
            }
        }
        assert_eq!(hits, 3);
    });
    cluster.stop();
}

#[test]
fn event_days_past_the_retention_are_dropped() {
    let driver = Rc::new(SimDriver::with_disk(46, Config::default(), created(46)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    let client = cluster.client.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let (gone, _) = accept_listed(node, shard, &["w@example.org"], 1).await;
        while node.spool().tenant(gone).is_some() {
            sleep(Duration::from_millis(50)).await;
        }
        let changes = node.spool().changes();
        let first = changes.partitions(KIND_EVENT).await.expect("partitions");
        assert_eq!(first.len(), 1);
        let searched = changes.partitions(KIND_SEARCH).await.expect("partitions");
        assert_eq!(searched, first);
        sleep(Duration::from_millis(u64::from(EVENT_DAYS - 1) * DAY)).await;
        client.checkpoint().await.expect("checkpoint");
        let kept = changes.partitions(KIND_EVENT).await.expect("partitions");
        assert_eq!(kept, first);
        let kept = changes.partitions(KIND_SEARCH).await.expect("partitions");
        assert_eq!(kept, first);
        sleep(Duration::from_millis(2 * DAY)).await;
        for _ in 0..2 {
            client.checkpoint().await.expect("checkpoint");
        }
        let left = changes.partitions(KIND_EVENT).await.expect("partitions");
        assert_eq!(left, []);
        let left = changes.partitions(KIND_SEARCH).await.expect("partitions");
        assert_eq!(left, []);
    });
    cluster.stop();
}

async fn searched(
    node: &Node<Idle>,
    tenant: u32,
    query: &SearchQuery,
    limit: usize,
) -> Vec<sched::EventRead> {
    let mut found = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = node
            .search(tenant, query, cursor.as_deref(), limit)
            .await
            .expect("page");
        assert!(page.events.len() <= limit);
        found.extend(page.events);
        cursor = Some(page.next);
        if !page.more {
            break;
        }
    }
    let last = node
        .search(tenant, query, cursor.as_deref(), limit)
        .await
        .expect("last");
    assert!(last.events.is_empty() && !last.more);
    found
}

async fn search_ids_match(
    node: &Node<Idle>,
    all: &sched::EventPage,
    id: MessageId,
    (from, to): (u64, u64),
) {
    let same = all
        .events
        .iter()
        .find(|e| e.event.message == id)
        .expect("listed");
    let address = same
        .body
        .as_ref()
        .expect("opened")
        .address
        .to_ascii_lowercase();
    for (field, value) in [
        (SearchField::Recipient, address.as_slice()),
        (SearchField::Message, &id.bytes()[..]),
    ] {
        let query = SearchQuery::new(field, value, &[], from, to).expect("query");
        let found = searched(node, 1, &query, 10).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, same.id);
    }
}

async fn search_cursors(reader: &Node<Idle>, domain: &SearchQuery, other: &SearchQuery, to: u64) {
    let page = reader.search(1, domain, None, 1).await.expect("page");
    assert!(page.more);
    let moved =
        SearchQuery::new(SearchField::Domain, b"example.org", &[], to, to + 1).expect("moved");
    let rest = reader
        .search(1, &moved, Some(&page.next), 10)
        .await
        .expect("rest");
    assert_eq!(rest.events.len(), 3);
    assert!(!rest.events.iter().any(|r| r.id == page.events[0].id));
    for (from, to) in [(true, true), (true, false), (false, true)] {
        let pinned = domain.clone().fixed(from, to);
        let again = reader.search(1, &pinned, Some(&page.next), 10).await;
        assert!(again.is_ok());
        let pinned = moved.clone().fixed(from, to);
        assert_eq!(
            reader.search(1, &pinned, Some(&page.next), 10).await.err(),
            Some(ReadError::Cursor)
        );
    }
    assert_eq!(
        reader.search(1, other, Some(&page.next), 1).await.err(),
        Some(ReadError::Cursor)
    );
    assert_eq!(
        reader.search(2, domain, Some(&page.next), 1).await.err(),
        Some(ReadError::Cursor)
    );
    assert_eq!(
        reader.search(1, domain, None, 0).await.err(),
        Some(ReadError::Limit)
    );
    assert_eq!(
        reader.search(1, domain, None, 101).await.err(),
        Some(ReadError::Limit)
    );
    assert_eq!(
        reader.search(9, domain, None, 10).await.err(),
        Some(ReadError::Tenant)
    );
}

#[test]
fn search_finds_events_by_each_field_in_pages_across_cores() {
    let driver = Rc::new(SimDriver::with_disk(48, Config::default(), created(48)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        configure(&nodes, vec![tenant(2, 1, State::Active)]).await;
        let sent = [
            (0, "Same@Example.org"),
            (1, "same@example.org"),
            (0, "r2@example.org"),
            (1, "r3@example.org"),
            (0, "q@other.net"),
        ];
        let mut ids = Vec::new();
        for (node, address) in sent {
            let node = &nodes[node];
            let shard = owned_shard(node).await;
            ids.push((node, accept_listed(node, shard, &[address], 1).await.0));
        }
        for (node, id) in &ids {
            while node.spool().tenant(*id).is_some() {
                sleep(Duration::from_millis(50)).await;
            }
        }
        let reader = &nodes[1];
        let all = reader.events(1, None, 10).await.expect("events");
        assert_eq!(all.events.len(), 5);
        let first = all.events.iter().map(|r| r.event.time).min().expect("time");
        let last = all.events.iter().map(|r| r.event.time).max().expect("time");
        let (from, to) = (first, last + 1);
        let query = |field, value: &[u8], kinds: &[EventKind]| {
            SearchQuery::new(field, value, kinds, from, to).expect("query")
        };
        let same = query(SearchField::Recipient, b"SAME@example.ORG", &[]);
        let found = searched(reader, 1, &same, 1).await;
        let mut messages: Vec<MessageId> = found.iter().map(|r| r.event.message).collect();
        messages.sort_unstable_by_key(MessageId::bytes);
        let mut expected = vec![ids[0].1, ids[1].1];
        expected.sort_unstable_by_key(MessageId::bytes);
        assert_eq!(messages, expected);
        for read in &found {
            let body = read.body.as_ref().expect("opened");
            assert!(body.address.eq_ignore_ascii_case(b"same@example.org"));
            assert_eq!(read.event.kind, EventKind::Expired);
        }
        let domain = query(SearchField::Domain, b"EXAMPLE.org", &[]);
        let found = searched(reader, 1, &domain, 1).await;
        assert_eq!(found.len(), 4);
        let times: Vec<u64> = found.iter().map(|r| r.event.time).collect();
        let mut newest = times.clone();
        newest.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(times, newest);
        let mut named: Vec<[u8; 16]> = found.iter().map(|r| r.id).collect();
        named.sort_unstable();
        named.dedup();
        assert_eq!(named.len(), 4);
        for read in &found {
            let same = all
                .events
                .iter()
                .find(|e| e.event.message == read.event.message)
                .expect("listed");
            assert_eq!(
                (read.id, read.shard, read.sequence),
                (same.id, same.shard, same.sequence)
            );
        }
        search_ids_match(&nodes[0], &all, ids[2].1, (from, to)).await;
        let other = query(SearchField::Domain, b"other.net", &[]);
        let found = searched(reader, 1, &other, 10).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].event.message, ids[4].1);
        for (_, id) in &ids {
            let by_id = query(SearchField::Message, &id.bytes(), &[]);
            let found = searched(&nodes[0], 1, &by_id, 10).await;
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].event.message, *id);
        }
        let failed = query(SearchField::Domain, b"example.org", &[EventKind::Failed]);
        assert_eq!(searched(reader, 1, &failed, 10).await, []);
        let expired = query(SearchField::Domain, b"example.org", &[EventKind::Expired]);
        assert_eq!(searched(reader, 1, &expired, 10).await.len(), 4);
        let later =
            SearchQuery::new(SearchField::Domain, b"example.org", &[], to, to + 1).expect("later");
        assert_eq!(searched(reader, 1, &later, 10).await, []);
        assert_eq!(searched(reader, 2, &domain, 10).await, []);
        search_cursors(reader, &domain, &other, to).await;
        UNWRAP_DOWN.set(true);
        assert_eq!(
            reader.search(1, &domain, None, 10).await.err(),
            Some(ReadError::Unavailable)
        );
        UNWRAP_DOWN.set(false);
        assert_eq!(searched(reader, 1, &domain, 10).await.len(), 4);
    });
    cluster.stop();
}

#[test]
fn a_search_past_the_scan_budget_pages_on_without_skipping() {
    let driver = Rc::new(SimDriver::with_disk(49, Config::default(), created(49)));
    let cluster = started(&driver, 1);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let batch = |n: usize| -> Vec<String> {
            (0..100).map(|r| format!("b{n}.{r}@example.org")).collect()
        };
        let mut ids = Vec::new();
        for n in 0..12 {
            let addresses = batch(n);
            let addresses: Vec<&str> = addresses.iter().map(String::as_str).collect();
            let id = accept_listed(node, shard, &addresses, 1).await.0;
            while node.spool().tenant(id).is_some() {
                sleep(Duration::from_millis(50)).await;
            }
            ids.push(id);
            if n == 0 {
                sleep(Duration::from_secs(1)).await;
            }
        }
        let old = every_event(node).await;
        let cut = old
            .iter()
            .filter(|r| r.event.message == ids[0])
            .map(|r| r.event.time)
            .max()
            .expect("time")
            + 1;
        let (from, _) = search_range();
        let older =
            SearchQuery::new(SearchField::Domain, b"example.org", &[], from, cut).expect("query");
        let first = node.search(1, &older, None, 10).await.expect("page");
        assert_eq!(first.events, []);
        assert!(first.more);
        let (got, _) = search_from(node, &older, Some(first.next)).await;
        let found: BTreeSet<[u8; 16]> = got.iter().copied().collect();
        assert_eq!(found.len(), got.len());
        let want: BTreeSet<[u8; 16]> = old
            .iter()
            .filter(|r| r.event.message == ids[0])
            .map(|r| r.id)
            .collect();
        assert_eq!(want.len(), 100);
        assert_eq!(found, want);
        let all = searched(node, 1, &domain_query(), 100).await;
        assert_eq!(ids_of(&all).len(), 1200);
        assert_eq!(all.len(), 1200);
        assert!(node.search_stats().scans > 12);
    });
    cluster.stop();
}

#[test]
fn a_search_finds_nothing_after_a_shred_with_real_keys() {
    let wall = 20_000 * DAY + 3_600_000;
    let config = Config {
        wall_start_ms: wall,
        ..Config::default()
    };
    let driver = Rc::new(SimDriver::with_disk(50, config, created(50)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let node = &nodes[0];
        let shard = owned_shard(node).await;
        let (id, _) = accept_listed(node, shard, &["k@example.org"], 1).await;
        while node.spool().tenant(id).is_some() {
            sleep(Duration::from_millis(50)).await;
        }
        let (from, to) = (wall - DAY, wall + DAY);
        let queries = [
            SearchQuery::new(SearchField::Domain, b"example.org", &[], from, to).expect("query"),
            SearchQuery::new(SearchField::Recipient, b"k@example.org", &[], from, to)
                .expect("query"),
            SearchQuery::new(SearchField::Message, &id.bytes(), &[], from, to).expect("query"),
        ];
        for query in &queries {
            for reader in &nodes {
                assert_eq!(searched(reader, 1, query, 10).await.len(), 1);
            }
        }
        regenerate(&nodes, 1).await;
        for query in &queries {
            for reader in &nodes {
                assert_eq!(searched(reader, 1, query, 10).await, []);
            }
        }
    });
    cluster.stop();
}

fn search_range() -> (u64, u64) {
    let wall = Config::default().wall_start_ms;
    (wall - DAY, wall + DAY)
}

fn domain_query() -> SearchQuery {
    let (from, to) = search_range();
    SearchQuery::new(SearchField::Domain, b"example.org", &[], from, to).expect("query")
}

async fn every_event(node: &Node<Idle>) -> Vec<sched::EventRead> {
    let mut found = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = node.events(1, cursor.as_deref(), 100).await.expect("page");
        found.extend(page.events);
        cursor = Some(page.next);
        if !page.more {
            return found;
        }
    }
}

async fn search_from(
    node: &Node<Idle>,
    query: &SearchQuery,
    after: Option<String>,
) -> (Vec<[u8; 16]>, String) {
    let mut found = Vec::new();
    let mut cursor = after;
    loop {
        let page = node
            .search(1, query, cursor.as_deref(), 3)
            .await
            .expect("page");
        found.extend(page.events.iter().map(|r| r.id));
        cursor = Some(page.next);
        if !page.more {
            return (found, cursor.unwrap_or_default());
        }
    }
}

fn ids_of(reads: &[sched::EventRead]) -> BTreeSet<[u8; 16]> {
    reads.iter().map(|r| r.id).collect()
}

fn address_of(read: &sched::EventRead) -> Vec<u8> {
    read.body
        .as_ref()
        .expect("opened")
        .address
        .to_ascii_lowercase()
}

async fn each_field_finds(seed: u64, node: &Node<Idle>, whole: &[sched::EventRead]) {
    let (from, to) = search_range();
    let all = ids_of(whole);
    assert_eq!(all.len(), whole.len(), "seed {seed}: event ids repeat");
    let found = searched(node, 1, &domain_query(), 7).await;
    assert_eq!(ids_of(&found), all, "seed {seed}: domain");
    assert_eq!(found.len(), all.len(), "seed {seed}: domain repeats");
    let mut asked = BTreeSet::new();
    for read in whole {
        let address = address_of(read);
        let message = read.event.message.bytes();
        for (field, value) in [
            (SearchField::Recipient, address.clone()),
            (SearchField::Message, message.to_vec()),
        ] {
            if !asked.insert((field, value.clone())) {
                continue;
            }
            let want: BTreeSet<[u8; 16]> = whole
                .iter()
                .filter(|r| match field {
                    SearchField::Recipient => address_of(r) == value,
                    _ => r.event.message.bytes()[..] == value[..],
                })
                .map(|r| r.id)
                .collect();
            let query = SearchQuery::new(field, &value, &[], from, to).expect("query");
            let found = searched(node, 1, &query, 2).await;
            assert_eq!(found.len(), want.len(), "seed {seed}: {field:?} repeats");
            assert_eq!(ids_of(&found), want, "seed {seed}: {field:?}");
        }
    }
}

async fn search_drained(seed: u64, nodes: &[Node<Idle>]) {
    let empty = || nodes.iter().all(|n| n.spool().messages_of(1).is_empty());
    for _ in 0..20_000 {
        if empty() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("seed {seed}: messages left");
}

async fn old_generation_entries(nodes: &[Node<Idle>]) -> (usize, usize) {
    let start = index::key(1, [0; 16]);
    let end = index::key(1, [0xff; 16]);
    let (mut old, mut new) = (0, 0);
    for node in nodes {
        let changes = node.spool().changes();
        let mut fresh = BTreeSet::new();
        let mut stale = BTreeSet::new();
        for (owner, partition) in changes.partitions(KIND_SEARCH).await.expect("partitions") {
            let entries = changes
                .scan(owner, (KIND_SEARCH, partition), start..end, usize::MAX)
                .await
                .expect("scan");
            for entry in entries {
                let found = Found::decode(&entry.value).expect("value");
                if found.generation == 1 {
                    stale.insert(owner);
                    old += 1;
                } else {
                    fresh.insert(owner);
                    new += 1;
                }
            }
        }
        assert!(
            fresh.intersection(&stale).next().is_none(),
            "old generation kept next to new entries"
        );
    }
    (old, new)
}

fn search_crashed(seed: u64, cores: u16) -> Disk {
    let config = Config {
        halt_after: Some(30 + seed * 7_919 % 80),
        faults: Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        },
        ..Config::default()
    };
    let first = Rc::new(SimDriver::with_disk(seed, config, created(seed)));
    if let Some(cluster) = try_started(&first, cores, 0, None, false, &settings_named(NAMING)) {
        let nodes = cluster.nodes.clone();
        let power = Rc::clone(&first);
        cluster.run(async move {
            let work = async {
                ready(&nodes).await;
                answering(&nodes);
                accept_some(&nodes, 0, 5).await;
                expire_some(&nodes, 0, 2).await;
                sleep(Duration::from_secs(3600)).await;
            };
            let _ = unless_halted(&power, work).await;
        });
        if !first.is_halted() {
            cluster.stop();
        }
    }
    first.crash()
}

async fn search_round(seed: u64, reader: &Node<Idle>) -> usize {
    let before = ids_of(&every_event(reader).await);
    let (got, _) = search_from(reader, &domain_query(), None).await;
    let paged: BTreeSet<[u8; 16]> = got.iter().copied().collect();
    assert_eq!(paged.len(), got.len(), "seed {seed}: a cursor repeated");
    assert!(paged.is_superset(&before), "seed {seed}: a cursor skipped");
    before.len()
}

type Carried = (BTreeSet<[u8; 16]>, BTreeSet<[u8; 16]>, String);

async fn search_second(seed: u64, nodes: Vec<Node<Idle>>) -> Carried {
    ready(&nodes).await;
    answering(&nodes);
    let done = Rc::new(Cell::new(false));
    let reader = nodes[nodes.len() - 1].clone();
    let finished = Rc::clone(&done);
    let polling = spawn(async move {
        let mut rounds = 0;
        while !finished.get() {
            search_round(seed, &reader).await;
            rounds += 1;
            sleep(Duration::from_millis(300)).await;
        }
        rounds
    });
    accept_some(&nodes, 5, 3).await;
    expire_some(&nodes, 2, 1).await;
    search_drained(seed, &nodes).await;
    done.set(true);
    assert!(polling.await > 1, "seed {seed}: no rounds while writing");
    let whole = every_event(&nodes[0]).await;
    assert_eq!(search_round(seed, &nodes[0]).await, whole.len());
    each_field_finds(seed, &nodes[0], &whole).await;
    let page = nodes[0]
        .search(1, &domain_query(), None, 3)
        .await
        .expect("page");
    (ids_of(&page.events), ids_of(&whole), page.next)
}

async fn search_third(
    seed: u64,
    nodes: Vec<Node<Idle>>,
    client: Client,
    (mut paged, before, cursor): Carried,
) {
    ready(&nodes).await;
    answering(&nodes);
    accept_some(&nodes, 8, 2).await;
    search_drained(seed, &nodes).await;
    let (more, _) = search_from(&nodes[0], &domain_query(), Some(cursor.clone())).await;
    paged.extend(more);
    assert!(paged.is_superset(&before), "seed {seed}: a cursor skipped");
    let whole = every_event(&nodes[0]).await;
    each_field_finds(seed, &nodes[nodes.len() - 1], &whole).await;
    regenerate(&nodes, 1).await;
    let query = domain_query();
    assert_eq!(
        nodes[0].search(1, &query, Some(&cursor), 10).await.err(),
        Some(ReadError::Cursor),
        "seed {seed}: old cursor"
    );
    for node in &nodes {
        assert_eq!(searched(node, 1, &query, 10).await, [], "seed {seed}");
    }
    let (from, to) = search_range();
    for read in &whole {
        for (field, value) in [
            (SearchField::Recipient, address_of(read)),
            (SearchField::Message, read.event.message.bytes().to_vec()),
        ] {
            let query = SearchQuery::new(field, &value, &[], from, to).expect("query");
            assert_eq!(searched(&nodes[0], 1, &query, 10).await, [], "seed {seed}");
        }
    }
    accept_some(&nodes, 10, nodes.len() * 2).await;
    search_drained(seed, &nodes).await;
    client.checkpoint().await.expect("checkpoint");
    let (_, new) = old_generation_entries(&nodes).await;
    assert_ne!(new, 0, "seed {seed}");
    let whole = every_event(&nodes[0]).await;
    assert!(whole.iter().all(|r| r.event.generation == 2), "seed {seed}");
    let read =
        |nodes: &[Node<Idle>]| -> u64 { nodes.iter().map(|n| n.search_stats().blocks).sum() };
    let before = read(&nodes);
    each_field_finds(seed, &nodes[0], &whole).await;
    assert!(read(&nodes) > before, "seed {seed}: no blocks read");
}

fn search_sim(seed: u64) {
    ANSWERS.set(None);
    let (first, second) =
        [(1, 2), (2, 4), (4, 1), (2, 1)][usize::try_from(seed % 4).expect("small")];
    let disk = search_crashed(seed, first);
    let driver = Rc::new(SimDriver::with_disk(seed + 1, Config::default(), disk));
    let cluster = started(&driver, second);
    let nodes = cluster.nodes.clone();
    let carried = cluster.run(search_second(seed, nodes));
    cluster.stop();
    let driver = Rc::new(SimDriver::with_disk(
        seed + 2,
        Config::default(),
        driver.crash(),
    ));
    let cluster = started(&driver, first);
    let nodes = cluster.nodes.clone();
    let client = cluster.client.clone();
    cluster.run(search_third(seed, nodes, client, carried));
    cluster.stop();
}

#[test]
fn search_finds_every_event_through_crashes_core_changes_and_a_shred() {
    check(0..4, search_sim);
}

#[test]
fn events_read_in_pages_across_cores_without_gaps() {
    let driver = Rc::new(SimDriver::with_disk(47, Config::default(), created(47)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        configure(&nodes, vec![tenant(2, 1, State::Active)]).await;
        let mut ids = Vec::new();
        for (n, node) in [0, 0, 1, 0, 1].into_iter().enumerate() {
            let node = &nodes[node];
            let shard = owned_shard(node).await;
            let address = format!("r{n}@example.org");
            ids.push((
                node,
                accept_listed(node, shard, &[address.as_str()], 1).await.0,
            ));
        }
        for (node, id) in &ids {
            while node.spool().tenant(*id).is_some() {
                sleep(Duration::from_millis(50)).await;
            }
        }
        let reader = &nodes[1];
        let mut seen = Vec::new();
        let mut named = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = reader.events(1, cursor.as_deref(), 2).await.expect("page");
            assert!(page.events.len() <= 2);
            for read in &page.events {
                let body = read.body.as_ref().expect("opened");
                assert_eq!(read.event.kind, EventKind::Expired);
                assert!(body.address.ends_with(b"@example.org"));
                seen.push((read.shard, read.sequence, read.event.message));
                named.push(read.id);
            }
            cursor = Some(page.next);
            if !page.more {
                break;
            }
        }
        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 5);
        assert_eq!(seen.len(), 5);
        let again = reader.events(1, None, 10).await.expect("again");
        let mut ids_again: Vec<[u8; 16]> = again.events.iter().map(|read| read.id).collect();
        let mut first: Vec<[u8; 16]> = named.clone();
        first.sort_unstable();
        first.dedup();
        assert_eq!(first.len(), 5);
        ids_again.sort_unstable();
        assert_eq!(ids_again, first);
        let mut messages: Vec<MessageId> = seen.iter().map(|s| s.2).collect();
        messages.sort_unstable_by_key(MessageId::bytes);
        let mut expected: Vec<MessageId> = ids.iter().map(|i| i.1).collect();
        expected.sort_unstable_by_key(MessageId::bytes);
        assert_eq!(messages, expected);
        let last = reader
            .events(1, cursor.as_deref(), 10)
            .await
            .expect("empty");
        assert!(last.events.is_empty() && !last.more);
        assert_eq!(
            reader.events(2, cursor.as_deref(), 10).await.err(),
            Some(ReadError::Cursor)
        );
        assert_eq!(
            reader.events(1, Some("zz"), 10).await.err(),
            Some(ReadError::Cursor)
        );
        assert_eq!(
            reader.events(1, None, 0).await.err(),
            Some(ReadError::Limit)
        );
        assert_eq!(
            reader.events(1, None, 1001).await.err(),
            Some(ReadError::Limit)
        );
        assert_eq!(
            reader.events(9, None, 10).await.err(),
            Some(ReadError::Tenant)
        );
        let other = reader.events(2, None, 10).await.expect("other");
        assert_eq!(other.events, []);
    });
    cluster.stop();
}

#[test]
fn event_values_and_bodies_refuse_damage() {
    let event = Event {
        generation: 7,
        time: 1,
        kind: EventKind::Suppressed,
        lost: 0,
        message: MessageId::from_bytes([9; 16]),
        recipient: 4,
        stamp: Stamp { boot: 1, write: 2 },
        batch: 5,
        day: 6,
    };
    let mut value = event.encode();
    assert_eq!(value.len(), EVENT_VALUE);
    assert_eq!(Event::decode(&value), Some(event));
    value[12] = 9;
    assert_eq!(Event::decode(&value), None);
    assert_eq!(Event::decode(&value[1..]), None);
    let body = EventBody {
        kind: EventKind::Canceled,
        time: 8,
        address: b"b@example.org".to_vec(),
        reply: b"550 no".to_vec(),
        attempts: 1,
        class: 0,
    };
    let bytes = body.encode();
    assert_eq!(EventBody::decode(&bytes), Some(body));
    assert_eq!(EventBody::decode(&bytes[..bytes.len() - 1]), None);
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(EventBody::decode(&long), None);
    let mut kind = bytes.clone();
    kind[0] = 0;
    assert_eq!(EventBody::decode(&kind), None);
    let mut key = index::key(1, [0; 16]);
    key[4..12].copy_from_slice(&77u64.to_be_bytes());
    assert_eq!(event_sequence(&key), 77);
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
    let Some(cluster) = try_started(
        driver,
        cores,
        0,
        Some(tuning),
        false,
        &settings_named(NAMING),
    ) else {
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

async fn records_left(control: &Node<Idle>, count: usize) {
    while control.control_records() != Some(count) {
        sleep(Duration::from_millis(1)).await;
    }
}

async fn queues_gone(nodes: &[Node<Idle>], ids: &[u32]) {
    for node in nodes {
        while ids.iter().any(|id| node.queues().entry(*id).is_some())
            || node.queues().leftovers() > 0
        {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

fn swept_name(tenant: u32, n: u32) -> control::Name {
    control::Name {
        tenant,
        domain: format!("d{n}.example.org").into(),
        generation: 1,
        pool: 1,
    }
}

#[test]
fn a_deleted_tenant_loses_its_control_records_and_queues_on_every_core() {
    let smtp = Scopes {
        smtp: true,
        api: false,
        hooks: false,
    };
    let driver = Rc::new(SimDriver::with_disk(47, Config::default(), created(47)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    let ids = cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let control = control_of(&nodes);
        let dkim = control
            .dkim_new(1, DkimAlg::Ed25519Sha256, "example.org", "s1")
            .await
            .expect("dkim");
        let domain = control.domain_new(1, "example.org").await.expect("domain");
        let (access, _) = control.access_new(1, smtp, 0).await.expect("access");
        control.access_new(2, smtp, 0).await.expect("access");
        records_left(control, 4).await;
        let mut ids = Vec::new();
        for n in 0..8 {
            ids.push(
                nodes[0]
                    .queues()
                    .name(&swept_name(1, n))
                    .await
                    .expect("name"),
            );
        }
        let kept = nodes[1]
            .queues()
            .name(&swept_name(2, 0))
            .await
            .expect("name");
        control.delete_tenant(1).await.expect("delete");
        wait_for(&nodes, 1, 1, State::Deleted).await;
        records_left(control, 1).await;
        queues_gone(&nodes, &ids).await;
        for node in &nodes {
            let table = node.table();
            assert!(table.access(access.id).is_none());
            assert!(table.dkim(1, dkim.id).is_none());
            assert!(table.domain(1, domain.id).is_none());
        }
        assert!(nodes.iter().any(|n| n.queues().entry(kept).is_some()));
        ids
    });
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(48, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        assert_eq!(control_of(&nodes).control_records(), Some(1));
        for node in &nodes {
            assert_eq!(node.queues().stats().skipped, 0);
        }
        keys_listening().await;
        configure(&nodes, vec![tenant(1, 2, State::Active)]).await;
        wait_for(&nodes, 1, 2, State::Active).await;
        let fresh = control::Name {
            generation: 2,
            ..swept_name(1, 0)
        };
        let id = nodes[0].queues().name(&fresh).await.expect("fresh");
        assert!(!ids.contains(&id));
    });
    restarted.stop();
}

fn a_sweep_cut_by_a_crash(seed: u64) {
    let smtp = Scopes {
        smtp: true,
        api: false,
        hooks: false,
    };
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let control = control_of(&nodes);
        for _ in 0..4 {
            control.access_new(1, smtp, 0).await.expect("access");
        }
        control.access_new(2, smtp, 0).await.expect("access");
        control.delete_tenant(1).await.expect("delete");
        while control.table().tenant(1).map(|t| t.state) != Some(State::Deleted) {
            sleep(Duration::from_micros(50)).await;
        }
    });
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        assert_eq!(control_of(&nodes).control_records(), Some(1), "seed {seed}");
        for node in &nodes {
            assert_eq!(node.table().accesses(1).count(), 0);
        }
    });
    restarted.stop();
}

#[test]
fn a_sweep_cut_by_a_crash_finishes_at_start() {
    for seed in 0..6 {
        a_sweep_cut_by_a_crash(900 + seed * 2);
    }
}

async fn access_everywhere(nodes: &[Node<Idle>], id: u32, present: bool) {
    for node in nodes {
        while node.table().access(id).is_some() != present {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

#[test]
fn access_keys_check_on_every_core_until_revoked_across_restarts() {
    let smtp = Scopes {
        smtp: true,
        api: false,
        hooks: false,
    };
    let driver = Rc::new(SimDriver::with_disk(43, Config::default(), created(43)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    let tokens = cluster.run(async move {
        ready(&nodes).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let other = nodes.iter().find(|n| !n.controls()).expect("other core");
        assert!(matches!(
            other.access_new(1, smtp, 0).await,
            Err(sched::Error::Control(control::Error::Invalid("core")))
        ));
        assert!(matches!(
            control.access_new(7, smtp, 0).await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
        assert!(matches!(
            control.access_new(1, smtp, 5).await,
            Err(sched::Error::Control(control::Error::Invalid("pool")))
        ));
        assert!(matches!(
            control.access_new(1, Scopes::default(), 0).await,
            Err(sched::Error::Control(control::Error::Invalid("scopes")))
        ));
        let (first, kept) = control.access_new(1, smtp, 0).await.expect("new");
        let (second, revoked) = control.access_new(1, smtp, 1).await.expect("new");
        assert_eq!((first.id, second.id), (1, 2));
        assert!(matches!(
            control
                .access_new(
                    1,
                    Scopes {
                        hooks: true,
                        ..smtp
                    },
                    1
                )
                .await,
            Err(sched::Error::Control(control::Error::Invalid("scopes")))
        ));
        assert!(matches!(
            control.write(Object::Access(first.clone())).await,
            Err(sched::Error::Control(control::Error::Invalid("kind")))
        ));
        access_everywhere(&nodes, 2, true).await;
        for node in &nodes {
            let table = node.table();
            let grant = table.check(&kept, Scope::Smtp).expect("grant");
            assert_eq!((grant.access, grant.tenant, grant.pool), (1, 1, 1));
            assert!(table.check(&kept, Scope::Api).is_none());
            assert!(table.check(&revoked, Scope::Smtp).is_some());
        }
        assert!(matches!(
            control.access_revoke(2, 2).await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
        control.access_revoke(1, 2).await.expect("revoke");
        assert!(matches!(
            control.access_revoke(1, 2).await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
        access_everywhere(&nodes, 2, false).await;
        for node in &nodes {
            assert!(node.table().check(&revoked, Scope::Smtp).is_none());
        }
        (kept.to_vec(), revoked.to_vec())
    });
    drop(cluster);
    let driver = Rc::new(SimDriver::with_disk(44, Config::default(), driver.crash()));
    let restarted = started(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        access_everywhere(&nodes, 1, true).await;
        for node in &nodes {
            let table = node.table();
            assert!(table.check(&tokens.0, Scope::Smtp).is_some());
            assert!(table.check(&tokens.1, Scope::Smtp).is_none());
            assert!(table.access(2).is_none());
        }
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let (third, _) = control.access_new(1, smtp, 0).await.expect("new");
        assert_eq!(third.id, 3);
        control
            .write(tenant(1, 1, State::Suspended))
            .await
            .expect("suspend");
        wait_for(&nodes, 1, 1, State::Suspended).await;
        for node in &nodes {
            assert!(node.table().check(&tokens.0, Scope::Smtp).is_none());
        }
    });
}

async fn domain_everywhere(nodes: &[Node<Idle>], domain: &Domain) {
    for node in nodes {
        while node.table().domain(domain.tenant, domain.id) != Some(domain) {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

fn domain_refused(result: Result<Domain, sched::Error>, what: &str) {
    match result {
        Err(sched::Error::Control(control::Error::Invalid(w))) => assert_eq!(w, what),
        Err(sched::Error::Control(control::Error::Refused)) => assert_eq!("refused", what),
        other => panic!("{other:?}"),
    }
}

async fn bad_domain_writes(control: &Node<Idle>, made: &Domain, suffix: Domain, keys: [u32; 3]) {
    let [ed, rsa, elsewhere] = keys;
    assert!(matches!(
        control.write(Object::Domain(made.clone())).await,
        Err(sched::Error::Control(control::Error::Invalid("kind")))
    ));
    domain_refused(
        control
            .domain_write(Domain {
                return_path: false,
                state: Verification::Verified,
                ..suffix
            })
            .await,
        "public suffix",
    );
    for (rsa, ed25519) in [(ed, 0), (0, rsa), (0, elsewhere), (0, 99)] {
        domain_refused(
            control
                .domain_write(Domain {
                    return_path: false,
                    rsa,
                    ed25519,
                    ..made.clone()
                })
                .await,
            "dkim keys",
        );
    }
    domain_refused(
        control
            .domain_write(Domain {
                return_path: false,
                name: "example.net".into(),
                ..made.clone()
            })
            .await,
        "refused",
    );
    domain_refused(
        control
            .domain_write(Domain {
                return_path: false,
                tenant: 2,
                ..made.clone()
            })
            .await,
        "refused",
    );
}

#[test]
fn sender_domains_pick_their_keys_and_keep_named_keys() {
    let driver = Rc::new(SimDriver::with_disk(45, Config::default(), created(45)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let other = nodes.iter().find(|n| !n.controls()).expect("other core");
        domain_refused(other.domain_new(1, "example.org").await, "core");
        domain_refused(control.domain_new(7, "example.org").await, "refused");
        domain_refused(control.domain_new(1, "exa mple.org").await, "domain");
        let made = control.domain_new(1, "Example.ORG").await.expect("new");
        assert_eq!((made.id, &*made.name), (1, "example.org"));
        assert_eq!(made.state, Verification::Unverified);
        domain_refused(control.domain_new(1, "example.org").await, "refused");
        let suffix = control.domain_new(1, "co.uk").await.expect("new");
        let ed = control
            .dkim_new(1, DkimAlg::Ed25519Sha256, "example.org", "s1")
            .await
            .expect("dkim");
        let rsa = control
            .dkim_new(1, DkimAlg::RsaSha256, "example.org", "s2")
            .await
            .expect("dkim");
        let elsewhere = control
            .dkim_new(1, DkimAlg::Ed25519Sha256, "example.net", "s1")
            .await
            .expect("dkim");
        bad_domain_writes(control, &made, suffix, [ed.id, rsa.id, elsewhere.id]).await;
        let verified = control
            .domain_write(Domain {
                return_path: false,
                state: Verification::Verified,
                rsa: rsa.id,
                ed25519: ed.id,
                ..made
            })
            .await
            .expect("write");
        domain_everywhere(&nodes, &verified).await;
        for node in &nodes {
            let table = node.table();
            let sender = table.sender(1, "news.example.org").expect("sender");
            assert_eq!((sender.rsa, sender.ed25519), (rsa.id, ed.id));
            assert!(table.sender(2, "example.org").is_none());
        }
        for key in [rsa.id, ed.id] {
            assert!(matches!(
                control.dkim_remove(1, key).await,
                Err(sched::Error::Control(control::Error::Refused))
            ));
        }
        assert!(matches!(
            control.dkim_remove(2, elsewhere.id).await,
            Err(sched::Error::Control(control::Error::Refused))
        ));
        control.dkim_remove(1, elsewhere.id).await.expect("remove");
        let unsigned = control
            .domain_write(Domain {
                return_path: false,
                rsa: 0,
                ..verified
            })
            .await
            .expect("write");
        domain_everywhere(&nodes, &unsigned).await;
        control.dkim_remove(1, rsa.id).await.expect("remove");
        for node in &nodes {
            while node.table().dkim(1, rsa.id).is_some()
                || node.table().dkim(1, elsewhere.id).is_some()
            {
                sleep(Duration::from_millis(1)).await;
            }
            let digest = digest_of(b"x");
            assert_eq!(node.sign(1, rsa.id, digest).await, Err(Refusal::Signer));
            node.sign(1, ed.id, digest).await.expect("sign");
        }
    });
}

fn hook_refused<T: std::fmt::Debug>(result: Result<T, sched::Error>, what: &str) {
    match result {
        Err(sched::Error::Control(control::Error::Invalid(w))) => assert_eq!(w, what),
        Err(sched::Error::Control(control::Error::Refused)) => assert_eq!("refused", what),
        Err(sched::Error::Control(control::Error::Full)) => assert_eq!("full", what),
        other => panic!("{other:?}"),
    }
}

async fn old_generation_hidden(nodes: &[Node<Idle>], control: &Node<Idle>, theirs: &Hook) {
    assert!(matches!(
        control.write(Object::Hook(theirs.clone())).await,
        Err(sched::Error::Control(control::Error::Invalid("kind")))
    ));
    control.delete_tenant(theirs.tenant).await.expect("delete");
    assert_eq!(control.table().hook(theirs.tenant, theirs.id), Some(theirs));
    for node in nodes {
        while node
            .table()
            .tenant(theirs.tenant)
            .is_some_and(|t| t.state == State::Active)
        {
            sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(node.hooks(theirs.tenant), Vec::new());
        hook_refused(node.hook(theirs.tenant, theirs.id), "refused");
        hook_refused(
            node.hook_secret(theirs.tenant, theirs.id, 1)
                .await
                .map(drop),
            "refused",
        );
    }
    hook_refused(
        control.hook_remove(theirs.tenant, theirs.id).await,
        "refused",
    );
    wait_for(nodes, theirs.tenant, theirs.generation, State::Deleted).await;
    while !control.controls() {
        sleep(Duration::from_millis(1)).await;
    }
    let next = tenant(theirs.tenant, theirs.generation + 1, State::Active);
    control.write(next).await.expect("write");
    wait_for(nodes, theirs.tenant, theirs.generation + 1, State::Active).await;
    let fresh = control
        .hook_new(theirs.tenant, "https://hooks.example.org/", 0)
        .await
        .expect("new");
    assert_eq!(fresh.generation, theirs.generation + 1);
    assert_eq!(control.hooks(theirs.tenant), vec![fresh]);
}

async fn versions_end(control: &Node<Idle>, at: &str) {
    let next = control.hook_new(1, at, 0).await.expect("new");
    assert_eq!(next.id, u32::try_from(MAX_HOOKS).expect("small") + 2);
    for version in 2..=u8::MAX {
        let hook = control.hook_rotate(1, next.id).await.expect("rotate");
        assert_eq!(hook.version, version);
    }
    hook_refused(control.hook_rotate(1, next.id).await, "full");
}

async fn hook_everywhere(nodes: &[Node<Idle>], hook: &Hook) {
    for node in nodes {
        while node.table().hook(hook.tenant, hook.id) != Some(hook) {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

#[test]
fn webhook_endpoints_are_made_changed_rotated_and_removed_on_the_control_core() {
    let driver = Rc::new(SimDriver::with_disk(47, Config::default(), created(47)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let other = nodes.iter().find(|n| !n.controls()).expect("other core");
        let at = "https://hooks.example.org/in";
        hook_refused(other.hook_new(1, at, 0).await, "core");
        hook_refused(control.hook_new(7, at, 0).await, "refused");
        hook_refused(
            control.hook_new(1, "http://hooks.example.org/", 0).await,
            "url",
        );
        let made = control.hook_new(1, at, 0).await.expect("new");
        assert_eq!((made.id, made.events, made.version), (1, ALL_EVENTS, 1));
        assert_eq!(made.state, HookState::Active);
        hook_everywhere(&nodes, &made).await;
        let theirs = control.hook_new(2, at, 1).await.expect("new");
        hook_refused(
            control
                .hook_change(1, theirs.id, HookChange::default())
                .await,
            "refused",
        );
        hook_refused(control.hook_rotate(1, theirs.id).await, "refused");
        hook_refused(control.hook_remove(1, theirs.id).await, "refused");
        hook_refused(
            other.hook_secret(1, theirs.id, 1).await.map(drop),
            "refused",
        );
        for _ in 1..MAX_HOOKS {
            control.hook_new(1, at, 0).await.expect("new");
        }
        hook_refused(control.hook_new(1, at, 0).await, "full");
        let paused = control
            .hook_change(
                1,
                made.id,
                HookChange {
                    url: Some("https://other.example.org/x".into()),
                    events: Some(3),
                    enabled: Some(false),
                },
            )
            .await
            .expect("change");
        assert_eq!(
            (&*paused.url, paused.events),
            ("https://other.example.org/x", 3)
        );
        assert_eq!(paused.state, HookState::Paused);
        hook_refused(
            control
                .hook_change(
                    1,
                    made.id,
                    HookChange {
                        url: Some("https://10.0.0.1/".into()),
                        ..HookChange::default()
                    },
                )
                .await,
            "url",
        );
        let enabled = HookChange {
            enabled: Some(true),
            ..HookChange::default()
        };
        let active = control
            .hook_change(1, made.id, enabled)
            .await
            .expect("change");
        assert_eq!((active.state, active.events), (HookState::Active, 3));
        let first = other.hook_secret(1, made.id, 1).await.expect("secret");
        hook_refused(other.hook_secret(1, made.id, 2).await.map(drop), "refused");
        let rotated = control.hook_rotate(1, made.id).await.expect("rotate");
        assert_eq!(rotated.version, 2);
        hook_everywhere(&nodes, &rotated).await;
        let (_, previous) = other.hook_versions(1, made.id).expect("versions");
        assert_eq!(previous, Some(1));
        let second = other.hook_secret(1, made.id, 2).await.expect("secret");
        let again = control.hook_secret(1, made.id, 1).await.expect("secret");
        assert!(*first == *again && *first != *second);
        hook_refused(other.hook_secret(1, made.id, 3).await.map(drop), "refused");
        sleep(Duration::from_millis(ROTATION_MS)).await;
        assert_eq!(other.hook_versions(1, made.id).expect("versions").1, None);
        hook_refused(other.hook_secret(1, made.id, 1).await.map(drop), "refused");
        control.hook_remove(1, made.id).await.expect("remove");
        for node in &nodes {
            while node.table().hook(1, made.id).is_some() {
                sleep(Duration::from_millis(1)).await;
            }
            hook_refused(node.hook_secret(1, made.id, 2).await.map(drop), "refused");
        }
        versions_end(control, at).await;
        old_generation_hidden(&nodes, control, &theirs).await;
    });
}

#[test]
fn system_records_come_back_sealed_and_other_keys_drop_them() {
    keep_restores();
    let driver = Rc::new(SimDriver::with_disk(41, Config::default(), created(41)));
    let cluster = started_with_keys(&driver, 2);
    let restored = restores();
    assert_eq!(restored.len(), 2);
    assert!(restored.iter().all(|r| r.saved.is_empty() && r.unread == 0));
    let homes: Vec<u16> = restored.iter().map(|r| r.records.home()).collect();
    assert!(homes.iter().all(|&home| home != sched::CONTROL_SHARD));
    let (first, second) = (homes[0], homes[1]);
    cluster.run(async move {
        keys_listening().await;
        let one = &restored[0].records;
        one.put(first, 1, b"one".to_vec()).await.expect("put");
        one.put(first, 2, b"two".to_vec()).await.expect("put");
        one.put(first, 2, b"two again".to_vec()).await.expect("put");
        one.remove(first, 1).await.expect("remove");
        one.remove(first, 7).await.expect("remove missing");
        let two = &restored[1].records;
        two.put(second, 1, b"other core".to_vec())
            .await
            .expect("put");
    });
    cluster.stop();

    let driver = Rc::new(SimDriver::with_disk(42, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let restored = restores();
    let expected = BTreeSet::from([
        (first, 2, b"two again".to_vec()),
        (second, 1, b"other core".to_vec()),
    ]);
    assert_eq!(saved(&restored), expected);
    assert!(restored.iter().all(|r| r.unread == 0 && r.dropped == 0));
    restarted.stop();

    let driver = Rc::new(SimDriver::with_disk(43, Config::default(), driver.crash()));
    let other = started(&driver, 2);
    let restored = restores();
    assert!(saved(&restored).is_empty());
    assert_eq!(restored.iter().map(|r| r.dropped).sum::<u64>(), 2);
    let removed: u64 = other.nodes.iter().map(|n| n.system_records().removed).sum();
    assert_eq!(removed, 2);
    other.stop();

    let driver = Rc::new(SimDriver::with_disk(44, Config::default(), driver.crash()));
    let last = started_with_keys(&driver, 2);
    let restored = restores();
    assert!(saved(&restored).is_empty());
    assert!(restored.iter().all(|r| r.dropped == 0 && r.unread == 0));
    last.stop();
}

#[test]
fn the_transport_ticks_every_minute_until_close() {
    let driver = Rc::new(SimDriver::with_disk(45, Config::default(), created(45)));
    let cluster = started(&driver, 2);
    let before = TICKS.get();
    cluster.run(async {
        sleep(Duration::from_secs(150)).await;
    });
    assert_eq!(TICKS.get() - before, 4);
    cluster.stop();
}

const MILLION: u32 = 1_000_000;

async fn read_all(
    node: &Node<Idle>,
    after: Option<String>,
    limit: usize,
) -> (Vec<Given>, u32, String) {
    let mut found = Vec::new();
    let mut lost = 0;
    let mut cursor = after;
    loop {
        let page = node
            .events(1, cursor.as_deref(), limit)
            .await
            .expect("page");
        for read in &page.events {
            let body = read.body.as_ref().expect("opened");
            lost += read.event.lost;
            found.push((
                read.event.message,
                read.event.recipient,
                body.attempts,
                read.event.kind,
            ));
        }
        cursor = Some(page.next);
        if !page.more {
            return (found, lost, cursor.unwrap_or_default());
        }
    }
}

async fn accept_some(nodes: &[Node<Idle>], from: usize, count: usize) {
    for n in from..from + count {
        let node = &nodes[n % nodes.len()];
        let shard = owned_shard(node).await;
        let addresses: Vec<String> = (0..3).map(|r| format!("r{n}.{r}@example.org")).collect();
        let addresses: Vec<&str> = addresses.iter().map(String::as_str).collect();
        accept_listed(node, shard, &addresses, u64::MAX / 2).await;
    }
}

async fn expire_some(nodes: &[Node<Idle>], from: usize, count: usize) {
    for n in from..from + count {
        let node = &nodes[n % nodes.len()];
        let shard = owned_shard(node).await;
        let addresses: Vec<String> = (0..3).map(|r| format!("x{n}.{r}@example.org")).collect();
        let addresses: Vec<&str> = addresses.iter().map(String::as_str).collect();
        accept_listed(node, shard, &addresses, 1).await;
    }
}

fn answering(nodes: &[Node<Idle>]) {
    let clock = nodes[0].sched().clock();
    ANSWERS.with_borrow_mut(|a| {
        let given = a.take().map(|a| a.given).unwrap_or_default();
        *a = Some(Answers { clock, given });
    });
}

fn crashed_while_answering(seed: u64) -> Disk {
    let config = Config {
        halt_after: Some(30 + seed * 7_919 % 80),
        faults: Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        },
        ..Config::default()
    };
    let first = Rc::new(SimDriver::with_disk(seed, config, created(seed)));
    if let Some(cluster) = try_started(&first, 2, 0, None, false, &settings_named(NAMING)) {
        let nodes = cluster.nodes.clone();
        let power = Rc::clone(&first);
        cluster.run(async move {
            let work = async {
                ready(&nodes).await;
                answering(&nodes);
                accept_some(&nodes, 0, 8).await;
                sleep(Duration::from_secs(3600)).await;
            };
            let _ = unless_halted(&power, work).await;
        });
        if !first.is_halted() {
            cluster.stop();
        }
    }
    first.crash()
}

fn check_events(seed: u64, whole: &[Given], given: &[Given]) {
    let mut keys = BTreeSet::new();
    for event in whole {
        assert!(
            given.contains(event),
            "seed {seed}: event without an answer {event:?}"
        );
        assert!(
            keys.insert((event.0.bytes(), event.1, event.2)),
            "seed {seed}: event twice {event:?}"
        );
        if event.3 != EventKind::Deferred {
            assert!(
                !given
                    .iter()
                    .any(|g| (g.0, g.1) == (event.0, event.1) && g.2 > event.2),
                "seed {seed}: final event before a later attempt {event:?}"
            );
        }
    }
    let mut finals: BTreeMap<([u8; 16], u32), Given> = BTreeMap::new();
    for g in given {
        finals.insert((g.0.bytes(), g.1), *g);
    }
    assert!(!finals.is_empty(), "seed {seed}: nothing answered");
    for g in finals.values() {
        assert_ne!(
            g.3,
            EventKind::Deferred,
            "seed {seed}: last answer not final {g:?}"
        );
        assert!(
            whole.contains(g),
            "seed {seed}: final answer without event {g:?}"
        );
    }
}

fn events_follow_results(seed: u64) {
    ANSWERS.set(None);
    let disk = crashed_while_answering(seed);
    let second = Rc::new(SimDriver::with_disk(seed + 1, Config::default(), disk));
    let cluster = started(&second, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let done = Rc::new(Cell::new(false));
        let reader = nodes[1].clone();
        let finished = Rc::clone(&done);
        let polling = spawn(async move {
            let mut collected = Vec::new();
            let mut lost = 0;
            let mut cursor = None;
            loop {
                let closing = finished.get();
                let (part, more_lost, next) = read_all(&reader, cursor.take(), 2).await;
                collected.extend(part);
                lost += more_lost;
                cursor = Some(next);
                if closing {
                    return (collected, lost);
                }
                sleep(Duration::from_millis(300)).await;
            }
        });
        accept_some(&nodes, 8, 4).await;
        let empty = || nodes.iter().all(|n| n.spool().messages_of(1).is_empty());
        for _ in 0..20_000 {
            if empty() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(empty(), "seed {seed}: messages left");
        done.set(true);
        let (mut polled, polled_lost) = polling.await;
        let (mut whole, lost, _) = read_all(&nodes[0], None, 1000).await;
        assert_eq!((lost, polled_lost), (0, 0), "seed {seed}: events lost");
        polled.sort_unstable_by_key(|e| (e.0.bytes(), e.1, e.2));
        whole.sort_unstable_by_key(|e| (e.0.bytes(), e.1, e.2));
        assert_eq!(
            polled, whole,
            "seed {seed}: cursor reads differ from a full read"
        );
        let given = ANSWERS.with_borrow_mut(|a| a.take().map(|a| a.given).unwrap_or_default());
        check_events(seed, &whole, &given);
    });
    cluster.stop();
}

#[test]
fn events_follow_results_across_a_crash() {
    check(0..6, events_follow_results);
}

#[test]
fn cursor_items_are_written_read_dropped_and_kept_across_a_restart() {
    let driver = Rc::new(SimDriver::with_disk(49, Config::default(), created(49)));
    let cluster = started_with_keys(&driver, 2);
    let nodes = cluster.nodes.clone();
    let records = cluster.run(async move {
        keys_listening().await;
        ready(&nodes).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let records = control.control_records();
        for node in &nodes {
            let changes = node.spool().changes();
            for shard in node.spool().shards() {
                assert_eq!(
                    read_cursor(changes, shard, 1, 3).await.expect("read"),
                    (None)
                );
                let first = Cursor {
                    generation: 1,
                    acked: u64::from(shard) + 10,
                    lost: 0,
                    counted: 0,
                };
                write_cursor(changes, shard, 1, 3, &first)
                    .await
                    .expect("write");
                assert_eq!(
                    read_cursor(changes, shard, 1, 3).await.expect("read"),
                    (Some(first))
                );
                assert_eq!(
                    read_cursor(changes, shard, 2, 3).await.expect("read"),
                    (None)
                );
                let moved = Cursor {
                    acked: first.acked + 5,
                    lost: 2,
                    counted: 20_000,
                    ..first
                };
                write_cursor(changes, shard, 1, 3, &moved)
                    .await
                    .expect("write");
                assert_eq!(
                    read_cursor(changes, shard, 1, 3).await.expect("read"),
                    (Some(moved))
                );
                write_cursor(changes, shard, 1, 4, &first)
                    .await
                    .expect("write");
                drop_cursor(changes, shard, 1, 4).await.expect("drop");
                drop_cursor(changes, shard, 1, 4).await.expect("drop again");
                assert_eq!(
                    read_cursor(changes, shard, 1, 4).await.expect("read"),
                    (None)
                );
            }
        }
        assert_eq!(control.control_records(), records);
        records
    });
    cluster.stop();
    let driver = Rc::new(SimDriver::with_disk(50, Config::default(), driver.crash()));
    let restarted = started_with_keys(&driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        keys_listening().await;
        wait_for(&nodes, 1, 1, State::Active).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        assert_eq!(control.control_records(), records);
        for node in &nodes {
            let changes = node.spool().changes();
            for shard in node.spool().shards() {
                let kept = read_cursor(changes, shard, 1, 3).await.expect("read");
                assert_eq!(
                    kept.map(|c| (c.acked, c.lost)),
                    Some((u64::from(shard) + 15, 2))
                );
                assert_eq!(
                    read_cursor(changes, shard, 1, 4).await.expect("read"),
                    (None)
                );
            }
        }
    });
    restarted.stop();
}

#[test]
fn cursor_bytes_round_trip_and_refuse_other_formats() {
    let cursor = Cursor {
        generation: 7,
        acked: u64::MAX - 1,
        lost: 3,
        counted: 20_001,
    };
    let bytes = cursor.encode();
    assert_eq!(Cursor::decode(&bytes), Some(cursor));
    let mut other = bytes;
    other[0] = 2;
    assert_eq!(Cursor::decode(&other), None);
    assert_eq!(Cursor::decode(&bytes[..24]), None);
}

type Streamed = (MessageId, u32, EventKind, u16, u64);

#[derive(Default)]
struct Caught {
    calls: RefCell<Vec<(u32, Vec<Streamed>)>>,
    refuse: Cell<u32>,
    tried: Cell<usize>,
    slow: Cell<bool>,
    flying: Cell<u32>,
    most: Cell<u32>,
    lost: Cell<u64>,
}

struct Catch(Rc<Caught>, Node<Idle>);

impl Deliver for Catch {
    fn deliver(&self, call: Rc<Call>) -> Sending {
        let caught = Rc::clone(&self.0);
        let node = self.1.clone();
        Box::pin(async move {
            if caught.refuse.get() > 0 {
                caught.refuse.set(caught.refuse.get() - 1);
                caught.tried.set(caught.tried.get().max(call.events.len()));
                return Outcome::Retry {
                    after: Duration::from_secs(2),
                    status: Some(500),
                };
            }
            caught.flying.set(caught.flying.get() + 1);
            caught.most.set(caught.most.get().max(caught.flying.get()));
            if caught.slow.get() {
                sleep(Duration::from_secs(3)).await;
            }
            caught.flying.set(caught.flying.get() - 1);
            let events = node
                .open_call(&call)
                .await
                .expect("opened")
                .iter()
                .map(|r| {
                    assert!(r.body.is_some(), "event body opened");
                    (
                        r.event.message,
                        r.event.recipient,
                        r.event.kind,
                        r.shard,
                        r.sequence,
                    )
                })
                .collect();
            caught.calls.borrow_mut().push((call.hook, events));
            caught.lost.set(caught.lost.get() + call.lost);
            Outcome::Acked { status: 200 }
        })
    }
}

async fn drained(nodes: &[Node<Idle>]) {
    for _ in 0..20_000 {
        if nodes.iter().all(|n| n.spool().messages_of(1).is_empty()) {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("messages left");
}

fn delivered_to(caught: &Caught, hook: u32) -> Vec<Streamed> {
    caught
        .calls
        .borrow()
        .iter()
        .filter(|(h, _)| *h == hook)
        .flat_map(|(_, events)| events.iter().copied())
        .collect()
}

fn check_streamed(seed: u64, got: &[Streamed], want: &[Given]) {
    let mut once = BTreeSet::new();
    for event in got {
        assert!(
            once.insert((event.3, event.4)),
            "seed {seed}: event twice {event:?}"
        );
    }
    let mut last: BTreeMap<(MessageId, u32), u64> = BTreeMap::new();
    for event in got {
        let before = last.insert((event.0, event.1), event.4);
        assert!(
            before.is_none_or(|b| b < event.4),
            "seed {seed}: out of order {event:?}"
        );
    }
    let mut got: Vec<_> = got.iter().map(|e| (e.0.bytes(), e.1, e.2 as u8)).collect();
    let mut want: Vec<_> = want.iter().map(|e| (e.0.bytes(), e.1, e.3 as u8)).collect();
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want, "seed {seed}: streamed events differ");
}

#[test]
fn webhook_streams_send_each_matching_event_once_from_the_head() {
    ANSWERS.set(None);
    let seed = 51;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    let caught = Rc::new(Caught::default());
    let watching = Rc::clone(&caught);
    let (all, some) = cluster.run(async move {
        let caught = watching;
        ready(&nodes).await;
        answering(&nodes);
        accept_some(&nodes, 0, 2).await;
        drained(&nodes).await;
        let (before, _, _) = read_all(&nodes[0], None, 1000).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let at = "https://hooks.example.org/in";
        let all = control.hook_new(1, at, 0).await.expect("new").id;
        let some = control.hook_new(1, at, 1).await.expect("new").id;
        let other = control.hook_new(2, at, 0).await.expect("new").id;
        caught.refuse.set(2);
        let tasks: Vec<_> = nodes
            .iter()
            .map(|n| n.start_hooks(Rc::new(Catch(Rc::clone(&caught), n.clone()))))
            .collect();
        sleep(Duration::from_secs(2)).await;
        accept_some(&nodes, 2, 6).await;
        drained(&nodes).await;
        sleep(Duration::from_secs(10)).await;
        let (whole, _, _) = read_all(&nodes[0], None, 1000).await;
        let fresh: Vec<Given> = whole.into_iter().filter(|e| !before.contains(e)).collect();
        assert_ne!(fresh.len(), 0);
        check_streamed(seed, &delivered_to(&caught, all), &fresh);
        let wanted: Vec<Given> = fresh
            .iter()
            .copied()
            .filter(|e| e.3 == EventKind::Delivered)
            .collect();
        check_streamed(seed, &delivered_to(&caught, some), &wanted);
        assert_eq!(delivered_to(&caught, other).len(), 0);
        assert_eq!(caught.refuse.get(), 0);
        for node in &nodes {
            let changes = node.spool().changes();
            for shard in node.spool().shards() {
                let top = delivered_to(&caught, all)
                    .iter()
                    .filter(|e| e.3 == shard)
                    .map(|e| e.4)
                    .max()
                    .unwrap_or(0);
                let cursor = read_cursor(changes, shard, 1, all).await.expect("read");
                assert!(cursor.is_some_and(|c| c.acked >= top), "shard {shard}");
            }
        }
        drop(tasks);
        (all, some)
    });
    cluster.stop();
    let sent = caught.calls.borrow().len();
    let driver = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    let restarted = started(&driver, 2);
    let nodes = restarted.nodes.clone();
    let watching = Rc::clone(&caught);
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        let tasks: Vec<_> = nodes
            .iter()
            .map(|n| n.start_hooks(Rc::new(Catch(Rc::clone(&watching), n.clone()))))
            .collect();
        sleep(Duration::from_secs(5)).await;
        assert_eq!(
            watching.calls.borrow().len(),
            sent,
            "acknowledged events sent again"
        );
        drop(tasks);
    });
    restarted.stop();
    assert!(delivered_to(&caught, all).len() > delivered_to(&caught, some).len());
}

#[test]
fn a_webhook_paused_and_resumed_while_sending_keeps_one_call_and_every_event() {
    ANSWERS.set(None);
    let seed = 53;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 1);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let control = &nodes[0];
        let hook = control
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let caught = Rc::new(Caught::default());
        caught.slow.set(true);
        let task = control.start_hooks(Rc::new(Catch(Rc::clone(&caught), control.clone())));
        sleep(Duration::from_secs(2)).await;
        accept_some(&nodes, 0, 4).await;
        drained(&nodes).await;
        for enabled in [false, true, false, true] {
            sleep(Duration::from_millis(700)).await;
            let change = HookChange {
                enabled: Some(enabled),
                ..HookChange::default()
            };
            control.hook_change(1, hook, change).await.expect("change");
        }
        caught.slow.set(false);
        accept_some(&nodes, 4, 2).await;
        drained(&nodes).await;
        sleep(Duration::from_secs(20)).await;
        assert_eq!(caught.most.get(), 1, "two calls in flight");
        let (whole, _, _) = read_all(&nodes[0], None, 1000).await;
        let got: BTreeSet<_> = delivered_to(&caught, hook)
            .iter()
            .map(|e| (e.0.bytes(), e.1, e.2 as u8))
            .collect();
        let want: BTreeSet<_> = whole
            .iter()
            .map(|e| (e.0.bytes(), e.1, e.3 as u8))
            .collect();
        assert_eq!(got, want, "events missing");
        drop(task);
    });
    cluster.stop();
}

async fn cursors_everywhere(nodes: &[Node<Idle>], hook: u32, present: bool) {
    for node in nodes {
        let changes = node.spool().changes();
        for shard in node.spool().shards() {
            for _ in 0..200 {
                let found = read_cursor(changes, shard, 1, hook).await.expect("read");
                if found.is_some() == present {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
            let found = read_cursor(changes, shard, 1, hook).await.expect("read");
            assert_eq!(found.is_some(), present, "hook {hook} shard {shard}");
        }
    }
}

#[test]
fn webhook_cursors_stay_while_paused_and_go_with_their_endpoint() {
    let driver = Rc::new(SimDriver::with_disk(55, Config::default(), created(55)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let at = "https://hooks.example.org/in";
        let paused = control.hook_new(1, at, 0).await.expect("new").id;
        let removed = control.hook_new(1, at, 0).await.expect("new").id;
        let caught = Rc::new(Caught::default());
        let tasks: Vec<_> = nodes
            .iter()
            .map(|n| n.start_hooks(Rc::new(Catch(Rc::clone(&caught), n.clone()))))
            .collect();
        cursors_everywhere(&nodes, paused, true).await;
        cursors_everywhere(&nodes, removed, true).await;
        let off = HookChange {
            enabled: Some(false),
            ..HookChange::default()
        };
        control.hook_change(1, paused, off).await.expect("pause");
        control.hook_remove(1, removed).await.expect("remove");
        cursors_everywhere(&nodes, removed, false).await;
        sleep(Duration::from_secs(3)).await;
        cursors_everywhere(&nodes, paused, true).await;
        drop(tasks);
    });
    cluster.stop();
}

async fn lost_of(node: &Node<Idle>, hook: u32) -> u64 {
    let mut lost = 0;
    for shard in node.spool().shards() {
        let found = read_cursor(node.spool().changes(), shard, 1, hook).await;
        lost += found.expect("read").map_or(0, |c| c.lost);
    }
    lost
}

#[test]
fn events_dropped_by_retention_are_counted_lost_for_each_webhook() {
    ANSWERS.set(None);
    let seed = 57;
    let refusing = || {
        let caught = Caught::default();
        caught.refuse.set(u32::MAX);
        Rc::new(caught)
    };
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started_behind(&driver, 1, 8 * DAY_MS as u64);
    let nodes = cluster.nodes.clone();
    let (live, paused, total, day, shards) = cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let node = &nodes[0];
        let (before, _, _) = read_all(node, None, 1000).await;
        let at = "https://hooks.example.org/in";
        let live = node.hook_new(1, at, 0).await.expect("new").id;
        let paused = node.hook_new(1, at, 0).await.expect("new").id;
        let task = node.start_hooks(Rc::new(Catch(refusing(), node.clone())));
        cursors_everywhere(&nodes, live, true).await;
        cursors_everywhere(&nodes, paused, true).await;
        drop(task);
        accept_some(&nodes, 0, 30).await;
        drained(&nodes).await;
        let (whole, _, _) = read_all(node, None, 1000).await;
        let total = (whole.len() - before.len()) as u64;
        let day = node.requests().today();
        let kept = node.spool().changes().partitions(KIND_EVENT).await;
        let shards: Vec<u16> = kept
            .expect("partitions")
            .into_iter()
            .filter(|p| p.1 == day)
            .map(|p| p.0)
            .collect();
        (live, paused, total, day, shards)
    });
    cluster.stop();
    assert!(total > 100, "{total} events");
    let wall = Config::default().wall_start_ms;
    let behind = wall - (u64::from(day + 7) * DAY_MS as u64 - 60_000);
    let driver = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    let restarted = started_behind(&driver, 1, behind);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        answering(&nodes);
        let node = &nodes[0];
        assert_eq!(node.requests().today(), day + 6);
        let off = HookChange {
            enabled: Some(false),
            ..HookChange::default()
        };
        node.hook_change(1, paused, off).await.expect("pause");
        let caught = refusing();
        let task = node.start_hooks(Rc::new(Catch(Rc::clone(&caught), node.clone())));
        let again = node.start_hooks(Rc::new(Catch(Rc::clone(&caught), node.clone())));
        sleep(Duration::from_secs(120)).await;
        assert_eq!(node.requests().today(), day + 7);
        assert_ne!(shards.len(), 0);
        for &shard in &shards {
            for hook in [live, paused] {
                let found = read_cursor(node.spool().changes(), shard, 1, hook).await;
                assert_eq!(found.expect("read").map(|c| c.counted), Some(day));
            }
        }
        assert_eq!(lost_of(node, paused).await, total);
        assert_eq!(lost_of(node, live).await, total);
        assert!(caught.tried.get() > 0);
        let (before, _, _) = read_all(node, None, 1000).await;
        caught.refuse.set(0);
        accept_some(&nodes, 30, 2).await;
        drained(&nodes).await;
        sleep(Duration::from_secs(10)).await;
        let (whole, _, _) = read_all(node, None, 1000).await;
        let fresh: Vec<Given> = whole.into_iter().filter(|e| !before.contains(e)).collect();
        assert_ne!(fresh.len(), 0);
        check_streamed(seed, &delivered_to(&caught, live), &fresh);
        assert_eq!(caught.lost.get(), total);
        assert_eq!(lost_of(node, live).await, 0);
        assert_eq!(lost_of(node, paused).await, total);
        drop((task, again));
    });
    restarted.stop();
}

#[derive(Default)]
struct Attempts {
    calls: RefCell<Vec<([u8; 16], u64, usize)>>,
    retry: Cell<bool>,
}

struct Attempted(Rc<Attempts>);

impl Deliver for Attempted {
    fn deliver(&self, call: Rc<Call>) -> Sending {
        let attempts = Rc::clone(&self.0);
        Box::pin(async move {
            attempts
                .calls
                .borrow_mut()
                .push((call.id, call.lost, call.events.len()));
            if attempts.retry.get() {
                Outcome::Retry {
                    after: Duration::from_secs(1),
                    status: Some(500),
                }
            } else {
                Outcome::Acked { status: 200 }
            }
        })
    }
}

async fn calls_at_least(attempts: &Attempts, n: usize) {
    for _ in 0..30_000 {
        if attempts.calls.borrow().len() >= n {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("only {} calls", attempts.calls.borrow().len());
}

async fn find_call(
    attempts: &Attempts,
    matches: impl Fn(&([u8; 16], u64, usize)) -> bool,
) -> ([u8; 16], u64, usize) {
    for _ in 0..30_000 {
        let found = attempts
            .calls
            .borrow()
            .iter()
            .copied()
            .find(|call| matches(call));
        if let Some(call) = found {
            return call;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("no matching call");
}

async fn new_call(attempts: &Attempts, known: &[[u8; 16]]) -> ([u8; 16], u64, usize) {
    find_call(attempts, |(id, _, _)| !known.contains(id)).await
}

async fn set_enabled(nodes: &[Node<Idle>], hook: u32, enabled: bool) {
    let changed = nodes[0]
        .hook_change(
            1,
            hook,
            HookChange {
                enabled: Some(enabled),
                ..HookChange::default()
            },
        )
        .await
        .expect("change");
    hook_everywhere(nodes, &changed).await;
}

async fn lost_is_zero(node: &Node<Idle>, hook: u32) {
    for _ in 0..30_000 {
        if lost_of(node, hook).await == 0 {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("lost never settled");
}

#[test]
fn call_ids_survive_retries_and_change_with_cursor_and_mask() {
    ANSWERS.set(None);
    let driver = Rc::new(SimDriver::with_disk(59, Config::default(), created(59)));
    let cluster = started(&driver, 1);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let node = &nodes[0];
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let attempts = Rc::new(Attempts::default());
        attempts.retry.set(true);
        let task = node.start_hooks(Rc::new(Attempted(Rc::clone(&attempts))));
        accept_some(&nodes, 0, 2).await;
        drained(&nodes).await;
        calls_at_least(&attempts, 2).await;
        let first = attempts.calls.borrow()[0].0;
        assert!(
            attempts
                .calls
                .borrow()
                .iter()
                .all(|(id, lost, _)| *id == first && *lost == 0),
            "a retry changed the call"
        );
        attempts.retry.set(false);
        accept_some(&nodes, 2, 2).await;
        drained(&nodes).await;
        let (second, _, _) = new_call(&attempts, &[first]).await;
        attempts.retry.set(true);
        accept_some(&nodes, 4, 3).await;
        drained(&nodes).await;
        let (third, _, _) = new_call(&attempts, &[first, second]).await;
        calls_at_least(&attempts, 2).await;
        let paused = node
            .hook_change(
                1,
                hook,
                HookChange {
                    url: None,
                    events: Some(1),
                    enabled: Some(false),
                },
            )
            .await
            .expect("pause");
        hook_everywhere(&nodes, &paused).await;
        set_enabled(&nodes, hook, true).await;
        let (_, _, events) = new_call(&attempts, &[first, second, third]).await;
        assert!(events > 0, "the masked refill is empty");
        attempts.retry.set(false);
        sleep(Duration::from_secs(5)).await;
        drop(task);
    });
    cluster.stop();
}

#[test]
fn lost_only_calls_with_the_same_total_get_different_ids_after_a_cursor_move() {
    ANSWERS.set(None);
    let seed = 63;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 1);
    let nodes = cluster.nodes.clone();
    let attempts = Rc::new(Attempts::default());
    let watching = Rc::clone(&attempts);
    let (hook, first, one) = cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let changes = node.spool().changes();
        let shard = node.spool().shards()[0];
        let one = Cursor {
            generation: 1,
            acked: changes.watch().head(),
            lost: 5,
            counted: 0,
        };
        write_cursor(changes, shard, 1, hook, &one)
            .await
            .expect("cursor");
        let task = node.start_hooks(Rc::new(Attempted(Rc::clone(&watching))));
        let (first, lost, events) = new_call(&watching, &[]).await;
        assert_eq!((lost, events), (5, 0));
        lost_is_zero(node, hook).await;
        drop(task);
        (hook, first, one)
    });
    cluster.stop();
    let driver = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    let restarted = started(&driver, 1);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        let node = &nodes[0];
        let changes = node.spool().changes();
        let shard = node.spool().shards()[0];
        let two = Cursor {
            acked: changes.watch().head(),
            ..one
        };
        assert_ne!(two.acked, one.acked, "the cursor did not move");
        write_cursor(changes, shard, 1, hook, &two)
            .await
            .expect("cursor");
        let task = node.start_hooks(Rc::new(Attempted(Rc::clone(&attempts))));
        let (second, lost, events) = new_call(&attempts, &[first]).await;
        assert_eq!((lost, events), (5, 0));
        assert_ne!(first, second, "two lost-only calls shared an id");
        drop(task);
    });
    restarted.stop();
}

#[test]
fn a_trimmed_call_keeps_its_id_and_lost_is_reported_once() {
    ANSWERS.set(None);
    let seed = 61;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started_behind(&driver, 1, 8 * DAY_MS as u64);
    let nodes = cluster.nodes.clone();
    let attempts = Rc::new(Attempts::default());
    let watching = Rc::clone(&attempts);
    let (hook, day, first, batch, events) = cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        watching.retry.set(true);
        let task = node.start_hooks(Rc::new(Attempted(Rc::clone(&watching))));
        expire_some(&nodes, 0, 5).await;
        drained(&nodes).await;
        calls_at_least(&watching, 2).await;
        let first = watching.calls.borrow()[0].0;
        assert!(
            watching.calls.borrow().iter().all(|(id, ..)| *id == first),
            "a retry changed the id"
        );
        let day = node.requests().today();
        set_enabled(&nodes, hook, false).await;
        let now = node.sched().clock().now();
        sleep(Duration::from_millis(now / DAY * DAY + DAY + 1_000 - now)).await;
        expire_some(&nodes, 5, 25).await;
        drained(&nodes).await;
        set_enabled(&nodes, hook, true).await;
        let (batch, _, events) = new_call(&watching, &[first]).await;
        assert_eq!(events, 90, "the refill must stay under the batch cap");
        drop(task);
        (hook, day, first, batch, events)
    });
    cluster.stop();
    let wall = Config::default().wall_start_ms;
    let behind = wall - (u64::from(day + 7) * DAY_MS as u64 - 60_000);
    let driver = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    let restarted = started_behind(&driver, 1, behind);
    let nodes = restarted.nodes.clone();
    let watching = attempts;
    restarted.run(async move {
        wait_for(&nodes, 1, 1, State::Active).await;
        let node = &nodes[0];
        assert_eq!(node.requests().today(), day + 6);
        watching.retry.set(true);
        let task = node.start_hooks(Rc::new(Attempted(Rc::clone(&watching))));
        let before = watching.calls.borrow().len();
        calls_at_least(&watching, before + 1).await;
        assert_eq!(
            watching.calls.borrow()[before].0,
            batch,
            "a crash rebuild of the same range changed the id"
        );
        let (_, _, trimmed_events) =
            find_call(&watching, |(id, _, n)| *id == batch && *n < events).await;
        watching.retry.set(false);
        let known = [first, batch];
        let (lost_id, lost, _) = find_call(&watching, |(id, lost, n)| {
            !known.contains(id) && *n == 0 && *lost > 0
        })
        .await;
        assert_eq!(
            lost,
            u64::try_from(events - trimmed_events).expect("small"),
            "the trimmed events were not counted lost"
        );
        lost_is_zero(node, hook).await;
        expire_some(&nodes, 30, 1).await;
        drained(&nodes).await;
        let (_, quiet, some) = new_call(&watching, &[first, batch, lost_id]).await;
        assert_eq!(quiet, 0, "lost reported again after the ack");
        assert!(some > 0);
        drop(task);
    });
    restarted.stop();
}

struct HookAnswers {
    calls: RefCell<Vec<usize>>,
}

struct HookAnswer(Rc<HookAnswers>, usize, Outcome);

impl Deliver for HookAnswer {
    fn deliver(&self, _call: Rc<Call>) -> Sending {
        self.0.calls.borrow_mut()[self.1] += 1;
        if self.2 == Outcome::Gone && KEYS_DOWN_ON_GONE.with(Cell::get) {
            HOOK_KEYS_DOWN.set(true);
        }
        Box::pin(std::future::ready(self.2))
    }
}

async fn status_hook(nodes: &[Node<Idle>]) -> Hook {
    let control = nodes.iter().find(|n| n.controls()).expect("control core");
    let hook = control
        .hook_new(1, "https://hooks.example.org/in", 0)
        .await
        .expect("new");
    hook_everywhere(nodes, &hook).await;
    for node in nodes {
        let changes = node.spool().changes();
        for shard in node.spool().shards() {
            let cursor = Cursor {
                generation: 1,
                acked: changes.watch().head(),
                lost: 1,
                counted: 0,
            };
            write_cursor(changes, shard, 1, hook.id, &cursor)
                .await
                .expect("cursor");
        }
    }
    hook
}

fn start_hook_answers(
    nodes: &[Node<Idle>],
    answers: &Rc<HookAnswers>,
    outcomes: Vec<Outcome>,
) -> Vec<JoinHandle<()>> {
    nodes
        .iter()
        .zip(outcomes)
        .enumerate()
        .map(|(core, (node, outcome))| {
            node.start_hooks(Rc::new(HookAnswer(Rc::clone(answers), core, outcome)))
        })
        .collect()
}

async fn wait_hook_state(nodes: &[Node<Idle>], id: u32, state: HookState) {
    for _ in 0..120 {
        if nodes.iter().all(|node| {
            node.table()
                .hook(1, id)
                .is_some_and(|hook| hook.state == state)
        }) {
            return;
        }
        sleep(Duration::from_secs(1)).await;
    }
    panic!("hook did not become {state:?}");
}

fn retry_status() -> Outcome {
    Outcome::Retry {
        after: Duration::from_secs(3600),
        status: Some(500),
    }
}

#[test]
fn a_gone_stream_disables_the_hook_on_every_core_without_retrying() {
    let seed = 70;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let hook = status_hook(&nodes).await;
        let answers = Rc::new(HookAnswers {
            calls: RefCell::new(vec![0; nodes.len()]),
        });
        let tasks = start_hook_answers(&nodes, &answers, vec![Outcome::Gone, retry_status()]);
        wait_hook_state(&nodes, hook.id, HookState::Gone).await;
        sleep(Duration::from_secs(3700)).await;
        assert_eq!(answers.calls.borrow()[0], 1);
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        assert_eq!(
            control.hook_stats(),
            HookStats {
                gone: 1,
                failing: 0,
                write_failed: 0,
            }
        );
        for node in nodes.iter().filter(|n| !n.controls()) {
            assert_eq!(node.hook_stats(), HookStats::default());
        }
        drop(tasks);
    });
    cluster.stop();
}

#[test]
fn webhook_calls_and_streams_are_counted_on_each_core() {
    let seed = 72;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        status_hook(&nodes).await;
        let answers = Rc::new(HookAnswers {
            calls: RefCell::new(vec![0; nodes.len()]),
        });
        let acked = Outcome::Acked { status: 200 };
        let tasks = start_hook_answers(&nodes, &answers, vec![acked, retry_status()]);
        sleep(Duration::from_secs(10)).await;
        assert_eq!(answers.calls.borrow().as_slice(), &[1, 1]);
        assert_eq!(
            nodes[0].call_stats(),
            CallStats {
                acked: 1,
                streams: 1,
                ..CallStats::default()
            }
        );
        assert_eq!(
            nodes[1].call_stats(),
            CallStats {
                retried: 1,
                streams: 1,
                failing: 1,
                ..CallStats::default()
            }
        );
        drop(tasks);
    });
    cluster.stop();
}

#[test]
fn three_days_of_failures_on_every_core_disable_the_hook() {
    let seed = 71;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let hook = status_hook(&nodes).await;
        let answers = Rc::new(HookAnswers {
            calls: RefCell::new(vec![0; nodes.len()]),
        });
        let tasks = start_hook_answers(&nodes, &answers, vec![retry_status(), retry_status()]);
        sleep(Duration::from_millis(3 * DAY + 1_000)).await;
        wait_hook_state(&nodes, hook.id, HookState::Failing).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let status = control.hook_status(control.hook(1, hook.id).as_ref().expect("hook"));
        assert_eq!(status.last_status, Some(500));
        assert!(status.failing_since.is_some());
        assert_eq!(status.lost, u64::from(SHARDS));
        assert_eq!(
            control.hook_stats(),
            HookStats {
                gone: 0,
                failing: 1,
                write_failed: 0,
            }
        );
        drop(tasks);
    });
    cluster.stop();
}

#[test]
fn a_recent_success_on_one_core_prevents_failing_disable() {
    ANSWERS.set(None);
    let seed = 72;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let hook = status_hook(&nodes).await;
        let answers = Rc::new(HookAnswers {
            calls: RefCell::new(vec![0; nodes.len()]),
        });
        let tasks = start_hook_answers(
            &nodes,
            &answers,
            vec![Outcome::Acked { status: 204 }, retry_status()],
        );
        sleep(Duration::from_millis(2 * DAY)).await;
        answering(&nodes);
        accept_some(&nodes, 0, 1).await;
        drained(&nodes).await;
        sleep(Duration::from_millis(DAY + 120_000)).await;
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let hook = control.hook(1, hook.id).expect("hook");
        assert_eq!(hook.state, HookState::Active);
        assert_eq!(control.hook_status(&hook).last_status, Some(500));
        assert_eq!(control.hook_stats(), HookStats::default());
        drop(tasks);
    });
    cluster.stop();
}

#[test]
fn a_core_that_does_not_report_blocks_the_failing_decision() {
    let seed = 73;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let hook = status_hook(&nodes).await;
        let answers = Rc::new(HookAnswers {
            calls: RefCell::new(vec![0; nodes.len()]),
        });
        let task =
            nodes[0].start_hooks(Rc::new(HookAnswer(Rc::clone(&answers), 0, retry_status())));
        sleep(Duration::from_millis(3 * DAY + 120_000)).await;
        assert_eq!(
            nodes[0].table().hook(1, hook.id).map(|hook| hook.state),
            Some(HookState::Active)
        );
        drop(task);
    });
    cluster.stop();
}

#[test]
fn a_failed_gone_write_is_retried_on_the_next_round() {
    let seed = 74;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 1);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let hook = status_hook(&nodes).await;
        let answers = Rc::new(HookAnswers {
            calls: RefCell::new(vec![0; nodes.len()]),
        });
        KEYS_DOWN_ON_GONE.set(true);
        let tasks = start_hook_answers(&nodes, &answers, vec![Outcome::Gone]);
        sleep(Duration::from_secs(120)).await;
        assert_eq!(answers.calls.borrow()[0], 1);
        assert_eq!(
            nodes[0].table().hook(1, hook.id).map(|hook| hook.state),
            Some(HookState::Active)
        );
        let failed = nodes[0].hook_stats();
        assert!(failed.write_failed >= 1);
        assert_eq!(failed.gone, 0);
        KEYS_DOWN_ON_GONE.set(false);
        HOOK_KEYS_DOWN.set(false);
        wait_hook_state(&nodes, hook.id, HookState::Gone).await;
        assert_eq!(answers.calls.borrow()[0], 1);
        let stats = nodes[0].hook_stats();
        assert_eq!(stats.gone, 1);
        assert_eq!(stats.write_failed, failed.write_failed);
        drop(tasks);
    });
    cluster.stop();
}

#[test]
fn hook_status_reports_are_chunked_and_pruned_on_delete() {
    let seed = 75;
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 1);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let missing: Vec<Object> = (3..=9).map(|id| tenant(id, 1, State::Active)).collect();
        configure(&nodes, missing).await;
        let mut hooks = Vec::new();
        for id in 1..=65_u32 {
            let tenant = (id - 1) / u32::try_from(MAX_HOOKS).expect("small") + 1;
            let hook = node
                .hook_new(tenant, "https://hooks.example.org/in", 0)
                .await
                .expect("new");
            let hook = node
                .hook_change(
                    tenant,
                    hook.id,
                    HookChange {
                        enabled: Some(false),
                        ..HookChange::default()
                    },
                )
                .await
                .expect("pause");
            let shard = node.spool().shards()[0];
            let cursor = Cursor {
                generation: 1,
                acked: node.spool().changes().watch().head(),
                lost: u64::from(id),
                counted: 0,
            };
            write_cursor(node.spool().changes(), shard, tenant, hook.id, &cursor)
                .await
                .expect("cursor");
            hooks.push(hook);
        }
        let task = node.start_hooks(Rc::new(Catch(Rc::new(Caught::default()), node.clone())));
        for _ in 0..120 {
            if node.hook_status(&hooks[64]).lost == 65 {
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }
        for (id, hook) in hooks.iter().enumerate() {
            assert_eq!(node.hook_status(hook).lost, id as u64 + 1);
        }
        node.hook_remove(hooks[0].tenant, hooks[0].id)
            .await
            .expect("remove");
        assert_eq!(node.hook_status(&hooks[0]).lost, 0);
        node.delete_tenant(hooks[8].tenant).await.expect("delete");
        wait_for(&nodes, hooks[8].tenant, 1, State::Deleted).await;
        assert_eq!(node.hook_status(&hooks[8]).lost, 0);
        drop(task);
    });
    cluster.stop();
}

#[derive(Clone, Copy)]
enum Endpoint {
    Healthy,
    Flapping,
    Slow,
    Failing,
}

struct Sim {
    modes: RefCell<BTreeMap<u32, Endpoint>>,
    calls: RefCell<Vec<(u32, Vec<Streamed>)>>,
    lost: RefCell<BTreeMap<u32, u64>>,
    flying: RefCell<BTreeSet<(u32, usize)>>,
    rng: RefCell<Rng>,
}

struct Flying(Rc<Sim>, (u32, usize));

impl Drop for Flying {
    fn drop(&mut self) {
        self.0.flying.borrow_mut().remove(&self.1);
    }
}

struct SimEndpoint(Rc<Sim>, Node<Idle>, usize);

impl Deliver for SimEndpoint {
    fn deliver(&self, call: Rc<Call>) -> Sending {
        let (sim, node, core) = (Rc::clone(&self.0), self.1.clone(), self.2);
        Box::pin(async move {
            let current =
                node.table().hook(call.tenant, call.hook).is_some_and(|h| {
                    h.state == HookState::Active && h.generation == call.generation
                }) && node
                    .table()
                    .tenant(call.tenant)
                    .is_some_and(|t| t.state == State::Active && t.generation == call.generation);
            if !current {
                return Outcome::Refused(Duration::from_secs(1));
            }
            let key = (call.hook, core);
            assert!(sim.flying.borrow_mut().insert(key), "two calls in flight");
            let _flying = Flying(Rc::clone(&sim), key);
            let mode = sim
                .modes
                .borrow()
                .get(&call.hook)
                .copied()
                .unwrap_or(Endpoint::Healthy);
            let (wait, ok) = {
                let mut rng = sim.rng.borrow_mut();
                match mode {
                    Endpoint::Healthy => (Duration::ZERO, true),
                    Endpoint::Flapping => (
                        Duration::from_millis(rng.below(200)),
                        rng.chance(MILLION / 2),
                    ),
                    Endpoint::Slow => (
                        rng.between(Duration::from_secs(1), Duration::from_secs(5)),
                        true,
                    ),
                    Endpoint::Failing => (Duration::from_millis(rng.below(100)), false),
                }
            };
            sleep(wait).await;
            if !ok {
                return Outcome::Retry {
                    after: Duration::from_secs(1),
                    status: Some(503),
                };
            }
            let events: Vec<Streamed> = node
                .open_call(&call)
                .await
                .expect("opened")
                .iter()
                .map(|r| {
                    (
                        r.event.message,
                        r.event.recipient,
                        r.event.kind,
                        r.shard,
                        r.sequence,
                    )
                })
                .collect();
            sim.calls.borrow_mut().push((call.hook, events));
            *sim.lost.borrow_mut().entry(call.hook).or_default() += call.lost;
            Outcome::Acked { status: 200 }
        })
    }
}

fn sim_hooks(sim: &Rc<Sim>, nodes: &[Node<Idle>]) -> Vec<JoinHandle<()>> {
    nodes
        .iter()
        .enumerate()
        .map(|(core, n)| n.start_hooks(Rc::new(SimEndpoint(Rc::clone(sim), n.clone(), core))))
        .collect()
}

fn first_seen(sim: &Sim, hook: u32) -> Vec<Streamed> {
    let mut seen = BTreeSet::new();
    let mut last: BTreeMap<(MessageId, u32), u64> = BTreeMap::new();
    let mut first = Vec::new();
    for (h, events) in sim.calls.borrow().iter() {
        if *h != hook {
            continue;
        }
        let mut inside: BTreeMap<(MessageId, u32), u64> = BTreeMap::new();
        for event in events {
            let before = inside.insert((event.0, event.1), event.4);
            assert!(
                before.is_none_or(|b| b < event.4),
                "out of order in one call {event:?}"
            );
            if seen.insert((event.3, event.4)) {
                let before = last.insert((event.0, event.1), event.4);
                assert!(before.is_none_or(|b| b < event.4), "out of order {event:?}");
                first.push(*event);
            }
        }
    }
    first
}

fn missing(sim: &Sim, hook: u32, want: &[Given], only: Option<EventKind>) -> usize {
    let mut got: Vec<_> = first_seen(sim, hook)
        .iter()
        .map(|e| (e.0.bytes(), e.1, e.2 as u8))
        .collect();
    got.sort_unstable();
    let mut absent = 0;
    for e in want.iter().filter(|e| only.is_none_or(|k| e.3 == k)) {
        match got.binary_search(&(e.0.bytes(), e.1, e.3 as u8)) {
            Ok(i) => drop(got.remove(i)),
            Err(_) => absent += 1,
        }
    }
    assert_eq!(got.len(), 0, "events streamed that were never given");
    absent
}

async fn delivered_all(sim: &Sim, nodes: &[Node<Idle>], hook: u32, only: Option<EventKind>) {
    for _ in 0..600 {
        let (whole, _, _) = read_all(&nodes[0], None, 1000).await;
        if missing(sim, hook, &whole, only) == 0 {
            return;
        }
        sleep(Duration::from_secs(1)).await;
    }
    let (whole, _, _) = read_all(&nodes[0], None, 1000).await;
    panic!(
        "hook {hook}: {} events missing",
        missing(sim, hook, &whole, only)
    );
}

async fn cursors_of(nodes: &[Node<Idle>], tenant: u32, hook: u32) -> usize {
    let mut found = 0;
    for node in nodes {
        for shard in node.spool().shards() {
            let cursor = read_cursor(node.spool().changes(), shard, tenant, hook).await;
            found += usize::from(cursor.expect("read").is_some());
        }
    }
    found
}

async fn lost_everywhere(nodes: &[Node<Idle>], hook: u32) -> u64 {
    let mut lost = 0;
    for node in nodes {
        lost += lost_of(node, hook).await;
    }
    lost
}

fn webhooks_sim(seed: u64) {
    ANSWERS.set(None);
    let (first_cores, second_cores) =
        [(1, 2), (2, 4), (4, 1), (2, 1)][usize::try_from(seed % 4).expect("small")];
    let mut rng = Rng::new(seed);
    let sim = Rc::new(Sim {
        modes: RefCell::default(),
        calls: RefCell::default(),
        lost: RefCell::default(),
        flying: RefCell::default(),
        rng: RefCell::new(Rng::new(seed ^ 0x5157)),
    });
    let first_count = 4 + rng.index(4);
    let cut = rng.between(Duration::ZERO, Duration::from_secs(3));
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started_behind(&driver, first_cores, 8 * DAY_MS as u64);
    let nodes = cluster.nodes.clone();
    let shared = Rc::clone(&sim);
    let (hooks, day) = cluster.run(async move {
        let sim = shared;
        ready(&nodes).await;
        answering(&nodes);
        let (before, _, _) = read_all(&nodes[0], None, 1000).await;
        assert_eq!(before.len(), 0);
        let control = control_of(&nodes);
        let at = "https://hooks.example.org/in";
        let mut hooks = Vec::new();
        for (tenant, events, mode) in [
            (1, 0, Endpoint::Flapping),
            (1, 1, Endpoint::Slow),
            (1, 0, Endpoint::Healthy),
            (2, 0, Endpoint::Failing),
        ] {
            let id = control.hook_new(tenant, at, events).await.expect("new").id;
            sim.modes.borrow_mut().insert(id, mode);
            hooks.push(id);
        }
        let tasks = sim_hooks(&sim, &nodes);
        for &hook in &hooks[..3] {
            cursors_everywhere(&nodes, hook, true).await;
        }
        accept_some(&nodes, 0, first_count).await;
        sleep(cut).await;
        drop(tasks);
        (hooks, nodes[0].requests().today())
    });
    cluster.stop();
    let [all, some, late, other] = hooks[..] else {
        panic!("four hooks");
    };
    let driver = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    let cluster = started_behind(&driver, second_cores, 8 * DAY_MS as u64);
    let nodes = cluster.nodes.clone();
    let total = cluster.run(webhooks_second(
        Rc::clone(&sim),
        nodes,
        seed,
        [all, some, late, other],
        first_count,
    ));
    cluster.stop();
    let undelivered = u64::try_from(missing(&sim, late, &total, None)).expect("fits");
    assert_ne!(undelivered, 0, "seed {seed}");
    let wall = Config::default().wall_start_ms;
    let behind = wall - (u64::from(day + 7) * DAY_MS as u64 - 60_000);
    let driver = Rc::new(SimDriver::with_disk(
        seed + 2,
        Config::default(),
        driver.crash(),
    ));
    let cluster = started_behind(&driver, first_cores, behind);
    let nodes = cluster.nodes.clone();
    cluster.run(webhooks_third(
        Rc::clone(&sim),
        nodes,
        seed,
        [all, late],
        first_count,
        day,
        (total.len(), undelivered),
    ));
    cluster.stop();
}

#[test]
fn webhooks_reach_every_endpoint_through_crashes_core_changes_deletes_and_retention() {
    check(0..4, webhooks_sim);
}

async fn webhooks_second(
    sim: Rc<Sim>,
    nodes: Vec<Node<Idle>>,
    seed: u64,
    [all, some, late, other]: [u32; 4],
    first_count: usize,
) -> Vec<Given> {
    wait_for(&nodes, 1, 1, State::Active).await;
    answering(&nodes);
    let control = control_of(&nodes).clone();
    let tasks = sim_hooks(&sim, &nodes);
    accept_some(&nodes, first_count, 4).await;
    assert!(cursors_of(&nodes, 2, other).await > 0, "seed {seed}");
    control.delete_tenant(2).await.expect("delete");
    wait_for(&nodes, 2, 1, State::Deleted).await;
    while control.write(tenant(2, 2, State::Active)).await.is_err() {
        sleep(Duration::from_millis(50)).await;
    }
    for _ in 0..200 {
        if cursors_of(&nodes, 2, other).await == 0 {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(cursors_of(&nodes, 2, other).await, 0, "seed {seed}");
    for node in &nodes {
        assert_eq!(node.hooks(2), Vec::new(), "seed {seed}");
    }
    let fresh = control
        .hook_new(2, "https://hooks.example.org/in", 0)
        .await
        .expect("new")
        .id;
    assert!(fresh > other, "seed {seed}");
    drained(&nodes).await;
    sim.modes.borrow_mut().insert(all, Endpoint::Healthy);
    delivered_all(&sim, &nodes, all, None).await;
    delivered_all(&sim, &nodes, some, Some(EventKind::Delivered)).await;
    let off = HookChange {
        enabled: Some(false),
        ..HookChange::default()
    };
    control.hook_change(1, late, off).await.expect("pause");
    accept_some(&nodes, first_count + 4, 3).await;
    drained(&nodes).await;
    delivered_all(&sim, &nodes, all, None).await;
    sleep(Duration::from_secs(3)).await;
    let (whole, _, _) = read_all(&nodes[0], None, 1000).await;
    drop(tasks);
    whole
}

async fn webhooks_third(
    sim: Rc<Sim>,
    nodes: Vec<Node<Idle>>,
    seed: u64,
    [all, late]: [u32; 2],
    first_count: usize,
    day: u32,
    (total, undelivered): (usize, u64),
) {
    wait_for(&nodes, 1, 1, State::Active).await;
    answering(&nodes);
    let control = control_of(&nodes).clone();
    let tasks = sim_hooks(&sim, &nodes);
    sleep(Duration::from_secs(120)).await;
    assert_eq!(nodes[0].requests().today(), day + 7, "seed {seed}");
    assert_eq!(lost_everywhere(&nodes, all).await, 0, "seed {seed}");
    let lost = lost_everywhere(&nodes, late).await;
    let total = u64::try_from(total).expect("fits");
    assert!(
        lost >= undelivered && lost <= total,
        "seed {seed}: lost {lost}, undelivered {undelivered}, total {total}"
    );
    let on = HookChange {
        enabled: Some(true),
        ..HookChange::default()
    };
    control.hook_change(1, late, on).await.expect("resume");
    let (before, _, _) = read_all(&nodes[0], None, 1000).await;
    accept_some(&nodes, first_count + 7, 2).await;
    drained(&nodes).await;
    let (whole, _, _) = read_all(&nodes[0], None, 1000).await;
    let fresh: Vec<Given> = whole.into_iter().filter(|e| !before.contains(e)).collect();
    assert_ne!(fresh.len(), 0, "seed {seed}");
    for hook in [late, all] {
        for _ in 0..600 {
            let got: BTreeSet<_> = first_seen(&sim, hook)
                .iter()
                .map(|e| (e.0.bytes(), e.1, e.2 as u8))
                .collect();
            if fresh
                .iter()
                .all(|e| got.contains(&(e.0.bytes(), e.1, e.3 as u8)))
            {
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }
    }
    for hook in [late, all] {
        let got: BTreeSet<_> = first_seen(&sim, hook)
            .iter()
            .map(|e| (e.0.bytes(), e.1, e.2 as u8))
            .collect();
        for e in &fresh {
            assert!(
                got.contains(&(e.0.bytes(), e.1, e.3 as u8)),
                "seed {seed}: hook {hook} missed {e:?}"
            );
        }
    }
    for _ in 0..60 {
        if lost_everywhere(&nodes, late).await == 0 {
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(lost_everywhere(&nodes, late).await, 0, "seed {seed}");
    assert_eq!(
        sim.lost.borrow().get(&late).copied(),
        Some(lost),
        "seed {seed}"
    );
    assert_eq!(
        sim.lost.borrow().get(&all).copied().unwrap_or(0),
        0,
        "seed {seed}"
    );
    drop(tasks);
}
