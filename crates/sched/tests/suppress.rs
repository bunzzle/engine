use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

use control::{Label, Naming, Object, Pool, Sealer, State, Table, Tenant};
use index::{Entry, Op};
use rt::sim::{Config, Disk, Machine, SimDriver, Stalls};
use rt::{JoinHandle, Runtime, sleep};
use sched::{
    Answered, Attempt, Clock, Hash, Hasher, KIND_SUPPRESS, Meshes, Node, Parts, Reason, Refusal,
    Running, SHAPE, Settings, Suppression, Transport, normalize, punycode, retain,
};
use store::{Client, Committer, DataFile, Options, SLOT_SIZE, Setup, boot};

const PATH: &str = "/data/store";
const SHARDS: u16 = 8;

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 96,
    shards: SHARDS as u32,
};

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

struct Keyed;

impl Hasher for Keyed {
    fn hash(&self, tenant: u32, data: &[u8]) -> Hash {
        index::siphash128(&[3; 16], &[&tenant.to_le_bytes()[..], data].concat())
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
            recipients: 100,
            inline: 2048,
            body: 64 * 1024,
        },
        naming: Naming {
            key: *b"naming key 16 by",
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
    let machine = Machine::new(Rc::clone(driver), usize::from(cores) + 1, Stalls::default());
    let setup = Setup {
        cores,
        credits: 4,
        reserve: 4,
        flush: 1,
    };
    let booted = machine.block_on(0, boot(PATH, setup)).expect("boot");
    let committer = machine.spawn_on(0, booted.committer.run());
    let meshes = std::sync::Arc::new(Meshes::new(cores));
    let mut tasks = Vec::new();
    for start in booted.starts {
        let index = start.index();
        let links = meshes.take(index).expect("links");
        tasks.push(machine.spawn_on(usize::from(index) + 1, async move {
            let core = start.open().await.expect("open");
            let parts = Parts {
                sealer: Rc::new(Toy),
                hasher: Rc::new(Keyed),
                transport: Idle,
                clock: Clock::start(),
            };
            Node::start(core, links, settings(), parts)
                .await
                .expect("start")
        }));
    }
    let started = machine.block_on(0, async move {
        let mut started = Vec::new();
        for task in tasks {
            started.push(task.await);
        }
        started
    });
    let (nodes, runnings) = started.into_iter().unzip();
    Cluster {
        machine,
        nodes,
        runnings,
        client: booted.client,
        committer,
    }
}

async fn configure(nodes: &[Node<Idle>], objects: Vec<Object>) {
    let control = nodes.iter().find(|n| n.controls()).expect("control core");
    for object in objects {
        control.write(object).await.expect("write");
    }
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
        addresses: vec![(std::net::IpAddr::from([192, 0, 2, 1]), 1)],
    });
    configure(
        nodes,
        vec![
            pool,
            tenant(1, 1, State::Active),
            tenant(2, 1, State::Active),
        ],
    )
    .await;
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
                &["brief@example.org", "kept@example.org", "free@example.org"],
            )
            .await;
        assert_eq!(checked, Ok(vec![true, true, false]));
        let found = lists.get(1, "brief@example.org").await.expect("get");
        assert_eq!(found.and_then(|s| s.until), Some(now + 1_000));
        sleep(Duration::from_millis(1_500)).await;
        let checked = lists
            .check(1, &["brief@example.org", "kept@example.org"])
            .await;
        assert_eq!(checked, Ok(vec![false, true]));
        let page = lists.list(1, None, 10).await.expect("list");
        let listed: Vec<&str> = page.listed.iter().map(|l| l.address.as_str()).collect();
        assert_eq!(listed, vec!["kept@example.org"]);

        configure(&nodes, vec![tenant(1, 2, State::Active)]).await;
        wait_for(&nodes, 1, 2, State::Active).await;
        let checked = lists.check(1, &["kept@example.org"]).await;
        assert_eq!(checked, Ok(vec![false]));
        let page = lists.list(1, None, 10).await.expect("list");
        assert_eq!(page.listed, Vec::new());
        lists
            .add(1, "kept@example.org", Reason::Manual, None)
            .await
            .expect("add again");
        let checked = lists.check(1, &["kept@example.org"]).await;
        assert_eq!(checked, Ok(vec![true]));

        configure(&nodes, vec![tenant(2, 1, State::Suspended)]).await;
        wait_for(&nodes, 2, 1, State::Suspended).await;
        assert_eq!(
            lists.check(2, &["kept@example.org"]).await,
            Err(Refusal::Tenant)
        );
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
                    let hash = lists.hash(1, &listed.address).expect("hash");
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
