use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

use control::{Label, Naming, Object, Pool, Sealer, State, Table, Tenant};
use index::{Entry, Op};
use rt::sim::{Config, Disk, Machine, SimDriver, Stalls};
use rt::{JoinHandle, Runtime, sleep};
use sched::{
    Answered, Attempt, Begun, Clock, DAY, Draft, Hash, Hasher, KIND_REQUEST, KIND_SUPPRESS, Meshes,
    Node, Parts, Reason, Refusal, Running, SHAPE, Settings, Suppression, Ticket, Transport,
    normalize, punycode, retain, retain_request,
};
use spool::{Body, Head, HeadClear, Message, MessageId, SLICE, Slice};
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
    started_behind(driver, cores, 0)
}

fn started_behind(driver: &Rc<SimDriver>, cores: u16, behind: u64) -> Cluster {
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
                clock: Clock::at(rt::wall_ms().saturating_sub(behind), rt::now()),
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
            sealed: vec![1; 64],
        },
        body: Body::Inline(vec![2; 300]),
        slices,
    }
}

fn owner<'a>(nodes: &'a [Node<Idle>], tenant: u32, key: &[u8]) -> (&'a Node<Idle>, u16) {
    let shard = nodes[0].request_shard(tenant, key);
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
        let (node, shard) = owner(&nodes, 1, key);
        let ticket = fresh(node, 1, key, [1; 16]).await;
        let id = accept(node, ticket, shard, "a@example.org").await;
        assert_eq!(replayed(node, 1, key, [1; 16]).await, vec![id]);
        assert_eq!(
            node.begin(1, key, [2; 16]).await.err(),
            Some(Refusal::Conflict)
        );
        let (other, _) = owner(&nodes, 2, key);
        drop(fresh(other, 2, key, [1; 16]).await);
        let (elsewhere, _) = owner(&nodes, 1, b"order-2");
        let wrong = nodes
            .iter()
            .find(|n| !std::ptr::eq(*n, elsewhere))
            .expect("another core");
        assert_eq!(
            wrong.begin(1, b"order-2", [1; 16]).await.err(),
            Some(Refusal::Message)
        );
        let (node, shard) = owner(&nodes, 1, b"order-3");
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
        let (node, shard) = owner(&nodes, 1, key);
        let first = fresh(node, 1, key, [5; 16]).await;
        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let node = node.clone();
                rt::spawn(async move { node.begin(1, b"same", [5; 16]).await })
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

        let racers: Vec<_> = (0..3)
            .map(|n| {
                let node = owner(&nodes, 1, b"race").0.clone();
                rt::spawn(async move {
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
        let (node, shard) = owner(&nodes, 1, key);
        let first = fresh(node, 1, key, [7; 16]).await;
        let waiter = {
            let node = node.clone();
            rt::spawn(async move { node.begin(1, b"failing", [7; 16]).await })
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
        let (node, shard) = owner(&nodes, 1, early);
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
        let (late_node, late_shard) = owner(&nodes, 1, late);
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
        let (node, shard) = owner(&nodes, 1, key);
        let ticket = fresh(node, 1, key, [4; 16]).await;
        accept(node, ticket, shard, "f@example.org").await;
        configure(&nodes, vec![tenant(1, 2, State::Active)]).await;
        wait_for(&nodes, 1, 2, State::Active).await;
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
            let (node, shard) = owner(&nodes, 1, &key);
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
            let (node, _) = owner(&nodes, 1, key);
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
