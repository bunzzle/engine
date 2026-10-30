use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use control::{
    Cache, Call, Error, KIND_QUEUE, Label, LoadedQueues, Name, Naming, Queue, Queues, Sealer,
    Tenancy, domain_ok, naming_shard, queue_shard, siphash,
};
use rt::sim::{Config, Disk, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Mesh, Runtime, timeout};
use store::{
    Batch, Change, Changes, Client, DataFile, Delivery, HEAD_ITEM, Keeper, Op, Options, SLOT_SIZE,
    Setup, Shards, boot, control_key,
};

const PATH: &str = "/data/store";
const SHARDS: u32 = 8;
const KEY: [u8; 16] = *b"naming key 16 by";

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 64,
    shards: SHARDS,
};

const NAMING: Naming = Naming {
    key: KEY,
    shards: SHARDS,
    cache: 64,
};

const DOMAINS: [&str; 12] = [
    "example.org",
    "example.net",
    "mail.example.com",
    "a.example",
    "b.example",
    "c.example",
    "xn--bcher-kva.example",
    "d-1.example",
    "e2.example",
    "f.g.h.example",
    "test",
    "z.example",
];

#[derive(Default)]
struct Toy {
    gone: BTreeSet<u32>,
}

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
        if self.gone.contains(&label.tenant) {
            return None;
        }
        let head = label_bytes(label);
        let rest = sealed.strip_prefix(head.as_slice())?;
        Some(rest.iter().map(|b| b ^ 0x5a).collect())
    }
}

fn name(tenant: u32, generation: u32, pool: u32, domain: &str) -> Name {
    Name {
        tenant,
        domain: domain.into(),
        generation,
        pool,
    }
}

#[test]
fn siphash_matches_the_reference() {
    let key: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).expect("small"));
    assert_eq!(siphash(&key, &[]), 0x726f_db47_dd0e_0e31);
    assert_eq!(siphash(&key, &[0]), 0x74f8_39c5_93dc_67fd);
    let k0 = u64::from_le_bytes(key[..8].try_into().expect("8"));
    let k1 = u64::from_le_bytes(key[8..].try_into().expect("8"));
    for len in 0..64 {
        let data: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i * 7 % 256).expect("byte"))
            .collect();
        #[allow(deprecated)]
        let mut reference = std::hash::SipHasher::new_with_keys(k0, k1);
        std::hash::Hasher::write(&mut reference, &data);
        assert_eq!(
            siphash(&key, &data),
            std::hash::Hasher::finish(&reference),
            "length {len}"
        );
    }
}

#[test]
fn domains_are_lowercase_a_labels() {
    for good in DOMAINS {
        assert!(domain_ok(good), "{good}");
    }
    let long = format!("{}.example", "a".repeat(64));
    let too_long = ["a"; 128].join(".");
    for bad in [
        "",
        "Example.org",
        "exa mple.org",
        "-a.example",
        "a-.example",
        "a..example",
        "a.example.",
        "bücher.example",
        "a_b.example",
        long.as_str(),
        too_long.as_str(),
    ] {
        assert!(!domain_ok(bad), "{bad}");
    }
    assert!(matches!(
        name(0, 1, 1, "example.org").check(),
        Err(Error::Invalid("tenant id"))
    ));
    assert!(matches!(
        name(1, 1, 1, "Example.org").check(),
        Err(Error::Invalid("domain"))
    ));
}

#[test]
fn queue_records_round_trip_and_refuse_damage() {
    let queue = Queue {
        id: 77,
        name: name(3, 9, 2, "example.org"),
        draining: true,
    };
    let clear = queue.encode();
    assert_eq!(Queue::decode(&clear, "example.org".into()), Some(queue));
    for at in [0, 1, 2, 3, 20, 23] {
        let mut damaged = clear.clone();
        damaged[at] ^= 0x10;
        assert_eq!(Queue::decode(&damaged, "example.org".into()), None, "{at}");
    }
    assert_eq!(Queue::decode(&clear[..23], "example.org".into()), None);
    assert_eq!(Queue::decode(&clear, "Example.org".into()), None);
}

#[test]
fn cache_evicts_unused_names_first_and_forgets_by_domain() {
    let mut cache = Cache::new(3);
    let a = name(1, 1, 1, "a.example");
    let b = name(1, 1, 2, "a.example");
    let c = name(2, 1, 1, "a.example");
    let d = name(1, 1, 1, "b.example");
    cache.put(a.clone(), 1);
    cache.put(b.clone(), 2);
    cache.put(c.clone(), 3);
    assert_eq!(cache.get(&a), Some(1));
    cache.put(d.clone(), 4);
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.get(&b), None);
    assert_eq!(cache.get(&a), Some(1));
    assert_eq!(cache.get(&d), Some(4));
    assert_eq!(cache.stats().evicted, 1);
    let mut cache = Cache::new(8);
    for (n, id) in [(&a, 1), (&b, 2), (&c, 3), (&d, 4)] {
        cache.put(n.clone(), id);
    }
    assert_eq!(cache.forget(1, "a.example"), 2);
    assert_eq!(cache.get(&a), None);
    assert_eq!(cache.get(&b), None);
    assert_eq!(cache.get(&c), Some(3));
    assert_eq!(cache.get(&d), Some(4));
    assert_eq!(cache.len(), 2);
}

struct Node {
    queues: Vec<Queues>,
    meshes: Vec<JoinHandle<()>>,
    owners: Vec<JoinHandle<Keeper>>,
    changes: Vec<Changes>,
    committer: JoinHandle<()>,
    client: Client,
    skipped: u64,
    loaded: usize,
}

impl Node {
    fn start(machine: &Machine, cores: u16, sealer: &Rc<Toy>) -> Option<Self> {
        let setup = Setup {
            cores,
            credits: 4,
            reserve: 0,
        };
        let booted = machine
            .block_on(0, async move {
                timeout(Duration::from_secs(60), boot(PATH, setup)).await
            })
            .ok()?
            .ok()?;
        let committer = machine.spawn_on(0, async move { drop(booted.committer.run().await) });
        let mesh = Arc::new(Mesh::<Call>::new(cores));
        let mut node = Self {
            queues: Vec::new(),
            meshes: Vec::new(),
            owners: Vec::new(),
            changes: Vec::new(),
            committer,
            client: booted.client,
            skipped: 0,
            loaded: 0,
        };
        for start in booted.starts {
            let index = start.index();
            let at = usize::from(index) + 1;
            let opener = Rc::clone(sealer);
            let (loaded, core): (LoadedQueues, _) = machine.block_on(at, async move {
                let core = timeout(Duration::from_secs(60), start.open())
                    .await
                    .ok()?
                    .ok()?;
                let loaded = Queues::load(&core, NAMING, opener.as_ref()).await.ok()?;
                Some((loaded, core))
            })?;
            node.skipped += loaded.skipped();
            node.loaded += loaded.queues();
            let (owner, changes) = Shards::new(core);
            node.owners.push(machine.spawn_on(at, owner.run()));
            node.changes.push(changes.clone());
            let ends = mesh.take(index).expect("ends");
            let sealer: Rc<dyn Sealer> = Rc::clone(sealer) as Rc<dyn Sealer>;
            let (queues, done) =
                machine.block_on(at, async move { loaded.start(ends, changes, sealer) });
            node.queues.push(queues);
            node.meshes.push(done);
        }
        Some(node)
    }

    async fn stop(self) {
        for queues in &self.queues {
            queues.close();
        }
        for done in self.meshes {
            done.await;
        }
        for changes in &self.changes {
            changes.close();
        }
        for owner in self.owners {
            drop(owner.await);
        }
        drop(self.queues);
        drop(self.client);
        self.committer.await;
    }
}

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

fn machine(driver: &Rc<SimDriver>, cores: u16) -> Machine {
    let stalls = Stalls {
        per_mille: 50,
        max: Duration::from_millis(5),
    };
    Machine::new(Rc::clone(driver), usize::from(cores) + 1, stalls)
}

fn names(driver: &SimDriver, count: usize) -> Vec<Name> {
    (0..count)
        .map(|_| {
            let tenant = u32::try_from(driver.random() % 3).expect("small") + 1;
            let pool = u32::try_from(driver.random() % 2).expect("small") + 1;
            let domain = DOMAINS[usize::try_from(driver.random() % 12).expect("small")];
            name(tenant, 1, pool, domain)
        })
        .collect()
}

type Answers = Vec<(u16, Name, u32)>;

fn ask_all(machine: &Machine, node: &Node, driver: &Rc<SimDriver>, count: usize) -> Answers {
    let mut tasks = Vec::new();
    for (core, queues) in (0..).zip(&node.queues) {
        let asked = names(driver, count);
        let queues = queues.clone();
        tasks.push(machine.spawn_on(usize::from(core) + 1, async move {
            let mut answers = Vec::new();
            for name in asked {
                let id = queues.name(&name).await.expect("named");
                answers.push((core, name, id));
            }
            answers
        }));
    }
    machine.block_on(0, async move {
        let mut answers = Vec::new();
        for task in tasks {
            answers.extend(task.await);
        }
        answers
    })
}

fn one_id_per_name(answers: &Answers) -> BTreeMap<Name, u32> {
    let mut by_name = BTreeMap::new();
    let mut by_id = BTreeMap::new();
    for (_, name, id) in answers {
        assert_eq!(*by_name.entry(name.clone()).or_insert(*id), *id, "{name:?}");
        assert_eq!(*by_id.entry(*id).or_insert(name.clone()), *name, "id {id}");
    }
    by_name
}

fn check_owners(node: &Node, cores: u16, by_name: &BTreeMap<Name, u32>) {
    for (name, &id) in by_name {
        let shard = naming_shard(&KEY, name.tenant, &name.domain, SHARDS);
        assert_eq!(
            queue_shard(id, SHARDS),
            shard,
            "id {id} off its naming shard"
        );
        let owner = &node.queues[usize::from(shard % cores)];
        assert_eq!(owner.owned(name), Some(id));
        assert_eq!(owner.holder(id), Some((name.tenant, name.generation)));
        for (core, other) in (0..).zip(&node.queues) {
            if core != shard % cores {
                assert_eq!(other.holder(id), None);
            }
        }
    }
}

fn naming(seed: u64) {
    let cores: u16 = if seed.is_multiple_of(2) { 2 } else { 4 };
    let sealer = Rc::new(Toy::default());
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let machine = machine(&driver, cores);
    let node = Node::start(&machine, cores, &sealer).expect("start");
    let answers = ask_all(&machine, &node, &driver, 40);
    let by_name = one_id_per_name(&answers);
    check_owners(&node, cores, &by_name);
    let allocated: u64 = node.queues.iter().map(|q| q.stats().allocated).sum();
    assert_eq!(
        allocated,
        by_name.len() as u64,
        "seed {seed}: joined requests"
    );
    let hits: u64 = node.queues.iter().map(|q| q.stats().cache.hits).sum();
    assert!(hits > 0);
    machine.block_on(0, node.stop());
    let driver = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    let machine = self::machine(&driver, cores);
    let node = Node::start(&machine, cores, &sealer).expect("restart");
    assert_eq!(node.loaded, by_name.len());
    assert_eq!(node.skipped, 0);
    check_owners(&node, cores, &by_name);
    let again = ask_all(&machine, &node, &driver, 40);
    let after = one_id_per_name(&again);
    for (name, id) in &after {
        if let Some(before) = by_name.get(name) {
            assert_eq!(id, before, "seed {seed}: {name:?} renamed after restart");
        } else {
            assert!(!by_name.values().any(|v| v == id), "id {id} reused");
        }
    }
    machine.block_on(0, node.stop());
}

#[test]
fn every_core_gets_one_id_per_name_from_its_naming_shard() {
    check(0..8, naming);
}

#[test]
fn rebind_moves_or_drains_and_survives_a_restart() {
    let cores: u16 = 2;
    let sealer = Rc::new(Toy::default());
    let driver = Rc::new(SimDriver::with_disk(1, Config::default(), created(1)));
    let machine = machine(&driver, cores);
    let node = Node::start(&machine, cores, &sealer).expect("start");
    let moved = name(1, 1, 1, "example.org");
    let drained = name(1, 1, 1, "example.net");
    let target = name(1, 1, 2, "example.net");
    let core_of = |n: &Name| naming_shard(&KEY, n.tenant, &n.domain, SHARDS) % cores;
    let owner_of = |n: &Name| node.queues[usize::from(core_of(n))].clone();
    let peer_of = |n: &Name| node.queues[usize::from(1 - core_of(n))].clone();
    let (m, d, t, before, rebound, renamed, empty) = {
        let (moved, drained, target) = (moved.clone(), drained.clone(), target.clone());
        let (peer, first, second) = (peer_of(&moved), owner_of(&moved), owner_of(&drained));
        let refused = peer_of(&moved);
        machine.block_on(usize::from(1 - core_of(&moved)) + 1, async move {
            let m = peer.name(&moved).await.expect("moved");
            let d = peer.name(&drained).await.expect("drained");
            let t = peer.name(&target).await.expect("target");
            let before = peer.cached();
            assert!(matches!(
                refused.rebind(&moved, 2).await,
                Err(Error::Invalid("core"))
            ));
            let rebound = first.rebind(&moved, 2).await.expect("rebind");
            let drained_into = second.rebind(&drained, 2).await.expect("rebind");
            assert_eq!(drained_into, t);
            let renamed = peer.name(&moved).await.expect("renamed");
            let empty = first.rebind(&name(1, 1, 1, "z.example"), 2).await;
            (m, d, t, before, rebound, renamed, empty.is_err())
        })
    };
    assert_eq!(before, 3);
    assert_eq!(rebound, m);
    assert_ne!(renamed, m, "old name kept after a rebind");
    assert!(empty);
    let moved_to = name(1, 1, 2, "example.org");
    assert_eq!(owner_of(&moved).owned(&moved), Some(renamed));
    assert_eq!(owner_of(&moved).owned(&moved_to), Some(m));
    let entry = owner_of(&drained).entry(d).expect("drained entry");
    assert!(entry.draining);
    assert_eq!(entry.name.pool, 2);
    assert_eq!(owner_of(&drained).owned(&drained), None);
    assert_eq!(owner_of(&drained).owned(&target), Some(t));
    machine.block_on(0, node.stop());
    let driver = Rc::new(SimDriver::with_disk(2, Config::default(), driver.crash()));
    let machine = self::machine(&driver, cores);
    let node = Node::start(&machine, cores, &sealer).expect("restart");
    let owner_of = |n: &Name| node.queues[usize::from(core_of(n))].clone();
    assert_eq!(owner_of(&moved_to).owned(&moved_to), Some(m));
    assert_eq!(owner_of(&moved).owned(&moved), Some(renamed));
    assert_eq!(owner_of(&target).owned(&target), Some(t));
    assert_eq!(owner_of(&drained).owned(&drained), None);
    assert!(owner_of(&drained).entry(d).expect("kept").draining);
    assert_eq!(owner_of(&drained).holder(d), Some((1, 1)));
    machine.block_on(0, node.stop());
}

#[test]
fn records_that_do_not_open_or_decode_are_skipped_at_start() {
    let cores: u16 = 1;
    let sealer = Rc::new(Toy::default());
    let driver = Rc::new(SimDriver::with_disk(1, Config::default(), created(1)));
    let machine = machine(&driver, cores);
    let node = Node::start(&machine, cores, &sealer).expect("start");
    let queues = node.queues[0].clone();
    let changes = node.changes[0].clone();
    let (kept, gone) = machine.block_on(1, async move {
        let kept = queues.name(&name(1, 1, 1, "a.example")).await.expect("a");
        let gone = queues.name(&name(2, 1, 1, "a.example")).await.expect("b");
        let shard = naming_shard(&KEY, 1, "b.example", SHARDS);
        let ids: Vec<u32> = (900..)
            .filter(|&id| queue_shard(id, SHARDS) == shard)
            .take(4)
            .collect();
        let real = |id| Queue {
            id,
            name: name(1, 1, 1, "b.example"),
            draining: false,
        };
        let seal_for = |id| {
            Toy::default().seal(
                &Label {
                    tenant: 1,
                    generation: 1,
                    kind: KIND_QUEUE,
                    id,
                },
                b"b.example",
            )
        };
        for (id, tenant, clear, sealed) in [
            (ids[0], 1, vec![9; 24], seal_for(ids[0])),
            (ids[1], 1, real(ids[1]).encode(), b"not sealed".to_vec()),
            (ids[2], 3, real(ids[2]).encode(), seal_for(ids[2])),
            (ids[3], 1, real(ids[2]).encode(), seal_for(ids[2])),
        ] {
            let batch = Batch {
                shard,
                message: control_key(KIND_QUEUE, id),
                tenant,
                ops: vec![Op {
                    item: HEAD_ITEM,
                    change: Change::Put(Delivery {
                        status: 0,
                        attempts: 0,
                        due: 0,
                    }),
                    clear,
                    bodies: Vec::new(),
                    sealed,
                }],
            };
            changes.apply(batch).await.expect("raw record");
        }
        (kept, gone)
    });
    machine.block_on(0, node.stop());
    let refusing = Rc::new(Toy {
        gone: BTreeSet::from([2]),
    });
    let driver = Rc::new(SimDriver::with_disk(2, Config::default(), driver.crash()));
    let machine = self::machine(&driver, cores);
    let node = Node::start(&machine, cores, &refusing).expect("restart");
    assert_eq!(node.skipped, 5);
    assert_eq!(node.loaded, 1);
    assert!(node.queues[0].entry(kept).is_some());
    assert!(node.queues[0].entry(gone).is_none());
    let queues = node.queues[0].clone();
    let again = machine.block_on(1, async move {
        queues
            .name(&name(2, 1, 1, "a.example"))
            .await
            .expect("again")
    });
    assert_eq!(queue_shard(again, SHARDS), queue_shard(gone, SHARDS));
    assert!(again > gone, "id {again} reused");
    machine.block_on(0, node.stop());
}

const ASKS: usize = 24;

fn asks(seed: u64, halt_after: Option<u64>) -> (Answers, Rc<SimDriver>) {
    let config = Config {
        halt_after,
        ..Config::default()
    };
    let sealer = Rc::new(Toy::default());
    let driver = Rc::new(SimDriver::with_disk(seed, config, created(seed)));
    let machine = machine(&driver, 2);
    let acked = Rc::new(RefCell::new(Vec::new()));
    let Some(node) = Node::start(&machine, 2, &sealer) else {
        return (Vec::new(), driver);
    };
    let mut tasks = Vec::new();
    for (core, queues) in (0..).zip(&node.queues) {
        let wanted = names(&driver, ASKS);
        let queues = queues.clone();
        let log = Rc::clone(&acked);
        tasks.push(machine.spawn_on(usize::from(core) + 1, async move {
            for name in wanted {
                if let Ok(id) = queues.name(&name).await {
                    log.borrow_mut().push((core, name, id));
                }
            }
        }));
    }
    let power = Rc::clone(&driver);
    machine.block_on(0, async move {
        let work = async {
            for task in tasks {
                task.await;
            }
            if !power.is_halted() {
                node.stop().await;
            }
        };
        let _ = timeout(Duration::from_secs(60), work).await;
    });
    let acked = acked.borrow().clone();
    (acked, driver)
}

fn crash_at(seed: u64, point: u64) {
    let (acked, driver) = asks(seed, Some(point));
    assert!(driver.is_halted(), "crash point {point} not reached");
    let named = one_id_per_name(&acked);
    let sealer = Rc::new(Toy::default());
    let driver = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    let machine = machine(&driver, 2);
    let node = Node::start(&machine, 2, &sealer).expect("restart");
    assert_eq!(node.skipped, 0);
    assert!(node.loaded >= named.len(), "acknowledged name lost");
    check_owners(&node, 2, &named);
    machine.block_on(0, node.stop());
}

#[test]
fn acknowledged_names_survive_a_crash_at_every_disk_operation() {
    let only = env::var("SIM_CRASH_AT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    check(0..2, |seed| {
        let (acked, driver) = asks(seed, None);
        assert_eq!(acked.len(), 2 * ASKS);
        let total = driver.disk_ops();
        let points: Vec<u64> = only.map_or_else(|| (1..=total).collect(), |p| vec![p]);
        for point in points {
            if let Err(failure) = panic::catch_unwind(AssertUnwindSafe(|| crash_at(seed, point))) {
                eprintln!("crash point {point} of {total}; replay with SIM_CRASH_AT={point}");
                panic::resume_unwind(failure);
            }
        }
    });
}
