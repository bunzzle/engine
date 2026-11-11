use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Duration;

use control::{
    Created, Dkim, Error, KIND_TENANT, KeyError, KeySource, Limits, Loaded, Object, Pool, Ready,
    Snapshot, State, Table, Tenant, Update, Writer,
};
use crypto::{DkimAlg, Secret, Tenant as Root, TenantKeys};
use rt::sim::{Config, Disk, SimDriver, check};
use rt::{JoinHandle, Runtime, spawn, timeout};
use store::{
    Batch, Change, Changes, Client, DataFile, Delivery, HEAD_ITEM, Keeper, Op, Options, SLOT_SIZE,
    Setup, Shards, boot, control_key,
};

const PATH: &str = "/data/store";
const BUDGET: usize = 64 * 1024;

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 32,
    shards: 4,
};

#[derive(Default)]
struct Toy {
    unknown: BTreeSet<u32>,
    asked: Cell<u32>,
}

fn keys(tenant: u32, generation: u32) -> TenantKeys {
    TenantKeys::derive(tenant, generation, &Root::new(&Secret::new([1; 32])), 1)
}

impl KeySource for Toy {
    fn get(&self, _: u32, _: u32) -> Option<TenantKeys> {
        None
    }

    fn create(&self, _: u32, _: u32) -> Created<'_> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn ready(&self, tenant: u32, generation: u32) -> Ready<'_> {
        self.asked.set(self.asked.get() + 1);
        let answer = if self.unknown.contains(&tenant) {
            Err(KeyError::Unknown)
        } else {
            Ok(keys(tenant, generation))
        };
        Box::pin(std::future::ready(answer))
    }
}

struct Node {
    changes: Changes,
    owner: JoinHandle<Keeper>,
    committer: JoinHandle<()>,
    client: Client,
}

impl Node {
    async fn open(budget: usize) -> (Self, Loaded, Snapshot) {
        Self::open_with(budget, &Toy::default()).await
    }

    async fn open_with(budget: usize, source: &Toy) -> (Self, Loaded, Snapshot) {
        let setup = Setup {
            cores: 1,
            credits: 4,
            reserve: 0,
            flush: 0,
        };
        let booted = boot(PATH, setup).await.expect("boot");
        let committer = spawn(async move { drop(booted.committer.run().await) });
        let core = booted
            .starts
            .into_iter()
            .next()
            .expect("core")
            .open()
            .await
            .expect("open");
        let (mut loaded, mut snapshot) = Writer::load(&core.keeper, 0, budget).expect("load");
        loaded
            .open(&mut snapshot, &core.file, source)
            .await
            .expect("open");
        let (owner, changes) = Shards::new(core);
        let node = Self {
            changes,
            owner: spawn(owner.run()),
            committer,
            client: booted.client,
        };
        (node, loaded, snapshot)
    }

    async fn close(self) {
        self.changes.close();
        drop(self.owner.await);
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

fn on<F>(
    seed: u64,
    config: Config,
    disk: Disk,
    work: impl FnOnce() -> F,
) -> (F::Output, Rc<SimDriver>)
where
    F: Future + 'static,
    F::Output: 'static,
{
    let driver = Rc::new(SimDriver::with_disk(seed, config, disk));
    let output = Runtime::new(driver.clone()).block_on(work());
    (output, driver)
}

fn tenant(id: u32, state: State) -> Object {
    Object::Tenant(Tenant {
        id,
        generation: 1,
        state,
        default_pool: 1,
        pools: vec![1, 2],
        limits: Limits {
            rate: 100,
            burst: 10,
            queued: 10_000,
        },
    })
}

fn pool(id: u32) -> Object {
    Object::Pool(Pool {
        id,
        addresses: vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 5)],
    })
}

fn table(snapshot: Snapshot) -> Table {
    let mut table = Table::default();
    table.load(snapshot);
    table
}

fn dkim(id: u32, tenant: u32) -> Object {
    Object::Dkim(Dkim {
        id,
        tenant,
        generation: 1,
        alg: DkimAlg::Ed25519Sha256,
        domain: "example.org".into(),
        selector: "s1".into(),
        public: vec![7; 32],
        blob: vec![9; 80],
    })
}

#[test]
fn dkim_ids_are_never_given_twice_across_restarts() {
    let ((), driver) = on(1, Config::default(), created(1), || async {
        let (node, loaded, _) = Node::open(BUDGET).await;
        let mut writer = loaded.writer(node.changes.clone());
        assert_eq!(writer.reserve_dkim().await.expect("reserve"), 1);
        assert_eq!(writer.reserve_dkim().await.expect("reserve"), 2);
        writer
            .write_sealed(dkim(1, 4), &keys(4, 1))
            .await
            .expect("write");
        node.close().await;
    });
    let ((), driver) = on(2, Config::default(), driver.crash(), || async {
        let (node, loaded, snapshot) = Node::open(BUDGET).await;
        let table = table(snapshot);
        assert_eq!(table.dkim(4, 1).map(|d| d.selector.as_ref()), Some("s1"));
        assert!(table.dkim(5, 1).is_none());
        assert_eq!(table.dkims(4).count(), 1);
        let mut writer = loaded.writer(node.changes.clone());
        assert_eq!(writer.dkim_next(), 3);
        writer
            .write_sealed(dkim(10, 4), &keys(4, 1))
            .await
            .expect("write");
        assert_eq!(writer.dkim_next(), 11);
        node.close().await;
    });
    on(3, Config::default(), driver.crash(), || async {
        let (node, loaded, _) = Node::open(BUDGET).await;
        let mut writer = loaded.writer(node.changes.clone());
        assert_eq!(writer.skipped(), 0);
        assert_eq!(writer.reserve_dkim().await.expect("reserve"), 11);
        node.close().await;
    });
}

#[test]
fn dkim_records_open_only_with_their_tenant_keys() {
    let ((), driver) = on(1, Config::default(), created(1), || async {
        let (node, loaded, _) = Node::open(BUDGET).await;
        let mut writer = loaded.writer(node.changes.clone());
        assert!(matches!(
            writer.write(dkim(1, 4)).await,
            Err(Error::Invalid("kind"))
        ));
        assert!(matches!(
            writer.write_sealed(pool(1), &keys(4, 1)).await,
            Err(Error::Invalid("kind"))
        ));
        writer.write(tenant(4, State::Active)).await.expect("write");
        writer.write(tenant(5, State::Active)).await.expect("write");
        writer.write(tenant(6, State::Active)).await.expect("write");
        for (id, owner) in [(1, 4), (2, 5), (3, 6)] {
            writer
                .write_sealed(dkim(id, owner), &keys(owner, 1))
                .await
                .expect("write");
        }
        assert!(matches!(
            writer.write_sealed(dkim(4, 4), &keys(5, 1)).await,
            Err(Error::Invalid("seal"))
        ));
        writer
            .write(Object::Tenant(Tenant {
                state: State::Deleted,
                ..match tenant(6, State::Active) {
                    Object::Tenant(t) => t,
                    _ => unreachable!(),
                }
            }))
            .await
            .expect("write");
        node.close().await;
    });
    on(2, Config::default(), driver.crash(), || async {
        let source = Toy {
            unknown: BTreeSet::from([5]),
            ..Toy::default()
        };
        let (node, loaded, snapshot) = Node::open_with(BUDGET, &source).await;
        assert_eq!(snapshot.version, 7);
        let table = table(snapshot);
        assert_eq!(
            table.dkim(4, 1).map(|d| d.domain.as_ref()),
            Some("example.org")
        );
        assert!(table.dkim(4, 4).is_none());
        assert!(table.dkim(5, 2).is_none());
        assert!(table.dkim(6, 3).is_none());
        assert_eq!(source.asked.get(), 2);
        let mut writer = loaded.writer(node.changes.clone());
        assert_eq!(writer.skipped(), 2);
        assert_eq!(writer.dkim_next(), 4);
        assert_eq!(writer.write(pool(1)).await.expect("write").version, 8);
        node.close().await;
    });
}

#[test]
fn writes_take_versions_in_order_and_load_again() {
    let (written, driver) = on(1, Config::default(), created(1), || async {
        let (node, loaded, snapshot) = Node::open(BUDGET).await;
        assert_eq!(snapshot, Snapshot::default());
        let mut writer = loaded.writer(node.changes.clone());
        let mut written = Vec::new();
        for object in [
            tenant(1, State::Active),
            pool(1),
            tenant(2, State::Active),
            tenant(1, State::Suspended),
        ] {
            written.push(writer.write(object).await.expect("write"));
        }
        node.close().await;
        written
    });
    let versions: Vec<u64> = written.iter().map(|u| u.version).collect();
    assert_eq!(versions, vec![1, 2, 3, 4]);
    on(2, Config::default(), driver.crash(), || async {
        let (node, loaded, snapshot) = Node::open(BUDGET).await;
        assert_eq!(snapshot.version, 4);
        assert_eq!(snapshot.objects.len(), 3);
        let table = table(snapshot);
        assert_eq!(table.tenant(1).map(|t| t.state), Some(State::Suspended));
        assert_eq!(table.tenant(2).map(|t| t.state), Some(State::Active));
        assert!(table.pool(1).is_some());
        let mut writer = loaded.writer(node.changes.clone());
        assert_eq!(writer.skipped(), 0);
        let next = writer.write(pool(2)).await.expect("write");
        assert_eq!(next.version, 5);
        node.close().await;
    });
}

#[test]
fn refused_writes_take_no_version() {
    on(1, Config::default(), created(1), || async {
        let budget = 3 * 160;
        let (node, loaded, _) = Node::open(budget).await;
        let mut writer = loaded.writer(node.changes.clone());
        writer.write(tenant(1, State::Active)).await.expect("first");
        assert!(matches!(
            writer.write(tenant(0, State::Active)).await,
            Err(Error::Invalid("tenant id"))
        ));
        writer
            .write(tenant(2, State::Active))
            .await
            .expect("second");
        let used = writer.used();
        assert!(matches!(
            writer
                .write(Object::Pool(Pool {
                    id: 1,
                    addresses: vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), 1); 20],
                }))
                .await,
            Err(Error::Full)
        ));
        assert_eq!(writer.used(), used);
        let replaced = writer
            .write(tenant(1, State::Suspended))
            .await
            .expect("same size replaces");
        assert_eq!(replaced.version, 3);
        assert_eq!(writer.used(), used);
        node.close().await;
    });
}

#[test]
fn damaged_or_misplaced_records_are_skipped_at_start() {
    let ((), driver) = on(1, Config::default(), created(1), || async {
        let (node, loaded, _) = Node::open(BUDGET).await;
        let mut writer = loaded.writer(node.changes.clone());
        writer.write(tenant(1, State::Active)).await.expect("write");
        let moved = Update {
            version: 9,
            object: tenant(6, State::Active),
        }
        .encode();
        for (id, tenant, clear) in [(5, 5, vec![7; 48]), (6, 5, moved.clone()), (7, 7, moved)] {
            let batch = Batch {
                shard: 0,
                message: control_key(KIND_TENANT, id),
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
                    sealed: Vec::new(),
                }],
            };
            node.changes.apply(batch).await.expect("raw record");
        }
        node.close().await;
    });
    on(2, Config::default(), driver.crash(), || async {
        let (node, loaded, snapshot) = Node::open(BUDGET).await;
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.objects, vec![tenant(1, State::Active)]);
        assert_eq!(loaded.writer(node.changes.clone()).skipped(), 3);
        node.close().await;
    });
}

const WRITES: u32 = 30;

fn writes(seed: u64, halt_after: Option<u64>) -> (Vec<u32>, Rc<SimDriver>) {
    let config = Config {
        halt_after,
        ..Config::default()
    };
    let acked = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&acked);
    let ((), driver) = on(seed, config, created(seed), move || async move {
        let work = async {
            let (node, loaded, _) = Node::open(BUDGET).await;
            let mut writer = loaded.writer(node.changes.clone());
            for id in 1..=WRITES {
                let object = if id % 3 == 0 {
                    pool(id)
                } else {
                    tenant(id, State::Active)
                };
                let update = writer.write(object).await.expect("write");
                assert_eq!(update.version, u64::from(id));
                log.borrow_mut().push(id);
            }
            node.close().await;
        };
        let _ = timeout(Duration::from_secs(60), work).await;
    });
    let acked = acked.borrow().clone();
    (acked, driver)
}

fn crash_at(seed: u64, point: u64) {
    let (acked, driver) = writes(seed, Some(point));
    assert!(driver.is_halted(), "crash point {point} not reached");
    on(
        seed + 1,
        Config::default(),
        driver.crash(),
        move || async move {
            let (node, _, snapshot) = Node::open(BUDGET).await;
            let durable = u32::try_from(snapshot.version).expect("fits");
            assert!(
                durable >= u32::try_from(acked.len()).expect("fits"),
                "acknowledged write lost"
            );
            assert!(durable <= WRITES);
            let mut ids: Vec<u32> = snapshot.objects.iter().map(Object::id).collect();
            ids.sort_unstable();
            assert_eq!(
                ids,
                (1..=durable).collect::<Vec<_>>(),
                "durable writes are a prefix"
            );
            node.close().await;
        },
    );
}

#[test]
fn acknowledged_writes_survive_a_crash_at_every_disk_operation() {
    let only = env::var("SIM_CRASH_AT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    check(0..2, |seed| {
        let (acked, driver) = writes(seed, None);
        assert_eq!(acked.len(), WRITES as usize);
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
