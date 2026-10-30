use std::cell::RefCell;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Duration;

use control::{
    Error, KIND_TENANT, Limits, Loaded, Object, Pool, Snapshot, State, Table, Tenant, Update,
    Writer,
};
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

struct Node {
    changes: Changes,
    owner: JoinHandle<Keeper>,
    committer: JoinHandle<()>,
    client: Client,
}

impl Node {
    async fn open(budget: usize) -> (Self, Loaded, Snapshot) {
        let setup = Setup {
            cores: 1,
            credits: 4,
            reserve: 0,
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
        let (loaded, snapshot) = Writer::load(&core.keeper, 0, budget).expect("load");
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
