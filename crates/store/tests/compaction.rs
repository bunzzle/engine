use std::cell::RefCell;
use std::env;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, sleep, spawn, timeout};
use store::{
    Change, Changes, Committer, CoreFile, DataFile, Delivery, Error, INDEX_SIZE, Index, Keeper,
    Location, Options, Owner, Record, SLOT_SIZE, Setup, Shards, Usage, boot, load, recover,
};

const PATH: &str = "/data/store";
const SHARDS: u16 = 4;
const ALL: [u16; SHARDS as usize] = [0, 1, 2, 3];
const CORES: u16 = 2;
const HOT: u64 = 4;
const COLD: u64 = 1000;
const MILLION: u32 = 1_000_000;
const HORIZON: Duration = Duration::from_secs(30);

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 48,
    shards: SHARDS as u32,
};

struct Nobody;

impl Owner for Nobody {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        std::future::ready(None)
    }
}

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

fn sealed(key: u64, version: u64) -> Vec<u8> {
    let len = 150 + usize::try_from(key % 50).expect("fits");
    let byte = u8::try_from((key ^ version) % 251).expect("fits");
    vec![byte; len]
}

fn put(key: u64, version: u64) -> Index {
    Index {
        key,
        tenant: 7,
        change: Change::Put(Delivery {
            status: 1,
            attempts: 0,
            due: version,
        }),
    }
}

fn audit(usage: &Usage, keeper: &Keeper) {
    let mut owned = vec![(0u32, 0u64); OPTIONS.region_count as usize];
    for shard in ALL {
        for item in keeper.state(shard).expect("kept").entries().values() {
            let slot = &mut owned[item.location.region as usize];
            slot.0 += 1;
            slot.1 += u64::from(item.location.size);
        }
    }
    for (region, (extents, bytes)) in (0u32..).zip(owned) {
        let count = usage.count(region);
        assert_eq!(
            (count.extents, count.bytes),
            (extents, bytes),
            "region {region}: committer count vs owner maps"
        );
    }
}

async fn contents(file: &CoreFile, keeper: &Keeper) -> usize {
    let mut moved = 0;
    let reader = file.reader();
    for shard in ALL {
        for (&key, item) in keeper.state(shard).expect("kept").entries() {
            let buf = reader
                .read(item.location, item.tenant, &Nobody)
                .await
                .expect("read");
            let record = Record::decode(&buf).expect("record");
            let index = Index::decode(record.payload()).expect("index");
            assert!(
                !matches!(index.change, Change::Delete),
                "key {key} points at a delete"
            );
            moved += usize::from(matches!(index.change, Change::Move { .. }));
            let version = item.delivery.due;
            assert_eq!(
                &record.payload()[INDEX_SIZE..],
                sealed(key, version).as_slice(),
                "key {key} content"
            );
        }
    }
    moved
}

async fn work(changes: Changes, shards: Vec<u16>, steps: u64) -> bool {
    let mut cold = 0;
    for step in 0..steps {
        let shard = shards[usize::try_from(step).expect("fits") % shards.len()];
        let (key, version) = if step % 6 == 5 {
            cold += 1;
            (COLD + cold, 0)
        } else {
            (step % HOT, step)
        };
        match changes
            .change(shard, put(key, version), sealed(key, version))
            .await
        {
            Ok(_) => {}
            Err(Error::Reserve | Error::Full) => sleep(Duration::from_millis(1)).await,
            Err(_) => return false,
        }
    }
    true
}

fn merge(keepers: Vec<Keeper>) -> Keeper {
    let mut all = Keeper::default();
    for keeper in keepers {
        for shard in ALL {
            if let (Some(state), Some(roots)) = (keeper.state(shard), keeper.roots(shard)) {
                all.insert(shard, state.clone(), roots.to_vec());
            }
        }
    }
    all
}

struct Outcome {
    driver: Rc<SimDriver>,
    finished: Option<(Committer, Keeper)>,
}

fn workload(seed: u64, steps: u64, halt_after: Option<u64>, disk: Disk) -> Outcome {
    let config = Config {
        halt_after,
        faults: Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        },
        ..Config::default()
    };
    let driver = Rc::new(SimDriver::with_disk(seed, config, disk));
    let stalls = Stalls {
        per_mille: 50,
        max: Duration::from_millis(1),
    };
    let machine = Machine::new(Rc::clone(&driver), usize::from(CORES) + 1, stalls);
    let setup = Setup {
        cores: CORES,
        credits: 4,
        reserve: 0,
    };
    let none = |driver| Outcome {
        driver,
        finished: None,
    };
    let Ok(Ok(booted)) =
        machine.block_on(0, async move { timeout(HORIZON, boot(PATH, setup)).await })
    else {
        return none(driver);
    };
    let committer = machine.spawn_on(0, booted.committer.run());
    let mut owners: Vec<JoinHandle<Keeper>> = Vec::new();
    let mut workers: Vec<JoinHandle<bool>> = Vec::new();
    let mut closers = Vec::new();
    for start in booted.starts {
        let core = usize::from(start.index()) + 1;
        let opened = machine.block_on(core, async move { timeout(HORIZON, start.open()).await });
        let Ok(Ok(opened)) = opened else {
            return none(driver);
        };
        let shards = opened.shards.clone();
        let (owner, changes) = Shards::new(opened);
        owners.push(machine.spawn_on(core, owner.run()));
        workers.push(machine.spawn_on(core, work(changes.clone(), shards, steps)));
        closers.push(changes);
    }
    let client = booted.client;
    let finished = Rc::new(RefCell::new(None));
    let result = Rc::clone(&finished);
    machine.block_on(0, async move {
        let done = async move {
            let mut ok = true;
            let running = Rc::new(RefCell::new(true));
            let ticking = Rc::clone(&running);
            let ticker = {
                let client = client.clone();
                spawn(async move {
                    while *ticking.borrow() {
                        sleep(Duration::from_millis(2)).await;
                        if client.checkpoint().await.is_err() {
                            return false;
                        }
                    }
                    true
                })
            };
            for worker in workers {
                ok &= worker.await;
            }
            *running.borrow_mut() = false;
            ok &= ticker.await;
            for _ in 0..6 {
                ok &= client.checkpoint().await.is_ok();
                sleep(Duration::from_millis(5)).await;
            }
            for closer in closers {
                closer.close();
            }
            let mut keepers = Vec::new();
            for owner in owners {
                keepers.push(owner.await);
            }
            drop(client);
            let committer = committer.await;
            if ok {
                *result.borrow_mut() = Some((committer, merge(keepers)));
            }
        };
        let _ = timeout(HORIZON, done).await;
    });
    let finished = finished.borrow_mut().take();
    Outcome { driver, finished }
}

async fn reopen() -> (Usage, Keeper, CoreFile) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let parts = loaded.parts.clone();
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    let usage = recovered.state.usage.clone();
    let entries = recovered.entries.clone();
    let (committer, _client) = Committer::new(data, recovered.journal, recovered.state);
    let file = committer.source().open().await.expect("open");
    let keeper = Keeper::rebuild(&file, &parts, &entries, &ALL)
        .await
        .expect("rebuild");
    (usage, keeper, file)
}

#[test]
fn compaction_moves_live_records_and_frees_their_regions() {
    let outcome = workload(1, 600, None, created(1));
    let (committer, keeper) = outcome.finished.expect("workload finished");
    let stats = committer.compaction();
    assert!(stats.emptied > 0, "{stats:?}");
    audit(committer.usage(), &keeper);
    let cold: usize = ALL
        .iter()
        .map(|&s| {
            let entries = keeper.state(s).expect("kept").entries();
            entries.keys().filter(|&&k| k > COLD).count()
        })
        .sum();
    assert_eq!(cold, 200);
    drop(committer);
    let after = Rc::new(SimDriver::with_disk(
        2,
        Config::default(),
        outcome.driver.crash(),
    ));
    Runtime::new(after).block_on(async move {
        let (usage, rebuilt, file) = reopen().await;
        audit(&usage, &rebuilt);
        for shard in ALL {
            assert_eq!(
                rebuilt.state(shard).expect("kept").entries(),
                keeper.state(shard).expect("kept").entries()
            );
        }
        assert!(contents(&file, &rebuilt).await > 0, "no record was moved");
    });
}

fn crash_at(seed: u64, steps: u64, point: u64) {
    let outcome = workload(seed, steps, Some(point), created(seed));
    assert!(
        outcome.driver.is_halted(),
        "crash point {point} not reached"
    );
    let after = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        outcome.driver.crash(),
    ));
    Runtime::new(after).block_on(async {
        let (usage, keeper, file) = reopen().await;
        audit(&usage, &keeper);
        contents(&file, &keeper).await;
    });
}

#[test]
fn moves_survive_a_crash_at_every_disk_operation() {
    let only = env::var("SIM_CRASH_AT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let steps = 240;
    check(0..1, |seed| {
        let outcome = workload(seed, steps, None, created(seed));
        let (committer, _) = outcome.finished.as_ref().expect("workload ran");
        assert!(
            committer.compaction().emptied > 0,
            "{:?}",
            committer.compaction()
        );
        let total = outcome.driver.disk_ops();
        let points: Vec<u64> = only.map_or_else(|| sampled(seed, total), |p| vec![p]);
        for point in points {
            if let Err(failure) =
                panic::catch_unwind(AssertUnwindSafe(|| crash_at(seed, steps, point)))
            {
                eprintln!("crash point {point} of {total}; replay with SIM_CRASH_AT={point}");
                panic::resume_unwind(failure);
            }
        }
    });
}

fn sampled(seed: u64, total: u64) -> Vec<u64> {
    let stride = total.div_ceil(300).max(1);
    let first = 1 + seed % stride;
    (first..=total)
        .step_by(usize::try_from(stride).expect("fits"))
        .collect()
}

#[test]
fn a_region_with_a_record_nobody_owns_is_never_a_victim() {
    let driver = Rc::new(SimDriver::with_disk(5, Config::default(), created(5)));
    Runtime::new(driver).block_on(async {
        let setup = Setup {
            cores: 1,
            credits: 4,
            reserve: 0,
        };
        let booted = boot(PATH, setup).await.expect("boot");
        let committer = spawn(booted.committer.run());
        let client = booted.client;
        let mut core = booted
            .starts
            .into_iter()
            .next()
            .expect("core")
            .open()
            .await
            .expect("open");
        let stray = store::Submission {
            claim: store::Claim::Intake,
            records: vec![store::Write {
                kind: 9,
                counted: true,
                shard: 0,
                tenant: 7,
                payload: vec![1; 64],
            }],
            bodies: Vec::new(),
            dead: Vec::new(),
        };
        core.session.submit(0, stray).expect("credit");
        let Some(store::Event::Durable { locations, .. }) = core.results.recv().await else {
            panic!("stray record not durable");
        };
        let stray = locations[0];
        let (owner, changes) = Shards::new(core);
        let owner = spawn(owner.run());
        for step in 0..1200u64 {
            let key = step % HOT;
            changes
                .change(0, put(key, step), sealed(key, step))
                .await
                .expect("put");
            if step % 40 == 39 {
                client.checkpoint().await.expect("checkpoint");
            }
        }
        for _ in 0..4 {
            client.checkpoint().await.expect("checkpoint");
        }
        changes.close();
        drop(owner.await);
        drop(client);
        let committer = committer.await;
        let stats = committer.compaction();
        assert!(stats.emptied > 0, "{stats:?}");
        assert_eq!(stats.dropped, 0, "{stats:?}");
        assert!(committer.regions().is_used(stray.region));
        assert!(committer.usage().count(stray.region).extents >= 1);
    });
}
