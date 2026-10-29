use std::cell::RefCell;
use std::env;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, sleep, spawn, timeout};
use store::{
    Change, Changes, Claim, Committer, DataFile, Delivery, Error, Index, Keeper, Options,
    SLOT_SIZE, Setup, Shards, Submission, Usage, Write, boot, load, recover,
};

const PATH: &str = "/data/store";
const SHARDS: u16 = 4;
const ALL: [u16; SHARDS as usize] = [0, 1, 2, 3];
const CORES: u16 = 2;
const KEYS: u64 = 8;
const MILLION: u32 = 1_000_000;
const HORIZON: Duration = Duration::from_secs(60);

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 32,
    shards: SHARDS as u32,
};

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

fn put(key: u64, step: u64) -> Index {
    Index {
        key,
        tenant: 7,
        change: Change::Put(Delivery {
            status: u8::try_from(step % 200).expect("fits"),
            attempts: 1,
            due: step,
        }),
    }
}

fn delete(key: u64) -> Index {
    Index {
        key,
        tenant: 7,
        change: Change::Delete,
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

async fn work(changes: Changes, shards: Vec<u16>, worker: u64, steps: u64) -> bool {
    for step in 0..steps {
        let shard = shards[usize::try_from(step).expect("fits") % shards.len()];
        let key = (step * 7 + worker * 3) % KEYS;
        let index = if step % 5 == 4 {
            delete(key)
        } else {
            put(key, step)
        };
        let sealed = vec![
            u8::try_from(worker).expect("fits");
            16 + usize::try_from(step % 40).expect("fits")
        ];
        match changes.change(shard, index, sealed).await {
            Ok(_) | Err(Error::NotFound) => {}
            Err(_) => return false,
        }
    }
    for &shard in &shards {
        for key in 0..KEYS {
            match changes.change(shard, delete(key), Vec::new()).await {
                Ok(_) | Err(Error::NotFound) => {}
                Err(_) => return false,
            }
        }
    }
    true
}

struct Outcome {
    driver: Rc<SimDriver>,
    finished: Option<(Committer, Keeper)>,
}

fn workload(seed: u64, halt_after: Option<u64>, disk: Disk) -> Outcome {
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
        per_mille: 100,
        max: Duration::from_millis(2),
    };
    let machine = Machine::new(Rc::clone(&driver), usize::from(CORES) + 1, stalls);
    let setup = Setup {
        cores: CORES,
        credits: 2,
        reserve: 0,
    };
    let Ok(Ok(booted)) =
        machine.block_on(0, async move { timeout(HORIZON, boot(PATH, setup)).await })
    else {
        return Outcome {
            driver,
            finished: None,
        };
    };
    let committer = machine.spawn_on(0, booted.committer.run());
    let mut owners: Vec<JoinHandle<Keeper>> = Vec::new();
    let mut workers: Vec<JoinHandle<bool>> = Vec::new();
    let mut closers = Vec::new();
    for start in booted.starts {
        let core = usize::from(start.index()) + 1;
        let opened = machine.block_on(core, async move { timeout(HORIZON, start.open()).await });
        let Ok(Ok(opened)) = opened else {
            return Outcome {
                driver,
                finished: None,
            };
        };
        let shards = opened.shards.clone();
        let (owner, changes) = Shards::new(opened);
        owners.push(machine.spawn_on(core, owner.run()));
        for worker in 0..3 {
            let task = work(changes.clone(), shards.clone(), worker, 30);
            workers.push(machine.spawn_on(core, task));
        }
        closers.push(changes);
    }
    let client = booted.client;
    let finished = Rc::new(RefCell::new(None));
    let result = Rc::clone(&finished);
    machine.block_on(0, async move {
        let checkpoints = {
            let client = client.clone();
            spawn(async move {
                for _ in 0..8 {
                    sleep(Duration::from_millis(3)).await;
                    if client.checkpoint().await.is_err() {
                        return false;
                    }
                }
                true
            })
        };
        let done = async move {
            let mut ok = checkpoints.await;
            for worker in workers {
                ok &= worker.await;
            }
            for _ in 0..2 {
                ok &= client.checkpoint().await.is_ok();
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

#[test]
fn deleting_everything_gives_the_space_back() {
    let outcome = workload(1, None, created(1));
    let (committer, keeper) = outcome.finished.expect("workload finished");
    audit(committer.usage(), &keeper);
    assert!(
        ALL.iter()
            .all(|&s| keeper.state(s).expect("kept").is_empty())
    );
    let regions = committer.regions();
    let used = regions.count() - regions.free();
    assert!(used <= 6, "{used} regions still used");
}

async fn rebuilt_audit() {
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
    audit(&usage, &keeper);
}

fn crash_at(seed: u64, point: u64) {
    let outcome = workload(seed, Some(point), created(seed));
    assert!(
        outcome.driver.is_halted(),
        "crash point {point} not reached"
    );
    let after = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        outcome.driver.crash(),
    ));
    Runtime::new(after).block_on(rebuilt_audit());
}

#[test]
fn counts_match_the_owner_maps_after_a_crash_at_every_disk_operation() {
    let only = env::var("SIM_CRASH_AT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    check(0..1, |seed| {
        let outcome = workload(seed, None, created(seed));
        assert!(outcome.finished.is_some(), "workload ran");
        let total = outcome.driver.disk_ops();
        let points: Vec<u64> = only.map_or_else(|| sampled(seed, total), |p| vec![p]);
        for point in points {
            if let Err(failure) = panic::catch_unwind(AssertUnwindSafe(|| crash_at(seed, point))) {
                eprintln!("crash point {point} of {total}; replay with SIM_CRASH_AT={point}");
                panic::resume_unwind(failure);
            }
        }
    });
}

#[test]
fn uncounted_records_leave_their_region_empty() {
    let driver = Rc::new(SimDriver::with_disk(3, Config::default(), created(3)));
    Runtime::new(driver).block_on(async {
        let data = DataFile::open(PATH).await.expect("open");
        let loaded = load(&data, 0).await.expect("load");
        let recovered = recover(&data, loaded.position, loaded.state)
            .await
            .expect("recover");
        let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
        let committer = spawn(committer.run());
        let record = |counted| Submission {
            claim: Claim::Intake,
            records: vec![Write {
                kind: 9,
                counted,
                shard: 0,
                tenant: 7,
                payload: vec![1; 100],
            }],
            bodies: Vec::new(),
            dead: Vec::new(),
        };
        let uncounted = client.commit(record(false)).await.expect("commit");
        let region = uncounted.locations[0].region;
        let counted = client.commit(record(true)).await.expect("commit");
        assert_eq!(counted.locations[0].region, region);
        drop(client);
        let committer = committer.await;
        let count = committer.usage().count(region);
        assert_eq!(count.extents, 1);
        assert_eq!(u64::from(counted.locations[0].size), count.bytes);
    });
}

#[test]
fn the_owner_refuses_changes_it_cannot_apply() {
    let driver = Rc::new(SimDriver::with_disk(4, Config::default(), created(4)));
    Runtime::new(driver).block_on(async {
        let setup = Setup {
            cores: CORES,
            credits: 2,
            reserve: 0,
        };
        let booted = boot(PATH, setup).await.expect("boot");
        let committer = spawn(booted.committer.run());
        let mut starts = booted.starts.into_iter();
        let core = starts.next().expect("core 0").open().await.expect("open");
        drop(starts);
        let (owner, changes) = Shards::new(core);
        let owner = spawn(owner.run());
        let refused = changes.change(1, put(5, 1), Vec::new()).await;
        assert!(matches!(refused, Err(Error::Invalid("owner"))));
        let missing = changes.change(2, delete(5), Vec::new()).await;
        assert!(matches!(missing, Err(Error::NotFound)));
        let first = changes
            .change(2, put(5, 1), vec![3; 10])
            .await
            .expect("put");
        let second = changes
            .change(2, put(5, 2), vec![4; 10])
            .await
            .expect("put");
        let stale = Index {
            key: 5,
            tenant: 7,
            change: Change::Move { old: first },
        };
        let moved = changes.change(2, stale, vec![4; 10]).await;
        assert!(matches!(moved, Err(Error::Invalid("moved"))));
        let current = Index {
            key: 5,
            tenant: 7,
            change: Change::Move { old: second },
        };
        changes.change(2, current, vec![4; 10]).await.expect("move");
        changes.close();
        let keeper = owner.await;
        drop(booted.client);
        let committer = committer.await;
        let mut all = Keeper::default();
        for shard in ALL {
            let kept = keeper.state(shard).cloned().unwrap_or_default();
            all.insert(shard, kept, Vec::new());
        }
        audit(committer.usage(), &all);
    });
}

fn sampled(seed: u64, total: u64) -> Vec<u64> {
    let stride = total.div_ceil(300).max(1);
    let first = 1 + seed % stride;
    (first..=total)
        .step_by(usize::try_from(stride).expect("fits"))
        .collect()
}
