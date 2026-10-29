use std::cell::RefCell;
use std::env;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, SimDriver, check};
use rt::{Buf, File, OpenOptions, Runtime, sleep, spawn};
use store::{
    Body, Claim, Client, Committer, DataFile, Dead, Location, Options, Range, Record, Recovered,
    SLOT_SIZE, Submission, Write, ZONE_SIZE, checksum, load, recover,
};

const MILLION: u32 = 1_000_000;
const PATH: &str = "/data/store";
const HORIZON: Duration = Duration::from_secs(60);

const OPTIONS: Options = Options {
    journal_size: 2 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: 4,
};

#[derive(Clone, Default)]
struct Model {
    records: Vec<(Location, Vec<u8>)>,
    bodies: Vec<(Range, Vec<u8>)>,
}

type Shared = Rc<RefCell<Model>>;

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    run(&setup, async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

async fn reopen() -> (DataFile, Recovered) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    (data, recovered)
}

fn payload(client: u64, step: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&client.to_le_bytes());
    out.extend_from_slice(&step.to_le_bytes());
    out.resize(len.max(16), u8::try_from(step % 251).expect("fits"));
    out
}

fn submission(records: Vec<Vec<u8>>, bodies: Vec<Body>, dead: Vec<Dead>) -> Submission {
    Submission {
        claim: Claim::Intake,
        records: records
            .into_iter()
            .map(|payload| Write {
                kind: 7,
                shard: 0,
                tenant: 3,
                payload,
            })
            .collect(),
        bodies,
        dead,
    }
}

fn kill(location: &Location) -> Dead {
    Dead {
        tenant: 3,
        region: location.region,
        epoch: location.epoch,
        offset: location.offset,
        length: location.size,
    }
}

fn kill_body(range: &Range) -> Dead {
    Dead {
        tenant: 3,
        region: range.region,
        epoch: range.epoch,
        offset: range.offset,
        length: range.length,
    }
}

async fn records(client: Client, id: u64, model: Shared) {
    let mut mine: Vec<(Location, Vec<u8>)> = Vec::new();
    for step in 0..40u64 {
        let len = 100 + usize::try_from((step * 53 + id * 17) % 1500).expect("fits");
        let record = payload(id, step, len);
        let old = (mine.len() > 4).then(|| mine.remove(0));
        let dead = old.iter().map(|(l, _)| kill(l)).collect();
        if let Some((location, _)) = &old {
            model.borrow_mut().records.retain(|(l, _)| l != location);
        }
        if let Ok(durable) = client
            .commit(submission(vec![record.clone()], Vec::new(), dead))
            .await
        {
            let entry = (durable.locations[0], record);
            mine.push(entry.clone());
            model.borrow_mut().records.push(entry);
        }
        if step % 13 == 12 {
            let _ = client.checkpoint().await;
        }
    }
}

async fn bodies(client: Client, model: Shared) {
    let options = OpenOptions {
        read: true,
        write: true,
        ..OpenOptions::default()
    };
    let Ok(file) = File::open(PATH, &options).await else {
        return;
    };
    let mut previous: Option<Range> = None;
    for step in 0..8u64 {
        let Ok(lease) = client.allocate(Claim::Intake).await else {
            continue;
        };
        let bytes = payload(
            9,
            step,
            4096 * (1 + usize::try_from(step % 3).expect("fits")),
        );
        let at = ZONE_SIZE + OPTIONS.journal_size + u64::from(lease.region()) * OPTIONS.region_size;
        let (written, _) = file.write_all_at(Buf::from_slice(&bytes), at).await;
        if written.is_err() {
            continue;
        }
        let range = Range {
            region: lease.region(),
            epoch: lease.epoch(),
            offset: 0,
            length: u32::try_from(bytes.len()).expect("fits"),
            checksum: checksum(&bytes),
        };
        let old = previous.take();
        if let Some(old) = &old {
            model.borrow_mut().bodies.retain(|(r, _)| !same(r, old));
        }
        let dead = old.iter().map(kill_body).collect();
        let body = Body {
            shard: 0,
            tenant: 3,
            range,
        };
        if client
            .commit(submission(Vec::new(), vec![body], dead))
            .await
            .is_ok()
        {
            model.borrow_mut().bodies.push((range, bytes));
            previous = Some(range);
        }
        lease.seal();
    }
}

fn same(a: &Range, b: &Range) -> bool {
    (a.region, a.epoch, a.offset, a.length) == (b.region, b.epoch, b.offset, b.length)
}

fn workload(seed: u64, halt_after: Option<u64>, disk: Disk) -> (Rc<SimDriver>, Shared) {
    let config = Config {
        halt_after,
        faults: Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        },
        ..Config::default()
    };
    let driver = Rc::new(SimDriver::with_disk(seed, config, disk));
    let model = Shared::default();
    let shared = model.clone();
    run(&driver, async move {
        let Ok(data) = DataFile::open(PATH).await else {
            return;
        };
        let Ok(loaded) = load(&data, 0).await else {
            return;
        };
        let Ok(recovered) = recover(&data, loaded.position, loaded.state).await else {
            return;
        };
        let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
        let committer = spawn(committer.run());
        let mut tasks = Vec::new();
        for id in 0..3u64 {
            tasks.push(spawn(records(client.clone(), id, shared.clone())));
        }
        tasks.push(spawn(bodies(client.clone(), shared.clone())));
        drop(client);
        spawn(async move {
            for task in tasks {
                task.await;
            }
            drop(committer.await);
        });
        sleep(HORIZON).await;
    });
    (driver, model)
}

async fn verify(data: &DataFile, recovered: &Recovered, model: &Model) {
    let state = &recovered.state;
    for (location, expected) in &model.records {
        assert!(
            state.regions.is_used(location.region),
            "record region freed"
        );
        assert_eq!(state.epochs[location.region as usize], location.epoch);
        let offset = data.region_offset(location.region) + location.offset;
        let len = location.size as usize;
        let (result, buf) = data.file().read_at(Buf::new(len), offset).await;
        assert_eq!(result.expect("read"), len);
        let record = Record::decode(&buf).expect("acknowledged record decodes");
        assert_eq!(
            (record.epoch(), record.sequence()),
            (location.epoch, location.sequence)
        );
        assert_eq!(record.payload(), &expected[..]);
    }
    for (range, expected) in &model.bodies {
        assert!(state.regions.is_used(range.region), "body region freed");
        assert_eq!(state.epochs[range.region as usize], range.epoch);
        let offset = data.region_offset(range.region) + range.offset;
        let (result, buf) = data.file().read_at(Buf::new(expected.len()), offset).await;
        assert_eq!(result.expect("read"), expected.len());
        assert_eq!(&buf[..], &expected[..]);
    }
    for entry in &recovered.entries {
        for range in &entry.commit.ranges {
            let offset = data.region_offset(range.region) + range.offset;
            let len = range.length as usize;
            let (result, buf) = data.file().read_at(Buf::new(len), offset).await;
            assert_eq!(result.expect("read"), len);
            assert_eq!(checksum(&buf), range.checksum, "partial batch applied");
        }
    }
    let usage = &state.usage;
    let mut region_bytes = 0;
    for region in 0..OPTIONS.region_count {
        region_bytes += usage.count(region).bytes;
        if !state.regions.is_used(region) {
            assert!(usage.is_empty(region), "free region {region} has live data");
        }
    }
    assert_eq!(region_bytes, usage.tenants().values().sum::<u64>());
    for (location, _) in &model.records {
        assert!(usage.count(location.region).extents > 0);
    }
    for (range, _) in &model.bodies {
        assert!(usage.count(range.region).extents > 0);
    }
}

fn recover_and_continue(seed: u64, disk: Disk, model: Model) {
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), disk));
    let model = Rc::new(model);
    let shared = model.clone();
    run(&driver, async move {
        let (data, recovered) = reopen().await;
        verify(&data, &recovered, &shared).await;
        let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
        let committer = spawn(committer.run());
        let record = payload(77, 0, 300);
        let durable = client
            .commit(submission(vec![record.clone()], Vec::new(), Vec::new()))
            .await
            .expect("writing continues after recovery");
        client
            .checkpoint()
            .await
            .expect("checkpoint after recovery");
        drop(client);
        drop(committer.await);
        let (data, recovered) = reopen().await;
        let mut model = Model {
            records: shared.records.clone(),
            bodies: shared.bodies.clone(),
        };
        model.records.push((durable.locations[0], record));
        verify(&data, &recovered, &model).await;
    });
}

fn replay_point(name: &str) -> Option<u64> {
    env::var(name).ok().and_then(|s| s.parse::<u64>().ok())
}

fn crash_in_recovery(seed: u64, disk: Disk, step: u64, model: &Model) {
    let config = Config {
        halt_after: Some(step),
        faults: Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        },
        ..Config::default()
    };
    let driver = Rc::new(SimDriver::with_disk(seed + 1, config, disk));
    run(&driver, async {
        spawn(async { drop(reopen().await) });
        sleep(HORIZON).await;
    });
    assert!(driver.is_halted(), "recovery point {step} not reached");
    recover_and_continue(seed + 2, driver.crash(), model.clone());
}

fn crash_at(seed: u64, point: u64) {
    let (driver, model) = workload(seed, Some(point), created(seed));
    assert!(driver.is_halted(), "crash point {point} not reached");
    let disk = driver.crash();
    let model = model.take();
    let probe = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        disk.clone(),
    ));
    run(&probe, async { drop(reopen().await) });
    let total = probe.disk_ops();
    let steps: Vec<u64> =
        replay_point("SIM_RECOVERY_AT").map_or_else(|| (1..=total).collect(), |s| vec![s]);
    for step in steps {
        let attempt = || crash_in_recovery(seed, disk.clone(), step, &model);
        if let Err(failure) = panic::catch_unwind(AssertUnwindSafe(attempt)) {
            eprintln!("recovery point {step} of {total}; replay with SIM_RECOVERY_AT={step}");
            panic::resume_unwind(failure);
        }
    }
    recover_and_continue(seed + 1, disk, model);
}

#[test]
fn every_crash_point_recovers() {
    let only = replay_point("SIM_CRASH_AT");
    check(0..1, |seed| {
        let (driver, model) = workload(seed, None, created(seed));
        assert!(!model.borrow().records.is_empty(), "workload ran");
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
