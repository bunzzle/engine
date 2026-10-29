use std::cell::RefCell;
use std::env;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Duration;

use rt::Buf;
use rt::sim::{Config, Disk, Faults, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, sleep, spawn, timeout};
use store::{
    Batch, Change, Changes, Claim, Client, Committer, CoreFile, DataFile, Delivery, Error,
    HEAD_ITEM, Header, INDEX_SIZE, Index, Item, Keeper, Key, Lease, Location, Op, Options, Owner,
    Range, Record, SLOT_SIZE, Setup, Shards, Usage, boot, checksum, encode, load, record_size,
    recover,
};

const PATH: &str = "/data/store";
const SHARDS: u16 = 4;
const ALL: [u16; SHARDS as usize] = [0, 1, 2, 3];
const CORES: u16 = 2;
const HOT: u64 = 4;
const COLD: u64 = 1000;
const MILLION: u32 = 1_000_000;
const HORIZON: Duration = Duration::from_secs(30);
const BODY_ITEM: u32 = 1;
const KIND_CHUNK: u8 = 9;

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
        key: Key::head(key),
        tenant: 7,
        change: Change::Put(Delivery {
            status: 1,
            attempts: 0,
            due: version,
        }),
    }
}

fn chunk(key: u64, n: u64) -> Vec<u8> {
    let len = 900 + usize::try_from((key * 37 + n * 11) % 1500).expect("fits");
    vec![u8::try_from((key + n) % 251).expect("fits"); len]
}

fn chunks(key: u64) -> u64 {
    1 + key % 4
}

fn body(key: u64, epoch: u64, sector: usize) -> Buf {
    let size: usize = (0..chunks(key))
        .map(|n| record_size(chunk(key, n).len()))
        .sum();
    let len = size.next_multiple_of(sector);
    let mut buf = Buf::aligned(len, sector);
    buf.set_len(len);
    buf.fill(0);
    let mut at = 0;
    for n in 0..chunks(key) {
        let header = Header {
            kind: KIND_CHUNK,
            flags: 0,
            shard: 0,
            tenant: 7,
            epoch,
            sequence: epoch,
        };
        at += encode(&header, &chunk(key, n), &mut buf[at..]);
    }
    buf
}

fn owned(item: &Item) -> impl Iterator<Item = (u32, u64)> + '_ {
    let record = std::iter::once((item.location.region, u64::from(item.location.size)));
    record.chain(item.bodies.iter().map(|b| (b.region, u64::from(b.length))))
}

fn audit(usage: &Usage, keeper: &Keeper) {
    let mut owned_bytes = vec![(0u32, 0u64); OPTIONS.region_count as usize];
    for shard in ALL {
        for item in keeper.state(shard).expect("kept").entries().values() {
            for (region, bytes) in owned(item) {
                let slot = &mut owned_bytes[region as usize];
                slot.0 += 1;
                slot.1 += bytes;
            }
        }
    }
    let owned = owned_bytes;
    for (region, (extents, bytes)) in (0u32..).zip(owned) {
        let count = usage.count(region);
        assert_eq!(
            (count.extents, count.bytes),
            (extents, bytes),
            "region {region}: committer count vs owner maps"
        );
    }
}

async fn check_body(file: &CoreFile, key: u64, item: &Item) -> bool {
    assert_eq!(item.bodies.len(), 1, "key {key} bodies");
    let range = item.bodies[0];
    let buf = file.reader().range(range).await.expect("body range");
    let mut at = 0;
    let mut moved = false;
    for n in 0..chunks(key) {
        let record = Record::decode(&buf[at..]).expect("chunk");
        assert_eq!(
            (record.kind(), record.tenant(), record.epoch()),
            (KIND_CHUNK, 7, range.epoch),
            "key {key} chunk {n}"
        );
        assert_eq!(
            record.payload(),
            chunk(key, n).as_slice(),
            "key {key} chunk {n}"
        );
        moved |= record.sequence() != record.epoch();
        at += record.size();
    }
    assert!(buf[at..].iter().all(|&b| b == 0), "key {key} body padding");
    moved
}

async fn contents(file: &CoreFile, keeper: &Keeper) -> (usize, usize) {
    let mut moved = 0;
    let mut bodies = 0;
    let reader = file.reader();
    for shard in ALL {
        let state = keeper.state(shard).expect("kept");
        for (&key, item) in state.entries() {
            if key.item == BODY_ITEM {
                assert!(
                    state.get(Key::head(key.message)).is_some(),
                    "body without head"
                );
                bodies += usize::from(check_body(file, key.message, item).await);
                continue;
            }
            let key = key.message;
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
    (moved, bodies)
}

struct Bodies {
    client: Client,
    file: CoreFile,
    lease: Option<Lease>,
    offset: u64,
}

impl Bodies {
    async fn write(&mut self, key: u64) -> Result<Range, Error> {
        let sector = self.file.sector_size() as usize;
        let region_size = self.file.superblock().region_size();
        let length = body(key, 0, sector).len() as u64;
        if self.lease.is_none() || self.offset + length > region_size {
            self.lease = None;
            self.lease = Some(self.client.allocate(Claim::Intake).await?);
            self.offset = 0;
        }
        let lease = self.lease.as_ref().expect("lease");
        let buf = body(key, lease.epoch(), sector);
        let range = Range {
            region: lease.region(),
            epoch: lease.epoch(),
            offset: self.offset,
            length: u32::try_from(buf.len()).expect("fits"),
            checksum: checksum(&buf),
        };
        let at = self.file.region_offset(range.region) + range.offset;
        let (written, _) = self.file.file().write_all_at(buf, at).await;
        written?;
        self.offset += length;
        Ok(range)
    }
}

fn message(shard: u16, key: u64, range: Range) -> Batch {
    let op = |item, bodies| Op {
        item,
        change: put(key, 0).change,
        clear: Vec::new(),
        bodies,
        sealed: sealed(key, 0),
    };
    Batch {
        shard,
        message: key,
        tenant: 7,
        ops: vec![op(HEAD_ITEM, Vec::new()), op(BODY_ITEM, vec![range])],
    }
}

fn drop_message(shard: u16, key: u64) -> Batch {
    Batch {
        shard,
        message: key,
        tenant: 7,
        ops: vec![Op {
            item: HEAD_ITEM,
            change: Change::Drop,
            clear: Vec::new(),
            bodies: Vec::new(),
            sealed: Vec::new(),
        }],
    }
}

async fn work(changes: Changes, shards: Vec<u16>, steps: u64, mut bodies: Bodies) -> bool {
    let mut cold = 0;
    let mut last = None;
    for step in 0..steps {
        let shard = shards[usize::try_from(step).expect("fits") % shards.len()];
        let result = if step % 6 == 5 {
            cold += 1;
            let key = COLD + cold;
            let created = match bodies.write(key).await {
                Ok(range) => changes.apply(message(shard, key, range)).await.map(drop),
                Err(error) => Err(error),
            };
            match (created.is_ok(), last.take()) {
                (true, Some((at, old))) if cold % 2 == 0 => {
                    changes.apply(drop_message(at, old)).await.map(drop)
                }
                (true, _) => {
                    last = Some((shard, key));
                    Ok(())
                }
                (false, _) => created,
            }
        } else {
            let key = step % HOT;
            changes
                .change(shard, put(key, step), sealed(key, step))
                .await
                .map(drop)
        };
        match result {
            Ok(()) => {}
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
        let bodies = Bodies {
            client: opened.session.client().clone(),
            file: opened.file.clone(),
            lease: None,
            offset: 0,
        };
        let (owner, changes) = Shards::new(opened);
        owners.push(machine.spawn_on(core, owner.run()));
        workers.push(machine.spawn_on(core, work(changes.clone(), shards, steps, bodies)));
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
            entries
                .keys()
                .filter(|k| k.message > COLD && k.item == HEAD_ITEM)
                .count()
        })
        .sum();
    assert_eq!(cold, 100);
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
        let (records, bodies) = contents(&file, &rebuilt).await;
        assert!(records > 0, "no record was moved");
        assert!(bodies > 0, "no body was moved");
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
            claim: Claim::Intake,
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

const SMALL: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: SHARDS as u32,
};

#[test]
fn compaction_keeps_intake_running_on_a_small_disk() {
    let setup = Rc::new(SimDriver::new(6, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &SMALL).await.expect("create");
    });
    let driver = Rc::new(SimDriver::with_disk(6, Config::default(), setup.crash()));
    Runtime::new(driver).block_on(async {
        let setup = Setup {
            cores: 1,
            credits: 8,
            reserve: 1,
        };
        let booted = boot(PATH, setup).await.expect("boot");
        let committer = spawn(booted.committer.run());
        let client = booted.client;
        let core = booted
            .starts
            .into_iter()
            .next()
            .expect("core")
            .open()
            .await
            .expect("open");
        let (owner, changes) = Shards::new(core);
        let owner = spawn(owner.run());
        let workers: Vec<JoinHandle<u64>> = (0..4u64)
            .map(|worker| {
                let changes = changes.clone();
                spawn(async move {
                    let mut written = 0;
                    for step in 0..16_000u64 {
                        let shard =
                            u16::try_from((step + worker) % u64::from(SHARDS)).expect("fits");
                        let key = if step % 10 == 0 {
                            COLD + worker * 1000 + step % 400
                        } else {
                            worker * 10 + step % HOT
                        };
                        let body = sealed(key, step);
                        written += body.len() as u64;
                        changes
                            .change(shard, put(key, step), body)
                            .await
                            .unwrap_or_else(|e| panic!("worker {worker} step {step}: {e}"));
                    }
                    written
                })
            })
            .collect();
        let mut written = 0;
        for worker in workers {
            written += worker.await;
        }
        changes.close();
        let keeper = owner.await;
        drop(client);
        let committer = committer.await;
        let disk = u64::from(SMALL.region_count) * SMALL.region_size;
        assert!(
            written > 5 * disk,
            "{written} bytes written on a {disk} byte disk"
        );
        let stats = committer.compaction();
        assert!(stats.emptied > 0 && stats.moved > 0, "{stats:?}");
        assert!(
            stats.moved < 2 * written,
            "{stats:?} for {written} bytes written"
        );
        assert!(!committer.space().low, "{:?}", committer.space());
        let mut all = Keeper::default();
        for shard in ALL {
            let kept = keeper.state(shard).cloned().unwrap_or_default();
            all.insert(shard, kept, Vec::new());
        }
        let mut held = vec![(0u32, 0u64); SMALL.region_count as usize];
        for shard in ALL {
            for item in all.state(shard).expect("kept").entries().values() {
                let slot = &mut held[item.location.region as usize];
                slot.0 += 1;
                slot.1 += u64::from(item.location.size);
            }
        }
        for (region, (extents, bytes)) in (0u32..).zip(held) {
            let count = committer.usage().count(region);
            assert_eq!(
                (count.extents, count.bytes),
                (extents, bytes),
                "region {region}"
            );
        }
    });
}
