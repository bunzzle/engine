use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, sleep, spawn, timeout};
use spool::{
    BODY_ITEM, Body, Error, Head, HeadClear, Limits, Message, MessageId, SLICE, Slice, Spool,
    decode_chunk, slice_item, slice_parts,
};
use store::{
    CoreFile, DataFile, HEAD_ITEM, Index, Keeper, Location, Options, Owner, Range, Record,
    SLOT_SIZE, Setup, boot, split_key,
};

const PATH: &str = "/data/store";
const SHARDS: u16 = 4;
const ALL: [u16; SHARDS as usize] = [0, 1, 2, 3];
const CORES: u16 = 2;
const MILLION: u32 = 1_000_000;
const HORIZON: Duration = Duration::from_secs(60);
const NODE: u32 = 3;

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 96,
    shards: SHARDS as u32,
};

const LIMITS: Limits = Limits {
    recipients: 3000,
    inline: 2048,
    body: 512 * 1024,
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

fn bytes(seed: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|n| u8::try_from((seed * 31 + n as u64 * 7) % 251).expect("fits"))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Expected {
    Inline(Vec<u8>),
    Chain(Vec<Vec<u8>>),
}

#[derive(Clone, Debug)]
struct Accepted {
    id: MessageId,
    tenant: u32,
    head: Head,
    body: Expected,
    slices: Vec<Slice>,
}

#[derive(Default)]
struct Model {
    accepted: Vec<Accepted>,
    boots: BTreeMap<u16, u32>,
}

type Shared = Rc<RefCell<Model>>;

fn recipients(step: u64) -> usize {
    match step % 10 {
        0 => 1,
        3 => 1000,
        6 => SLICE as usize + 5,
        9 => 2 * SLICE as usize + 1,
        n => usize::try_from(n * 13).expect("fits"),
    }
}

fn slices(seed: u64, count: usize) -> Vec<Slice> {
    let size = SLICE as usize;
    (0..count.div_ceil(size))
        .map(|k| {
            let n = size.min(count - k * size);
            Slice {
                queues: (0..n)
                    .map(|r| u32::try_from((seed + r as u64) % 97).expect("fits"))
                    .collect(),
                sealed: bytes(seed + k as u64, 8 * n + 16),
            }
        })
        .collect()
}

fn chunks(seed: u64, chunk: usize) -> Vec<Vec<u8>> {
    (0..=seed % 4)
        .map(|n| {
            let len = 500 + usize::try_from((seed * 977 + n * 131) % 20_000).expect("fits");
            bytes(seed ^ n, len.min(chunk))
        })
        .collect()
}

async fn draft(intake: &Spool, shard: u16, step: u64) -> Result<(Message, Accepted), Error> {
    let id = intake.id(shard).await?;
    let seed = id.key ^ u64::from(shard) << 40;
    let slices = slices(seed, recipients(step));
    let head = Head {
        clear: HeadClear {
            batch_key: seed % 5,
            recipients: u32::try_from(slices.iter().map(|s| s.queues.len()).sum::<usize>())
                .expect("fits"),
            body_size: seed % 100_000,
            accepted: step,
            not_before: step + 1,
            priority: u8::try_from(step % 3).expect("fits"),
        },
        expiry: 1000 + step,
        sealed: bytes(seed, 200 + usize::try_from(seed % 300).expect("fits")),
    };
    let (body, expected) = if step.is_multiple_of(3) {
        let sealed = bytes(seed + 1, 100 + usize::try_from(seed % 1900).expect("fits"));
        (Body::Inline(sealed.clone()), Expected::Inline(sealed))
    } else {
        let chunks = chunks(seed, intake.chunk());
        let written = intake.body(id, 7, &chunks).await?;
        (Body::Chain(written), Expected::Chain(chunks))
    };
    let accepted = Accepted {
        id,
        tenant: 7,
        head: head.clone(),
        body: expected,
        slices: slices.clone(),
    };
    let message = Message {
        id,
        tenant: 7,
        head,
        body,
        slices,
    };
    Ok((message, accepted))
}

async fn work(intake: Spool, shards: Vec<u16>, steps: u64, model: Shared) -> bool {
    let mut step = 0;
    let mut group = 0;
    while step < steps {
        group += 1;
        let mut messages = Vec::new();
        let mut accepted = Vec::new();
        for _ in 0..=group % 3 {
            let shard = shards[usize::try_from(step).expect("fits") % shards.len()];
            match draft(&intake, shard, step).await {
                Ok((message, expected)) => {
                    model
                        .borrow_mut()
                        .boots
                        .entry(shard)
                        .and_modify(|b| *b = (*b).max(split_key(expected.id.key).0))
                        .or_insert(split_key(expected.id.key).0);
                    messages.push(message);
                    accepted.push(expected);
                }
                Err(Error::Store(store::Error::Reserve | store::Error::Full)) => {}
                Err(_) => return false,
            }
            step += 1;
        }
        match intake.accept(messages).await {
            Ok(()) => model.borrow_mut().accepted.extend(accepted),
            Err(Error::Store(
                store::Error::Reserve | store::Error::Full | store::Error::Invalid("batch"),
            )) => sleep(Duration::from_millis(1)).await,
            Err(Error::Limit("submission")) => {}
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
    finished: bool,
}

fn workload(seed: u64, steps: u64, halt_after: Option<u64>, disk: Disk, model: &Shared) -> Outcome {
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
    let Ok(Ok(booted)) =
        machine.block_on(0, async move { timeout(HORIZON, boot(PATH, setup)).await })
    else {
        return Outcome {
            driver,
            finished: false,
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
                finished: false,
            };
        };
        let shards = opened.shards.clone();
        let (intake, owner) = Spool::new(opened, NODE, LIMITS).expect("limits");
        owners.push(machine.spawn_on(core, owner.run()));
        closers.push(intake.changes().clone());
        workers.push(machine.spawn_on(core, work(intake, shards, steps, Rc::clone(model))));
    }
    let client = booted.client;
    let finished = Rc::new(RefCell::new(false));
    let result = Rc::clone(&finished);
    machine.block_on(0, async move {
        let done = async move {
            let running = Rc::new(RefCell::new(true));
            let ticking = Rc::clone(&running);
            let ticker = {
                let client = client.clone();
                spawn(async move {
                    while *ticking.borrow() {
                        sleep(Duration::from_millis(3)).await;
                        if client.checkpoint().await.is_err() {
                            return false;
                        }
                    }
                    true
                })
            };
            let mut ok = true;
            for worker in workers {
                ok &= worker.await;
            }
            *running.borrow_mut() = false;
            ok &= ticker.await;
            for closer in closers {
                closer.close();
            }
            for owner in owners {
                drop(owner.await);
            }
            drop(client);
            drop(committer.await);
            *result.borrow_mut() = ok;
        };
        let _ = timeout(HORIZON, done).await;
    });
    let finished = *finished.borrow();
    Outcome { driver, finished }
}

async fn reopen(model: &Model) -> (Keeper, CoreFile) {
    let setup = Setup {
        cores: CORES,
        credits: 4,
        reserve: 0,
    };
    let booted = boot(PATH, setup).await.expect("boot");
    let mut keepers = Vec::new();
    let mut file = None;
    for start in booted.starts {
        let mut core = start.open().await.expect("open");
        for &shard in &core.shards {
            let key = core.ids.next(shard).expect("id");
            let before = model.boots.get(&shard).copied().unwrap_or(0);
            assert!(split_key(key).0 > before, "shard {shard} id repeats a boot");
        }
        keepers.push(core.keeper);
        file = Some(core.file);
    }
    (merge(keepers), file.expect("a core"))
}

async fn read(file: &CoreFile, location: Location, tenant: u32) -> Vec<u8> {
    let buf = file
        .reader()
        .read(location, tenant, &Nobody)
        .await
        .expect("read");
    let record = Record::decode(&buf).expect("record");
    let parts = Index::parts(record.payload()).expect("index");
    parts.sealed.to_vec()
}

async fn chain(file: &CoreFile, key: u64, ranges: &[Range]) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    for &range in ranges {
        let buf = file.reader().range(range).await.expect("body range");
        let mut at = 0;
        while at < buf.len() {
            let Ok(record) = Record::decode(&buf[at..]) else {
                assert!(buf[at..].iter().all(|&b| b == 0), "body padding");
                break;
            };
            assert_eq!(record.epoch(), range.epoch);
            let (message, n, sealed) = decode_chunk(record.payload()).expect("chunk");
            assert_eq!((message, n as usize), (key, chunks.len()));
            chunks.push(sealed.to_vec());
            at += record.size();
        }
    }
    chunks
}

async fn verify(file: &CoreFile, keeper: &Keeper, model: &Model) {
    for message in &model.accepted {
        let state = keeper.state(message.id.shard).expect("kept");
        let key = message.id.key;
        assert_eq!(
            state.message(key).count(),
            2 + message.slices.len(),
            "message {key} items"
        );
        let head = state.get(store::Key::head(key)).expect("head");
        assert_eq!(head.tenant, message.tenant);
        assert_eq!(HeadClear::decode(&head.clear), Some(message.head.clear));
        assert_eq!(head.delivery.due, message.head.expiry);
        assert_eq!(read(file, head.location, 7).await, message.head.sealed);
        let body = state.get(store::Key::new(key, BODY_ITEM)).expect("body");
        let found = if body.bodies.is_empty() {
            Expected::Inline(read(file, body.location, 7).await)
        } else {
            Expected::Chain(chain(file, key, &body.bodies).await)
        };
        assert_eq!(found, message.body, "message {key} body");
        for (k, slice) in (0u32..).zip(&message.slices) {
            let item = state
                .get(store::Key::new(key, slice_item(k)))
                .expect("slice");
            assert!(
                item.clear.is_empty(),
                "slice clear part stays out of the map"
            );
            let payload = read(file, item.location, 7).await;
            let (queues, sealed) = slice_parts(&payload).expect("slice");
            assert_eq!((&queues, sealed), (&slice.queues, slice.sealed.as_slice()));
        }
    }
    for shard in ALL {
        let state = keeper.state(shard).expect("kept");
        for (key, item) in state.entries() {
            if key.item != HEAD_ITEM {
                continue;
            }
            let total = HeadClear::decode(&item.clear).expect("head").recipients as usize;
            let slices = total.div_ceil(SLICE as usize);
            assert_eq!(
                state.message(key.message).count(),
                2 + slices,
                "message {} is whole",
                key.message
            );
        }
    }
}

fn after(driver: &SimDriver, seed: u64, model: Shared) {
    let after = Rc::new(SimDriver::with_disk(
        seed,
        Config::default(),
        driver.crash(),
    ));
    Runtime::new(after).block_on(async move {
        let model = model.take();
        let (keeper, file) = reopen(&model).await;
        verify(&file, &keeper, &model).await;
    });
}

#[test]
fn accepted_messages_come_back_whole() {
    let model = Shared::default();
    let outcome = workload(1, 120, None, created(1), &model);
    assert!(outcome.finished, "workload finished");
    let shared = Rc::clone(&model);
    let model = model.borrow();
    assert!(
        model.accepted.len() > 100,
        "{} accepted",
        model.accepted.len()
    );
    let chained = model
        .accepted
        .iter()
        .filter(|m| matches!(&m.body, Expected::Chain(c) if c.len() > 1))
        .count();
    let wide = model
        .accepted
        .iter()
        .filter(|m| m.slices.len() == 3)
        .count();
    assert!(chained > 0 && wide > 0, "{chained} chained, {wide} wide");
    drop(model);
    after(&outcome.driver, 2, shared);
}

fn crash_at(seed: u64, steps: u64, point: u64) {
    let model = Shared::default();
    let outcome = workload(seed, steps, Some(point), created(seed), &model);
    assert!(
        outcome.driver.is_halted(),
        "crash point {point} not reached"
    );
    after(&outcome.driver, seed + 1, model);
}

fn sampled(seed: u64, total: u64) -> Vec<u64> {
    let stride = total.div_ceil(200).max(1);
    let first = 1 + seed % stride;
    (first..=total)
        .step_by(usize::try_from(stride).expect("fits"))
        .collect()
}

#[test]
fn accepted_messages_survive_a_crash_at_every_disk_operation() {
    let only = env::var("SIM_CRASH_AT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let steps = 40;
    check(0..1, |seed| {
        let model = Shared::default();
        let outcome = workload(seed, steps, None, created(seed), &model);
        assert!(outcome.finished, "workload ran");
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
