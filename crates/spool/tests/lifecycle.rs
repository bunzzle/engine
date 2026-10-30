use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, sleep, spawn, timeout};
use spool::{
    Body, Done, Error, Head, HeadClear, Limits, Message, MessageId, Outcome, Reply, Report, SLICE,
    Slice, Spool, Status,
};
use store::{DataFile, HEAD_ITEM, Keeper, Options, SLOT_SIZE, Setup, boot};

const PATH: &str = "/data/store";
const SHARDS: u16 = 4;
const CORES: u16 = 2;
const MILLION: u32 = 1_000_000;
const HORIZON: Duration = Duration::from_secs(60);

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 64,
    shards: SHARDS as u32,
};

const LIMITS: Limits = Limits {
    recipients: 3000,
    inline: 2048,
    body: 512 * 1024,
};

type Key = (u16, u64);

#[derive(Default)]
struct Model {
    accepted: BTreeMap<Key, u32>,
    tenants: BTreeMap<Key, u32>,
    submitted: BTreeSet<Key>,
    attempts: BTreeMap<(Key, u32), u16>,
    finals: BTreeSet<(Key, u32)>,
    may_drop: BTreeSet<Key>,
    dropped: BTreeSet<Key>,
    merged: usize,
    waited: usize,
}

type Shared = Rc<RefCell<Model>>;

fn key(id: MessageId) -> Key {
    (id.shard, id.key)
}

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % n
    }
}

fn recipients(rng: &mut Rng) -> usize {
    match rng.below(20) {
        0 => SLICE as usize + 3,
        1 => 1,
        n => usize::try_from(n * 2).expect("fits"),
    }
}

fn expected(error: &Error) -> bool {
    matches!(
        error,
        Error::Store(store::Error::Reserve | store::Error::Full)
    )
}

async fn accept(
    spool: &Spool,
    shard: u16,
    step: u64,
    rng: &mut Rng,
    model: &Shared,
) -> Result<(MessageId, u32), Error> {
    let id = spool.id(shard).await?;
    let count = recipients(rng);
    let size = SLICE as usize;
    let slices = (0..count.div_ceil(size))
        .map(|k| {
            let n = size.min(count - k * size);
            Slice {
                queues: vec![5; n],
                sealed: vec![6; 4 * n],
            }
        })
        .collect();
    let message = Message {
        id,
        tenant: 7 + u32::from(shard.is_multiple_of(3)),
        head: Head {
            clear: HeadClear {
                recipients: u32::try_from(count).expect("fits"),
                accepted: step,
                ..HeadClear::default()
            },
            expiry: 1000 + step,
            sealed: vec![1; 64],
        },
        body: Body::Inline(vec![2; 300]),
        slices,
    };
    model.borrow_mut().submitted.insert(key(id));
    model.borrow_mut().tenants.insert(key(id), message.tenant);
    spool.accept(vec![message]).await?;
    Ok((id, u32::try_from(count).expect("fits")))
}

fn outcome(rng: &mut Rng, step: u64) -> Outcome {
    match rng.below(4) {
        0 => Outcome::Delivered,
        1 => Outcome::Failed,
        _ => Outcome::Deferred {
            due: 2000 + step,
            class: u8::try_from(rng.below(4)).expect("fits"),
            notified: rng.below(2) == 0,
        },
    }
}

async fn reported(spool: Spool, id: MessageId, reports: Vec<Report>, model: Shared) -> bool {
    let result = spool.report(id, reports.clone()).await;
    let mut model = model.borrow_mut();
    match result {
        Ok(Done::Kept) => {
            for report in &reports {
                *model
                    .attempts
                    .entry((key(id), report.recipient))
                    .or_default() += 1;
                if !matches!(report.outcome, Outcome::Deferred { .. }) {
                    model.finals.insert((key(id), report.recipient));
                }
            }
            true
        }
        Ok(Done::Dropped) => {
            model.dropped.insert(key(id));
            true
        }
        Err(e) => expected(&e),
    }
}

async fn ended(spool: Spool, id: MessageId, now: Option<u64>, model: Shared) -> bool {
    model.borrow_mut().may_drop.insert(key(id));
    let result = match now {
        Some(now) => spool.expire(id, now).await,
        None => spool.cancel(id).await,
    };
    match result {
        Ok(()) => {
            model.borrow_mut().dropped.insert(key(id));
            true
        }
        Err(e) => expected(&e),
    }
}

async fn round(spool: &Spool, id: MessageId, step: u64, rng: &mut Rng, model: &Shared) -> bool {
    let total = model.borrow().accepted[&key(id)];
    let mut claimed = Vec::new();
    for _ in 0..=rng.below(6) {
        let r = u32::try_from(rng.below(u64::from(total))).expect("fits");
        match spool.claim(id, r) {
            Ok(state) if state.status.is_final() => return false,
            Ok(_) => claimed.push(r),
            Err(Error::State("claimed" | "final")) => {}
            Err(_) => return false,
        }
    }
    let mut tasks: Vec<JoinHandle<bool>> = Vec::new();
    let cancel = rng.below(6) == 0;
    if cancel && !claimed.is_empty() {
        model.borrow_mut().waited += 1;
    }
    if cancel {
        tasks.push(spawn(ended(spool.clone(), id, None, Rc::clone(model))));
    }
    let mut calls = vec![Vec::new(), Vec::new()];
    for &r in &claimed {
        let outcome = outcome(rng, step);
        let reply = if rng.below(2) == 0 {
            let Ok(stamp) = spool.stamp(id.shard) else {
                return false;
            };
            Some(Reply {
                stamp,
                sealed: vec![9; 40],
            })
        } else {
            None
        };
        if !matches!(outcome, Outcome::Deferred { .. }) {
            model.borrow_mut().may_drop.insert(key(id));
        }
        let n = usize::try_from(rng.below(2)).expect("fits");
        calls[n].push(Report {
            recipient: r,
            outcome,
            reply,
        });
    }
    if calls.iter().all(|c| !c.is_empty()) {
        model.borrow_mut().merged += 1;
    }
    for reports in calls.into_iter().filter(|c| !c.is_empty()) {
        tasks.push(spawn(reported(
            spool.clone(),
            id,
            reports,
            Rc::clone(model),
        )));
    }
    let mut ok = true;
    for task in tasks {
        ok &= task.await;
    }
    ok
}

fn recount(spool: &Spool, model: &Model) -> Vec<(u32, u64)> {
    let mut open: BTreeMap<u32, u64> = BTreeMap::new();
    for id in spool.messages() {
        let tenant = model.tenants[&key(id)];
        let count = (0..)
            .map_while(|r| spool.recipient(id, r))
            .filter(|s| !s.status.is_final())
            .count();
        *open.entry(tenant).or_default() += count as u64;
    }
    open.into_iter().filter(|(_, n)| *n > 0).collect()
}

async fn work(spool: Spool, shards: Vec<u16>, steps: u64, seed: u64, model: Shared) -> bool {
    let mut rng = Rng(seed ^ u64::from(shards[0]) << 32);
    let mut live: Vec<MessageId> = Vec::new();
    let closed: Rc<RefCell<BTreeMap<u32, u64>>> = Rc::default();
    let mut opened: BTreeMap<u32, u64> = BTreeMap::new();
    let closing = Rc::clone(&closed);
    spool.on_close(move |tenant, n| *closing.borrow_mut().entry(tenant).or_default() += n);
    for (tenant, n) in spool.open_counts() {
        *opened.entry(tenant).or_default() += n;
    }
    for step in 0..steps {
        live.retain(|id| spool.recipient(*id, 0).is_some());
        if live.len() < 3 || rng.below(3) == 0 {
            let shard = shards[usize::try_from(rng.below(shards.len() as u64)).expect("fits")];
            match accept(&spool, shard, step, &mut rng, &model).await {
                Ok((id, count)) => {
                    assert!(spool.recipient(id, count - 1).is_some());
                    let tenant = model.borrow().tenants[&key(id)];
                    *opened.entry(tenant).or_default() += u64::from(count);
                    model.borrow_mut().accepted.insert(key(id), count);
                    live.push(id);
                }
                Err(e) if expected(&e) => sleep(Duration::from_millis(1)).await,
                Err(_) => return false,
            }
            continue;
        }
        let id = live[usize::try_from(rng.below(live.len() as u64)).expect("fits")];
        let ok = if rng.below(12) == 0 {
            let now = 1000 + steps;
            if !spool.expired(now).contains(&id) {
                return false;
            }
            ended(spool.clone(), id, Some(now), Rc::clone(&model)).await
        } else {
            round(&spool, id, step, &mut rng, &model).await
        };
        if !ok {
            return false;
        }
    }
    let left: Vec<(u32, u64)> = opened
        .iter()
        .map(|(t, n)| (*t, n - closed.borrow().get(t).copied().unwrap_or(0)))
        .filter(|(_, n)| *n > 0)
        .collect();
    assert_eq!(spool.open_counts(), left, "open counts against closes");
    assert_eq!(spool.open_counts(), recount(&spool, &model.borrow()));
    true
}

struct Run {
    driver: Rc<SimDriver>,
    finished: bool,
}

fn workload(seed: u64, steps: u64, halt_after: Option<u64>, disk: Disk, model: &Shared) -> Run {
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
        return Run {
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
            return Run {
                driver,
                finished: false,
            };
        };
        let shards = opened.shards.clone();
        let (spool, owner) = Spool::new(opened, 3, LIMITS).expect("limits");
        owners.push(machine.spawn_on(core, owner.run()));
        closers.push(spool.changes().clone());
        let model = Rc::clone(model);
        workers.push(machine.spawn_on(core, work(spool, shards, steps, seed, model)));
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
    Run { driver, finished }
}

async fn verify(model: &Model) {
    let setup = Setup {
        cores: CORES,
        credits: 4,
        reserve: 0,
    };
    let booted = boot(PATH, setup).await.expect("boot");
    let committer = spawn(booted.committer.run());
    let mut seen = BTreeSet::new();
    for start in booted.starts {
        let core = start.open().await.expect("open");
        let shards = core.shards.clone();
        for &shard in &shards {
            let state = core.keeper.state(shard).expect("kept");
            for k in state.entries().keys() {
                if k.item != HEAD_ITEM {
                    assert!(
                        state.get(store::Key::head(k.message)).is_some(),
                        "item {k:?} without its head"
                    );
                }
            }
        }
        let (spool, owner) = Spool::new(core, 3, LIMITS).expect("rebuild");
        let owner = spawn(owner.run());
        assert_eq!(
            spool.open_counts(),
            recount(&spool, model),
            "open counts after start"
        );
        for id in spool.messages() {
            seen.insert(key(id));
            assert!(model.submitted.contains(&key(id)), "unknown message {id:?}");
        }
        for (&k, &total) in &model.accepted {
            if !shards.contains(&k.0) {
                continue;
            }
            let id = MessageId {
                node: 3,
                shard: k.0,
                key: k.1,
            };
            let present = spool.recipient(id, 0).is_some();
            if model.dropped.contains(&k) {
                assert!(!present, "dropped message {k:?} came back");
                continue;
            }
            if !present {
                assert!(model.may_drop.contains(&k), "message {k:?} lost");
                continue;
            }
            assert!(spool.recipient(id, total - 1).is_some());
            assert!(spool.recipient(id, total).is_none());
            for r in 0..total {
                let state = spool.recipient(id, r).expect("recipient");
                let acked = model.attempts.get(&(k, r)).copied().unwrap_or(0);
                assert!(
                    state.attempts >= acked,
                    "{k:?} recipient {r}: {} attempts, {acked} acknowledged",
                    state.attempts
                );
                if model.finals.contains(&(k, r)) {
                    assert!(state.status.is_final(), "{k:?} recipient {r} final");
                }
                if state.status == Status::Ready {
                    assert_eq!(state.attempts, 0);
                }
            }
        }
        spool.changes().close();
        drop(owner.await);
    }
    drop(booted.client);
    drop(committer.await);
    let present = model
        .accepted
        .keys()
        .filter(|k| !model.may_drop.contains(k))
        .all(|k| seen.contains(k));
    assert!(present, "every message without a drop request is back");
}

fn after(driver: &SimDriver, seed: u64, model: &Shared) {
    let after = Rc::new(SimDriver::with_disk(
        seed,
        Config::default(),
        driver.crash(),
    ));
    let model = model.take();
    Runtime::new(after).block_on(async move { verify(&model).await });
}

#[test]
fn recipient_states_and_drops_match_what_was_acknowledged() {
    let model = Shared::default();
    let run = workload(1, 150, None, created(1), &model);
    assert!(run.finished, "workload finished");
    {
        let model = model.borrow();
        assert!(model.dropped.len() > 20, "{} dropped", model.dropped.len());
        assert!(model.merged > 20, "{} merged rounds", model.merged);
        assert!(
            model.waited > 3,
            "{} cancels with open claims",
            model.waited
        );
        assert!(model.finals.len() > 50, "{} finals", model.finals.len());
    }
    after(&run.driver, 2, &model);
}

fn crash_at(seed: u64, steps: u64, point: u64) {
    let model = Shared::default();
    let run = workload(seed, steps, Some(point), created(seed), &model);
    assert!(run.driver.is_halted(), "crash point {point} not reached");
    after(&run.driver, seed + 1, &model);
}

fn sampled(seed: u64, total: u64) -> Vec<u64> {
    let stride = total.div_ceil(200).max(1);
    let first = 1 + seed % stride;
    (first..=total)
        .step_by(usize::try_from(stride).expect("fits"))
        .collect()
}

#[test]
fn recipient_states_survive_a_crash_at_every_disk_operation() {
    let only = env::var("SIM_CRASH_AT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let steps = 60;
    check(0..1, |seed| {
        let model = Shared::default();
        let run = workload(seed, steps, None, created(seed), &model);
        assert!(run.finished, "workload ran");
        let total = run.driver.disk_ops();
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
