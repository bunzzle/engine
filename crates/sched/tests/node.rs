use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, sleep, spawn, timeout};
use sched::{
    Answer, Answered, Arrival, Attempt, Clock, Kind, Limits, Mesh, Note, Sched, Transport,
};
use spool::{Body, Head, HeadClear, Message, MessageId, SLICE, Slice, Spool};
use store::{Client, DataFile, Keeper, Options, SLOT_SIZE, Setup, boot};

const PATH: &str = "/data/store";
const SHARDS: u16 = 4;
const CORES: u16 = 2;
const MESSAGES: u64 = 30;
const SLACK: u64 = 1_000;
const HORIZON: Duration = Duration::from_hours(7 * 24);
const FIRST: Duration = Duration::from_mins(30);
const MILLION: u32 = 1_000_000;

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 64,
    shards: SHARDS as u32,
};

const LIMITS: spool::Limits = spool::Limits {
    recipients: 3000,
    inline: 2048,
    body: 512 * 1024,
};

type MessageKey = (u16, u64);
type Key = (u16, u64, u32);

#[derive(Default)]
struct World {
    recipients: BTreeSet<Key>,
    submitted: BTreeSet<Key>,
    queues: BTreeMap<Key, u32>,
    misrouted: u64,
    in_attempt: BTreeSet<Key>,
    finals: BTreeMap<Key, u32>,
    durable: BTreeSet<Key>,
    expiries: BTreeMap<MessageKey, u64>,
    cancelling: BTreeSet<MessageKey>,
    overlaps: u64,
    early: u64,
    again: u64,
    attempts: u64,
    replies: u64,
    restored: u64,
    spools: Vec<Spool>,
}

type Shared = Rc<RefCell<World>>;

fn key(id: MessageId, r: u32) -> Key {
    (id.shard, id.key, r)
}

struct Simulated {
    world: Shared,
    driver: Rc<SimDriver>,
    clock: Clock,
}

impl Simulated {
    fn below(&self, n: u64) -> u64 {
        self.driver.random() % n
    }

    fn answer(&self) -> Answer {
        match self.below(20) {
            0..=9 => Answer::Delivered,
            10..=11 => Answer::Failed,
            12..=14 => Answer::Deferred(Kind::Temporary),
            15 => Answer::Deferred(Kind::Greylisted),
            16 => Answer::Deferred(Kind::Throttled),
            17 => Answer::Deferred(Kind::MailboxFull),
            _ => Answer::Deferred(Kind::RetryAfter(self.below(3_600_000))),
        }
    }
}

impl Transport for Simulated {
    async fn send(&self, attempt: Attempt) -> Vec<Answered> {
        let now = self.clock.now();
        {
            let mut world = self.world.borrow_mut();
            world.attempts += 1;
            let owner = usize::from(attempt.message.shard % CORES);
            let spool = world.spools[owner].clone();
            for c in &attempt.recipients {
                let k = key(attempt.message, c.recipient);
                let state = spool
                    .recipient(attempt.message, c.recipient)
                    .expect("claimed recipient");
                if state.due > now + SLACK {
                    world.early += 1;
                }
                if world.queues.get(&k) != Some(&attempt.queue) {
                    world.misrouted += 1;
                }
                if world.durable.contains(&k) {
                    world.again += 1;
                }
                if !world.in_attempt.insert(k) {
                    world.overlaps += 1;
                }
            }
        }
        sleep(Duration::from_millis(1 + self.below(2_000))).await;
        let mut world = self.world.borrow_mut();
        attempt
            .recipients
            .iter()
            .map(|c| {
                let k = key(attempt.message, c.recipient);
                world.in_attempt.remove(&k);
                let answer = self.answer();
                if matches!(answer, Answer::Delivered | Answer::Failed) {
                    *world.finals.entry(k).or_default() += 1;
                }
                let reply = if self.below(3) == 0 {
                    world.replies += 1;
                    vec![9; 24]
                } else {
                    Vec::new()
                };
                Answered {
                    recipient: c.recipient,
                    answer,
                    reply,
                }
            })
            .collect()
    }
}

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

fn message(id: MessageId, now: u64, driver: &SimDriver, expiring: bool) -> Message {
    let tenant = u32::try_from(driver.random() % 3).expect("small");
    let count = 1 + usize::try_from(driver.random() % 40).expect("small");
    let queues: Vec<u32> = (0..count)
        .map(|_| tenant * 10 + u32::try_from(driver.random() % 5).expect("small"))
        .collect();
    let not_before = if expiring || driver.random().is_multiple_of(5) {
        now + 1_800_000
    } else {
        0
    };
    let expiry = if expiring {
        now + 600_000
    } else if driver.random().is_multiple_of(5) {
        now + driver.random() % 7_200_000
    } else {
        u64::MAX / 2
    };
    let slices = queues
        .chunks(SLICE as usize)
        .map(|chunk| Slice {
            queues: chunk.to_vec(),
            sealed: vec![6; 4 * chunk.len()],
        })
        .collect();
    Message {
        id,
        tenant,
        head: Head {
            clear: HeadClear {
                recipients: u32::try_from(count).expect("small"),
                accepted: now,
                not_before,
                ..HeadClear::default()
            },
            expiry,
            sealed: vec![1; 64],
        },
        body: Body::Inline(vec![2; 300]),
        slices,
    }
}

async fn intake(
    spool: Spool,
    sched: Sched<Simulated>,
    shards: Vec<u16>,
    driver: Rc<SimDriver>,
    world: Shared,
) {
    for n in 0..MESSAGES {
        let shard = shards[usize::try_from(n).expect("small") % shards.len()];
        let Ok(id) = spool.id(shard).await else {
            return;
        };
        let message = message(id, sched.clock().now(), &driver, n == 0);
        let arrival = Arrival::of(&message);
        let count = u32::try_from(arrival.queues.len()).expect("small");
        {
            let mut world = world.borrow_mut();
            world
                .expiries
                .insert((id.shard, id.key), message.head.expiry);
            for (r, queue) in (0..count).zip(&arrival.queues) {
                world.submitted.insert(key(id, r));
                world.queues.insert(key(id, r), *queue);
            }
        }
        if spool.accept(vec![message]).await.is_err() {
            return;
        }
        {
            let mut world = world.borrow_mut();
            for r in 0..count {
                world.recipients.insert(key(id, r));
            }
        }
        if driver.random().is_multiple_of(4) {
            let mut stale = arrival.clone();
            stale.due = 0;
            sched.enqueue(stale);
        }
        sched.enqueue(arrival);
        if n > 0 && driver.random().is_multiple_of(6) {
            let spool = spool.clone();
            let wait = Duration::from_millis(driver.random() % 3_000);
            world.borrow_mut().cancelling.insert((id.shard, id.key));
            drop(spawn(async move {
                sleep(wait).await;
                let _ = spool.cancel(id).await;
            }));
        }
        if driver.random().is_multiple_of(3) {
            sleep(Duration::from_millis(driver.random() % 500)).await;
        }
    }
}

fn config() -> sched::Config {
    sched::Config {
        limits: Limits {
            active: 60,
            queue: 12,
            batch: 7,
            ..Limits::default()
        },
        slack: SLACK,
        ..sched::Config::new(u32::from(SHARDS))
    }
}

async fn settle(world: &Shared) {
    loop {
        sleep(Duration::from_secs(10)).await;
        let empty = world
            .borrow()
            .spools
            .iter()
            .all(|s| s.messages().is_empty());
        if empty {
            return;
        }
    }
}

fn ticker(client: Client, running: Rc<Cell<bool>>) -> JoinHandle<()> {
    spawn(async move {
        while running.get() {
            sleep(Duration::from_secs(20)).await;
            if client.checkpoint().await.is_err() {
                return;
            }
        }
    })
}

async fn halted(driver: Rc<SimDriver>) {
    while !driver.is_halted() {
        sleep(Duration::from_secs(1)).await;
    }
}

fn durable(world: &mut World) {
    let spools = world.spools.clone();
    let mut finals = BTreeSet::new();
    for &(shard, message, r) in &world.submitted {
        let id = MessageId {
            node: 3,
            shard,
            key: message,
        };
        let spool = &spools[usize::from(shard % CORES)];
        if spool.recipient(id, r).is_none_or(|s| s.status.is_final()) {
            finals.insert((shard, message, r));
        }
    }
    world.durable = finals;
}

#[derive(Default)]
struct Session {
    finished: bool,
    overdue: usize,
    errors: u64,
    expired: u64,
}

type Feed = (usize, Spool, Vec<u16>);

type Started = (
    Vec<Sched<Simulated>>,
    Vec<JoinHandle<()>>,
    Vec<Feed>,
    Vec<JoinHandle<Keeper>>,
    Vec<store::Changes>,
);

fn start_cores(
    machine: &Machine,
    starts: Vec<store::Start>,
    driver: &Rc<SimDriver>,
    world: &Shared,
) -> Option<Started> {
    let mesh = Arc::new(Mesh::<Note>::new(CORES));
    let mut started: Started = Default::default();
    for start in starts {
        let index = start.index();
        let core = usize::from(index) + 1;
        let (spool, owner, pending) = machine.block_on(core, async move {
            let core = timeout(Duration::from_secs(60), start.open())
                .await
                .ok()?
                .ok()?;
            timeout(Duration::from_secs(60), Spool::open(core, 3, LIMITS))
                .await
                .ok()?
                .ok()
        })?;
        let shards: Vec<u16> = (0..SHARDS).filter(|s| s % CORES == index).collect();
        world.borrow_mut().spools.push(spool.clone());
        world.borrow_mut().restored += pending.len() as u64;
        started.3.push(machine.spawn_on(core, owner.run()));
        started.4.push(spool.changes().clone());
        let ends = mesh.take(index).expect("ends");
        let transport_world = Rc::clone(world);
        let transport_driver = Rc::clone(driver);
        let opened = spool.clone();
        let (sched, done) = machine.block_on(core, async move {
            let clock = Clock::start();
            let transport = Simulated {
                world: transport_world,
                driver: transport_driver,
                clock,
            };
            let (sched, done) = Sched::start(ends, opened, transport, clock, config());
            sched.restore(pending);
            (sched, done)
        });
        started.1.push(done);
        started.2.push((core, spool, shards));
        started.0.push(sched);
    }
    Some(started)
}

fn session(driver: &Rc<SimDriver>, world: &Shared, intake_on: bool, limit: Duration) -> Session {
    let stalls = Stalls {
        per_mille: 50,
        max: Duration::from_millis(5),
    };
    let machine = Machine::new(Rc::clone(driver), usize::from(CORES) + 1, stalls);
    let setup = Setup {
        cores: CORES,
        credits: 4,
        reserve: 0,
    };
    let Ok(Ok(booted)) = machine.block_on(0, async move {
        timeout(Duration::from_secs(60), boot(PATH, setup)).await
    }) else {
        return Session::default();
    };
    let committer = machine.spawn_on(0, booted.committer.run());
    world.borrow_mut().spools.clear();
    world.borrow_mut().in_attempt.clear();
    let Some((scheds, meshes, feeds, owners, closers)) =
        start_cores(&machine, booted.starts, driver, world)
    else {
        return Session::default();
    };
    durable(&mut world.borrow_mut());
    let mut intakes = Vec::new();
    if intake_on {
        for ((core, spool, shards), sched) in feeds.into_iter().zip(&scheds) {
            let feed = intake(
                spool,
                sched.clone(),
                shards,
                Rc::clone(driver),
                Rc::clone(world),
            );
            intakes.push(machine.spawn_on(core, feed));
        }
    }
    let client = booted.client;
    let watched = Rc::clone(world);
    let power = Rc::clone(driver);
    let result = machine.block_on(0, async move {
        let running = Rc::new(Cell::new(true));
        let ticker = ticker(client.clone(), Rc::clone(&running));
        let settled = Rc::clone(&watched);
        let mut work = pin!(async move {
            for feed in intakes {
                feed.await;
            }
            settle(&settled).await;
        });
        let mut halt = pin!(halted(Rc::clone(&power)));
        let race = poll_fn(|cx| {
            if work.as_mut().poll(cx).is_ready() {
                return Poll::Ready(true);
            }
            halt.as_mut().poll(cx).map(|()| false)
        });
        let finished = matches!(timeout(limit, race).await, Ok(true));
        running.set(false);
        let session = Session {
            finished,
            overdue: scheds.iter().map(Sched::overdue).sum(),
            errors: scheds.iter().map(Sched::report_errors).sum(),
            expired: scheds.iter().map(Sched::expired).sum(),
        };
        if power.is_halted() {
            return session;
        }
        let stop = async move {
            ticker.await;
            for sched in &scheds {
                sched.close();
            }
            for done in meshes {
                done.await;
            }
            for closer in closers {
                closer.close();
            }
            for owner in owners {
                drop(owner.await);
            }
            drop(scheds);
            watched.borrow_mut().spools.clear();
            drop(client);
            drop(committer.await);
        };
        let _ = timeout(Duration::from_secs(600), stop).await;
        session
    });
    world.borrow_mut().spools.clear();
    result
}

fn verify(seed: u64, world: &World) {
    assert_eq!(world.overlaps, 0, "seed {seed}: recipient in two attempts");
    assert_eq!(world.early, 0, "seed {seed}: attempt before due");
    assert_eq!(world.again, 0, "seed {seed}: durable final attempted again");
    assert_eq!(
        world.misrouted, 0,
        "seed {seed}: attempt in the wrong queue"
    );
    let finals: BTreeSet<Key> = world.finals.keys().copied().collect();
    assert!(finals.is_subset(&world.submitted));
    for &(shard, message, r) in world.recipients.difference(&finals) {
        let cancelled = world.cancelling.contains(&(shard, message));
        let expires = world.expiries[&(shard, message)] < u64::MAX / 2;
        assert!(
            cancelled || expires,
            "seed {seed}: recipient {r} of ({shard}, {message}) never final"
        );
    }
    assert!(world.attempts > 0);
}

fn one_session(seed: u64) {
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let world: Shared = Rc::default();
    let run = session(&driver, &world, true, HORIZON);
    assert!(run.finished, "seed {seed}: not every message finished");
    assert_eq!(run.overdue, 0, "seed {seed}: attempt over the bound");
    assert_eq!(run.errors, 0, "seed {seed}: report refused");
    assert!(run.expired > 0, "seed {seed}: no expiry ran");
    let world = world.borrow();
    verify(seed, &world);
    assert!(
        world.finals.values().all(|n| *n == 1),
        "seed {seed}: final answer twice"
    );
    assert!(world.replies > 0);
}

fn restart(seed: u64) {
    let world: Shared = Rc::default();
    let config = Config {
        halt_after: Some(200 + seed * 7_919 % 4_000),
        faults: Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        },
        ..Config::default()
    };
    let first = Rc::new(SimDriver::with_disk(seed, config, created(seed)));
    session(&first, &world, true, FIRST);
    let second = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        first.crash(),
    ));
    let run = session(&second, &world, false, HORIZON);
    assert!(
        run.finished,
        "seed {seed}: not every message finished after restart"
    );
    assert_eq!(run.overdue, 0, "seed {seed}: attempt over the bound");
    assert!(world.borrow().restored > 0, "seed {seed}: nothing restored");
    verify(seed, &world.borrow());
}

#[test]
fn every_recipient_is_attempted_until_final_once_at_a_time() {
    check(0..8, one_session);
}

#[test]
fn queues_are_rebuilt_after_a_crash_and_finish() {
    check(0..12, restart);
}
