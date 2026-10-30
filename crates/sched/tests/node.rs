use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use rt::sim::{Config, Disk, Machine, SimDriver, Stalls, check};
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

type Key = (u16, u64, u32);

#[derive(Default)]
struct World {
    recipients: BTreeSet<Key>,
    in_attempt: BTreeSet<Key>,
    finals: BTreeMap<Key, u32>,
    overlaps: u64,
    early: u64,
    attempts: u64,
    replies: u64,
    cancelled: BTreeSet<(u16, u64)>,
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
                let state = spool
                    .recipient(attempt.message, c.recipient)
                    .expect("claimed recipient");
                if state.due > now + SLACK {
                    world.early += 1;
                }
                if !world.in_attempt.insert(key(attempt.message, c.recipient)) {
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

fn message(id: MessageId, now: u64, driver: &SimDriver) -> Message {
    let tenant = u32::try_from(driver.random() % 3).expect("small");
    let count = 1 + usize::try_from(driver.random() % 40).expect("small");
    let queues: Vec<u32> = (0..count)
        .map(|_| tenant * 10 + u32::try_from(driver.random() % 5).expect("small"))
        .collect();
    let not_before = if driver.random().is_multiple_of(5) {
        now + 1_800_000
    } else {
        0
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
            expiry: u64::MAX / 2,
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
        let id = spool.id(shard).await.expect("id");
        let message = message(id, sched.clock().now(), &driver);
        let arrival = Arrival::of(&message);
        spool.accept(vec![message]).await.expect("accept");
        {
            let mut world = world.borrow_mut();
            for r in 0..u32::try_from(arrival.queues.len()).expect("small") {
                world.recipients.insert(key(id, r));
            }
        }
        if driver.random().is_multiple_of(4) {
            let mut stale = arrival.clone();
            stale.due = 0;
            sched.enqueue(stale);
        }
        sched.enqueue(arrival);
        if driver.random().is_multiple_of(6) {
            let spool = spool.clone();
            let world = Rc::clone(&world);
            let wait = Duration::from_millis(driver.random() % 3_000);
            drop(spawn(async move {
                sleep(wait).await;
                if spool.cancel(id).await.is_ok() {
                    world.borrow_mut().cancelled.insert((id.shard, id.key));
                }
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

fn run(seed: u64) {
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let stalls = Stalls {
        per_mille: 50,
        max: Duration::from_millis(5),
    };
    let machine = Machine::new(Rc::clone(&driver), usize::from(CORES) + 1, stalls);
    let setup = Setup {
        cores: CORES,
        credits: 4,
        reserve: 0,
    };
    let booted = machine
        .block_on(0, async move { boot(PATH, setup).await })
        .expect("boot");
    let committer = machine.spawn_on(0, booted.committer.run());
    let world: Shared = Rc::default();
    let mesh = Arc::new(Mesh::<Note>::new(CORES));
    let mut owners: Vec<JoinHandle<Keeper>> = Vec::new();
    let mut scheds = Vec::new();
    let mut intakes = Vec::new();
    let mut closers = Vec::new();
    let mut meshes = Vec::new();
    for start in booted.starts {
        let index = start.index();
        let core = usize::from(index) + 1;
        let opened = machine
            .block_on(core, async move { start.open().await })
            .expect("open");
        let shards = opened.shards.clone();
        let (spool, owner) = Spool::new(opened, 3, LIMITS).expect("limits");
        world.borrow_mut().spools.push(spool.clone());
        owners.push(machine.spawn_on(core, owner.run()));
        closers.push(spool.changes().clone());
        let ends = mesh.take(index).expect("ends");
        let transport_world = Rc::clone(&world);
        let transport_driver = Rc::clone(&driver);
        let started = spool.clone();
        let (sched, done) = machine.block_on(core, async move {
            let clock = Clock::start();
            let transport = Simulated {
                world: transport_world,
                driver: transport_driver,
                clock,
            };
            Sched::start(ends, started, transport, clock, config())
        });
        meshes.push(done);
        let feed = machine.spawn_on(
            core,
            intake(
                spool,
                sched.clone(),
                shards,
                Rc::clone(&driver),
                Rc::clone(&world),
            ),
        );
        intakes.push(feed);
        scheds.push(sched);
    }
    let client = booted.client;
    let watched = Rc::clone(&world);
    let finished = machine.block_on(0, async move {
        let work = async move {
            for feed in intakes {
                feed.await;
            }
            let running = Rc::new(Cell::new(true));
            let ticker = ticker(client.clone(), Rc::clone(&running));
            settle(&watched).await;
            running.set(false);
            ticker.await;
            let overdue: usize = scheds.iter().map(Sched::overdue).sum();
            let errors: u64 = scheds.iter().map(Sched::report_errors).sum();
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
            (overdue, errors)
        };
        timeout(HORIZON, work).await
    });
    let Ok((overdue, errors)) = finished else {
        panic!("seed {seed}: not every message finished");
    };
    verify(seed, &world.borrow(), overdue, errors);
}

fn verify(seed: u64, world: &World, overdue: usize, errors: u64) {
    assert_eq!(overdue, 0, "seed {seed}: attempt over the bound");
    assert_eq!(world.overlaps, 0, "seed {seed}: recipient in two attempts");
    assert_eq!(world.early, 0, "seed {seed}: attempt before due");
    assert_eq!(errors, 0, "seed {seed}: report refused");
    let finals: BTreeSet<Key> = world.finals.keys().copied().collect();
    assert!(finals.is_subset(&world.recipients));
    for (shard, message, r) in world.recipients.difference(&finals) {
        assert!(
            world.cancelled.contains(&(*shard, *message)),
            "seed {seed}: recipient {r} of ({shard}, {message}) never final"
        );
    }
    assert!(!world.cancelled.is_empty(), "seed {seed}: no cancel ran");
    assert!(
        world.finals.values().all(|n| *n == 1),
        "seed {seed}: final answer twice"
    );
    assert!(world.replies > 0 && world.attempts > 0);
}

#[test]
fn every_recipient_is_attempted_until_final_once_at_a_time() {
    check(0..8, run);
}
