use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::future::poll_fn;
use std::panic::{self, AssertUnwindSafe};
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

use rt::sim::{Config, Disk, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, sleep, spawn, timeout};
use store::{
    Body, Change, Claim, Client, Committer, CoreFile, DataFile, Dead, Delivery, Error, Event,
    Index, Item, KIND_STATE, Keeper, Key, Location, MAX_DELTAS, Options, Part, Range, Results,
    Root, SLOT_SIZE, Session, Setup, ShardState, Source, Start, Submission, Write, boot,
    encode_roots, load, read_run, recover,
};

const PATH: &str = "/data/store";
const SHARDS: u16 = 4;

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: SHARDS as u32,
};

fn run<T: 'static>(seed: u64, future: impl Future<Output = T> + 'static) -> T {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), setup.crash()));
    Runtime::new(driver).block_on(future)
}

async fn start(
    sessions: u32,
) -> (
    Client,
    Vec<(Session, Results)>,
    Source,
    JoinHandle<Committer>,
) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    let (mut committer, client) = Committer::new(data, recovered.journal, recovered.state);
    committer.set_part_timeout(Duration::from_secs(5));
    let sessions = (0..sessions)
        .map(|_| committer.session(&client, 8))
        .collect();
    let source = committer.source();
    (client, sessions, source, spawn(committer.run()))
}

struct Core {
    session: Session,
    results: Results,
    keeper: Keeper,
    data: CoreFile,
    sent: BTreeMap<u64, (u16, Vec<Index>)>,
    tag: u64,
}

impl Core {
    async fn new(pair: (Session, Results), source: &Source) -> Self {
        Self::owning(pair, source, &ALL).await
    }

    async fn owning(
        (session, results): (Session, Results),
        source: &Source,
        shards: &[u16],
    ) -> Self {
        let mut keeper = Keeper::default();
        for &shard in shards {
            keeper.insert(shard, ShardState::default(), Vec::new());
        }
        Self {
            session,
            results,
            keeper,
            data: source.open().await.expect("open"),
            sent: BTreeMap::new(),
            tag: 0,
        }
    }

    async fn change(&mut self, shard: u16, index: Index) {
        self.changes(shard, vec![index]).await;
    }

    async fn changes(&mut self, shard: u16, indexes: Vec<Index>) {
        let records = indexes
            .iter()
            .map(|index| Write {
                kind: KIND_STATE,
                counted: true,
                shard,
                tenant: index.tenant,
                payload: index.payload(&[0xCD; 32]),
            })
            .collect();
        let submission = Submission {
            claim: Claim::Intake,
            records,
            bodies: Vec::new(),
            dead: Vec::new(),
        };
        self.tag += 1;
        self.sent.insert(self.tag, (shard, indexes));
        self.session.submit(self.tag, submission).expect("credit");
        while !self.sent.is_empty() {
            self.pump().await;
        }
    }

    async fn pump(&mut self) -> Event {
        let event = self.results.recv().await.expect("event");
        match &event {
            Event::Durable {
                tag,
                sequence,
                locations,
            } => {
                let (shard, indexes) = self.sent.remove(tag).expect("sent");
                for (index, location) in indexes.iter().zip(locations) {
                    self.keeper
                        .apply(shard, index, &[], &[], *location, *sequence);
                }
            }
            Event::Rejected { error, .. } => panic!("rejected: {error:?}"),
            Event::Cut { sequence } => {
                self.keeper
                    .cut(&self.session, &self.data, *sequence)
                    .await
                    .expect("cut");
            }
            Event::Published { sequence } => self.keeper.published(*sequence),
            Event::Abandoned { sequence } => self.keeper.abandoned(*sequence),
            Event::Compact { .. } => panic!("no survey was sent"),
        }
        event
    }

    async fn checkpoint(&mut self, client: &Client) -> Result<u64, Error> {
        let client = client.clone();
        let request = spawn(async move { client.checkpoint().await });
        loop {
            if matches!(
                self.pump().await,
                Event::Published { .. } | Event::Abandoned { .. }
            ) {
                return request.await;
            }
        }
    }

    async fn check(&self) {
        for shard in 0..SHARDS {
            let Some(roots) = self.keeper.roots(shard) else {
                continue;
            };
            assert!(roots.len() <= MAX_DELTAS + 1);
            assert!(roots.first().is_none_or(|r| r.base));
            let state = self.keeper.state(shard).expect("kept");
            assert_eq!(&fold(&self.data, shard, roots).await, state.entries());
        }
    }
}

async fn fold(data: &CoreFile, shard: u16, roots: &[Root]) -> BTreeMap<Key, Item> {
    let mut map = BTreeMap::new();
    for root in roots {
        let run = read_run(data, root, shard).await.expect("run");
        if run.base {
            map.clear();
        }
        for (key, item) in run.changes {
            match item {
                Some(item) => map.insert(key, item),
                None => map.remove(&key),
            };
        }
    }
    map
}

fn put(key: u64, status: u8) -> Index {
    Index {
        key: Key::head(key),
        tenant: 7,
        change: Change::Put(Delivery {
            status,
            attempts: 1,
            due: 500 + key,
        }),
    }
}

fn delete(key: u64) -> Index {
    Index {
        key: Key::head(key),
        tenant: 7,
        change: Change::Delete,
    }
}

#[test]
fn runs_hold_the_shard_state_across_checkpoints_and_restarts() {
    run(21, async {
        let (client, mut sessions, source, committer) = start(1).await;
        let mut core = Core::new(sessions.remove(0), &source).await;
        let mut deltas = 0;
        let mut bases = 0;
        for round in 0..60u64 {
            let shard = u16::try_from(round % u64::from(SHARDS)).expect("fits");
            for step in 0..=round % 4 {
                let key = (round * 7 + step * 3) % 40;
                let index = if (round + step) % 5 == 4 {
                    delete(key)
                } else {
                    put(key, u8::try_from(round % 200).expect("fits"))
                };
                core.change(shard, index).await;
            }
            let before = core.keeper.roots(shard).expect("kept").to_vec();
            core.checkpoint(&client).await.expect("checkpoint");
            let after = core.keeper.roots(shard).expect("kept");
            if after.len() == 1 {
                bases += 1;
            } else {
                assert_eq!(&after[..before.len()], before.as_slice());
                deltas += 1;
            }
            core.check().await;
            let data = DataFile::open(PATH).await.expect("open");
            let loaded = load(&data, 0).await.expect("load");
            for part in &loaded.parts {
                let roots = store::decode_roots(&part.bytes).expect("roots");
                assert_eq!(roots, core.keeper.roots(part.tag).expect("kept"));
            }
        }
        assert!(
            bases > 1 && deltas > MAX_DELTAS,
            "{bases} bases, {deltas} deltas"
        );
        let expected: Vec<BTreeMap<Key, Item>> = (0..SHARDS)
            .map(|s| core.keeper.state(s).expect("kept").entries().clone())
            .collect();
        drop(client);
        drop(core);
        let committer = committer.await;
        let regions = committer.regions();
        assert!(
            regions.count() - regions.free() <= 8,
            "{} regions still used",
            regions.count() - regions.free()
        );
        drop(committer);
        let data = DataFile::open(PATH).await.expect("reopen");
        let loaded = load(&data, 0).await.expect("load");
        drop(data);
        let file = core_file().await;
        assert_ne!(loaded.state.runs.len(), 0);
        for &region in &loaded.state.runs {
            assert!(loaded.state.regions.is_used(region));
        }
        for part in &loaded.parts {
            let roots = store::decode_roots(&part.bytes).expect("roots");
            let shard = part.tag;
            assert_eq!(
                fold(&file, shard, &roots).await,
                expected[usize::from(shard)]
            );
        }
        assert_eq!(loaded.parts.len(), usize::from(SHARDS));
    });
}

fn fail_cut(session: Session, mut results: Results, failing: u32) -> JoinHandle<()> {
    spawn(async move {
        let mut cuts = 0;
        while let Some(event) = results.recv().await {
            if let Event::Cut { sequence } = event {
                if cuts == failing {
                    session.fail(sequence).expect("fail");
                } else {
                    let parts = [1, 3]
                        .map(|tag| Part {
                            tag,
                            replay_sequence: sequence,
                            bytes: encode_roots(&[]),
                        })
                        .to_vec();
                    session.parts(sequence, parts).expect("parts");
                }
                cuts += 1;
            }
        }
    })
}

#[test]
fn an_abandoned_cut_keeps_its_changes_for_the_next_one() {
    run(22, async {
        let (client, mut sessions, source, _committer) = start(2).await;
        let other = sessions.pop().expect("second");
        let _failing = fail_cut(other.0, other.1, 1);
        let mut core = Core::owning(sessions.remove(0), &source, &[0, 2]).await;
        for key in 0..5 {
            core.change(2, put(key, 1)).await;
        }
        core.checkpoint(&client).await.expect("checkpoint");
        let base = core.keeper.roots(2).expect("kept").to_vec();
        assert_eq!(base.len(), 1);
        core.change(2, delete(2)).await;
        core.change(2, put(6, 3)).await;
        assert!(matches!(
            core.checkpoint(&client).await,
            Err(Error::Invalid("part"))
        ));
        assert_eq!(core.keeper.roots(2).expect("kept"), base.as_slice());
        core.change(2, put(9, 4)).await;
        core.checkpoint(&client).await.expect("checkpoint");
        let roots = core.keeper.roots(2).expect("kept");
        assert_eq!(roots.len(), 2, "the next cut writes a delta");
        let entries = fold(&core.data, 2, roots).await;
        let keys: Vec<u64> = entries.keys().map(|k| k.message).collect();
        assert_eq!(keys, vec![0, 1, 3, 4, 6, 9]);
        core.check().await;
    });
}

#[test]
fn a_root_outside_the_state_regions_abandons_the_checkpoint() {
    run(23, async {
        let (client, mut sessions, _source, _committer) = start(1).await;
        let (session, mut results) = sessions.remove(0);
        let answer = spawn(async move {
            while let Some(event) = results.recv().await {
                if let Event::Cut { sequence } = event {
                    let root = Root {
                        region: 5,
                        base: true,
                        epoch: 0,
                        offset: 0,
                        length: 4096,
                        checksum: 0,
                        covered: sequence - 1,
                    };
                    let part = Part {
                        tag: 0,
                        replay_sequence: sequence,
                        bytes: encode_roots(&[root]),
                    };
                    session.parts(sequence, vec![part]).expect("parts");
                    return;
                }
            }
        });
        assert!(matches!(
            client.checkpoint().await,
            Err(Error::Invalid("part"))
        ));
        answer.await;
    });
}

#[test]
fn bodies_and_dead_entries_cannot_point_into_state_regions() {
    run(24, async {
        let (client, mut sessions, source, committer) = start(1).await;
        let mut core = Core::new(sessions.remove(0), &source).await;
        core.change(0, put(1, 1)).await;
        core.checkpoint(&client).await.expect("checkpoint");
        let root = core.keeper.roots(0).expect("kept")[0];
        let body = Submission {
            claim: Claim::Intake,
            records: Vec::new(),
            bodies: vec![Body {
                shard: 0,
                tenant: 7,
                range: Range {
                    region: root.region,
                    epoch: root.epoch,
                    offset: root.offset,
                    length: root.length,
                    checksum: root.checksum,
                },
            }],
            dead: Vec::new(),
        };
        core.session.submit(1, body).expect("credit");
        assert!(matches!(
            core.results.recv().await,
            Some(Event::Rejected {
                tag: 1,
                error: Error::Invalid("range")
            })
        ));
        let dead = Submission {
            claim: Claim::Intake,
            records: Vec::new(),
            bodies: Vec::new(),
            dead: vec![Dead {
                tenant: 7,
                region: root.region,
                epoch: root.epoch,
                offset: root.offset,
                length: root.length,
            }],
        };
        assert!(matches!(
            client.commit(dead).await,
            Err(Error::Invalid("dead"))
        ));
        drop(client);
        drop(core);
        let committer = committer.await;
        assert!(!committer.usage().is_quarantined(root.region));
    });
}

#[test]
fn a_new_base_follows_the_last_allowed_delta() {
    run(25, async {
        let (client, mut sessions, source, _committer) = start(1).await;
        let mut core = Core::new(sessions.remove(0), &source).await;
        for chunk in 0..4 {
            core.changes(
                2,
                (chunk * 200..(chunk + 1) * 200)
                    .map(|k| put(k, 1))
                    .collect(),
            )
            .await;
        }
        core.checkpoint(&client).await.expect("checkpoint");
        let mut lengths = Vec::new();
        for round in 0..=MAX_DELTAS as u64 {
            core.change(2, put(round, 2)).await;
            core.checkpoint(&client).await.expect("checkpoint");
            lengths.push(core.keeper.roots(2).expect("kept").len());
        }
        let mut expected: Vec<usize> = (2..=MAX_DELTAS + 1).collect();
        expected.push(1);
        assert_eq!(lengths, expected);
        core.check().await;
    });
}

const ALL: [u16; SHARDS as usize] = [0, 1, 2, 3];

async fn core_file() -> CoreFile {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    let (committer, _client) = Committer::new(data, recovered.journal, recovered.state);
    committer.source().open().await.expect("open")
}

async fn rebuild(shards: &[u16]) -> Keeper {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let parts = loaded.parts.clone();
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    drop(data);
    let file = core_file().await;
    Keeper::rebuild(&file, &parts, &recovered.entries, shards)
        .await
        .expect("rebuild")
}

fn moved(core: &Core, shard: u16, key: u64) -> Index {
    let old = core
        .keeper
        .state(shard)
        .expect("kept")
        .get(Key::head(key))
        .expect("present");
    Index {
        key: Key::head(key),
        tenant: 7,
        change: Change::Move { old: old.location },
    }
}

#[test]
fn a_restart_rebuilds_runs_and_the_journal_after_them() {
    run(26, async {
        let (client, mut sessions, source, committer) = start(1).await;
        let mut core = Core::new(sessions.remove(0), &source).await;
        for round in 0..12u64 {
            let shard = u16::try_from(round % 4).expect("fits");
            core.changes(shard, (0..6).map(|k| put(round + k, 1)).collect())
                .await;
            if round % 3 == 2 {
                core.change(shard, delete(round)).await;
                let index = moved(&core, shard, round + 1);
                core.change(shard, index).await;
                core.checkpoint(&client).await.expect("checkpoint");
            }
        }
        let lease = client.allocate(Claim::Intake).await.expect("lease");
        let bytes = vec![0x5A; 4096];
        let at = core.data.region_offset(lease.region());
        let (written, _) = core
            .data
            .file()
            .write_all_at(rt::Buf::from_slice(&bytes), at)
            .await;
        written.expect("write body");
        let body = Submission {
            claim: Claim::Intake,
            records: vec![Write {
                kind: KIND_STATE,
                counted: true,
                shard: 1,
                tenant: 7,
                payload: put(99, 9).payload(&[2; 16]),
            }],
            bodies: vec![Body {
                shard: 0,
                tenant: 7,
                range: Range {
                    region: lease.region(),
                    epoch: lease.epoch(),
                    offset: 0,
                    length: 4096,
                    checksum: store::checksum(&bytes),
                },
            }],
            dead: Vec::new(),
        };
        core.tag += 1;
        core.sent.insert(core.tag, (1, vec![put(99, 9)]));
        core.session.submit(core.tag, body).expect("credit");
        while !core.sent.is_empty() {
            core.pump().await;
        }
        lease.seal();
        core.change(2, delete(10)).await;
        let index = moved(&core, 3, 12);
        core.change(3, index).await;
        let roots: Vec<Vec<Root>> = ALL
            .iter()
            .map(|&s| core.keeper.roots(s).expect("kept").to_vec())
            .collect();
        let states: Vec<ShardState> = ALL
            .iter()
            .map(|&s| core.keeper.state(s).expect("kept").clone())
            .collect();
        drop(client);
        drop(core);
        drop(committer.await);
        let rebuilt = rebuild(&ALL).await;
        for shard in ALL {
            let index = usize::from(shard);
            assert_eq!(rebuilt.roots(shard).expect("kept"), roots[index].as_slice());
            assert_eq!(
                rebuilt.state(shard).expect("kept").entries(),
                states[index].entries()
            );
        }
        let some = rebuild(&[1, 3]).await;
        assert!(some.state(0).is_none() && some.state(2).is_none());
        assert_eq!(some.state(3).expect("kept").entries(), states[3].entries());
    });
}

#[derive(Clone, Default)]
struct Model {
    acked: Vec<(u16, Index, Location, u64)>,
    inflight: BTreeMap<u16, Index>,
}

type Shared = Rc<RefCell<Model>>;

const MILLION: u32 = 1_000_000;
const HORIZON: Duration = Duration::from_secs(60);
const CORES: u16 = 2;
const STEPS: u64 = 24;

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

fn step_index(step: u64, state: &ShardState) -> Index {
    let key = step * 5 % 13;
    let change = match (step % 4, state.get(Key::head(key))) {
        (3, Some(item)) => Change::Move { old: item.location },
        (2, _) => Change::Delete,
        _ => Change::Put(Delivery {
            status: u8::try_from(step % 200).expect("fits"),
            attempts: 1,
            due: step,
        }),
    };
    Index {
        key: Key::head(key),
        tenant: 7,
        change,
    }
}

async fn keep(start: Start, model: Shared) {
    let Ok(mut core) = start.open().await else {
        return;
    };
    for step in 0..STEPS {
        let shard = core.shards[usize::try_from(step).expect("fits") % core.shards.len()];
        let index = step_index(step, core.keeper.state(shard).expect("kept"));
        let submission = Submission {
            claim: Claim::Intake,
            records: vec![Write {
                kind: KIND_STATE,
                counted: true,
                shard,
                tenant: 7,
                payload: index.payload(&[1; 24]),
            }],
            bodies: Vec::new(),
            dead: Vec::new(),
        };
        model.borrow_mut().inflight.insert(shard, index);
        if core.session.submit(step, submission).is_err() {
            return;
        }
        loop {
            match core.results.recv().await {
                Some(Event::Durable {
                    sequence,
                    locations,
                    ..
                }) => {
                    core.keeper
                        .apply(shard, &index, &[], &[], locations[0], sequence);
                    let mut model = model.borrow_mut();
                    model.inflight.remove(&shard);
                    model.acked.push((shard, index, locations[0], sequence));
                    break;
                }
                Some(Event::Cut { sequence }) => {
                    if core
                        .keeper
                        .cut(&core.session, &core.file, sequence)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Some(Event::Published { sequence }) => core.keeper.published(sequence),
                Some(Event::Abandoned { sequence }) => core.keeper.abandoned(sequence),
                Some(Event::Compact { .. }) => panic!("no survey was sent"),
                Some(Event::Rejected { .. }) | None => return,
            }
        }
    }
}

async fn halted(driver: Rc<SimDriver>) {
    while !driver.is_halted() {
        sleep(Duration::from_millis(100)).await;
    }
}

fn workload(seed: u64, halt_after: Option<u64>, disk: Disk) -> (Rc<SimDriver>, Model) {
    let config = Config {
        halt_after,
        faults: rt::sim::Faults {
            torn_write: MILLION / 4,
            ..rt::sim::Faults::default()
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
        credits: 1,
        reserve: 0,
    };
    let Ok(Ok(booted)) =
        machine.block_on(0, async move { timeout(HORIZON, boot(PATH, setup)).await })
    else {
        return (driver, Model::default());
    };
    let model = Shared::default();
    let committer = machine.spawn_on(0, booted.committer.run());
    let tasks: Vec<_> = booted
        .starts
        .into_iter()
        .map(|start| {
            let core = usize::from(start.index()) + 1;
            machine.spawn_on(core, keep(start, Rc::clone(&model)))
        })
        .collect();
    let client = booted.client;
    let power = Rc::clone(&driver);
    machine.block_on(0, async move {
        let checkpoints = spawn(async move {
            for _ in 0..6 {
                sleep(Duration::from_millis(3)).await;
                if client.checkpoint().await.is_err() {
                    break;
                }
            }
        });
        let mut done = pin!(async move {
            for task in tasks {
                task.await;
            }
            checkpoints.await;
            drop(committer.await);
        });
        let mut halt = pin!(halted(power));
        let race = poll_fn(|cx| {
            if done.as_mut().poll(cx).is_ready() || halt.as_mut().poll(cx).is_ready() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        let _ = timeout(HORIZON, race).await;
    });
    let model = model.borrow().clone();
    (driver, model)
}

fn expected(model: &Model, shard: u16) -> ShardState {
    let mut state = ShardState::default();
    for (s, index, location, sequence) in &model.acked {
        if *s == shard {
            state.apply(index, &[], &[], *location, *sequence);
        }
    }
    state
}

fn audit(model: &Model, rebuilt: &Keeper) {
    for shard in ALL {
        let found = rebuilt.state(shard).expect("kept").entries();
        let mut state = expected(model, shard);
        if found == state.entries() {
            continue;
        }
        let index = *model
            .inflight
            .get(&shard)
            .unwrap_or_else(|| panic!("shard {shard} differs"));
        let location = found.get(&index.key).map_or(
            Location {
                region: 0,
                epoch: 0,
                offset: 0,
                sequence: 0,
                size: 0,
            },
            |item| item.location,
        );
        state.apply(&index, &[], &[], location, u64::MAX);
        assert_eq!(
            found,
            state.entries(),
            "shard {shard} after the unanswered change"
        );
    }
}

fn crash_at(seed: u64, point: u64) {
    let (driver, model) = workload(seed, Some(point), created(seed));
    assert!(driver.is_halted(), "crash point {point} not reached");
    let after = Rc::new(SimDriver::with_disk(
        seed + 1,
        Config::default(),
        driver.crash(),
    ));
    Runtime::new(after).block_on(async move {
        let rebuilt = rebuild(&ALL).await;
        audit(&model, &rebuilt);
    });
}

#[test]
fn shard_state_survives_a_crash_at_every_disk_operation() {
    let only = env::var("SIM_CRASH_AT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    check(0..1, |seed| {
        let (driver, model) = workload(seed, None, created(seed));
        assert_eq!(
            model.acked.len(),
            usize::from(CORES) * usize::try_from(STEPS).expect("fits"),
            "workload ran"
        );
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
