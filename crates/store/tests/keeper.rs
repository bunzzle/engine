use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, SimDriver};
use rt::{JoinHandle, Runtime, spawn};
use store::{
    Body, Change, Claim, Client, Committer, DataFile, Dead, Delivery, Error, Event, Index, Item,
    Keeper, MAX_DELTAS, Options, Part, Range, Results, Root, SLOT_SIZE, Session, ShardState,
    Submission, Write, encode_roots, load, read_run, recover,
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

async fn start(sessions: u32) -> (Client, Vec<(Session, Results)>, JoinHandle<Committer>) {
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
    (client, sessions, spawn(committer.run()))
}

struct Core {
    session: Session,
    results: Results,
    keeper: Keeper,
    data: DataFile,
    sent: BTreeMap<u64, (u16, Vec<Index>)>,
    tag: u64,
}

impl Core {
    async fn new((session, results): (Session, Results)) -> Self {
        let mut keeper = Keeper::default();
        for shard in 0..SHARDS {
            keeper.insert(shard, ShardState::default(), Vec::new());
        }
        Self {
            session,
            results,
            keeper,
            data: DataFile::open(PATH).await.expect("open"),
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
                kind: 9,
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
                    self.keeper.apply(shard, index, *location, *sequence);
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
            let roots = self.keeper.roots(shard).expect("kept");
            assert!(roots.len() <= MAX_DELTAS + 1);
            assert!(roots.first().is_none_or(|r| r.base));
            let state = self.keeper.state(shard).expect("kept");
            assert_eq!(&fold(&self.data, shard, roots).await, state.entries());
        }
    }
}

async fn fold(data: &DataFile, shard: u16, roots: &[Root]) -> BTreeMap<u64, Item> {
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
        key,
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
        key,
        tenant: 7,
        change: Change::Delete,
    }
}

#[test]
fn runs_hold_the_shard_state_across_checkpoints_and_restarts() {
    run(21, async {
        let (client, mut sessions, committer) = start(1).await;
        let mut core = Core::new(sessions.remove(0)).await;
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
        let expected: Vec<BTreeMap<u64, Item>> = (0..SHARDS)
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
        assert_ne!(loaded.state.runs.len(), 0);
        for &region in &loaded.state.runs {
            assert!(loaded.state.regions.is_used(region));
        }
        for part in &loaded.parts {
            let roots = store::decode_roots(&part.bytes).expect("roots");
            let shard = part.tag;
            assert_eq!(
                fold(&data, shard, &roots).await,
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
                    session.parts(sequence, Vec::new()).expect("parts");
                }
                cuts += 1;
            }
        }
    })
}

#[test]
fn an_abandoned_cut_keeps_its_changes_for_the_next_one() {
    run(22, async {
        let (client, mut sessions, _committer) = start(2).await;
        let other = sessions.pop().expect("second");
        let _failing = fail_cut(other.0, other.1, 1);
        let mut core = Core::new(sessions.remove(0)).await;
        for key in 0..5 {
            core.change(1, put(key, 1)).await;
        }
        core.checkpoint(&client).await.expect("checkpoint");
        let base = core.keeper.roots(1).expect("kept").to_vec();
        assert_eq!(base.len(), 1);
        core.change(1, delete(2)).await;
        core.change(1, put(6, 3)).await;
        assert!(matches!(
            core.checkpoint(&client).await,
            Err(Error::Invalid("part"))
        ));
        assert_eq!(core.keeper.roots(1).expect("kept"), base.as_slice());
        core.change(1, put(9, 4)).await;
        core.checkpoint(&client).await.expect("checkpoint");
        let roots = core.keeper.roots(1).expect("kept");
        assert_eq!(roots.len(), 2, "the next cut writes a delta");
        let entries = fold(&core.data, 1, roots).await;
        let keys: Vec<u64> = entries.keys().copied().collect();
        assert_eq!(keys, vec![0, 1, 3, 4, 6, 9]);
        core.check().await;
    });
}

#[test]
fn a_root_outside_the_state_regions_abandons_the_checkpoint() {
    run(23, async {
        let (client, mut sessions, _committer) = start(1).await;
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
        let (client, mut sessions, committer) = start(1).await;
        let mut core = Core::new(sessions.remove(0)).await;
        core.change(0, put(1, 1)).await;
        core.checkpoint(&client).await.expect("checkpoint");
        let root = core.keeper.roots(0).expect("kept")[0];
        let body = Submission {
            claim: Claim::Intake,
            records: Vec::new(),
            bodies: vec![Body {
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
        assert!(matches!(
            client.commit(body).await,
            Err(Error::Invalid("range"))
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
        let (client, mut sessions, _committer) = start(1).await;
        let mut core = Core::new(sessions.remove(0)).await;
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
