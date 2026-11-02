use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use index::{Entry, Op, Shape};
use rt::sim::{Config, SimDriver};
use rt::{JoinHandle, Runtime, spawn};
use store::{
    Claim, Client, Committer, CoreFile, DataFile, Error, Event, IndexRecord, IndexRoot, Keeper,
    Options, Part, Results, SLOT_SIZE, Session, ShardState, Source, Submission, Tiering,
    decode_part, encode_part, load, recover,
};

const PATH: &str = "/data/indexes";
const SHARDS: u16 = 4;
const ALL: [u16; 4] = [0, 1, 2, 3];
const SHAPE: Shape = Shape { value: 8 };

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 48,
    shards: SHARDS as u32,
};

type Partition = (u8, u32);
type Model = BTreeMap<(u16, Partition), BTreeMap<[u8; 20], (Op, Vec<u8>, Vec<u8>)>>;

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
    flush: u32,
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
        .map(|_| committer.session(&client, 8, flush))
        .collect();
    let source = committer.source();
    (client, sessions, source, spawn(committer.run()))
}

async fn reopen() -> (Keeper, CoreFile) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    let (committer, _client) = Committer::new(data, recovered.journal, recovered.state);
    let file = committer.source().open().await.expect("open file");
    let keeper = Keeper::rebuild(&file, &loaded.parts, &recovered.entries, &ALL)
        .await
        .expect("rebuild");
    (keeper, file)
}

async fn restart(flush: u32, model: Model) -> (Client, Core, JoinHandle<Committer>) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    let (mut committer, client) = Committer::new(data, recovered.journal, recovered.state);
    committer.set_part_timeout(Duration::from_secs(5));
    let (session, results) = committer.session(&client, 8, flush);
    let file = committer.source().open().await.expect("open file");
    let keeper = Keeper::rebuild(&file, &loaded.parts, &recovered.entries, &ALL)
        .await
        .expect("rebuild");
    let core = Core {
        session,
        results,
        keeper,
        data: file,
        sent: BTreeMap::new(),
        tag: 0,
        model,
    };
    (client, core, spawn(committer.run()))
}

struct Core {
    session: Session,
    results: Results,
    keeper: Keeper,
    data: CoreFile,
    sent: BTreeMap<u64, (u16, Vec<IndexRecord>)>,
    tag: u64,
    model: Model,
}

impl Core {
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
            model: Model::new(),
        }
    }

    async fn write(&mut self, shard: u16, records: Vec<IndexRecord>) -> Vec<store::Location> {
        let submission = Submission {
            claim: Claim::Intake,
            records: records.iter().map(|r| r.write(shard)).collect(),
            bodies: Vec::new(),
            dead: Vec::new(),
        };
        self.tag += 1;
        let tag = self.tag;
        self.sent.insert(tag, (shard, records));
        self.session.submit(tag, submission).expect("credit");
        loop {
            if let Event::Durable {
                tag: done,
                locations,
                ..
            } = self.pump().await
                && done == tag
            {
                return locations;
            }
        }
    }

    async fn pump(&mut self) -> Event {
        let event = self.results.recv().await.expect("event");
        match &event {
            Event::Durable { tag, .. } => {
                let (shard, records) = self.sent.remove(tag).expect("sent");
                for record in records {
                    let entry = &record.entry;
                    self.model
                        .entry((shard, (record.kind, record.partition)))
                        .or_default()
                        .insert(
                            entry.key,
                            (entry.op, entry.value.clone(), entry.payload.clone()),
                        );
                    self.keeper.apply_index(shard, record).expect("apply");
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

    async fn merge_once(&mut self) -> Option<Result<(), Error>> {
        let job = self.keeper.plan(&self.data)?;
        let task = store::merge(
            job,
            self.data.clone(),
            self.session.clone(),
            self.keeper.tiering().clone(),
        );
        let done = spawn(task).await;
        Some(self.keeper.merged(done))
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
}

async fn verify(keeper: &Keeper, data: &CoreFile, model: &Model) {
    for (&(shard, partition), entries) in model {
        let scanned: Vec<Entry> = keeper
            .scan(data, shard, partition)
            .await
            .expect("scan")
            .into_iter()
            .filter(|e| e.op == Op::Put)
            .collect();
        let expected: Vec<Entry> = entries
            .iter()
            .filter(|(_, (op, _, _))| *op == Op::Put)
            .map(|(key, (op, value, payload))| Entry {
                key: *key,
                op: *op,
                value: value.clone(),
                payload: payload.clone(),
            })
            .collect();
        assert_eq!(scanned, expected, "shard {shard} partition {partition:?}");
        for (key, (op, value, _)) in entries {
            let found = keeper
                .lookup(data, shard, partition, key)
                .await
                .expect("lookup");
            match op {
                Op::Put => assert_eq!(found, Some((Op::Put, value.clone()))),
                Op::Delete => assert!(found.is_none_or(|(op, _)| op == Op::Delete)),
            }
        }
        let mut absent = *entries.keys().next().expect("entries");
        absent[19] ^= 0xFF;
        if !entries.contains_key(&absent) {
            let found = keeper.lookup(data, shard, partition, &absent).await;
            assert_eq!(found.expect("lookup"), None);
        }
    }
}

fn key(tenant: u32, n: u64) -> [u8; 20] {
    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&n.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
    hash[8..].copy_from_slice(&n.to_le_bytes());
    index::key(tenant, hash)
}

fn put(kind: u8, partition: u32, n: u64, round: u64) -> IndexRecord {
    let payload = if n.is_multiple_of(3) {
        Vec::new()
    } else {
        vec![u8::try_from(n % 251).expect("fits"); usize::try_from(n % 40).expect("fits")]
    };
    IndexRecord {
        kind,
        partition,
        entry: Entry::put(key(3, n), (n ^ round).to_le_bytes().to_vec(), payload),
    }
}

fn delete(kind: u8, partition: u32, n: u64) -> IndexRecord {
    IndexRecord {
        kind,
        partition,
        entry: Entry::delete(key(3, n), SHAPE),
    }
}

#[test]
fn index_records_round_trip_and_refuse_damage() {
    let record = put(2, 20_001, 7, 1);
    let bytes = record.encode();
    assert_eq!(IndexRecord::decode(&bytes), Some(record.clone()));
    let tombstone = delete(1, 0, 9);
    assert_eq!(
        IndexRecord::decode(&tombstone.encode()),
        Some(tombstone.clone())
    );
    let write = record.write(5);
    assert!(!write.counted, "index records are uncounted");
    assert_eq!((write.shard, write.tenant), (5, 3));
    let mut op = bytes.clone();
    op[1] = 3;
    assert_eq!(IndexRecord::decode(&op), None);
    let mut reserved = bytes.clone();
    reserved[12] = 1;
    assert_eq!(IndexRecord::decode(&reserved), None);
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(IndexRecord::decode(&long), None);
    let mut payload = tombstone.encode();
    payload[8] = 1;
    payload.push(1);
    assert_eq!(
        IndexRecord::decode(&payload),
        None,
        "a delete has no payload"
    );
    for cut in 0..bytes.len() {
        assert_eq!(IndexRecord::decode(&bytes[..cut]), None);
    }
}

#[test]
fn index_partitions_survive_checkpoints_and_restarts() {
    run(41, async {
        let (client, mut sessions, source, committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        for round in 0..6u64 {
            let batches = if round == 0 { 40 } else { 8 };
            for batch in 0..batches {
                let records = (0..100)
                    .map(|i| {
                        let n = (batch * 100 + i) * (2 * round + 1) % 4_000;
                        if round > 0 && (n + round).is_multiple_of(7) {
                            delete(1, 0, n)
                        } else {
                            put(1, 0, n, round)
                        }
                    })
                    .collect();
                core.write(2, records).await;
            }
            let day = (0..30).map(|n| {
                put(
                    2,
                    20_000 + u32::try_from(round % 2).expect("fits"),
                    n,
                    round,
                )
            });
            core.write(1, day.collect()).await;
            core.checkpoint(&client).await.expect("checkpoint");
            verify(&core.keeper, &core.data, &core.model).await;
        }
        let roots = core.keeper.index_roots(2).expect("kept");
        assert!(
            roots.iter().filter(|r| r.run == 0).count() > 1,
            "a run spans segments"
        );
        let regions: Vec<u32> = roots.iter().map(|r| r.region).collect();
        assert!(
            regions.windows(2).any(|w| w[0] != w[1]),
            "segments span regions"
        );
        core.write(2, vec![delete(1, 0, 1), put(1, 0, 5_000, 9)])
            .await;
        core.write(3, vec![put(2, 20_002, 1, 9)]).await;
        let model = core.model.clone();
        let published: Vec<Vec<IndexRoot>> = ALL
            .iter()
            .map(|&s| core.keeper.index_roots(s).expect("kept"))
            .collect();
        drop(client);
        drop(core);
        let committer = committer.await;
        let regions = committer.regions();
        assert!(
            regions.count() - regions.free() < 24,
            "{} regions still used",
            regions.count() - regions.free()
        );
        drop(committer);
        let (keeper, file) = reopen().await;
        for &shard in &ALL {
            assert_eq!(
                keeper.index_roots(shard).expect("kept"),
                published[usize::from(shard)]
            );
        }
        assert_eq!(keeper.partitions(3), vec![(2, 20_002)]);
        verify(&keeper, &file, &model).await;
        drop(keeper);
        drop(file);
        let (client, mut core, committer) = restart(2, model).await;
        for round in 0..4u64 {
            let records = (0..100).map(|n| put(1, 0, 4_000 + round * 100 + n, round));
            core.write(2, records.collect()).await;
            core.write(0, vec![put(2, 20_003, round, round)]).await;
            core.checkpoint(&client).await.expect("checkpoint");
        }
        let model = core.model.clone();
        drop(client);
        drop(core);
        drop(committer.await);
        let (keeper, file) = reopen().await;
        verify(&keeper, &file, &model).await;
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
                            bytes: encode_part(&[], &[]),
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
fn an_abandoned_cut_keeps_index_changes_for_the_next_one() {
    run(42, async {
        let (client, mut sessions, source, _committer) = start(2, 1).await;
        let other = sessions.pop().expect("second");
        let _failing = fail_cut(other.0, other.1, 1);
        let mut core = Core::owning(sessions.remove(0), &source, &[0, 2]).await;
        core.write(2, (0..5).map(|n| put(1, 0, n, 0)).collect())
            .await;
        core.checkpoint(&client).await.expect("checkpoint");
        let first = core.keeper.index_roots(2).expect("kept");
        assert_eq!(first.len(), 1);
        core.write(2, vec![delete(1, 0, 2), put(1, 0, 6, 1)]).await;
        assert!(matches!(
            core.checkpoint(&client).await,
            Err(Error::Invalid("part"))
        ));
        assert_eq!(core.keeper.index_roots(2).expect("kept"), first);
        verify(&core.keeper, &core.data, &core.model).await;
        core.write(2, vec![put(1, 0, 9, 2), put(1, 0, 6, 3)]).await;
        core.checkpoint(&client).await.expect("checkpoint");
        let roots = core.keeper.index_roots(2).expect("kept");
        assert_eq!(roots.len(), 1, "the small run is rewritten");
        assert_ne!(roots[0], first[0]);
        verify(&core.keeper, &core.data, &core.model).await;
    });
}

async fn answer_cuts(session: &Session, mut results: Results, count: u32) -> Results {
    let mut cuts = 0;
    while let Some(event) = results.recv().await {
        if let Event::Cut { sequence } = event {
            let parts = ALL
                .map(|tag| Part {
                    tag,
                    replay_sequence: sequence,
                    bytes: encode_part(&[], &[]),
                })
                .to_vec();
            session.parts(sequence, parts).expect("parts");
            cuts += 1;
            if cuts == count {
                break;
            }
        }
    }
    results
}

#[test]
fn merge_regions_need_a_reservation_and_stay_held_until_given_back() {
    run(43, async {
        let (client, mut sessions, _source, committer) = start(1, 1).await;
        let (session, results) = sessions.remove(0);
        assert!(matches!(
            session.claim(Claim::Index).await,
            Err(Error::Full)
        ));
        assert!(matches!(
            session.claim(Claim::Intake).await,
            Err(Error::Invalid("claim"))
        ));
        for claim in [Claim::State, Claim::Flush, Claim::Index] {
            assert!(matches!(
                client.allocate(claim).await,
                Err(Error::Invalid("claim"))
            ));
        }
        session.reserve_index(3).await.expect("reserve");
        let (held, _) = session.claim(Claim::Index).await.expect("claim");
        let (given, _) = session.claim(Claim::Index).await.expect("claim");
        let session = Rc::new(session);
        let answering = {
            let session = Rc::clone(&session);
            spawn(async move { answer_cuts(&session, results, 2).await })
        };
        client.checkpoint().await.expect("checkpoint");
        session.unhold(given).expect("give back");
        client.checkpoint().await.expect("checkpoint");
        let results = answering.await;
        drop(results);
        drop(session);
        drop(client);
        let committer = committer.await;
        let regions = committer.regions();
        assert!(
            regions.is_used(held),
            "a held region survives two publishes"
        );
        assert!(!regions.is_used(given), "a given back region is released");
        assert_eq!(
            regions.merging(),
            0,
            "a closed session returns its reservation"
        );
    });
}

#[test]
fn lookups_see_frozen_entries_while_a_cut_is_pending() {
    run(49, async {
        let (client, mut sessions, source, _committer) = start(1, 1).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        core.write(3, (0..40).map(|n| put(1, 0, n, 0)).collect())
            .await;
        let request = {
            let client = client.clone();
            spawn(async move { client.checkpoint().await })
        };
        while !matches!(core.pump().await, Event::Cut { .. }) {}
        assert_eq!(core.keeper.index_roots(3).expect("kept"), Vec::new());
        verify(&core.keeper, &core.data, &core.model).await;
        while !matches!(core.pump().await, Event::Published { .. }) {}
        request.await.expect("checkpoint");
        assert_eq!(core.keeper.index_roots(3).expect("kept").len(), 1);
        verify(&core.keeper, &core.data, &core.model).await;
    });
}

#[test]
fn a_session_claims_only_its_own_merge_reservation() {
    run(48, async {
        let (client, mut sessions, _source, committer) = start(2, 1).await;
        let (second, second_results) = sessions.pop().expect("second");
        let (first, first_results) = sessions.pop().expect("first");
        first.reserve_index(1).await.expect("reserve");
        assert!(matches!(second.claim(Claim::Index).await, Err(Error::Full)));
        second.reserve_index(2).await.expect("reserve");
        first.claim(Claim::Index).await.expect("claim");
        assert!(matches!(first.claim(Claim::Index).await, Err(Error::Full)));
        second.unreserve_index(1).expect("unreserve");
        drop((first, first_results, second, second_results, client));
        assert_eq!(committer.await.regions().merging(), 0);
    });
}

#[test]
fn an_index_root_outside_the_run_regions_abandons_the_checkpoint() {
    run(45, async {
        let (client, mut sessions, _source, _committer) = start(1, 1).await;
        let (session, mut results) = sessions.remove(0);
        let answer = spawn(async move {
            while let Some(event) = results.recv().await {
                if let Event::Cut { sequence } = event {
                    let root = IndexRoot {
                        kind: 1,
                        partition: 0,
                        run: 0,
                        segment: 0,
                        region: 5,
                        epoch: 0,
                        offset: 0,
                        length: 8192,
                        checksum: 0,
                        covered: sequence - 1,
                    };
                    let mut parts: Vec<Part> = ALL
                        .map(|tag| Part {
                            tag,
                            replay_sequence: sequence,
                            bytes: encode_part(&[], &[]),
                        })
                        .to_vec();
                    parts[0].bytes = encode_part(&[], &[root]);
                    session.parts(sequence, parts).expect("parts");
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
fn index_records_are_uncounted_and_their_regions_free_after_a_checkpoint() {
    run(46, async {
        let (client, mut sessions, source, committer) = start(1, 1).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        let locations = core
            .write(0, (0..50).map(|n| put(1, 0, n, 0)).collect())
            .await;
        let stream = locations[0].region;
        for batch in 0..12u64 {
            let records = (0..200).map(|n| put(1, 0, batch * 200 + n, 1)).collect();
            core.write(0, records).await;
        }
        let last = core.write(0, vec![put(1, 0, 9_999, 2)]).await;
        assert_ne!(last[0].region, stream, "the stream moved on");
        core.checkpoint(&client).await.expect("checkpoint");
        verify(&core.keeper, &core.data, &core.model).await;
        drop(client);
        drop(core);
        let committer = committer.await;
        assert_eq!(committer.usage().counts()[stream as usize].bytes, 0);
        assert!(
            !committer.regions().is_used(stream),
            "stream region released"
        );
    });
}

#[test]
fn a_damaged_index_root_fails_the_rebuild() {
    run(47, async {
        let (client, mut sessions, source, committer) = start(1, 1).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        core.write(1, (0..20).map(|n| put(1, 0, n, 0)).collect())
            .await;
        core.checkpoint(&client).await.expect("checkpoint");
        drop(client);
        drop(core);
        drop(committer.await);
        let data = DataFile::open(PATH).await.expect("open");
        let loaded = load(&data, 0).await.expect("load");
        let recovered = recover(&data, loaded.position, loaded.state)
            .await
            .expect("recover");
        let (committer, _client) = Committer::new(data, recovered.journal, recovered.state);
        let file = committer.source().open().await.expect("open file");
        let at = loaded.parts.iter().position(|p| p.tag == 1).expect("part");
        let roots = decode_part(&loaded.parts[at].bytes).expect("roots");
        let intact = Keeper::rebuild(&file, &loaded.parts, &recovered.entries, &ALL).await;
        assert!(intact.is_ok());
        for damage in 0..3 {
            let mut index = roots.index.clone();
            match damage {
                0 => index[0].checksum ^= 1,
                1 => index[0].covered += 1,
                _ => index[0].length += 4096,
            }
            let mut parts = loaded.parts.clone();
            parts[at].bytes = encode_part(&roots.state, &index);
            let damaged = Keeper::rebuild(&file, &parts, &recovered.entries, &ALL).await;
            assert!(
                matches!(damaged, Err(Error::Damaged { .. })),
                "damage {damage}"
            );
        }
    });
}

fn tiny_flushes(core: &mut Core) {
    core.keeper.set_tiering(Tiering {
        flush_size: 1,
        bytes_per_tick: 64 * 1024,
        tick: Duration::from_millis(1),
        ..Tiering::default()
    });
}

async fn rounds(core: &mut Core, client: &Client, shard: u16, partition: (u8, u32), count: u64) {
    for round in 0..count {
        let records = (0..60)
            .map(|i| {
                let n = (round * 37 + i * 11) % 300;
                if (n + round).is_multiple_of(5) {
                    delete(partition.0, partition.1, n)
                } else {
                    put(partition.0, partition.1, n, round)
                }
            })
            .collect();
        core.write(shard, records).await;
        core.checkpoint(client).await.expect("checkpoint");
    }
}

#[test]
fn small_flushes_rewrite_the_newest_run_and_drop_its_tombstones() {
    run(50, async {
        let (client, mut sessions, source, _committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        rounds(&mut core, &client, 1, (1, 0), 5).await;
        assert_eq!(core.keeper.runs(1, (1, 0)), 1);
        let scanned = core.keeper.scan(&core.data, 1, (1, 0)).await.expect("scan");
        assert!(
            scanned.iter().all(|e| e.op == Op::Put),
            "the only run holds no tombstones"
        );
        verify(&core.keeper, &core.data, &core.model).await;
    });
}

#[test]
fn tiered_merges_replace_neighbouring_runs_and_survive_restarts() {
    run(51, async {
        let (client, mut sessions, source, committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        tiny_flushes(&mut core);
        rounds(&mut core, &client, 2, (1, 0), 7).await;
        assert_eq!(core.keeper.runs(2, (1, 0)), 7);
        assert_eq!(core.keeper.most_runs(), 7);
        let job = core.keeper.plan(&core.data).expect("a merge is due");
        assert_eq!((job.shard(), job.partition(), job.runs()), (2, (1, 0), 4));
        core.keeper.cancel(&job);
        let mut fresh = Keeper::default();
        fresh.insert(0, ShardState::default(), Vec::new());
        assert!(fresh.plan(&core.data).is_none());
        verify(&core.keeper, &core.data, &core.model).await;
        drop(client);
        drop(core);
        drop(committer.await);
        let (client, mut core, committer) = restart(2, Model::new()).await;
        tiny_flushes(&mut core);
        core.model = model_of(&core).await;
        let before = core.keeper.runs(2, (1, 0));
        core.merge_once().await.expect("planned").expect("merged");
        assert_eq!(
            core.keeper.runs(2, (1, 0)),
            before,
            "the swap waits for a cut"
        );
        verify(&core.keeper, &core.data, &core.model).await;
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.runs(2, (1, 0)), before - 3);
        verify(&core.keeper, &core.data, &core.model).await;
        let model = core.model.clone();
        drop(client);
        drop(core);
        drop(committer.await);
        let (keeper, file) = reopen().await;
        assert_eq!(keeper.runs(2, (1, 0)), before - 3);
        verify(&keeper, &file, &model).await;
    });
}

async fn model_of(core: &Core) -> Model {
    let mut model = Model::new();
    for &shard in &ALL {
        for partition in core.keeper.partitions(shard) {
            let scanned = core
                .keeper
                .scan(&core.data, shard, partition)
                .await
                .expect("scan");
            let entries = model.entry((shard, partition)).or_default();
            for entry in scanned {
                entries.insert(entry.key, (entry.op, entry.value, entry.payload));
            }
        }
    }
    model
}

#[test]
fn merges_drop_what_the_caller_does_not_retain() {
    run(52, async {
        let (client, mut sessions, source, _committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        tiny_flushes(&mut core);
        rounds(&mut core, &client, 0, (2, 7), 4).await;
        core.keeper.close_partition(0, (2, 7));
        let expected = model_of(&core).await;
        core.keeper.set_tiering(Tiering {
            retain: Rc::new(|kind, entry, oldest| {
                assert_eq!(kind, 2);
                !(oldest && entry.value[0] % 2 == 1)
            }),
            ..core.keeper.tiering().clone()
        });
        core.merge_once().await.expect("planned").expect("merged");
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.runs(0, (2, 7)), 1);
        let scanned = core.keeper.scan(&core.data, 0, (2, 7)).await.expect("scan");
        let kept: Vec<_> = expected[&(0, (2, 7))]
            .iter()
            .filter(|(_, (op, value, _))| *op == Op::Put && value[0] % 2 == 0)
            .map(|(key, _)| *key)
            .collect();
        assert_eq!(scanned.iter().map(|e| e.key).collect::<Vec<_>>(), kept);
        assert!(scanned.iter().all(|e| e.op == Op::Put));
    });
}

#[test]
fn a_closed_partition_merges_whole_unless_space_is_short() {
    run(53, async {
        let (client, mut sessions, source, _committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        tiny_flushes(&mut core);
        rounds(&mut core, &client, 1, (2, 3), 3).await;
        rounds(&mut core, &client, 3, (2, 1), 5).await;
        core.keeper.close_partition(1, (2, 3));
        let newest = core
            .keeper
            .index_roots(1)
            .expect("kept")
            .last()
            .expect("root")
            .covered;
        core.merge_once().await.expect("planned").expect("merged");
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.runs(1, (2, 3)), 1);
        let roots = core.keeper.index_roots(1).expect("kept");
        assert!(
            roots.iter().all(|r| r.covered == newest),
            "a merge keeps the newest covered"
        );
        core.keeper.close_partition(3, (2, 1));
        let job = core.keeper.plan(&core.data).expect("whole merge");
        assert_eq!((job.shard(), job.runs()), (3, 5));
        let regions = job.regions();
        core.keeper.cancel(&job);
        let taken = squeeze(&core.session).await;
        core.session
            .unreserve_index(regions - 1)
            .expect("unreserve");
        let refused = core.merge_once().await.expect("planned");
        assert!(matches!(refused, Err(Error::Full)));
        core.session
            .unreserve_index(taken - (regions - 1))
            .expect("unreserve");
        let job = core.keeper.plan(&core.data).expect("tiered merge");
        assert_eq!(
            (job.shard(), job.runs()),
            (3, 4),
            "a refused day keeps tiered merges"
        );
        core.keeper.cancel(&job);
        core.merge_once().await.expect("planned").expect("merged");
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.runs(3, (2, 1)), 2);
        verify(&core.keeper, &core.data, &core.model).await;
    });
}

async fn squeeze(session: &Session) -> u32 {
    for n in (1..OPTIONS.region_count).rev() {
        if session.reserve_index(n).await.is_ok() {
            return n;
        }
    }
    panic!("no region to reserve");
}

#[test]
fn a_dropped_partition_leaves_at_the_next_publish() {
    run(54, async {
        let (client, mut sessions, source, _committer) = start(2, 2).await;
        let other = sessions.pop().expect("second");
        let _failing = fail_cut(other.0, other.1, 1);
        let mut core = Core::owning(sessions.remove(0), &source, &[0, 2]).await;
        core.write(2, (0..30).map(|n| put(2, 19_999, n, 0)).collect())
            .await;
        core.write(2, (0..30).map(|n| put(2, 20_000, n, 0)).collect())
            .await;
        core.checkpoint(&client).await.expect("checkpoint");
        core.keeper.drop_partition(2, (2, 19_999));
        assert!(core.keeper.plan(&core.data).is_none());
        assert!(core.checkpoint(&client).await.is_err());
        assert_eq!(core.keeper.partitions(2), vec![(2, 19_999), (2, 20_000)]);
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.partitions(2), vec![(2, 20_000)]);
        core.model.remove(&(2, (2, 19_999)));
        verify(&core.keeper, &core.data, &core.model).await;
        let keeper = from_disk(&core.data).await;
        assert_eq!(keeper.partitions(2), vec![(2, 20_000)]);
        verify(&keeper, &core.data, &core.model).await;
    });
}

async fn from_disk(file: &CoreFile) -> Keeper {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    drop(data);
    Keeper::rebuild(file, &loaded.parts, &[], &ALL)
        .await
        .expect("rebuild")
}

#[test]
fn a_finished_merge_waits_through_an_abandoned_cut() {
    run(55, async {
        let (client, mut sessions, source, _committer) = start(2, 2).await;
        let other = sessions.pop().expect("second");
        let _failing = fail_cut(other.0, other.1, 6);
        let mut core = Core::owning(sessions.remove(0), &source, &[0, 2]).await;
        tiny_flushes(&mut core);
        rounds(&mut core, &client, 0, (1, 0), 6).await;
        core.merge_once().await.expect("planned").expect("merged");
        assert!(core.checkpoint(&client).await.is_err());
        assert_eq!(core.keeper.runs(0, (1, 0)), 6);
        verify(&core.keeper, &core.data, &core.model).await;
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.runs(0, (1, 0)), 3);
        verify(&core.keeper, &core.data, &core.model).await;
        assert!(
            core.merge_once().await.is_none(),
            "too few similar runs left"
        );
    });
}

#[test]
fn merged_regions_are_given_back_and_the_reservation_returned() {
    run(56, async {
        let (client, mut sessions, source, committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        tiny_flushes(&mut core);
        rounds(&mut core, &client, 1, (1, 0), 5).await;
        core.merge_once().await.expect("planned").expect("merged");
        core.checkpoint(&client).await.expect("checkpoint");
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.runs(1, (1, 0)), 2);
        let Core {
            session, results, ..
        } = core;
        drop(session);
        drop(client);
        let committer = committer.await;
        assert!(committer.held(0).len() <= 1, "held {:?}", committer.held(0));
        assert_eq!(committer.regions().merging(), 0);
        drop(results);
    });
}

#[test]
fn merges_leave_the_newest_run_to_flushes() {
    run(57, async {
        let (client, mut sessions, source, _committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        tiny_flushes(&mut core);
        for round in 0..4u64 {
            let records = (0..300).map(|n| put(1, 0, round * 1_000 + n, round));
            core.write(2, records.collect()).await;
            core.checkpoint(&client).await.expect("checkpoint");
        }
        core.write(2, (0..160).map(|n| put(1, 0, 9_000 + n, 9)).collect())
            .await;
        core.checkpoint(&client).await.expect("checkpoint");
        let newest: Vec<IndexRoot> = core
            .keeper
            .index_roots(2)
            .expect("kept")
            .into_iter()
            .filter(|r| r.run == 4)
            .collect();
        core.merge_once().await.expect("planned").expect("merged");
        core.checkpoint(&client).await.expect("checkpoint");
        let roots = core.keeper.index_roots(2).expect("kept");
        let last: Vec<IndexRoot> = roots.iter().filter(|r| r.run == 1).copied().collect();
        assert_eq!(last.len(), newest.len());
        for (a, b) in last.iter().zip(&newest) {
            assert_eq!(
                (a.region, a.offset, a.checksum),
                (b.region, b.offset, b.checksum)
            );
        }
        verify(&core.keeper, &core.data, &core.model).await;
    });
}

#[test]
fn a_tombstone_in_a_middle_merge_still_hides_older_puts() {
    run(58, async {
        let (client, mut sessions, source, _committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        tiny_flushes(&mut core);
        core.write(0, (0..400).map(|n| put(1, 0, n, 0)).collect())
            .await;
        core.checkpoint(&client).await.expect("checkpoint");
        for round in 1..6u64 {
            let mut records: Vec<IndexRecord> = (0..60)
                .map(|n| put(1, 0, 1_000 + round * 100 + n, round))
                .collect();
            if round == 1 {
                records.push(delete(1, 0, 7));
            }
            core.write(0, records).await;
            core.checkpoint(&client).await.expect("checkpoint");
        }
        let job = core.keeper.plan(&core.data).expect("planned");
        assert_eq!(job.runs(), 4);
        core.keeper.cancel(&job);
        core.merge_once().await.expect("planned").expect("merged");
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.runs(0, (1, 0)), 3);
        let found = core.keeper.lookup(&core.data, 0, (1, 0), &key(3, 7)).await;
        assert_eq!(found.expect("lookup"), Some((Op::Delete, vec![0; 8])));
        verify(&core.keeper, &core.data, &core.model).await;
    });
}

#[test]
fn a_long_merge_keeps_its_regions_across_publishes() {
    run(59, async {
        let (client, mut sessions, source, _committer) = start(1, 2).await;
        let mut core = Core::owning(sessions.remove(0), &source, &ALL).await;
        core.keeper.set_tiering(Tiering {
            flush_size: 1,
            bytes_per_tick: 8 * 1024,
            tick: Duration::from_millis(2),
            ..Tiering::default()
        });
        for round in 0..5u64 {
            for batch in 0..8u64 {
                let records = (0..250)
                    .map(|i| put(1, 0, round * 10_000 + batch * 250 + i, round))
                    .collect();
                core.write(3, records).await;
            }
            core.checkpoint(&client).await.expect("checkpoint");
        }
        let job = core.keeper.plan(&core.data).expect("planned");
        assert!(job.regions() > 2, "{} regions", job.regions());
        let finished = Rc::new(std::cell::Cell::new(false));
        let task = {
            let finished = Rc::clone(&finished);
            let merge = store::merge(
                job,
                core.data.clone(),
                core.session.clone(),
                core.keeper.tiering().clone(),
            );
            spawn(async move {
                let done = merge.await;
                finished.set(true);
                done
            })
        };
        let mut round = 0u64;
        while !finished.get() {
            let records = (0..20)
                .map(|i| put(2, 1, round * 1_000 + i, round))
                .collect();
            core.write(3, records).await;
            core.checkpoint(&client).await.expect("checkpoint");
            round += 1;
        }
        assert!(round > 4, "{round} publishes during the merge");
        core.keeper.merged(task.await).expect("merged");
        core.checkpoint(&client).await.expect("checkpoint");
        assert_eq!(core.keeper.runs(3, (1, 0)), 2);
        verify(&core.keeper, &core.data, &core.model).await;
        let keeper = from_disk(&core.data).await;
        verify(&keeper, &core.data, &core.model).await;
    });
}
