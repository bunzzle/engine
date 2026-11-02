use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use index::{Entry, Op, Shape};
use rt::sim::{Config, SimDriver};
use rt::{JoinHandle, Runtime, spawn};
use store::{
    Claim, Client, Committer, CoreFile, DataFile, Error, Event, IndexRecord, IndexRoot, Keeper,
    Options, Part, Results, SLOT_SIZE, Session, ShardState, Source, Submission, decode_part,
    encode_part, load, recover,
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
        let scanned = keeper.scan(data, shard, partition).await.expect("scan");
        let expected: Vec<Entry> = entries
            .iter()
            .map(|(key, (op, value, payload))| Entry {
                key: *key,
                op: *op,
                value: value.clone(),
                payload: payload.clone(),
            })
            .collect();
        assert_eq!(scanned, expected, "shard {shard} partition {partition:?}");
        for (key, (op, value, _)) in entries {
            let found = keeper.lookup(data, shard, partition, key).await;
            assert_eq!(found.expect("lookup"), Some((*op, value.clone())));
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
        assert_eq!(roots.len(), 2, "one new run after the abandoned cut");
        assert_eq!(roots[0], first[0]);
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
