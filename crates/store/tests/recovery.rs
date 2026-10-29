use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Faults, SimDriver, check};
use rt::{Buf, File, JoinHandle, OpenOptions, Runtime, sleep, spawn};
use store::{
    Claim, Client, Commit, Committer, DataFile, Durable, Error, Journal, Location, Options,
    Position, Range, Record, Recovered, SLOT_SIZE, State, Submission, Write, load, recover,
};

const MILLION: u32 = 1_000_000;
const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 16 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 8,
    shards: 4,
};

type Acked = Vec<(Durable, Vec<Vec<u8>>)>;

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

fn created(seed: u64) -> Rc<SimDriver> {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    run(&setup, async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    Rc::new(SimDriver::with_disk(seed, Config::default(), setup.crash()))
}

async fn reopen() -> (DataFile, Result<Recovered, Error>) {
    let data = DataFile::open(PATH).await.expect("open");
    let recovered = match load(&data, 0).await {
        Ok(loaded) => recover(&data, loaded.position, loaded.state).await,
        Err(e) => Err(e),
    };
    (data, recovered)
}

async fn start() -> (Client, JoinHandle<Committer>) {
    let (data, recovered) = reopen().await;
    let recovered = recovered.expect("recover");
    let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
    (client, spawn(committer.run()))
}

fn payload(client: u64, step: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&client.to_le_bytes());
    out.extend_from_slice(&step.to_le_bytes());
    out.resize(len.max(16), u8::try_from(step % 251).expect("fits"));
    out
}

fn submission(records: Vec<Vec<u8>>) -> Submission {
    Submission {
        claim: Claim::Intake,
        records: records
            .into_iter()
            .map(|payload| Write {
                kind: 7,
                counted: true,
                shard: 0,
                tenant: 3,
                payload,
            })
            .collect(),
        bodies: Vec::new(),
        dead: Vec::new(),
    }
}

async fn read(data: &DataFile, location: Location) -> Vec<u8> {
    let offset = data.region_offset(location.region) + location.offset;
    let len = location.size as usize;
    let (result, buf) = data.file().read_at(Buf::new(len), offset).await;
    assert_eq!(result.expect("read"), len);
    let record = Record::decode(&buf).expect("record decodes");
    assert_eq!(record.epoch(), location.epoch);
    assert_eq!(record.sequence(), location.sequence);
    record.payload().to_vec()
}

async fn damage(data: &DataFile, location: Location) {
    let file = File::open(
        PATH,
        &OpenOptions {
            read: true,
            write: true,
            ..OpenOptions::default()
        },
    )
    .await
    .expect("open raw");
    let at = data.region_offset(location.region) + location.offset + 50;
    let (result, _) = file.write_all_at(Buf::from_slice(&[0x5A; 16]), at).await;
    result.expect("damage");
    file.sync_data().await.expect("sync");
}

async fn three_batches() -> Vec<Durable> {
    let (client, committer) = start().await;
    let mut durable = Vec::new();
    for step in 0..3 {
        let records = vec![payload(1, step, 300)];
        durable.push(client.commit(submission(records)).await.expect("commit"));
    }
    drop(client);
    committer.await;
    durable
}

fn sequences(recovered: &Recovered) -> Vec<u64> {
    recovered.entries.iter().map(|e| e.sequence).collect()
}

#[test]
fn state_is_rebuilt_and_writing_continues() {
    let driver = created(1);
    run(&driver, async {
        let (client, committer) = start().await;
        let mut acked = Vec::new();
        for step in 0..5 {
            let records = vec![payload(1, step, 40_000)];
            let durable = client
                .commit(submission(records.clone()))
                .await
                .expect("commit");
            acked.push((durable, records));
        }
        drop(client);
        let committer = committer.await;
        let used: BTreeSet<u32> = (0..OPTIONS.region_count)
            .filter(|&r| committer.regions().is_used(r))
            .collect();
        assert!(used.len() > 1, "the stream moved to a second region");
        drop(committer);
        let last = acked.last().expect("acked").0.locations[0].sequence;
        let (data, recovered) = reopen().await;
        let recovered = recovered.expect("recover");
        assert_eq!(recovered.torn, None);
        assert_eq!(sequences(&recovered), vec![1, 2, 3, 4, 5]);
        let state = &recovered.state;
        let rebuilt: BTreeSet<u32> = (0..OPTIONS.region_count)
            .filter(|&r| state.regions.is_used(r))
            .collect();
        assert_eq!(rebuilt, used);
        for region in &used {
            assert_eq!(state.epochs[*region as usize], 1);
        }
        assert_eq!(state.record_sequence, last + 1);
        drop(data);
        drop(recovered);
        let (client, committer) = start().await;
        let next = client
            .commit(submission(vec![payload(2, 0, 100)]))
            .await
            .expect("commit after recovery");
        assert_eq!(next.sequence, 6);
        assert_eq!(next.locations[0].sequence, last + 1);
        assert!(!used.contains(&next.locations[0].region));
        drop(client);
        let committer = committer.await;
        for (durable, records) in &acked {
            for (location, expected) in durable.locations.iter().zip(records) {
                assert_eq!(&read(committer.data(), *location).await, expected);
            }
        }
    });
}

#[test]
fn a_torn_last_batch_is_cut_once() {
    let driver = created(2);
    run(&driver, async {
        let durable = three_batches().await;
        let (data, _) = reopen().await;
        damage(&data, durable[2].locations[0]).await;
        drop(data);
        let (_, recovered) = reopen().await;
        let recovered = recovered.expect("recover");
        assert_eq!(recovered.torn, Some(3));
        assert_eq!(sequences(&recovered), vec![1, 2]);
        assert_eq!(recovered.journal.position().sequence, 3);
        drop(recovered);
        let (_, again) = reopen().await;
        let again = again.expect("recover again");
        assert_eq!(again.torn, None, "the cut commit was erased");
        assert_eq!(sequences(&again), vec![1, 2]);
        drop(again);
        let (client, committer) = start().await;
        let next = client
            .commit(submission(vec![payload(2, 0, 100)]))
            .await
            .expect("commit after cut");
        assert_eq!(next.sequence, 3);
        assert_eq!(
            next.locations[0].sequence, durable[2].locations[0].sequence,
            "the cut record sequence is reused"
        );
        drop(client);
        committer.await;
        let (_, last) = reopen().await;
        let last = last.expect("recover after new commit");
        assert_eq!(last.torn, None);
        assert_eq!(sequences(&last), vec![1, 2, 3]);
    });
}

#[test]
fn a_damaged_batch_with_a_successor_stops_recovery() {
    let driver = created(3);
    run(&driver, async {
        let durable = three_batches().await;
        let (data, _) = reopen().await;
        damage(&data, durable[1].locations[0]).await;
        drop(data);
        let (_, recovered) = reopen().await;
        assert!(matches!(
            recovered,
            Err(Error::Lost {
                sequence: 2,
                newer: 3
            })
        ));
        let (_, again) = reopen().await;
        assert!(
            matches!(again, Err(Error::Lost { .. })),
            "nothing was cut or overwritten"
        );
    });
}

#[test]
fn a_commit_that_does_not_match_the_state_is_reported() {
    let driver = Rc::new(SimDriver::new(4, Config::default()));
    run(&driver, async {
        let data = DataFile::create(PATH, &OPTIONS).await.expect("create");
        let (mut journal, _) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        let commit = Commit {
            record_sequence: 1,
            ranges: vec![Range {
                region: 2,
                epoch: 1,
                offset: 0,
                length: 4096,
                checksum: 0,
            }],
            ..Commit::default()
        };
        journal.append(data.file(), &commit).await.expect("append");
        data.file().sync_data().await.expect("sync");
        let state = State::new(OPTIONS.region_count, 0);
        let recovered = recover(&data, Position::START, state).await;
        assert!(matches!(recovered, Err(Error::BadCommit(1))));
    });
}

#[test]
fn acknowledged_records_survive_repeated_crashes() {
    check(0..100, |seed| {
        let faults = Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        };
        let config = Config {
            faults,
            ..Config::default()
        };
        let mut disk = created(seed).crash();
        let acked: Rc<RefCell<Acked>> = Rc::default();
        for round in 0..3u64 {
            let driver = Rc::new(SimDriver::with_disk(seed * 4 + round, config.clone(), disk));
            let out = acked.clone();
            let wait = Duration::from_micros(driver.random() % 60_000);
            run(&driver, async move {
                let (client, _committer) = start().await;
                for id in 0..3u64 {
                    let client = client.clone();
                    let acked = out.clone();
                    spawn(async move {
                        for step in 0..20u64 {
                            let len = 30 + usize::try_from(step).expect("fits") * 37;
                            let records = vec![payload(round * 10 + id, step, len)];
                            if let Ok(durable) = client.commit(submission(records.clone())).await {
                                acked.borrow_mut().push((durable, records));
                            }
                        }
                    });
                }
                sleep(wait).await;
            });
            disk = driver.crash();
        }
        let driver = Rc::new(SimDriver::with_disk(seed * 4 + 3, Config::default(), disk));
        let acked = acked.take();
        run(&driver, async move {
            let (data, recovered) = reopen().await;
            let recovered = recovered.expect("recover after crashes");
            let mut seen = BTreeSet::new();
            for (durable, records) in &acked {
                for (location, expected) in durable.locations.iter().zip(records) {
                    assert!(
                        seen.insert(location.sequence),
                        "record sequence {} acknowledged twice",
                        location.sequence
                    );
                    assert!(recovered.state.regions.is_used(location.region));
                    assert_eq!(
                        recovered.state.epochs[location.region as usize],
                        location.epoch
                    );
                    assert_eq!(&read(&data, *location).await, expected);
                }
            }
            if let Some(&highest) = seen.last() {
                assert!(recovered.state.record_sequence > highest);
            }
        });
    });
}
