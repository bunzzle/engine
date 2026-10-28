use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Faults, SimDriver, check};
use rt::{Buf, File, JoinHandle, OpenOptions, Runtime, sleep, spawn};
use store::{
    Claim, Client, Committer, DataFile, Durable, Error, Journal, Location, Options, Position,
    Range, Record, Regions, SLOT_SIZE, Submission, Write, ZONE_SIZE, checksum,
};

const MILLION: u32 = 1_000_000;

type Acked = Vec<(Durable, Vec<Vec<u8>>)>;
const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 16 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 8,
    shards: 4,
};

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

async fn start(reserve: u32) -> (Client, JoinHandle<Committer>) {
    let data = DataFile::open(PATH).await.expect("open");
    let (journal, _) = Journal::recover(&data, Position::START)
        .await
        .expect("recover");
    let regions = Regions::new(OPTIONS.region_count, reserve);
    let (committer, client) = Committer::new(data, journal, regions);
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
                tenant: 3,
                payload,
            })
            .collect(),
        ranges: Vec::new(),
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

#[test]
fn concurrent_submissions_share_commits() {
    let driver = created(1);
    run(&driver, async {
        let (client, committer) = start(0).await;
        let acked = Rc::new(RefCell::new(Vec::new()));
        let mut tasks = Vec::new();
        for id in 0..20u64 {
            let client = client.clone();
            let acked = acked.clone();
            tasks.push(spawn(async move {
                for step in 0..5u64 {
                    let records = vec![payload(id, step, 40), payload(id, step + 100, 300)];
                    let durable = client
                        .commit(submission(records.clone()))
                        .await
                        .expect("commit");
                    acked.borrow_mut().push((durable, records));
                }
            }));
        }
        for task in tasks {
            task.await;
        }
        drop(client);
        let committer = committer.await;
        let acked = acked.take();
        let commits: BTreeSet<u64> = acked.iter().map(|(d, _)| d.sequence).collect();
        assert_eq!(acked.len(), 100);
        assert!(
            commits.len() < 100,
            "no grouping: {} commits",
            commits.len()
        );
        for (durable, records) in &acked {
            for (location, expected) in durable.locations.iter().zip(records) {
                assert_eq!(&read(committer.data(), *location).await, expected);
            }
        }
        let (_, entries) = Journal::recover(committer.data(), Position::START)
            .await
            .expect("recover");
        assert_eq!(entries.len(), commits.len());
        for entry in &entries {
            for range in &entry.commit.ranges {
                let offset = committer.data().region_offset(range.region) + range.offset;
                let len = range.length as usize;
                let (result, buf) = committer.data().file().read_at(Buf::new(len), offset).await;
                assert_eq!(result.expect("read"), len);
                assert_eq!(checksum(&buf), range.checksum);
                assert!(range.offset.is_multiple_of(4096) && len.is_multiple_of(4096));
            }
        }
    });
}

#[test]
fn the_stream_moves_to_a_new_region_when_full() {
    let driver = created(2);
    run(&driver, async {
        let (client, committer) = start(0).await;
        let mut regions = BTreeSet::new();
        for step in 0..30u64 {
            let durable = client
                .commit(submission(vec![payload(0, step, 10_000)]))
                .await
                .expect("commit");
            regions.insert(durable.locations[0].region);
        }
        drop(client);
        let committer = committer.await;
        assert!(regions.len() >= 3, "regions used: {regions:?}");
        let (_, entries) = Journal::recover(committer.data(), Position::START)
            .await
            .expect("recover");
        let allocated: BTreeSet<u32> = entries
            .iter()
            .flat_map(|e| e.commit.allocations.iter().map(|a| a.region))
            .collect();
        assert_eq!(allocated, regions);
    });
}

#[test]
fn body_ranges_are_committed_with_their_allocation() {
    let driver = created(3);
    run(&driver, async {
        let (client, committer) = start(0).await;
        let (region, epoch) = client.allocate(Claim::Intake).await.expect("allocate");
        let file = File::open(
            PATH,
            &OpenOptions {
                read: true,
                write: true,
                ..OpenOptions::default()
            },
        )
        .await
        .expect("open");
        let body = vec![9u8; 8192];
        let offset = ZONE_SIZE + OPTIONS.journal_size + u64::from(region) * OPTIONS.region_size;
        let (result, _) = file.write_all_at(Buf::from_slice(&body), offset).await;
        result.expect("write body");
        let range = Range {
            region,
            epoch,
            offset: 0,
            length: 8192,
            checksum: checksum(&body),
        };
        let bad = Range {
            offset: 100,
            ..range
        };
        let refused = client
            .commit(Submission {
                ranges: vec![bad],
                ..submission(Vec::new())
            })
            .await;
        assert!(matches!(refused, Err(Error::Invalid("range"))));
        let durable = client
            .commit(Submission {
                ranges: vec![range],
                ..submission(vec![payload(1, 1, 50)])
            })
            .await
            .expect("commit");
        drop(client);
        let committer = committer.await;
        assert_eq!(
            committer.data().region_offset(region),
            offset,
            "test layout matches"
        );
        let (_, entries) = Journal::recover(committer.data(), Position::START)
            .await
            .expect("recover");
        let entry = entries
            .iter()
            .find(|e| e.sequence == durable.sequence)
            .expect("commit found");
        assert!(entry.commit.ranges.contains(&range));
        assert!(
            entry
                .commit
                .allocations
                .iter()
                .any(|a| a.region == region && a.epoch == epoch)
        );
    });
}

#[test]
fn intake_is_refused_at_the_reserve() {
    let driver = created(4);
    run(&driver, async {
        let (client, committer) = start(7).await;
        client
            .commit(submission(vec![payload(0, 0, 10)]))
            .await
            .expect("first region");
        assert!(matches!(
            client.allocate(Claim::Intake).await,
            Err(Error::Reserve)
        ));
        client
            .allocate(Claim::Internal)
            .await
            .expect("internal claim");
        drop(client);
        assert_eq!(committer.await.regions().free(), 6);
    });
}

#[test]
fn a_failed_sync_fails_every_caller() {
    let setup = created(5);
    let faults = Faults {
        sync_error: MILLION,
        ..Faults::default()
    };
    let config = Config {
        faults,
        ..Config::default()
    };
    let driver = Rc::new(SimDriver::with_disk(6, config, setup.crash()));
    run(&driver, async {
        let (client, committer) = start(0).await;
        let first = client.commit(submission(vec![payload(0, 0, 10)])).await;
        assert!(matches!(first, Err(Error::Failed)));
        let second = client.commit(submission(vec![payload(0, 1, 10)])).await;
        assert!(matches!(second, Err(Error::Failed)));
        assert!(matches!(
            client.allocate(Claim::Internal).await,
            Err(Error::Failed)
        ));
        drop(client);
        assert!(committer.await.is_failed());
    });
}

#[test]
fn acknowledged_records_survive_a_crash() {
    check(0..150, |seed| {
        let setup = created(seed);
        let faults = Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        };
        let config = Config {
            faults,
            ..Config::default()
        };
        let driver = Rc::new(SimDriver::with_disk(seed, config, setup.crash()));
        let acked: Rc<RefCell<Acked>> = Rc::default();
        let out = acked.clone();
        let wait = Duration::from_micros(driver.random() % 60_000);
        run(&driver, async move {
            let (client, _committer) = start(0).await;
            for id in 0..4u64 {
                let client = client.clone();
                let acked = out.clone();
                spawn(async move {
                    for step in 0..30u64 {
                        let records = vec![payload(
                            id,
                            step,
                            30 + usize::try_from(step).expect("fits") * 37,
                        )];
                        if let Ok(durable) = client.commit(submission(records.clone())).await {
                            acked.borrow_mut().push((durable, records));
                        }
                    }
                });
            }
            sleep(wait).await;
        });
        let acked = acked.take();
        let driver = Rc::new(SimDriver::with_disk(
            seed + 1,
            Config::default(),
            driver.crash(),
        ));
        run(&driver, async move {
            let data = DataFile::open(PATH).await.expect("open after crash");
            let (_, entries) = Journal::recover(&data, Position::START)
                .await
                .expect("recover");
            let last = entries.last().map_or(0, |e| e.sequence);
            for (durable, records) in &acked {
                assert!(
                    durable.sequence <= last,
                    "acked commit {} lost",
                    durable.sequence
                );
                for (location, expected) in durable.locations.iter().zip(records) {
                    assert_eq!(&read(&data, *location).await, expected);
                }
            }
        });
    });
}
