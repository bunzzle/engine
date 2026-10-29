use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Faults, SimDriver, check};
use rt::{Buf, File, OpenOptions, Runtime, sleep, spawn};
use store::{
    Allocation, Commit, DataFile, Dead, Entry, Error, Journal, Live, Options, Position, Range,
    SLOT_SIZE,
};

const MILLION: u32 = 1_000_000;
const PATH: &str = "/data/store";
const SECTOR: u64 = 4096;

const OPTIONS: Options = Options {
    journal_size: SLOT_SIZE,
    region_size: SLOT_SIZE,
    region_count: 2,
    shards: 2,
};

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

fn commit(sequence: u64, ranges: usize) -> Commit {
    Commit {
        live: vec![Live {
            tenant: 4,
            region: 1,
            extents: u32::try_from(ranges).expect("fits"),
            bytes: sequence * 10,
        }],
        dead: vec![Dead {
            tenant: 4,
            region: 0,
            epoch: sequence,
            offset: SECTOR,
            length: 48,
        }],
        record_sequence: sequence,
        ranges: (0..ranges)
            .map(|i| Range {
                region: u32::try_from(i % 2).expect("fits"),
                epoch: sequence,
                offset: i as u64 * SECTOR,
                length: 100,
                checksum: u32::try_from(sequence).expect("fits") ^ 0xA5A5,
            })
            .collect(),
        allocations: vec![Allocation {
            region: 1,
            epoch: sequence,
        }],
    }
}

fn ranges_for(sequence: u64) -> usize {
    if sequence.is_multiple_of(5) { 200 } else { 3 }
}

fn sequences(entries: &[Entry]) -> Vec<u64> {
    entries.iter().map(|e| e.sequence).collect()
}

async fn damage(at: u64) {
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
    let (result, _) = file
        .write_all_at(Buf::from_slice(&[0x5A; 64]), at + 50)
        .await;
    result.expect("damage");
}

#[test]
fn appended_commits_are_recovered_in_order() {
    let driver = Rc::new(SimDriver::new(1, Config::default()));
    run(&driver, async {
        let data = DataFile::create(PATH, &OPTIONS).await.expect("create");
        let (mut journal, entries) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        assert_eq!(entries, Vec::new());
        for sequence in 1..=5 {
            let at = journal
                .append(data.file(), &commit(sequence, ranges_for(sequence)))
                .await
                .expect("append");
            assert_eq!(at.sequence, sequence);
        }
        data.file().sync_data().await.expect("sync");
        let next = journal.position();
        let (again, entries) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        assert_eq!(sequences(&entries), vec![1, 2, 3, 4, 5]);
        for entry in &entries {
            assert_eq!(
                entry.commit,
                commit(entry.sequence, ranges_for(entry.sequence))
            );
        }
        assert_eq!(again.position(), next);
        assert_eq!(again.free(), journal.free());
    });
}

#[test]
fn the_ring_wraps_and_ignores_older_laps() {
    let driver = Rc::new(SimDriver::new(2, Config::default()));
    run(&driver, async {
        let data = DataFile::create(PATH, &OPTIONS).await.expect("create");
        let (mut journal, _) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        let mut written = Vec::new();
        for sequence in 1..=60 {
            let at = journal
                .append(data.file(), &commit(sequence, ranges_for(sequence)))
                .await
                .expect("append");
            written.push(at);
            journal.release(sequence.saturating_sub(4));
        }
        data.file().sync_data().await.expect("sync");
        let start = written[55];
        let (again, entries) = Journal::recover(&data, start).await.expect("recover");
        assert_eq!(sequences(&entries), (56..=60).collect::<Vec<_>>());
        assert_eq!(again.position(), journal.position());
    });
}

#[test]
fn a_full_ring_applies_backpressure() {
    let driver = Rc::new(SimDriver::new(3, Config::default()));
    run(&driver, async {
        let data = DataFile::create(PATH, &OPTIONS).await.expect("create");
        let (mut journal, _) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        for sequence in 1..=16 {
            journal
                .append(data.file(), &commit(sequence, 1))
                .await
                .expect("append");
        }
        assert_eq!(journal.free(), 0);
        assert!(matches!(
            journal.append(data.file(), &commit(17, 1)).await,
            Err(Error::JournalFull)
        ));
        journal.release(2);
        journal
            .append(data.file(), &commit(17, 1))
            .await
            .expect("append after release");
        let huge = commit(18, 40_000);
        assert!(matches!(
            journal.append(data.file(), &huge).await,
            Err(Error::CommitTooLarge)
        ));
    });
}

#[test]
fn a_damaged_copy_is_read_from_the_other_ring_and_a_lost_one_stops() {
    let driver = Rc::new(SimDriver::new(4, Config::default()));
    run(&driver, async {
        let data = DataFile::create(PATH, &OPTIONS).await.expect("create");
        let rings = data.superblock().journal_offsets();
        let (mut journal, _) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        let mut second = Position::START;
        for sequence in 1..=3 {
            let at = journal
                .append(data.file(), &commit(sequence, 2))
                .await
                .expect("append");
            if sequence == 2 {
                second = at;
            }
        }
        damage(rings[0] + second.offset).await;
        let (_, entries) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        assert_eq!(sequences(&entries), vec![1, 2, 3]);
        damage(rings[1] + second.offset).await;
        let (_, entries) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        assert_eq!(sequences(&entries), vec![1, 2, 3], "ring A was repaired");
        damage(rings[0] + second.offset).await;
        damage(rings[1] + second.offset).await;
        let lost = Journal::recover(&data, Position::START).await;
        assert!(
            matches!(
                lost,
                Err(Error::Lost {
                    sequence: 2,
                    newer: 3
                })
            ),
            "a damaged middle commit stops recovery"
        );
    });
}

async fn raw(at: u64) -> Vec<u8> {
    let file = File::open(
        PATH,
        &OpenOptions {
            read: true,
            ..OpenOptions::default()
        },
    )
    .await
    .expect("open raw");
    let (result, buf) = file.read_at(Buf::new(4096), at).await;
    result.expect("read raw");
    buf.to_vec()
}

async fn overwrite(at: u64, bytes: Vec<u8>) {
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
    let (result, _) = file.write_all_at(Buf::from_slice(&bytes), at).await;
    result.expect("overwrite");
    file.sync_data().await.expect("sync");
}

async fn two_versions_of_the_second_commit(with_successor: bool) -> Result<Vec<u64>, Error> {
    let data = DataFile::create(PATH, &OPTIONS).await.expect("create");
    let rings = data.superblock().journal_offsets();
    let (mut journal, _) = Journal::recover(&data, Position::START)
        .await
        .expect("recover");
    journal
        .append(data.file(), &commit(1, 2))
        .await
        .expect("append");
    let stale = journal
        .append(data.file(), &commit(2, 5))
        .await
        .expect("append");
    data.file().sync_data().await.expect("sync");
    let stale_bytes = raw(rings[0] + stale.offset).await;
    damage(rings[0] + stale.offset).await;
    damage(rings[1] + stale.offset).await;
    let (mut journal, entries) = Journal::recover(&data, Position::START)
        .await
        .expect("recover");
    assert_eq!(sequences(&entries), vec![1]);
    journal
        .append(data.file(), &commit(2, 2))
        .await
        .expect("append");
    if with_successor {
        journal
            .append(data.file(), &commit(3, 2))
            .await
            .expect("append");
    }
    data.file().sync_data().await.expect("sync");
    overwrite(rings[0] + stale.offset, stale_bytes).await;
    let (_, entries) = Journal::recover(&data, Position::START).await?;
    for entry in &entries {
        assert_eq!(entry.commit, commit(entry.sequence, 2));
    }
    let first = sequences(&entries);
    damage(rings[1] + stale.offset).await;
    let (_, entries) = Journal::recover(&data, Position::START).await?;
    assert_eq!(sequences(&entries), first, "ring A was repaired");
    Ok(first)
}

#[test]
fn the_copy_with_a_successor_wins_when_the_rings_disagree() {
    let driver = Rc::new(SimDriver::new(5, Config::default()));
    let result = run(&driver, two_versions_of_the_second_commit(true));
    assert_eq!(result.expect("recovers"), vec![1, 2, 3]);
}

#[test]
fn rings_that_disagree_without_a_successor_are_a_fork() {
    let driver = Rc::new(SimDriver::new(6, Config::default()));
    let result = run(&driver, two_versions_of_the_second_commit(false));
    assert!(matches!(result, Err(Error::JournalFork)));
}

#[test]
fn a_read_error_is_never_the_end_of_the_log() {
    check(0..80, |seed| {
        let setup = Rc::new(SimDriver::new(seed, Config::default()));
        run(&setup, async {
            let data = DataFile::create(PATH, &OPTIONS).await.expect("create");
            let (mut journal, _) = Journal::recover(&data, Position::START)
                .await
                .expect("recover");
            for sequence in 1..=4 {
                journal
                    .append(data.file(), &commit(sequence, 2))
                    .await
                    .expect("append");
            }
            data.file().sync_data().await.expect("sync");
        });
        let config = Config {
            faults: Faults {
                read_error: MILLION / 20,
                ..Faults::default()
            },
            ..Config::default()
        };
        let driver = Rc::new(SimDriver::with_disk(seed, config, setup.crash()));
        run(&driver, async {
            let Ok(data) = DataFile::open(PATH).await else {
                return;
            };
            match Journal::recover(&data, Position::START).await {
                Ok((_, entries)) => assert_eq!(sequences(&entries), vec![1, 2, 3, 4]),
                Err(e) => assert!(matches!(e, Error::Io(_)), "unexpected error {e}"),
            }
        });
    });
}

#[test]
fn every_synced_commit_survives_a_crash() {
    check(0..200, |seed| {
        let faults = Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        };
        let setup = Rc::new(SimDriver::new(seed, Config::default()));
        run(&setup, async {
            DataFile::create(PATH, &OPTIONS).await.expect("create");
        });
        let config = Config {
            faults,
            ..Config::default()
        };
        let driver = Rc::new(SimDriver::with_disk(seed, config, setup.crash()));
        let synced = Rc::new(Cell::new(0u64));
        let start = Rc::new(Cell::new(Position::START));
        let counter = synced.clone();
        let oldest = start.clone();
        let wait = Duration::from_micros(driver.random() % 400_000);
        run(&driver, async move {
            spawn(async move {
                let data = DataFile::open(PATH).await.expect("open");
                let (mut journal, _) = Journal::recover(&data, Position::START)
                    .await
                    .expect("recover");
                let positions = RefCell::new(Vec::new());
                let mut sequence = 0;
                loop {
                    sequence += 1;
                    let at = journal
                        .append(data.file(), &commit(sequence, ranges_for(sequence)))
                        .await
                        .expect("append");
                    positions.borrow_mut().push(at);
                    data.file().sync_data().await.expect("sync");
                    counter.set(sequence);
                    if sequence > 3 {
                        let keep = positions.borrow()[usize::try_from(sequence - 3).expect("fits")];
                        oldest.set(keep);
                        journal.release(keep.sequence - 1);
                    }
                }
            });
            sleep(wait).await;
        });
        let durable = synced.get();
        let start = start.get();
        let driver = Rc::new(SimDriver::with_disk(
            seed + 1,
            Config::default(),
            driver.crash(),
        ));
        run(&driver, async move {
            let data = DataFile::open(PATH).await.expect("open after crash");
            let (_, entries) = Journal::recover(&data, start).await.expect("recover");
            let last = entries.last().map_or(start.sequence - 1, |e| e.sequence);
            assert!(last >= durable, "lost synced commits: {last} < {durable}");
            for (index, entry) in entries.iter().enumerate() {
                assert_eq!(entry.sequence, start.sequence + index as u64);
                assert_eq!(
                    entry.commit,
                    commit(entry.sequence, ranges_for(entry.sequence))
                );
            }
        });
    });
}
