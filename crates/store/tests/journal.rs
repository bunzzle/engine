use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Faults, SimDriver, check};
use rt::{Buf, File, OpenOptions, Runtime, sleep, spawn};
use store::{
    Allocation, Commit, DataFile, Entry, Error, Journal, Options, Position, Range, SLOT_SIZE,
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
fn a_damaged_copy_is_read_from_the_other_ring() {
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
        let (journal, entries) = Journal::recover(&data, Position::START)
            .await
            .expect("recover");
        assert_eq!(sequences(&entries), vec![1]);
        assert_eq!(journal.position().sequence, 2);
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
