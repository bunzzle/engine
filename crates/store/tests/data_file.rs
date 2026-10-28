use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, SimDriver, check};
use rt::{Buf, File, OpenOptions, Runtime, sleep, spawn};
use store::{Checkpoint, Claim, DataFile, Error, FORMAT, Options, Regions, SLOT_SIZE, ZONE_SIZE};

const MILLION: u32 = 1_000_000;
const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 4,
    shards: 8,
};

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

fn config(edit: impl FnOnce(&mut Config)) -> Config {
    let mut config = Config::default();
    edit(&mut config);
    config
}

fn checkpoint(sequence: u64) -> Checkpoint {
    Checkpoint {
        sequence,
        offset: ZONE_SIZE,
        length: 4096,
        checksum: 42,
    }
}

fn created(seed: u64) -> Disk {
    let driver = Rc::new(SimDriver::new(seed, Config::default()));
    run(&driver, async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    driver.crash()
}

fn restart(seed: u64, disk: Disk, config: Config) -> Rc<SimDriver> {
    Rc::new(SimDriver::with_disk(seed, config, disk))
}

async fn damage(slots: &[usize]) {
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
    for &slot in slots {
        let (result, _) = file
            .write_all_at(Buf::from_slice(&[0xAB; 512]), SLOT_SIZE * slot as u64 + 100)
            .await;
        result.expect("damage");
    }
    file.sync_data().await.expect("sync");
}

#[test]
fn create_then_open_reads_the_same_superblock() {
    let driver = restart(2, created(1), Config::default());
    run(&driver, async {
        let data = DataFile::open(PATH).await.expect("open");
        let superblock = data.superblock();
        assert_eq!(superblock.format(), FORMAT);
        assert_eq!(superblock.oldest_format(), FORMAT);
        assert_eq!(superblock.sector_size(), 4096);
        assert_eq!(superblock.sequence(), 1);
        assert_eq!(superblock.shards(), 8);
        assert_eq!(superblock.region_count(), 4);
        assert_eq!(superblock.checkpoint(), None);
        assert_eq!(superblock.file_size(), ZONE_SIZE + 10 * SLOT_SIZE);
        assert_eq!(data.region_offset(0), ZONE_SIZE + SLOT_SIZE);
        assert_eq!(data.region_offset(3), ZONE_SIZE + 7 * SLOT_SIZE);
        assert_eq!(
            superblock.journal_offsets(),
            [ZONE_SIZE, ZONE_SIZE + 9 * SLOT_SIZE]
        );
        let stat = data.file().stat().await.expect("stat");
        assert_eq!(stat.len, superblock.file_size());
    });
}

#[test]
fn the_data_file_is_zero_filled() {
    let disk = created(3);
    let bytes = disk
        .contents(std::path::Path::new(PATH))
        .expect("file exists");
    let regions = usize::try_from(ZONE_SIZE).expect("fits");
    assert!(bytes[regions..].iter().all(|&b| b == 0));
}

#[test]
fn create_refuses_bad_options_and_existing_files() {
    let driver = restart(4, created(3), Config::default());
    run(&driver, async {
        let bad = Options {
            region_size: SLOT_SIZE + 1,
            ..OPTIONS
        };
        assert!(matches!(
            DataFile::create("/data/other", &bad).await,
            Err(Error::Config(_))
        ));
        assert!(matches!(
            DataFile::create(PATH, &OPTIONS).await,
            Err(Error::Io(_))
        ));
    });
}

#[test]
fn an_empty_file_is_not_formatted() {
    let driver = Rc::new(SimDriver::new(5, Config::default()));
    run(&driver, async {
        let file = File::open(
            PATH,
            &OpenOptions {
                read: true,
                write: true,
                create: true,
                ..OpenOptions::default()
            },
        )
        .await
        .expect("create raw");
        let (result, _) = file
            .write_all_at(Buf::from_slice(&[0; 4096]), ZONE_SIZE)
            .await;
        result.expect("write");
        assert!(matches!(
            DataFile::open(PATH).await,
            Err(Error::NotFormatted)
        ));
    });
}

#[test]
fn a_changed_sector_size_refuses_to_open() {
    let mut disk = created(6);
    disk.set_sector_size(8192);
    let driver = restart(7, disk, config(|c| c.sector_size = 8192));
    run(&driver, async {
        assert!(matches!(
            DataFile::open(PATH).await,
            Err(Error::SectorSizeChanged {
                stored: 4096,
                found: 8192
            })
        ));
    });
}

#[test]
fn an_unsupported_sector_size_is_refused() {
    let driver = Rc::new(SimDriver::new(8, config(|c| c.sector_size = 128 * 1024)));
    run(&driver, async {
        assert!(matches!(
            DataFile::create(PATH, &OPTIONS).await,
            Err(Error::UnsupportedSectorSize(131_072))
        ));
    });
}

#[test]
fn two_damaged_copies_are_repaired() {
    let driver = restart(10, created(9), Config::default());
    run(&driver, async {
        damage(&[0, 1]).await;
        drop(DataFile::open(PATH).await.expect("open with two copies"));
        damage(&[2, 3]).await;
        let data = DataFile::open(PATH).await.expect("open after repair");
        assert_eq!(data.superblock().sequence(), 1);
    });
}

#[test]
fn three_damaged_copies_lose_the_quorum() {
    let driver = restart(12, created(11), Config::default());
    run(&driver, async {
        damage(&[0, 1, 3]).await;
        assert!(matches!(DataFile::open(PATH).await, Err(Error::QuorumLost)));
    });
}

#[test]
fn updates_chain_and_survive_a_restart() {
    let driver = restart(14, created(13), Config::default());
    run(&driver, async {
        let mut data = DataFile::open(PATH).await.expect("open");
        data.update(Some(checkpoint(5)), FORMAT)
            .await
            .expect("update");
        data.update(Some(checkpoint(9)), FORMAT)
            .await
            .expect("update");
    });
    let driver = restart(15, driver.crash(), Config::default());
    run(&driver, async {
        let data = DataFile::open(PATH).await.expect("open");
        assert_eq!(data.superblock().sequence(), 3);
        assert_eq!(data.superblock().checkpoint(), Some(checkpoint(9)));
    });
}

#[test]
fn an_update_is_atomic_across_a_crash() {
    check(0..300, |seed| {
        let faults = Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        };
        let driver = restart(seed, created(seed), config(|c| c.faults = faults));
        let done = Rc::new(Cell::new(false));
        let finished = done.clone();
        let wait = Duration::from_micros(driver.random() % 30_000);
        run(&driver, async move {
            spawn(async move {
                let mut data = DataFile::open(PATH).await.expect("open");
                data.update(Some(checkpoint(7)), FORMAT)
                    .await
                    .expect("update");
                finished.set(true);
            });
            sleep(wait).await;
        });
        let completed = done.get();
        let driver = restart(seed + 1, driver.crash(), Config::default());
        run(&driver, async move {
            let data = DataFile::open(PATH).await.expect("open after crash");
            let found = data.superblock().checkpoint();
            if completed {
                assert_eq!(found, Some(checkpoint(7)));
            } else {
                assert!(found.is_none() || found == Some(checkpoint(7)));
            }
        });
        let driver = restart(seed + 2, driver.crash(), Config::default());
        run(&driver, async {
            DataFile::open(PATH).await.expect("open after repair");
        });
    });
}

#[test]
fn a_failed_sync_fails_the_data_file() {
    let faults = Faults {
        sync_error: MILLION,
        ..Faults::default()
    };
    let driver = restart(17, created(16), config(|c| c.faults = faults));
    run(&driver, async {
        let mut data = DataFile::open(PATH).await.expect("open");
        assert!(matches!(
            data.update(Some(checkpoint(1)), FORMAT).await,
            Err(Error::Io(_))
        ));
        assert!(data.is_failed());
        assert!(matches!(
            data.update(Some(checkpoint(1)), FORMAT).await,
            Err(Error::Failed)
        ));
    });
}

#[test]
fn intake_stops_at_the_reserve() {
    let mut regions = Regions::new(4, 2);
    assert_eq!(regions.acquire(Claim::Intake).expect("first"), 0);
    assert_eq!(regions.acquire(Claim::Intake).expect("second"), 1);
    assert!(matches!(
        regions.acquire(Claim::Intake),
        Err(Error::Reserve)
    ));
    assert_eq!(regions.acquire(Claim::Internal).expect("internal"), 2);
    regions.release(0);
    regions.release(2);
    assert_eq!(regions.acquire(Claim::Intake).expect("reused"), 0);
    regions.mark_used(3);
    assert_eq!(regions.acquire(Claim::Internal).expect("last"), 2);
    assert_eq!(regions.free(), 0);
    assert!(matches!(regions.acquire(Claim::Internal), Err(Error::Full)));
    assert_eq!(regions.count(), 4);
}
