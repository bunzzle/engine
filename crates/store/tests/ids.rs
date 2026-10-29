use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, SimDriver, check};
use rt::{JoinHandle, Runtime, sleep, spawn};
use store::{
    Client, Committer, DataFile, Ids, Options, SLOT_SIZE, Setup, boot, load, message_key, recover,
    split_key,
};

const PATH: &str = "/data/store";
const MILLION: u32 = 1_000_000;

const OPTIONS: Options = Options {
    journal_size: 2 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: 4,
};

const SETUP: Setup = Setup {
    cores: 2,
    credits: 2,
    reserve: 0,
};

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

async fn stored_boot() -> u32 {
    DataFile::open(PATH)
        .await
        .expect("open")
        .superblock()
        .boot()
}

async fn start() -> (Client, JoinHandle<Committer>) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
    (client, spawn(committer.run()))
}

#[test]
fn ids_count_per_shard_from_one() {
    let mut ids = Ids::new(5, &[0, 2]);
    assert_eq!(ids.next(0), Some(message_key(5, 1)));
    assert_eq!(ids.next(0), Some(message_key(5, 2)));
    assert_eq!(ids.next(2), Some(message_key(5, 1)));
    assert_eq!(ids.next(1), None);
    assert_eq!(ids.boot(0), Some(5));
    assert_eq!(ids.boot(1), None);
}

#[test]
fn ids_run_out_and_renew_with_a_new_boot() {
    let mut ids = Ids::starting_at(3, &[1], u32::MAX - 1);
    assert_eq!(ids.next(1), Some(message_key(3, u32::MAX - 1)));
    assert_eq!(ids.next(1), Some(message_key(3, u32::MAX)));
    assert_eq!(ids.next(1), None);
    assert_eq!(ids.next(1), None);
    ids.renew(1, 4);
    assert_eq!(ids.boot(1), Some(4));
    assert_eq!(ids.next(1), Some(message_key(4, 1)));
}

#[test]
#[should_panic(expected = "boot must move forwards")]
fn renew_refuses_an_older_boot() {
    let mut ids = Ids::new(3, &[1]);
    ids.renew(1, 3);
}

#[test]
fn keys_order_by_boot_then_counter() {
    assert_eq!(split_key(message_key(7, 9)), (7, 9));
    assert_eq!(
        split_key(message_key(u32::MAX, u32::MAX)),
        (u32::MAX, u32::MAX)
    );
    assert!(message_key(1, u32::MAX) < message_key(2, 1));
    assert!(message_key(2, 1) < message_key(2, 2));
}

#[test]
fn every_start_takes_a_new_boot() {
    let driver = Rc::new(SimDriver::with_disk(1, Config::default(), created(1)));
    Runtime::new(driver).block_on(async {
        assert_eq!(stored_boot().await, 0);
        for expected in 1..=3 {
            let booted = boot(PATH, SETUP).await.expect("boot");
            let committer = spawn(booted.committer.run());
            for start in booted.starts {
                let mut core = start.open().await.expect("open");
                for &shard in &core.shards {
                    assert_eq!(core.ids.boot(shard), Some(expected));
                    assert_eq!(core.ids.next(shard), Some(message_key(expected, 1)));
                }
            }
            drop(booted.client);
            drop(committer.await);
            assert_eq!(stored_boot().await, expected);
        }
    });
}

#[test]
fn a_boot_handed_out_is_never_handed_out_again() {
    check(0..100, |seed| {
        let faults = Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        };
        let config = Config {
            faults,
            ..Config::default()
        };
        let mut disk = created(seed);
        let mut seen: Vec<u32> = Vec::new();
        for round in 0..6u64 {
            let driver = Rc::new(SimDriver::with_disk(seed * 8 + round, config.clone(), disk));
            let wait = Duration::from_micros(driver.random() % 3_000);
            let handed: Rc<Cell<Option<u32>>> = Rc::default();
            let out = handed.clone();
            Runtime::new(driver.clone()).block_on(async move {
                spawn(async move {
                    if let Ok(booted) = boot(PATH, SETUP).await {
                        let _committer = spawn(booted.committer.run());
                        for start in booted.starts {
                            if let Ok(core) = start.open().await {
                                out.set(core.ids.boot(core.shards[0]));
                            }
                        }
                    }
                });
                sleep(wait).await;
            });
            if let Some(found) = handed.get() {
                assert!(
                    seen.iter().all(|&old| old < found),
                    "boot {found} after {seen:?}"
                );
                seen.push(found);
            }
            disk = driver.crash();
        }
    });
}

#[test]
fn a_running_store_renews_the_boot_at_the_next_checkpoint() {
    let driver = Rc::new(SimDriver::with_disk(2, Config::default(), created(2)));
    Runtime::new(driver).block_on(async {
        let (client, committer) = start().await;
        let first = client.clone();
        let second = client.clone();
        let (a, b) = (
            spawn(async move { first.boot().await }),
            spawn(async move { second.boot().await }),
        );
        assert_eq!(a.await.expect("renew"), 1);
        assert_eq!(b.await.expect("renew"), 1);
        client.checkpoint().await.expect("checkpoint");
        assert_eq!(client.boot().await.expect("renew"), 2);
        drop(client);
        drop(committer.await);
        assert_eq!(stored_boot().await, 2);
        let (client, committer) = start().await;
        client.checkpoint().await.expect("checkpoint");
        drop(client);
        drop(committer.await);
        assert_eq!(stored_boot().await, 2);
    });
}
