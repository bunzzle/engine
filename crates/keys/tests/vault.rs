use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use crypto::{Secret, seal_batch};
use keys::file::{self, Master};
use keys::{Clock, Error, MIN_GAP, MODE, State, Step, Vault};
use rt::sim::{Config, Disk, SimDriver, check};
use rt::{Runtime, sleep, spawn};

const DIR: &str = "/keys";
const MILLION: u32 = 1_000_000;

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

fn quiet() -> Config {
    let mut config = Config::default();
    config.faults.crash_keep = 0;
    config
}

fn fresh(seed: u64) -> Disk {
    let driver = Rc::new(SimDriver::new(seed, quiet()));
    run(&driver, async {
        Vault::init(Path::new(DIR), 100).await.expect("init");
    });
    driver.crash()
}

fn states(disk: &Disk) -> Vec<State> {
    let masters: Vec<Master> = ["master.0", "master.1"]
        .iter()
        .filter_map(|name| disk.contents(&Path::new(DIR).join(name)))
        .filter_map(Master::decode)
        .collect();
    let mut out = Vec::new();
    for name in ["keys.0", "keys.1", "export", "export.tmp"] {
        let Some(bytes) = disk.contents(&Path::new(DIR).join(name)) else {
            continue;
        };
        for master in &masters {
            if let Ok(clear) = file::open(master, bytes) {
                out.push(State::decode(&clear).expect("opened state decodes"));
            }
        }
    }
    out
}

#[test]
fn state_survives_a_restart() {
    let disk = fresh(1);
    let driver = Rc::new(SimDriver::with_disk(1, quiet(), disk));
    let before = run(&driver, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 1, 30).expect("create");
        vault.create(2, 1, 30).expect("create");
        vault.flush().await.expect("flush");
        let keys = vault.keys(1, 1).expect("keys");
        (
            *keys.data.expose(),
            *keys.hash.expose(),
            keys.today,
            keys.tomorrow,
            *vault.naming().expose(),
        )
    });
    let driver = Rc::new(SimDriver::with_disk(2, quiet(), driver.crash()));
    run(&driver, async move {
        let vault = Vault::open(Path::new(DIR)).await.expect("open");
        let keys = vault.keys(1, 1).expect("keys");
        assert_eq!(vault.day(), 100);
        assert_eq!(*keys.data.expose(), before.0);
        assert_eq!(*keys.hash.expose(), before.1);
        assert_eq!((keys.today, keys.tomorrow), (before.2, before.3));
        assert_eq!(*vault.naming().expose(), before.4);
        assert_ne!(keys.today, keys.tomorrow);
        assert!(vault.keys(2, 1).is_ok());
        let listed: Vec<(u32, u32, u16, u32)> = vault
            .listed()
            .iter()
            .map(|l| (l.tenant, l.generation, l.retention, l.oldest))
            .collect();
        assert_eq!(listed, [(1, 1, 30, 100), (2, 1, 30, 100)]);
    });
}

#[test]
fn keys_wait_until_durable_and_create_is_idempotent() {
    let driver = Rc::new(SimDriver::with_disk(3, quiet(), fresh(3)));
    run(&driver, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 4, 30).expect("create");
        assert_eq!(vault.keys(1, 4).err(), Some(Error::Pending));
        vault.flush().await.expect("flush");
        let first = *vault.keys(1, 4).expect("keys").data.expose();
        vault.create(1, 4, 30).expect("same generation again");
        assert!(!vault.is_dirty());
        assert_eq!(*vault.keys(1, 4).expect("keys").data.expose(), first);
        assert_eq!(vault.create(1, 5, 30), Err(Error::Generation));
        assert_eq!(vault.create(2, 1, 0), Err(Error::Retention));
        assert_eq!(vault.keys(1, 5).err(), Some(Error::Unknown));
        assert_eq!(vault.set_retention(1, 4, 0).await, Err(Error::Retention));
        assert_eq!(
            vault.create(3, 1, keys::MAX_RETENTION + 1),
            Err(Error::Retention)
        );
    });
}

#[test]
fn unwrap_opens_only_live_days_of_the_right_tenant() {
    let driver = Rc::new(SimDriver::with_disk(4, quiet(), fresh(4)));
    run(&driver, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 2, 3).expect("create");
        vault.flush().await.expect("flush");
        let keys = vault.keys(1, 2).expect("keys");
        let batch = Secret::new([8; 32]);
        let wrap = seal_batch(&keys.today, 1, 2, 100, 0, 5, &batch).expect("wrap");
        assert!(vault.unwrap(1, 5, &wrap).expect("opens") == batch);
        assert_eq!(vault.unwrap(1, 6, &wrap).err(), Some(Error::Open));
        assert_eq!(vault.unwrap(9, 5, &wrap).err(), Some(Error::Unknown));
        let next = seal_batch(&keys.tomorrow, 1, 2, 101, 0, 5, &batch).expect("wrap");
        assert!(vault.unwrap(1, 5, &next).expect("opens") == batch);
        let late = seal_batch(&keys.tomorrow, 1, 2, 102, 0, 5, &batch).expect("wrap");
        assert_eq!(vault.unwrap(1, 5, &late).err(), Some(Error::Gone));
        let early = seal_batch(&keys.today, 1, 2, 99, 0, 5, &batch).expect("wrap");
        assert_eq!(vault.unwrap(1, 5, &early).err(), Some(Error::Gone));
    });
}

#[test]
fn delete_leaves_nothing_readable_on_disk() {
    let driver = Rc::new(SimDriver::with_disk(5, quiet(), fresh(5)));
    run(&driver, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 1, 30).expect("create");
        vault.create(2, 1, 30).expect("create");
        vault.flush().await.expect("flush");
        vault.create(3, 1, 30).expect("create");
        vault.flush().await.expect("flush");
        vault.delete(2, 1).await.expect("delete");
        assert_eq!(vault.keys(2, 1).err(), Some(Error::Unknown));
        vault.delete(2, 1).await.expect("delete again");
        assert!(vault.keys(1, 1).is_ok());
    });
    let disk = driver.disk();
    let states = states(&disk);
    assert!(!states.is_empty());
    assert!(states.iter().all(|s| !s.tenants.contains_key(&2)));
    assert!(states.iter().all(|s| s.tenants.contains_key(&3)));
}

#[test]
fn shred_waits_for_settled_days_and_force_wins() {
    let driver = Rc::new(SimDriver::with_disk(6, quiet(), fresh(6)));
    run(&driver, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 1, 2).expect("create");
        vault.flush().await.expect("flush");
        let keys = vault.keys(1, 1).expect("keys");
        let batch = Secret::new([8; 32]);
        let old = seal_batch(&keys.today, 1, 1, 100, 0, 1, &batch).expect("wrap");
        for _ in 0..3 {
            vault.new_day(None, false).await.expect("new day");
        }
        assert_eq!(vault.day(), 103);
        assert!(vault.unwrap(1, 1, &old).is_ok());
        assert!(!vault.shred(Some(99), false).await.expect("shred"));
        assert!(vault.unwrap(1, 1, &old).is_ok());
        assert!(vault.shred(Some(100), false).await.expect("shred"));
        assert_eq!(vault.unwrap(1, 1, &old).err(), Some(Error::Gone));
        vault.new_day(None, true).await.expect("forced day");
        let later = vault.keys(1, 1).expect("keys");
        assert_eq!(later.day, 104);
    });
    let states = states(&driver.disk());
    assert!(states.iter().all(|s| s.tenants[&1].oldest == 102));
}

#[test]
fn restore_from_an_export_rotates_at_once() {
    let driver = Rc::new(SimDriver::with_disk(7, quiet(), fresh(7)));
    run(&driver, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 1, 30).expect("create");
        vault.flush().await.expect("flush");
    });
    let disk = driver.disk();
    let master = ["master.0", "master.1"]
        .iter()
        .filter_map(|n| disk.contents(&Path::new(DIR).join(n)))
        .find_map(Master::decode)
        .expect("master");
    let export = disk
        .contents(&Path::new(DIR).join("export"))
        .expect("export")
        .to_vec();
    let id = master.id;
    let target = Rc::new(SimDriver::new(8, quiet()));
    run(&target, async move {
        let vault = Vault::restore(Path::new(DIR), &master, &export)
            .await
            .expect("restore");
        assert!(vault.keys(1, 1).is_ok());
    });
    let restored = target.disk();
    let masters: Vec<u64> = ["master.0", "master.1"]
        .iter()
        .filter_map(|n| restored.contents(&Path::new(DIR).join(n)))
        .filter_map(Master::decode)
        .map(|m| m.id)
        .collect();
    assert_eq!(masters, [id + 1]);
}

#[test]
fn unreadable_slots_are_refused_and_left_alone() {
    let mut disk = fresh(9);
    for name in ["keys.0", "keys.1"] {
        let path = Path::new(DIR).join(name);
        let mut bytes = disk.contents(&path).expect("slot").to_vec();
        if !bytes.is_empty() {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            disk.put(&path, &bytes);
        }
    }
    let before = disk
        .contents(&Path::new(DIR).join("keys.0"))
        .map(<[u8]>::to_vec);
    let driver = Rc::new(SimDriver::with_disk(9, quiet(), disk));
    run(&driver, async {
        assert_eq!(
            Vault::open(Path::new(DIR)).await.err(),
            Some(Error::Unreadable)
        );
    });
    assert_eq!(
        driver
            .disk()
            .contents(&Path::new(DIR).join("keys.0"))
            .map(<[u8]>::to_vec),
        before
    );
}

#[test]
fn files_are_private_and_pending_tenants_do_not_unwrap() {
    let driver = Rc::new(SimDriver::with_disk(10, quiet(), fresh(10)));
    run(&driver, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 1, 30).expect("create");
        let batch = Secret::new([8; 32]);
        let other = crypto::day_public(&Secret::new([1; 32])).expect("public");
        let wrap = seal_batch(&other, 1, 1, 100, 0, 1, &batch).expect("wrap");
        assert_eq!(vault.unwrap(1, 1, &wrap).err(), Some(Error::Pending));
        vault.flush().await.expect("flush");
        assert_eq!(vault.unwrap(1, 1, &wrap).err(), Some(Error::Open));
    });
    let disk = driver.disk();
    for name in [
        "master.0", "master.1", "keys.0", "keys.1", "export", "phase",
    ] {
        assert_eq!(disk.mode(&Path::new(DIR).join(name)), Some(MODE), "{name}");
    }
}

#[test]
fn a_crashed_init_is_refused_by_open_and_can_run_again() {
    check(0..10, |seed| {
        let total = {
            let driver = Rc::new(SimDriver::new(seed, quiet()));
            run(&driver, async {
                Vault::init(Path::new(DIR), 100).await.expect("init");
            });
            driver.disk_ops()
        };
        for halt in 1..=total {
            let mut config = quiet();
            config.faults.crash_keep = MILLION / 2;
            config.faults.torn_write = MILLION / 4;
            config.halt_after = Some(halt);
            let driver = Rc::new(SimDriver::new(seed, config));
            run(&driver, async {
                spawn(async {
                    let _ = Vault::init(Path::new(DIR), 100).await;
                });
                sleep(Duration::from_secs(10)).await;
            });
            let restart = Rc::new(SimDriver::with_disk(seed, quiet(), driver.crash()));
            run(&restart, async move {
                match Vault::open(Path::new(DIR)).await {
                    Ok(vault) => assert_eq!(vault.day(), 100),
                    Err(error) => {
                        assert!(
                            matches!(error, Error::Interrupted | Error::Io(_)),
                            "seed {seed} halt {halt}: {error}"
                        );
                        let vault = Vault::init(Path::new(DIR), 100)
                            .await
                            .unwrap_or_else(|e| panic!("seed {seed} halt {halt}: init again: {e}"));
                        assert_eq!(vault.day(), 100);
                    }
                }
                assert_eq!(
                    Vault::init(Path::new(DIR), 100).await.err(),
                    Some(Error::Exists)
                );
            });
        }
    });
}

#[test]
fn a_crashed_restore_finishes_or_runs_again_and_always_rotates() {
    let source = Rc::new(SimDriver::with_disk(11, quiet(), fresh(11)));
    run(&source, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 1, 30).expect("create");
        vault.flush().await.expect("flush");
    });
    let disk = source.disk();
    let master_bytes = ["master.0", "master.1"]
        .iter()
        .filter_map(|n| disk.contents(&Path::new(DIR).join(n)))
        .find(|bytes| Master::decode(bytes).is_some())
        .expect("master")
        .to_vec();
    let id = Master::decode(&master_bytes).expect("master").id;
    let export = disk
        .contents(&Path::new(DIR).join("export"))
        .expect("export")
        .to_vec();
    let restore = |driver: &Rc<SimDriver>| {
        let (master, export) = (master_bytes.clone(), export.clone());
        run(driver, async move {
            spawn(async move {
                let master = Master::decode(&master).expect("master");
                let _ = Vault::restore(Path::new(DIR), &master, &export).await;
            });
            sleep(Duration::from_secs(10)).await;
        });
    };
    let total = {
        let driver = Rc::new(SimDriver::new(11, quiet()));
        restore(&driver);
        driver.disk_ops()
    };
    for halt in 1..=total {
        let mut config = quiet();
        config.faults.crash_keep = MILLION / 2;
        config.faults.torn_write = MILLION / 4;
        config.halt_after = Some(halt);
        let driver = Rc::new(SimDriver::new(halt, config));
        restore(&driver);
        let restart = Rc::new(SimDriver::with_disk(halt, quiet(), driver.crash()));
        let (master, export) = (master_bytes.clone(), export.clone());
        run(&restart, async move {
            let vault = if let Ok(vault) = Vault::open(Path::new(DIR)).await {
                vault
            } else {
                let master = Master::decode(&master).expect("master");
                Vault::restore(Path::new(DIR), &master, &export)
                    .await
                    .unwrap_or_else(|e| panic!("halt {halt}: restore again: {e}"))
            };
            assert!(vault.keys(1, 1).is_ok(), "halt {halt}");
        });
        let after = restart.disk();
        let ids: Vec<u64> = ["master.0", "master.1"]
            .iter()
            .filter_map(|n| after.contents(&Path::new(DIR).join(n)))
            .filter_map(Master::decode)
            .map(|m| m.id)
            .collect();
        assert_eq!(ids.len(), 1, "halt {halt}");
        assert!(
            ids[0] > id,
            "halt {halt}: restored vault still on the exported master"
        );
    }
}

#[test]
fn restore_checks_its_input_before_writing() {
    let source = Rc::new(SimDriver::with_disk(12, quiet(), fresh(12)));
    let disk = source.disk();
    let master = ["master.0", "master.1"]
        .iter()
        .filter_map(|n| disk.contents(&Path::new(DIR).join(n)))
        .find_map(Master::decode)
        .expect("master");
    let export = disk
        .contents(&Path::new(DIR).join("export"))
        .expect("export")
        .to_vec();
    let target = Rc::new(SimDriver::new(12, quiet()));
    run(&target, async move {
        let wrong = Master::generate(master.id).expect("master");
        assert!(
            Vault::restore(Path::new(DIR), &wrong, &export)
                .await
                .is_err()
        );
        assert!(
            Vault::restore(Path::new(DIR), &master, &export)
                .await
                .is_ok()
        );
    });
    let after = target.disk();
    assert!(after.exists(&Path::new(DIR).join("keys.0")));
}

#[test]
fn retention_is_durable_when_set_returns() {
    let driver = Rc::new(SimDriver::with_disk(13, quiet(), fresh(13)));
    run(&driver, async {
        let mut vault = Vault::open(Path::new(DIR)).await.expect("open");
        vault.create(1, 1, 30).expect("create");
        vault.flush().await.expect("flush");
        vault.set_retention(1, 1, 5).await.expect("retention");
    });
    let states = states(&driver.crash());
    let newest = states
        .iter()
        .filter_map(|s| s.tenants.get(&1))
        .map(|entry| entry.retention)
        .collect::<Vec<_>>();
    assert!(newest.contains(&5), "{newest:?}");
}

#[test]
fn clock_moves_one_day_at_a_time() {
    let start = rt::Instant::default();
    let mut clock = Clock::default();
    assert_eq!(clock.step(100, 100, start), Step::Wait);
    assert_eq!(clock.step(100, 99, start), Step::Behind);
    assert_eq!(clock.step(100, 102, start), Step::Ahead);
    assert_eq!(clock.step(100, 101, start), Step::Move);
    clock.moved(start);
    let soon = start + MIN_GAP.saturating_sub(Duration::from_secs(1));
    assert_eq!(clock.step(101, 102, soon), Step::Wait);
    assert_eq!(clock.step(101, 102, start + MIN_GAP), Step::Move);
}

#[derive(Clone, Debug)]
enum Ack {
    Created(u32, [u8; 32]),
    Deleting(u32),
    Deleted(u32),
    Day(u32),
    Oldest(u32, u32),
}

async fn script(log: Rc<RefCell<Vec<Ack>>>) {
    let push = |ack| log.borrow_mut().push(ack);
    let Ok(mut vault) = Vault::open(Path::new(DIR)).await else {
        return;
    };
    for tenant in 1..=16 {
        if vault.create(tenant, 1, 2).is_err() {
            return;
        }
    }
    if vault.flush().await.is_err() {
        return;
    }
    for tenant in 1..=16 {
        push(Ack::Created(
            tenant,
            *vault.keys(tenant, 1).expect("durable").data.expose(),
        ));
    }
    push(Ack::Deleting(2));
    if vault.delete(2, 1).await.is_err() {
        return;
    }
    push(Ack::Deleted(2));
    for day in 101..=103 {
        if vault.new_day(None, false).await.is_err() {
            return;
        }
        push(Ack::Day(day));
    }
    if vault.create(17, 1, 2).is_err() || vault.flush().await.is_err() {
        return;
    }
    push(Ack::Created(
        17,
        *vault.keys(17, 1).expect("durable").data.expose(),
    ));
    if vault.shred(None, true).await.is_err() {
        return;
    }
    push(Ack::Oldest(1, 101));
    push(Ack::Deleting(3));
    if vault.delete(3, 1).await.is_err() {
        return;
    }
    push(Ack::Deleted(3));
}

fn session(seed: u64, halt_after: Option<u64>) -> (Rc<SimDriver>, Vec<Ack>) {
    let mut config = quiet();
    config.faults.crash_keep = MILLION / 2;
    config.faults.torn_write = MILLION / 4;
    config.halt_after = halt_after;
    let driver = Rc::new(SimDriver::with_disk(seed, config, fresh(seed)));
    let log = Rc::new(RefCell::new(Vec::new()));
    let out = log.clone();
    run(&driver, async move {
        spawn(script(out));
        sleep(Duration::from_secs(60)).await;
    });
    let acks = log.borrow().clone();
    (driver, acks)
}

#[test]
fn acknowledged_changes_survive_crashes_and_shreds_hold_on_disk() {
    check(0..40, |seed| {
        let (full, acks) = session(seed, None);
        assert!(
            matches!(acks.last(), Some(Ack::Deleted(3))),
            "seed {seed}: script finishes without faults"
        );
        let total = full.disk_ops();
        for halt in (1..=total).step_by(usize::try_from(seed % 3 + 1).expect("small")) {
            let (driver, acks) = session(seed, Some(halt));
            let disk = driver.crash();
            if let Some(bytes) = disk.contents(&Path::new(DIR).join("export")) {
                assert!(
                    file::sealed_len(bytes).is_some_and(|len| len <= bytes.len()),
                    "seed {seed} halt {halt}: export is not a whole slot"
                );
            }
            let on_disk = states(&disk);
            let restart = Rc::new(SimDriver::with_disk(seed, quiet(), disk));
            let replay = acks.clone();
            let gone = Rc::new(RefCell::new(Vec::new()));
            let found = gone.clone();
            run(&restart, async move {
                let acks = replay;
                let vault = Vault::open(Path::new(DIR))
                    .await
                    .unwrap_or_else(|e| panic!("seed {seed} halt {halt}: {e}"));
                for ack in &acks {
                    match ack {
                        Ack::Created(tenant, data) => {
                            if let Ok(keys) = vault.keys(*tenant, 1) {
                                assert_eq!(keys.data.expose(), data, "seed {seed} halt {halt}");
                            } else {
                                assert!(
                                    acks.iter()
                                        .any(|a| matches!(a, Ack::Deleting(t) if t == tenant)),
                                    "seed {seed} halt {halt}: tenant {tenant} lost"
                                );
                            }
                        }
                        Ack::Deleted(tenant) => {
                            assert_eq!(vault.keys(*tenant, 1).err(), Some(Error::Unknown));
                        }
                        Ack::Day(day) => assert!(vault.day() >= *day, "seed {seed} halt {halt}"),
                        Ack::Deleting(tenant) => {
                            if vault.keys(*tenant, 1).is_err() {
                                found.borrow_mut().push(*tenant);
                            }
                        }
                        Ack::Oldest(_, _) => {}
                    }
                }
            });
            check_export(&restart.disk(), &acks, &gone.borrow(), seed, halt);
            let after = restart.disk();
            for state in states(&after) {
                for tenant in gone.borrow().iter() {
                    assert!(
                        !state.tenants.contains_key(tenant),
                        "seed {seed} halt {halt}: tenant {tenant} readable after restart"
                    );
                }
            }
            for ack in &acks {
                for state in &on_disk {
                    match ack {
                        Ack::Deleted(tenant) => assert!(
                            !state.tenants.contains_key(tenant),
                            "seed {seed} halt {halt}: deleted tenant {tenant} readable on disk"
                        ),
                        Ack::Oldest(tenant, oldest) => {
                            if let Some(entry) = state.tenants.get(tenant) {
                                assert!(
                                    entry.oldest >= *oldest,
                                    "seed {seed} halt {halt}: shredded day readable on disk"
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    });
}

fn check_export(after: &Disk, acks: &[Ack], gone: &[u32], seed: u64, halt: u64) {
    assert!(
        !after.exists(&Path::new(DIR).join("export.tmp")),
        "seed {seed} halt {halt}: export.tmp left after open"
    );
    let exported = {
        let master = ["master.0", "master.1"]
            .iter()
            .filter_map(|n| after.contents(&Path::new(DIR).join(n)))
            .find_map(Master::decode)
            .expect("live master");
        let bytes = after
            .contents(&Path::new(DIR).join("export"))
            .expect("export");
        State::decode(&file::open(&master, bytes).expect("export opens")).expect("state")
    };
    for ack in acks {
        match ack {
            Ack::Created(tenant, _) if !gone.contains(tenant) => assert!(
                exported.tenants.contains_key(tenant),
                "seed {seed} halt {halt}: export lacks tenant {tenant}"
            ),
            Ack::Deleted(tenant) => assert!(
                !exported.tenants.contains_key(tenant),
                "seed {seed} halt {halt}: export holds deleted tenant {tenant}"
            ),
            _ => {}
        }
    }
}
