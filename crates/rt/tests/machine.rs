use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Faults, Machine, SimDriver, Stalls};
use rt::{Buf, File, OpenOptions, channel, now, sleep, yield_now};

const PATH: &str = "/data/file";

fn config() -> Config {
    Config {
        faults: Faults {
            crash_keep: 0,
            torn_write: 0,
            ..Faults::default()
        },
        ..Config::default()
    }
}

fn options() -> OpenOptions {
    OpenOptions {
        read: true,
        write: true,
        create: true,
        ..OpenOptions::default()
    }
}

fn interleaving(seed: u64, stalls: Stalls) -> Vec<usize> {
    let sim = Rc::new(SimDriver::new(seed, config()));
    let machine = Machine::new(sim, 4, stalls);
    let log = Rc::new(RefCell::new(Vec::new()));
    let tasks: Vec<_> = (0..machine.cores())
        .map(|core| {
            let log = Rc::clone(&log);
            machine.spawn_on(core, async move {
                for _ in 0..20 {
                    log.borrow_mut().push(core);
                    yield_now().await;
                }
            })
        })
        .collect();
    machine.block_on(0, async move {
        for task in tasks {
            task.await;
        }
    });
    Rc::try_unwrap(log).expect("tasks done").into_inner()
}

#[test]
fn the_same_seed_gives_the_same_order() {
    for seed in 0..10 {
        assert_eq!(
            interleaving(seed, Stalls::default()),
            interleaving(seed, Stalls::default())
        );
    }
}

#[test]
fn seeds_change_the_order_between_cores() {
    let orders: Vec<_> = (0..10)
        .map(|seed| interleaving(seed, Stalls::default()))
        .collect();
    assert!(orders.iter().any(|order| order != &orders[0]));
    for order in &orders {
        for core in 0..4 {
            assert_eq!(order.iter().filter(|&&c| c == core).count(), 20);
        }
    }
}

#[test]
fn stalled_cores_pause_in_simulated_time_and_finish() {
    let stalls = Stalls {
        per_mille: 300,
        max: Duration::from_millis(5),
    };
    let sim = Rc::new(SimDriver::new(3, config()));
    let machine = Machine::new(Rc::clone(&sim), 3, stalls);
    let busy = machine.spawn_on(1, async {
        for _ in 0..200 {
            yield_now().await;
        }
    });
    let elapsed = machine.block_on(0, async move {
        let start = now();
        busy.await;
        now().saturating_duration_since(start)
    });
    assert!(elapsed > Duration::ZERO, "stalls let simulated time pass");
    let order = interleaving(3, stalls);
    assert_eq!(order.len(), 80);
}

#[test]
fn timers_fire_on_every_core() {
    let sim = Rc::new(SimDriver::new(4, config()));
    let machine = Machine::new(sim, 3, Stalls::default());
    let sleepers: Vec<_> = (0..3u64)
        .map(|core| {
            machine.spawn_on(usize::try_from(core).expect("fits"), async move {
                sleep(Duration::from_millis(10 * (core + 1))).await;
                now()
            })
        })
        .collect();
    let woke = machine.block_on(0, async move {
        let mut woke = Vec::new();
        for sleeper in sleepers {
            woke.push(sleeper.await);
        }
        woke
    });
    assert!(woke.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn cores_talk_through_channels() {
    let sim = Rc::new(SimDriver::new(5, config()));
    let machine = Machine::new(sim, 3, Stalls::default());
    let (to_hub, mut hub) = channel::<(usize, u32)>();
    for core in 1..3 {
        let to_hub = to_hub.clone();
        drop(machine.spawn_on(core, async move {
            for step in 0..5 {
                to_hub.send((core, step)).expect("send");
                yield_now().await;
            }
        }));
    }
    drop(to_hub);
    let received = machine.block_on(0, async move {
        let mut received = Vec::new();
        while let Some(message) = hub.recv().await {
            received.push(message);
        }
        received
    });
    assert_eq!(received.len(), 10);
    for core in 1..3 {
        let steps: Vec<u32> = received
            .iter()
            .filter(|(c, _)| *c == core)
            .map(|(_, s)| *s)
            .collect();
        assert_eq!(steps, vec![0, 1, 2, 3, 4]);
    }
}

fn written_through_one_core_synced_through_another(sync: bool) -> Vec<u8> {
    let sim = Rc::new(SimDriver::new(6, config()));
    let machine = Machine::new(Rc::clone(&sim), 2, Stalls::default());
    machine.block_on(0, async {
        let file = File::open(PATH, &options()).await.expect("open");
        file.sync_data().await.expect("create durably");
        rt::sync_dir("/data").await.expect("sync dir");
    });
    machine.block_on(0, async {
        let file = File::open(PATH, &options()).await.expect("open");
        let (written, _) = file.write_all_at(Buf::from_slice(b"durable?"), 0).await;
        written.expect("write");
    });
    if sync {
        machine.block_on(1, async {
            let file = File::open(PATH, &options()).await.expect("open");
            file.sync_data().await.expect("sync");
        });
    }
    let after = Rc::new(SimDriver::with_disk(6, config(), sim.crash()));
    let machine = Machine::new(after, 1, Stalls::default());
    machine.block_on(0, async {
        let file = File::open(PATH, &options()).await.expect("reopen");
        let (read, buf) = file.read_at(Buf::new(8), 0).await;
        read.expect("read");
        buf.to_vec()
    })
}

#[test]
fn a_sync_on_one_core_covers_writes_from_another() {
    assert_eq!(
        written_through_one_core_synced_through_another(true),
        b"durable?"
    );
}

#[test]
fn a_crash_before_the_other_core_syncs_loses_the_write() {
    assert_eq!(
        written_through_one_core_synced_through_another(false),
        Vec::<u8>::new()
    );
}
