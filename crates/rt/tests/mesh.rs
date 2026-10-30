use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use rt::Mesh;
use rt::sim::{Config, Machine, SimDriver, Stalls, check};
use rt::yield_now;

const CORES: u16 = 4;

type Log = Rc<RefCell<Vec<Vec<(u16, u64)>>>>;

fn exchange(seed: u64) {
    let sim = Rc::new(SimDriver::new(seed, Config::default()));
    let stalls = Stalls {
        per_mille: 50,
        max: Duration::from_millis(5),
    };
    let machine = Machine::new(Rc::clone(&sim), usize::from(CORES), stalls);
    let mesh = Arc::new(Mesh::<u64>::new(CORES));
    let log: Log = Rc::new(RefCell::new(vec![Vec::new(); usize::from(CORES)]));
    let mut tasks = Vec::new();
    for core in 0..CORES {
        let ends = mesh.take(core).expect("ends");
        assert!(mesh.take(core).is_none());
        let log = Rc::clone(&log);
        let driver = Rc::clone(&sim);
        tasks.push(machine.spawn_on(usize::from(core), async move {
            let record = Rc::clone(&log);
            let (peers, done) = ends.start(move |from, value| {
                record.borrow_mut()[usize::from(core)].push((from, value));
            });
            let mut next = [0u64; CORES as usize];
            for _ in 0..300 {
                let to = u16::try_from(driver.random() % u64::from(CORES)).expect("core");
                peers.send(to, next[usize::from(to)]);
                next[usize::from(to)] += 1;
                if driver.random().is_multiple_of(4) {
                    yield_now().await;
                }
            }
            peers.close();
            done.await;
            next
        }));
    }
    let sent = machine.block_on(0, async move {
        let mut sent = Vec::new();
        for task in tasks {
            sent.push(task.await);
        }
        sent
    });
    let log = log.borrow();
    for (to, received) in log.iter().enumerate() {
        for (from, counts) in sent.iter().enumerate() {
            let from = u16::try_from(from).expect("core");
            let values: Vec<u64> = received
                .iter()
                .filter(|(f, _)| *f == from)
                .map(|(_, v)| *v)
                .collect();
            let expected: Vec<u64> = (0..counts[to]).collect();
            assert_eq!(values, expected, "seed {seed}: {from} -> {to}");
        }
    }
}

#[test]
fn every_message_arrives_once_in_order_per_pair() {
    check(0..50, exchange);
}

#[test]
fn sends_in_one_turn_go_as_one_batch() {
    let sim = Rc::new(SimDriver::new(1, Config::default()));
    let machine = Machine::new(sim, 2, Stalls::default());
    let mesh = Arc::new(Mesh::<u64>::new(2));
    let count = Rc::new(RefCell::new(0));
    let receiver = mesh.take(1).expect("ends");
    let counted = Rc::clone(&count);
    let other = machine.spawn_on(1, async move {
        let (peers, done) = receiver.start(move |_, _| *counted.borrow_mut() += 1);
        peers.close();
        done.await;
    });
    let ends = mesh.take(0).expect("ends");
    let flushes = machine.block_on(0, async move {
        let (peers, done) = ends.start(|_, _| {});
        let second = peers.clone();
        let helper = rt::spawn(async move {
            for value in 50..100 {
                second.send(1, value);
            }
        });
        for value in 0..50 {
            peers.send(1, value);
        }
        yield_now().await;
        helper.await;
        yield_now().await;
        let flushes = peers.flushes();
        peers.close();
        done.await;
        other.await;
        flushes
    });
    assert_eq!(flushes, 1);
    assert_eq!(*count.borrow(), 100);
}
