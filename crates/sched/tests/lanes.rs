use std::collections::BTreeMap;

use rt::sim::{Rng, check};
use sched::{Entry, Lanes, Limits, Take, ranges};
use spool::MessageId;

fn id(n: u64) -> MessageId {
    MessageId {
        node: 0,
        shard: 0,
        key: n,
    }
}

fn entry(n: u64, recipients: std::ops::Range<u32>) -> Entry {
    Entry {
        message: id(n),
        recipients: vec![recipients],
    }
}

fn limits(active: u32, queue: u32, batch: u32) -> Limits {
    Limits {
        active,
        queue,
        batch,
        ..Limits::default()
    }
}

#[test]
fn entries_leave_in_due_order_not_arrival_order() {
    let mut lanes = Lanes::new(Limits::default());
    lanes.enqueue(7, 1, entry(1, 0..1), 5_000, 0);
    lanes.enqueue(7, 1, entry(2, 0..1), 10, 0);
    assert!(lanes.next(5).is_none());
    assert_eq!(lanes.deadline(), Some(10));
    let take = lanes.next(10).expect("due");
    assert_eq!(take.entries, vec![entry(2, 0..1)]);
    lanes.done(7, 1, 10);
    assert!(lanes.next(4_999).is_none());
    assert_eq!(lanes.deadline(), Some(5_000));
    let take = lanes.next(5_000).expect("due");
    assert_eq!(take.entries, vec![entry(1, 0..1)]);
}

#[test]
fn a_queue_at_its_cap_waits_for_answers() {
    let mut lanes = Lanes::new(limits(1_000, 100, 100));
    lanes.enqueue(1, 1, entry(1, 0..250), 0, 0);
    let first = lanes.next(0).expect("take");
    assert_eq!(first.count, 100);
    assert_eq!(first.entries, vec![entry(1, 0..100)]);
    assert!(lanes.next(0).is_none());
    lanes.done(1, 100, 0);
    let second = lanes.next(0).expect("take");
    assert_eq!(second.entries, vec![entry(1, 100..200)]);
}

#[test]
fn the_active_limit_bounds_every_take() {
    let mut lanes = Lanes::new(limits(150, 100, 100));
    lanes.enqueue(1, 1, entry(1, 0..100), 0, 0);
    lanes.enqueue(2, 2, entry(2, 0..100), 0, 0);
    assert_eq!(lanes.next(0).map(|t| t.count), Some(100));
    assert_eq!(lanes.next(0).map(|t| t.count), Some(50));
    assert!(lanes.next(0).is_none());
    assert_eq!(lanes.active(), 150);
}

#[test]
fn tenants_share_the_core_whatever_their_queue_count() {
    let mut lanes = Lanes::new(limits(1_000, 1_000, 10));
    lanes.enqueue(0, 1, entry(0, 0..1_000), 0, 0);
    for q in 1..=1_000 {
        lanes.enqueue(q, 2, entry(u64::from(q), 0..10), 0, 0);
    }
    let mut per_tenant = BTreeMap::new();
    for _ in 0..200 {
        let take = lanes.next(0).expect("due work");
        *per_tenant.entry(take.tenant).or_insert(0) += 1;
        lanes.done(take.queue, take.count, 0);
    }
    assert_eq!(per_tenant.get(&1), Some(&100));
    assert_eq!(per_tenant.get(&2), Some(&100));
}

#[test]
fn retry_now_makes_waiting_entries_due() {
    let mut lanes = Lanes::new(Limits::default());
    lanes.enqueue(3, 9, entry(1, 0..2), 3_600_000, 0);
    lanes.enqueue(4, 9, entry(2, 0..1), 7_200_000, 0);
    assert!(lanes.next(100).is_none());
    lanes.retry_tenant(9, 100);
    assert_eq!(lanes.deadline(), None);
    let mut counts = vec![lanes.next(100).expect("due").count];
    counts.push(lanes.next(100).expect("due").count);
    counts.sort_unstable();
    assert_eq!(counts, vec![1, 2]);
}

#[test]
fn lane_bytes_are_counted_and_returned() {
    let mut lanes = Lanes::new(Limits {
        bytes: 1_000,
        ..Limits::default()
    });
    for n in 0..20 {
        lanes.enqueue(1, 1, entry(n, 0..1), 0, 0);
    }
    assert!(lanes.over_budget());
    while let Some(take) = lanes.next(0) {
        lanes.done(take.queue, take.count, 0);
    }
    assert_eq!(lanes.bytes(), 0);
    assert_eq!(lanes.entries(), 0);
    assert_eq!(lanes.recipients(), 0);
    assert!(lanes.queues(1).is_empty());
}

#[test]
fn ranges_merge_neighbours() {
    assert_eq!(ranges([0, 1, 2, 5, 6, 9]), vec![0..3, 5..7, 9..10]);
    assert!(ranges([]).is_empty());
}

fn model(seed: u64) {
    let mut rng = Rng::new(seed);
    let limits = limits(
        1 + u32::try_from(rng.below(300)).expect("small"),
        1 + u32::try_from(rng.below(50)).expect("small"),
        1 + u32::try_from(rng.below(40)).expect("small"),
    );
    let mut lanes = Lanes::new(limits);
    let mut due: BTreeMap<u32, BTreeMap<(MessageId, u32), u64>> = BTreeMap::new();
    let mut taken: BTreeMap<(MessageId, u32), u32> = BTreeMap::new();
    let mut open: Vec<Take> = Vec::new();
    let mut in_flight: BTreeMap<u32, u32> = BTreeMap::new();
    let mut now = 0;
    let mut message = 0;
    for _ in 0..3_000 {
        match rng.below(10) {
            0..=2 => {
                message += 1;
                let queue = u32::try_from(rng.below(12)).expect("small");
                let count = 1 + u32::try_from(rng.below(120)).expect("small");
                let at = now + rng.below(5_000);
                let picked: Vec<u32> = (0..count).filter(|_| rng.below(4) != 0).collect();
                let queue_due = due.entry(queue).or_default();
                for &r in &picked {
                    queue_due.insert((id(message), r), at);
                }
                let entry = Entry {
                    message: id(message),
                    recipients: ranges(picked),
                };
                lanes.enqueue(queue, queue % 3, entry, at, now);
            }
            3..=5 => {
                if let Some(take) = lanes.next(now) {
                    let queue = in_flight.entry(take.queue).or_insert(0);
                    *queue += take.count;
                    assert!(*queue <= limits.queue, "seed {seed}: queue cap");
                    assert!(take.count <= limits.batch, "seed {seed}: batch");
                    for e in &take.entries {
                        for r in e.recipients.iter().flat_map(Clone::clone) {
                            let at = due[&take.queue][&(e.message, r)];
                            assert!(at <= now, "seed {seed}: early take");
                            *taken.entry((e.message, r)).or_insert(0) += 1;
                        }
                    }
                    open.push(take);
                }
            }
            6..=7 if !open.is_empty() => {
                let take = open.swap_remove(rng.index(open.len()));
                *in_flight.get_mut(&take.queue).expect("open") -= take.count;
                lanes.done(take.queue, take.count, now);
            }
            8 => now += rng.below(1_000),
            9 => {
                let queue = u32::try_from(rng.below(12)).expect("small");
                lanes.retry_now(queue, now);
                for at in due.entry(queue).or_default().values_mut() {
                    *at = (*at).min(now);
                }
            }
            _ => {}
        }
        assert!(lanes.active() <= limits.active, "seed {seed}: active");
    }
    now += 10_000;
    loop {
        for take in open.drain(..) {
            lanes.done(take.queue, take.count, now);
        }
        let Some(take) = lanes.next(now) else { break };
        for e in &take.entries {
            for r in e.recipients.iter().flat_map(Clone::clone) {
                *taken.entry((e.message, r)).or_insert(0) += 1;
            }
        }
        open.push(take);
    }
    let total: usize = due.values().map(BTreeMap::len).sum();
    assert_eq!(taken.len(), total, "seed {seed}: every recipient taken");
    assert!(taken.values().all(|n| *n == 1), "seed {seed}: taken twice");
    assert_eq!(lanes.bytes(), 0);
    assert_eq!(lanes.active(), 0);
}

#[test]
fn every_recipient_is_taken_once_never_early_within_limits() {
    check(0..50, model);
}
