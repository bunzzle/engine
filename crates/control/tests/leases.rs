use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use control::{Ask, Error, Gcra, LIFETIME, Leases, Limits, limit_core};
use rt::sim::{Config, Machine, SimDriver, Stalls, check};
use rt::{Instant, JoinHandle, Mesh, sleep};

const CORES: u16 = 4;
const SHARDS: u32 = 8;
const RATED: u32 = 1;
const QUEUED: u32 = 2;
const BOTH: u32 = 3;
const RATE: u32 = 1_000;
const BURST: u32 = 50;
const LIMIT: u64 = 400;

fn limits(tenant: u32) -> Option<Limits> {
    match tenant {
        RATED => Some(Limits {
            rate: RATE,
            burst: BURST,
            queued: 0,
        }),
        QUEUED => Some(Limits {
            rate: 0,
            burst: 0,
            queued: LIMIT,
        }),
        BOTH => Some(Limits {
            rate: RATE,
            burst: BURST,
            queued: LIMIT,
        }),
        _ => None,
    }
}

struct Node {
    machine: Machine,
    leases: Vec<Leases<u32>>,
    done: Vec<JoinHandle<()>>,
}

impl Node {
    fn start(seed: u64) -> Self {
        let sim = Rc::new(SimDriver::new(seed, Config::default()));
        let stalls = Stalls {
            per_mille: 50,
            max: Duration::from_millis(5),
        };
        let machine = Machine::new(sim, usize::from(CORES), stalls);
        let mesh = Arc::new(Mesh::<Ask<u32>>::new(CORES));
        let mut leases = Vec::new();
        let mut done = Vec::new();
        for core in 0..CORES {
            let ends = mesh.take(core).expect("ends");
            let (lease, handle) = machine.block_on(usize::from(core), async move {
                Leases::start(ends, |t| limit_core(*t, SHARDS, CORES), |t| limits(*t))
            });
            leases.push(lease);
            done.push(handle);
        }
        Self {
            machine,
            leases,
            done,
        }
    }

    fn stop(self) {
        let Self {
            machine,
            leases,
            done,
        } = self;
        machine.block_on(0, async move {
            for lease in &leases {
                lease.close();
            }
            for handle in done {
                handle.await;
            }
        });
    }
}

fn bound(window: Duration) -> u64 {
    let span = window + LIFETIME;
    let tokens = u128::from(RATE) * span.as_nanos() / 1_000_000_000;
    u64::try_from(tokens).expect("fits") + u64::from(BURST)
}

fn check_windows(times: &mut [u64]) {
    times.sort_unstable();
    for window in [
        Duration::from_millis(1),
        Duration::from_millis(10),
        Duration::from_millis(100),
        Duration::from_millis(500),
        Duration::from_secs(2),
    ] {
        let width = u64::try_from(window.as_nanos()).expect("fits");
        let mut end = 0;
        for start in 0..times.len() {
            while end < times.len() && times[end] <= times[start] + width {
                end += 1;
            }
            let count = (end - start) as u64;
            assert!(
                count <= bound(window),
                "{count} accepted in {window:?}, bound {}",
                bound(window)
            );
        }
    }
}

fn rate(seed: u64) {
    let node = Node::start(seed);
    let accepted = Rc::new(RefCell::new(Vec::new()));
    let hot = usize::try_from(seed % u64::from(CORES)).expect("small");
    let mut tasks = Vec::new();
    for (core, lease) in node.leases.iter().enumerate() {
        let lease = lease.clone();
        let log = Rc::clone(&accepted);
        tasks.push(node.machine.spawn_on(core, async move {
            let deadline = rt::now() + Duration::from_secs(2);
            let mut mine = 0_u64;
            let gap = if core == hot {
                Duration::from_micros(200)
            } else {
                Duration::from_millis(400)
            };
            while rt::now() < deadline {
                match lease.take(&RATED).await {
                    Ok(taken) => {
                        let until = taken.token.expect("token");
                        let now = rt::now();
                        assert!(now < until, "token used after its life");
                        assert!(
                            until.saturating_duration_since(now) <= LIFETIME,
                            "token lives longer than {LIFETIME:?}"
                        );
                        assert!(!taken.slot);
                        log.borrow_mut().push(now.as_nanos());
                        mine += 1;
                    }
                    Err(Error::Busy) => {}
                    Err(e) => panic!("{e}"),
                }
                sleep(gap).await;
            }
            mine
        }));
    }
    let counts = node.machine.block_on(0, async move {
        let mut counts = Vec::new();
        for task in tasks {
            counts.push(task.await);
        }
        counts
    });
    check_windows(&mut accepted.borrow_mut());
    let total: u64 = counts.iter().sum();
    assert!(total <= bound(Duration::from_secs(2)));
    assert!(
        counts[hot] * 10 >= u64::from(RATE) * 2 * 9,
        "seed {seed}: hot core got {} of {}",
        counts[hot],
        RATE * 2
    );
    node.stop();
}

#[test]
fn rate_stays_in_bound_and_one_hot_core_gets_it() {
    check(0..8, rate);
}

fn queued(seed: u64, key: u32) {
    let node = Node::start(seed);
    let leases = Rc::new(node.leases.clone());
    let hot = usize::try_from(seed % u64::from(CORES)).expect("small");
    let peak = Rc::new(RefCell::new(0_u64));
    let mut tasks = Vec::new();
    for core in 0..usize::from(CORES) {
        let all = Rc::clone(&leases);
        let top = Rc::clone(&peak);
        tasks.push(node.machine.spawn_on(core, async move {
            let lease = &all[core];
            let mut held = 0_u64;
            let start = rt::now();
            let first = if core == hot { 0 } else { 30 };
            while held < first && rt::now() < start + Duration::from_secs(1) {
                if lease.take(&key).await.is_ok() {
                    held += 1;
                }
                sleep(Duration::from_millis(1)).await;
            }
            if core != hot {
                sleep(Duration::from_millis(200)).await;
                lease.free(&key, held / 2);
                return lease.used(&key);
            }
            sleep(Duration::from_millis(100)).await;
            let deadline = rt::now() + Duration::from_millis(600);
            while rt::now() < deadline {
                if lease.take(&key).await.is_ok() {
                    let used: u64 = all.iter().map(|l| l.used(&key)).sum();
                    let held: u64 = all.iter().map(|l| l.held(&key)).sum();
                    assert!(used <= held && held <= LIMIT, "{used} used, {held} held");
                    let mut top = top.borrow_mut();
                    *top = (*top).max(used);
                }
                sleep(Duration::from_micros(500)).await;
            }
            lease.used(&key)
        }));
    }
    let used = node.machine.block_on(0, async move {
        let mut used = Vec::new();
        for task in tasks {
            used.push(task.await);
        }
        used
    });
    let others: u64 = (0..usize::from(CORES))
        .filter(|c| *c != hot)
        .map(|c| used[c])
        .sum();
    assert_eq!(*peak.borrow(), LIMIT, "seed {seed}: limit not reached");
    assert!(
        used[hot] * 10 >= (LIMIT - others) * 9,
        "seed {seed}: hot core holds {} of {}",
        used[hot],
        LIMIT - others
    );
    let owner = usize::from(limit_core(key, SHARDS, CORES));
    assert!(node.leases[owner].granted(&key) <= LIMIT);
    node.stop();
}

#[test]
fn queued_stays_in_limit_and_one_hot_core_reaches_it() {
    check(0..8, |seed| queued(seed, QUEUED));
}

#[test]
fn rate_and_queued_together() {
    check(0..4, |seed| queued(seed, BOTH));
}

#[test]
fn counts_at_start_take_their_slots() {
    let node = Node::start(1);
    let leases = node.leases.clone();
    let (taken, busy) = node.machine.block_on(1, async move {
        leases[1].restore([(QUEUED, 300), (RATED, 5)]);
        let mut taken = 0;
        let mut busy = 0;
        for _ in 0..200 {
            match leases[2].take(&QUEUED).await {
                Ok(_) => taken += 1,
                Err(Error::Busy) => busy += 1,
                Err(e) => panic!("{e}"),
            }
        }
        (taken, busy)
    });
    assert_eq!(taken, 100);
    assert_eq!(busy, 100);
    assert_eq!(node.leases[1].used(&QUEUED), 300);
    node.stop();
}

#[test]
fn a_failed_accept_gives_its_token_and_slot_back() {
    let node = Node::start(2);
    let leases = node.leases.clone();
    node.machine.block_on(3, async move {
        let lease = &leases[3];
        let taken = lease.take(&BOTH).await.expect("take");
        assert!(taken.token.is_some() && taken.slot);
        assert_eq!(lease.used(&BOTH), 1);
        let held = lease.held(&BOTH);
        lease.give_back(&BOTH, taken);
        assert_eq!(lease.used(&BOTH), 0);
        assert_eq!(lease.held(&BOTH), held);
        assert!(matches!(lease.take(&9).await, Err(Error::Invalid("key"))));
    });
    node.stop();
}

#[test]
fn idle_cores_return_their_free_slots() {
    let node = Node::start(3);
    let leases = node.leases.clone();
    let owner = usize::from(limit_core(QUEUED, SHARDS, CORES));
    let core = (owner + 1) % usize::from(CORES);
    let (granted, after) = node.machine.block_on(core, async move {
        let lease = &leases[core];
        for _ in 0..20 {
            lease.take(&QUEUED).await.expect("take");
        }
        lease.free(&QUEUED, 20);
        sleep(Duration::from_millis(10)).await;
        let granted = leases[owner].granted(&QUEUED);
        sleep(Duration::from_millis(2_500)).await;
        (granted, leases[owner].granted(&QUEUED))
    });
    assert!(granted >= 20);
    assert_eq!(after, 0);
    assert_eq!(node.leases[core].held(&QUEUED), 0);
    assert!(node.leases[core].stats().returned >= 20);
    node.stop();
}

fn spread(seed: u64) {
    let sim = SimDriver::new(seed, Config::default());
    let limits = Limits {
        rate: RATE,
        burst: BURST,
        queued: 0,
    };
    let mut gcra = Gcra::default();
    let mut now = 1_000_000_000_u64;
    let mut grants = Vec::new();
    for _ in 0..20_000 {
        now += sim.random() % 3_000_000;
        if sim.random().is_multiple_of(50) {
            now += 500_000_000;
        }
        let want = u32::try_from(sim.random() % 200).expect("small") + 1;
        let tokens = gcra.grant(limits, want, Instant::from_nanos(now));
        assert!(tokens.count <= want.min(RATE / 10));
        if tokens.count == 0 {
            let next = tokens.next.expect("next").as_nanos();
            assert!(next > now);
            let again = gcra.grant(limits, 1, Instant::from_nanos(next));
            assert_eq!(again.count, 1, "seed {seed}: refused at its next time");
            grants.push((next, 1));
        } else {
            assert_eq!(tokens.until.as_nanos(), now + 100_000_000);
            grants.push((now, tokens.count));
        }
    }
    for window in [1_000_000_u64, 10_000_000, 100_000_000, 1_000_000_000] {
        let bound = u64::from(RATE) * window / 1_000_000_000 + u64::from(BURST);
        let mut end = 0;
        let mut sum = 0_u64;
        for start in 0..grants.len() {
            while end < grants.len() && grants[end].0 <= grants[start].0 + window {
                sum += u64::from(grants[end].1);
                end += 1;
            }
            assert!(
                sum <= bound,
                "seed {seed}: {sum} granted in {window} ns, bound {bound}"
            );
            sum -= u64::from(grants[start].1);
        }
    }
}

#[test]
fn gcra_grants_stay_in_rate_and_burst() {
    check(0..20, spread);
}

#[test]
fn gcra_gives_the_whole_burst_after_idle() {
    let limits = Limits {
        rate: RATE,
        burst: BURST,
        queued: 0,
    };
    let mut gcra = Gcra::default();
    let start = Instant::from_nanos(5_000_000_000);
    assert_eq!(gcra.grant(limits, 100, start).count, BURST);
    let refused = gcra.grant(limits, 1, start);
    assert_eq!(refused.count, 0);
    assert_eq!(refused.next, Some(start + Duration::from_millis(1)));
    let wide = Limits {
        burst: 500,
        ..limits
    };
    let mut gcra = Gcra::default();
    assert_eq!(gcra.grant(wide, 1_000, start).count, RATE / 10);
    assert_eq!(gcra.grant(wide, 1_000, start).count, RATE / 10);
}
