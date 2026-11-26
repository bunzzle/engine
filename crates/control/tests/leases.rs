use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use control::{
    Ask, Error, Gcra, LIFETIME, Leases, Limits, Quota, Rate, Signal, SiteHealth, Taken, Window,
    limit_core,
};
use rt::sim::{Config, Machine, SimDriver, Stalls, check};
use rt::{Instant, JoinHandle, Mesh, Runtime, sleep, spawn};

const CORES: u16 = 4;
const SHARDS: u32 = 8;
const RATED: u32 = 1;
const QUEUED: u32 = 2;
const BOTH: u32 = 3;
const RATE: u32 = 1_000;
const BURST: u32 = 50;
const LIMIT: u64 = 400;

const SLOW: u32 = 4;
const PERIOD: Duration = Duration::from_secs(10);

const SITE: u32 = 5;
const ONE: u32 = 6;
const COOL: u32 = 7;
const DEADLY: u32 = 8;

fn site(window: Window) -> Quota {
    Quota {
        rate: Rate::NONE,
        burst: 0,
        queued: LIMIT,
        window: Some(window),
    }
}

fn quota(key: u32) -> Option<Quota> {
    if key == SLOW {
        return Some(Quota {
            rate: Rate::per_minute(6),
            burst: 1,
            queued: LIMIT,
            window: None,
        });
    }
    match key {
        SITE | DEADLY => Some(site(Window::default())),
        ONE => Some(site(Window::new(
            1,
            Duration::from_secs(60),
            Duration::from_secs(60),
        ))),
        COOL => Some(site(Window::new(
            5,
            Duration::from_mins(20),
            Duration::from_secs(60),
        ))),
        _ => limits(key).map(Quota::from),
    }
}

fn limits(tenant: u32) -> Option<Limits> {
    match tenant {
        RATED => Some(Limits {
            rate: RATE,
            burst: BURST,
            connections: 0,
            queued: 0,
        }),
        QUEUED => Some(Limits {
            rate: 0,
            burst: 0,
            connections: 0,
            queued: LIMIT,
        }),
        BOTH => Some(Limits {
            rate: RATE,
            burst: BURST,
            connections: 0,
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
                Leases::start(ends, |t| limit_core(*t, SHARDS, CORES), |t| quota(*t))
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

fn counts_at_start(seed: u64) {
    let node = Node::start(seed);
    let mut opened = Vec::new();
    for (core, lease) in node.leases.iter().enumerate() {
        let lease = lease.clone();
        let slots = 100 * u64::try_from(core).expect("small");
        let late = Duration::from_millis(3 * slots / 100);
        opened.push(node.machine.spawn_on(core, async move {
            sleep(late).await;
            lease.restore([(QUEUED, slots / 2), (RATED, 5)]);
            lease.opened().await;
            if usize::from(limit_core(QUEUED, SHARDS, CORES)) == core {
                assert_eq!(
                    lease.granted(&QUEUED),
                    300,
                    "owner opened before every count"
                );
            }
        }));
    }
    let leases = node.leases.clone();
    let hot = usize::try_from(seed % u64::from(CORES)).expect("small");
    let (taken, busy) = node.machine.block_on(hot, async move {
        for done in opened {
            done.await;
        }
        let mut taken = 0;
        let mut busy = 0;
        for _ in 0..200 {
            match leases[hot].take(&QUEUED).await {
                Ok(_) => taken += 1,
                Err(Error::Busy) => busy += 1,
                Err(e) => panic!("{e}"),
            }
        }
        (taken, busy)
    });
    assert_eq!(taken, 100, "seed {seed}");
    assert_eq!(busy, 100, "seed {seed}");
    let cold = (hot + 1) % usize::from(CORES);
    assert_eq!(
        node.leases[cold].used(&QUEUED),
        50 * u64::try_from(cold).expect("small")
    );
    let owner = usize::from(limit_core(QUEUED, SHARDS, CORES));
    assert_eq!(node.leases[owner].granted(&QUEUED), LIMIT);
    node.stop();
}

#[test]
fn counts_at_start_take_their_slots() {
    check(0..8, counts_at_start);
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
        connections: 0,
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
        let tokens = gcra.grant(limits.into(), want, Instant::from_nanos(now));
        assert!(tokens.count <= want.min(RATE / 10));
        if tokens.count == 0 {
            let next = tokens.next.expect("next").as_nanos();
            assert!(next > now);
            let again = gcra.grant(limits.into(), 1, Instant::from_nanos(next));
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
        connections: 0,
        queued: 0,
    };
    let mut gcra = Gcra::default();
    let start = Instant::from_nanos(5_000_000_000);
    assert_eq!(gcra.grant(limits.into(), 100, start).count, BURST);
    let refused = gcra.grant(limits.into(), 1, start);
    assert_eq!(refused.count, 0);
    assert_eq!(refused.next, Some(start + Duration::from_millis(1)));
    let wide = Limits {
        burst: 500,
        connections: 0,
        ..limits
    };
    let mut gcra = Gcra::default();
    assert_eq!(gcra.grant(wide.into(), 1_000, start).count, RATE / 10);
    assert_eq!(gcra.grant(wide.into(), 1_000, start).count, RATE / 10);
}

#[test]
fn waits_as_long_as_asked() {
    let sim = Rc::new(SimDriver::new(3, Config::default()));
    Runtime::new(sim).block_on(async {
        let mesh = Mesh::<Ask<u32>>::new(1);
        let ends = mesh.take(0).expect("ends");
        let (leases, done) = Leases::start(ends, |_| 0, |t| quota(*t));
        let mut held = Vec::new();
        for _ in 0..LIMIT {
            held.push(leases.take(&QUEUED).await.expect("slot"));
        }
        assert!(matches!(leases.take(&QUEUED).await, Err(Error::Busy)));
        let freer = leases.clone();
        let freeing = spawn(async move {
            sleep(Duration::from_secs(1)).await;
            freer.free(&QUEUED, 1);
        });
        let start = rt::now();
        let taken = leases
            .take_within(&QUEUED, Duration::from_secs(2))
            .await
            .expect("slot after the wait");
        assert!(taken.slot);
        let waited = rt::now().saturating_duration_since(start);
        assert!(waited >= Duration::from_secs(1), "{waited:?}");
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        freeing.await;
        leases.close();
        done.await;
    });
}

#[test]
fn rates_below_one_per_second_never_mean_no_limit() {
    assert_eq!(Rate::per_second(0), Rate::NONE);
    assert_eq!(Rate::per_hour(0).period(), None);
    assert_eq!(Rate::per_hour(1).period(), Some(Duration::from_secs(3_600)));
    assert_eq!(
        Rate::per(u32::MAX, Duration::from_nanos(1)).period(),
        Some(Duration::from_nanos(1))
    );
    assert!(Rate::per(1, Duration::MAX).period().is_some());
    let start = Instant::from_nanos(5_000_000_000);
    for burst in [0, 1, 7, u32::MAX] {
        let quota = Quota {
            rate: Rate::per(1, Duration::MAX),
            burst,
            queued: 0,
            window: None,
        };
        let mut gcra = Gcra::default();
        let mut granted = 0;
        for step in 0..1_000 {
            granted += gcra
                .grant(quota, 1, start + Duration::from_secs(step))
                .count;
        }
        assert_eq!(granted, burst.clamp(1, 1_000), "burst {burst}");
    }
    let hourly = Quota {
        rate: Rate::per_hour(2),
        burst: 1,
        queued: 0,
        window: None,
    };
    let mut gcra = Gcra::default();
    assert_eq!(gcra.grant(hourly, 5, start).count, 1);
    let refused = gcra.grant(hourly, 1, start + Duration::from_secs(60));
    assert_eq!(refused.count, 0);
    assert_eq!(refused.next, Some(start + Duration::from_mins(30)));
}

#[test]
fn a_slow_key_gives_one_token_per_period() {
    let sim = Rc::new(SimDriver::new(4, Config::default()));
    Runtime::new(sim).block_on(async {
        let mesh = Mesh::<Ask<u32>>::new(1);
        let ends = mesh.take(0).expect("ends");
        let (leases, done) = Leases::start(ends, |_| 0, |t| quota(*t));
        let start = rt::now();
        let first = leases.take(&SLOW).await.expect("first token");
        assert!(first.token.is_some() && first.slot);
        let mut taken = vec![start];
        while rt::now() < start + PERIOD * 3 + PERIOD / 2 {
            if leases.take(&SLOW).await.is_ok() {
                taken.push(rt::now());
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(taken.len(), 4, "{taken:?}");
        for pair in taken.windows(2) {
            let gap = pair[1].saturating_duration_since(pair[0]);
            assert!(gap + LIFETIME >= PERIOD, "{gap:?}");
        }
        leases.close();
        done.await;
    });
}

#[test]
fn a_token_only_take_holds_no_slot() {
    let node = Node::start(5);
    let leases = node.leases.clone();
    node.machine.block_on(1, async move {
        let lease = &leases[1];
        for _ in 0..20 {
            let taken = lease.take_token(&BOTH).await.expect("token");
            assert!(taken.token.is_some());
            assert!(!taken.slot);
        }
        assert_eq!(lease.used(&BOTH), 0);
        assert_eq!(lease.held(&BOTH), 0);
        let free = lease.take_token(&QUEUED).await.expect("no rate");
        assert_eq!(free.token, None);
        assert!(!free.slot);
        assert_eq!(lease.held(&QUEUED), 0);
        let owner = usize::from(limit_core(BOTH, SHARDS, CORES));
        assert_eq!(leases[owner].granted(&BOTH), 0);
    });
    node.stop();
}

fn blocked(seed: u64) {
    let node = Node::start(seed);
    let leases = node.leases.clone();
    let owner = usize::from(limit_core(QUEUED, SHARDS, CORES));
    let hot = usize::try_from(seed % u64::from(CORES)).expect("small");
    let other = (hot + 1) % usize::from(CORES);
    node.machine.block_on(hot, async move {
        let lease = &leases[hot];
        for _ in 0..10 {
            lease.take(&QUEUED).await.expect("slot");
        }
        let full = leases.clone();
        let waiter = spawn(async move {
            let mut held = 0;
            loop {
                match full[other]
                    .take_within(&QUEUED, Duration::from_secs(5))
                    .await
                {
                    Ok(_) => held += 1,
                    Err(e) => return (held, e),
                }
            }
        });
        sleep(Duration::from_millis(50)).await;
        leases[other].block(&QUEUED);
        let (held, refused) = waiter.await;
        assert!(matches!(refused, Error::Blocked), "{refused}");
        assert_eq!(held + 10, LIMIT, "seed {seed}");
        let deadline = rt::now() + Duration::from_secs(1);
        while !leases.iter().all(|l| l.blocked(&QUEUED)) && rt::now() < deadline {
            sleep(Duration::from_millis(1)).await;
        }
        for core in &leases {
            assert!(core.blocked(&QUEUED));
            assert!(matches!(core.take(&QUEUED).await, Err(Error::Blocked)));
            assert!(matches!(
                core.take_token(&QUEUED).await,
                Err(Error::Blocked)
            ));
            assert_eq!(core.held(&QUEUED), core.used(&QUEUED));
        }
        lease.free(&QUEUED, 9);
        lease.give_back(
            &QUEUED,
            Taken {
                token: None,
                slot: true,
            },
        );
        leases[other].free(&QUEUED, held);
        sleep(Duration::from_millis(10)).await;
        assert_eq!(leases[owner].granted(&QUEUED), 0);
        lease.unblock(&QUEUED);
        let deadline = rt::now() + Duration::from_secs(1);
        while leases.iter().any(|l| l.blocked(&QUEUED)) && rt::now() < deadline {
            sleep(Duration::from_millis(1)).await;
        }
        for core in &leases {
            assert!(!core.blocked(&QUEUED));
            assert!(core.take(&QUEUED).await.expect("unblocked").slot);
        }
    });
    node.stop();
}

#[test]
fn a_blocked_key_refuses_takes_on_every_core_until_unblocked() {
    check(0..8, blocked);
}

#[test]
fn a_dead_host_is_seen_on_every_core_until_it_expires() {
    let node = Node::start(6);
    let leases = node.leases.clone();
    let egress = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    node.machine.block_on(0, async move {
        leases[0].mark_dead(egress, remote, Duration::from_secs(60));
        sleep(Duration::from_millis(50)).await;
        for lease in &leases {
            assert!(lease.is_dead(egress, remote));
            assert_eq!(lease.dead_hosts(), 1);
        }
        leases[0].mark_dead(egress, remote, Duration::from_mins(100));
        sleep(Duration::from_millis(50)).await;
        for lease in &leases {
            assert!(lease.is_dead(egress, remote));
        }
        sleep(Duration::from_secs(61)).await;
        for lease in &leases {
            assert!(
                !lease.is_dead(egress, remote),
                "a repeat mark was not sent, so the first until holds"
            );
            assert_eq!(lease.dead_hosts(), 0);
        }
        leases[2].mark_dead(egress, remote, Duration::from_secs(60));
        sleep(Duration::from_millis(50)).await;
        for lease in &leases {
            assert!(lease.is_dead(egress, remote));
        }
    });
    node.stop();
}

#[test]
fn dead_marks_stop_at_the_cap() {
    let node = Node::start(7);
    let leases = node.leases.clone();
    node.machine.block_on(0, async move {
        let egress = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ttl = Duration::from_secs(3_600);
        for n in 0..10_000_u32 {
            let remote = IpAddr::V4(Ipv4Addr::new(
                10,
                1,
                u8::try_from(n / 256).expect("octet"),
                u8::try_from(n % 256).expect("octet"),
            ));
            leases[0].mark_dead(egress, remote, ttl);
        }
        let extra = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
        leases[0].mark_dead(egress, extra, ttl);
        assert_eq!(leases[0].dead_hosts(), 10_000);
        assert!(!leases[0].is_dead(egress, extra));
        sleep(Duration::from_millis(100)).await;
        for lease in &leases[1..] {
            assert_eq!(lease.dead_hosts(), 10_000);
            assert!(!lease.is_dead(egress, extra));
        }
    });
    node.stop();
}

#[test]
fn a_zero_ttl_marks_nothing_on_any_core() {
    let node = Node::start(8);
    let leases = node.leases.clone();
    let egress = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    node.machine.block_on(0, async move {
        leases[0].mark_dead(egress, remote, Duration::ZERO);
        sleep(Duration::from_millis(50)).await;
        for lease in &leases {
            assert_eq!(lease.dead_hosts(), 0);
            assert!(!lease.is_dead(egress, remote));
        }
    });
    node.stop();
}

fn with_single<T: 'static>(test: impl AsyncFnOnce(Leases<u32>) -> T + 'static) -> T {
    let sim = Rc::new(SimDriver::new(11, Config::default()));
    Runtime::new(sim).block_on(async move {
        let mesh = Mesh::<Ask<u32>>::new(1);
        let ends = mesh.take(0).expect("ends");
        let (leases, done) = Leases::start(ends, |_| 0, |t| quota(*t));
        let out = test(leases.clone()).await;
        leases.close();
        done.await;
        out
    })
}

#[test]
fn a_window_grows_on_success_only_up_to_granted_plus_initial() {
    with_single(async |leases: Leases<u32>| {
        let mut held = Vec::new();
        held.push(leases.take(&ONE).await.expect("first slot"));
        for _ in 0..50 {
            leases.feedback(&ONE, Signal::Success);
        }
        sleep(Duration::from_millis(50)).await;
        assert_eq!(leases.granted(&ONE), 1, "no demand, no new slots");
        held.push(leases.take(&ONE).await.expect("window grew to two"));
        sleep(Duration::from_millis(50)).await;
        assert_eq!(leases.granted(&ONE), 2);
        for _ in 0..50 {
            leases.feedback(&ONE, Signal::Success);
        }
        sleep(Duration::from_millis(50)).await;
        assert_eq!(leases.granted(&ONE), 3, "grew one more on success");
        for _ in 0..50 {
            leases.feedback(&ONE, Signal::Success);
        }
        sleep(Duration::from_millis(50)).await;
        assert_eq!(
            leases.granted(&ONE),
            3,
            "growth stops at granted plus initial"
        );
        held.push(leases.take(&ONE).await.expect("third slot"));
        assert!(
            matches!(leases.take(&ONE).await, Err(Error::Busy)),
            "two in use plus an initial of one"
        );
        drop(held);
    });
}

#[test]
fn a_throttle_halves_the_window_recalls_free_slots_and_stops_growth_while_cooling() {
    let node = Node::start(13);
    let leases = node.leases.clone();
    let owner = usize::from(limit_core(SITE, SHARDS, CORES));
    let other = (owner + 1) % usize::from(CORES);
    node.machine.block_on(other, async move {
        let lease = &leases[other];
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(lease.take(&SITE).await.expect("slot"));
        }
        for _ in 0..200 {
            lease.feedback(&SITE, Signal::Success);
        }
        sleep(Duration::from_millis(100)).await;
        for _ in 0..5 {
            held.push(lease.take(&SITE).await.expect("grown slot"));
        }
        assert!(lease.held(&SITE) > 5, "the window grew past five");
        for _ in 0..200 {
            lease.feedback(&SITE, Signal::Success);
        }
        sleep(Duration::from_millis(100)).await;
        let all = lease.held(&SITE);
        lease.free(&SITE, all);
        lease.feedback(&SITE, Signal::Throttle);
        sleep(Duration::from_millis(100)).await;
        assert_eq!(lease.held(&SITE), 0, "recall took the free slots");
        assert_eq!(leases[owner].stats().cuts, 1);
        assert_eq!(leases[owner].granted(&SITE), 0);
        for _ in 0..5 {
            held.push(lease.take(&SITE).await.expect("slot after the cut"));
        }
        let mut drained = 0;
        while let Ok(slot) = lease.take_within(&SITE, Duration::from_millis(50)).await {
            held.push(slot);
            drained += 1;
            assert!(drained <= 10, "the cut window caps the slots");
        }
        for _ in 0..200 {
            lease.feedback(&SITE, Signal::Success);
        }
        sleep(Duration::from_millis(100)).await;
        assert!(
            matches!(lease.take(&SITE).await, Err(Error::Busy)),
            "no growth while cooling"
        );
        sleep(Duration::from_secs(61)).await;
        for _ in 0..200 {
            lease.feedback(&SITE, Signal::Success);
        }
        sleep(Duration::from_millis(100)).await;
        held.push(lease.take(&SITE).await.expect("growth after the cool"));
        drop(held);
    });
    node.stop();
}

#[test]
fn a_failed_cohort_marks_the_site_dead_until_one_probe_decides() {
    with_single(async |leases: Leases<u32>| {
        let taken = leases.take(&SITE).await.expect("slot");
        for _ in 0..10 {
            leases.feedback(&SITE, Signal::Failure);
        }
        sleep(Duration::from_millis(50)).await;
        assert!(matches!(leases.take(&SITE).await, Err(Error::Blocked)));
        assert_eq!(leases.stats().deaths, 1);
        assert_eq!(leases.sites(), (1, 1));
        leases.give_back(&SITE, taken);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(leases.granted(&SITE), 0);
        sleep(Duration::from_secs(62)).await;
        let deadline = rt::now() + Duration::from_secs(5);
        while leases.blocked(&SITE) && rt::now() < deadline {
            sleep(Duration::from_millis(10)).await;
        }
        assert!(!leases.blocked(&SITE));
        let probe = leases.take(&SITE).await.expect("one probe slot");
        assert!(matches!(leases.take(&SITE).await, Err(Error::Busy)));
        leases.feedback(&SITE, Signal::Success);
        sleep(Duration::from_millis(50)).await;
        let mut held = vec![probe];
        for _ in 0..4 {
            held.push(
                leases
                    .take(&SITE)
                    .await
                    .expect("back at the initial window"),
            );
        }
        assert!(matches!(leases.take(&SITE).await, Err(Error::Busy)));
        drop(held);
        leases.free(&SITE, 5);
        for _ in 0..10 {
            leases.feedback(&SITE, Signal::Failure);
        }
        sleep(Duration::from_millis(50)).await;
        assert!(matches!(leases.take(&SITE).await, Err(Error::Blocked)));
        assert_eq!(leases.stats().deaths, 2);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(leases.granted(&SITE), 0);
        sleep(Duration::from_secs(62)).await;
        let deadline = rt::now() + Duration::from_secs(5);
        while leases.blocked(&SITE) && rt::now() < deadline {
            sleep(Duration::from_millis(10)).await;
        }
        leases.take(&SITE).await.expect("probe slot again");
        leases.feedback(&SITE, Signal::Failure);
        sleep(Duration::from_millis(50)).await;
        assert!(
            matches!(leases.take(&SITE).await, Err(Error::Blocked)),
            "a failed probe starts a new dead spell"
        );
        assert_eq!(leases.stats().deaths, 3);
    });
}

#[test]
fn a_manual_block_survives_the_end_of_a_dead_window() {
    with_single(async |leases: Leases<u32>| {
        leases.take(&SITE).await.expect("slot");
        for _ in 0..10 {
            leases.feedback(&SITE, Signal::Failure);
        }
        sleep(Duration::from_millis(50)).await;
        assert!(leases.blocked(&SITE));
        leases.block(&SITE);
        leases.free(&SITE, 1);
        sleep(Duration::from_secs(62)).await;
        sleep(Duration::from_millis(100)).await;
        assert!(leases.blocked(&SITE), "the manual block stays");
        assert!(matches!(leases.take(&SITE).await, Err(Error::Blocked)));
        leases.unblock(&SITE);
        sleep(Duration::from_millis(100)).await;
        assert!(!leases.blocked(&SITE));
        leases.take(&SITE).await.expect("probe slot after unblock");
    });
}

#[test]
fn an_idle_window_is_dropped_unless_cooling_or_dead() {
    with_single(async |leases: Leases<u32>| {
        leases.take(&SITE).await.expect("slot");
        leases.free(&SITE, 1);
        leases.take(&COOL).await.expect("slot");
        leases.free(&COOL, 1);
        leases.feedback(&COOL, Signal::Throttle);
        leases.take(&DEADLY).await.expect("slot");
        leases.free(&DEADLY, 1);
        for _ in 0..10 {
            leases.feedback(&DEADLY, Signal::Failure);
        }
        sleep(Duration::from_millis(100)).await;
        assert_eq!(leases.sites(), (3, 1));
        sleep(Duration::from_secs(630)).await;
        assert_eq!(
            leases.sites(),
            (2, 0),
            "only the idle normal window dropped"
        );
        sleep(Duration::from_secs(90)).await;
        assert_eq!(leases.sites(), (1, 0), "the idle probe dropped");
        sleep(Duration::from_mins(9)).await;
        assert_eq!(
            leases.sites(),
            (0, 0),
            "the cooled window dropped once the cool-down passed"
        );
    });
}

#[test]
fn a_throttled_probe_restarts_at_a_window_of_one() {
    with_single(async |leases: Leases<u32>| {
        leases.take(&SITE).await.expect("slot");
        for _ in 0..10 {
            leases.feedback(&SITE, Signal::Failure);
        }
        leases.free(&SITE, 1);
        sleep(Duration::from_secs(62)).await;
        let deadline = rt::now() + Duration::from_secs(5);
        while leases.blocked(&SITE) && rt::now() < deadline {
            sleep(Duration::from_millis(10)).await;
        }
        let probe = leases.take(&SITE).await.expect("probe slot");
        leases.feedback(&SITE, Signal::Throttle);
        leases.give_back(&SITE, probe);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(leases.stats().cuts, 1);
        leases.take(&SITE).await.expect("window of one");
        assert!(matches!(leases.take(&SITE).await, Err(Error::Busy)));
    });
}

#[test]
fn a_manual_unblock_does_not_end_a_dead_window() {
    with_single(async |leases: Leases<u32>| {
        leases.take(&SITE).await.expect("slot");
        leases.block(&SITE);
        for _ in 0..10 {
            leases.feedback(&SITE, Signal::Failure);
        }
        leases.free(&SITE, 1);
        sleep(Duration::from_millis(50)).await;
        leases.unblock(&SITE);
        sleep(Duration::from_millis(100)).await;
        assert!(leases.blocked(&SITE), "still dead");
        assert!(matches!(leases.take(&SITE).await, Err(Error::Blocked)));
        sleep(Duration::from_secs(62)).await;
        let deadline = rt::now() + Duration::from_secs(5);
        while leases.blocked(&SITE) && rt::now() < deadline {
            sleep(Duration::from_millis(10)).await;
        }
        assert!(!leases.blocked(&SITE));
        leases.take(&SITE).await.expect("probe slot");
    });
}

#[test]
fn a_cut_takes_back_slots_in_use_as_they_finish() {
    with_single(async |leases: Leases<u32>| {
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(leases.take(&SITE).await.expect("slot"));
        }
        leases.feedback(&SITE, Signal::Throttle);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(leases.stats().cuts, 1);
        held.clear();
        for _ in 0..5 {
            leases.free(&SITE, 1);
            sleep(Duration::from_millis(10)).await;
        }
        sleep(Duration::from_millis(50)).await;
        let mut again = Vec::new();
        for _ in 0..2 {
            again.push(leases.take(&SITE).await.expect("within the cut window"));
        }
        assert!(
            matches!(leases.take(&SITE).await, Err(Error::Busy)),
            "only two slots after cutting five"
        );
        assert_eq!(leases.granted(&SITE), 2);
    });
}

#[test]
fn a_site_view_shows_after_feedback() {
    with_single(async |leases: Leases<u32>| {
        assert_eq!(leases.site_views(), []);
        let held = leases.take(&SITE).await.expect("slot");
        leases.feedback(&SITE, Signal::Success);
        sleep(Duration::from_millis(50)).await;
        let views = leases.site_views();
        assert_eq!(views.len(), 1);
        let view = &views[0];
        assert_eq!(view.key, SITE);
        assert_eq!(view.window, 5, "the initial window");
        assert_eq!(view.limit, LIMIT);
        assert_eq!(view.in_use, 1);
        assert_eq!(view.health, SiteHealth::Normal);
        assert!(!view.paused);
        assert!(held.slot);
    });
}

#[test]
fn a_blocked_site_view_shows_paused_without_a_window() {
    with_single(async |leases: Leases<u32>| {
        assert_eq!(leases.site_views(), []);
        leases.block(&SITE);
        sleep(Duration::from_millis(50)).await;
        let views = leases.site_views();
        assert_eq!(views.len(), 1);
        let view = &views[0];
        assert_eq!(view.key, SITE);
        assert_eq!(view.window, 0, "no window yet");
        assert_eq!(view.limit, LIMIT);
        assert_eq!(view.in_use, 0);
        assert!(view.paused);
        assert_eq!(view.health, SiteHealth::Normal);
        leases.unblock(&SITE);
        sleep(Duration::from_millis(50)).await;
        assert!(leases.site_views().is_empty(), "unblocked and unwatched");
    });
}

#[test]
fn a_dead_site_view_shows_dead() {
    with_single(async |leases: Leases<u32>| {
        leases.take(&SITE).await.expect("slot");
        for _ in 0..10 {
            leases.feedback(&SITE, Signal::Failure);
        }
        sleep(Duration::from_millis(50)).await;
        let views = leases.site_views();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].health, SiteHealth::Dead);
        assert!(!views[0].paused, "a death is not a manual pause");
    });
}

#[test]
fn feedback_before_the_probe_slot_is_ignored() {
    with_single(async |leases: Leases<u32>| {
        leases.take(&SITE).await.expect("slot");
        for _ in 0..10 {
            leases.feedback(&SITE, Signal::Failure);
        }
        sleep(Duration::from_secs(62)).await;
        let deadline = rt::now() + Duration::from_secs(5);
        while leases.blocked(&SITE) && rt::now() < deadline {
            sleep(Duration::from_millis(10)).await;
        }
        leases.feedback(&SITE, Signal::Failure);
        leases.free(&SITE, 1);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(
            leases.stats().deaths,
            1,
            "a late failure does not end the probe"
        );
        leases.take(&SITE).await.expect("probe slot");
    });
}
