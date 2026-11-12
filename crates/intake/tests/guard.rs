use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use intake::{Guard, Limits, Opened, Owner, Prefix, Refused};
use rt::sim::{Config, Machine, SimDriver, Stalls, check};
use rt::{Instant, Mesh, sleep};

fn at(secs: u64) -> Instant {
    Instant::from_nanos(secs * 1_000_000_000)
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("address")
}

fn keys(text: &str) -> (Prefix, Prefix) {
    Prefix::of(ip(text))
}

#[test]
fn prefixes_group_nets_and_wide_nets() {
    assert_eq!(keys("::ffff:192.0.2.1"), keys("192.0.2.1"));
    assert_eq!(keys("192.0.2.1").1, keys("192.0.2.200").1);
    assert_ne!(keys("192.0.2.1").0, keys("192.0.2.200").0);
    assert_ne!(keys("192.0.2.1").1, keys("192.0.3.1").1);
    assert_eq!(keys("2001:db8:1:2::1").0, keys("2001:db8:1:2:ffff::9").0);
    assert_ne!(keys("2001:db8:1:2::1").0, keys("2001:db8:1:3::1").0);
    assert_eq!(keys("2001:db8:1:2::1").1, keys("2001:db8:1:ff::1").1);
    assert_ne!(keys("2001:db8:1:2::1").1, keys("2001:db8:2:2::1").1);
    assert_ne!(keys("0.0.0.1").0, keys("::1").0);
}

#[test]
fn nets_cap_unauthenticated_sessions_and_forget_idle_entries() {
    let mut owner = Owner::new(Limits::default());
    let (net, wide) = keys("192.0.2.1");
    for _ in 0..16 {
        assert_eq!(owner.open(net, wide, at(0)), Opened::Ok);
    }
    assert_eq!(owner.open(net, wide, at(0)), Opened::Full);
    let (other, other_wide) = keys("192.0.2.2");
    assert_eq!(owner.open(other, other_wide, at(0)), Opened::Ok);
    owner.close(other, at(0));
    owner.close(net, at(0));
    assert_eq!(owner.open(net, wide, at(0)), Opened::Ok);
    for _ in 0..17 {
        owner.close(net, at(0));
    }
    let stats = owner.stats();
    assert_eq!((stats.nets, stats.open, stats.full), (0, 0, 1));
}

#[test]
fn failures_leak_and_ban_for_ten_minutes() {
    let mut owner = Owner::new(Limits::default());
    let (net, wide) = keys("192.0.2.1");
    for _ in 0..10 {
        assert!(!owner.failed(net, wide, at(0)));
    }
    assert!(!owner.failed(net, wide, at(60)));
    assert!(owner.failed(net, wide, at(60)));
    assert_eq!(owner.open(net, wide, at(60)), Opened::Banned);
    assert_eq!(owner.open(net, wide, at(659)), Opened::Banned);
    let (other, other_wide) = keys("192.0.2.2");
    assert_eq!(owner.open(other, other_wide, at(61)), Opened::Ok);
    assert_eq!(owner.open(net, wide, at(660)), Opened::Ok);
    let stats = owner.stats();
    assert_eq!((stats.bans, stats.banned, stats.failures), (1, 2, 12));
}

#[test]
fn failures_across_a_wide_net_ban_all_of_it() {
    let mut owner = Owner::new(Limits::default());
    for n in 0..30 {
        let (net, wide) = keys(&format!("2001:db8:1:{n:x}::1"));
        assert!(!owner.failed(net, wide, at(0)));
    }
    let (net, wide) = keys("2001:db8:1:fe::1");
    assert!(owner.failed(net, wide, at(0)));
    let (fresh, fresh_wide) = keys("2001:db8:1:ff::7");
    assert_eq!(owner.open(fresh, fresh_wide, at(1)), Opened::Banned);
    let (outside, outside_wide) = keys("2001:db8:2::1");
    assert_eq!(owner.open(outside, outside_wide, at(1)), Opened::Ok);
}

#[test]
fn a_full_table_evicts_only_idle_unbanned_entries() {
    let limits = Limits {
        entries: 4,
        ..Limits::default()
    };
    let mut owner = Owner::new(limits);
    let nets: Vec<_> = (1..=4).map(|n| keys(&format!("192.0.2.{n}"))).collect();
    for &(net, wide) in &nets {
        assert_eq!(owner.open(net, wide, at(0)), Opened::Ok);
    }
    let (fifth, fifth_wide) = keys("198.51.100.1");
    assert_eq!(owner.open(fifth, fifth_wide, at(0)), Opened::Full);
    assert_eq!(owner.stats().table_full, 1);
    let (first, first_wide) = nets[0];
    owner.failed(first, first_wide, at(0));
    owner.close(first, at(0));
    assert_eq!(owner.stats().nets, 4);
    assert_eq!(owner.open(fifth, fifth_wide, at(0)), Opened::Ok);
    let stats = owner.stats();
    assert_eq!((stats.evicted, stats.nets, stats.open), (1, 4, 4));

    let limits = Limits {
        entries: 2,
        net_failures: 0,
        ..Limits::default()
    };
    let mut owner = Owner::new(limits);
    for text in ["192.0.2.1", "192.0.2.2"] {
        let (net, wide) = keys(text);
        assert!(owner.failed(net, wide, at(0)));
    }
    let (new, new_wide) = keys("192.0.2.3");
    assert_eq!(owner.open(new, new_wide, at(599)), Opened::Full);
    assert_eq!(owner.open(new, new_wide, at(600)), Opened::Ok);
    let (banned, banned_wide) = keys("192.0.2.1");
    assert_eq!(owner.open(banned, banned_wide, at(600)), Opened::Ok);
}

#[test]
fn tenants_hold_up_to_their_limit() {
    let mut owner = Owner::new(Limits::default());
    assert_eq!(owner.open_tenant(5, 2), Opened::Ok);
    assert_eq!(owner.open_tenant(5, 2), Opened::Ok);
    assert_eq!(owner.open_tenant(5, 2), Opened::Full);
    assert_eq!(owner.open_tenant(6, 2), Opened::Ok);
    owner.close_tenant(5);
    assert_eq!(owner.open_tenant(5, 2), Opened::Ok);
    for tenant in [5, 5, 6, 7] {
        owner.close_tenant(tenant);
    }
    let stats = owner.stats();
    assert_eq!((stats.tenants, stats.tenant_open), (0, 0));
}

fn guards(seed: u64, limits: Limits) -> (Machine, Vec<Guard>) {
    let driver = Rc::new(SimDriver::new(seed, Config::default()));
    let machine = Machine::new(driver, 3, Stalls::default());
    let mesh = Mesh::new(3);
    let guards = (0..3u16)
        .map(|core| {
            let ends = mesh.take(core).expect("ends");
            machine.block_on(usize::from(core), async move {
                Guard::start(ends, [9; 16], limits).0
            })
        })
        .collect();
    (machine, guards)
}

fn opened(guards: &[Guard]) -> (u64, u64) {
    guards.iter().fold((0, 0), |(open, tenants), guard| {
        let owner = guard.stats().owner;
        (open + owner.open, tenants + owner.tenant_open)
    })
}

fn nets(guards: &[Guard]) -> usize {
    guards.iter().map(|guard| guard.stats().owner.nets).sum()
}

async fn settled(guards: &[Guard]) {
    for _ in 0..100 {
        let waiting: usize = guards.iter().map(|g| g.stats().waiting).sum();
        if waiting == 0 && opened(guards) == (0, 0) {
            return;
        }
        sleep(Duration::from_millis(1)).await;
    }
    panic!("slots not returned: {:?}", opened(guards));
}

#[test]
fn every_core_counts_on_the_same_owner() {
    check(0..4, |seed| {
        let (machine, guards) = guards(seed, Limits::default());
        machine.block_on(0, async move {
            let ip = ip("2001:db8::9");
            let mut slots = Vec::new();
            for n in 0..16 {
                slots.push(guards[n % 3].open(ip).await.expect("slot"));
            }
            assert_eq!(guards[1].open(ip).await.err(), Some(Refused::Full));
            slots.pop();
            let slot = guards[0].open(ip).await.expect("after a close");
            drop((slot, slots));
            settled(&guards).await;
            assert_eq!(nets(&guards), 0);

            let tenant = guards[0].open_tenant(4, 1).await.expect("tenant");
            assert_eq!(guards[2].open_tenant(4, 1).await.err(), Some(Refused::Full));
            drop(tenant);
            settled(&guards).await;

            for n in 0..10 {
                assert_eq!(guards[n % 3].failed(ip).await, Ok(false));
            }
            assert_eq!(guards[0].failed(ip).await, Ok(true));
            assert_eq!(guards[1].open(ip).await.err(), Some(Refused::Banned));
            let owners = guards.iter().filter(|g| g.stats().owner.bans > 0).count();
            assert_eq!(owners, 1);
        });
    });
}

#[test]
fn an_answer_after_the_deadline_returns_its_slot() {
    check(0..4, |seed| {
        let limits = Limits {
            ask: Duration::ZERO,
            ..Limits::default()
        };
        let (machine, guards) = guards(seed, limits);
        machine.block_on(0, async move {
            let ip = ip("192.0.2.9");
            assert_eq!(guards[0].open(ip).await.err(), Some(Refused::Unanswered));
            assert_eq!(
                guards[1].open_tenant(3, 1).await.err(),
                Some(Refused::Unanswered)
            );
            assert_eq!(guards[2].failed(ip).await, Err(Refused::Unanswered));
            settled(&guards).await;
            let unanswered: u64 = guards.iter().map(|g| g.stats().unanswered).sum();
            assert_eq!(unanswered, 3);
            let failures: u64 = guards.iter().map(|g| g.stats().owner.failures).sum();
            assert_eq!(failures, 1);
            assert_eq!(nets(&guards), 1);
        });
    });
}

#[test]
fn sessions_and_memory_stay_within_the_core_limits() {
    let limits = Limits {
        sessions: 2,
        budget: 100,
        ..Limits::default()
    };
    let (machine, guards) = guards(0, limits);
    machine.block_on(0, async move {
        let guard = &guards[0];
        let first = guard.admit().expect("first");
        let second = guard.admit().expect("second");
        assert!(guard.admit().is_none());
        drop(first);
        let third = guard.admit().expect("third");
        let held = guard.reserve(60).expect("held");
        assert!(guard.reserve(41).is_none());
        let rest = guard.reserve(40).expect("rest");
        drop(held);
        let again = guard.reserve(60).expect("again");
        let stats = guard.stats();
        assert_eq!(
            (
                stats.sessions,
                stats.refused,
                stats.reserved,
                stats.peak,
                stats.busy
            ),
            (2, 1, 100, 100, 1)
        );
        drop((second, third, rest, again));
        assert_eq!(guard.stats().reserved, 0);
        assert_eq!(guard.stats().sessions, 0);
    });
}
