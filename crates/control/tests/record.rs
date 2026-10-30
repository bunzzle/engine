use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use control::{Error, Limits, MAX_ADDRESSES, MAX_POOLS, Object, Pool, State, Tenant, Update};

fn tenant(id: u32) -> Tenant {
    Tenant {
        id,
        generation: 3,
        state: State::Active,
        default_pool: 9,
        pools: vec![4, 9],
        limits: Limits {
            rate: 500,
            burst: 50,
            queued: 1 << 40,
        },
    }
}

fn pool(id: u32) -> Pool {
    Pool {
        id,
        addresses: vec![
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 10),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                1,
            ),
        ],
    }
}

fn invalid(object: &Object, what: &str) {
    match object.check() {
        Err(Error::Invalid(w)) => assert_eq!(w, what),
        other => panic!("{what}: {other:?}"),
    }
}

#[test]
fn records_round_trip() {
    for object in [
        Object::Tenant(tenant(1)),
        Object::Tenant(Tenant {
            state: State::Suspended,
            ..tenant(u32::MAX)
        }),
        Object::Pool(pool(0)),
        Object::Pool(Pool {
            id: 2,
            addresses: Vec::new(),
        }),
    ] {
        let update = Update {
            version: 77,
            object,
        };
        assert_eq!(Update::decode(&update.encode()), Some(update));
    }
}

#[test]
fn tenants_and_pools_are_checked() {
    invalid(&Object::Tenant(tenant(0)), "tenant id");
    invalid(
        &Object::Tenant(Tenant {
            pools: Vec::new(),
            ..tenant(1)
        }),
        "pools",
    );
    invalid(
        &Object::Tenant(Tenant {
            pools: (1..=u32::try_from(MAX_POOLS).expect("fits") + 1).collect(),
            default_pool: 1,
            ..tenant(1)
        }),
        "pools",
    );
    invalid(
        &Object::Tenant(Tenant {
            pools: vec![9, 4, 9],
            ..tenant(1)
        }),
        "pools",
    );
    invalid(
        &Object::Tenant(Tenant {
            default_pool: 5,
            ..tenant(1)
        }),
        "default pool",
    );
    invalid(
        &Object::Pool(Pool {
            id: 1,
            addresses: vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
        }),
        "addresses",
    );
    invalid(
        &Object::Pool(Pool {
            id: 1,
            addresses: vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), 1); MAX_ADDRESSES + 1],
        }),
        "addresses",
    );
    Object::Tenant(Tenant {
        pools: (1..=u32::try_from(MAX_POOLS).expect("fits")).collect(),
        default_pool: 1,
        ..tenant(1)
    })
    .check()
    .expect("max pools");
}

#[test]
fn damaged_records_do_not_decode() {
    let good = Update {
        version: 1,
        object: Object::Tenant(tenant(1)),
    }
    .encode();
    assert!(Update::decode(&good).is_some());
    for at in [0, 1, 2, 3, 22, 23, 36, 37, 38, 39] {
        let mut bad = good.clone();
        bad[at] ^= 0x40;
        assert_eq!(Update::decode(&bad), None, "byte {at}");
    }
    assert_eq!(Update::decode(&good[..good.len() - 1]), None);
    let mut longer = good.clone();
    longer.extend_from_slice(&[0; 4]);
    assert_eq!(Update::decode(&longer), None);
    let mut zero = good.clone();
    zero[4..8].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(Update::decode(&zero), None);
    let pool = Update {
        version: 1,
        object: Object::Pool(pool(1)),
    }
    .encode();
    let mut padded = pool.clone();
    padded[16 + 4 + 19] = 1;
    assert_eq!(Update::decode(&padded), None);
    let mut weightless = pool;
    weightless[16 + 4 + 16..16 + 4 + 18].copy_from_slice(&[0, 0]);
    assert_eq!(Update::decode(&weightless), None);
}
