use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use control::{
    Dkim, Error, Limits, MAX_ADDRESSES, MAX_BLOB, MAX_POOLS, MAX_PUBLIC, Object, Pool, State,
    Tenant, Update,
};
use crypto::DkimAlg;

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

fn dkim(alg: DkimAlg) -> Dkim {
    Dkim {
        id: 12,
        tenant: 4,
        generation: 2,
        alg,
        domain: "mail.example.org".into(),
        selector: "s2026".into(),
        public: vec![
            3;
            if alg == DkimAlg::Ed25519Sha256 {
                32
            } else {
                294
            }
        ],
        blob: vec![5; 1250],
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
        Object::Tenant(Tenant {
            state: State::Deleting,
            ..tenant(2)
        }),
        Object::Tenant(Tenant {
            state: State::Deleted,
            ..tenant(3)
        }),
        Object::Pool(pool(0)),
        Object::Pool(Pool {
            id: 2,
            addresses: Vec::new(),
        }),
        Object::Dkim(dkim(DkimAlg::RsaSha256)),
        Object::Dkim(dkim(DkimAlg::Ed25519Sha256)),
    ] {
        let update = Update {
            version: 77,
            object,
        };
        let decoded = Update::decode_sealed(&update.encode(), &update.secret());
        assert_eq!(decoded, Some(update));
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

#[test]
fn dkim_records_check_names_keys_and_blobs() {
    let good = dkim(DkimAlg::RsaSha256);
    for (bad, what) in [
        (
            Dkim {
                tenant: 0,
                ..good.clone()
            },
            "tenant id",
        ),
        (
            Dkim {
                domain: "Example.org".into(),
                ..good.clone()
            },
            "domain",
        ),
        (
            Dkim {
                domain: "".into(),
                ..good.clone()
            },
            "domain",
        ),
        (
            Dkim {
                selector: "s_1".into(),
                ..good.clone()
            },
            "selector",
        ),
        (
            Dkim {
                selector: "s".repeat(64).into(),
                ..good.clone()
            },
            "selector",
        ),
        (
            Dkim {
                domain: format!("{}org", "a.".repeat(118)).into(),
                ..good.clone()
            },
            "selector",
        ),
        (
            Dkim {
                public: Vec::new(),
                ..good.clone()
            },
            "public key",
        ),
        (
            Dkim {
                public: vec![1; MAX_PUBLIC + 1],
                ..good.clone()
            },
            "public key",
        ),
        (
            Dkim {
                alg: DkimAlg::Ed25519Sha256,
                ..good.clone()
            },
            "public key",
        ),
        (
            Dkim {
                blob: Vec::new(),
                ..good.clone()
            },
            "blob",
        ),
        (
            Dkim {
                blob: vec![1; MAX_BLOB + 1],
                ..good.clone()
            },
            "blob",
        ),
    ] {
        invalid(&Object::Dkim(bad), what);
    }
    Object::Dkim(Dkim {
        selector: "a.b-c".into(),
        public: vec![1; MAX_PUBLIC],
        blob: vec![1; MAX_BLOB],
        ..good
    })
    .check()
    .expect("limits");
}

#[test]
fn dkim_records_give_their_dns_name_and_text() {
    let mut rsa = dkim(DkimAlg::RsaSha256);
    rsa.public = b"foob".to_vec();
    assert_eq!(rsa.name(), "s2026._domainkey.mail.example.org");
    assert_eq!(rsa.txt(), "v=DKIM1; k=rsa; p=Zm9vYg==");
    rsa.public = b"fooba".to_vec();
    assert_eq!(rsa.txt(), "v=DKIM1; k=rsa; p=Zm9vYmE=");
    let mut ed = dkim(DkimAlg::Ed25519Sha256);
    ed.public = (0..32).collect();
    assert_eq!(
        ed.txt(),
        "v=DKIM1; k=ed25519; p=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
    );
}

#[test]
fn damaged_dkim_records_do_not_decode() {
    let update = Update {
        version: 1,
        object: Object::Dkim(dkim(DkimAlg::Ed25519Sha256)),
    };
    let (good, secret) = (update.encode(), update.secret());
    let decode = |clear: &[u8], secret: &[u8]| Update::decode_sealed(clear, secret);
    assert!(decode(&good, &secret).is_some());
    assert_eq!(Update::decode(&good), None);
    for at in [20, 21, 23, 24, 26] {
        let mut bad = good.clone();
        bad[at] ^= 0x40;
        assert_eq!(decode(&bad, &secret), None, "byte {at}");
    }
    for at in [0, 1, 2, 3] {
        let mut bad = secret.clone();
        bad[at] ^= 0x40;
        assert_eq!(decode(&good, &bad), None, "secret byte {at}");
    }
    let mut zero_tenant = good.clone();
    zero_tenant[28..32].copy_from_slice(&[0; 4]);
    assert_eq!(decode(&zero_tenant, &secret), None);
    let mut not_text = secret.clone();
    not_text[4] = 0xff;
    assert_eq!(decode(&good, &not_text), None);
    assert_eq!(decode(&good[..good.len() - 1], &secret), None);
    assert_eq!(decode(&good, &secret[..secret.len() - 1]), None);
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(decode(&longer, &secret), None);
    let mut longer_secret = secret;
    longer_secret.push(0);
    assert_eq!(decode(&good, &longer_secret), None);
}

#[test]
fn dkim_names_and_public_keys_stay_out_of_the_clear_part() {
    let made = dkim(DkimAlg::Ed25519Sha256);
    let update = Update {
        version: 1,
        object: Object::Dkim(made.clone()),
    };
    let clear = update.encode();
    for hidden in [
        made.domain.as_bytes(),
        made.selector.as_bytes(),
        &made.public,
    ] {
        assert!(!clear.windows(hidden.len()).any(|w| w == hidden));
    }
    assert!(clear.ends_with(&made.blob));
    let tenant = Update {
        version: 1,
        object: Object::Tenant(tenant(1)),
    };
    assert_eq!(tenant.secret(), Vec::<u8>::new());
    assert_eq!(Update::decode_sealed(&tenant.encode(), &[0]), None);
}
