use control::{
    Domain, Error, KIND_DKIM, Limits, Note, Object, Removal, Snapshot, State, Table, Tenant,
    Update, Verification, public_suffix, verifiable,
};

fn domain(id: u32, tenant: u32, name: &str, state: Verification) -> Domain {
    Domain {
        id,
        tenant,
        generation: 1,
        state,
        rsa: 0,
        ed25519: 0,
        name: name.into(),
    }
}

fn tenant(id: u32, generation: u32) -> Object {
    Object::Tenant(Tenant {
        id,
        generation,
        state: State::Active,
        default_pool: 1,
        pools: vec![1],
        limits: Limits::default(),
    })
}

#[test]
fn domain_records_round_trip_sealed_and_are_checked() {
    let good = Domain {
        rsa: 4,
        ed25519: 9,
        ..domain(3, 2, "mail.example.org", Verification::Verified)
    };
    for object in [
        good.clone(),
        domain(1, 2, "example.org", Verification::Unverified),
    ] {
        let update = Update {
            version: 5,
            object: Object::Domain(object),
        };
        let clear = update.encode();
        assert_eq!(clear.len(), 40);
        assert_eq!(
            Update::decode_sealed(&clear, &update.secret()),
            Some(update.clone())
        );
        assert_eq!(Update::decode(&clear), None);
        assert_eq!(Update::decode_sealed(&clear, b"Example.org"), None);
        for at in [16 + 4, 16 + 5, 16 + 21] {
            let mut bad = clear.clone();
            bad[at] = 3;
            assert_eq!(Update::decode_sealed(&bad, &update.secret()), None);
        }
    }
    let label = Object::Domain(good.clone()).sealed().expect("sealed");
    assert_eq!((label.tenant, label.kind, label.id), (2, 7, 3));
    for (bad, what) in [
        (
            Domain {
                id: 0,
                ..good.clone()
            },
            "domain id",
        ),
        (
            Domain {
                tenant: 0,
                ..good.clone()
            },
            "tenant id",
        ),
        (
            Domain {
                name: "Example.org".into(),
                ..good.clone()
            },
            "domain",
        ),
        (
            Domain {
                name: "".into(),
                ..good.clone()
            },
            "domain",
        ),
        (
            Domain {
                rsa: 9,
                ..good.clone()
            },
            "dkim keys",
        ),
    ] {
        assert!(matches!(
            Object::Domain(bad).check(),
            Err(Error::Invalid(w)) if w == what
        ));
    }
    Object::Domain(Domain {
        rsa: 0,
        ed25519: 0,
        ..good
    })
    .check()
    .expect("no keys");
}

#[test]
fn a_domain_covers_itself_and_its_subdomains_only() {
    let d = domain(1, 1, "example.org", Verification::Verified);
    for yes in [
        "example.org",
        "EXAMPLE.org",
        "a.example.org",
        "b.a.Example.ORG",
    ] {
        assert!(d.covers(yes), "{yes}");
    }
    for no in [
        "org",
        "xample.org",
        "anexample.org",
        "example.org.evil",
        "",
        "é.example.or",
    ] {
        assert!(!d.covers(no), "{no}");
    }
    assert!(
        Domain {
            rsa: 4,
            ..d.clone()
        }
        .names(4)
    );
    assert!(!d.names(0));
}

#[test]
fn senders_take_the_longest_verified_domain_of_the_current_generation() {
    let mut table = Table::default();
    table.load(Snapshot {
        version: 1,
        objects: vec![
            tenant(1, 2),
            tenant(2, 1),
            Object::Domain(Domain {
                generation: 2,
                ..domain(1, 1, "example.org", Verification::Verified)
            }),
            Object::Domain(Domain {
                generation: 2,
                ..domain(2, 1, "mail.example.org", Verification::Verified)
            }),
            Object::Domain(Domain {
                generation: 2,
                ..domain(3, 1, "news.example.org", Verification::Unverified)
            }),
            Object::Domain(domain(4, 1, "old.example.org", Verification::Verified)),
            Object::Domain(domain(5, 2, "other.org", Verification::Verified)),
        ],
    });
    let sender = |tenant, from: &str| table.sender(tenant, from).map(|d| d.id);
    assert_eq!(sender(1, "example.org"), Some(1));
    assert_eq!(sender(1, "a.mail.example.org"), Some(2));
    assert_eq!(sender(1, "news.example.org"), Some(1));
    assert_eq!(sender(1, "old.example.org"), Some(1));
    assert_eq!(sender(1, "other.org"), None);
    assert_eq!(sender(2, "other.org"), Some(5));
    assert_eq!(sender(2, "example.org"), None);
    assert_eq!(sender(3, "example.org"), None);
    assert_eq!(table.domains(1).count(), 4);
    assert!(table.domain(2, 1).is_none());
}

#[test]
fn removed_dkim_keys_leave_every_table() {
    let mut table = Table::default();
    table.load(Snapshot::default());
    table.take(Note::Update(Update {
        version: 1,
        object: tenant(1, 1),
    }));
    table.take(Note::Remove(Removal {
        version: 2,
        kind: KIND_DKIM,
        id: 7,
    }));
    assert_eq!(table.version(), 2);
    assert_eq!(table.dkims(1).count(), 0);
}

#[test]
fn public_suffix_rules_keep_wildcards_and_exceptions() {
    for suffix in [
        "com",
        "uk",
        "co.uk",
        "com.au",
        "gob.mx",
        "x.sch.uk",
        "foo.ck",
        "x.kobe.jp",
        "a.nom.br",
    ] {
        assert!(public_suffix(suffix), "{suffix}");
        assert!(!verifiable(suffix), "{suffix}");
    }
    for name in [
        "example.com",
        "example.co.uk",
        "www.ck",
        "a.foo.ck",
        "city.kobe.jp",
        "a.x.kobe.jp",
        "a.x.sch.uk",
        "uk.com",
        "sch.uk",
    ] {
        assert!(!public_suffix(name), "{name}");
        assert!(verifiable(name), "{name}");
    }
    assert!(!verifiable("Example.com"));
    assert!(!verifiable("exa mple.com"));
}
