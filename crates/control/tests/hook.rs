use control::{ALL_EVENTS, Error, Hook, HookState, KIND_HOOK, Object, Update, hook_url_ok};

pub fn hook(id: u32, tenant: u32) -> Hook {
    Hook {
        id,
        tenant,
        generation: 1,
        state: HookState::Active,
        events: ALL_EVENTS,
        version: 1,
        previous_until: 0,
        url: "https://hooks.example.org/in?token=abc".into(),
    }
}

#[test]
fn hook_records_round_trip_sealed_and_are_checked() {
    let rotated = Hook {
        state: HookState::Failing,
        events: 0b101,
        version: 3,
        previous_until: 1_700_000_000_000,
        ..hook(7, 2)
    };
    for object in [hook(1, 2), rotated.clone()] {
        let update = Update {
            version: 9,
            object: Object::Hook(object),
        };
        let clear = update.encode();
        assert_eq!(clear.len(), 40);
        assert_eq!(
            Update::decode_sealed(&clear, &update.secret()),
            Some(update.clone())
        );
        assert_eq!(Update::decode(&clear), None);
        for at in [16 + 4, 16 + 7, 16 + 8, 16 + 11] {
            let mut bad = clear.clone();
            bad[at] = 9;
            assert_eq!(Update::decode_sealed(&bad, &update.secret()), None);
        }
        assert_eq!(
            Update::decode_sealed(&clear, b"http://hooks.example.org/"),
            None
        );
    }
    let label = Object::Hook(rotated.clone()).sealed().expect("sealed");
    assert_eq!(
        (label.tenant, label.generation, label.kind, label.id),
        (2, 1, KIND_HOOK, 7)
    );
    assert!(rotated.wants(0) && !rotated.wants(1) && rotated.wants(2) && !rotated.wants(9));
    let good = hook(1, 2);
    for (bad, what) in [
        (
            Hook {
                id: 0,
                ..good.clone()
            },
            "hook id",
        ),
        (
            Hook {
                tenant: 0,
                ..good.clone()
            },
            "tenant id",
        ),
        (
            Hook {
                events: 0,
                ..good.clone()
            },
            "events",
        ),
        (
            Hook {
                version: 0,
                ..good.clone()
            },
            "secret version",
        ),
        (
            Hook {
                previous_until: 5,
                ..good.clone()
            },
            "secret version",
        ),
        (
            Hook {
                url: "http://hooks.example.org/".into(),
                ..good.clone()
            },
            "url",
        ),
    ] {
        assert!(matches!(
            Object::Hook(bad).check(),
            Err(Error::Invalid(w)) if w == what
        ));
    }
}

#[test]
fn hook_urls_are_https_with_a_host_name() {
    for url in [
        "https://hooks.example.org",
        "https://hooks.example.org/",
        "https://hooks.example.org:8443/in",
        "https://hooks.example.org?x=1",
        "https://a-b.example.org/p/q?token=a%20b&x=1",
    ] {
        assert!(hook_url_ok(url), "{url}");
    }
    let long = format!("https://hooks.example.org/{}", "a".repeat(2048));
    for url in [
        "http://hooks.example.org/",
        "https://",
        "https://localhost/",
        "https://Hooks.example.org/",
        "https://10.0.0.1/",
        "https://1.2.3.4:443/",
        "https://[::1]/",
        "https://user@hooks.example.org/",
        "https://hooks.example.org:0/",
        "https://hooks.example.org:08/",
        "https://hooks.example.org:65536/",
        "https://hooks.example.org:x/",
        "https://hooks.example.org/a b",
        "https://hooks.example.org/#frag",
        "https://hooks..example.org/",
        long.as_str(),
    ] {
        assert!(!hook_url_ok(url), "{url}");
    }
}

#[test]
fn hook_masks_cover_report_kinds_and_old_all_grows() {
    let seal = |events| {
        let update = Update {
            version: 1,
            object: Object::Hook(Hook {
                events,
                ..hook(3, 4)
            }),
        };
        let clear = update.encode();
        let Some(Update {
            object: Object::Hook(found),
            ..
        }) = Update::decode_sealed(&clear, &update.secret())
        else {
            panic!("hook decodes");
        };
        found
    };
    assert_eq!(seal(0x3f).events, 0x3f);
    let old = Update {
        version: 1,
        object: Object::Hook(Hook {
            events: 0x3f,
            ..hook(3, 4)
        }),
    };
    let mut clear = old.encode();
    let marker = clear.len() - 40 + 16 + 7;
    assert_eq!(clear[marker], 1);
    clear[marker] = 0;
    let Some(Update {
        object: Object::Hook(upgraded),
        ..
    }) = Update::decode_sealed(&clear, &old.secret())
    else {
        panic!("old hook decodes");
    };
    assert_eq!(upgraded.events, ALL_EVENTS);
    clear[marker] = 2;
    assert_eq!(Update::decode_sealed(&clear, &old.secret()), None);
    clear[marker] = 1;
    clear[marker - 2] = 0x07;
    assert_eq!(Update::decode_sealed(&clear, &old.secret()), None);
    assert_eq!(seal(0b1100_0001).events, 0b1100_0001);
    let complaints = seal(0b1000_0000);
    assert!(complaints.wants(7));
    assert!(!complaints.wants(6));
    assert!(!complaints.wants(0));
}
