use control::{
    Access, Error, Grant, KIND_ACCESS, Limits, Note, Object, Removal, Scope, Scopes, Snapshot,
    State, TOKEN, Table, Tenant, Token, Update,
};

const SMTP: Scopes = Scopes {
    smtp: true,
    api: false,
};

fn tenant(id: u32, generation: u32, state: State) -> Object {
    Object::Tenant(Tenant {
        id,
        generation,
        state,
        default_pool: 9,
        pools: vec![4, 9],
        limits: Limits::default(),
    })
}

fn access(token: &Token, tenant: u32, scopes: Scopes, pool: u32) -> Access {
    Access {
        id: token.id(),
        tenant,
        generation: 1,
        scopes,
        pool,
        hash: token.hash(),
    }
}

fn table(objects: Vec<Object>) -> Table {
    let mut table = Table::default();
    table.load(Snapshot {
        version: 1,
        objects,
    });
    table
}

#[test]
fn access_records_round_trip_and_are_checked() {
    let token = Token::new(7).expect("token");
    for scopes in [
        SMTP,
        Scopes {
            smtp: false,
            api: true,
        },
        Scopes {
            smtp: true,
            api: true,
        },
    ] {
        let update = Update {
            version: 12,
            object: Object::Access(access(&token, 3, scopes, 4)),
        };
        assert_eq!(update.secret(), Vec::<u8>::new());
        let encoded = update.encode();
        assert_eq!(encoded.len(), 64);
        assert_eq!(Update::decode(&encoded), Some(update.clone()));
        assert_eq!(Update::decode_sealed(&encoded, b"x"), None);
        assert_eq!(Update::decode(&encoded[..63]), None);
        let mut bad = encoded.clone();
        bad[16 + 4] |= 4;
        assert_eq!(Update::decode(&bad), None);
        let mut bad = encoded;
        bad[16 + 6] = 1;
        assert_eq!(Update::decode(&bad), None);
    }
    let good = access(&token, 3, SMTP, 0);
    for (bad, what) in [
        (Access { id: 0, ..good }, "access id"),
        (Access { tenant: 0, ..good }, "tenant id"),
        (
            Access {
                scopes: Scopes::default(),
                ..good
            },
            "scopes",
        ),
    ] {
        assert!(matches!(
            Object::Access(bad).check(),
            Err(Error::Invalid(w)) if w == what
        ));
    }
}

#[test]
fn tokens_are_strict_base64url_and_round_trip() {
    let token = Token::new(0x0102_0304).expect("token");
    let text = token.text();
    assert_eq!(text.len(), TOKEN);
    assert!(text.starts_with(b"bz_"));
    assert!(
        text[3..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(c))
    );
    let parsed = Token::parse(&text).expect("parse");
    assert_eq!(parsed.id(), 0x0102_0304);
    assert_eq!(parsed.hash(), token.hash());
    assert_eq!(&*parsed.text(), &*text);
    assert_ne!(Token::new(1).expect("token").hash(), token.hash());

    let zero = Token::parse(&[b"bz_".as_slice(), &[b'A'; 48]].concat()).expect("parse");
    assert_eq!(zero.id(), 0);
    let ones = Token::parse(&[b"bz_".as_slice(), &[b'_'; 48]].concat()).expect("parse");
    assert_eq!(ones.id(), u32::MAX);
    assert_eq!(&*ones.text(), [b"bz_".as_slice(), &[b'_'; 48]].concat());

    let mut swapped = text.to_vec();
    for (at, c) in [(3, b'+'), (10, b'/'), (50, b'='), (20, b' '), (0, b'B')] {
        let keep = swapped[at];
        swapped[at] = c;
        assert!(Token::parse(&swapped).is_none(), "{}", char::from(c));
        swapped[at] = keep;
    }
    assert!(Token::parse(&text[..TOKEN - 1]).is_none());
    assert!(Token::parse(&[&*text, b"A"].concat()).is_none());
    assert!(Token::parse(&text[3..]).is_none());
    assert!(Token::parse(b"").is_none());
}

#[test]
fn only_a_matching_secret_scope_generation_and_active_tenant_pass() {
    let token = Token::new(5).expect("token");
    let api = Token::new(6).expect("token");
    let pooled = Token::new(8).expect("token");
    let table = table(vec![
        tenant(3, 1, State::Active),
        Object::Access(access(&token, 3, SMTP, 0)),
        Object::Access(access(
            &api,
            3,
            Scopes {
                smtp: false,
                api: true,
            },
            0,
        )),
        Object::Access(access(&pooled, 3, SMTP, 4)),
    ]);
    let grant = |token: &Token, scope| table.check(&token.text(), scope);
    assert_eq!(
        grant(&token, Scope::Smtp),
        Some(Grant {
            access: 5,
            tenant: 3,
            generation: 1,
            pool: 9,
        })
    );
    assert_eq!(grant(&pooled, Scope::Smtp).map(|g| g.pool), Some(4));
    assert_eq!(grant(&token, Scope::Api), None);
    assert_eq!(grant(&api, Scope::Smtp), None);
    assert_eq!(grant(&api, Scope::Api).map(|g| g.access), Some(6));

    let mut forged = token.text().to_vec();
    forged[3 + 8] = if forged[3 + 8] == b'A' { b'B' } else { b'A' };
    assert_eq!(table.check(&forged, Scope::Smtp), None);
    let mut moved = Token::new(5).expect("token").text().to_vec();
    assert_eq!(table.check(&moved, Scope::Smtp), None);
    moved[3..9].copy_from_slice(&api.text()[3..9]);
    assert_eq!(table.check(&moved, Scope::Api), None);
    assert_eq!(grant(&Token::new(99).expect("token"), Scope::Smtp), None);
    assert_eq!(table.check(b"bz_", Scope::Smtp), None);
    assert_eq!(grant(&Token::new(0).expect("token"), Scope::Smtp), None);
}

#[test]
fn keys_of_other_states_and_generations_are_refused() {
    let token = Token::new(5).expect("token");
    let record = Object::Access(access(&token, 3, SMTP, 0));
    let text = token.text();
    for (state, generation) in [
        (State::Suspended, 1),
        (State::Deleting, 1),
        (State::Deleted, 1),
        (State::Active, 2),
    ] {
        let table = table(vec![tenant(3, generation, state), record.clone()]);
        assert_eq!(table.check(&text, Scope::Smtp), None, "{state:?}");
    }
    assert_eq!(table(vec![record]).check(&text, Scope::Smtp), None);
}

#[test]
fn removals_apply_in_version_order() {
    let token = Token::new(5).expect("token");
    let record = Object::Access(access(&token, 3, SMTP, 0));
    let mut table = table(vec![tenant(3, 1, State::Active)]);
    let removal = Removal {
        version: 3,
        kind: KIND_ACCESS,
        id: 5,
    };
    table.take(Note::Remove(removal));
    assert_eq!(table.waiting(), 1);
    table.take(Note::Update(Update {
        version: 2,
        object: record.clone(),
    }));
    assert_eq!(table.version(), 3);
    assert!(table.access(5).is_none());
    assert_eq!(table.check(&token.text(), Scope::Smtp), None);
    table.apply(Update {
        version: 4,
        object: record,
    });
    assert_eq!(table.accesses(3).count(), 1);
    assert!(table.check(&token.text(), Scope::Smtp).is_some());
    table.remove(Removal {
        version: 4,
        ..removal
    });
    assert!(table.access(5).is_some());
    table.remove(Removal {
        version: 5,
        ..removal
    });
    assert_eq!(table.accesses(3).count(), 0);
    assert_eq!(table.version(), 5);
}
