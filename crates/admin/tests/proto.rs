use admin::{Code, Error, Frames, MAX_FRAME, PoolSpec, Reply, Request, TenantSpec, VERSION};

fn body(frame: &[u8]) -> Vec<u8> {
    let mut frames = Frames::default();
    frames.push(frame);
    frames.pop().expect("frame").expect("whole")
}

#[test]
fn requests_and_replies_round_trip() {
    let frame = Request::Status.encode();
    assert_eq!(frame, [0, 0, 0, 2, VERSION, 1]);
    assert_eq!(Request::decode(&body(&frame)), Ok(Request::Status));
    for code in [
        Code::Ok,
        Code::Refused,
        Code::NotFound,
        Code::Busy,
        Code::Failed,
    ] {
        let reply = Reply::new(code, "tenant 7: ünïcode");
        assert_eq!(Reply::decode(&body(&reply.encode())), Ok(reply));
    }
}

#[test]
fn bad_requests_are_named() {
    assert_eq!(Request::decode(&[]), Err(Error::Body));
    assert_eq!(Request::decode(&[VERSION]), Err(Error::Body));
    assert_eq!(Request::decode(&[VERSION + 1, 1]), Err(Error::Version));
    assert_eq!(Request::decode(&[VERSION, 0]), Err(Error::Command));
    assert_eq!(Request::decode(&[VERSION, 1, 0]), Err(Error::Body));
    assert_eq!(Reply::decode(&[VERSION, 9]), Err(Error::Body));
    assert_eq!(Reply::decode(&[VERSION, 0, 0xff]), Err(Error::Body));
}

#[test]
fn frames_split_join_and_refuse_bad_lengths() {
    let mut joined = Request::Status.encode();
    joined.extend_from_slice(&Request::Status.encode());
    let mut frames = Frames::default();
    for byte in &joined {
        frames.push(&[*byte]);
    }
    assert_eq!(frames.pop(), Ok(Some(vec![VERSION, 1])));
    assert_eq!(frames.pop(), Ok(Some(vec![VERSION, 1])));
    assert_eq!(frames.pop(), Ok(None));
    let mut empty = Frames::default();
    empty.push(&[0, 0, 0, 0]);
    assert_eq!(empty.pop(), Err(Error::Frame));
    let mut large = Frames::default();
    let len = u32::try_from(MAX_FRAME + 1).expect("fits");
    large.push(&len.to_be_bytes());
    assert_eq!(large.pop(), Err(Error::Frame));
}

#[test]
fn long_replies_are_cut_on_a_char_boundary() {
    let text = "é".repeat(MAX_FRAME);
    let reply = Reply::decode(&body(&Reply::new(Code::Ok, text).encode())).expect("reply");
    assert_eq!(reply.text.len(), MAX_FRAME - 2);
    assert!(reply.text.chars().all(|c| c == 'é'));
}

#[test]
fn random_input_never_panics() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let len = usize::try_from(next() % 24).expect("small");
        let mut bytes: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
        if next() % 2 == 0 && len >= 4 {
            let small = u32::try_from(next() % 20).expect("small");
            bytes[..4].copy_from_slice(&small.to_be_bytes());
        }
        let _ = Request::decode(&bytes);
        let _ = Reply::decode(&bytes);
        let mut frames = Frames::default();
        for chunk in bytes.chunks(1 + usize::try_from(next() % 5).expect("small")) {
            frames.push(chunk);
            while let Ok(Some(body)) = frames.pop() {
                assert!(!body.is_empty() && body.len() <= MAX_FRAME);
                let _ = Request::decode(&body);
            }
        }
    }
}

#[test]
fn every_request_round_trips() {
    let requests = [
        Request::Status,
        Request::TenantList(7),
        Request::PoolList(0),
        Request::QueueList { tenant: 5, from: 9 },
        Request::QueueRetry {
            tenant: 5,
            queue: 9,
        },
        Request::QueueRebind {
            tenant: 5,
            queue: 9,
            pool: 2,
        },
        Request::KeyCreate {
            tenant: 5,
            smtp: true,
            api: false,
            hooks: true,
            pool: 2,
        },
        Request::KeyRevoke { tenant: 5, id: 9 },
        Request::KeyList { tenant: 5, from: 9 },
        Request::TenantSuspend(u32::MAX),
        Request::TenantResume(7),
        Request::TenantCreate(TenantSpec {
            id: 7,
            pools: vec![3, 1, 2],
            rate: 10,
            burst: 20,
            connections: 5,
            queued: u64::MAX,
        }),
        Request::TenantCreate(TenantSpec::default()),
        Request::PoolSet(PoolSpec {
            id: 1,
            addresses: vec![
                ("192.0.2.1".parse().expect("ip"), 1),
                ("2001:db8::1".parse().expect("ip"), u16::MAX),
            ],
        }),
        Request::PoolSet(PoolSpec {
            id: 2,
            addresses: Vec::new(),
        }),
        Request::SiteList { from: None },
        Request::SiteList {
            from: Some(("example.com".to_owned(), "192.0.2.1".parse().expect("ip"))),
        },
        Request::SiteList {
            from: Some(("münchen.de".to_owned(), "2001:db8::1".parse().expect("ip"))),
        },
        Request::SitePause {
            egress: "192.0.2.1".parse().expect("ip"),
            site: "example.com".to_owned(),
        },
        Request::SiteResume {
            egress: "2001:db8::1".parse().expect("ip"),
            site: "example.com".to_owned(),
        },
    ];
    for request in requests {
        assert_eq!(Request::decode(&body(&request.encode())), Ok(request));
    }
}

#[test]
fn short_long_or_odd_fields_are_refused() {
    let create = body(
        &Request::TenantCreate(TenantSpec {
            id: 7,
            pools: vec![1],
            ..TenantSpec::default()
        })
        .encode(),
    );
    for cut in 2..create.len() {
        assert_eq!(Request::decode(&create[..cut]), Err(Error::Body), "{cut}");
    }
    let mut long = create.clone();
    long.push(0);
    assert_eq!(Request::decode(&long), Err(Error::Body));
    let pool = body(
        &Request::PoolSet(PoolSpec {
            id: 1,
            addresses: vec![("192.0.2.1".parse().expect("ip"), 1)],
        })
        .encode(),
    );
    let mut odd = pool.clone();
    odd[7] = 5;
    assert_eq!(Request::decode(&odd), Err(Error::Body));
    assert_eq!(Request::decode(&[VERSION, 4, 0, 0, 0]), Err(Error::Body));
    assert_eq!(Request::decode(&[VERSION, 8]), Err(Error::Body));
    let mut unknown_scopes = body(
        &Request::KeyCreate {
            tenant: 5,
            smtp: true,
            api: true,
            hooks: true,
            pool: 2,
        }
        .encode(),
    );
    unknown_scopes[6] = 8;
    assert_eq!(Request::decode(&unknown_scopes), Err(Error::Body));
    for request in [
        Request::KeyCreate {
            tenant: 5,
            smtp: true,
            api: true,
            hooks: false,
            pool: 2,
        },
        Request::KeyRevoke { tenant: 5, id: 9 },
        Request::KeyList { tenant: 5, from: 9 },
        Request::SiteList {
            from: Some(("example.com".to_owned(), "192.0.2.1".parse().expect("ip"))),
        },
        Request::SitePause {
            egress: "192.0.2.1".parse().expect("ip"),
            site: "example.com".to_owned(),
        },
        Request::SiteResume {
            egress: "2001:db8::1".parse().expect("ip"),
            site: "example.com".to_owned(),
        },
    ] {
        let short = body(&request.encode());
        for cut in 2..short.len() {
            assert_eq!(Request::decode(&short[..cut]), Err(Error::Body), "{cut}");
        }
        let mut long = short;
        long.push(0);
        assert_eq!(Request::decode(&long), Err(Error::Body));
    }
    assert_eq!(Request::decode(&[VERSION, 14, 2]), Err(Error::Body));
    assert_eq!(Request::decode(&[VERSION, 14, 1, 0]), Err(Error::Body));
    assert_eq!(
        Request::decode(&[VERSION, 15, 4, 192, 0, 2, 1, 0]),
        Err(Error::Body)
    );
    let mut bad_utf8 = body(
        &Request::SitePause {
            egress: "192.0.2.1".parse().expect("ip"),
            site: "example.com".to_owned(),
        }
        .encode(),
    );
    bad_utf8[8] = 0xff;
    assert_eq!(Request::decode(&bad_utf8), Err(Error::Body));
    assert_eq!(Request::decode(&[VERSION, 255]), Err(Error::Command));
}
