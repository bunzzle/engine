use admin::{Code, Error, Frames, MAX_FRAME, Reply, Request, VERSION};

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
