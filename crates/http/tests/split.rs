use crate::common::{Rng, run};

const STREAMS: [&str; 5] = [
    "GET /a?b HTTP/1.1\r\nHost: x\r\n\r\nPOST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world",
    "\r\nPOST /m HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\nT: v\r\n\r\nGET /z HTTP/1.1\r\nHost: x\r\n\r\n",
    "POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
    "POST /m HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX",
    "GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n",
];

#[test]
fn every_split_point_gives_the_same_result() {
    for stream in STREAMS {
        let bytes = stream.as_bytes();
        let whole = run(&[bytes]);
        for at in 0..=bytes.len() {
            let split = run(&[&bytes[..at], &bytes[at..]]);
            assert_eq!(split.seen, whole.seen, "{stream:?} at {at}");
            assert_eq!(split.output, whole.output, "{stream:?} at {at}");
            assert_eq!(split.closed, whole.closed, "{stream:?} at {at}");
        }
        let bytewise: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(run(&bytewise).seen, whole.seen, "{stream:?} byte by byte");
    }
}

#[test]
fn random_splits_give_the_same_result() {
    let mut rng = Rng(7);
    for _ in 0..2000 {
        let stream = STREAMS[rng.below(STREAMS.len())].as_bytes();
        let whole = run(&[stream]);
        let mut pieces = Vec::new();
        let mut rest = stream;
        while !rest.is_empty() {
            let take = 1 + rng.below(rest.len());
            pieces.push(&rest[..take]);
            rest = &rest[take..];
        }
        let split = run(&pieces);
        assert_eq!(split.seen, whole.seen);
        assert_eq!(split.output, whole.output);
    }
}
