use std::env;

use store::{
    FLAG_MORE, Header, MAX_PAYLOAD, RECORD_ALIGN, RECORD_FORMAT, RECORD_HEADER_SIZE, Record,
    RecordError, checksum, chunks, encode, peek, rebase, record_size,
};

const HEADER: Header = Header {
    kind: 3,
    flags: 0,
    shard: 5,
    tenant: 0xDEAD_BEEF,
    epoch: 9,
    sequence: 1234,
};

fn encoded(header: &Header, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0xEE; record_size(payload.len())];
    let size = encode(header, payload, &mut out);
    assert_eq!(size, out.len());
    out
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut x = self.0;
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("fits")
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
    }
}

#[test]
fn a_record_round_trips_and_is_read_in_place() {
    let bytes = encoded(&HEADER, b"hello");
    assert_eq!(bytes.len(), 48);
    assert_eq!(bytes.len() % RECORD_ALIGN, 0);
    assert!(bytes[RECORD_HEADER_SIZE + 5..].iter().all(|&b| b == 0));
    let record = Record::decode(&bytes).expect("decodes");
    assert_eq!(record.header(), HEADER);
    assert_eq!(record.format(), RECORD_FORMAT);
    assert_eq!(record.payload(), b"hello");
    assert_eq!(record.size(), bytes.len());
    assert_eq!(peek(&bytes), Ok(bytes.len()));
    assert_eq!(
        record.payload().as_ptr(),
        bytes[RECORD_HEADER_SIZE..].as_ptr()
    );
}

#[test]
fn records_follow_each_other_in_a_buffer() {
    let mut stream = encoded(&HEADER, b"first");
    stream.extend(encoded(
        &Header {
            sequence: 1235,
            ..HEADER
        },
        &[7; 100],
    ));
    let first = Record::decode(&stream).expect("first");
    let second = Record::decode(&stream[first.size()..]).expect("second");
    assert_eq!(second.sequence(), 1235);
    assert_eq!(second.payload(), &[7; 100]);
}

#[test]
fn damage_is_reported_by_kind() {
    let bytes = encoded(&HEADER, b"payload");
    assert_eq!(
        Record::decode(&bytes[..10]).err(),
        Some(RecordError::Truncated)
    );
    assert_eq!(
        Record::decode(&bytes[..RECORD_HEADER_SIZE + 3]).err(),
        Some(RecordError::Truncated)
    );
    let mut header = bytes.clone();
    header[12] ^= 1;
    assert_eq!(
        Record::decode(&header).err(),
        Some(RecordError::HeaderChecksum)
    );
    let mut body = bytes.clone();
    body[RECORD_HEADER_SIZE] ^= 1;
    assert_eq!(peek(&body), Ok(bytes.len()));
    assert_eq!(Record::decode(&body).err(), Some(RecordError::BodyChecksum));
    let mut padding = bytes.clone();
    padding[RECORD_HEADER_SIZE + 7] = 1;
    assert_eq!(Record::decode(&padding).err(), Some(RecordError::Padding));
    let mut reserved = bytes.clone();
    reserved[22] = 1;
    resum(&mut reserved);
    assert_eq!(Record::decode(&reserved).err(), Some(RecordError::Reserved));
}

fn resum(bytes: &mut [u8]) {
    let sum = checksum(&bytes[4..RECORD_HEADER_SIZE]);
    bytes[..4].copy_from_slice(&sum.to_le_bytes());
}

#[test]
fn format_one_records_read_as_shard_zero() {
    let mut bytes = encoded(&HEADER, b"old");
    assert_eq!(Record::decode(&bytes).expect("decode").shard(), 5);
    bytes[14..16].copy_from_slice(&1u16.to_le_bytes());
    bytes[20..24].fill(0);
    resum(&mut bytes);
    let record = Record::decode(&bytes).expect("format 1 decodes");
    assert_eq!(record.format(), 1);
    assert_eq!(record.shard(), 0);
    assert_eq!(record.header().shard, 0);
    bytes[20] = 5;
    resum(&mut bytes);
    assert_eq!(Record::decode(&bytes).err(), Some(RecordError::Reserved));
}

#[test]
fn the_largest_payload_fits_and_larger_values_are_chunked() {
    let payload = vec![1u8; MAX_PAYLOAD];
    let bytes = encoded(&HEADER, &payload);
    assert_eq!(
        Record::decode(&bytes).expect("decodes").payload().len(),
        MAX_PAYLOAD
    );

    let value = vec![2u8; 2 * MAX_PAYLOAD + 10];
    let parts: Vec<_> = chunks(&value).collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].0, FLAG_MORE);
    assert_eq!(parts[1].0, FLAG_MORE);
    assert_eq!(parts[2], (0, &value[2 * MAX_PAYLOAD..]));
    assert_eq!(chunks(&payload).count(), 1);
    assert_eq!(chunks(&[]).collect::<Vec<_>>(), vec![(0, &[][..])]);

    let mut joined = Vec::new();
    for (flags, part) in chunks(&value) {
        let bytes = encoded(&Header { flags, ..HEADER }, part);
        let record = Record::decode(&bytes).expect("chunk decodes");
        joined.extend_from_slice(record.payload());
        assert_eq!(record.has_more(), flags == FLAG_MORE);
    }
    assert_eq!(joined, value);
}

#[test]
#[should_panic(expected = "payload too large")]
fn encode_refuses_an_oversized_payload() {
    let payload = vec![0u8; MAX_PAYLOAD + 1];
    let mut out = vec![0u8; record_size(payload.len())];
    encode(&HEADER, &payload, &mut out);
}

#[test]
fn fuzz_decode() {
    let seed: u64 = env::var("FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let iterations: u64 = env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    for iteration in 0..iterations {
        let case = seed.wrapping_mul(1_000_003).wrapping_add(iteration);
        let mut rng = Rng(case);
        let len = if rng.below(50) == 0 {
            rng.below(8192)
        } else {
            rng.below(200)
        };
        let header = Header {
            kind: rng.bytes(1)[0],
            flags: rng.bytes(1)[0],
            shard: 5,
            tenant: u32::try_from(rng.next() >> 32).expect("fits"),
            epoch: rng.next(),
            sequence: rng.next(),
        };
        let payload = rng.bytes(len);
        let original = encoded(&header, &payload);
        let end = RECORD_HEADER_SIZE + len;
        let mut input = original.clone();
        let mutation = rng.below(6);
        match mutation {
            0 => {}
            1 => {
                let at = rng.below(end);
                input[at] ^= 1 << rng.below(8);
            }
            2 => input.truncate(rng.below(input.len())),
            3 => {
                for _ in 0..=rng.below(8) {
                    let at = rng.below(input.len());
                    input[at] = rng.bytes(1)[0];
                }
            }
            4 => {
                let len = rng.below(256);
                input = rng.bytes(len);
            }
            _ => {
                let len = rng.below(64);
                input.extend(rng.bytes(len));
            }
        }
        let result = std::panic::catch_unwind(|| Record::decode(&input).map(|r| r.header()));
        let Ok(result) = result else {
            panic!("decode panicked; replay with FUZZ_SEED={seed} (iteration {iteration})");
        };
        match mutation {
            0 | 5 => assert_eq!(result, Ok(header), "case {case}"),
            1 => assert!(result.is_err(), "single bit flip accepted in case {case}"),
            _ => {}
        }
        if let Ok(record) = Record::decode(&input) {
            let again = encoded(&record.header(), record.payload());
            assert_eq!(
                &again[..end.min(again.len())],
                &input[..end.min(again.len())]
            );
            assert!(record.size() <= input.len().next_multiple_of(RECORD_ALIGN));
        }
    }
}

fn range(payloads: &[usize], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut at = 0;
    for &size in payloads {
        at += encode(&HEADER, &vec![7; size], &mut out[at..]);
    }
    out
}

#[test]
fn rebase_moves_every_record_to_the_new_epoch() {
    let mut bytes = range(&[10, 300, 1], 4096);
    let before = bytes.clone();
    assert!(rebase(&mut bytes, HEADER.tenant, 9, 40));
    let mut at = 0;
    for size in [10, 300, 1] {
        let record = Record::decode(&bytes[at..]).expect("rebased record");
        assert_eq!(record.epoch(), 40);
        assert_eq!(
            record.header(),
            Header {
                epoch: 40,
                ..HEADER
            }
        );
        assert_eq!(record.payload(), vec![7; size].as_slice());
        at += record.size();
    }
    assert_eq!(&bytes[at..], &before[at..]);
    for (tenant, epoch) in [(HEADER.tenant + 1, 9), (HEADER.tenant, 8)] {
        let mut bytes = before.clone();
        assert!(!rebase(&mut bytes, tenant, epoch, 40));
    }
    let mut tail = before.clone();
    tail[4000] = 1;
    assert!(
        !rebase(&mut tail, HEADER.tenant, 9, 40),
        "garbage after records"
    );
    let mut empty = vec![0u8; 4096];
    assert!(!rebase(&mut empty, HEADER.tenant, 9, 40), "no records");
}
