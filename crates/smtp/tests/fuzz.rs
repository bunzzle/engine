mod common;

use std::env;

use common::{Client, LIMIT, PLAIN, Rng};

fn number(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn cases(default: u64) -> impl Iterator<Item = Rng> {
    let seed = number("FUZZ_SEED", 1);
    (0..number("FUZZ_ITERATIONS", default))
        .map(move |i| Rng(seed.wrapping_mul(1_000_003).wrapping_add(i)))
}

fn content(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..rng.below(12) {
        let len = if rng.below(20) == 0 {
            998
        } else {
            rng.below(80)
        };
        for _ in 0..len {
            out.push(b". a.Zx-"[rng.below(7)]);
        }
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn stuffed(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in content.split_inclusive(|&b| b == b'\n') {
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn chunked(rng: &mut Rng, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = content;
    loop {
        let take = rng.below(rest.len() + 1);
        let last = take == rest.len() && rng.below(2) == 0;
        let word = if last { " LAST" } else { "" };
        out.extend_from_slice(format!("BDAT {take}{word}\r\n").as_bytes());
        out.extend_from_slice(&rest[..take]);
        rest = &rest[take..];
        if last {
            return out;
        }
    }
}

fn script(rng: &mut Rng) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut flushes = vec![
        b"EHLO client.example\r\n".to_vec(),
        format!("AUTH PLAIN {PLAIN}\r\n").into_bytes(),
    ];
    let mut messages = Vec::new();
    for _ in 0..=rng.below(3) {
        let mut head = b"MAIL FROM:<a@example.org>\r\n".to_vec();
        for i in 0..=rng.below(3) {
            head.extend_from_slice(format!("RCPT TO:<r{i}@example.net>\r\n").as_bytes());
        }
        let body = content(rng);
        if rng.below(2) == 0 {
            head.extend_from_slice(b"DATA\r\n");
            flushes.push(head);
            flushes.push(stuffed(&body));
        } else {
            head.extend(chunked(rng, &body));
            flushes.push(head);
        }
        messages.push(body);
    }
    flushes.push(b"QUIT\r\n".to_vec());
    (flushes, messages)
}

fn run(flushes: &[Vec<u8>], mut split: Option<&mut Rng>) -> Client {
    let mut client = Client::new(true);
    for flush in flushes {
        let mut rest = flush.as_slice();
        while !rest.is_empty() {
            let take = match split.as_deref_mut() {
                Some(rng) => 1 + rng.below(rest.len()),
                None => rest.len(),
            };
            client.send(&rest[..take]);
            rest = &rest[take..];
        }
    }
    client
}

#[test]
fn messages_round_trip_through_data_and_chunks_for_any_split() {
    for mut rng in cases(2_000) {
        let (flushes, messages) = script(&mut rng);
        let whole = run(&flushes, None);
        let text = whole.text();
        assert!(!text.contains("\r\n4") && !text.contains("\r\n5"), "{text}");
        assert_eq!(whole.messages, messages);
        assert!(whole.server.closed());
        let split = run(&flushes, Some(&mut rng));
        assert_eq!(split.output, whole.output);
        assert_eq!(shape(&split.log), shape(&whole.log));
        assert_eq!(split.messages, whole.messages);
    }
}

fn shape(log: &[String]) -> (Vec<&str>, Vec<&str>) {
    let (rcpt, other): (Vec<&String>, Vec<&String>) =
        log.iter().partition(|l| l.starts_with("rcpt "));
    let addresses = rcpt.iter().flat_map(|l| l[5..].split(' ')).collect();
    (other.iter().map(|l| l.as_str()).collect(), addresses)
}

fn well_formed(output: &[u8]) {
    for line in output.split_inclusive(|&b| b == b'\n') {
        assert!(line.ends_with(b"\r\n"), "{line:?}");
        assert!(
            line.len() >= 5 && line[..3].iter().all(u8::is_ascii_digit),
            "{line:?}"
        );
        assert!(line[3] == b' ' || line[3] == b'-', "{line:?}");
        assert!(
            line[..line.len() - 2]
                .iter()
                .all(|b| (32..=126).contains(b))
        );
    }
}

fn clean(message: &[u8]) {
    assert!(message.is_empty() || message.ends_with(b"\r\n"));
    for line in message.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        assert!(line.len() <= 998);
        assert!(!line.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0));
    }
    assert!(message.windows(2).all(|w| w[1] != b'\n' || w[0] == b'\r'));
}

#[test]
fn mutated_sessions_keep_every_rule() {
    const NOISE: &[u8] = b"\r\n.\0x :<>@\xff";
    for mut rng in cases(4_000) {
        let (flushes, _) = script(&mut rng);
        let mut bytes = flushes.concat();
        for _ in 0..=rng.below(6) {
            let at = rng.below(bytes.len() + 1);
            match rng.below(4) {
                0 => bytes.insert(at, NOISE[rng.below(NOISE.len())]),
                1 if at < bytes.len() => {
                    bytes.remove(at);
                }
                2 if at < bytes.len() => bytes[at] = NOISE[rng.below(NOISE.len())],
                _ => {
                    let end = (at + rng.below(40)).min(bytes.len());
                    let copy = bytes[at..end].to_vec();
                    bytes.splice(at..at, copy);
                }
            }
        }
        let flushes = if rng.below(2) == 0 {
            vec![bytes]
        } else {
            flushes_of(&mut rng, &bytes)
        };
        let client = run(&flushes, Some(&mut rng));
        well_formed(&client.output);
        for message in &client.messages {
            clean(message);
            assert!(message.len() as u64 <= LIMIT);
        }
        assert!(client.log.iter().filter(|l| *l == "close").count() <= 1);
    }
}

fn flushes_of(rng: &mut Rng, bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let take = 1 + rng.below(rest.len());
        out.push(rest[..take].to_vec());
        rest = &rest[take..];
    }
    out
}

#[test]
fn random_bytes_never_panic() {
    for mut rng in cases(4_000) {
        let len = rng.below(400);
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                if rng.below(3) == 0 {
                    b"\r\n.: <>"[rng.below(7)]
                } else {
                    rng.next().to_le_bytes()[0]
                }
            })
            .collect();
        let mut flushes = vec![
            b"EHLO c\r\n".to_vec(),
            format!("AUTH PLAIN {PLAIN}\r\n").into_bytes(),
        ];
        flushes.push(b"MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.net>\r\n".to_vec());
        if rng.below(2) == 0 {
            flushes.push(b"DATA\r\n".to_vec());
        }
        flushes.extend(flushes_of(&mut rng, &bytes));
        let client = run(&flushes, Some(&mut rng));
        well_formed(&client.output);
        for message in &client.messages {
            clean(message);
        }
    }
}
