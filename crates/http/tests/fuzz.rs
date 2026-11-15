use std::env;

use http::Status;

use crate::common::{Rng, Seen, run};

const PARTS: [&str; 24] = [
    "GET ",
    "POST ",
    "/",
    "/v1",
    "?a=b",
    " HTTP/1.1",
    " HTTP/1.0",
    "\r\n",
    "\n",
    "\r",
    " ",
    "\t",
    "Host: x",
    "Content-Length: ",
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: x",
    "Expect: 100-continue",
    "Connection: close",
    "0",
    "5",
    "a",
    ";",
    ":",
    "\0",
];

fn number(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[test]
fn random_input_never_breaks_the_server() {
    let seed = number("FUZZ_SEED", 1 + number("SIM_OFFSET", 0));
    let iterations = number("FUZZ_ITERATIONS", 3000 * number("SIM_SCALE", 1));
    for i in 0..iterations {
        let mut rng = Rng(seed.wrapping_mul(1_000_003).wrapping_add(i));
        let mut input = Vec::new();
        for _ in 0..rng.below(60) {
            if rng.below(8) == 0 {
                input.push(u8::try_from(rng.below(256)).expect("byte"));
            } else {
                input.extend_from_slice(PARTS[rng.below(PARTS.len())].as_bytes());
            }
        }
        let whole = run(&[&input]);
        let at = rng.below(input.len() + 1);
        let split = run(&[&input[..at], &input[at..]]);
        assert_eq!(whole.seen, split.seen, "{input:?}");
        assert_eq!(whole.output, split.output, "{input:?}");
        let faults = whole.seen.iter().position(|s| matches!(s, Seen::Fault(_)));
        if let Some(index) = faults {
            assert_eq!(index + 1, whole.seen.len(), "{input:?}");
            assert!(whole.closed, "{input:?}");
            assert_ne!(whole.seen[index], Seen::Fault(Status::OK));
        }
        let text = String::from_utf8_lossy(&whole.output);
        assert_eq!(
            text.matches("HTTP/1.1 ").count(),
            whole.seen.len(),
            "{input:?}"
        );
    }
}
