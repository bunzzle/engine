use std::time::Duration;

const SIZES: [(&str, u64); 4] = [
    ("GiB", 1 << 30),
    ("MiB", 1 << 20),
    ("KiB", 1 << 10),
    ("B", 1),
];
const TIMES: [(&str, u64); 4] = [("ms", 1), ("s", 1_000), ("m", 60_000), ("h", 3_600_000)];

pub fn duration(text: &str) -> Option<Duration> {
    scaled(text, &TIMES).map(Duration::from_millis)
}

pub fn size(text: &str) -> Option<u64> {
    scaled(text, &SIZES)
}

fn scaled(text: &str, units: &[(&str, u64)]) -> Option<u64> {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (number, unit) = text.split_at(digits);
    if number.is_empty() || (number.len() > 1 && number.starts_with('0')) {
        return None;
    }
    let scale = units.iter().find(|(name, _)| *name == unit)?.1;
    number.parse::<u64>().ok()?.checked_mul(scale)
}
