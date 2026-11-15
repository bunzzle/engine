use std::env;

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut x = self.0;
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("fits")
    }
}

pub fn number(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

pub fn cases(default: u64) -> impl Iterator<Item = Rng> {
    let seed = number("FUZZ_SEED", 1 + number("SIM_OFFSET", 0));
    let iterations = number("FUZZ_ITERATIONS", default * number("SIM_SCALE", 1));
    (0..iterations).map(move |i| Rng(seed.wrapping_mul(1_000_003).wrapping_add(i)))
}
