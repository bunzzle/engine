use std::time::Duration;

pub const MILLION: u32 = 1_000_000;

#[derive(Clone, Debug)]
pub struct Rng {
    state: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut x = seed;
        let mut next = || {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        Self {
            state: [next(), next(), next(), next()],
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = &mut self.state;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let shifted = *s1 << 17;
        *s2 ^= *s0;
        *s3 ^= *s1;
        *s1 ^= *s2;
        *s0 ^= *s3;
        *s2 ^= shifted;
        *s3 = s3.rotate_left(45);
        result
    }

    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        let wide = u128::from(self.next_u64()) * u128::from(bound);
        u64::try_from(wide >> 64).unwrap_or(0)
    }

    pub fn index(&mut self, len: usize) -> usize {
        let bound = u64::try_from(len).unwrap_or(u64::MAX);
        usize::try_from(self.below(bound)).unwrap_or(0)
    }

    pub fn chance(&mut self, per_million: u32) -> bool {
        per_million > 0 && self.below(u64::from(MILLION)) < u64::from(per_million)
    }

    pub fn between(&mut self, low: Duration, high: Duration) -> Duration {
        if high <= low {
            return low;
        }
        let low_nanos = u64::try_from(low.as_nanos()).unwrap_or(u64::MAX);
        let high_nanos = u64::try_from(high.as_nanos()).unwrap_or(u64::MAX);
        Duration::from_nanos(low_nanos + self.below(high_nanos - low_nanos + 1))
    }
}
