use crate::entry::Key;

pub const BITS_PER_KEY: usize = 10;

const LINE: usize = 64;
const PROBES: u64 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    Split,
    Whole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bloom {
    bytes: Vec<u8>,
    probe: Probe,
}

impl Bloom {
    pub fn new(keys: usize, probe: Probe) -> Self {
        let lines = (keys * BITS_PER_KEY).div_ceil(LINE * 8).max(1);
        Self {
            bytes: vec![0; lines * LINE],
            probe,
        }
    }

    pub fn from_bytes(bytes: Vec<u8>, probe: Probe) -> Option<Self> {
        (!bytes.is_empty() && bytes.len().is_multiple_of(LINE)).then_some(Self { bytes, probe })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn add(&mut self, key: &Key) {
        let (line, h) = self.probe(key);
        for bit in bits(h) {
            self.bytes[line + bit / 8] |= 1 << (bit % 8);
        }
    }

    pub fn may(&self, key: &Key) -> bool {
        let (line, h) = self.probe(key);
        bits(h).all(|bit| self.bytes[line + bit / 8] & (1 << (bit % 8)) != 0)
    }

    fn probe(&self, key: &Key) -> (usize, u64) {
        let (h1, h2) = match self.probe {
            Probe::Split => split(key),
            Probe::Whole => whole(key),
        };
        let lines = (self.bytes.len() / LINE) as u64;
        let line = u64::try_from((u128::from(h1) * u128::from(lines)) >> 64).expect("below lines");
        (usize::try_from(line).expect("fits") * LINE, h2)
    }
}

fn split(key: &Key) -> (u64, u64) {
    let tenant = u64::from(u32::from_be_bytes(key[..4].try_into().expect("4 bytes")));
    let h1 = u64::from_le_bytes(key[4..12].try_into().expect("8 bytes"))
        ^ tenant.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let h2 = u64::from_le_bytes(key[12..20].try_into().expect("8 bytes"));
    (h1, h2)
}

fn whole(key: &Key) -> (u64, u64) {
    let a = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
    let b = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));
    let c = u64::from(u32::from_le_bytes(key[16..].try_into().expect("4 bytes")));
    let h1 = mix(a ^ mix(b ^ mix(c ^ 0x9e37_79b9_7f4a_7c15)));
    (h1, mix(h1 ^ 0xc2b2_ae3d_27d4_eb4f))
}

fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

fn bits(h: u64) -> impl Iterator<Item = usize> {
    let step = (h >> 32) | 1;
    (0..PROBES).map(move |i| {
        usize::try_from(h.wrapping_add(i.wrapping_mul(step)) % (LINE as u64 * 8)).expect("fits")
    })
}
