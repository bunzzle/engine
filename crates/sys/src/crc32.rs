use crate::crc32c::{slice8, tables};

const POLY: u32 = 0xEDB8_8320;

const TABLES: [[u32; 256]; 8] = tables(POLY);

pub fn checksum(data: &[u8]) -> u32 {
    !update(!0, data)
}

pub fn update(crc: u32, data: &[u8]) -> u32 {
    slice8(&TABLES, crc, data)
}

#[derive(Clone, Copy, Debug)]
pub struct Hasher(u32);

impl Hasher {
    pub fn new() -> Self {
        Self(!0)
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0 = update(self.0, data);
    }

    pub fn finish(self) -> u32 {
        !self.0
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Hasher, checksum};

    fn bitwise(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn matches_the_check_values() {
        assert_eq!(checksum(b""), 0);
        assert_eq!(checksum(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            checksum(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn matches_bit_by_bit_and_in_parts() {
        let data: Vec<u8> = (0..300u32)
            .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).expect("byte"))
            .collect();
        for len in 0..data.len() {
            let part = &data[..len];
            assert_eq!(checksum(part), bitwise(part), "{len}");
            let mut hasher = Hasher::new();
            let (a, b) = part.split_at(len / 3);
            hasher.update(a);
            hasher.update(b);
            assert_eq!(hasher.finish(), bitwise(part), "{len}");
        }
    }
}
