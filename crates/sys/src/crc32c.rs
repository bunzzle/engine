const POLY: u32 = 0x82F6_3B78;

const TABLES: [[u32; 256]; 8] = tables();

const fn tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        tables[0][i as usize] = crc;
        i += 1;
    }
    let mut t = 1;
    while t < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = tables[t - 1][i];
            tables[t][i] = (prev >> 8) ^ tables[0][(prev & 0xff) as usize];
            i += 1;
        }
        t += 1;
    }
    tables
}

pub fn checksum(data: &[u8]) -> u32 {
    !update(!0, data)
}

pub fn hardware() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("sse4.2")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("crc")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub fn update(crc: u32, data: &[u8]) -> u32 {
    if std::arch::is_x86_feature_detected!("sse4.2") {
        // SAFETY: the CPU reported SSE4.2 at run time just above.
        return unsafe { x86::update(crc, data) };
    }
    software(crc, data)
}

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
pub fn update(crc: u32, data: &[u8]) -> u32 {
    if std::arch::is_aarch64_feature_detected!("crc") {
        // SAFETY: the CPU reported the CRC extension at run time just above.
        return unsafe { arm::update(crc, data) };
    }
    software(crc, data)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn update(crc: u32, data: &[u8]) -> u32 {
    software(crc, data)
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use std::arch::x86_64::{_mm_crc32_u8, _mm_crc32_u64};

    #[target_feature(enable = "sse4.2")]
    pub fn update(crc: u32, data: &[u8]) -> u32 {
        let (words, rest) = data.as_chunks::<8>();
        let mut wide = u64::from(crc);
        for word in words {
            wide = _mm_crc32_u64(wide, u64::from_le_bytes(*word));
        }
        let mut crc = u32::try_from(wide).expect("crc32 keeps the high half zero");
        for &byte in rest {
            crc = _mm_crc32_u8(crc, byte);
        }
        crc
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use std::arch::aarch64::{__crc32cb, __crc32cd};

    #[target_feature(enable = "crc")]
    pub fn update(mut crc: u32, data: &[u8]) -> u32 {
        let (words, rest) = data.as_chunks::<8>();
        for word in words {
            crc = __crc32cd(crc, u64::from_le_bytes(*word));
        }
        for &byte in rest {
            crc = __crc32cb(crc, byte);
        }
        crc
    }
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

pub fn software(mut crc: u32, data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<8>();
    for word in words {
        let low = crc ^ u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        let high = u32::from_le_bytes([word[4], word[5], word[6], word[7]]);
        crc = TABLES[7][(low & 0xff) as usize]
            ^ TABLES[6][((low >> 8) & 0xff) as usize]
            ^ TABLES[5][((low >> 16) & 0xff) as usize]
            ^ TABLES[4][(low >> 24) as usize]
            ^ TABLES[3][(high & 0xff) as usize]
            ^ TABLES[2][((high >> 8) & 0xff) as usize]
            ^ TABLES[1][((high >> 16) & 0xff) as usize]
            ^ TABLES[0][(high >> 24) as usize];
    }
    for &byte in rest {
        crc = TABLES[0][((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::{Hasher, checksum, hardware, software, update};

    #[test]
    fn hardware_matches_software() {
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert!(hardware());
        }
        let size: u32 = if cfg!(miri) { 80 } else { 1100 };
        let data: Vec<u8> = (0..size)
            .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).expect("byte"))
            .collect();
        for start in 0..9 {
            for len in 0..data.len() - start {
                let part = &data[start..start + len];
                for seed in [0, !0, 0x1234_5678] {
                    assert_eq!(update(seed, part), software(seed, part));
                }
            }
        }
    }

    #[test]
    fn matches_the_standard_check_values() {
        assert_eq!(checksum(b"123456789"), 0xE306_9283);
        assert_eq!(checksum(b""), 0);
        assert_eq!(checksum(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(checksum(&[0xFFu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn every_split_point_matches_the_bytewise_result() {
        let data: Vec<u8> = (0..300u32)
            .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).expect("byte"))
            .collect();
        for len in 0..data.len() {
            let mut crc = !0u32;
            for &byte in &data[..len] {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 {
                        (crc >> 1) ^ 0x82F6_3B78
                    } else {
                        crc >> 1
                    };
                }
            }
            assert_eq!(checksum(&data[..len]), !crc);
        }
    }

    #[test]
    fn the_hasher_matches_one_shot_checksums() {
        let data: Vec<u8> = (0..1000u32)
            .map(|i| u8::try_from(i % 251).expect("byte"))
            .collect();
        for split in [0, 1, 7, 8, 9, 500, 999, 1000] {
            let mut hasher = Hasher::new();
            hasher.update(&data[..split]);
            hasher.update(&data[split..]);
            assert_eq!(hasher.finish(), checksum(&data));
        }
    }
}
