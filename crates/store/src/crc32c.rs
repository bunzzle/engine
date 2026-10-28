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

fn update(mut crc: u32, data: &[u8]) -> u32 {
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
    use super::checksum;

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
}
