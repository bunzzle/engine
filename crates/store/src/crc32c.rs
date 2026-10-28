const POLY: u32 = 0x82F6_3B78;

const TABLE: [u32; 256] = table();

const fn table() -> [u32; 256] {
    let mut table = [0u32; 256];
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
        table[i as usize] = crc;
        i += 1;
    }
    table
}

pub fn checksum(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::checksum;

    #[test]
    fn matches_the_standard_check_value() {
        assert_eq!(checksum(b"123456789"), 0xE306_9283);
        assert_eq!(checksum(b""), 0);
    }
}
