const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(TABLE[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc = 0_u32;
    let mut bits = 0;
    let mut count = 0_usize;
    let mut pad = 0;
    for &c in text {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad += 1;
                count += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        if pad > 0 {
            return None;
        }
        acc = acc << 6 | u32::from(value);
        bits += 6;
        count += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits).to_le_bytes()[0]);
            acc &= (1 << bits) - 1;
        }
    }
    let padded = match bits {
        0 => pad == 0,
        4 => pad == 2,
        2 => pad == 1,
        _ => false,
    };
    (count.is_multiple_of(4) && padded && acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_length() {
        let data: Vec<u8> = (0..=255).collect();
        for n in 0..40 {
            let text = encode(&data[..n]);
            assert_eq!(decode(text.as_bytes()), Some(data[..n].to_vec()));
        }
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"fo"), "Zm8=");
    }

    #[test]
    fn skips_folding_and_refuses_bad_input() {
        assert_eq!(decode(b"Zm9v\r\n YmFy"), Some(b"foobar".to_vec()));
        for bad in [
            &b"Zm8"[..],
            b"Zm8==",
            b"Zm=8",
            b"Zm9v!",
            b"Zm9=",
            b"Zg=",
            b"Zh==",
        ] {
            assert_eq!(decode(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }
}
