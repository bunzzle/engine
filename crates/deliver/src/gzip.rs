const HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
const STORED: usize = 65_535;

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let blocks = data.len().div_ceil(STORED).max(1);
    let mut out = Vec::with_capacity(HEADER.len() + data.len() + blocks * 5 + 8);
    out.extend_from_slice(&HEADER);
    let mut chunks = data.chunks(STORED).peekable();
    if chunks.peek().is_none() {
        stored(&mut out, &[], true);
    }
    while let Some(chunk) = chunks.next() {
        stored(&mut out, chunk, chunks.peek().is_none());
    }
    out.extend_from_slice(&sys::crc32::checksum(data).to_le_bytes());
    let size = u64::try_from(data.len()).unwrap_or(u64::MAX) & u64::from(u32::MAX);
    out.extend_from_slice(
        &u32::try_from(size)
            .expect("masked to 32 bits")
            .to_le_bytes(),
    );
    out
}

fn stored(out: &mut Vec<u8>, chunk: &[u8], last: bool) {
    let len = u16::try_from(chunk.len()).expect("a stored block holds at most 65535 bytes");
    out.push(u8::from(last));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(chunk);
}

#[cfg(test)]
mod tests {
    use super::{HEADER, STORED, gzip};

    fn gunzip(bytes: &[u8]) -> Option<Vec<u8>> {
        let rest = bytes.strip_prefix(&HEADER[..4])?;
        let mut at = 6;
        let mut out = Vec::new();
        loop {
            let head = *rest.get(at)?;
            if head & 0b110 != 0 {
                return None;
            }
            let len = u16::from_le_bytes([*rest.get(at + 1)?, *rest.get(at + 2)?]);
            let nlen = u16::from_le_bytes([*rest.get(at + 3)?, *rest.get(at + 4)?]);
            if len != !nlen {
                return None;
            }
            let start = at + 5;
            let end = start + usize::from(len);
            out.extend_from_slice(rest.get(start..end)?);
            at = end;
            if head & 1 == 1 {
                break;
            }
        }
        let trailer = rest.get(at..)?;
        if trailer.len() != 8 {
            return None;
        }
        let crc = u32::from_le_bytes(trailer[..4].try_into().ok()?);
        let size = u32::from_le_bytes(trailer[4..].try_into().ok()?);
        (crc == sys::crc32::checksum(&out) && usize::try_from(size).ok()? == out.len())
            .then_some(out)
    }

    #[test]
    fn stored_blocks_read_back() {
        for len in [0, 1, 100, STORED - 1, STORED, STORED + 1, 3 * STORED + 7] {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 7 % 251).expect("byte"))
                .collect();
            let packed = gzip(&data);
            assert_eq!(packed[..10], HEADER);
            assert_eq!(packed.len(), 18 + len + 5 * len.div_ceil(STORED).max(1));
            assert_eq!(gunzip(&packed).as_deref(), Some(&data[..]), "{len}");
        }
    }

    #[test]
    fn empty_input_is_one_final_block() {
        assert_eq!(
            gzip(b""),
            [
                0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 1, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
