use crypto::Sha256;

const FLUSH: usize = 8192;

pub(crate) fn relaxed_field(name: &[u8], value: &[u8], out: &mut Vec<u8>) {
    out.extend(name.iter().map(u8::to_ascii_lowercase));
    out.push(b':');
    let mut space = false;
    let mut any = false;
    for &b in value {
        match b {
            b'\r' | b'\n' => {}
            b' ' | b'\t' => space = true,
            _ => {
                if space && any {
                    out.push(b' ');
                }
                space = false;
                any = true;
                out.push(b);
            }
        }
    }
    out.extend_from_slice(b"\r\n");
}

pub struct BodyHash {
    hash: Sha256,
    buffer: Vec<u8>,
    lines: u64,
    space: bool,
    cr: bool,
    any: bool,
}

impl BodyHash {
    pub fn new() -> Self {
        Self {
            hash: Sha256::new(),
            buffer: Vec::with_capacity(FLUSH + 2),
            lines: 0,
            space: false,
            cr: false,
            any: false,
        }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        for &b in chunk {
            self.byte(b);
        }
        self.flush();
    }

    pub fn finish(mut self) -> [u8; 32] {
        if self.cr {
            self.cr = false;
            self.content(b'\r');
        }
        if self.any {
            self.buffer.extend_from_slice(b"\r\n");
        }
        self.flush();
        self.hash.finish()
    }

    fn byte(&mut self, b: u8) {
        if self.cr {
            self.cr = false;
            if b == b'\n' {
                self.space = false;
                self.lines += 1;
                return;
            }
            self.content(b'\r');
        }
        match b {
            b'\r' => self.cr = true,
            b' ' | b'\t' => self.space = true,
            _ => self.content(b),
        }
    }

    fn content(&mut self, b: u8) {
        while self.lines > 0 {
            self.buffer.extend_from_slice(b"\r\n");
            self.lines -= 1;
            if self.buffer.len() >= FLUSH {
                self.flush();
            }
        }
        if self.space {
            self.buffer.push(b' ');
            self.space = false;
        }
        self.buffer.push(b);
        self.any = true;
        if self.buffer.len() >= FLUSH {
            self.flush();
        }
    }

    fn flush(&mut self) {
        self.hash.update(&self.buffer);
        self.buffer.clear();
    }
}

impl Default for BodyHash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crypto::sha256;

    use super::*;

    fn hash(body: &[u8]) -> [u8; 32] {
        let mut hash = BodyHash::new();
        hash.update(body);
        hash.finish()
    }

    #[test]
    fn relaxed_body_rules() {
        let cases: [(&[u8], &[u8]); 9] = [
            (b"", b""),
            (b"\r\n\r\n", b""),
            (b" \t \r\n", b""),
            (b"a", b"a\r\n"),
            (b"a\r\n", b"a\r\n"),
            (b"a  \t\r\n\r\n\r\n", b"a\r\n"),
            (b"  a \t b  \r\n", b" a b\r\n"),
            (b"a\r\n \r\nb\r\n\r\n", b"a\r\n\r\nb\r\n"),
            (b"a\rb\r\n", b"a\rb\r\n"),
        ];
        for (body, canonical) in cases {
            assert_eq!(
                hash(body),
                sha256(canonical),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn long_runs_of_empty_lines_flush_in_pieces() {
        let mut body = b"a\r\n".to_vec();
        body.extend(b"\r\n".repeat(20_000));
        body.extend_from_slice(b"b\r\n");
        let mut canonical = b"a\r\n".to_vec();
        canonical.extend(b"\r\n".repeat(20_000));
        canonical.extend_from_slice(b"b\r\n");
        assert_eq!(hash(&body), sha256(&canonical));
    }

    #[test]
    fn relaxed_field_unfolds_and_lowercases_the_name() {
        let mut out = Vec::new();
        relaxed_field(b"SubJect", b" \t one\r\n  two \t\r\n", &mut out);
        assert_eq!(out, b"subject:one two\r\n");
        out.clear();
        relaxed_field(b"X", b"\r\n", &mut out);
        assert_eq!(out, b"x:\r\n");
    }
}
