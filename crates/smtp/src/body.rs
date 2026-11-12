use std::mem;

use crate::reply::{self, Reply};

pub(crate) const TEXT_LINE: usize = 998;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    Cr(u64),
    Long(u64),
    Nul(u64),
    Size,
}

impl Fault {
    pub(crate) fn reply(self) -> Reply {
        match self {
            Self::Cr(line) => Reply::owned(554, "5.6.0", format!("Bare CR in line {line}")),
            Self::Long(line) => Reply::owned(
                554,
                "5.6.0",
                format!("Line {line} longer than {TEXT_LINE} octets"),
            ),
            Self::Nul(line) => Reply::owned(554, "5.6.0", format!("NUL octet in line {line}")),
            Self::Size => reply::TOO_BIG,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    Start(bool),
    Dot(bool),
    Mid,
}

#[derive(Debug)]
pub(crate) struct Decoder {
    dots: bool,
    at: At,
    cr: bool,
    line: u64,
    length: usize,
    size: u64,
    limit: u64,
    lf: u64,
    fault: Option<Fault>,
    halted: bool,
    discarded: u64,
}

impl Decoder {
    pub(crate) fn data(limit: u64, crlf: bool) -> Self {
        Self::new(limit, true, crlf)
    }

    pub(crate) fn chunks(limit: u64) -> Self {
        Self::new(limit, false, true)
    }

    fn new(limit: u64, dots: bool, crlf: bool) -> Self {
        Self {
            dots,
            at: At::Start(crlf),
            cr: false,
            line: 1,
            length: 0,
            size: 0,
            limit,
            lf: 0,
            fault: None,
            halted: false,
            discarded: 0,
        }
    }

    pub(crate) fn fault(&self) -> Option<Fault> {
        self.fault
    }

    pub(crate) fn halted(&self) -> bool {
        self.halted
    }

    pub(crate) fn discarded(&self) -> u64 {
        self.discarded
    }

    pub(crate) fn lf(&self) -> u64 {
        self.lf
    }

    pub(crate) fn halt(&mut self) {
        self.halted = true;
    }

    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> (usize, bool) {
        for (i, &b) in input.iter().enumerate() {
            if self.halted {
                self.discarded += 1;
            }
            if mem::take(&mut self.cr) {
                if b == b'\n' {
                    if self.end(true, out) {
                        return (i + 1, true);
                    }
                    continue;
                }
                self.fail(Fault::Cr(self.line));
                self.at = At::Mid;
                self.length += 1;
            }
            match b {
                b'\r' => self.cr = true,
                b'\n' => {
                    self.end(false, out);
                }
                _ => self.byte(b, out),
            }
        }
        (input.len(), false)
    }

    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) {
        if mem::take(&mut self.cr) {
            self.fail(Fault::Cr(self.line));
        }
        if self.at == At::Mid {
            self.put(b"\r\n", out);
        }
    }

    fn byte(&mut self, b: u8, out: &mut Vec<u8>) {
        if let At::Start(crlf) = self.at
            && self.dots
            && b == b'.'
        {
            self.at = At::Dot(crlf);
            return;
        }
        self.length += 1;
        if self.length > TEXT_LINE {
            self.fail(Fault::Long(self.line));
        }
        if b == 0 {
            self.fail(Fault::Nul(self.line));
        }
        self.at = At::Mid;
        self.put(&[b], out);
    }

    fn end(&mut self, crlf: bool, out: &mut Vec<u8>) -> bool {
        if let At::Dot(after_crlf) = mem::replace(&mut self.at, At::Start(crlf)) {
            if after_crlf && crlf {
                return true;
            }
            self.put(b".", out);
        }
        self.put(b"\r\n", out);
        if !crlf {
            self.lf += 1;
        }
        self.line += 1;
        self.length = 0;
        false
    }

    fn put(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        if self.halted {
            return;
        }
        self.size += bytes.len() as u64;
        if self.size > self.limit {
            self.fail(Fault::Size);
            return;
        }
        out.extend_from_slice(bytes);
    }

    fn fail(&mut self, fault: Fault) {
        self.fault.get_or_insert(fault);
        self.halted = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(input: &[u8]) -> (Vec<u8>, usize, bool, Option<Fault>) {
        let mut decoder = Decoder::data(1 << 20, true);
        let mut out = Vec::new();
        let (used, done) = decoder.feed(input, &mut out);
        (out, used, done, decoder.fault())
    }

    #[test]
    fn ends_only_at_crlf_dot_crlf() {
        assert_eq!(data(b".\r\n"), (Vec::new(), 3, true, None));
        assert_eq!(
            data(b"a\r\n.\r\nQUIT\r\n"),
            (b"a\r\n".to_vec(), 6, true, None)
        );
        let cases: [(&[u8], &[u8]); 4] = [
            (b"a\n.\nb\r\n.\r\n", b"a\r\n.\r\nb\r\n"),
            (b"a\n.\r\nb\r\n.\r\n", b"a\r\n.\r\nb\r\n"),
            (b"a\r\n.\nb\r\n.\r\n", b"a\r\n.\r\nb\r\n"),
            (b"a\r\n..\r\n.b\r\n.\r\n", b"a\r\n.\r\nb\r\n"),
        ];
        for (input, want) in cases {
            let (out, used, done, fault) = data(input);
            assert_eq!(
                (out.as_slice(), used, done, fault),
                (want, input.len(), true, None)
            );
        }
    }

    #[test]
    fn normalises_bare_lf_and_counts_it() {
        let mut decoder = Decoder::data(1 << 20, true);
        let mut out = Vec::new();
        assert_eq!(decoder.feed(b"a\nb\n\r\n.\r\n", &mut out), (9, true));
        assert_eq!(out, b"a\r\nb\r\n\r\n");
        assert_eq!(decoder.lf(), 2);
    }

    #[test]
    fn a_bare_cr_faults_but_reading_goes_on_to_the_end() {
        let (_, used, done, fault) = data(b"a\r\n\r.\r\nb\r\n.\r\n");
        assert_eq!((used, done, fault), (13, true, Some(Fault::Cr(2))));
        let cases: [(&[u8], u64); 4] = [
            (b"a\r.\rb\r\n.\r\n", 1),
            (b"a\r\n.\r.\r\n.\r\n", 2),
            (b"a\r\r\n.\r\n", 1),
            (b"a\r\nb\rc\r\n.\r\n", 2),
        ];
        for (input, line) in cases {
            let (_, used, done, fault) = data(input);
            assert_eq!(
                (used, done, fault),
                (input.len(), true, Some(Fault::Cr(line)))
            );
        }
    }

    #[test]
    fn lines_over_the_limit_or_with_nul_fault() {
        let mut input = vec![b'a'; TEXT_LINE];
        input.extend_from_slice(b"\r\n");
        input.extend(vec![b'.'; TEXT_LINE + 1]);
        input.extend_from_slice(b"\r\n.\r\n");
        assert_eq!(data(&input).3, None);
        let mut long = vec![b'a'; TEXT_LINE + 1];
        long.extend_from_slice(b"\r\n.\r\n");
        assert_eq!(data(&long).3, Some(Fault::Long(1)));
        assert_eq!(data(b"a\r\nb\0\r\n.\r\n").3, Some(Fault::Nul(2)));
    }

    #[test]
    fn the_size_counts_stored_bytes() {
        let mut decoder = Decoder::data(5, true);
        let mut out = Vec::new();
        assert_eq!(decoder.feed(b"..a\r\n.\r\n", &mut out), (8, true));
        assert_eq!(decoder.fault(), None);
        let mut decoder = Decoder::data(5, true);
        out.clear();
        assert_eq!(decoder.feed(b"abcd\r\nxyz\r\n.\r\n", &mut out), (14, true));
        assert_eq!(decoder.fault(), Some(Fault::Size));
        assert_eq!(decoder.discarded(), 8);
    }

    #[test]
    fn chunks_keep_dots_and_join_a_split_crlf() {
        let mut decoder = Decoder::chunks(1 << 20);
        let mut out = Vec::new();
        decoder.feed(b"a\r", &mut out);
        decoder.feed(b"\n.\r\n.", &mut out);
        decoder.feed(b"\nb", &mut out);
        decoder.finish(&mut out);
        assert_eq!(out, b"a\r\n.\r\n.\r\nb\r\n");
        assert_eq!((decoder.fault(), decoder.lf()), (None, 1));
        let mut decoder = Decoder::chunks(1 << 20);
        decoder.feed(b"a\r", &mut out);
        decoder.finish(&mut out);
        assert_eq!(decoder.fault(), Some(Fault::Cr(1)));
    }
}
