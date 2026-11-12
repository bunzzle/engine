use crate::mailbox::from_domain;

pub const HEADER_CAP: usize = 256 * 1024;
const RECEIVED: usize = 50;

const SINGLE: [&str; 14] = [
    "date",
    "subject",
    "message-id",
    "to",
    "cc",
    "reply-to",
    "sender",
    "in-reply-to",
    "references",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "list-unsubscribe",
    "list-unsubscribe-post",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    TooLarge,
    Malformed,
    Hidden,
    Loop,
    Repeated,
    From,
    Signer,
}

#[derive(Default)]
pub struct HeaderBuffer {
    section: Vec<u8>,
    done: bool,
}

impl HeaderBuffer {
    pub fn push<'a>(&mut self, bytes: &'a [u8]) -> Result<&'a [u8], Fault> {
        if self.done {
            return Ok(bytes);
        }
        let start = self.section.len().saturating_sub(3);
        let before = self.section.len();
        self.section.extend_from_slice(bytes);
        let end = if self.section.starts_with(b"\r\n") {
            Some(0)
        } else {
            self.section[start..]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|at| start + at + 2)
        };
        match end {
            Some(end) => {
                if end > HEADER_CAP {
                    return Err(Fault::TooLarge);
                }
                self.done = true;
                let rest = end + 2 - before;
                self.section.truncate(end);
                Ok(&bytes[rest..])
            }
            None if self.section.len() > HEADER_CAP => Err(Fault::TooLarge),
            None => Ok(&[]),
        }
    }

    pub fn done(&self) -> bool {
        self.done
    }

    pub fn section(&self) -> &[u8] {
        &self.section
    }

    pub fn finish(self) -> Vec<u8> {
        self.section
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Checked {
    pub from: String,
    pub date: bool,
    pub message_id: bool,
}

pub fn check(section: &[u8]) -> Result<Checked, Fault> {
    if section.iter().any(|&b| b == 0 || !b.is_ascii()) {
        return Err(Fault::Malformed);
    }
    let fields = dkim::parse(section).map_err(|_| Fault::Malformed)?;
    let count = |name: &str| fields.iter().filter(|f| f.is(name)).count();
    if count("bcc") > 0 || count("return-path") > 0 {
        return Err(Fault::Hidden);
    }
    if count("received") > RECEIVED {
        return Err(Fault::Loop);
    }
    if SINGLE.iter().any(|name| count(name) > 1) {
        return Err(Fault::Repeated);
    }
    let mut from = fields.iter().filter(|f| f.is("from"));
    let (Some(field), None) = (from.next(), from.next()) else {
        return Err(Fault::From);
    };
    Ok(Checked {
        from: from_domain(field.value()).ok_or(Fault::From)?,
        date: count("date") == 1,
        message_id: count("message-id") == 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(message: &[u8], step: usize) -> Result<(Vec<u8>, Vec<u8>), Fault> {
        let mut buffer = HeaderBuffer::default();
        let mut body = Vec::new();
        for piece in message.chunks(step) {
            body.extend_from_slice(buffer.push(piece)?);
        }
        Ok((buffer.finish(), body))
    }

    #[test]
    fn splits_header_and_body_at_any_cut() {
        let cases: [(&[u8], &[u8], &[u8]); 4] = [
            (
                b"A: 1\r\nB: 2\r\n\r\nbody\r\n",
                b"A: 1\r\nB: 2\r\n",
                b"body\r\n",
            ),
            (b"A: 1\r\n\r\n", b"A: 1\r\n", b""),
            (b"\r\nbody\r\n", b"", b"body\r\n"),
            (b"A: 1\r\n\r\n\r\n\r\n", b"A: 1\r\n", b"\r\n\r\n"),
        ];
        for (message, header, body) in cases {
            for step in 1..=message.len() {
                let (h, b) = split(message, step).expect("split");
                assert_eq!((h.as_slice(), b.as_slice()), (header, body), "step {step}");
            }
        }
    }

    #[test]
    fn a_message_without_an_empty_line_is_all_header() {
        let mut buffer = HeaderBuffer::default();
        assert_eq!(buffer.push(b"A: 1\r\n").expect("push"), b"");
        assert!(!buffer.done());
        assert_eq!(buffer.finish(), b"A: 1\r\n");
    }

    #[test]
    fn caps_the_header_section() {
        let line = format!("X: {}\r\n", "a".repeat(990));
        let mut message = line.repeat(HEADER_CAP / line.len());
        message.push_str("\r\nbody");
        assert!(split(message.as_bytes(), 4096).is_ok());
        let mut over = line.repeat(HEADER_CAP / line.len() + 1);
        over.push_str("\r\nbody");
        for step in [1000, 4096, over.len()] {
            assert_eq!(split(over.as_bytes(), step), Err(Fault::TooLarge));
        }
    }

    fn checked(section: &str) -> Result<Checked, Fault> {
        check(section.as_bytes())
    }

    #[test]
    fn reads_the_from_domain() {
        let found = checked("From: Ann <a@Mail.Example.org>\r\nSubject: hi\r\n").expect("ok");
        assert_eq!(
            found,
            Checked {
                from: "mail.example.org".into(),
                date: false,
                message_id: false,
            }
        );
        let full = checked("Date: x\r\nMessage-ID: <1@a>\r\nFrom: a@b.org\r\n").expect("ok");
        assert!(full.date && full.message_id);
    }

    #[test]
    fn refuses_bad_sections() {
        let cases = [
            ("From: a@b.org\r\nX: \0\r\n", Fault::Malformed),
            ("From: a@b.org\r\nX: \u{e9}\r\n", Fault::Malformed),
            ("From: a@b.org\r\nno colon\r\n", Fault::Malformed),
            (" From: a@b.org\r\n", Fault::Malformed),
            ("From: a@b.org\r\nBcc: c@d.org\r\n", Fault::Hidden),
            ("From: a@b.org\r\nReturn-Path: <c@d.org>\r\n", Fault::Hidden),
            (
                "From: a@b.org\r\nsubject: 1\r\nSubject: 2\r\n",
                Fault::Repeated,
            ),
            (
                "From: a@b.org\r\nTo: c@d.org\r\nto: e@f.org\r\n",
                Fault::Repeated,
            ),
            ("Subject: hi\r\n", Fault::From),
            ("From: a@b.org\r\nfrom: c@d.org\r\n", Fault::From),
            ("From: a@b.org, c@d.org\r\n", Fault::From),
            ("", Fault::From),
        ];
        for (section, fault) in cases {
            assert_eq!(checked(section), Err(fault), "{section:?}");
        }
    }

    #[test]
    fn counts_received_fields() {
        let received = "Received: by a\r\n";
        let ok = format!("{}From: a@b.org\r\n", received.repeat(RECEIVED));
        assert!(checked(&ok).is_ok());
        let over = format!("{}From: a@b.org\r\n", received.repeat(RECEIVED + 1));
        assert_eq!(checked(&over), Err(Fault::Loop));
    }
}
