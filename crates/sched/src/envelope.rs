use crypto::DkimAlg;

const VERSION: u8 = 1;
const EIGHT_BIT: u8 = 1;
const DECLARED: u8 = 2;
const RET_SHIFT: u8 = 2;
const RET_MASK: u8 = 3 << RET_SHIFT;
const SMTPUTF8: u8 = 1;
const REQUIRETLS: u8 = 2;
const REQUIRED: u8 = SMTPUTF8 | REQUIRETLS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ret {
    #[default]
    None,
    Full,
    Headers,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Required {
    pub smtputf8: bool,
    pub requiretls: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Envelope {
    pub sender: String,
    pub eight_bit: bool,
    pub declared: bool,
    pub ret: Ret,
    pub required: Required,
    pub envid: Vec<u8>,
    pub signatures: Vec<(u32, DkimAlg)>,
}

impl Envelope {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let sender = u16::try_from(self.sender.len()).ok()?;
        let envid = u8::try_from(self.envid.len()).ok()?;
        let count = u8::try_from(self.signatures.len()).ok()?;
        let ret = match self.ret {
            Ret::None => 0,
            Ret::Full => 1,
            Ret::Headers => 2,
        };
        let flags = (u8::from(self.eight_bit) * EIGHT_BIT)
            | (u8::from(self.declared) * DECLARED)
            | (ret << RET_SHIFT);
        let required = (u8::from(self.required.smtputf8) * SMTPUTF8)
            | (u8::from(self.required.requiretls) * REQUIRETLS);
        let mut out = Vec::with_capacity(8 + self.sender.len() + self.envid.len() + 5 * 2);
        out.extend_from_slice(&[VERSION, flags, required]);
        out.extend_from_slice(&sender.to_le_bytes());
        out.extend_from_slice(self.sender.as_bytes());
        out.push(envid);
        out.extend_from_slice(&self.envid);
        out.push(count);
        for (key, alg) in &self.signatures {
            out.extend_from_slice(&key.to_le_bytes());
            out.push(alg.code());
        }
        Some(out)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut read = Reader(bytes);
        let [version, flags, required] = read.array()?;
        if version != VERSION || required & !REQUIRED != 0 {
            return None;
        }
        let sender = usize::from(u16::from_le_bytes(read.array()?));
        let sender = String::from_utf8(read.take(sender)?.to_vec()).ok()?;
        let [envid] = read.array()?;
        let envid = read.take(usize::from(envid))?.to_vec();
        let [count] = read.array()?;
        let mut signatures = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let key = u32::from_le_bytes(read.array()?);
            let [alg] = read.array()?;
            signatures.push((key, DkimAlg::from_code(alg)?));
        }
        if !read.0.is_empty() {
            return None;
        }
        let ret = match (flags & RET_MASK) >> RET_SHIFT {
            0 => Ret::None,
            1 => Ret::Full,
            2 => Ret::Headers,
            _ => return None,
        };
        Some(Self {
            sender,
            eight_bit: flags & EIGHT_BIT != 0,
            declared: flags & DECLARED != 0,
            ret,
            required: Required {
                smtputf8: required & SMTPUTF8 != 0,
                requiretls: required & REQUIRETLS != 0,
            },
            envid,
            signatures,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recipient {
    pub address: String,
    pub orcpt: Vec<u8>,
    pub notify: u8,
}

pub fn encode_slice(recipients: &[Recipient]) -> Option<Vec<u8>> {
    let count = u16::try_from(recipients.len()).ok()?;
    let size: usize = recipients
        .iter()
        .map(|r| 5 + r.address.len() + r.orcpt.len())
        .sum();
    let mut out = Vec::with_capacity(3 + size);
    out.push(VERSION);
    out.extend_from_slice(&count.to_le_bytes());
    for recipient in recipients {
        let address = u16::try_from(recipient.address.len()).ok()?;
        let orcpt = u16::try_from(recipient.orcpt.len()).ok()?;
        out.extend_from_slice(&address.to_le_bytes());
        out.extend_from_slice(recipient.address.as_bytes());
        out.extend_from_slice(&orcpt.to_le_bytes());
        out.extend_from_slice(&recipient.orcpt);
        out.push(recipient.notify);
    }
    Some(out)
}

pub fn decode_slice(bytes: &[u8]) -> Option<Vec<Recipient>> {
    let mut read = Reader(bytes);
    let [version] = read.array()?;
    if version != VERSION {
        return None;
    }
    let count = u16::from_le_bytes(read.array()?);
    let mut out = Vec::with_capacity(usize::from(count).min(bytes.len() / 5));
    for _ in 0..count {
        let address = usize::from(u16::from_le_bytes(read.array()?));
        let address = String::from_utf8(read.take(address)?.to_vec()).ok()?;
        let orcpt = usize::from(u16::from_le_bytes(read.array()?));
        let orcpt = read.take(orcpt)?.to_vec();
        let [notify] = read.array()?;
        out.push(Recipient {
            address,
            orcpt,
            notify,
        });
    }
    read.0.is_empty().then_some(out)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> Envelope {
        Envelope {
            sender: "bounce@example.org".into(),
            eight_bit: true,
            declared: false,
            ret: Ret::Headers,
            required: Required {
                smtputf8: false,
                requiretls: true,
            },
            envid: b"env-1".to_vec(),
            signatures: vec![(7, DkimAlg::RsaSha256), (9, DkimAlg::Ed25519Sha256)],
        }
    }

    #[test]
    fn envelope_round_trips() {
        for envelope in [Envelope::default(), full()] {
            let bytes = envelope.encode().expect("encode");
            assert_eq!(Envelope::decode(&bytes), Some(envelope));
        }
    }

    #[test]
    fn envelope_layout_is_frozen() {
        let bytes = full().encode().expect("encode");
        let mut expected = vec![1, 0b1001, 2, 18, 0];
        expected.extend_from_slice(b"bounce@example.org");
        expected.push(5);
        expected.extend_from_slice(b"env-1");
        expected.extend_from_slice(&[2, 7, 0, 0, 0, 1, 9, 0, 0, 0, 2]);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn envelope_ignores_unknown_flags_but_not_unknown_requirements() {
        let mut bytes = full().encode().expect("encode");
        bytes[1] |= 0x80;
        assert_eq!(Envelope::decode(&bytes), Some(full()));
        bytes[2] |= 0x04;
        assert_eq!(Envelope::decode(&bytes), None);
    }

    #[test]
    fn envelope_refuses_bad_bytes() {
        let bytes = full().encode().expect("encode");
        for cut in 0..bytes.len() {
            assert_eq!(Envelope::decode(&bytes[..cut]), None, "cut {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Envelope::decode(&longer), None);
        let mut version = bytes.clone();
        version[0] = 2;
        assert_eq!(Envelope::decode(&version), None);
        let mut ret = bytes.clone();
        ret[1] |= RET_MASK;
        assert_eq!(Envelope::decode(&ret), None);
        let mut alg = bytes;
        let last = alg.len() - 1;
        alg[last] = 3;
        assert_eq!(Envelope::decode(&alg), None);
    }

    fn recipients() -> Vec<Recipient> {
        vec![
            Recipient {
                address: "a@example.org".into(),
                orcpt: b"rfc822;a@example.org".to_vec(),
                notify: 4 | 8,
            },
            Recipient {
                address: "b@example.net".into(),
                ..Recipient::default()
            },
        ]
    }

    #[test]
    fn slice_round_trips_and_is_frozen() {
        let bytes = encode_slice(&recipients()).expect("encode");
        let mut expected = vec![1, 2, 0, 13, 0];
        expected.extend_from_slice(b"a@example.org");
        expected.extend_from_slice(&[20, 0]);
        expected.extend_from_slice(b"rfc822;a@example.org");
        expected.extend_from_slice(&[12, 13, 0]);
        expected.extend_from_slice(b"b@example.net");
        expected.extend_from_slice(&[0, 0, 0]);
        assert_eq!(bytes, expected);
        assert_eq!(decode_slice(&bytes), Some(recipients()));
        assert_eq!(decode_slice(&[1, 0, 0]), Some(Vec::new()));
    }

    #[test]
    fn slice_refuses_bad_bytes() {
        let bytes = encode_slice(&recipients()).expect("encode");
        for cut in 0..bytes.len() {
            assert_eq!(decode_slice(&bytes[..cut]), None, "cut {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode_slice(&longer), None);
        let mut version = bytes;
        version[0] = 0;
        assert_eq!(decode_slice(&version), None);
        assert_eq!(decode_slice(&[1, 0xff, 0xff]), None);
    }
}
