use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;
use crate::name::{MAX_WIRE, Name};

pub const HEADER: usize = 12;
pub const PAYLOAD: u16 = 1232;
const QR: u16 = 0x8000;
const OPCODE: u16 = 0x7800;
const TC: u16 = 0x0200;
const RD: u16 = 0x0100;
const AD: u16 = 0x0020;
const RCODE: u16 = 0x000f;
const DO: u32 = 0x8000;
const CLASS_IN: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_OPT: u16 = 41;
const MAX_JUMPS: usize = 64;
const TTL_MAX: u32 = 0x7fff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    A,
    Aaaa,
    Mx,
    Txt,
    Tlsa,
}

impl Type {
    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Tlsa => 52,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Mx {
        preference: u16,
        exchange: Name,
    },
    Txt(Vec<u8>),
    Tlsa {
        usage: u8,
        selector: u8,
        matching: u8,
        data: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    Other(u8),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub rcode: Rcode,
    pub truncated: bool,
    pub authentic: bool,
    pub name: Name,
    pub records: Vec<Record>,
    pub ttl: u32,
    pub negative_ttl: Option<u32>,
}

pub fn query(id: u16, name: &Name, kind: Type, dnssec: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + name.wire().len() + 15);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(RD | AD).to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]);
    out.extend_from_slice(name.wire());
    out.extend_from_slice(&kind.code().to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    let flags = if dnssec { DO } else { 0 };
    out.push(0);
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&PAYLOAD.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

pub fn matches(id: u16, name: &Name, kind: Type, packet: &[u8]) -> bool {
    let mut reader = Reader::new(packet);
    let Ok(got) = reader.u16() else {
        return false;
    };
    let Ok(flags) = reader.u16() else {
        return false;
    };
    if got != id || flags & QR == 0 || flags & OPCODE != 0 {
        return false;
    }
    if !matches!(reader.u16(), Ok(1)) {
        return false;
    }
    reader.at = HEADER;
    question(&mut reader, name, kind).is_ok()
}

fn question(reader: &mut Reader<'_>, name: &Name, kind: Type) -> Result<(), Error> {
    let asked = reader.name()?;
    let (qtype, qclass) = (reader.u16()?, reader.u16()?);
    if asked != *name || qtype != kind.code() || qclass != CLASS_IN {
        return Err(Error::Malformed);
    }
    Ok(())
}

pub fn parse(id: u16, name: &Name, kind: Type, packet: &[u8]) -> Result<Reply, Error> {
    if !matches(id, name, kind, packet) {
        return Err(Error::Malformed);
    }
    let mut reader = Reader::new(packet);
    reader.at = 2;
    let flags = reader.u16()?;
    let counts = [reader.u16()?, reader.u16()?, reader.u16()?, reader.u16()?];
    question(&mut reader, name, kind)?;
    let truncated = flags & TC != 0;
    let rcode = match flags & RCODE {
        0 => Rcode::NoError,
        2 => Rcode::ServFail,
        3 => Rcode::NxDomain,
        5 => Rcode::Refused,
        other => Rcode::Other(u8::try_from(other).unwrap_or(u8::MAX)),
    };
    let mut reply = Reply {
        rcode,
        truncated,
        authentic: flags & AD != 0,
        name: name.clone(),
        records: Vec::new(),
        ttl: u32::MAX,
        negative_ttl: None,
    };
    if truncated {
        return Ok(reply);
    }
    let mut answers = Vec::with_capacity(usize::from(counts[1]));
    for _ in 0..counts[1] {
        answers.push(reader.record()?);
    }
    for _ in 0..counts[2] {
        let raw = reader.record()?;
        if raw.kind == TYPE_SOA && raw.class == CLASS_IN {
            let minimum = soa_minimum(packet, raw.data)?;
            let ttl = minimum.min(raw.ttl);
            reply.negative_ttl = Some(reply.negative_ttl.map_or(ttl, |t| t.min(ttl)));
        }
    }
    for _ in 0..counts[3] {
        reader.record()?;
    }
    if reader.at != packet.len() {
        return Err(Error::Malformed);
    }
    follow(&mut reply, packet, &answers, kind)?;
    Ok(reply)
}

fn follow(reply: &mut Reply, packet: &[u8], answers: &[Raw], kind: Type) -> Result<(), Error> {
    for _ in 0..=8 {
        let Some(alias) = answers
            .iter()
            .find(|r| r.kind == TYPE_CNAME && r.class == CLASS_IN && r.owner == reply.name)
        else {
            break;
        };
        let mut reader = Reader::new(packet);
        reader.at = alias.data.start;
        let target = reader.name()?;
        if reader.at != alias.data.end {
            return Err(Error::Malformed);
        }
        reply.ttl = reply.ttl.min(alias.ttl);
        reply.name = target;
    }
    if answers
        .iter()
        .any(|r| r.kind == TYPE_CNAME && r.class == CLASS_IN && r.owner == reply.name)
    {
        return Err(Error::Malformed);
    }
    for raw in answers {
        if raw.kind != kind.code() || raw.class != CLASS_IN || raw.owner != reply.name {
            continue;
        }
        reply.records.push(record(packet, raw, kind)?);
        reply.ttl = reply.ttl.min(raw.ttl);
    }
    Ok(())
}

fn record(packet: &[u8], raw: &Raw, kind: Type) -> Result<Record, Error> {
    let data = &packet[raw.data.clone()];
    let mut reader = Reader::new(packet);
    reader.at = raw.data.start;
    let record = match kind {
        Type::A => Record::A(Ipv4Addr::from(
            <[u8; 4]>::try_from(data).map_err(|_| Error::Malformed)?,
        )),
        Type::Aaaa => Record::Aaaa(Ipv6Addr::from(
            <[u8; 16]>::try_from(data).map_err(|_| Error::Malformed)?,
        )),
        Type::Mx => {
            let preference = reader.u16()?;
            let exchange = reader.name()?;
            if reader.at != raw.data.end {
                return Err(Error::Malformed);
            }
            Record::Mx {
                preference,
                exchange,
            }
        }
        Type::Txt => {
            let mut text = Vec::with_capacity(data.len());
            let mut rest = data;
            while let Some((&len, tail)) = rest.split_first() {
                let len = usize::from(len);
                let part = tail.get(..len).ok_or(Error::Malformed)?;
                text.extend_from_slice(part);
                rest = &tail[len..];
            }
            Record::Txt(text)
        }
        Type::Tlsa => {
            let [usage, selector, matching, rest @ ..] = data else {
                return Err(Error::Malformed);
            };
            Record::Tlsa {
                usage: *usage,
                selector: *selector,
                matching: *matching,
                data: rest.to_vec(),
            }
        }
    };
    Ok(record)
}

fn soa_minimum(packet: &[u8], data: std::ops::Range<usize>) -> Result<u32, Error> {
    let mut reader = Reader::new(packet);
    reader.at = data.start;
    reader.skip_name()?;
    reader.skip_name()?;
    for _ in 0..4 {
        reader.u32()?;
    }
    let minimum = reader.u32()?;
    if reader.at != data.end {
        return Err(Error::Malformed);
    }
    Ok(minimum)
}

struct Raw {
    owner: Name,
    kind: u16,
    class: u16,
    ttl: u32,
    data: std::ops::Range<usize>,
}

struct Reader<'a> {
    packet: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(packet: &'a [u8]) -> Self {
        Self { packet, at: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(len).ok_or(Error::Malformed)?;
        let bytes = self.packet.get(self.at..end).ok_or(Error::Malformed)?;
        self.at = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn record(&mut self) -> Result<Raw, Error> {
        let owner = self.name()?;
        let kind = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let len = usize::from(self.u16()?);
        let start = self.at;
        self.take(len)?;
        Ok(Raw {
            owner,
            kind,
            class,
            ttl: if ttl > TTL_MAX { 0 } else { ttl },
            data: start..start + len,
        })
    }

    fn skip_name(&mut self) -> Result<(), Error> {
        self.walk(None)
    }

    fn name(&mut self) -> Result<Name, Error> {
        let mut wire = Vec::with_capacity(32);
        self.walk(Some(&mut wire))?;
        Ok(Name::from_wire(wire))
    }

    fn walk(&mut self, mut out: Option<&mut Vec<u8>>) -> Result<(), Error> {
        let mut at = self.at;
        let mut floor = self.at;
        let mut jumped = false;
        let mut jumps = 0;
        let mut length = 0;
        loop {
            let len = *self.packet.get(at).ok_or(Error::Malformed)?;
            match len & 0xc0 {
                0x00 => {
                    let size = usize::from(len);
                    length += size + 1;
                    if length > MAX_WIRE {
                        return Err(Error::Malformed);
                    }
                    let label = self
                        .packet
                        .get(at + 1..at + 1 + size)
                        .ok_or(Error::Malformed)?;
                    if let Some(out) = out.as_deref_mut() {
                        out.push(len);
                        out.extend(label.iter().map(u8::to_ascii_lowercase));
                    }
                    at += 1 + size;
                    if size == 0 {
                        if !jumped {
                            self.at = at;
                        }
                        return Ok(());
                    }
                }
                0xc0 => {
                    let low = *self.packet.get(at + 1).ok_or(Error::Malformed)?;
                    let target = usize::from(len & 0x3f) << 8 | usize::from(low);
                    jumps += 1;
                    if target >= floor || jumps > MAX_JUMPS {
                        return Err(Error::Malformed);
                    }
                    if !jumped {
                        self.at = at + 2;
                        jumped = true;
                    }
                    floor = target;
                    at = target;
                }
                _ => return Err(Error::Malformed),
            }
        }
    }
}
