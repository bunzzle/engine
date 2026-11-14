#![allow(dead_code)]

use dns::Name;

pub const QR: u16 = 0x8000;
pub const TC: u16 = 0x0200;
pub const AD: u16 = 0x0020;
pub const SERVFAIL: u16 = 2;
pub const NXDOMAIN: u16 = 3;

pub struct Rr {
    pub owner: Vec<u8>,
    pub kind: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

pub fn wire(name: &str) -> Vec<u8> {
    Name::parse(name).expect("name").wire().to_vec()
}

pub fn rr(owner: &str, kind: u16, ttl: u32, data: Vec<u8>) -> Rr {
    Rr {
        owner: wire(owner),
        kind,
        ttl,
        data,
    }
}

pub fn mx(preference: u16, exchange: &str) -> Vec<u8> {
    let mut data = preference.to_be_bytes().to_vec();
    data.extend(wire(exchange));
    data
}

pub fn soa(minimum: u32) -> Vec<u8> {
    let mut data = wire("ns.example.net");
    data.extend(wire("hostmaster.example.net"));
    for value in [1u32, 2, 3, 4, minimum] {
        data.extend(value.to_be_bytes());
    }
    data
}

pub fn question_end(query: &[u8]) -> usize {
    let mut at = 12;
    while query[at] != 0 {
        at += 1 + usize::from(query[at]);
    }
    at + 5
}

pub fn reply(query: &[u8], flags: u16, answers: &[Rr], authority: &[Rr]) -> Vec<u8> {
    let mut out = query[..2].to_vec();
    out.extend((QR | 0x0100 | 0x0080 | flags).to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend(u16::try_from(answers.len()).expect("few").to_be_bytes());
    out.extend(u16::try_from(authority.len()).expect("few").to_be_bytes());
    out.extend(0u16.to_be_bytes());
    out.extend_from_slice(&query[12..question_end(query)]);
    for rr in answers.iter().chain(authority) {
        out.extend_from_slice(&rr.owner);
        out.extend(rr.kind.to_be_bytes());
        out.extend(1u16.to_be_bytes());
        out.extend(rr.ttl.to_be_bytes());
        out.extend(u16::try_from(rr.data.len()).expect("small").to_be_bytes());
        out.extend_from_slice(&rr.data);
    }
    out
}
