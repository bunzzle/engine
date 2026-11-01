use crate::error::Error;

pub const BLOCK: usize = 4096;
pub const KEY: usize = 20;
pub const MAX_PAYLOAD: usize = BLOCK - 4;

const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;
const REFERENCE: usize = 6;

pub type Key = [u8; KEY];

pub fn key(tenant: u32, hash: [u8; 16]) -> Key {
    let mut key = [0; KEY];
    key[..4].copy_from_slice(&tenant.to_be_bytes());
    key[4..].copy_from_slice(&hash);
    key
}

pub fn tenant(key: &Key) -> u32 {
    u32::from_be_bytes(key[..4].try_into().expect("4 bytes"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Put,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: Key,
    pub op: Op,
    pub value: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Entry {
    pub fn put(key: Key, value: Vec<u8>, payload: Vec<u8>) -> Self {
        Self {
            key,
            op: Op::Put,
            value,
            payload,
        }
    }

    pub fn delete(key: Key, shape: Shape) -> Self {
        Self {
            key,
            op: Op::Delete,
            value: vec![0; usize::from(shape.value)],
            payload: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub value: u16,
}

impl Shape {
    pub const fn entry(self) -> usize {
        KEY + 1 + self.value as usize + REFERENCE
    }

    pub const fn per_block(self) -> usize {
        (BLOCK - 2 - 4) / self.entry()
    }

    pub fn check(self, entry: &Entry) -> Result<(), Error> {
        if entry.value.len() != usize::from(self.value) {
            return Err(Error::Shape);
        }
        if entry.payload.len() > MAX_PAYLOAD || entry.op == Op::Delete && !entry.payload.is_empty()
        {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference {
    pub offset: u32,
    pub length: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub key: Key,
    pub op: Op,
    pub value: Vec<u8>,
    pub payload: Reference,
}

pub(crate) fn encode(shape: Shape, entry: &Entry, payload: Reference, out: &mut [u8]) {
    let value = usize::from(shape.value);
    out[..KEY].copy_from_slice(&entry.key);
    out[KEY] = match entry.op {
        Op::Put => OP_PUT,
        Op::Delete => OP_DELETE,
    };
    out[KEY + 1..KEY + 1 + value].copy_from_slice(&entry.value);
    let at = KEY + 1 + value;
    out[at..at + 4].copy_from_slice(&payload.offset.to_le_bytes());
    out[at + 4..at + 6].copy_from_slice(&payload.length.to_le_bytes());
}

pub(crate) fn decode(shape: Shape, bytes: &[u8]) -> Result<Found, Error> {
    let value = usize::from(shape.value);
    let op = match bytes[KEY] {
        OP_PUT => Op::Put,
        OP_DELETE => Op::Delete,
        _ => return Err(Error::Corrupt("entry op")),
    };
    let at = KEY + 1 + value;
    Ok(Found {
        key: bytes[..KEY].try_into().expect("key"),
        op,
        value: bytes[KEY + 1..at].to_vec(),
        payload: Reference {
            offset: u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes")),
            length: u16::from_le_bytes(bytes[at + 4..at + 6].try_into().expect("2 bytes")),
        },
    })
}
