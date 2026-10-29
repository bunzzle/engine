use std::fmt;

use crate::layout::{Fields, FieldsMut};
use sys::crc32c::checksum;

pub const RECORD_HEADER_SIZE: usize = 40;
pub const RECORD_ALIGN: usize = 8;
pub const MAX_PAYLOAD: usize = 1024 * 1024;
pub const RECORD_FORMAT: u16 = 2;
pub const SYSTEM_SHARD: u16 = u16::MAX;
pub const FLAG_MORE: u8 = 1;

const OLDEST_RECORD_FORMAT: u16 = 1;
const HEADER_CRC: usize = 0;
const BODY_CRC: usize = 4;
const LENGTH: usize = 8;
const KIND: usize = 12;
const FLAGS: usize = 13;
const FORMAT: usize = 14;
const TENANT: usize = 16;
const EPOCH: usize = 24;
const SHARD: usize = 20;
const RESERVED: usize = 22;
const SEQUENCE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub flags: u8,
    pub shard: u16,
    pub tenant: u32,
    pub epoch: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    Truncated,
    HeaderChecksum,
    TooLarge(u32),
    Format(u16),
    Reserved,
    BodyChecksum,
    Padding,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("record truncated"),
            Self::HeaderChecksum => f.write_str("record header checksum mismatch"),
            Self::TooLarge(length) => write!(f, "record payload of {length} bytes is too large"),
            Self::Format(format) => write!(f, "unsupported record format {format}"),
            Self::Reserved => f.write_str("record reserved bytes are not zero"),
            Self::BodyChecksum => f.write_str("record payload checksum mismatch"),
            Self::Padding => f.write_str("record padding is not zero"),
        }
    }
}

impl std::error::Error for RecordError {}

pub fn record_size(payload: usize) -> usize {
    (RECORD_HEADER_SIZE + payload).next_multiple_of(RECORD_ALIGN)
}

pub fn encode(header: &Header, payload: &[u8], out: &mut [u8]) -> usize {
    assert!(payload.len() <= MAX_PAYLOAD, "payload too large");
    let size = record_size(payload.len());
    let out = &mut out[..size];
    let end = RECORD_HEADER_SIZE + payload.len();
    out[RECORD_HEADER_SIZE..end].copy_from_slice(payload);
    out[end..].fill(0);
    let mut fields = FieldsMut::new(out);
    fields.put_u32(BODY_CRC, checksum(payload));
    fields.put_u32(
        LENGTH,
        u32::try_from(payload.len()).expect("payload fits in u32"),
    );
    fields.put_u8(KIND, header.kind);
    fields.put_u8(FLAGS, header.flags);
    fields.put_u16(FORMAT, RECORD_FORMAT);
    fields.put_u32(TENANT, header.tenant);
    fields.put_u16(SHARD, header.shard);
    fields.put_u16(RESERVED, 0);
    fields.put_u64(EPOCH, header.epoch);
    fields.put_u64(SEQUENCE, header.sequence);
    let sum = checksum(&out[BODY_CRC..RECORD_HEADER_SIZE]);
    FieldsMut::new(out).put_u32(HEADER_CRC, sum);
    size
}

pub fn peek(bytes: &[u8]) -> Result<usize, RecordError> {
    let length = verified_length(bytes)?;
    Ok(record_size(length))
}

pub fn peek_header(bytes: &[u8]) -> Result<Header, RecordError> {
    verified_length(bytes)?;
    let fields = Fields::new(bytes);
    Ok(Header {
        kind: fields.u8(KIND),
        flags: fields.u8(FLAGS),
        shard: shard(&fields),
        tenant: fields.u32(TENANT),
        epoch: fields.u64(EPOCH),
        sequence: fields.u64(SEQUENCE),
    })
}

fn shard(fields: &Fields<'_>) -> u16 {
    if fields.u16(FORMAT) == 1 {
        0
    } else {
        fields.u16(SHARD)
    }
}

fn verified_length(bytes: &[u8]) -> Result<usize, RecordError> {
    if bytes.len() < RECORD_HEADER_SIZE {
        return Err(RecordError::Truncated);
    }
    let fields = Fields::new(bytes);
    if fields.u32(HEADER_CRC) != checksum(&bytes[BODY_CRC..RECORD_HEADER_SIZE]) {
        return Err(RecordError::HeaderChecksum);
    }
    let length = fields.u32(LENGTH);
    let format = fields.u16(FORMAT);
    if !(OLDEST_RECORD_FORMAT..=RECORD_FORMAT).contains(&format) {
        return Err(RecordError::Format(format));
    }
    let reserved = if format == 1 {
        fields.u32(SHARD) != 0
    } else {
        fields.u16(RESERVED) != 0
    };
    if reserved {
        return Err(RecordError::Reserved);
    }
    match usize::try_from(length) {
        Ok(length) if length <= MAX_PAYLOAD => Ok(length),
        _ => Err(RecordError::TooLarge(length)),
    }
}

pub fn rebase(bytes: &mut [u8], tenant: u32, from: u64, to: u64) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        let size = match Record::decode(&bytes[at..]) {
            Ok(record) if record.tenant() == tenant && record.epoch() == from => record.size(),
            Ok(_) => return false,
            Err(_) => return at > 0 && bytes[at..].iter().all(|&b| b == 0),
        };
        let header = &mut bytes[at..at + RECORD_HEADER_SIZE];
        FieldsMut::new(header).put_u64(EPOCH, to);
        let sum = checksum(&header[BODY_CRC..]);
        FieldsMut::new(header).put_u32(HEADER_CRC, sum);
        at += size;
    }
    at > 0
}

#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    bytes: &'a [u8],
}

impl<'a> Record<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, RecordError> {
        let length = verified_length(bytes)?;
        let end = RECORD_HEADER_SIZE + length;
        if bytes.len() < end {
            return Err(RecordError::Truncated);
        }
        let payload = &bytes[RECORD_HEADER_SIZE..end];
        if Fields::new(bytes).u32(BODY_CRC) != checksum(payload) {
            return Err(RecordError::BodyChecksum);
        }
        let padded = record_size(length).min(bytes.len());
        if bytes[end..padded].iter().any(|&b| b != 0) {
            return Err(RecordError::Padding);
        }
        Ok(Self {
            bytes: &bytes[..end],
        })
    }

    pub fn header(&self) -> Header {
        Header {
            kind: self.kind(),
            flags: self.flags(),
            shard: self.shard(),
            tenant: self.tenant(),
            epoch: self.epoch(),
            sequence: self.sequence(),
        }
    }

    pub fn checksum(&self) -> u32 {
        self.fields().u32(HEADER_CRC)
    }

    pub fn shard(&self) -> u16 {
        shard(&self.fields())
    }

    pub fn kind(&self) -> u8 {
        self.fields().u8(KIND)
    }

    pub fn flags(&self) -> u8 {
        self.fields().u8(FLAGS)
    }

    pub fn format(&self) -> u16 {
        self.fields().u16(FORMAT)
    }

    pub fn tenant(&self) -> u32 {
        self.fields().u32(TENANT)
    }

    pub fn epoch(&self) -> u64 {
        self.fields().u64(EPOCH)
    }

    pub fn sequence(&self) -> u64 {
        self.fields().u64(SEQUENCE)
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[RECORD_HEADER_SIZE..]
    }

    pub fn has_more(&self) -> bool {
        self.flags() & FLAG_MORE != 0
    }

    pub fn size(&self) -> usize {
        record_size(self.payload().len())
    }

    fn fields(&self) -> Fields<'a> {
        Fields::new(self.bytes)
    }
}

#[derive(Clone, Debug)]
pub struct Chunks<'a> {
    rest: &'a [u8],
    started: bool,
}

pub fn chunks(value: &[u8]) -> Chunks<'_> {
    Chunks {
        rest: value,
        started: false,
    }
}

impl<'a> Iterator for Chunks<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.started && self.rest.is_empty() {
            return None;
        }
        self.started = true;
        let (head, tail) = self.rest.split_at(self.rest.len().min(MAX_PAYLOAD));
        self.rest = tail;
        let flags = if tail.is_empty() { 0 } else { FLAG_MORE };
        Some((flags, head))
    }
}
