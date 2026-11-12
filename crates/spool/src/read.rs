use store::{
    Crc32c, HEAD_ITEM, Index, Key, Location, Pin, RECORD_HEADER_SIZE, Range, Record, peek,
};

use crate::bodies::{KIND_BODY_CHUNK, decode_chunk};
use crate::error::Error;
use crate::intake::{MessageId, Spool};
use crate::items::{BODY_ITEM, HeadClear, WRAP, head_parts};
use crate::pending::Fixed;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredBody {
    Inline(Location),
    Chain(Box<[Range]>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub id: MessageId,
    pub tenant: u32,
    pub clear: HeadClear,
    pub head: Location,
    pub body: StoredBody,
}

pub struct Opened {
    pub wrap: [u8; WRAP],
    pub head: Vec<u8>,
    pub body: Source,
    pub pins: Pinned,
}

pub struct Pinned {
    _pins: Vec<Pin>,
}

pub enum Source {
    Inline(Vec<u8>),
    Chain(Chunks),
}

pub struct Chunks {
    spool: Spool,
    tenant: u32,
    message: u64,
    ranges: Box<[Range]>,
    range: usize,
    at: u32,
    crc: Crc32c,
    held: Vec<u8>,
    next: u32,
}

fn damaged(range: &Range) -> Error {
    Error::Store(store::Error::Damaged {
        region: range.region,
        offset: range.offset,
    })
}

impl Spool {
    pub async fn stored(&self, id: MessageId) -> Result<Stored, Error> {
        let keys = vec![Key::new(id.key, HEAD_ITEM), Key::new(id.key, BODY_ITEM)];
        let mut items = self.inner.changes.items(id.shard, keys).await?.into_iter();
        let (Some(Some(head)), Some(Some(body))) = (items.next(), items.next()) else {
            return Err(Error::State("message"));
        };
        let clear = HeadClear::decode(&head.clear).ok_or(Error::State("head"))?;
        if body.tenant != head.tenant {
            return Err(Error::State("body"));
        }
        let body = if body.bodies.is_empty() {
            StoredBody::Inline(body.location)
        } else {
            StoredBody::Chain(body.bodies)
        };
        Ok(Stored {
            id,
            tenant: head.tenant,
            clear,
            head: head.location,
            body,
        })
    }

    pub async fn open_stored(&self, stored: &Stored) -> Result<Opened, Error> {
        let pins = self.inner.reader.pins();
        let mut pinned = vec![pins.pin(stored.head.region)];
        match &stored.body {
            StoredBody::Inline(at) => pinned.push(pins.pin(at.region)),
            StoredBody::Chain(ranges) => pinned.extend(ranges.iter().map(|r| pins.pin(r.region))),
        }
        let region = self.sealed(stored.head, stored.tenant).await?;
        let (wrap, head) = head_parts(&region).ok_or(Error::State("head"))?;
        let (wrap, head) = (*wrap, head.to_vec());
        let body = match &stored.body {
            StoredBody::Inline(at) => Source::Inline(self.sealed(*at, stored.tenant).await?),
            StoredBody::Chain(ranges) => Source::Chain(Chunks {
                spool: self.clone(),
                tenant: stored.tenant,
                message: stored.id.key,
                ranges: ranges.clone(),
                range: 0,
                at: 0,
                crc: Crc32c::new(),
                held: Vec::new(),
                next: 0,
            }),
        };
        Ok(Opened {
            wrap,
            head,
            body,
            pins: Pinned { _pins: pinned },
        })
    }

    async fn sealed(&self, at: Location, tenant: u32) -> Result<Vec<u8>, Error> {
        let buf = self.inner.reader.read(at, tenant, &Fixed).await?;
        let record = Record::decode(&buf).map_err(|_| Error::State("record"))?;
        let parts = Index::parts(record.payload()).ok_or(Error::State("record"))?;
        Ok(parts.sealed.to_vec())
    }
}

impl Chunks {
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, Error> {
        loop {
            let Some(&range) = self.ranges.get(self.range) else {
                return Ok(None);
            };
            if let Some(chunk) = self.take(&range)? {
                return Ok(Some(chunk));
            }
            if self.at == range.length {
                if self.crc.finish() != range.checksum || self.held.iter().any(|&b| b != 0) {
                    return Err(damaged(&range));
                }
                self.range += 1;
                self.at = 0;
                self.crc = Crc32c::new();
                self.held.clear();
                continue;
            }
            let len = self.spool.inner.limits.read.min(range.length - self.at);
            let buf = self.spool.inner.reader.part(range, self.at, len).await?;
            self.crc.update(&buf);
            self.held.extend_from_slice(&buf);
            self.at += len;
        }
    }

    fn take(&mut self, range: &Range) -> Result<Option<Vec<u8>>, Error> {
        if self.held.len() < RECORD_HEADER_SIZE {
            return Ok(None);
        }
        if self.held[..RECORD_HEADER_SIZE].iter().all(|&b| b == 0) {
            return Ok(None);
        }
        let size = peek(&self.held).map_err(|_| damaged(range))?;
        if self.held.len() < size {
            return Ok(None);
        }
        let record = Record::decode(&self.held[..size]).map_err(|_| damaged(range))?;
        let fits = record.kind() == KIND_BODY_CHUNK
            && record.tenant() == self.tenant
            && record.epoch() == range.epoch;
        let chunk = decode_chunk(record.payload())
            .filter(|&(message, n, _)| fits && message == self.message && n == self.next)
            .map(|(_, _, sealed)| sealed.to_vec())
            .ok_or_else(|| damaged(range))?;
        self.next += 1;
        self.held.drain(..size);
        Ok(Some(chunk))
    }
}
