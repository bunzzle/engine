use std::cell::RefCell;
use std::rc::Rc;

use rt::Buf;
use store::{
    Claim, Client, CoreFile, Fields, FieldsMut, Header, Lease, Range, checksum, encode, record_size,
};

use crate::error::Error;

pub const KIND_BODY_CHUNK: u8 = 5;
pub(crate) const CHUNK_FIXED: usize = 16;

pub struct Written {
    pub(crate) shard: u16,
    pub(crate) message: u64,
    pub(crate) tenant: u32,
    pub(crate) ranges: Vec<Range>,
    pub(crate) leases: Vec<Rc<Lease>>,
}

impl Written {
    pub(crate) fn new(shard: u16, message: u64, tenant: u32) -> Self {
        Self {
            shard,
            message,
            tenant,
            ranges: Vec::new(),
            leases: Vec::new(),
        }
    }

    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }
}

pub fn decode_chunk(payload: &[u8]) -> Option<(u64, u32, &[u8])> {
    let fields = Fields::new(payload.get(..CHUNK_FIXED)?);
    (fields.u32(12) == 0).then(|| (fields.u64(0), fields.u32(8), &payload[CHUNK_FIXED..]))
}

struct Open {
    lease: Rc<Lease>,
    offset: u64,
}

pub(crate) struct Writer {
    client: Client,
    file: CoreFile,
    open: RefCell<Option<Open>>,
}

impl Writer {
    pub(crate) fn new(client: Client, file: CoreFile) -> Self {
        Self {
            client,
            file,
            open: RefCell::new(None),
        }
    }

    pub(crate) async fn write<C: AsRef<[u8]>>(
        &self,
        shard: u16,
        tenant: u32,
        message: u64,
        chunks: &[C],
    ) -> Result<Written, Error> {
        let mut written = Written::new(shard, message, tenant);
        let mut next = 0;
        while next < chunks.len() {
            next += self.append(&mut written, next, &chunks[next..]).await?;
        }
        Ok(written)
    }

    pub(crate) async fn append<C: AsRef<[u8]>>(
        &self,
        written: &mut Written,
        first: usize,
        chunks: &[C],
    ) -> Result<usize, Error> {
        let sector = u64::from(self.file.sector_size());
        let region_size = self.file.superblock().region_size();
        let sizes: Vec<u64> = chunks
            .iter()
            .map(|c| record_size(CHUNK_FIXED + c.as_ref().len()) as u64)
            .collect();
        let (lease, offset, count) = self.reserve(&sizes, sector, region_size).await?;
        let used: u64 = sizes[..count].iter().sum();
        let length = used.next_multiple_of(sector);
        let len = usize::try_from(length).expect("range fits in memory");
        let mut buf = Buf::aligned(len, self.file.sector_size() as usize);
        buf.set_len(len);
        buf.fill(0);
        let mut at = 0;
        for (n, chunk) in (first..).zip(&chunks[..count]) {
            let chunk = chunk.as_ref();
            let mut payload = vec![0; CHUNK_FIXED + chunk.len()];
            let mut fields = FieldsMut::new(&mut payload);
            fields.put_u64(0, written.message);
            fields.put_u32(8, u32::try_from(n).expect("chunk count fits in u32"));
            payload[CHUNK_FIXED..].copy_from_slice(chunk);
            let header = Header {
                kind: KIND_BODY_CHUNK,
                flags: 0,
                shard: written.shard,
                tenant: written.tenant,
                epoch: lease.epoch(),
                sequence: written.message,
            };
            at += encode(&header, &payload, &mut buf[at..]);
        }
        let range = Range {
            region: lease.region(),
            epoch: lease.epoch(),
            offset,
            length: u32::try_from(length).expect("range fits in a region"),
            checksum: checksum(&buf),
        };
        let (result, _) = self
            .file
            .file()
            .write_all_at(buf, self.file.region_offset(range.region) + offset)
            .await;
        result.map_err(store::Error::from)?;
        written.ranges.push(range);
        if !written.leases.last().is_some_and(|l| Rc::ptr_eq(l, &lease)) {
            written.leases.push(lease);
        }
        Ok(count)
    }

    async fn reserve(
        &self,
        sizes: &[u64],
        sector: u64,
        region_size: u64,
    ) -> Result<(Rc<Lease>, u64, usize), Error> {
        loop {
            if let Some(found) = self.take(sizes, sector, region_size) {
                return Ok(found);
            }
            let lease = self.client.allocate(Claim::Intake).await?;
            if let Some(found) = self.take(sizes, sector, region_size) {
                return Ok(found);
            }
            *self.open.borrow_mut() = Some(Open {
                lease: Rc::new(lease),
                offset: 0,
            });
        }
    }

    fn take(
        &self,
        sizes: &[u64],
        sector: u64,
        region_size: u64,
    ) -> Option<(Rc<Lease>, u64, usize)> {
        let mut open = self.open.borrow_mut();
        let open = open.as_mut()?;
        let room = region_size - open.offset;
        let mut used = 0;
        let count = sizes
            .iter()
            .take_while(|&&size| {
                used += size;
                used.next_multiple_of(sector) <= room
            })
            .count();
        if count == 0 {
            return None;
        }
        let used: u64 = sizes[..count].iter().sum();
        let offset = open.offset;
        open.offset += used.next_multiple_of(sector);
        Some((Rc::clone(&open.lease), offset, count))
    }
}
