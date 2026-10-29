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

    pub(crate) async fn write(
        &self,
        shard: u16,
        tenant: u32,
        message: u64,
        chunks: &[Vec<u8>],
    ) -> Result<Written, Error> {
        let sector = u64::from(self.file.sector_size());
        let region_size = self.file.superblock().region_size();
        let sizes: Vec<u64> = chunks
            .iter()
            .map(|c| record_size(CHUNK_FIXED + c.len()) as u64)
            .collect();
        let mut written = Written {
            shard,
            message,
            tenant,
            ranges: Vec::new(),
            leases: Vec::new(),
        };
        let mut next = 0;
        while next < chunks.len() {
            let (lease, offset, end) = self.reserve(&sizes[next..], sector, region_size).await?;
            let count = end;
            let used: u64 = sizes[next..next + count].iter().sum();
            let length = used.next_multiple_of(sector);
            let len = usize::try_from(length).expect("range fits in memory");
            let mut buf = Buf::aligned(len, self.file.sector_size() as usize);
            buf.set_len(len);
            buf.fill(0);
            let mut at = 0;
            for (n, chunk) in (next..next + count).zip(&chunks[next..next + count]) {
                let mut payload = vec![0; CHUNK_FIXED + chunk.len()];
                let mut fields = FieldsMut::new(&mut payload);
                fields.put_u64(0, message);
                fields.put_u32(8, u32::try_from(n).expect("chunk count fits in u32"));
                payload[CHUNK_FIXED..].copy_from_slice(chunk);
                let header = Header {
                    kind: KIND_BODY_CHUNK,
                    flags: 0,
                    shard,
                    tenant,
                    epoch: lease.epoch(),
                    sequence: message,
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
            written.leases.push(lease);
            next += count;
        }
        Ok(written)
    }

    async fn reserve(
        &self,
        sizes: &[u64],
        sector: u64,
        region_size: u64,
    ) -> Result<(Rc<Lease>, u64, usize), Error> {
        loop {
            if let Some(open) = self.open.borrow_mut().as_mut() {
                let room = region_size - open.offset;
                let mut used = 0;
                let count = sizes
                    .iter()
                    .take_while(|&&size| {
                        used += size;
                        used.next_multiple_of(sector) <= room
                    })
                    .count();
                if count > 0 {
                    let used: u64 = sizes[..count].iter().sum();
                    let offset = open.offset;
                    open.offset += used.next_multiple_of(sector);
                    return Ok((Rc::clone(&open.lease), offset, count));
                }
            }
            let lease = self.client.allocate(Claim::Intake).await?;
            *self.open.borrow_mut() = Some(Open {
                lease: Rc::new(lease),
                offset: 0,
            });
        }
    }
}
