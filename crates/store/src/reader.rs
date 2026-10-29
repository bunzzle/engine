use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use rt::{Buf, File};

use crate::committer::Location;
use crate::error::Error;
use crate::record::{Record, record_size};
use crate::superblock::Superblock;

pub const READ_ATTEMPTS: u32 = 4;

#[derive(Clone)]
pub struct Pins(Arc<[AtomicU32]>);

impl Pins {
    pub(crate) fn new(count: u32) -> Self {
        Self((0..count).map(|_| AtomicU32::new(0)).collect())
    }

    pub fn pin(&self, region: u32) -> Pin {
        self.0[region as usize].fetch_add(1, Ordering::AcqRel);
        Pin {
            pins: self.clone(),
            region,
        }
    }

    pub fn is_pinned(&self, region: u32) -> bool {
        self.0[region as usize].load(Ordering::Acquire) > 0
    }
}

pub struct Pin {
    pins: Pins,
    region: u32,
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.pins.0[self.region as usize].fetch_sub(1, Ordering::AcqRel);
    }
}

pub trait Owner {
    fn locate(&self, location: Location) -> impl Future<Output = Option<Location>>;
}

pub struct Reader {
    file: Rc<File>,
    regions_offset: u64,
    region_size: u64,
    region_count: u32,
    pins: Pins,
}

impl Reader {
    pub(crate) fn new(file: Rc<File>, superblock: &Superblock, pins: Pins) -> Self {
        Self {
            file,
            regions_offset: superblock.regions_offset(),
            region_size: superblock.region_size(),
            region_count: superblock.region_count(),
            pins,
        }
    }

    pub fn pins(&self) -> &Pins {
        &self.pins
    }

    pub async fn read(
        &self,
        location: Location,
        tenant: u32,
        owner: &impl Owner,
    ) -> Result<Buf, Error> {
        let mut at = location;
        for _ in 0..READ_ATTEMPTS {
            if let Some(buf) = self.read_once(at, tenant).await {
                return Ok(buf);
            }
            match owner.locate(at).await {
                Some(next) => at = next,
                None => return Err(Error::NotFound),
            }
        }
        Err(Error::Damaged {
            region: at.region,
            offset: at.offset,
        })
    }

    async fn read_once(&self, at: Location, tenant: u32) -> Option<Buf> {
        let size = u64::from(at.size);
        if at.region >= self.region_count || at.offset.checked_add(size)? > self.region_size {
            return None;
        }
        let _pin = self.pins.pin(at.region);
        let offset = self.regions_offset + u64::from(at.region) * self.region_size + at.offset;
        let len = usize::try_from(at.size).ok()?;
        let (read, buf) = self.file.read_at(Buf::new(len), offset).await;
        if read.ok()? != len {
            return None;
        }
        let record = Record::decode(&buf).ok()?;
        let header = record.header();
        let matches = header.tenant == tenant
            && header.epoch == at.epoch
            && header.sequence == at.sequence
            && record_size(record.payload().len()) == len;
        matches.then_some(buf)
    }
}
