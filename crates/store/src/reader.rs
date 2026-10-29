use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use rt::{Buf, File};

use crate::committer::Location;
use crate::error::Error;
use crate::record::{Record, record_size};

pub const READ_ATTEMPTS: u32 = 4;

#[derive(Clone, Default)]
pub struct Pins(Rc<RefCell<BTreeMap<u32, u32>>>);

impl Pins {
    pub fn pin(&self, region: u32) -> Pin {
        *self.0.borrow_mut().entry(region).or_default() += 1;
        Pin {
            pins: self.clone(),
            region,
        }
    }

    pub fn is_pinned(&self, region: u32) -> bool {
        self.0.borrow().contains_key(&region)
    }
}

pub struct Pin {
    pins: Pins,
    region: u32,
}

impl Drop for Pin {
    fn drop(&mut self) {
        let mut pins = self.pins.0.borrow_mut();
        if let Some(count) = pins.get_mut(&self.region) {
            *count -= 1;
            if *count == 0 {
                pins.remove(&self.region);
            }
        }
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
    pub(crate) fn new(
        file: Rc<File>,
        regions_offset: u64,
        region_size: u64,
        region_count: u32,
        pins: Pins,
    ) -> Self {
        Self {
            file,
            regions_offset,
            region_size,
            region_count,
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
