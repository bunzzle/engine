use store::{INDEX_SIZE, MAX_PAYLOAD, RECORD_HEADER_SIZE, fits};

use crate::error::Error;

const ADDRESS_MAX: usize = 256;
const ORCPT_MAX: usize = 500;
const RECIPIENT_FIXED: usize = 8;
const QUEUE_ID: usize = 4;
const SEAL_OVERHEAD: usize = 64;

pub const SLICE: u32 = slice_size();

#[allow(clippy::cast_possible_truncation)]
const fn slice_size() -> u32 {
    let room = MAX_PAYLOAD - INDEX_SIZE - 4 - SEAL_OVERHEAD;
    let per = ADDRESS_MAX + ORCPT_MAX + RECIPIENT_FIXED + QUEUE_ID;
    (room / per) as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub recipients: u32,
    pub inline: usize,
    pub body: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            recipients: 1000,
            inline: 4096,
            body: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Bounds {
    pub(crate) chunk: usize,
    pub(crate) ranges: usize,
}

impl Limits {
    pub(crate) fn slices(&self) -> usize {
        self.recipients.div_ceil(SLICE) as usize
    }

    pub fn validate(&self, region_size: u64) -> Result<(), Error> {
        self.check(region_size).map(drop)
    }

    pub(crate) fn check(&self, region_size: u64) -> Result<Bounds, Error> {
        let half = usize::try_from(region_size / 2).map_err(|_| Error::Limit("region"))?;
        let chunk = half
            .min(MAX_PAYLOAD)
            .checked_sub(RECORD_HEADER_SIZE + crate::bodies::CHUNK_FIXED)
            .ok_or(Error::Limit("region"))?;
        let ranges = usize::try_from(self.body.div_ceil(region_size / 2))
            .map_err(|_| Error::Limit("body"))?
            + 1;
        if self.inline > MAX_PAYLOAD - INDEX_SIZE {
            return Err(Error::Limit("inline"));
        }
        if self.recipients == 0 {
            return Err(Error::Limit("recipients"));
        }
        let dead = 2 + self.slices() + self.recipients as usize + ranges;
        if !fits(1, 1, 0, dead) {
            return Err(Error::Limit("recipients"));
        }
        Ok(Bounds { chunk, ranges })
    }
}
