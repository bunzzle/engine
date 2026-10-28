mod crc32c;
mod data_file;
mod error;
mod layout;
mod record;
mod regions;
mod superblock;

pub use crc32c::checksum;
pub use data_file::{DataFile, Options};
pub use error::Error;
pub use layout::{Fields, FieldsMut};
pub use record::{
    FLAG_MORE, Header, MAX_PAYLOAD, RECORD_ALIGN, RECORD_FORMAT, RECORD_HEADER_SIZE, Record,
    RecordError, chunks, encode, peek, record_size,
};
pub use regions::{Claim, Regions};
pub use superblock::{
    COPIES, Checkpoint, FORMAT, MAX_SECTOR_SIZE, MIN_SECTOR_SIZE, SLOT_SIZE, Superblock, ZONE_SIZE,
};
