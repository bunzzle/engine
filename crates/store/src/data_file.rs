use std::path::Path;

use rt::{Buf, File, OpenOptions, sync_dir};

use crate::error::Error;
use crate::superblock::{
    COPIES, Checkpoint, FORMAT, HEADER_SIZE, MAX_SECTOR_SIZE, MIN_SECTOR_SIZE, SLOT_SIZE, Stored,
    Superblock, ZONE_SIZE, select,
};

const FILL_CHUNK: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub journal_size: u64,
    pub region_size: u64,
    pub region_count: u32,
    pub shards: u32,
}

pub struct DataFile {
    file: File,
    superblock: Superblock,
    checksum: u32,
    failed: bool,
}

impl DataFile {
    pub async fn create(path: impl AsRef<Path>, options: &Options) -> Result<Self, Error> {
        if options.region_size == 0 || !options.region_size.is_multiple_of(SLOT_SIZE) {
            return Err(Error::Config(
                "region size must be a non-zero multiple of 64 KiB",
            ));
        }
        if options.journal_size == 0 || !options.journal_size.is_multiple_of(SLOT_SIZE) {
            return Err(Error::Config(
                "journal size must be a non-zero multiple of 64 KiB",
            ));
        }
        if options.region_count == 0 {
            return Err(Error::Config("region count must not be zero"));
        }
        if options.shards == 0 {
            return Err(Error::Config("shard count must not be zero"));
        }
        let regions_offset = ZONE_SIZE + options.journal_size;
        let file_size = u64::from(options.region_count)
            .checked_mul(options.region_size)
            .and_then(|regions| regions.checked_add(regions_offset))
            .and_then(|end| end.checked_add(options.journal_size))
            .ok_or(Error::Config("data file too large"))?;
        let path = path.as_ref();
        let file = File::open(
            path,
            &OpenOptions {
                read: true,
                write: true,
                create_new: true,
                ..OpenOptions::default()
            },
        )
        .await?;
        let sector_size = sector_size(file.stat().await?.sector_size)?;
        file.allocate(file_size).await?;
        zero_fill(&file, file_size, sector_size).await?;
        file.sync_data().await?;
        let superblock = Superblock {
            format: FORMAT,
            oldest_format: FORMAT,
            sector_size,
            sequence: 1,
            parent: 0,
            shards: options.shards,
            file_id: file_id(),
            file_size,
            regions_offset,
            journal_size: options.journal_size,
            region_size: options.region_size,
            region_count: options.region_count,
            checkpoint: None,
        };
        let mut checksum = 0;
        for slot in 0..COPIES {
            checksum = write_copy(&file, &superblock, slot).await?;
        }
        file.sync_data().await?;
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        sync_dir(dir).await?;
        Ok(Self {
            file,
            superblock,
            checksum,
            failed: false,
        })
    }

    pub async fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let file = File::open(
            path,
            &OpenOptions {
                read: true,
                write: true,
                ..OpenOptions::default()
            },
        )
        .await?;
        let stat = file.stat().await?;
        let found = sector_size(stat.sector_size)?;
        let mut copies = [None; COPIES];
        for (slot, copy) in copies.iter_mut().enumerate() {
            *copy = read_copy(&file, slot, found).await;
        }
        let selected = select(&copies)?;
        let superblock = selected.superblock;
        if superblock.format > FORMAT {
            return Err(Error::FormatTooNew(superblock.format));
        }
        superblock.validate()?;
        if superblock.oldest_format < FORMAT.saturating_sub(1).max(1) {
            return Err(Error::FormatTooOld(superblock.oldest_format));
        }
        if superblock.sector_size != found {
            return Err(Error::SectorSizeChanged {
                stored: superblock.sector_size,
                found,
            });
        }
        if stat.len != superblock.file_size {
            return Err(Error::SizeChanged {
                stored: superblock.file_size,
                found: stat.len,
            });
        }
        for &slot in &selected.stale {
            write_copy(&file, &superblock, slot).await?;
            file.sync_data().await?;
        }
        Ok(Self {
            file,
            superblock,
            checksum: selected.checksum,
            failed: false,
        })
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn sector_size(&self) -> u32 {
        self.superblock.sector_size
    }

    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub fn region_offset(&self, region: u32) -> u64 {
        assert!(
            region < self.superblock.region_count,
            "region {region} out of range"
        );
        self.superblock.regions_offset + u64::from(region) * self.superblock.region_size
    }

    pub async fn update(
        &mut self,
        checkpoint: Option<Checkpoint>,
        oldest_format: u16,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        assert!(
            (self.superblock.oldest_format..=FORMAT).contains(&oldest_format),
            "oldest format must not move backwards"
        );
        let previous = self
            .superblock
            .checkpoint
            .map_or(0, |c| c.position.sequence);
        assert!(
            checkpoint.is_some_and(|c| c.position.sequence >= previous)
                || (checkpoint.is_none() && self.superblock.checkpoint.is_none()),
            "checkpoint must not move backwards"
        );
        let next = Superblock {
            format: FORMAT,
            oldest_format,
            sequence: self.superblock.sequence + 1,
            parent: self.checksum,
            checkpoint,
            ..self.superblock
        };
        assert!(next.validate().is_ok(), "checkpoint out of range");
        let mut checksum = 0;
        for slot in 0..COPIES {
            let written = match write_copy(&self.file, &next, slot).await {
                Ok(sum) => self.file.sync_data().await.map(|()| sum),
                Err(e) => Err(e),
            };
            match written {
                Ok(sum) => checksum = sum,
                Err(e) => {
                    self.failed = true;
                    return Err(e.into());
                }
            }
        }
        self.superblock = next;
        self.checksum = checksum;
        Ok(())
    }
}

fn sector_size(reported: u32) -> Result<u32, Error> {
    let size = reported.max(MIN_SECTOR_SIZE);
    if !size.is_power_of_two() || size > MAX_SECTOR_SIZE {
        return Err(Error::UnsupportedSectorSize(reported));
    }
    Ok(size)
}

fn file_id() -> u64 {
    let mut x = rt::wall_ms() ^ rt::now().as_nanos().rotate_left(32);
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn slot_offset(slot: usize) -> u64 {
    SLOT_SIZE * slot as u64
}

async fn zero_fill(file: &File, size: u64, sector_size: u32) -> std::io::Result<()> {
    let chunk = usize::try_from(FILL_CHUNK.min(size)).expect("chunk fits in usize");
    let mut buf = Buf::aligned(chunk, sector_size as usize);
    buf.set_len(chunk);
    let mut offset = 0;
    while offset < size {
        let len = usize::try_from((size - offset).min(FILL_CHUNK)).expect("chunk fits in usize");
        buf.set_len(len);
        let (result, back) = file.write_all_at(buf, offset).await;
        result?;
        buf = back;
        offset += len as u64;
    }
    Ok(())
}

async fn write_copy(file: &File, superblock: &Superblock, slot: usize) -> std::io::Result<u32> {
    let size = superblock.sector_size as usize;
    let mut buf = Buf::aligned(size, size);
    buf.set_len(size);
    let copy = u16::try_from(slot).expect("slot fits in u16");
    let checksum = superblock.encode(copy, &mut buf);
    let (result, _) = file.write_all_at(buf, slot_offset(slot)).await;
    result.map(|()| checksum)
}

async fn read_copy(file: &File, slot: usize, sector_size: u32) -> Option<Stored> {
    let size = (sector_size as usize).max(HEADER_SIZE);
    let buf = Buf::aligned(size, sector_size as usize);
    let (result, buf) = file.read_at(buf, slot_offset(slot)).await;
    match result {
        Ok(n) if n >= HEADER_SIZE => Superblock::decode(&buf),
        _ => None,
    }
}
