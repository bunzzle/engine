use std::path::PathBuf;
use std::rc::Rc;

use rt::{File, OpenOptions};

use crate::data_file::sector_size;
use crate::error::Error;
use crate::reader::{Pins, Reader};
use crate::superblock::Superblock;

#[derive(Clone)]
pub struct Source {
    path: PathBuf,
    superblock: Superblock,
    pins: Pins,
}

impl Source {
    pub(crate) fn new(path: PathBuf, superblock: Superblock, pins: Pins) -> Self {
        Self {
            path,
            superblock,
            pins,
        }
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    pub async fn open(&self) -> Result<CoreFile, Error> {
        let file = File::open(
            &self.path,
            &OpenOptions {
                read: true,
                write: true,
                ..OpenOptions::default()
            },
        )
        .await?;
        let stat = file.stat().await?;
        let found = sector_size(stat.sector_size)?;
        if found != self.superblock.sector_size() {
            return Err(Error::SectorSizeChanged {
                stored: self.superblock.sector_size(),
                found,
            });
        }
        if stat.len != self.superblock.file_size() {
            return Err(Error::SizeChanged {
                stored: self.superblock.file_size(),
                found: stat.len,
            });
        }
        Ok(CoreFile {
            file: Rc::new(file),
            superblock: self.superblock,
            pins: self.pins.clone(),
        })
    }
}

pub struct CoreFile {
    file: Rc<File>,
    superblock: Superblock,
    pins: Pins,
}

impl CoreFile {
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    pub fn reader(&self) -> Reader {
        Reader::new(Rc::clone(&self.file), &self.superblock, self.pins.clone())
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn sector_size(&self) -> u32 {
        self.superblock.sector_size()
    }

    pub fn region_offset(&self, region: u32) -> u64 {
        self.superblock.region_offset(region)
    }
}
