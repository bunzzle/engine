use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};

use super::Faults;
use super::rng::{MILLION, Rng};
use crate::driver::OpenOptions;

const TEAR_UNIT: u64 = 512;

#[derive(Clone, Debug, Default)]
struct FileData {
    current: Vec<u8>,
    durable: Vec<u8>,
    dirty: BTreeSet<u64>,
    durable_exists: bool,
}

#[derive(Clone, Debug)]
pub struct Disk {
    files: BTreeMap<PathBuf, FileData>,
    sector_size: u64,
}

fn span(sector: u64, sector_size: u64, len: usize) -> Range<usize> {
    let start = usize::try_from(sector * sector_size)
        .unwrap_or(usize::MAX)
        .min(len);
    let end = usize::try_from((sector + 1) * sector_size)
        .unwrap_or(usize::MAX)
        .min(len);
    start..end
}

fn copy_into(dest: &mut Vec<u8>, at: usize, data: &[u8]) {
    if dest.len() < at + data.len() {
        dest.resize(at + data.len(), 0);
    }
    dest[at..at + data.len()].copy_from_slice(data);
}

impl Disk {
    pub fn new(sector_size: u32) -> Self {
        Self {
            files: BTreeMap::new(),
            sector_size: u64::from(sector_size),
        }
    }

    pub fn sector_size(&self) -> u32 {
        u32::try_from(self.sector_size).unwrap_or(u32::MAX)
    }

    pub fn set_sector_size(&mut self, sector_size: u32) {
        self.sector_size = u64::from(sector_size);
    }

    pub fn exists(&self, path: &Path) -> bool {
        self.files.contains_key(path)
    }

    pub fn contents(&self, path: &Path) -> Option<&[u8]> {
        self.files.get(path).map(|file| file.current.as_slice())
    }

    pub(super) fn open(&mut self, path: &Path, options: &OpenOptions) -> io::Result<()> {
        match self.files.get_mut(path) {
            Some(_) if options.create_new => Err(io::ErrorKind::AlreadyExists.into()),
            Some(file) => {
                if options.truncate {
                    file.current.clear();
                }
                Ok(())
            }
            None if options.create || options.create_new => {
                self.files.insert(path.to_path_buf(), FileData::default());
                Ok(())
            }
            None => Err(io::ErrorKind::NotFound.into()),
        }
    }

    pub(super) fn len(&self, path: &Path) -> u64 {
        self.files
            .get(path)
            .map_or(0, |file| file.current.len() as u64)
    }

    pub(super) fn read(&self, path: &Path, offset: u64, out: &mut [u8]) -> usize {
        let Some(file) = self.files.get(path) else {
            return 0;
        };
        let at = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(file.current.len());
        let n = out.len().min(file.current.len() - at);
        out[..n].copy_from_slice(&file.current[at..at + n]);
        n
    }

    pub(super) fn write(&mut self, path: &Path, offset: u64, data: &[u8]) {
        let sector_size = self.sector_size;
        let Some(file) = self.files.get_mut(path) else {
            return;
        };
        if data.is_empty() {
            return;
        }
        let at = usize::try_from(offset).unwrap_or(usize::MAX);
        copy_into(&mut file.current, at, data);
        let first = offset / sector_size;
        let last = (offset + data.len() as u64 - 1) / sector_size;
        file.dirty.extend(first..=last);
    }

    pub(super) fn allocate(&mut self, path: &Path, len: u64) {
        let sector_size = self.sector_size;
        let Some(file) = self.files.get_mut(path) else {
            return;
        };
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if file.current.len() < len {
            let first = file.current.len() as u64 / sector_size;
            let last = (len as u64).saturating_sub(1) / sector_size;
            file.current.resize(len, 0);
            file.dirty.extend(first..=last);
        }
    }

    pub(super) fn sync(&mut self, path: &Path, rng: &mut Rng, faults: &Faults) -> io::Result<()> {
        let sector_size = self.sector_size;
        let Some(file) = self.files.get_mut(path) else {
            return Err(io::ErrorKind::NotFound.into());
        };
        let dirty = std::mem::take(&mut file.dirty);
        if rng.chance(faults.sync_error) {
            for sector in dirty {
                if rng.chance(MILLION / 2) {
                    let range = span(sector, sector_size, file.current.len());
                    let old = span(sector, sector_size, file.durable.len());
                    let mut restored = vec![0; range.len()];
                    let keep = old.len().min(range.len());
                    restored[..keep].copy_from_slice(&file.durable[old.start..old.start + keep]);
                    file.current[range].copy_from_slice(&restored);
                }
            }
            return Err(io::Error::other("simulated sync failure"));
        }
        file.durable.resize(file.current.len(), 0);
        let sectors = (file.current.len() as u64).div_ceil(sector_size);
        for sector in dirty {
            if rng.chance(faults.lost_write) {
                continue;
            }
            let target = if sectors > 1 && rng.chance(faults.misdirected_write) {
                (sector + 1 + rng.below(sectors - 1)) % sectors
            } else {
                sector
            };
            let from = span(sector, sector_size, file.current.len());
            let to = span(target, sector_size, file.durable.len());
            let n = from.len().min(to.len());
            let data = file.current[from.start..from.start + n].to_vec();
            file.durable[to.start..to.start + n].copy_from_slice(&data);
        }
        Ok(())
    }

    pub(super) fn sync_dir(&mut self, dir: &Path) {
        for (path, file) in &mut self.files {
            if path.parent() == Some(dir) {
                file.durable_exists = true;
            }
        }
    }

    pub(super) fn crash(&mut self, rng: &mut Rng, faults: &Faults) {
        let sector_size = self.sector_size;
        self.files.retain(|_, file| file.durable_exists);
        for file in self.files.values_mut() {
            for sector in std::mem::take(&mut file.dirty) {
                let range = span(sector, sector_size, file.current.len());
                if range.is_empty() {
                    continue;
                }
                let units = (range.len() as u64).div_ceil(TEAR_UNIT);
                let kept = if units > 1 && rng.chance(faults.torn_write) {
                    usize::try_from((1 + rng.below(units - 1)) * TEAR_UNIT).unwrap_or(0)
                } else if rng.chance(faults.crash_keep) {
                    range.len()
                } else {
                    0
                };
                let data = file.current[range.start..range.start + kept].to_vec();
                copy_into(&mut file.durable, range.start, &data);
            }
            file.current.clone_from(&file.durable);
        }
    }
}
