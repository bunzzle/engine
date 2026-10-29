use std::io;

use rt::Buf;

use crate::crc32c::Hasher;
use crate::data_file::DataFile;
use crate::error::Error;
use crate::journal::{Entry, Journal, Position};
use crate::regions::Regions;
use crate::usage::Usage;

const VERIFY_CHUNK: u64 = 1024 * 1024;

#[derive(Debug)]
pub struct State {
    pub regions: Regions,
    pub epochs: Vec<u64>,
    pub usage: Usage,
    pub record_sequence: u64,
    pub checkpoint: Vec<u32>,
}

impl State {
    pub fn new(count: u32, reserve: u32) -> Self {
        Self {
            regions: Regions::new(count, reserve),
            epochs: vec![0; count as usize],
            usage: Usage::new(count),
            record_sequence: 1,
            checkpoint: Vec::new(),
        }
    }
}

pub struct Recovered {
    pub journal: Journal,
    pub state: State,
    pub entries: Vec<Entry>,
    pub torn: Option<u64>,
}

pub async fn recover(
    data: &DataFile,
    start: Position,
    mut state: State,
) -> Result<Recovered, Error> {
    let count = data.superblock().region_count();
    assert_eq!(state.regions.count(), count, "region count mismatch");
    assert_eq!(state.epochs.len(), count as usize, "epoch count mismatch");
    let scan = Journal::scan(data, start).await?;
    let mut keep = 0;
    let mut torn = None;
    for entry in scan.entries() {
        check(data, &state, entry)?;
        if !intact(data, entry).await? {
            torn = Some(entry.sequence);
            break;
        }
        apply(data, &mut state, entry)?;
        keep += 1;
    }
    let (journal, entries) = scan.finish(data.file(), keep).await?;
    Ok(Recovered {
        journal,
        state,
        entries,
        torn,
    })
}

fn check(data: &DataFile, state: &State, entry: &Entry) -> Result<(), Error> {
    let superblock = data.superblock();
    let sector = u64::from(superblock.sector_size());
    let bad = Error::BadCommit(entry.sequence);
    let commit = &entry.commit;
    if commit.record_sequence < state.record_sequence {
        return Err(bad);
    }
    for (index, allocation) in commit.allocations.iter().enumerate() {
        let valid = allocation.region < superblock.region_count()
            && !state.regions.is_used(allocation.region)
            && allocation.epoch > state.epochs[allocation.region as usize]
            && commit.allocations[..index]
                .iter()
                .all(|a| a.region != allocation.region);
        if !valid {
            return Err(bad);
        }
    }
    for range in &commit.ranges {
        if range.region >= superblock.region_count() {
            return Err(bad);
        }
        let epoch = commit
            .allocations
            .iter()
            .find(|a| a.region == range.region)
            .map(|a| a.epoch)
            .or_else(|| {
                state
                    .regions
                    .is_used(range.region)
                    .then(|| state.epochs[range.region as usize])
            });
        let valid = epoch == Some(range.epoch)
            && range.length > 0
            && range.offset.is_multiple_of(sector)
            && u64::from(range.length).is_multiple_of(sector)
            && range.offset + u64::from(range.length) <= superblock.region_size();
        if !valid {
            return Err(bad);
        }
    }
    Ok(())
}

async fn intact(data: &DataFile, entry: &Entry) -> Result<bool, Error> {
    let file = data.file();
    let align = data.sector_size() as usize;
    for range in &entry.commit.ranges {
        let base = data.region_offset(range.region) + range.offset;
        let length = u64::from(range.length);
        let mut hasher = Hasher::new();
        let mut at = 0;
        while at < length {
            let len = usize::try_from(VERIFY_CHUNK.min(length - at)).expect("chunk fits in usize");
            let (result, buf) = file.read_at(Buf::aligned(len, align), base + at).await;
            if result? != len {
                return Err(Error::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            hasher.update(&buf);
            at += len as u64;
        }
        if hasher.finish() != range.checksum {
            return Ok(false);
        }
    }
    Ok(true)
}

fn apply(data: &DataFile, state: &mut State, entry: &Entry) -> Result<(), Error> {
    let superblock = data.superblock();
    let bad = Error::BadCommit(entry.sequence);
    for allocation in &entry.commit.allocations {
        state.regions.mark_used(allocation.region);
        state.epochs[allocation.region as usize] = allocation.epoch;
    }
    for dead in &entry.commit.dead {
        let valid = dead.region < superblock.region_count()
            && state.regions.is_used(dead.region)
            && state.epochs[dead.region as usize] == dead.epoch
            && dead.length > 0
            && dead
                .offset
                .checked_add(u64::from(dead.length))
                .is_some_and(|end| end <= superblock.region_size());
        if !valid || state.usage.remove(dead).is_none() {
            return Err(bad);
        }
    }
    for live in &entry.commit.live {
        let valid = live.region < superblock.region_count()
            && state.regions.is_used(live.region)
            && live.extents > 0;
        if !valid || state.usage.add(live).is_none() {
            return Err(bad);
        }
    }
    state.record_sequence = entry.commit.record_sequence;
    Ok(())
}
