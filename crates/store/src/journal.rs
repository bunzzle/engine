use std::collections::VecDeque;

use rt::{Buf, File};

use crate::data_file::DataFile;
use crate::error::Error;
use crate::layout::{Fields, FieldsMut};
use crate::record::{self, Header, MAX_PAYLOAD, Record, record_size};

pub const KIND_COMMIT: u8 = 1;

const FIXED: usize = 8;
const RANGE: usize = 32;
const ALLOCATION: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub region: u32,
    pub epoch: u64,
    pub offset: u64,
    pub length: u32,
    pub checksum: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    pub region: u32,
    pub epoch: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Commit {
    pub ranges: Vec<Range>,
    pub allocations: Vec<Allocation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub offset: u64,
    pub sequence: u64,
    pub previous: u32,
}

impl Position {
    pub const START: Self = Self {
        offset: 0,
        sequence: 1,
        previous: 0,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub sequence: u64,
    pub checksum: u32,
    pub commit: Commit,
}

pub struct Journal {
    rings: [u64; 2],
    size: u64,
    sector: u64,
    next: Position,
    used: u64,
    pending: VecDeque<(u64, u64)>,
    failed: bool,
}

impl Journal {
    pub async fn recover(data: &DataFile, start: Position) -> Result<(Self, Vec<Entry>), Error> {
        let superblock = data.superblock();
        let mut journal = Self {
            rings: superblock.journal_offsets(),
            size: superblock.journal_size(),
            sector: u64::from(superblock.sector_size()),
            next: start,
            used: 0,
            pending: VecDeque::new(),
            failed: false,
        };
        assert!(
            start.offset < journal.size && start.offset.is_multiple_of(journal.sector),
            "journal start out of range"
        );
        let mut entries = Vec::new();
        loop {
            let at = journal.next.offset;
            let (found, waste) = match journal.read(data.file(), at).await? {
                Some(found) => (found, 0),
                None if at != 0 => match journal.read(data.file(), 0).await? {
                    Some(found) => (found, journal.size - at),
                    None => break,
                },
                None => break,
            };
            let (entry, bytes) = found;
            let offset = if waste > 0 { 0 } else { at };
            journal.advance(offset, bytes, waste, entry.checksum);
            entries.push(entry);
        }
        Ok((journal, entries))
    }

    pub fn position(&self) -> Position {
        self.next
    }

    pub fn free(&self) -> u64 {
        self.size - self.used
    }

    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub async fn append(&mut self, file: &File, commit: &Commit) -> Result<Position, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let payload = encode_commit(self.next.previous, commit)?;
        let bytes = (record_size(payload.len()) as u64).next_multiple_of(self.sector);
        let (offset, waste) = if self.next.offset + bytes > self.size {
            (0, self.size - self.next.offset)
        } else {
            (self.next.offset, 0)
        };
        if bytes > self.size || self.used + waste + bytes > self.size {
            return Err(Error::JournalFull);
        }
        let len = usize::try_from(bytes).expect("commit fits in memory");
        let align = usize::try_from(self.sector).expect("sector fits in usize");
        let mut buf = Buf::aligned(len, align);
        buf.set_len(len);
        let header = Header {
            kind: KIND_COMMIT,
            flags: 0,
            tenant: 0,
            epoch: 0,
            sequence: self.next.sequence,
        };
        record::encode(&header, &payload, &mut buf);
        let checksum = Fields::new(&buf).u32(0);
        let written = self.position();
        for ring in self.rings {
            let (result, back) = file.write_all_at(buf, ring + offset).await;
            buf = back;
            if let Err(e) = result {
                self.failed = true;
                return Err(e.into());
            }
        }
        self.advance(offset, bytes, waste, checksum);
        Ok(Position { offset, ..written })
    }

    pub fn release(&mut self, through: u64) {
        while let Some(&(sequence, bytes)) = self.pending.front() {
            if sequence > through {
                break;
            }
            self.used -= bytes;
            self.pending.pop_front();
        }
    }

    fn advance(&mut self, offset: u64, bytes: u64, waste: u64, checksum: u32) {
        self.used += waste + bytes;
        self.pending.push_back((self.next.sequence, waste + bytes));
        self.next = Position {
            offset: (offset + bytes) % self.size,
            sequence: self.next.sequence + 1,
            previous: checksum,
        };
    }

    async fn read(&self, file: &File, offset: u64) -> Result<Option<(Entry, u64)>, Error> {
        for ring in self.rings {
            if let Some(found) = self.read_ring(file, ring, offset).await? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    async fn read_ring(
        &self,
        file: &File,
        ring: u64,
        offset: u64,
    ) -> Result<Option<(Entry, u64)>, Error> {
        let align = usize::try_from(self.sector).expect("sector fits in usize");
        let Some(first) = read_exact(file, ring + offset, align, align).await else {
            return Ok(None);
        };
        let Ok(size) = record::peek(&first) else {
            return Ok(None);
        };
        let bytes = (size as u64).next_multiple_of(self.sector);
        if offset + bytes > self.size {
            return Ok(None);
        }
        let full = if size <= first.len() {
            first
        } else {
            let len = usize::try_from(bytes).expect("commit fits in memory");
            match read_exact(file, ring + offset, len, align).await {
                Some(full) => full,
                None => return Ok(None),
            }
        };
        let Ok(found) = Record::decode(&full) else {
            return Ok(None);
        };
        if found.kind() != KIND_COMMIT || found.sequence() != self.next.sequence {
            return Ok(None);
        }
        let (previous, commit) = decode_commit(found.payload())?;
        if previous != self.next.previous {
            return Ok(None);
        }
        let entry = Entry {
            sequence: found.sequence(),
            checksum: found.checksum(),
            commit,
        };
        Ok(Some((entry, bytes)))
    }
}

async fn read_exact(file: &File, offset: u64, len: usize, align: usize) -> Option<Buf> {
    let (result, buf) = file.read_at(Buf::aligned(len, align), offset).await;
    match result {
        Ok(n) if n == len => Some(buf),
        _ => None,
    }
}

fn encode_commit(previous: u32, commit: &Commit) -> Result<Vec<u8>, Error> {
    let size = FIXED + commit.ranges.len() * RANGE + commit.allocations.len() * ALLOCATION;
    if size > MAX_PAYLOAD {
        return Err(Error::CommitTooLarge);
    }
    let ranges = u16::try_from(commit.ranges.len()).map_err(|_| Error::CommitTooLarge)?;
    let allocations = u16::try_from(commit.allocations.len()).map_err(|_| Error::CommitTooLarge)?;
    let mut out = vec![0u8; size];
    let mut fields = FieldsMut::new(&mut out);
    fields.put_u32(0, previous);
    fields.put_u16(4, ranges);
    fields.put_u16(6, allocations);
    let mut at = FIXED;
    for range in &commit.ranges {
        fields.put_u32(at, range.region);
        fields.put_u32(at + 4, range.length);
        fields.put_u64(at + 8, range.epoch);
        fields.put_u64(at + 16, range.offset);
        fields.put_u32(at + 24, range.checksum);
        at += RANGE;
    }
    for allocation in &commit.allocations {
        fields.put_u32(at, allocation.region);
        fields.put_u64(at + 8, allocation.epoch);
        at += ALLOCATION;
    }
    Ok(out)
}

fn decode_commit(payload: &[u8]) -> Result<(u32, Commit), Error> {
    if payload.len() < FIXED {
        return Err(Error::Invalid("commit record"));
    }
    let fields = Fields::new(payload);
    let ranges = usize::from(fields.u16(4));
    let allocations = usize::from(fields.u16(6));
    if payload.len() != FIXED + ranges * RANGE + allocations * ALLOCATION {
        return Err(Error::Invalid("commit record"));
    }
    let mut commit = Commit {
        ranges: Vec::with_capacity(ranges),
        allocations: Vec::with_capacity(allocations),
    };
    let mut at = FIXED;
    for _ in 0..ranges {
        commit.ranges.push(Range {
            region: fields.u32(at),
            length: fields.u32(at + 4),
            epoch: fields.u64(at + 8),
            offset: fields.u64(at + 16),
            checksum: fields.u32(at + 24),
        });
        at += RANGE;
    }
    for _ in 0..allocations {
        commit.allocations.push(Allocation {
            region: fields.u32(at),
            epoch: fields.u64(at + 8),
        });
        at += ALLOCATION;
    }
    Ok((fields.u32(0), commit))
}
