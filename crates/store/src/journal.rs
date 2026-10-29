use std::collections::VecDeque;
use std::io;

use rt::{Buf, File};

use crate::data_file::DataFile;
use crate::error::Error;
use crate::layout::{Fields, FieldsMut};
use crate::record::{self, Header, MAX_PAYLOAD, Record, record_size};

pub const KIND_COMMIT: u8 = 1;

const FIXED: usize = 16;
const SCAN_CHUNK: u64 = 1024 * 1024;
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
    pub record_sequence: u64,
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
        let scan = Self::scan(data, start).await?;
        let keep = scan.found.len();
        scan.finish(data.file(), keep).await
    }

    pub(crate) async fn scan(data: &DataFile, start: Position) -> Result<Scan, Error> {
        let superblock = data.superblock();
        let journal = Self {
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
        let file = data.file();
        let mut next = start;
        let mut walked = Vec::new();
        loop {
            let mut found = journal
                .candidates(file, next.offset, next.sequence, next.previous)
                .await?;
            let pick = match found.len() {
                0 => break,
                1 => found.pop().expect("one candidate"),
                _ => {
                    let mut chained = Vec::new();
                    for candidate in found {
                        let after = (candidate.offset + candidate.bytes) % journal.size;
                        let successors = journal
                            .candidates(file, after, next.sequence + 1, candidate.entry.checksum)
                            .await?;
                        if !successors.is_empty() {
                            chained.push(candidate);
                        }
                    }
                    if chained.len() != 1 {
                        return Err(Error::JournalFork);
                    }
                    chained.pop().expect("one chained candidate")
                }
            };
            next = Position {
                offset: (pick.offset + pick.bytes) % journal.size,
                sequence: next.sequence + 1,
                previous: pick.entry.checksum,
            };
            walked.push(pick);
        }
        Ok(Scan {
            journal,
            found: walked,
        })
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

    pub fn reserve(&self, commit: &Commit) -> Result<(), Error> {
        let bytes = self.bytes(commit_payload_size(commit)?);
        self.place(bytes).map(|_| ())
    }

    pub async fn append(&mut self, file: &File, commit: &Commit) -> Result<Position, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let payload = encode_commit(self.next.previous, commit)?;
        let bytes = self.bytes(payload.len());
        let (offset, waste) = self.place(bytes)?;
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

    fn bytes(&self, payload: usize) -> u64 {
        (record_size(payload) as u64).next_multiple_of(self.sector)
    }

    fn place(&self, bytes: u64) -> Result<(u64, u64), Error> {
        let (offset, waste) = if self.next.offset + bytes > self.size {
            (0, self.size - self.next.offset)
        } else {
            (self.next.offset, 0)
        };
        if bytes > self.size || self.used + waste + bytes > self.size {
            return Err(Error::JournalFull);
        }
        Ok((offset, waste))
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

    async fn newer(&self, file: &File, sequence: u64) -> Result<Option<u64>, Error> {
        let align = usize::try_from(self.sector).expect("sector fits in usize");
        let chunk = SCAN_CHUNK.min(self.size);
        for ring in self.rings {
            let mut at = 0;
            while at < self.size {
                let len = usize::try_from(chunk.min(self.size - at)).expect("chunk fits in usize");
                let Some(buf) = read_exact(file, ring + at, len, align).await? else {
                    return Err(Error::Io(io::ErrorKind::UnexpectedEof.into()));
                };
                for offset in (0..len).step_by(align) {
                    if let Ok(header) = record::peek_header(&buf[offset..])
                        && header.kind == KIND_COMMIT
                        && header.sequence > sequence
                    {
                        return Ok(Some(header.sequence));
                    }
                }
                at += len as u64;
            }
        }
        Ok(None)
    }

    async fn candidates(
        &self,
        file: &File,
        at: u64,
        sequence: u64,
        previous: u32,
    ) -> Result<Vec<Found>, Error> {
        let mut places = vec![(at, 0)];
        if at != 0 {
            places.push((0, self.size - at));
        }
        let mut found: Vec<Found> = Vec::new();
        for (offset, waste) in places {
            for (index, ring) in self.rings.iter().enumerate() {
                let Some((entry, bytes, raw)) = self
                    .read_ring(file, ring + offset, offset, sequence, previous)
                    .await?
                else {
                    continue;
                };
                if waste > 0 && at + bytes <= self.size {
                    continue;
                }
                if let Some(same) = found
                    .iter_mut()
                    .find(|f| f.offset == offset && f.entry.checksum == entry.checksum)
                {
                    same.rings[index] = true;
                } else {
                    let mut rings = [false; 2];
                    rings[index] = true;
                    found.push(Found {
                        entry,
                        bytes,
                        offset,
                        waste,
                        rings,
                        raw,
                    });
                }
            }
        }
        Ok(found)
    }

    async fn read_ring(
        &self,
        file: &File,
        at: u64,
        offset: u64,
        sequence: u64,
        previous: u32,
    ) -> Result<Option<(Entry, u64, Vec<u8>)>, Error> {
        let align = usize::try_from(self.sector).expect("sector fits in usize");
        let Some(first) = read_exact(file, at, align, align).await? else {
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
            match read_exact(file, at, len, align).await? {
                Some(full) => full,
                None => return Ok(None),
            }
        };
        let Ok(found) = Record::decode(&full) else {
            return Ok(None);
        };
        if found.kind() != KIND_COMMIT || found.sequence() != sequence {
            return Ok(None);
        }
        let Some((before, commit)) = decode_commit(found.payload()) else {
            return Ok(None);
        };
        if before != previous {
            return Ok(None);
        }
        let entry = Entry {
            sequence,
            checksum: found.checksum(),
            commit,
        };
        let len = usize::try_from(bytes).expect("commit fits in memory");
        Ok(Some((entry, bytes, full[..len.min(full.len())].to_vec())))
    }
}

pub(crate) struct Scan {
    journal: Journal,
    found: Vec<Found>,
}

impl Scan {
    pub(crate) fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.found.iter().map(|found| &found.entry)
    }

    pub(crate) async fn finish(
        self,
        file: &File,
        keep: usize,
    ) -> Result<(Journal, Vec<Entry>), Error> {
        let Self { mut journal, found } = self;
        assert!(keep <= found.len(), "cannot keep more than was found");
        if let Some(newer) = found.get(keep + 1) {
            return Err(Error::Lost {
                sequence: found[keep].entry.sequence,
                newer: newer.entry.sequence,
            });
        }
        let end = journal.next.sequence + keep as u64;
        if let Some(newer) = journal.newer(file, end).await? {
            return Err(Error::Lost {
                sequence: end,
                newer,
            });
        }
        let sector = usize::try_from(journal.sector).expect("sector fits in usize");
        let mut writes = Vec::new();
        let mut entries = Vec::with_capacity(keep);
        let mut found = found.into_iter();
        for pick in found.by_ref().take(keep) {
            for (ring, present) in journal.rings.iter().zip(pick.rings) {
                if !present {
                    writes.push((ring + pick.offset, pick.raw.clone()));
                }
            }
            journal.advance(pick.offset, pick.bytes, pick.waste, pick.entry.checksum);
            entries.push(pick.entry);
        }
        for cut in found {
            for ring in journal.rings {
                writes.push((ring + cut.offset, vec![0; sector]));
            }
        }
        if !writes.is_empty() {
            for (offset, raw) in writes {
                let mut buf = Buf::aligned(raw.len(), sector);
                buf.extend_from_slice(&raw);
                let (result, _) = file.write_all_at(buf, offset).await;
                result?;
            }
            file.sync_data().await?;
        }
        Ok((journal, entries))
    }
}

struct Found {
    entry: Entry,
    bytes: u64,
    offset: u64,
    waste: u64,
    rings: [bool; 2],
    raw: Vec<u8>,
}

async fn read_exact(
    file: &File,
    offset: u64,
    len: usize,
    align: usize,
) -> Result<Option<Buf>, Error> {
    let (result, buf) = file.read_at(Buf::aligned(len, align), offset).await;
    Ok((result? == len).then_some(buf))
}

fn commit_payload_size(commit: &Commit) -> Result<usize, Error> {
    let size = FIXED + commit.ranges.len() * RANGE + commit.allocations.len() * ALLOCATION;
    if size > MAX_PAYLOAD
        || u16::try_from(commit.ranges.len()).is_err()
        || u16::try_from(commit.allocations.len()).is_err()
    {
        return Err(Error::CommitTooLarge);
    }
    Ok(size)
}

fn encode_commit(previous: u32, commit: &Commit) -> Result<Vec<u8>, Error> {
    let size = commit_payload_size(commit)?;
    let ranges = u16::try_from(commit.ranges.len()).map_err(|_| Error::CommitTooLarge)?;
    let allocations = u16::try_from(commit.allocations.len()).map_err(|_| Error::CommitTooLarge)?;
    let mut out = vec![0u8; size];
    let mut fields = FieldsMut::new(&mut out);
    fields.put_u32(0, previous);
    fields.put_u16(4, ranges);
    fields.put_u16(6, allocations);
    fields.put_u64(8, commit.record_sequence);
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

fn decode_commit(payload: &[u8]) -> Option<(u32, Commit)> {
    if payload.len() < FIXED {
        return None;
    }
    let fields = Fields::new(payload);
    let ranges = usize::from(fields.u16(4));
    let allocations = usize::from(fields.u16(6));
    if payload.len() != FIXED + ranges * RANGE + allocations * ALLOCATION {
        return None;
    }
    let mut commit = Commit {
        record_sequence: fields.u64(8),
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
    Some((fields.u32(0), commit))
}
