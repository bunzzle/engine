use rt::{Buf, Receiver, Sender, channel};

use crate::checkpoint::{Snapshot, encode, write_copy};
use crate::crc32c::checksum;
use crate::data_file::DataFile;
use crate::error::Error;
use crate::journal::{Allocation, Commit, Journal, Position, Range};
use crate::record::{self, Header, MAX_PAYLOAD, record_size};
use crate::recovery::State;
use crate::regions::{CHECKPOINT_RESERVE, Claim, Regions};
use crate::superblock::Checkpoint;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    pub kind: u8,
    pub tenant: u32,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission {
    pub claim: Claim,
    pub records: Vec<Write>,
    pub ranges: Vec<Range>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    pub region: u32,
    pub epoch: u64,
    pub offset: u64,
    pub sequence: u64,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Durable {
    pub sequence: u64,
    pub locations: Vec<Location>,
}

enum Request {
    Commit(Submission, Sender<Result<Durable, Error>>),
    Allocate(Claim, Sender<Result<(u32, u64), Error>>),
    Checkpoint(Sender<Result<u64, Error>>),
}

#[derive(Clone)]
pub struct Client {
    sender: Sender<Request>,
}

impl Client {
    pub async fn commit(&self, submission: Submission) -> Result<Durable, Error> {
        let (reply, mut answer) = channel();
        if self
            .sender
            .send(Request::Commit(submission, reply))
            .is_err()
        {
            return Err(Error::Failed);
        }
        answer.recv().await.unwrap_or(Err(Error::Failed))
    }

    pub async fn allocate(&self, claim: Claim) -> Result<(u32, u64), Error> {
        let (reply, mut answer) = channel();
        if self.sender.send(Request::Allocate(claim, reply)).is_err() {
            return Err(Error::Failed);
        }
        answer.recv().await.unwrap_or(Err(Error::Failed))
    }

    pub async fn checkpoint(&self) -> Result<u64, Error> {
        let (reply, mut answer) = channel();
        if self.sender.send(Request::Checkpoint(reply)).is_err() {
            return Err(Error::Failed);
        }
        answer.recv().await.unwrap_or(Err(Error::Failed))
    }
}

struct Stream {
    region: u32,
    epoch: u64,
    offset: u64,
}

struct Segment {
    region: u32,
    epoch: u64,
    offset: u64,
    bytes: Vec<u8>,
}

struct Accepted {
    reply: Sender<Result<Durable, Error>>,
    locations: Vec<Location>,
}

pub struct Committer {
    data: DataFile,
    journal: Journal,
    regions: Regions,
    epochs: Vec<u64>,
    stream: Option<Stream>,
    allocations: Vec<Allocation>,
    sequence: u64,
    checkpoint: Vec<u32>,
    inbox: Receiver<Request>,
    failed: bool,
}

impl Committer {
    pub fn new(data: DataFile, journal: Journal, state: State) -> (Self, Client) {
        let count = data.superblock().region_count();
        assert_eq!(state.regions.count(), count, "region count mismatch");
        assert_eq!(state.epochs.len(), count as usize, "epoch count mismatch");
        let (sender, inbox) = channel();
        let committer = Self {
            data,
            journal,
            regions: state.regions,
            epochs: state.epochs,
            stream: None,
            allocations: Vec::new(),
            sequence: state.record_sequence,
            checkpoint: state.checkpoint,
            inbox,
            failed: false,
        };
        (committer, Client { sender })
    }

    pub fn data(&self) -> &DataFile {
        &self.data
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn regions(&self) -> &Regions {
        &self.regions
    }

    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub async fn run(mut self) -> Self {
        while let Some(first) = self.inbox.recv().await {
            let mut batch = Vec::new();
            let mut requested = self.handle(first, &mut batch);
            while requested.is_none()
                && let Some(next) = self.inbox.try_recv()
            {
                requested = self.handle(next, &mut batch);
            }
            if !batch.is_empty() {
                self.commit(batch).await;
            }
            if let Some(reply) = requested {
                let result = self.checkpoint().await.map(|p| p.sequence);
                let _ = reply.send(result);
            }
        }
        self
    }

    fn handle(
        &mut self,
        request: Request,
        batch: &mut Vec<(Submission, Sender<Result<Durable, Error>>)>,
    ) -> Option<Sender<Result<u64, Error>>> {
        match request {
            Request::Allocate(claim, reply) => {
                let result = if self.failed {
                    Err(Error::Failed)
                } else {
                    self.allocate(claim)
                };
                let _ = reply.send(result);
            }
            Request::Commit(submission, reply) => {
                if self.failed {
                    let _ = reply.send(Err(Error::Failed));
                } else {
                    batch.push((submission, reply));
                }
            }
            Request::Checkpoint(reply) => return Some(reply),
        }
        None
    }

    pub async fn checkpoint(&mut self) -> Result<Position, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let position = self.journal.position();
        let count = self.regions.count();
        let mut used: Vec<bool> = (0..count).map(|r| self.regions.is_used(r)).collect();
        let mut epochs = self.epochs.clone();
        for allocation in &self.allocations {
            used[allocation.region as usize] = false;
            epochs[allocation.region as usize] = allocation.epoch - 1;
        }
        let mut regions = Vec::with_capacity(CHECKPOINT_RESERVE as usize);
        for _ in 0..CHECKPOINT_RESERVE {
            match self.regions.acquire(Claim::Checkpoint) {
                Ok(region) => regions.push(region),
                Err(e) => {
                    for region in regions {
                        self.regions.release(region);
                    }
                    return Err(e);
                }
            }
        }
        for &region in &regions {
            let epoch = &mut self.epochs[region as usize];
            *epoch += 1;
            used[region as usize] = true;
            epochs[region as usize] = *epoch;
        }
        let blob = encode(&Snapshot {
            position,
            record_sequence: self.sequence,
            used,
            epochs,
            release: self.checkpoint.clone(),
            parts: Vec::new(),
        });
        let sequence = self.data.superblock().sequence() + 1;
        let mut copies = Vec::with_capacity(regions.len());
        for &region in &regions {
            let epoch = self.epochs[region as usize];
            match write_copy(&self.data, region, epoch, sequence, &blob).await {
                Ok(copy) => copies.push(copy),
                Err(Error::CheckpointTooLarge) => {
                    for region in regions {
                        self.regions.release(region);
                    }
                    return Err(Error::CheckpointTooLarge);
                }
                Err(e) => {
                    self.failed = true;
                    return Err(e);
                }
            }
        }
        if let Err(e) = self.data.file().sync_data().await {
            self.failed = true;
            return Err(e.into());
        }
        let checkpoint = Checkpoint {
            position,
            copies: [copies[0], copies[1]],
        };
        let oldest = self.data.superblock().oldest_format();
        if let Err(e) = self.data.update(Some(checkpoint), oldest).await {
            self.failed = true;
            return Err(e);
        }
        self.journal.release(position.sequence - 1);
        for region in std::mem::replace(&mut self.checkpoint, regions) {
            self.regions.release(region);
        }
        Ok(position)
    }

    fn due(&self) -> bool {
        self.journal.size() - self.journal.free() >= self.journal.size() / 2
    }

    fn allocate(&mut self, claim: Claim) -> Result<(u32, u64), Error> {
        let region = self.regions.acquire(claim)?;
        let epoch = &mut self.epochs[region as usize];
        *epoch += 1;
        self.allocations.push(Allocation {
            region,
            epoch: *epoch,
        });
        Ok((region, *epoch))
    }

    async fn commit(&mut self, batch: Vec<(Submission, Sender<Result<Durable, Error>>)>) {
        let sector = u64::from(self.data.sector_size());
        let mut segments = Vec::new();
        let mut ranges = Vec::new();
        let mut accepted = Vec::new();
        for (submission, reply) in batch {
            match self.pack(&submission, &mut segments) {
                Ok(locations) => {
                    ranges.extend_from_slice(&submission.ranges);
                    accepted.push(Accepted { reply, locations });
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
        }
        if let Some(stream) = &mut self.stream {
            stream.offset = stream.offset.next_multiple_of(sector);
        }
        if accepted.is_empty() {
            return;
        }
        let mut commit = Commit {
            record_sequence: self.sequence,
            ranges: Vec::with_capacity(segments.len() + ranges.len()),
            allocations: self.allocations.clone(),
        };
        let align = self.data.sector_size() as usize;
        let mut buffers = Vec::with_capacity(segments.len());
        for segment in segments {
            let len = segment.bytes.len().next_multiple_of(align);
            let mut buf = Buf::aligned(len, align);
            buf.extend_from_slice(&segment.bytes);
            buf.set_len(len);
            commit.ranges.push(Range {
                region: segment.region,
                epoch: segment.epoch,
                offset: segment.offset,
                length: u32::try_from(len).expect("segment fits in a region"),
                checksum: checksum(&buf),
            });
            buffers.push((
                self.data.region_offset(segment.region) + segment.offset,
                buf,
            ));
        }
        commit.ranges.extend(ranges);
        let mut reserved = self.journal.reserve(&commit);
        if matches!(reserved, Err(Error::JournalFull)) && self.checkpoint().await.is_ok() {
            reserved = self.journal.reserve(&commit);
        }
        if let Err(e) = reserved {
            for entry in accepted {
                let error = match e {
                    _ if self.failed => Error::Failed,
                    Error::JournalFull => Error::JournalFull,
                    _ => Error::CommitTooLarge,
                };
                let _ = entry.reply.send(Err(error));
            }
            return;
        }
        let Ok(sequence) = self.write(buffers, &commit).await else {
            self.failed = true;
            for entry in accepted {
                let _ = entry.reply.send(Err(Error::Failed));
            }
            return;
        };
        self.allocations.clear();
        for entry in accepted {
            let _ = entry.reply.send(Ok(Durable {
                sequence,
                locations: entry.locations,
            }));
        }
        if self.due() {
            let _ = self.checkpoint().await;
        }
    }

    async fn write(&mut self, buffers: Vec<(u64, Buf)>, commit: &Commit) -> Result<u64, Error> {
        let file = self.data.file();
        for (offset, buf) in buffers {
            let (result, _) = file.write_all_at(buf, offset).await;
            result?;
        }
        let position = self.journal.append(file, commit).await?;
        file.sync_data().await?;
        Ok(position.sequence)
    }

    fn pack(
        &mut self,
        submission: &Submission,
        segments: &mut Vec<Segment>,
    ) -> Result<Vec<Location>, Error> {
        let superblock = self.data.superblock();
        let region_size = superblock.region_size();
        let sector = u64::from(superblock.sector_size());
        for range in &submission.ranges {
            let valid = range.region < superblock.region_count()
                && self.epochs[range.region as usize] == range.epoch
                && range.offset.is_multiple_of(sector)
                && u64::from(range.length).is_multiple_of(sector)
                && range.offset + u64::from(range.length) <= region_size;
            if !valid {
                return Err(Error::Invalid("range"));
            }
        }
        let mut total = 0u64;
        for write in &submission.records {
            if write.payload.len() > MAX_PAYLOAD {
                return Err(Error::CommitTooLarge);
            }
            total += record_size(write.payload.len()) as u64;
        }
        if total == 0 {
            return Ok(Vec::new());
        }
        if total > region_size {
            return Err(Error::CommitTooLarge);
        }
        let fits = self
            .stream
            .as_ref()
            .is_some_and(|s| s.offset + total <= region_size);
        if !fits {
            let (region, epoch) = self.allocate(submission.claim)?;
            self.stream = Some(Stream {
                region,
                epoch,
                offset: 0,
            });
        }
        let stream = self.stream.as_mut().expect("stream allocated");
        let same = segments
            .last()
            .is_some_and(|s: &Segment| s.region == stream.region && s.epoch == stream.epoch);
        if !same {
            segments.push(Segment {
                region: stream.region,
                epoch: stream.epoch,
                offset: stream.offset,
                bytes: Vec::new(),
            });
        }
        let segment = segments.last_mut().expect("segment present");
        let mut locations = Vec::with_capacity(submission.records.len());
        for write in &submission.records {
            let size = record_size(write.payload.len());
            let start = segment.bytes.len();
            segment.bytes.resize(start + size, 0);
            let header = Header {
                kind: write.kind,
                flags: 0,
                tenant: write.tenant,
                epoch: stream.epoch,
                sequence: self.sequence,
            };
            record::encode(&header, &write.payload, &mut segment.bytes[start..]);
            locations.push(Location {
                region: stream.region,
                epoch: stream.epoch,
                offset: stream.offset,
                sequence: self.sequence,
                size: u32::try_from(size).expect("record fits in u32"),
            });
            self.sequence += 1;
            stream.offset += size as u64;
        }
        Ok(locations)
    }
}
