use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use rt::{Buf, Receiver, Sender, channel};

mod compaction;
mod flight;
mod runs;

use crate::core_file::Source;
use crate::data_file::DataFile;
use crate::error::Error;
use crate::journal::{self, Allocation, Commit, Dead, Journal, Live, Range};
use crate::reader::{Pins, Reader};
use crate::record::{self, Header, MAX_PAYLOAD, record_size};
use crate::recovery::State;
use crate::regions::{Claim, Regions};
use crate::session::{Answer, Event, Owned, Results, Session};
use crate::usage::Usage;
use compaction::Compaction;
pub use compaction::{CompactionStats, Space};
use flight::{Next, Parked, Queues};
use runs::Runs;
use sys::crc32c::checksum;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    pub kind: u8,
    pub counted: bool,
    pub shard: u16,
    pub tenant: u32,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Body {
    pub shard: u16,
    pub tenant: u32,
    pub range: Range,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission {
    pub claim: Claim,
    pub records: Vec<Write>,
    pub bodies: Vec<Body>,
    pub dead: Vec<Dead>,
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

pub const PART_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) enum Reply {
    Once(Sender<Result<Durable, Error>>),
    Stream { session: usize, tag: u64 },
}

pub(crate) enum Request {
    Commit(Submission, Reply),
    Answer(Answer),
    Allocate(Claim, Sender<Result<(u32, u64), Error>>),
    Seal(u32, u64),
    ClaimState(usize, Sender<Result<(u32, u64), Error>>),
    Checkpoint(Sender<Result<u64, Error>>),
    Survey(usize, u64, Vec<Owned>),
    Compacted(usize, u32, u64),
}

pub struct Lease {
    region: u32,
    epoch: u64,
    sender: Sender<Request>,
}

impl Lease {
    pub fn region(&self) -> u32 {
        self.region
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn seal(self) {}
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.sender.send(Request::Seal(self.region, self.epoch));
    }
}

#[derive(Clone)]
pub struct Client {
    pub(crate) sender: Sender<Request>,
}

impl Client {
    pub async fn commit(&self, submission: Submission) -> Result<Durable, Error> {
        let (reply, mut answer) = channel();
        if self
            .sender
            .send(Request::Commit(submission, Reply::Once(reply)))
            .is_err()
        {
            return Err(Error::Failed);
        }
        answer.recv().await.unwrap_or(Err(Error::Failed))
    }

    pub async fn allocate(&self, claim: Claim) -> Result<Lease, Error> {
        let (reply, mut answer) = channel();
        if self.sender.send(Request::Allocate(claim, reply)).is_err() {
            return Err(Error::Failed);
        }
        let (region, epoch) = answer.recv().await.unwrap_or(Err(Error::Failed))?;
        Ok(Lease {
            region,
            epoch,
            sender: self.sender.clone(),
        })
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
    reply: Reply,
    locations: Vec<Location>,
}

pub struct Committer {
    data: DataFile,
    journal: Journal,
    regions: Regions,
    epochs: Vec<u64>,
    usage: Usage,
    open: Vec<bool>,
    busy: Vec<u32>,
    streams: [Option<Stream>; 2],
    leased: Vec<Option<u64>>,
    allocations: Vec<Allocation>,
    sequence: u64,
    checkpoint: Vec<u32>,
    carried: Vec<u32>,
    pins: Pins,
    inbox: Receiver<Request>,
    sessions: Vec<Option<Sender<Event>>>,
    queues: Queues,
    runs: Runs,
    part_timeout: Duration,
    compaction: Compaction,
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
            usage: state.usage,
            open: vec![false; count as usize],
            busy: Vec::new(),
            streams: [None, None],
            leased: vec![None; count as usize],
            allocations: Vec::new(),
            sequence: state.record_sequence,
            checkpoint: state.checkpoint,
            carried: Vec::new(),
            pins: Pins::new(count),
            inbox,
            sessions: Vec::new(),
            queues: Queues::default(),
            runs: Runs {
                regions: state.runs,
                appending: Vec::new(),
            },
            part_timeout: PART_TIMEOUT,
            compaction: Compaction::new(count),
            failed: false,
        };
        (committer, Client { sender })
    }

    pub fn session(&mut self, client: &Client, credits: u32) -> (Session, Results) {
        let (events, receiver) = channel();
        let credits = Arc::new(AtomicU32::new(credits));
        self.sessions.push(Some(events));
        self.runs.appending.push(None);
        self.regions.add_state_reserve();
        let session = Session {
            id: self.sessions.len() - 1,
            client: client.clone(),
            credits: Arc::clone(&credits),
        };
        (
            session,
            Results {
                events: receiver,
                credits,
            },
        )
    }

    pub fn set_part_timeout(&mut self, part_timeout: Duration) {
        self.part_timeout = part_timeout;
    }

    fn reply(&mut self, reply: Reply, result: Result<Durable, Error>) {
        match reply {
            Reply::Once(sender) => {
                let _ = sender.send(result);
            }
            Reply::Stream { session, tag } => {
                let event = match result {
                    Ok(durable) => Event::Durable {
                        tag,
                        sequence: durable.sequence,
                        locations: durable.locations,
                    },
                    Err(error) => Event::Rejected { tag, error },
                };
                self.send_event(session, event);
            }
        }
    }

    fn send_event(&mut self, session: usize, event: Event) {
        if let Some(slot) = self.sessions.get_mut(session)
            && let Some(sender) = slot
            && sender.send(event).is_err()
        {
            *slot = None;
        }
    }

    fn broadcast(&mut self, event: impl Fn() -> Event) {
        for session in 0..self.sessions.len() {
            self.send_event(session, event());
        }
    }

    pub fn reader(&self) -> Reader {
        self.data.reader(self.pins.clone())
    }

    pub fn source(&self) -> Source {
        self.data.source(self.pins.clone())
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

    pub fn usage(&self) -> &Usage {
        &self.usage
    }

    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub async fn run(mut self) -> Self {
        loop {
            let first = match self.next_request().await {
                Next::Request(request) => request,
                Next::Tick => {
                    self.settle().await;
                    continue;
                }
                Next::Closed => break,
            };
            let mut batch = Vec::new();
            self.handle(first, &mut batch);
            while let Some(next) = self.try_next_request() {
                self.handle(next, &mut batch);
            }
            if !batch.is_empty() {
                self.commit(batch).await;
            }
            self.settle().await;
        }
        self.close().await;
        self
    }

    fn handle(&mut self, request: Request, batch: &mut Vec<(Submission, Reply)>) {
        if self.defers(&request) {
            self.queues.deferred.push_back(request);
            return;
        }
        match request {
            Request::Allocate(claim, reply) => {
                let result = if self.failed {
                    Err(Error::Failed)
                } else {
                    self.allocate(claim)
                };
                if let Ok((region, epoch)) = result {
                    self.leased[region as usize] = Some(epoch);
                }
                let _ = reply.send(result);
            }
            Request::Commit(submission, reply) => {
                if self.failed {
                    self.reply(reply, Err(Error::Failed));
                } else {
                    batch.push((submission, reply));
                }
            }
            Request::Answer(answer) => self.answer(answer),
            Request::ClaimState(session, reply) => {
                let result = if self.failed {
                    Err(Error::Failed)
                } else {
                    self.claim_state(session)
                };
                let _ = reply.send(result);
            }
            Request::Seal(region, epoch) => {
                if self.epochs[region as usize] == epoch {
                    self.sealed(region);
                }
            }
            Request::Checkpoint(reply) => self.queues.requested.push_back(reply),
            Request::Survey(session, sequence, owned) => self.surveyed(session, sequence, owned),
            Request::Compacted(session, region, epoch) => self.compacted(session, region, epoch),
        }
    }

    fn free_unpinned(&mut self, pending: Vec<u32>) {
        let mut carried = Vec::new();
        for region in std::mem::take(&mut self.carried).into_iter().chain(pending) {
            if self.pins.is_pinned(region) {
                carried.push(region);
            } else {
                self.regions.release(region);
            }
        }
        self.carried = carried;
    }

    fn due(&self) -> bool {
        self.journal.size() - self.journal.free() >= self.journal.size() / 2
    }

    fn allocate(&mut self, claim: Claim) -> Result<(u32, u64), Error> {
        let region = self.regions.acquire(claim)?;
        assert!(
            self.usage.is_empty(region),
            "free region {region} has live data"
        );
        self.open[region as usize] = true;
        let epoch = &mut self.epochs[region as usize];
        *epoch += 1;
        self.allocations.push(Allocation {
            region,
            epoch: *epoch,
        });
        Ok((region, *epoch))
    }

    async fn commit(&mut self, batch: Vec<(Submission, Reply)>) {
        let sector = u64::from(self.data.sector_size());
        let mut segments = Vec::new();
        let mut ranges = Vec::new();
        let mut live = BTreeMap::<(u32, u32), Live>::new();
        let mut dead = Vec::new();
        let mut accepted = Vec::new();
        let mut load = Load {
            allocations: self.allocations.len(),
            ..Load::default()
        };
        let base = load;
        let mut batch = batch.into_iter();
        while let Some((submission, reply)) = batch.next() {
            if !load.add(&submission).fits() {
                if base.add(&submission).fits() {
                    self.defer(std::iter::once((submission, reply)).chain(batch));
                    break;
                }
                self.reply(reply, Err(Error::CommitTooLarge));
                continue;
            }
            if !self.owns(&reply, &submission) {
                self.reply(reply, Err(Error::Invalid("owner")));
                continue;
            }
            match self.pack(&submission, &mut segments) {
                Ok(locations) => {
                    load = load.add(&submission);
                    self.account(&submission, &locations);
                    count_live(&submission, &locations, &mut live);
                    ranges.extend(submission.bodies.iter().map(|b| b.range));
                    dead.extend_from_slice(&submission.dead);
                    accepted.push(Accepted { reply, locations });
                }
                Err(e) => {
                    self.reply(reply, Err(e));
                }
            }
        }
        for stream in self.streams.iter_mut().flatten() {
            stream.offset = stream.offset.next_multiple_of(sector);
        }
        if accepted.is_empty() {
            return;
        }
        let mut commit = Commit {
            record_sequence: self.sequence,
            streams: u16::try_from(segments.len()).expect("stream segments fit in u16"),
            ranges: Vec::with_capacity(segments.len() + ranges.len()),
            allocations: self.allocations.clone(),
            live: live.into_values().collect(),
            dead,
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
        self.busy = commit.ranges.iter().map(|r| r.region).collect();
        let mut reserved = self.journal.reserve(&commit);
        if matches!(reserved, Err(Error::JournalFull)) {
            if !self.checkpoint_in_flight() {
                self.begin_checkpoint(None);
                self.settle_flight().await;
            }
            if self.checkpoint_in_flight() {
                self.busy.clear();
                self.queues.parked = Some(Parked {
                    commit,
                    buffers,
                    accepted,
                });
                return;
            }
            reserved = self.journal.reserve(&commit);
        }
        self.busy.clear();
        if let Err(e) = reserved {
            self.refuse(accepted, &e);
            return;
        }
        self.finish_commit(commit, buffers, accepted).await;
    }

    fn defer(&mut self, rest: impl DoubleEndedIterator<Item = (Submission, Reply)>) {
        for (submission, reply) in rest.rev() {
            self.queues
                .deferred
                .push_front(Request::Commit(submission, reply));
        }
    }

    fn refuse(&mut self, accepted: Vec<Accepted>, e: &Error) {
        self.usage.forget();
        for entry in accepted {
            let error = match e {
                _ if self.failed => Error::Failed,
                Error::JournalFull => Error::JournalFull,
                _ => Error::CommitTooLarge,
            };
            self.reply(entry.reply, Err(error));
        }
    }

    async fn finish_commit(
        &mut self,
        commit: Commit,
        buffers: Vec<(u64, Buf)>,
        accepted: Vec<Accepted>,
    ) {
        let Ok(sequence) = self.write(buffers, &commit).await else {
            self.usage.forget();
            self.failed = true;
            for entry in accepted {
                self.reply(entry.reply, Err(Error::Failed));
            }
            return;
        };
        self.allocations.clear();
        self.usage.settle(&commit.live, &commit.dead);
        for entry in accepted {
            let durable = Durable {
                sequence,
                locations: entry.locations,
            };
            self.reply(entry.reply, Ok(durable));
        }
        if (self.due() || self.space_needs_checkpoint()) && !self.checkpoint_in_flight() {
            self.begin_checkpoint(None);
        }
        self.start_victim();
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

    fn admit(&mut self, dead: &[Dead], region_size: u64) -> Result<(), Error> {
        for entry in dead {
            if !self.tracked(entry.region, entry.epoch) {
                return Err(Error::Invalid("dead"));
            }
            let fits = entry
                .offset
                .checked_add(u64::from(entry.length))
                .is_some_and(|end| end <= region_size);
            if entry.length == 0 || !fits {
                self.usage.quarantine(entry.region);
                return Err(Error::Invalid("dead"));
            }
        }
        if let Err(region) = self.usage.hold(dead) {
            self.usage.quarantine(region);
            return Err(Error::Invalid("dead"));
        }
        Ok(())
    }

    fn tracked(&self, region: u32, epoch: u64) -> bool {
        region < self.regions.count()
            && self.regions.is_used(region)
            && self.epochs[region as usize] == epoch
            && !self.checkpoint.contains(&region)
            && !self.is_state(region)
            && self.allocations.iter().all(|a| a.region != region)
    }

    fn owns(&self, reply: &Reply, submission: &Submission) -> bool {
        let cores = self.sessions.len();
        let mut shards = submission
            .records
            .iter()
            .map(|w| w.shard)
            .chain(submission.bodies.iter().map(|b| b.shard));
        match reply {
            Reply::Stream { session, .. } => shards.all(|s| usize::from(s) % cores == *session),
            Reply::Once(_) => cores == 0 || shards.next().is_none(),
        }
    }

    fn check_bodies(&self, submission: &Submission) -> Result<(), Error> {
        let superblock = self.data.superblock();
        let region_size = superblock.region_size();
        let sector = u64::from(superblock.sector_size());
        for body in &submission.bodies {
            if u32::from(body.shard) >= superblock.shards() {
                return Err(Error::Invalid("shard"));
            }
            let range = &body.range;
            let valid = range.region < superblock.region_count()
                && self.leased[range.region as usize] == Some(range.epoch)
                && !self.is_victim(range.region)
                && self.regions.is_used(range.region)
                && !self.checkpoint.contains(&range.region)
                && !self.releasing(range.region)
                && !self.is_state(range.region)
                && self.epochs[range.region as usize] == range.epoch
                && range.length > 0
                && range.offset.is_multiple_of(sector)
                && u64::from(range.length).is_multiple_of(sector)
                && range.offset + u64::from(range.length) <= region_size;
            if !valid {
                return Err(Error::Invalid("range"));
            }
        }
        Ok(())
    }

    fn pack(
        &mut self,
        submission: &Submission,
        segments: &mut Vec<Segment>,
    ) -> Result<Vec<Location>, Error> {
        self.check_bodies(submission)?;
        let superblock = self.data.superblock();
        let region_size = superblock.region_size();
        let mut total = 0u64;
        for write in &submission.records {
            if u32::from(write.shard) >= superblock.shards() {
                return Err(Error::Invalid("shard"));
            }
            if write.payload.len() > MAX_PAYLOAD {
                return Err(Error::CommitTooLarge);
            }
            total += record_size(write.payload.len()) as u64;
        }
        if total > region_size {
            return Err(Error::CommitTooLarge);
        }
        self.admit(&submission.dead, region_size)?;
        if total == 0 {
            return Ok(Vec::new());
        }
        let class = usize::from(submission.claim == Claim::Internal);
        let fits = self.streams[class]
            .as_ref()
            .is_some_and(|s| s.offset + total <= region_size);
        if !fits {
            let (region, epoch) = match self.allocate(submission.claim) {
                Ok(allocated) => allocated,
                Err(e) => {
                    self.usage.unhold(&submission.dead);
                    return Err(e);
                }
            };
            if let Some(old) = self.streams[class].as_ref().map(|s| s.region) {
                self.sealed(old);
            }
            self.streams[class] = Some(Stream {
                region,
                epoch,
                offset: 0,
            });
        }
        let stream = self.streams[class].as_mut().expect("stream allocated");
        let found = segments
            .iter()
            .position(|s: &Segment| s.region == stream.region && s.epoch == stream.epoch);
        let at = found.unwrap_or_else(|| {
            segments.push(Segment {
                region: stream.region,
                epoch: stream.epoch,
                offset: stream.offset,
                bytes: Vec::new(),
            });
            segments.len() - 1
        });
        let segment = &mut segments[at];
        let mut locations = Vec::with_capacity(submission.records.len());
        for write in &submission.records {
            let size = record_size(write.payload.len());
            let start = segment.bytes.len();
            segment.bytes.resize(start + size, 0);
            let header = Header {
                kind: write.kind,
                flags: 0,
                shard: write.shard,
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

#[derive(Clone, Copy, Default)]
struct Load {
    ranges: usize,
    allocations: usize,
    live: usize,
    dead: usize,
}

impl Load {
    fn add(self, submission: &Submission) -> Self {
        let bodies = submission.bodies.len();
        let records = submission.records.len();
        Self {
            ranges: self.ranges + bodies + 1,
            allocations: self.allocations + 1,
            live: self.live + records + bodies,
            dead: self.dead + submission.dead.len(),
        }
    }

    fn fits(self) -> bool {
        journal::fits(self.ranges, self.allocations, self.live, self.dead)
    }
}

fn count_live(
    submission: &Submission,
    locations: &[Location],
    live: &mut BTreeMap<(u32, u32), Live>,
) {
    let records = submission
        .records
        .iter()
        .zip(locations)
        .filter(|(w, _)| w.counted)
        .map(|(w, l)| (w.tenant, l.region, u64::from(l.size)));
    let bodies = submission
        .bodies
        .iter()
        .map(|b| (b.tenant, b.range.region, u64::from(b.range.length)));
    for (tenant, region, bytes) in records.chain(bodies) {
        let entry = live.entry((tenant, region)).or_insert(Live {
            tenant,
            region,
            extents: 0,
            bytes: 0,
        });
        entry.extents += 1;
        entry.bytes += bytes;
    }
}
