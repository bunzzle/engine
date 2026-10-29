use std::collections::VecDeque;

use rt::{Buf, Sender, now, timeout};

use super::{Accepted, Committer, Request};
use crate::checkpoint::{Snapshot, encode, parts_valid, write_copy};
use crate::error::Error;
use crate::journal::{Commit, Position};
use crate::regions::{CHECKPOINT_RESERVE, Claim};
use crate::session::{Answer, Event};
use crate::superblock::Checkpoint;
use rt::Instant;

type CheckpointReply = Sender<Result<u64, Error>>;

pub(super) struct Flight {
    snapshot: Snapshot,
    regions: Vec<u32>,
    pending: Vec<u32>,
    waiting: Vec<usize>,
    referenced: Vec<u32>,
    invalid: bool,
    deadline: Instant,
    reply: Option<CheckpointReply>,
}

pub(super) struct Parked {
    pub(super) commit: Commit,
    pub(super) buffers: Vec<(u64, Buf)>,
    pub(super) accepted: Vec<Accepted>,
}

pub(super) enum Next {
    Request(Request),
    Tick,
    Closed,
}

#[derive(Default)]
pub(super) struct Queues {
    pub(super) flight: Option<Flight>,
    pub(super) parked: Option<Parked>,
    pub(super) deferred: VecDeque<Request>,
    pub(super) requested: VecDeque<CheckpointReply>,
}

impl Committer {
    pub(super) fn releasing(&self, region: u32) -> bool {
        self.queues
            .flight
            .as_ref()
            .is_some_and(|f| f.pending.contains(&region))
    }

    pub(super) fn checkpoint_in_flight(&self) -> bool {
        self.queues.flight.is_some()
    }

    pub(super) fn defers(&self, request: &Request) -> bool {
        self.queues.parked.is_some()
            && !matches!(
                request,
                Request::Answer(_) | Request::Seal(..) | Request::ClaimState(..)
            )
    }

    pub(super) fn try_next_request(&mut self) -> Option<Request> {
        if self.queues.parked.is_none()
            && let Some(request) = self.queues.deferred.pop_front()
        {
            return Some(request);
        }
        self.inbox.try_recv()
    }

    pub(super) async fn next_request(&mut self) -> Next {
        if let Some(request) = self.try_next_request() {
            return Next::Request(request);
        }
        let Some(deadline) = self.queues.flight.as_ref().map(|f| f.deadline) else {
            return self.inbox.recv().await.map_or(Next::Closed, Next::Request);
        };
        let left = deadline.saturating_duration_since(now());
        match timeout(left, self.inbox.recv()).await {
            Ok(Some(request)) => Next::Request(request),
            Ok(None) => Next::Closed,
            Err(_) => {
                self.prune_waiting();
                let flight = self.queues.flight.as_ref().expect("flight in progress");
                assert!(
                    flight.waiting.is_empty(),
                    "checkpoint part missing from sessions {:?} at cut {}",
                    flight.waiting,
                    flight.snapshot.position.sequence
                );
                Next::Tick
            }
        }
    }

    pub(super) fn answer(&mut self, answer: Answer) {
        let referenced = self.referenced(&answer.parts);
        let Some(flight) = self.queues.flight.as_mut() else {
            return;
        };
        let cut = flight.snapshot.position.sequence;
        if answer.sequence != cut || !flight.waiting.contains(&answer.session) {
            return;
        }
        flight.waiting.retain(|&s| s != answer.session);
        if answer.failed || answer.parts.iter().any(|p| p.replay_sequence != cut) {
            flight.invalid = true;
        }
        match referenced {
            Some(regions) => flight.referenced.extend(regions),
            None => flight.invalid = true,
        }
        flight.snapshot.parts.extend(answer.parts);
    }

    fn prune_waiting(&mut self) {
        let sessions = &self.sessions;
        if let Some(flight) = self.queues.flight.as_mut() {
            flight
                .waiting
                .retain(|&s| sessions[s].as_ref().is_some_and(|tx| !tx.is_closed()));
        }
    }

    pub(super) fn begin_checkpoint(&mut self, reply: Option<CheckpointReply>) {
        match self.try_begin_checkpoint() {
            Ok(()) => {
                if let Some(flight) = self.queues.flight.as_mut() {
                    flight.reply = reply;
                }
            }
            Err(error) => {
                if let Some(reply) = reply {
                    let _ = reply.send(Err(error));
                }
            }
        }
    }

    fn try_begin_checkpoint(&mut self) -> Result<(), Error> {
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
        let regions = self.acquire_checkpoint_regions()?;
        let pending: Vec<u32> = (0..count)
            .filter(|&r| {
                used[r as usize]
                    && !self.open[r as usize]
                    && self.usage.is_empty(r)
                    && !self.usage.is_quarantined(r)
                    && !self.checkpoint.contains(&r)
                    && !self.is_state(r)
                    && !self.carried.contains(&r)
                    && !self.pins.is_pinned(r)
                    && !self.busy.contains(&r)
                    && !regions.contains(&r)
            })
            .collect();
        for &region in &regions {
            let epoch = &mut self.epochs[region as usize];
            *epoch += 1;
            used[region as usize] = true;
            epochs[region as usize] = *epoch;
        }
        let mut release = self.checkpoint.clone();
        release.extend_from_slice(&self.carried);
        release.extend_from_slice(&pending);
        let snapshot = Snapshot {
            position,
            record_sequence: self.sequence,
            used,
            epochs,
            usage: self.usage.clone(),
            release,
            parts: Vec::new(),
        };
        let sequence = position.sequence;
        self.broadcast(|| Event::Cut { sequence });
        let waiting = (0..self.sessions.len())
            .filter(|&s| self.sessions[s].is_some())
            .collect();
        self.queues.flight =
            Some(Flight {
                snapshot,
                regions,
                pending,
                waiting,
                referenced: Vec::new(),
                invalid: false,
                deadline: Instant::from_nanos(now().as_nanos().saturating_add(
                    u64::try_from(self.part_timeout.as_nanos()).unwrap_or(u64::MAX),
                )),
                reply: None,
            });
        Ok(())
    }

    fn acquire_checkpoint_regions(&mut self) -> Result<Vec<u32>, Error> {
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
        Ok(regions)
    }

    pub(super) async fn settle(&mut self) {
        loop {
            if self.queues.flight.is_some() {
                self.prune_waiting();
                if self
                    .queues
                    .flight
                    .as_ref()
                    .is_some_and(|f| !f.waiting.is_empty())
                {
                    return;
                }
                self.finish().await;
            } else if self.queues.parked.is_none()
                && let Some(reply) = self.queues.requested.pop_front()
            {
                self.begin_checkpoint(Some(reply));
            } else {
                return;
            }
        }
    }

    pub(super) async fn settle_flight(&mut self) {
        self.prune_waiting();
        if self
            .queues
            .flight
            .as_ref()
            .is_some_and(|f| f.waiting.is_empty())
        {
            self.finish().await;
        }
    }

    pub(super) async fn finish(&mut self) {
        let Some(mut flight) = self.queues.flight.take() else {
            return;
        };
        let sequence = flight.snapshot.position.sequence;
        let reply = flight.reply.take();
        let shards = self.data.superblock().shards();
        let result = if flight.invalid || !parts_valid(&flight.snapshot.parts, shards) {
            for &region in &flight.regions {
                self.regions.release(region);
            }
            Err(Error::Invalid("part"))
        } else {
            self.write_flight(flight).await
        };
        if result.is_ok() {
            self.broadcast(|| Event::Published { sequence });
        } else {
            self.broadcast(|| Event::Abandoned { sequence });
        }
        if let Some(reply) = reply {
            let _ = reply.send(result.map(|p| p.sequence));
        }
        self.unpark().await;
    }

    async fn write_flight(&mut self, flight: Flight) -> Result<Position, Error> {
        let Flight {
            mut snapshot,
            regions,
            pending,
            referenced,
            ..
        } = flight;
        self.mark_state(&mut snapshot, &referenced);
        let position = snapshot.position;
        let blob = encode(&snapshot);
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
        self.free_unpinned(pending);
        self.release_state(&referenced);
        Ok(position)
    }

    async fn unpark(&mut self) {
        let Some(parked) = self.queues.parked.take() else {
            return;
        };
        self.busy = parked.commit.ranges.iter().map(|r| r.region).collect();
        let reserved = self.journal.reserve(&parked.commit);
        self.busy.clear();
        if let Err(e) = reserved {
            self.refuse(parked.accepted, &e);
            return;
        }
        self.finish_commit(parked.commit, parked.buffers, parked.accepted)
            .await;
    }

    pub(super) async fn close(&mut self) {
        self.prune_waiting();
        self.settle().await;
        if let Some(flight) = self.queues.flight.take() {
            for &region in &flight.regions {
                self.regions.release(region);
            }
            let sequence = flight.snapshot.position.sequence;
            self.broadcast(|| Event::Abandoned { sequence });
        }
        if let Some(parked) = self.queues.parked.take() {
            self.refuse(parked.accepted, &Error::JournalFull);
        }
        for request in std::mem::take(&mut self.queues.deferred) {
            if let Request::Commit(_, reply) = request {
                self.reply(reply, Err(Error::Failed));
            }
        }
    }
}
