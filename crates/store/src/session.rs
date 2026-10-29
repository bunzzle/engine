use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use rt::{Receiver, channel};

use crate::checkpoint::Part;
use crate::committer::{Client, Location, Reply, Request, Submission};
use crate::error::Error;

#[derive(Debug)]
pub enum Event {
    Durable {
        tag: u64,
        sequence: u64,
        locations: Vec<Location>,
    },
    Rejected {
        tag: u64,
        error: Error,
    },
    Cut {
        sequence: u64,
    },
    Published {
        sequence: u64,
    },
    Abandoned {
        sequence: u64,
    },
    Compact {
        region: u32,
        epoch: u64,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Owned {
    pub region: u32,
    pub extents: u32,
    pub bytes: u64,
}

pub(crate) struct Answer {
    pub(crate) session: usize,
    pub(crate) sequence: u64,
    pub(crate) parts: Vec<Part>,
    pub(crate) failed: bool,
}

pub struct Session {
    pub(crate) id: usize,
    pub(crate) client: Client,
    pub(crate) credits: Arc<AtomicU32>,
}

impl Session {
    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn credits(&self) -> u32 {
        self.credits.load(Ordering::Acquire)
    }

    pub fn submit(&self, tag: u64, submission: Submission) -> Result<(), Error> {
        let taken = self
            .credits
            .try_update(Ordering::AcqRel, Ordering::Acquire, |c| c.checked_sub(1));
        if taken.is_err() {
            return Err(Error::Busy);
        }
        let reply = Reply::Stream {
            session: self.id,
            tag,
        };
        if self
            .client
            .sender
            .send(Request::Commit(submission, reply))
            .is_err()
        {
            self.credits.fetch_add(1, Ordering::AcqRel);
            return Err(Error::Failed);
        }
        Ok(())
    }

    pub fn parts(&self, sequence: u64, parts: Vec<Part>) -> Result<(), Error> {
        self.answer(sequence, parts, false)
    }

    pub fn survey(&self, sequence: u64, owned: Vec<Owned>) -> Result<(), Error> {
        self.client
            .sender
            .send(Request::Survey(self.id, sequence, owned))
            .map_err(|_| Error::Failed)
    }

    pub fn compacted(&self, region: u32, epoch: u64) -> Result<(), Error> {
        self.client
            .sender
            .send(Request::Compacted(self.id, region, epoch))
            .map_err(|_| Error::Failed)
    }

    pub fn fail(&self, sequence: u64) -> Result<(), Error> {
        self.answer(sequence, Vec::new(), true)
    }

    fn answer(&self, sequence: u64, parts: Vec<Part>, failed: bool) -> Result<(), Error> {
        let answer = Answer {
            session: self.id,
            sequence,
            parts,
            failed,
        };
        self.client
            .sender
            .send(Request::Answer(answer))
            .map_err(|_| Error::Failed)
    }

    pub async fn claim_state(&self) -> Result<(u32, u64), Error> {
        let (reply, mut answer) = channel();
        if self
            .client
            .sender
            .send(Request::ClaimState(self.id, reply))
            .is_err()
        {
            return Err(Error::Failed);
        }
        answer.recv().await.unwrap_or(Err(Error::Failed))
    }
}

pub struct Results {
    pub(crate) events: Receiver<Event>,
    pub(crate) credits: Arc<AtomicU32>,
}

impl Results {
    pub async fn recv(&mut self) -> Option<Event> {
        let event = self.events.recv().await?;
        if matches!(event, Event::Durable { .. } | Event::Rejected { .. }) {
            self.credits.fetch_add(1, Ordering::AcqRel);
        }
        Some(event)
    }
}
