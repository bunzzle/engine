use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use rt::{Receiver, Sender};

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
}

pub(crate) struct Answer {
    pub(crate) session: usize,
    pub(crate) sequence: u64,
    pub(crate) parts: Vec<Part>,
}

pub struct Session {
    pub(crate) id: usize,
    pub(crate) client: Client,
    pub(crate) parts: Sender<Answer>,
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
        self.parts
            .send(Answer {
                session: self.id,
                sequence,
                parts,
            })
            .map_err(|_| Error::Failed)
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
