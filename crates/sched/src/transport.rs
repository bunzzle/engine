use spool::{MessageId, Opened, Stamp};

use crate::lanes::QueueId;
use crate::policy::Answer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claimed {
    pub recipient: u32,
    pub attempts: u16,
    pub class: u8,
    pub notified: bool,
    pub stamp: Stamp,
}

pub struct Attempt {
    pub queue: QueueId,
    pub tenant: u32,
    pub message: MessageId,
    pub recipients: Vec<Claimed>,
    pub stored: Opened,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answered {
    pub recipient: u32,
    pub answer: Answer,
    pub reply: Vec<u8>,
}

pub trait Transport {
    fn send(&self, attempt: Attempt) -> impl Future<Output = Vec<Answered>>;
}
