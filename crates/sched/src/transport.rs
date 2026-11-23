use std::net::IpAddr;

use spool::{MessageId, Stamp};

use crate::events::Written;
use crate::lanes::QueueId;
use crate::policy::Answer;
use crate::sign::Outgoing;
use crate::system::Restore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claimed {
    pub recipient: u32,
    pub attempts: u16,
    pub class: u8,
    pub notified: bool,
    pub stamp: Stamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub domain: Box<str>,
    pub pool: u32,
    pub egress: Vec<(IpAddr, u16)>,
}

pub struct Attempt {
    pub queue: QueueId,
    pub tenant: u32,
    pub message: MessageId,
    pub destination: Destination,
    pub recipients: Vec<Claimed>,
    pub outgoing: Outgoing,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnStats {
    pub ipv4_off: bool,
    pub ipv6_off: bool,
    pub unclear: u64,
    pub partly_refused: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answered {
    pub recipient: u32,
    pub answer: Answer,
    pub reply: Vec<u8>,
    pub event: Option<Written>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportMail {
    pub day: u64,
    pub domain: String,
    pub from: String,
    pub to: Vec<String>,
    pub message: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reported {
    Sent,
    Dropped,
    Failed,
}

pub trait Transport {
    fn send(&self, attempt: Attempt) -> impl Future<Output = Vec<Answered>>;

    fn restore(&self, restore: Restore) -> impl Future<Output = ()> {
        drop(restore);
        std::future::ready(())
    }

    fn tick(&self) -> impl Future<Output = ()> {
        std::future::ready(())
    }

    fn reports(&self) -> impl Future<Output = Vec<ReportMail>> {
        std::future::ready(Vec::new())
    }

    fn reported(&self, day: u64, domain: &str, done: Reported) {
        let _ = (day, domain, done);
    }

    fn probe_own(&self) -> impl Future<Output = OwnStats> {
        std::future::ready(OwnStats::default())
    }

    fn own_stats(&self) -> OwnStats {
        OwnStats::default()
    }
}
