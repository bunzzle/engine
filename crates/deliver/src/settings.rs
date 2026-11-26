use std::net::IpAddr;
use std::time::Duration;

use crate::address::Cidr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EightBit {
    Send,
    Fail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    pub connect: Duration,
    pub banner: Duration,
    pub ehlo: Duration,
    pub starttls: Duration,
    pub rset: Duration,
    pub command: Duration,
    pub body: Duration,
    pub final_reply: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            banner: Duration::from_secs(300),
            ehlo: Duration::from_secs(300),
            starttls: Duration::from_secs(300),
            rset: Duration::from_secs(20),
            command: Duration::from_secs(300),
            body: Duration::from_secs(180),
            final_reply: Duration::from_secs(600),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reporter {
    pub from: String,
    pub organization: String,
    pub contact: String,
    pub submitter: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Site {
    pub name: String,
    pub suffixes: Vec<String>,
    pub rate: Option<u32>,
    pub burst: u32,
    pub connect_rate: Option<u32>,
    pub reuse: Option<u32>,
}

impl Site {
    pub fn new(name: impl Into<String>, suffixes: Vec<String>) -> Self {
        Self {
            name: name.into(),
            suffixes,
            rate: None,
            burst: 1,
            connect_rate: None,
            reuse: None,
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        self.suffixes.iter().any(|suffix| {
            host == suffix
                || host
                    .strip_suffix(suffix.as_str())
                    .is_some_and(|head| head.ends_with('.'))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warmup {
    pub egress: IpAddr,
    pub from: u64,
    pub caps: Vec<u32>,
}

impl Warmup {
    pub fn cap(&self, today: u64) -> Option<u32> {
        let index = usize::try_from(today.saturating_sub(self.from)).unwrap_or(usize::MAX);
        self.caps.get(index).copied()
    }
}

pub fn default_caps() -> Vec<u32> {
    (0..12).map(|day| 50u32 << day).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub ehlo: String,
    pub port: u16,
    pub deadline: Duration,
    pub timeouts: Timeouts,
    pub eight_bit: EightBit,
    pub wait: Duration,
    pub idle: Duration,
    pub reuse: u32,
    pub pooled: usize,
    pub dead: Duration,
    pub mta_sts: bool,
    pub egress: Option<IpAddr>,
    pub allow: Vec<Cidr>,
    pub nat64: Vec<Cidr>,
    pub tlsrpt: bool,
    pub report_tenant: Option<u32>,
    pub reporter: Reporter,
    pub sites: Vec<Site>,
    pub warmups: Vec<Warmup>,
}

impl Settings {
    pub fn new(ehlo: impl Into<String>) -> Self {
        Self {
            ehlo: ehlo.into(),
            port: 25,
            deadline: Duration::from_secs(540),
            timeouts: Timeouts::default(),
            eight_bit: EightBit::Send,
            wait: Duration::from_secs(5),
            idle: Duration::from_secs(5),
            reuse: 100,
            pooled: 1000,
            dead: Duration::from_secs(60),
            mta_sts: false,
            egress: None,
            allow: Vec::new(),
            nat64: Vec::new(),
            tlsrpt: false,
            report_tenant: None,
            reporter: Reporter::default(),
            sites: Vec::new(),
            warmups: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{Warmup, default_caps};

    fn warmup(caps: Vec<u32>) -> Warmup {
        Warmup {
            egress: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            from: 100,
            caps,
        }
    }

    #[test]
    fn default_caps_double_from_fifty_for_twelve_days() {
        let caps = default_caps();
        assert_eq!(caps.len(), 12);
        assert_eq!(caps[0], 50);
        assert_eq!(caps[11], 102_400);
        for pair in caps.windows(2) {
            assert_eq!(pair[1], pair[0] * 2);
        }
    }

    #[test]
    fn cap_follows_the_schedule_from_the_start_day() {
        let warmup = warmup(vec![7, 14, 28]);
        assert_eq!(warmup.cap(99), Some(7));
        assert_eq!(warmup.cap(100), Some(7));
        assert_eq!(warmup.cap(101), Some(14));
        assert_eq!(warmup.cap(102), Some(28));
        assert_eq!(warmup.cap(103), None);
        assert_eq!(warmup.cap(u64::MAX), None);
    }
}
