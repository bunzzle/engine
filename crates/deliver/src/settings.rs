use std::time::Duration;

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
        }
    }
}
