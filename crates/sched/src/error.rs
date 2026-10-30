use std::fmt;

#[derive(Debug)]
pub enum Error {
    Spool(spool::Error),
    Control(control::Error),
    Closed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spool(e) => write!(f, "{e}"),
            Self::Control(e) => write!(f, "{e}"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<spool::Error> for Error {
    fn from(e: spool::Error) -> Self {
        Self::Spool(e)
    }
}

impl From<control::Error> for Error {
    fn from(e: control::Error) -> Self {
        Self::Control(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Tenant,
    Pool,
    Address,
    Suppressed,
    Recipients,
    Message,
    Busy,
    Failed,
}

impl Refusal {
    pub fn temporary(self) -> bool {
        matches!(self, Self::Busy | Self::Failed)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Self::Tenant => "tenant not active",
            Self::Pool => "pool not allowed",
            Self::Address => "invalid recipient address",
            Self::Suppressed => "recipient suppressed",
            Self::Recipients => "too many recipients",
            Self::Message => "message does not match its recipients",
            Self::Busy => "over the limit, try again later",
            Self::Failed => "temporary failure",
        };
        f.write_str(what)
    }
}
