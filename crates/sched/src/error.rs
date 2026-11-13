use std::fmt;

#[derive(Debug)]
pub enum Error {
    Spool(spool::Error),
    Control(control::Error),
    Naming,
    Node,
    Closed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spool(e) => write!(f, "{e}"),
            Self::Control(e) => write!(f, "{e}"),
            Self::Naming => write!(f, "naming key does not match this spool"),
            Self::Node => write!(f, "node id does not match this spool"),
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
    Conflict,
    Recipients,
    Message,
    Busy,
    Keys,
    Signer,
    Failed,
}

impl Refusal {
    pub fn temporary(self) -> bool {
        matches!(self, Self::Busy | Self::Keys | Self::Failed)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Self::Tenant => "tenant not active",
            Self::Pool => "pool not allowed",
            Self::Address => "invalid recipient address",
            Self::Suppressed => "recipient suppressed",
            Self::Conflict => "idempotency key used with another request",
            Self::Recipients => "too many recipients",
            Self::Message => "message does not match its recipients",
            Self::Busy => "over the limit, try again later",
            Self::Keys => "tenant keys unavailable, try again later",
            Self::Signer => "signing key not found",
            Self::Failed => "temporary failure",
        };
        f.write_str(what)
    }
}
