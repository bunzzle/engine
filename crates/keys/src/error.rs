use std::{fmt, io};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io(io::ErrorKind),
    Corrupt(&'static str),
    Unreadable,
    Exists,
    Interrupted,
    Failed,
    Unknown,
    Generation,
    Pending,
    Gone,
    Retention,
    Open,
    Busy,
    Bad,
    Closed,
    Peer,
    Crypto(crypto::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<crypto::Error> for Error {
    fn from(error: crypto::Error) -> Self {
        Self::Crypto(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "key file i/o failed: {kind}"),
            Self::Corrupt(what) => write!(f, "corrupt key file {what}"),
            Self::Unreadable => write!(f, "no key file slot opens"),
            Self::Exists => write!(f, "key vault already exists"),
            Self::Interrupted => write!(f, "key vault setup was interrupted; run it again"),
            Self::Failed => write!(f, "key vault stopped after a failed write"),
            Self::Unknown => write!(f, "unknown tenant"),
            Self::Generation => write!(f, "tenant exists with another generation"),
            Self::Pending => write!(f, "tenant keys not durable yet"),
            Self::Gone => write!(f, "day key shredded"),
            Self::Retention => write!(f, "retention out of range"),
            Self::Open => write!(f, "batch key did not open"),
            Self::Busy => write!(f, "unwrap limit reached"),
            Self::Bad => write!(f, "malformed keys request"),
            Self::Closed => write!(f, "keys connection closed"),
            Self::Peer => write!(f, "keys socket belongs to another user"),
            Self::Crypto(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}
