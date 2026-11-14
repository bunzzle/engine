use std::fmt;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Name,
    Timeout,
    ServFail,
    Refused,
    Malformed,
    Io(io::ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name => write!(f, "invalid name"),
            Self::Timeout => write!(f, "no answer in time"),
            Self::ServFail => write!(f, "server failure"),
            Self::Refused => write!(f, "query refused"),
            Self::Malformed => write!(f, "malformed answer"),
            Self::Io(kind) => write!(f, "{kind}"),
        }
    }
}

impl std::error::Error for Error {}
