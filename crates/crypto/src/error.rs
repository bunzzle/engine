use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Open,
    Format(&'static str),
    Order,
    Random,
    Key,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "sealed data did not open"),
            Self::Format(what) => write!(f, "bad sealed {what}"),
            Self::Order => write!(f, "stream chunk out of order"),
            Self::Random => write!(f, "random source failed"),
            Self::Key => write!(f, "key rejected"),
        }
    }
}

impl std::error::Error for Error {}
