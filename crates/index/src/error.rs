use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Corrupt(&'static str),
    Order,
    Shape,
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt(what) => write!(f, "corrupt index {what}"),
            Self::Order => write!(f, "index keys out of order"),
            Self::Shape => write!(f, "index value of the wrong size"),
            Self::TooLarge => write!(f, "index payload too large"),
        }
    }
}

impl std::error::Error for Error {}
