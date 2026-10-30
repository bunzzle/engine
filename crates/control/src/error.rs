use std::fmt;

#[derive(Debug)]
pub enum Error {
    Store(store::Error),
    Invalid(&'static str),
    Full,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Invalid(what) => write!(f, "invalid {what}"),
            Self::Full => write!(f, "control records over their budget"),
        }
    }
}

impl std::error::Error for Error {}

impl From<store::Error> for Error {
    fn from(e: store::Error) -> Self {
        Self::Store(e)
    }
}
