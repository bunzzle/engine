use std::fmt;

use crate::queue::KeyError;

#[derive(Debug)]
pub enum Error {
    Store(store::Error),
    Invalid(&'static str),
    Full,
    Refused,
    Busy,
    Keys {
        tenant: u32,
        generation: u32,
        error: KeyError,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Invalid(what) => write!(f, "invalid {what}"),
            Self::Full => write!(f, "control records over their budget"),
            Self::Refused => write!(f, "refused"),
            Self::Busy => write!(f, "over the limit, try again later"),
            Self::Keys {
                tenant,
                generation,
                error,
            } => {
                let what = match error {
                    KeyError::Unavailable => "unavailable",
                    KeyError::Unknown => "unknown",
                    KeyError::Failed => "failed",
                    KeyError::Conflict => "held by another generation",
                };
                write!(f, "keys {what} for tenant {tenant} generation {generation}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<store::Error> for Error {
    fn from(e: store::Error) -> Self {
        Self::Store(e)
    }
}
