use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    TooLarge,
    NoCertificate,
    NoKey,
    Pem,
    Tls(rustls::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::TooLarge => write!(f, "file too large"),
            Self::NoCertificate => write!(f, "no certificate found"),
            Self::NoKey => write!(f, "no private key found"),
            Self::Pem => write!(f, "malformed PEM"),
            Self::Tls(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}
