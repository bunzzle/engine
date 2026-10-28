use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Failed,
    Config(&'static str),
    NotFormatted,
    QuorumLost,
    Fork,
    ParentNotConnected,
    SequenceSkipped,
    Invalid(&'static str),
    UnsupportedSectorSize(u32),
    SectorSizeChanged { stored: u32, found: u32 },
    SizeChanged { stored: u64, found: u64 },
    FormatTooNew(u16),
    FormatTooOld(u16),
    Reserve,
    Full,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Failed => f.write_str("data file failed; restart required"),
            Self::Config(why) => write!(f, "invalid options: {why}"),
            Self::NotFormatted => f.write_str("no valid superblock found"),
            Self::QuorumLost => f.write_str("superblock quorum lost"),
            Self::Fork => f.write_str("superblock copies disagree at the same sequence"),
            Self::ParentNotConnected => {
                f.write_str("newest superblock does not chain to its parent")
            }
            Self::SequenceSkipped => f.write_str("superblock sequence skipped"),
            Self::Invalid(why) => write!(f, "invalid superblock: {why}"),
            Self::UnsupportedSectorSize(size) => write!(f, "unsupported sector size {size}"),
            Self::SectorSizeChanged { stored, found } => {
                write!(f, "sector size changed from {stored} to {found}")
            }
            Self::SizeChanged { stored, found } => {
                write!(f, "data file size changed from {stored} to {found}")
            }
            Self::FormatTooNew(format) => write!(f, "format {format} is newer than supported"),
            Self::FormatTooOld(format) => write!(f, "format {format} is older than supported"),
            Self::Reserve => f.write_str("free-space reserve reached"),
            Self::Full => f.write_str("no free region"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
