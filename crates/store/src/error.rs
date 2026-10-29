use std::{fmt, io};

use crate::record::RecordError;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Failed,
    Config(&'static str),
    NotFormatted,
    QuorumLost,
    Fork,
    ForeignCopy,
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
    JournalFull,
    JournalFork,
    CommitTooLarge,
    Lost { sequence: u64, newer: u64 },
    BadCommit(u64),
    CheckpointLost,
    CheckpointTooLarge,
    Record(RecordError),
    NotFound,
    Damaged { region: u32, offset: u64 },
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
            Self::ForeignCopy => f.write_str("superblock copy from another data file"),
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
            Self::JournalFull => f.write_str("commit journal full"),
            Self::JournalFork => f.write_str("commit journal rings disagree"),
            Self::CommitTooLarge => f.write_str("commit record too large"),
            Self::Lost { sequence, newer } => write!(
                f,
                "commit {sequence} is damaged or missing but commit {newer} exists; acknowledged data was lost"
            ),
            Self::BadCommit(sequence) => {
                write!(f, "commit {sequence} does not match the recovered state")
            }
            Self::CheckpointLost => f.write_str("no valid checkpoint copy"),
            Self::CheckpointTooLarge => f.write_str("checkpoint does not fit in a region"),
            Self::Record(e) => e.fmt(f),
            Self::NotFound => f.write_str("record no longer exists"),
            Self::Damaged { region, offset } => {
                write!(f, "damaged data in region {region} at offset {offset}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Record(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<RecordError> for Error {
    fn from(e: RecordError) -> Self {
        Self::Record(e)
    }
}
