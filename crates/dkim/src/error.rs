use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Line,
    Empty,
    Continuation,
    Colon,
    Name,
    Tag,
    Missing(&'static str),
    Domain,
    Selector,
    Expiry,
    Unsigned,
    Version,
    Algorithm,
    Canonicalization,
    Length,
    Base64,
    BodyHash,
    From,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Line => write!(f, "header line does not end in CRLF"),
            Self::Empty => write!(f, "empty line inside the header section"),
            Self::Continuation => write!(f, "header section starts with a continuation line"),
            Self::Colon => write!(f, "header line without a colon"),
            Self::Name => write!(f, "bad header field name"),
            Self::Tag => write!(f, "bad signature tag list"),
            Self::Missing(tag) => write!(f, "signature tag {tag}= missing"),
            Self::Domain => write!(f, "bad signing domain"),
            Self::Selector => write!(f, "bad selector"),
            Self::Expiry => write!(f, "expiry not after the signing time"),
            Self::Unsigned => write!(f, "field does not end in an empty b= tag"),
            Self::Version => write!(f, "unsupported signature version"),
            Self::Algorithm => write!(f, "unsupported signature algorithm"),
            Self::Canonicalization => write!(f, "unsupported canonicalization"),
            Self::Length => write!(f, "body length tag not accepted"),
            Self::Base64 => write!(f, "bad base64"),
            Self::BodyHash => write!(f, "body hash does not match"),
            Self::From => write!(f, "from field not signed"),
        }
    }
}

impl std::error::Error for Error {}
