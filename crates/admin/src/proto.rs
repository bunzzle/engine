use std::fmt;

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 64 * 1024;

const LEN: usize = 4;
const STATUS: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Frame,
    Version,
    Command,
    Body,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Frame => "frame too large or empty",
            Self::Version => "unknown protocol version",
            Self::Command => "unknown command",
            Self::Body => "malformed request",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Status,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let op = match self {
            Self::Status => STATUS,
        };
        framed(&[VERSION, op])
    }

    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let (version, op, rest) = head(body)?;
        if version != VERSION {
            return Err(Error::Version);
        }
        let request = match op {
            STATUS => Self::Status,
            _ => return Err(Error::Command),
        };
        if !rest.is_empty() {
            return Err(Error::Body);
        }
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Ok,
    Refused,
    NotFound,
    Busy,
    Failed,
}

impl Code {
    fn byte(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Refused => 1,
            Self::NotFound => 2,
            Self::Busy => 3,
            Self::Failed => 4,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Ok,
            1 => Self::Refused,
            2 => Self::NotFound,
            3 => Self::Busy,
            4 => Self::Failed,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: Code,
    pub text: String,
}

impl Reply {
    pub fn new(code: Code, text: impl Into<String>) -> Self {
        Self {
            code,
            text: text.into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let room = MAX_FRAME - 2;
        let mut end = self.text.len().min(room);
        while !self.text.is_char_boundary(end) {
            end -= 1;
        }
        let mut body = Vec::with_capacity(2 + end);
        body.extend_from_slice(&[VERSION, self.code.byte()]);
        body.extend_from_slice(&self.text.as_bytes()[..end]);
        framed(&body)
    }

    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let (version, code, rest) = head(body)?;
        if version != VERSION {
            return Err(Error::Version);
        }
        let code = Code::from_byte(code).ok_or(Error::Body)?;
        let text = std::str::from_utf8(rest).map_err(|_| Error::Body)?;
        Ok(Self::new(code, text))
    }
}

fn head(body: &[u8]) -> Result<(u8, u8, &[u8]), Error> {
    match body {
        [version, op, rest @ ..] => Ok((*version, *op, rest)),
        _ => Err(Error::Body),
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).expect("frame fits");
    let mut out = Vec::with_capacity(LEN + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[derive(Default)]
pub struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn pop(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let Some(len) = self.buf.first_chunk::<LEN>() else {
            return Ok(None);
        };
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| Error::Frame)?;
        if len == 0 || len > MAX_FRAME {
            return Err(Error::Frame);
        }
        if self.buf.len() < LEN + len {
            return Ok(None);
        }
        let body = self.buf[LEN..LEN + len].to_vec();
        self.buf.drain(..LEN + len);
        Ok(Some(body))
    }
}
