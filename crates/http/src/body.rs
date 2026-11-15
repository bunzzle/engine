use crate::request::{field, field_byte};
use crate::status::Status;

const SIZE_DIGITS: u32 = 16;

#[derive(Debug)]
enum State {
    Size { digits: u32, value: u64 },
    Extension,
    SizeEnd { value: u64 },
    Data { left: u64 },
    DataCr,
    DataLf,
    Trailer,
    TrailerEnd,
    LastEnd,
    Done,
}

#[derive(Debug)]
pub(crate) enum Decoder {
    Length { left: u64 },
    Chunked(Chunked),
}

#[derive(Debug)]
pub(crate) struct Chunked {
    state: State,
    limit: u64,
    total: u64,
    size: u64,
    extension: usize,
    extension_cap: usize,
    trailer: Vec<u8>,
    trailers: usize,
    trailer_cap: usize,
}

impl Decoder {
    pub(crate) fn length(left: u64) -> Self {
        Self::Length { left }
    }

    pub(crate) fn chunked(limit: u64, extension_cap: usize, trailer_cap: usize) -> Self {
        Self::Chunked(Chunked {
            state: State::Size {
                digits: 0,
                value: 0,
            },
            limit,
            total: 0,
            size: 0,
            extension: 0,
            extension_cap,
            trailer: Vec::new(),
            trailers: 0,
            trailer_cap,
        })
    }

    pub(crate) fn done(&self) -> bool {
        match self {
            Self::Length { left } => *left == 0,
            Self::Chunked(chunked) => matches!(chunked.state, State::Done),
        }
    }

    pub(crate) fn feed(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        room: usize,
    ) -> Result<usize, Status> {
        match self {
            Self::Length { left } => {
                let take = take(*left, input.len(), room);
                out.extend_from_slice(&input[..take]);
                *left -= take as u64;
                Ok(take)
            }
            Self::Chunked(chunked) => chunked.feed(input, out, room),
        }
    }
}

fn take(left: u64, available: usize, room: usize) -> usize {
    usize::try_from(left).map_or(available.min(room), |left| left.min(available).min(room))
}

fn hex(b: u8) -> Option<u64> {
    char::from(b).to_digit(16).map(u64::from)
}

impl Chunked {
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>, room: usize) -> Result<usize, Status> {
        let start = out.len();
        let mut used = 0;
        while used < input.len() {
            let b = input[used];
            match self.state {
                State::Data { left } => {
                    let space = room - (out.len() - start);
                    if space == 0 {
                        break;
                    }
                    let n = take(left, input.len() - used, space);
                    out.extend_from_slice(&input[used..used + n]);
                    used += n;
                    let left = left - n as u64;
                    self.state = if left == 0 {
                        State::DataCr
                    } else {
                        State::Data { left }
                    };
                    continue;
                }
                State::Done => break,
                _ => self.step(b)?,
            }
            used += 1;
        }
        Ok(used)
    }

    fn step(&mut self, b: u8) -> Result<(), Status> {
        self.state = match self.state {
            State::Size { digits, value } => match (hex(b), b) {
                (Some(d), _) if digits < SIZE_DIGITS => State::Size {
                    digits: digits + 1,
                    value: value * 16 + d,
                },
                (None, b';' | b' ' | b'\t') if digits > 0 => {
                    self.size = value;
                    self.extension = 1;
                    State::Extension
                }
                (None, b'\r') if digits > 0 => State::SizeEnd { value },
                _ => return Err(Status::BAD_REQUEST),
            },
            State::Extension => match b {
                b'\r' => State::SizeEnd { value: self.size },
                b'\n' => return Err(Status::BAD_REQUEST),
                _ if field_byte(b) && self.extension < self.extension_cap => {
                    self.extension += 1;
                    State::Extension
                }
                _ => return Err(Status::BAD_REQUEST),
            },
            State::SizeEnd { value } if b == b'\n' => self.chunk(value)?,
            State::DataCr if b == b'\r' => State::DataLf,
            State::DataLf if b == b'\n' => State::Size {
                digits: 0,
                value: 0,
            },
            State::Trailer => match b {
                b'\r' if self.trailer.is_empty() => State::LastEnd,
                b'\r' => {
                    if matches!(self.trailer[0], b' ' | b'\t') {
                        return Err(Status::BAD_REQUEST);
                    }
                    field(&self.trailer)?;
                    self.trailer.clear();
                    State::TrailerEnd
                }
                b'\n' => return Err(Status::BAD_REQUEST),
                _ => {
                    self.trailers += 1;
                    if self.trailers > self.trailer_cap {
                        return Err(Status::BAD_REQUEST);
                    }
                    self.trailer.push(b);
                    State::Trailer
                }
            },
            State::TrailerEnd if b == b'\n' => State::Trailer,
            State::LastEnd if b == b'\n' => State::Done,
            _ => return Err(Status::BAD_REQUEST),
        };
        Ok(())
    }

    fn chunk(&mut self, value: u64) -> Result<State, Status> {
        if value == 0 {
            return Ok(State::Trailer);
        }
        self.total = self
            .total
            .checked_add(value)
            .filter(|&total| total <= self.limit)
            .ok_or(Status::TOO_LARGE)?;
        Ok(State::Data { left: value })
    }
}
