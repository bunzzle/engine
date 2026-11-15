use std::mem;
use std::time::Duration;

use crate::body::Decoder;
use crate::date::imf;
use crate::request::{self, Framing, Request};
use crate::response::Response;
use crate::status::Status;

pub const CHUNK: usize = 65_536;

fn has_body(framing: Framing) -> bool {
    !matches!(framing, Framing::None | Framing::Length(0))
}
const LEADING_LINES: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub line: usize,
    pub head: usize,
    pub fields: usize,
    pub requests: u32,
    pub extension: usize,
    pub trailers: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            line: 8192,
            head: 16_384,
            fields: 64,
            requests: 1000,
            extension: 256,
            trailers: 4096,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    pub handshake: Duration,
    pub head: Duration,
    pub body: Duration,
    pub idle: Duration,
    pub grace: Duration,
    pub rate: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            head: Duration::from_secs(10),
            body: Duration::from_secs(30),
            idle: Duration::from_secs(60),
            grace: Duration::from_secs(30),
            rate: 65_536,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Head,
    Body,
    Handler,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Request(Request),
    Body(Vec<u8>),
    End,
    Fault(Status),
}

#[derive(Debug)]
enum Mode {
    Head,
    Request(Framing),
    Body(Decoder),
    Ended,
    Fault,
    Closed,
}

#[derive(Debug)]
pub struct Server {
    limits: Limits,
    mode: Mode,
    input: Vec<u8>,
    start: usize,
    scan: usize,
    line: usize,
    lines: usize,
    leading: u32,
    output: Vec<u8>,
    requests: u32,
    close: bool,
    expect: bool,
    head_only: bool,
}

impl Server {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            mode: Mode::Head,
            input: Vec::new(),
            start: 0,
            scan: 0,
            line: 0,
            lines: 0,
            leading: 0,
            output: Vec::new(),
            requests: 0,
            close: false,
            expect: false,
            head_only: false,
        }
    }

    pub fn input(&mut self, bytes: &[u8]) {
        if matches!(self.mode, Mode::Closed) {
            return;
        }
        if self.start > 0 {
            self.input.drain(..self.start);
            self.scan = self.scan.saturating_sub(self.start);
            self.line = self.line.saturating_sub(self.start);
            self.start = 0;
        }
        self.input.extend_from_slice(bytes);
    }

    pub fn wants_input(&self) -> bool {
        match self.mode {
            Mode::Head => self.input.len() - self.start < self.limits.head,
            Mode::Body(_) => self.input.len() - self.start < CHUNK,
            _ => false,
        }
    }

    pub fn phase(&self) -> Phase {
        match self.mode {
            Mode::Head if self.requests > 0 && self.start == self.input.len() => Phase::Idle,
            Mode::Head => Phase::Head,
            Mode::Body(_) => Phase::Body,
            Mode::Request(_) | Mode::Ended | Mode::Fault => Phase::Handler,
            Mode::Closed => Phase::Closed,
        }
    }

    pub fn closed(&self) -> bool {
        matches!(self.mode, Mode::Closed)
    }

    pub fn output(&mut self) -> Vec<u8> {
        mem::take(&mut self.output)
    }

    pub fn event(&mut self) -> Option<Event> {
        match &mut self.mode {
            Mode::Head => self.head().map(|result| match result {
                Ok(request) => {
                    self.close = request.close;
                    self.expect = request.expect;
                    self.head_only = request.method == "HEAD";
                    self.mode = Mode::Request(request.body);
                    Event::Request(request)
                }
                Err(status) => self.fault(status),
            }),
            Mode::Body(decoder) => {
                let mut out = Vec::new();
                match decoder.feed(&self.input[self.start..], &mut out, CHUNK) {
                    Ok(used) => self.start += used,
                    Err(status) => return Some(self.fault(status)),
                }
                if !out.is_empty() {
                    Some(Event::Body(out))
                } else if decoder.done() {
                    self.mode = Mode::Ended;
                    Some(Event::End)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn accept_body(&mut self, limit: u64) -> Result<(), Status> {
        let Mode::Request(framing) = self.mode else {
            return Err(Status::INTERNAL);
        };
        let decoder = match framing {
            Framing::None => Decoder::length(0),
            Framing::Length(n) if n > limit => {
                self.mode = Mode::Fault;
                return Err(Status::TOO_LARGE);
            }
            Framing::Length(n) => Decoder::length(n),
            Framing::Chunked => {
                Decoder::chunked(limit, self.limits.extension, self.limits.trailers)
            }
        };
        if self.expect && has_body(framing) {
            self.output
                .extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        self.mode = Mode::Body(decoder);
        Ok(())
    }

    pub fn respond(&mut self, response: &Response, now: u64) {
        if matches!(self.mode, Mode::Closed) {
            return;
        }
        let complete = match self.mode {
            Mode::Ended => true,
            Mode::Request(framing) => !has_body(framing),
            Mode::Head => self.start == self.input.len(),
            _ => false,
        };
        self.requests += 1;
        let close =
            !complete || self.close || response.closes() || self.requests >= self.limits.requests;
        response.write(&imf(now), close, self.head_only, &mut self.output);
        if close {
            self.mode = Mode::Closed;
            self.input.clear();
            self.start = 0;
            return;
        }
        self.mode = Mode::Head;
        self.close = false;
        self.expect = false;
        self.head_only = false;
        self.scan = self.start;
        self.line = self.start;
        self.lines = 0;
        self.leading = 0;
    }

    fn fault(&mut self, status: Status) -> Event {
        self.mode = Mode::Fault;
        Event::Fault(status)
    }

    fn head(&mut self) -> Option<Result<Request, Status>> {
        loop {
            let Some(found) = self.input[self.scan..].iter().position(|&b| b == b'\n') else {
                self.scan = self.input.len();
                return self.partial().map(Err);
            };
            let end = self.scan + found;
            self.scan = end + 1;
            if end == self.line || self.input[end - 1] != b'\r' {
                return Some(Err(Status::BAD_REQUEST));
            }
            let length = end - 1 - self.line;
            if self.lines == 0 && length == 0 {
                self.leading += 1;
                if self.leading > LEADING_LINES {
                    return Some(Err(Status::BAD_REQUEST));
                }
                self.start = self.scan;
                self.line = self.scan;
                continue;
            }
            if self.lines == 0 && length > self.limits.line {
                return Some(Err(Status::URI_TOO_LONG));
            }
            if self.scan - self.start > self.limits.head {
                return Some(Err(Status::HEADERS_TOO_LARGE));
            }
            self.line = self.scan;
            if length == 0 {
                let head = &self.input[self.start..self.scan];
                let result = request::parse(head);
                self.start = self.scan;
                return Some(result);
            }
            self.lines += 1;
            if self.lines > self.limits.fields + 1 {
                return Some(Err(Status::HEADERS_TOO_LARGE));
            }
        }
    }

    fn partial(&self) -> Option<Status> {
        let pending = self.input.len() - self.line;
        if self.lines == 0 && pending > self.limits.line + 1 {
            Some(Status::URI_TOO_LONG)
        } else if self.input.len() - self.start > self.limits.head {
            Some(Status::HEADERS_TOO_LARGE)
        } else {
            None
        }
    }
}
