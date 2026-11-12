use std::collections::VecDeque;
use std::fmt;
use std::mem;

use dkim::base64;

use crate::address::{self, Bad};
use crate::body::{Decoder, Fault};
use crate::command::{self, Command};
use crate::reply::{self, Reply};

const COMMAND_LINE: usize = 2048;
const AUTH_LINE: usize = 12_288;
const ERRORS: u32 = 20;
const AUTH_FAILURES: u32 = 3;
const OVERSHOOT: u32 = 1000;
const CHUNK: usize = 65_536;

#[derive(Clone, Debug)]
pub struct Config {
    pub name: String,
    pub message: u64,
    pub implicit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyType {
    SevenBit,
    EightBit,
}

pub struct Secret(Vec<u8>);

impl Secret {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

#[derive(Debug)]
pub enum Event {
    Starttls,
    Auth(Secret),
    Mail {
        from: String,
        size: Option<u64>,
        body: Option<BodyType>,
    },
    Recipients(Vec<String>),
    Data,
    Body(Vec<u8>),
    End {
        lf: u64,
    },
    Reset,
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hello {
    None,
    Helo,
    Ehlo,
}

#[derive(Debug)]
enum Mode {
    Command,
    Plain,
    Login(Prompt),
    Overflow,
    Data,
    Chunk { left: u64, last: bool },
    Skip { left: u64, reply: Reply },
    Wait(Wait),
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prompt {
    User,
    Token,
}

#[derive(Debug)]
enum Wait {
    Tls,
    Auth,
    Mail,
    Recipients(Vec<Option<Reply>>),
    Data {
        chunk: Option<(u64, bool)>,
        crlf: bool,
    },
    Message,
}

#[derive(Debug, Default)]
struct Transaction {
    recipients: u32,
    live: bool,
    decoder: Option<Decoder>,
    chunked: bool,
    failed: bool,
    refusal: Option<Reply>,
    received: u64,
}

enum Line {
    Ready { end: usize, next: usize, crlf: bool },
    More,
    Long,
}

#[derive(Debug)]
pub struct Server {
    config: Config,
    mode: Mode,
    input: Vec<u8>,
    start: usize,
    output: Vec<u8>,
    events: VecDeque<Event>,
    body: Vec<u8>,
    greeted: bool,
    hello: Hello,
    tls: bool,
    authenticated: bool,
    transaction: Option<Transaction>,
    errors: u32,
    failures: u32,
    overshoot: u32,
}

impl Server {
    pub fn new(config: Config) -> Self {
        let mut output = Vec::new();
        Reply::owned(220, "", format!("{} ESMTP", config.name)).write(&mut output);
        Self {
            tls: config.implicit,
            config,
            mode: Mode::Command,
            input: Vec::new(),
            start: 0,
            output,
            events: VecDeque::new(),
            body: Vec::new(),
            greeted: false,
            hello: Hello::None,
            authenticated: false,
            transaction: None,
            errors: 0,
            failures: 0,
            overshoot: 0,
        }
    }

    pub fn input(&mut self, bytes: &[u8]) {
        match self.mode {
            Mode::Closed => return,
            Mode::Wait(Wait::Tls | Wait::Data { chunk: None, .. }) => {
                self.close(&reply::SYNC);
                return;
            }
            _ => {}
        }
        if !self.greeted {
            self.output.clear();
            self.close(&reply::SYNC);
            return;
        }
        if self.start > 0 {
            self.input.drain(..self.start);
            self.start = 0;
        }
        self.input.extend_from_slice(bytes);
    }

    pub fn output(&mut self) -> Vec<u8> {
        self.greeted = true;
        mem::take(&mut self.output)
    }

    pub fn closed(&self) -> bool {
        matches!(self.mode, Mode::Closed)
    }

    pub fn tls(&self) -> bool {
        self.tls
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn poll(&mut self) -> Option<Event> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Some(event);
            }
            if matches!(self.mode, Mode::Wait(_) | Mode::Closed) {
                return None;
            }
            if self.errors >= ERRORS {
                self.close(&reply::ERRORS);
                continue;
            }
            if self.overshoot >= OVERSHOOT {
                self.close(&reply::OVERSHOOT);
                continue;
            }
            if !self.step() {
                return None;
            }
        }
    }

    pub fn secured(&mut self) {
        if !matches!(self.mode, Mode::Wait(Wait::Tls)) {
            return;
        }
        self.tls = true;
        self.hello = Hello::None;
        self.authenticated = false;
        self.mode = Mode::Command;
    }

    pub fn auth(&mut self, answer: Result<(), Reply>) {
        if !matches!(self.mode, Mode::Wait(Wait::Auth)) {
            return;
        }
        self.mode = Mode::Command;
        match answer {
            Ok(()) => {
                self.authenticated = true;
                self.send(&reply::AUTH_OK);
            }
            Err(reply) => self.auth_failed(&reply),
        }
    }

    pub fn mail(&mut self, answer: Result<(), Reply>) {
        if !matches!(self.mode, Mode::Wait(Wait::Mail)) {
            return;
        }
        self.mode = Mode::Command;
        match answer {
            Ok(()) => {
                self.transaction = Some(Transaction {
                    live: true,
                    ..Transaction::default()
                });
                self.send(&reply::SENDER_OK);
            }
            Err(reply) => self.send(&reply),
        }
    }

    pub fn recipients(&mut self, answers: impl IntoIterator<Item = Result<(), Reply>>) {
        let Mode::Wait(Wait::Recipients(slots)) = mem::replace(&mut self.mode, Mode::Command)
        else {
            return;
        };
        let mut answers = answers.into_iter();
        for slot in slots {
            let reply = match slot {
                Some(reply) => reply,
                None => match answers.next() {
                    Some(Ok(())) => {
                        if let Some(transaction) = self.transaction.as_mut() {
                            transaction.recipients += 1;
                        }
                        reply::RECIPIENT_OK
                    }
                    Some(Err(reply)) => reply,
                    None => reply::TEMPORARY,
                },
            };
            self.send(&reply);
        }
    }

    pub fn data(&mut self, answer: Result<(), Reply>) {
        let Mode::Wait(Wait::Data { chunk, crlf }) = mem::replace(&mut self.mode, Mode::Command)
        else {
            return;
        };
        let limit = self.config.message;
        let Some(transaction) = self.transaction.as_mut() else {
            return;
        };
        match (answer, chunk) {
            (Ok(()), None) => {
                transaction.decoder = Some(Decoder::data(limit, crlf));
                self.mode = Mode::Data;
                self.send(&reply::DATA_GO);
            }
            (Ok(()), Some((left, last))) => {
                transaction.decoder = Some(Decoder::chunks(limit));
                transaction.chunked = true;
                self.mode = Mode::Chunk { left, last };
            }
            (Err(reply), None) => {
                self.release();
                self.transaction = None;
                self.send(&reply);
            }
            (Err(reply), Some((left, _))) => {
                transaction.chunked = true;
                transaction.failed = true;
                self.release();
                self.mode = Mode::Skip { left, reply };
            }
        }
    }

    pub fn refuse(&mut self, reply: Reply) {
        if !matches!(self.mode, Mode::Data | Mode::Chunk { .. }) {
            return;
        }
        let Some(transaction) = self.transaction.as_mut() else {
            return;
        };
        if let Some(decoder) = transaction.decoder.as_mut()
            && !decoder.halted()
        {
            decoder.halt();
            transaction.refusal = Some(reply);
            self.body.clear();
            self.release();
        }
    }

    pub fn message(&mut self, reply: &Reply) {
        if !matches!(self.mode, Mode::Wait(Wait::Message)) {
            return;
        }
        self.mode = Mode::Command;
        self.transaction = None;
        self.send(reply);
    }

    fn step(&mut self) -> bool {
        match self.mode {
            Mode::Command | Mode::Plain | Mode::Login(_) => self.line(),
            Mode::Overflow => self.overflow(),
            Mode::Data => self.data_bytes(),
            Mode::Chunk { left, last } => self.chunk(left, last),
            Mode::Skip { left, .. } => self.skip(left),
            Mode::Wait(_) | Mode::Closed => false,
        }
    }

    fn next_line(&self) -> Line {
        let available = &self.input[self.start..];
        match available.iter().position(|&b| b == b'\n') {
            Some(lf) => {
                let crlf = lf > 0 && available[lf - 1] == b'\r';
                let end = if crlf { lf - 1 } else { lf };
                if end > AUTH_LINE {
                    Line::Long
                } else {
                    Line::Ready {
                        end: self.start + end,
                        next: self.start + lf + 1,
                        crlf,
                    }
                }
            }
            None if available.len() > AUTH_LINE + 1 => Line::Long,
            None => Line::More,
        }
    }

    fn line(&mut self) -> bool {
        let (end, next, crlf) = match self.next_line() {
            Line::Ready { end, next, crlf } => (end, next, crlf),
            Line::More => return false,
            Line::Long => {
                self.mode = Mode::Overflow;
                return true;
            }
        };
        let line = self.input[self.start..end].to_vec();
        self.start = next;
        match self.mode {
            Mode::Plain => self.plain(&line),
            Mode::Login(prompt) => self.login(&line, prompt),
            _ => self.command(&line, crlf),
        }
        true
    }

    fn overflow(&mut self) -> bool {
        let available = &self.input[self.start..];
        if let Some(lf) = available.iter().position(|&b| b == b'\n') {
            self.start += lf + 1;
            self.mode = Mode::Command;
            self.send(&reply::LINE_TOO_LONG);
            true
        } else {
            self.start = self.input.len();
            false
        }
    }

    fn command(&mut self, line: &[u8], crlf: bool) {
        let command = match command::parse(line) {
            Ok(command) => command,
            Err(reply) => return self.send(&reply),
        };
        if line.len() > COMMAND_LINE && !matches!(command, Command::Auth { .. }) {
            return self.send(&reply::LINE_TOO_LONG);
        }
        match command {
            Command::Ehlo | Command::Helo => {
                if self.last_in_group() {
                    self.hello(matches!(command, Command::Ehlo));
                }
            }
            Command::Starttls => self.starttls(),
            Command::Auth { mechanism, initial } => self.auth_command(mechanism, initial),
            Command::Mail(args) => self.mail_command(args),
            Command::Rcpt(args) => self.rcpt_group(args),
            Command::Data => self.data_command(crlf),
            Command::Bdat { size, last } => self.bdat(size, last),
            Command::BadBdat => self.close(&reply::SYNTAX),
            Command::Rset => {
                self.reset();
                self.send(&reply::OK);
            }
            Command::Noop => self.send(&reply::OK),
            Command::Quit => self.close(&reply::BYE),
            Command::Vrfy => self.send(&reply::VRFY),
            Command::Expn => self.send(&reply::NOT_IMPLEMENTED),
            Command::Help => self.send(&reply::HELP),
        }
    }

    fn hello(&mut self, extended: bool) {
        self.reset();
        self.hello = if extended { Hello::Ehlo } else { Hello::Helo };
        if !extended {
            return self.send(&Reply::owned(250, "", self.config.name.clone()));
        }
        let mut lines = vec![self.config.name.clone(), "PIPELINING".into()];
        lines.push("ENHANCEDSTATUSCODES".into());
        if self.tls {
            lines.push("8BITMIME".into());
            lines.push("CHUNKING".into());
            lines.push(format!("SIZE {}", self.config.message));
            lines.push("AUTH PLAIN LOGIN".into());
        } else {
            lines.push("STARTTLS".into());
        }
        let last = lines.len() - 1;
        for (i, line) in lines.iter().enumerate() {
            let dash = if i == last { ' ' } else { '-' };
            self.output
                .extend_from_slice(format!("250{dash}{line}\r\n").as_bytes());
        }
    }

    fn starttls(&mut self) {
        if !self.last_in_group() {
            return;
        }
        if self.hello != Hello::Ehlo || self.tls {
            return self.send(&reply::SEQUENCE);
        }
        self.reset();
        self.send(&reply::TLS_GO);
        self.events.push_back(Event::Starttls);
        self.mode = Mode::Wait(Wait::Tls);
    }

    fn auth_command(&mut self, mechanism: &[u8], initial: Option<&[u8]>) {
        if self.hello != Hello::Ehlo || self.authenticated || self.transaction.is_some() {
            return self.send(&reply::SEQUENCE);
        }
        if !self.tls {
            return self.send(&reply::TLS_FIRST);
        }
        if mechanism.eq_ignore_ascii_case(b"PLAIN") {
            if let Some(initial) = initial {
                self.plain(initial);
            } else {
                self.output.extend_from_slice(b"334 \r\n");
                self.mode = Mode::Plain;
            }
        } else if mechanism.eq_ignore_ascii_case(b"LOGIN") {
            if let Some(initial) = initial {
                self.login(initial, Prompt::User);
            } else {
                self.output.extend_from_slice(b"334 VXNlcm5hbWU6\r\n");
                self.mode = Mode::Login(Prompt::User);
            }
        } else {
            self.send(&reply::MECHANISM);
        }
    }

    fn response(&mut self, line: &[u8]) -> Option<Vec<u8>> {
        self.mode = Mode::Command;
        if line == b"*" {
            self.send(&reply::AUTH_CANCELLED);
            return None;
        }
        let decoded = (!line.contains(&b' ') && line.len() <= AUTH_LINE)
            .then(|| base64::decode(line))
            .flatten();
        if decoded.is_none() {
            self.send(&reply::AUTH_SYNTAX);
        }
        decoded
    }

    fn plain(&mut self, line: &[u8]) {
        let Some(decoded) = self.response(line) else {
            return;
        };
        let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
        let [authorize, user, token] = parts.as_slice() else {
            return self.send(&reply::AUTH_SYNTAX);
        };
        if user.is_empty() || token.is_empty() {
            return self.send(&reply::AUTH_SYNTAX);
        }
        if !authorize.is_empty() && authorize != user {
            return self.auth_failed(&reply::AUTH_FAILED);
        }
        self.events.push_back(Event::Auth(Secret(token.to_vec())));
        self.mode = Mode::Wait(Wait::Auth);
    }

    fn login(&mut self, line: &[u8], prompt: Prompt) {
        let Some(decoded) = self.response(line) else {
            return;
        };
        if decoded.is_empty() {
            return self.send(&reply::AUTH_SYNTAX);
        }
        if prompt == Prompt::Token {
            self.events.push_back(Event::Auth(Secret(decoded)));
            self.mode = Mode::Wait(Wait::Auth);
        } else {
            self.output.extend_from_slice(b"334 UGFzc3dvcmQ6\r\n");
            self.mode = Mode::Login(Prompt::Token);
        }
    }

    fn auth_failed(&mut self, reply: &Reply) {
        if reply.code() >= 500 {
            self.failures += 1;
        }
        self.send(reply);
        if self.failures >= AUTH_FAILURES {
            self.close(&reply::AUTH_FAILURES);
        }
    }

    fn mail_command(&mut self, args: &[u8]) {
        if self.hello == Hello::None || self.transaction.is_some() {
            return self.send(&reply::SEQUENCE);
        }
        if !self.tls {
            return self.send(&reply::TLS_FIRST);
        }
        if !self.authenticated {
            return self.send(&reply::AUTH_FIRST);
        }
        let path = match address::path(args) {
            Ok(path) => path,
            Err(Bad::Syntax) => return self.send(&reply::SENDER_SYNTAX),
            Err(Bad::Utf8) => return self.send(&reply::UTF8),
        };
        let mut size = None;
        let mut body = None;
        for (keyword, value) in &path.params {
            match (keyword.as_str(), value) {
                ("SIZE", Some(value)) => {
                    let Some(value) = std::str::from_utf8(value)
                        .ok()
                        .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))
                        .and_then(|v| v.parse::<u64>().ok())
                    else {
                        return self.send(&reply::SYNTAX);
                    };
                    if value > self.config.message {
                        return self.send(&reply::TOO_BIG);
                    }
                    size = Some(value);
                }
                ("BODY", Some(value)) if value.eq_ignore_ascii_case(b"7BIT") => {
                    body = Some(BodyType::SevenBit);
                }
                ("BODY", Some(value)) if value.eq_ignore_ascii_case(b"8BITMIME") => {
                    body = Some(BodyType::EightBit);
                }
                _ => return self.send(&reply::PARAMETER),
            }
        }
        let Some(from) = path.mailbox else {
            return self.send(&reply::NULL_SENDER);
        };
        self.events.push_back(Event::Mail { from, size, body });
        self.mode = Mode::Wait(Wait::Mail);
    }

    fn recipient(&self, args: &[u8]) -> Result<String, Reply> {
        if self.transaction.as_ref().is_none_or(|t| t.chunked) {
            return Err(reply::SEQUENCE);
        }
        match address::path(args) {
            Ok(path) if !path.params.is_empty() => Err(reply::PARAMETER),
            Ok(path) => path.mailbox.ok_or(reply::RECIPIENT_SYNTAX),
            Err(Bad::Syntax) => Err(reply::RECIPIENT_SYNTAX),
            Err(Bad::Utf8) => Err(reply::UTF8),
        }
    }

    fn rcpt_group(&mut self, first: &[u8]) {
        let mut slots = Vec::new();
        let mut addresses = Vec::new();
        let mut found = self.recipient(first);
        loop {
            match found {
                Ok(address) => {
                    addresses.push(address);
                    slots.push(None);
                }
                Err(reply) => slots.push(Some(reply)),
            }
            let Line::Ready { end, next, .. } = self.next_line() else {
                break;
            };
            let line = &self.input[self.start..end];
            let Ok(Command::Rcpt(args)) = command::parse(line) else {
                break;
            };
            if line.len() > COMMAND_LINE {
                break;
            }
            found = self.recipient(args);
            self.start = next;
        }
        if addresses.is_empty() {
            for reply in slots.into_iter().flatten() {
                self.send(&reply);
            }
        } else {
            self.events.push_back(Event::Recipients(addresses));
            self.mode = Mode::Wait(Wait::Recipients(slots));
        }
    }

    fn data_command(&mut self, crlf: bool) {
        if !self.last_in_group() {
            return;
        }
        let Some(transaction) = self.transaction.as_ref() else {
            return self.send(&reply::SEQUENCE);
        };
        if transaction.chunked {
            return self.send(&reply::SEQUENCE);
        }
        if transaction.recipients == 0 {
            return self.send(&reply::NO_RECIPIENTS);
        }
        self.events.push_back(Event::Data);
        self.mode = Mode::Wait(Wait::Data { chunk: None, crlf });
    }

    fn bdat(&mut self, size: u64, last: bool) {
        let received = self.transaction.as_ref().map_or(0, |t| t.received);
        if size > self.config.message.saturating_sub(received) {
            return self.close(&reply::TOO_BIG);
        }
        let refusal = match self.transaction.as_ref() {
            None => Some(reply::SEQUENCE),
            Some(t) if t.failed => Some(reply::SEQUENCE),
            Some(t) if t.recipients == 0 => Some(reply::NO_RECIPIENTS),
            Some(_) => None,
        };
        if let Some(reply) = refusal {
            self.mode = Mode::Skip { left: size, reply };
        } else if self.transaction.as_ref().is_some_and(|t| t.chunked) {
            self.mode = Mode::Chunk { left: size, last };
        } else {
            self.events.push_back(Event::Data);
            self.mode = Mode::Wait(Wait::Data {
                chunk: Some((size, last)),
                crlf: true,
            });
        }
    }

    fn data_bytes(&mut self) -> bool {
        let available = self.input.len() - self.start;
        if available == 0 {
            return false;
        }
        let take = available.min(CHUNK);
        let Some(transaction) = self.transaction.as_mut() else {
            return false;
        };
        let Some(decoder) = transaction.decoder.as_mut() else {
            return false;
        };
        let (used, done) = decoder.feed(&self.input[self.start..self.start + take], &mut self.body);
        self.start += used;
        let halted = decoder.halted();
        let over = decoder.discarded() > self.config.message;
        let lf = decoder.lf();
        let fault = decoder.fault();
        if halted {
            self.body.clear();
            self.release();
        }
        if over {
            self.close(&reply::DISCARD);
            return true;
        }
        if !done {
            if self.body.len() >= CHUNK || self.start == self.input.len() {
                self.flush();
            }
            return true;
        }
        if halted {
            let reply = self.halted_reply(fault);
            self.transaction = None;
            self.mode = Mode::Command;
            self.send(&reply);
        } else {
            self.flush();
            self.events.push_back(Event::End { lf });
            self.mode = Mode::Wait(Wait::Message);
        }
        true
    }

    fn chunk(&mut self, left: u64, last: bool) -> bool {
        let Some(transaction) = self.transaction.as_mut() else {
            return false;
        };
        let Some(decoder) = transaction.decoder.as_mut() else {
            return false;
        };
        let mut left = left;
        if left > 0 {
            let available = self.input.len() - self.start;
            if available == 0 {
                return false;
            }
            let take = available
                .min(CHUNK)
                .min(usize::try_from(left).unwrap_or(usize::MAX));
            decoder.feed(&self.input[self.start..self.start + take], &mut self.body);
            self.start += take;
            left -= take as u64;
            transaction.received += take as u64;
        }
        if left == 0 && last {
            decoder.finish(&mut self.body);
        }
        let halted = decoder.halted();
        let lf = decoder.lf();
        let fault = decoder.fault();
        if halted {
            self.body.clear();
            self.release();
        }
        if left > 0 {
            self.mode = Mode::Chunk { left, last };
            if self.body.len() >= CHUNK || self.start == self.input.len() {
                self.flush();
            }
            return true;
        }
        self.mode = Mode::Command;
        if halted {
            let reply = self.halted_reply(fault);
            if let Some(transaction) = self.transaction.as_mut() {
                transaction.failed = true;
            }
            self.send(&reply);
        } else if last {
            self.flush();
            self.events.push_back(Event::End { lf });
            self.mode = Mode::Wait(Wait::Message);
        } else {
            self.flush();
            self.send(&reply::OK);
        }
        true
    }

    fn skip(&mut self, left: u64) -> bool {
        let available = self.input.len() - self.start;
        let take = available.min(usize::try_from(left).unwrap_or(usize::MAX));
        self.start += take;
        let left = left - take as u64;
        if let Some(transaction) = self.transaction.as_mut() {
            transaction.received += take as u64;
        }
        match &mut self.mode {
            Mode::Skip { left: l, .. } if left > 0 => {
                *l = left;
                false
            }
            _ => {
                if let Mode::Skip { reply, .. } = mem::replace(&mut self.mode, Mode::Command) {
                    self.send(&reply);
                }
                true
            }
        }
    }

    fn halted_reply(&self, fault: Option<Fault>) -> Reply {
        self.transaction
            .as_ref()
            .and_then(|t| t.refusal.clone())
            .or_else(|| fault.map(Fault::reply))
            .unwrap_or(reply::TEMPORARY)
    }

    fn flush(&mut self) {
        if !self.body.is_empty() {
            self.events
                .push_back(Event::Body(mem::take(&mut self.body)));
        }
    }

    fn release(&mut self) {
        if let Some(transaction) = self.transaction.as_mut()
            && mem::take(&mut transaction.live)
        {
            self.events.push_back(Event::Reset);
        }
    }

    fn reset(&mut self) {
        self.release();
        self.transaction = None;
    }

    fn last_in_group(&mut self) -> bool {
        if self.start < self.input.len() {
            self.close(&reply::SYNC);
            return false;
        }
        true
    }

    fn send(&mut self, reply: &Reply) {
        reply.write(&mut self.output);
        if reply.code() == 421 {
            self.shut();
        } else if reply.overshoot() {
            self.overshoot += 1;
        } else if reply.failure() {
            self.errors += 1;
        }
    }

    fn close(&mut self, reply: &Reply) {
        reply.write(&mut self.output);
        self.shut();
    }

    fn shut(&mut self) {
        if self.closed() {
            return;
        }
        self.mode = Mode::Closed;
        self.transaction = None;
        self.body.clear();
        self.input.clear();
        self.start = 0;
        self.events.push_back(Event::Close);
    }
}
