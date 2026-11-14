use std::fmt::Write as _;

const MAX_LINE: usize = 4096;
const MAX_LINES: usize = 100;
const MAX_REPLY: usize = 64 * 1024;
const MAX_EXTENSIONS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub code: u16,
    pub status: Option<(u8, u16, u16)>,
    pub lines: Vec<String>,
}

impl Response {
    pub fn positive(&self) -> bool {
        (200..400).contains(&self.code)
    }

    pub fn transient(&self) -> bool {
        (400..500).contains(&self.code)
    }

    pub fn text(&self) -> String {
        let mut out = self.code.to_string();
        if let Some((class, subject, detail)) = self.status {
            let _ = write!(out, " {class}.{subject}.{detail}");
        }
        for (i, line) in self.lines.iter().enumerate() {
            out.push(if i == 0 { ' ' } else { '\n' });
            out.push_str(line);
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Syntax,
    TooLong,
}

#[derive(Default)]
pub struct Responses {
    buf: Vec<u8>,
    code: Option<u16>,
    lines: Vec<String>,
    size: usize,
    fault: Option<Fault>,
}

impl Responses {
    pub fn input(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn pending(&self) -> bool {
        !self.buf.is_empty() || self.code.is_some()
    }

    pub fn poll(&mut self) -> Option<Result<Response, Fault>> {
        if let Some(fault) = self.fault {
            return Some(Err(fault));
        }
        loop {
            let Some(end) = self.buf.iter().position(|&b| b == b'\n') else {
                if self.buf.len() > MAX_LINE {
                    return Some(Err(self.fail(Fault::TooLong)));
                }
                return None;
            };
            let mut line: Vec<u8> = self.buf.drain(..=end).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.len() > MAX_LINE {
                return Some(Err(self.fail(Fault::TooLong)));
            }
            self.size += line.len();
            if self.lines.len() >= MAX_LINES || self.size > MAX_REPLY {
                return Some(Err(self.fail(Fault::TooLong)));
            }
            match self.line(&line) {
                Err(fault) => return Some(Err(self.fail(fault))),
                Ok(Some(response)) => return Some(Ok(response)),
                Ok(None) => {}
            }
        }
    }

    fn fail(&mut self, fault: Fault) -> Fault {
        self.fault = Some(fault);
        fault
    }

    fn line(&mut self, line: &[u8]) -> Result<Option<Response>, Fault> {
        let digits = line.get(..3).ok_or(Fault::Syntax)?;
        if !digits.iter().all(u8::is_ascii_digit) || !(b'2'..=b'5').contains(&digits[0]) {
            return Err(Fault::Syntax);
        }
        let code = digits
            .iter()
            .fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
        if self.code.is_some_and(|c| c != code) {
            return Err(Fault::Syntax);
        }
        let (last, text) = match line.get(3) {
            None => (true, &[][..]),
            Some(b' ') => (true, &line[4..]),
            Some(b'-') => (false, &line[4..]),
            Some(_) => return Err(Fault::Syntax),
        };
        self.code = Some(code);
        self.lines.push(
            text.iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        char::from(b)
                    } else {
                        '?'
                    }
                })
                .collect(),
        );
        if !last {
            return Ok(None);
        }
        self.code = None;
        self.size = 0;
        let mut lines = std::mem::take(&mut self.lines);
        let status = status(code, &lines[0]).map(|(status, rest)| {
            lines[0] = rest;
            status
        });
        Ok(Some(Response {
            code,
            status,
            lines,
        }))
    }
}

fn status(code: u16, line: &str) -> Option<((u8, u16, u16), String)> {
    let (token, rest) = line.split_once(' ').unwrap_or((line, ""));
    let mut parts = token.split('.');
    let class: u8 = parts.next()?.parse().ok()?;
    let subject: u16 = parts.next()?.parse().ok()?;
    let detail: u16 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || u16::from(class) != code / 100 || subject > 999 || detail > 999 {
        return None;
    }
    Some(((class, subject, detail), rest.to_owned()))
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub size: Option<u64>,
    pub pipelining: bool,
    pub eight_bit: bool,
    pub smtputf8: bool,
    pub chunking: bool,
    pub starttls: bool,
    pub requiretls: bool,
    pub dsn: bool,
    pub enhanced: bool,
}

impl Capabilities {
    pub fn parse(ehlo: &Response) -> Self {
        let mut caps = Self::default();
        for line in ehlo.lines.iter().skip(1).take(MAX_EXTENSIONS) {
            let mut words = line.split_ascii_whitespace();
            let Some(keyword) = words.next() else {
                continue;
            };
            match keyword.to_ascii_uppercase().as_str() {
                "SIZE" => caps.size = Some(words.next().and_then(|n| n.parse().ok()).unwrap_or(0)),
                "PIPELINING" => caps.pipelining = true,
                "8BITMIME" => caps.eight_bit = true,
                "SMTPUTF8" => caps.smtputf8 = true,
                "CHUNKING" => caps.chunking = true,
                "STARTTLS" => caps.starttls = true,
                "REQUIRETLS" => caps.requiretls = true,
                "DSN" => caps.dsn = true,
                "ENHANCEDSTATUSCODES" => caps.enhanced = true,
                _ => {}
            }
        }
        caps
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ret {
    Full,
    Headers,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mail {
    pub sender: String,
    pub size: u64,
    pub eight_bit: bool,
    pub smtputf8: bool,
    pub requiretls: bool,
    pub ret: Option<Ret>,
    pub envid: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rcpt {
    pub address: String,
    pub notify: Option<String>,
    pub orcpt: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Unsafe,
    Smtputf8,
    RequireTls,
}

pub fn ehlo(name: &str) -> Result<Vec<u8>, Refused> {
    line("EHLO ", name)
}

pub fn helo(name: &str) -> Result<Vec<u8>, Refused> {
    line("HELO ", name)
}

pub const STARTTLS: &[u8] = b"STARTTLS\r\n";
pub const RSET: &[u8] = b"RSET\r\n";
pub const QUIT: &[u8] = b"QUIT\r\n";
pub const DATA: &[u8] = b"DATA\r\n";

fn line(verb: &str, arg: &str) -> Result<Vec<u8>, Refused> {
    if !safe(arg.as_bytes()) || arg.is_empty() {
        return Err(Refused::Unsafe);
    }
    Ok(format!("{verb}{arg}\r\n").into_bytes())
}

fn safe(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| b >= 0x21 && b != 0x7f && b != b'<' && b != b'>')
}

fn xtext(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    for &b in raw {
        if (33..=126).contains(&b) && b != b'+' && b != b'=' {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "+{b:02X}");
        }
    }
    out
}

fn mail_command(caps: &Capabilities, mail: &Mail) -> Result<String, Refused> {
    if !mail.sender.is_empty() && !safe(mail.sender.as_bytes()) {
        return Err(Refused::Unsafe);
    }
    if mail.smtputf8 && !caps.smtputf8 {
        return Err(Refused::Smtputf8);
    }
    if mail.requiretls && !caps.requiretls {
        return Err(Refused::RequireTls);
    }
    let mut out = format!("MAIL FROM:<{}>", mail.sender);
    if caps.size.is_some() {
        let _ = write!(out, " SIZE={}", mail.size);
    }
    if mail.eight_bit && caps.eight_bit {
        out.push_str(" BODY=8BITMIME");
    }
    if mail.smtputf8 {
        out.push_str(" SMTPUTF8");
    }
    if mail.requiretls {
        out.push_str(" REQUIRETLS");
    }
    if caps.dsn {
        match mail.ret {
            Some(Ret::Full) => out.push_str(" RET=FULL"),
            Some(Ret::Headers) => out.push_str(" RET=HDRS"),
            None => {}
        }
        if !mail.envid.is_empty() {
            let _ = write!(out, " ENVID={}", xtext(&mail.envid));
        }
    }
    out.push_str("\r\n");
    Ok(out)
}

fn rcpt_command(caps: &Capabilities, rcpt: &Rcpt) -> Result<String, Refused> {
    if !safe(rcpt.address.as_bytes()) {
        return Err(Refused::Unsafe);
    }
    let mut out = format!("RCPT TO:<{}>", rcpt.address);
    if caps.dsn {
        if let Some(notify) = &rcpt.notify {
            if !safe(notify.as_bytes()) {
                return Err(Refused::Unsafe);
            }
            let _ = write!(out, " NOTIFY={notify}");
        }
        if !rcpt.orcpt.is_empty() {
            let _ = write!(out, " ORCPT=rfc822;{}", xtext(&rcpt.orcpt));
        }
    }
    out.push_str("\r\n");
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Accepted,
    Refused(Response),
    Again(Response),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Wait,
    Send(Vec<u8>),
    Body,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Mail,
    Rcpt(usize),
    Data,
    Final,
    Over,
    Dot,
}

pub struct Transaction {
    pipelining: bool,
    commands: Vec<String>,
    expect: Vec<Expect>,
    mail: Option<Response>,
    answers: Vec<Option<Answer>>,
    reusable: bool,
}

impl Transaction {
    pub fn new(caps: &Capabilities, mail: &Mail, rcpts: &[Rcpt]) -> Result<Self, Refused> {
        let mut commands = vec![mail_command(caps, mail)?];
        for rcpt in rcpts {
            commands.push(rcpt_command(caps, rcpt)?);
        }
        Ok(Self {
            pipelining: caps.pipelining,
            commands,
            expect: Vec::new(),
            mail: None,
            answers: vec![None; rcpts.len()],
            reusable: true,
        })
    }

    pub fn start(&mut self) -> Vec<u8> {
        if self.pipelining {
            let mut out = self.commands.concat().into_bytes();
            out.extend_from_slice(DATA);
            self.expect.push(Expect::Mail);
            self.expect
                .extend((0..self.answers.len()).map(Expect::Rcpt));
            self.expect.push(Expect::Data);
            out
        } else {
            self.expect.push(Expect::Mail);
            self.commands[0].clone().into_bytes()
        }
    }

    pub fn reply(&mut self, response: &Response) -> Step {
        if self.expect.is_empty() {
            self.reusable = false;
            return Step::Done;
        }
        let expect = self.expect.remove(0);
        match expect {
            Expect::Mail => {
                if response.positive() {
                    self.mail = None;
                    if self.pipelining {
                        return Step::Wait;
                    }
                    self.expect.push(Expect::Rcpt(0));
                    return Step::Send(self.commands[1].clone().into_bytes());
                }
                self.mail = Some(response.clone());
                for answer in &mut self.answers {
                    *answer = Some(refusal(response, true));
                }
                if self.pipelining {
                    self.expect = vec![Expect::Over; self.expect.len()];
                    return self.waiting();
                }
                Step::Done
            }
            Expect::Rcpt(i) => {
                self.answers[i] = Some(if response.positive() {
                    Answer::Accepted
                } else {
                    refusal(response, false)
                });
                if self.pipelining {
                    return Step::Wait;
                }
                if i + 1 < self.answers.len() {
                    self.expect.push(Expect::Rcpt(i + 1));
                    return Step::Send(self.commands[i + 2].clone().into_bytes());
                }
                if self.accepted() == 0 {
                    return Step::Done;
                }
                self.expect.push(Expect::Data);
                Step::Send(DATA.to_vec())
            }
            Expect::Data => {
                if response.code == 354 {
                    if self.accepted() == 0 {
                        self.expect.push(Expect::Dot);
                        return Step::Send(b".\r\n".to_vec());
                    }
                    self.expect.push(Expect::Final);
                    return Step::Body;
                }
                if self.accepted() > 0 {
                    self.settle(response);
                }
                Step::Done
            }
            Expect::Final => {
                self.settle(response);
                Step::Done
            }
            Expect::Over => {
                if response.code == 354 {
                    self.expect.clear();
                    self.expect.push(Expect::Dot);
                    return Step::Send(b".\r\n".to_vec());
                }
                self.waiting()
            }
            Expect::Dot => Step::Done,
        }
    }

    fn waiting(&self) -> Step {
        if self.expect.is_empty() {
            Step::Done
        } else {
            Step::Wait
        }
    }

    fn settle(&mut self, response: &Response) {
        for answer in &mut self.answers {
            if *answer == Some(Answer::Accepted) {
                *answer = Some(if response.positive() {
                    Answer::Accepted
                } else {
                    refusal(response, true)
                });
            }
        }
    }

    fn accepted(&self) -> usize {
        self.answers
            .iter()
            .filter(|a| **a == Some(Answer::Accepted))
            .count()
    }

    pub fn reusable(&self) -> bool {
        self.reusable && self.expect.is_empty()
    }

    pub fn answers(&self) -> Vec<Option<Answer>> {
        self.answers.clone()
    }

    pub fn mail_refused(&self) -> Option<&Response> {
        self.mail.as_ref()
    }

    pub fn again(&self) -> bool {
        self.answers
            .iter()
            .any(|a| matches!(a, Some(Answer::Again(_))))
    }
}

fn refusal(response: &Response, whole: bool) -> Answer {
    let too_many = matches!(response.status, None | Some((_, 5, 3)));
    if !whole && too_many && matches!(response.code, 452 | 552) {
        return Answer::Again(response.clone());
    }
    Answer::Refused(response.clone())
}

#[derive(Default)]
pub struct Dots {
    middle: bool,
    cr: bool,
}

impl Dots {
    pub fn encode(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        out.reserve(chunk.len() + chunk.len() / 64);
        for &b in chunk {
            match b {
                b'\r' => {
                    if self.cr {
                        out.extend_from_slice(b"\r\n");
                        self.middle = false;
                    }
                    self.cr = true;
                }
                b'\n' => {
                    out.extend_from_slice(b"\r\n");
                    self.cr = false;
                    self.middle = false;
                }
                _ => {
                    if self.cr {
                        out.extend_from_slice(b"\r\n");
                        self.cr = false;
                        self.middle = false;
                    }
                    if !self.middle && b == b'.' {
                        out.push(b'.');
                    }
                    out.push(b);
                    self.middle = true;
                }
            }
        }
    }

    pub fn finish(mut self, out: &mut Vec<u8>) {
        if self.cr {
            out.extend_from_slice(b"\r\n");
            self.middle = false;
        }
        if self.middle {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");
    }
}
