use crate::request::token;
use crate::status::Status;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;

#[derive(Clone, Debug)]
pub struct Response {
    status: Status,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    close: bool,
}

impl Response {
    pub fn new(status: Status) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            close: false,
        }
    }

    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Result<Self, Invalid> {
        let value = value.into();
        let reserved = ["content-length", "transfer-encoding", "connection", "date"];
        if name.is_empty()
            || !name.bytes().all(token)
            || reserved.iter().any(|r| name.eq_ignore_ascii_case(r))
            || !value
                .bytes()
                .all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
        {
            return Err(Invalid);
        }
        self.headers.push((name, value));
        Ok(self)
    }

    pub fn body(mut self, content_type: &'static str, body: Vec<u8>) -> Result<Self, Invalid> {
        self = self.header("Content-Type", content_type)?;
        self.body = body;
        Ok(self)
    }

    #[must_use]
    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn closes(&self) -> bool {
        self.close
    }

    pub(crate) fn write(&self, date: &str, close: bool, head_only: bool, out: &mut Vec<u8>) {
        let status = self.status;
        out.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\nDate: {date}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n",
                status.code(),
                status.reason(),
                self.body.len()
            )
            .as_bytes(),
        );
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if close {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        if !head_only {
            out.extend_from_slice(&self.body);
        }
    }
}
