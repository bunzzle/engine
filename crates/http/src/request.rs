use crate::status::Status;

const LENGTH_DIGITS: usize = 19;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, Vec<u8>)>);

impl Headers {
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        self.0
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    pub fn count(&self, name: &str) -> usize {
        self.all(name).count()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Headers,
    pub body: Framing,
    pub expect: bool,
    pub close: bool,
}

pub(crate) fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

pub(crate) fn field_byte(b: u8) -> bool {
    b == b'\t' || b == b' ' || (0x21..=0x7e).contains(&b) || b >= 0x80
}

fn trim(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |i| i + 1);
    &value[start..end]
}

pub(crate) fn field(line: &[u8]) -> Result<(&[u8], &[u8]), Status> {
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(Status::BAD_REQUEST)?;
    let name = &line[..colon];
    if name.is_empty() || !name.iter().all(|&b| token(b)) {
        return Err(Status::BAD_REQUEST);
    }
    let value = trim(&line[colon + 1..]);
    if !value.iter().all(|&b| field_byte(b)) {
        return Err(Status::BAD_REQUEST);
    }
    Ok((name, value))
}

pub(crate) fn parse(head: &[u8]) -> Result<Request, Status> {
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let (method, target) = request_line(lines.next().ok_or(Status::BAD_REQUEST)?)?;
    let mut headers = Vec::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(Status::BAD_REQUEST);
        }
        let (name, value) = field(line)?;
        let name = String::from_utf8(name.to_ascii_lowercase()).map_err(|_| Status::BAD_REQUEST)?;
        headers.push((name, value.to_vec()));
    }
    let headers = Headers(headers);
    let host = host(&headers)?;
    let (path, query) = split_target(target, host)?;
    let body = framing(&method, &headers)?;
    let expect = expect(&headers)?;
    let close = headers.all("connection").any(|value| {
        value
            .split(|&b| b == b',')
            .any(|t| trim(t).eq_ignore_ascii_case(b"close"))
    });
    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
        expect,
        close,
    })
}

fn request_line(line: &[u8]) -> Result<(String, &[u8]), Status> {
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Status::BAD_REQUEST);
    };
    if method.is_empty() || !method.iter().all(|&b| token(b)) {
        return Err(Status::BAD_REQUEST);
    }
    if target.is_empty() || !target.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(Status::BAD_REQUEST);
    }
    version_ok(version)?;
    let method = String::from_utf8(method.to_vec()).map_err(|_| Status::BAD_REQUEST)?;
    Ok((method, target))
}

fn version_ok(version: &[u8]) -> Result<(), Status> {
    match version {
        b"HTTP/1.1" => Ok(()),
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit() =>
        {
            Err(Status::VERSION)
        }
        _ => Err(Status::BAD_REQUEST),
    }
}

fn host(headers: &Headers) -> Result<&[u8], Status> {
    let mut all = headers.all("host");
    let (Some(host), None) = (all.next(), all.next()) else {
        return Err(Status::BAD_REQUEST);
    };
    let bad = |b: &u8| matches!(b, b' ' | b'\t' | b'/' | b'\\' | b'?' | b'#' | b'@') || *b >= 0x80;
    if host.is_empty() || host.iter().any(bad) {
        return Err(Status::BAD_REQUEST);
    }
    Ok(host)
}

fn split_target(target: &[u8], host: &[u8]) -> Result<(String, Option<String>), Status> {
    if target.contains(&b'#') {
        return Err(Status::BAD_REQUEST);
    }
    let origin = if target[0] == b'/' {
        target
    } else {
        absolute(target, host)?
    };
    let text = std::str::from_utf8(origin).map_err(|_| Status::BAD_REQUEST)?;
    let (path, query) = match text.split_once('?') {
        Some((path, query)) => (path, Some(query.to_owned())),
        None => (text, None),
    };
    let path = if path.is_empty() { "/" } else { path };
    Ok((path.to_owned(), query))
}

fn absolute<'a>(target: &'a [u8], host: &[u8]) -> Result<&'a [u8], Status> {
    let rest = strip_scheme(target).ok_or(Status::BAD_REQUEST)?;
    let end = rest
        .iter()
        .position(|&b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    if !rest[..end].eq_ignore_ascii_case(host) {
        return Err(Status::BAD_REQUEST);
    }
    Ok(&rest[end..])
}

fn strip_scheme(target: &[u8]) -> Option<&[u8]> {
    for scheme in [&b"https://"[..], b"http://"] {
        if target.len() >= scheme.len() && target[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return Some(&target[scheme.len()..]);
        }
    }
    None
}

fn framing(method: &str, headers: &Headers) -> Result<Framing, Status> {
    let mut encodings = headers.all("transfer-encoding");
    let encoding = encodings.next();
    if encodings.next().is_some() {
        return Err(Status::BAD_REQUEST);
    }
    let mut length = None;
    for value in headers.all("content-length") {
        let parsed = content_length(value)?;
        if length.is_some_and(|n| n != parsed) {
            return Err(Status::BAD_REQUEST);
        }
        length = Some(parsed);
    }
    match (encoding, length) {
        (Some(_), Some(_)) => Err(Status::BAD_REQUEST),
        (Some(value), None) if value.eq_ignore_ascii_case(b"chunked") => Ok(Framing::Chunked),
        (Some(_), None) => Err(Status::NOT_IMPLEMENTED),
        (None, Some(n)) => Ok(Framing::Length(n)),
        (None, None) if matches!(method, "POST" | "PUT" | "PATCH") => Err(Status::LENGTH_REQUIRED),
        (None, None) => Ok(Framing::None),
    }
}

fn content_length(value: &[u8]) -> Result<u64, Status> {
    if value.is_empty() || value.len() > LENGTH_DIGITS || !value.iter().all(u8::is_ascii_digit) {
        return Err(Status::BAD_REQUEST);
    }
    Ok(value.iter().fold(0, |n, &d| n * 10 + u64::from(d - b'0')))
}

fn expect(headers: &Headers) -> Result<bool, Status> {
    let mut all = headers.all("expect");
    match (all.next(), all.next()) {
        (None, _) => Ok(false),
        (Some(value), None) if value.eq_ignore_ascii_case(b"100-continue") => Ok(true),
        _ => Err(Status::EXPECTATION_FAILED),
    }
}
