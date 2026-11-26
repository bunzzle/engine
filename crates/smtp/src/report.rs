#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    Bounces(Vec<Bounce>),
    Complaint { recipient: Option<String> },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounce {
    pub status: (u8, u16, u16),
    pub original: Option<String>,
    pub recipient: Option<String>,
    pub diagnostic: String,
}

const MAX_FIELD: usize = 65_536;
const MAX_BLOCKS: usize = 1000;
const MAX_DIAG: usize = 1024;

pub fn parse(message: &[u8]) -> Report {
    let (head, body) = split_head(message);
    let Some(fields) = parse_fields(head) else {
        return Report::Unknown;
    };
    let Some(boundary) = field(&fields, "content-type").and_then(boundary_of) else {
        return Report::Unknown;
    };
    let parts = split_parts(body, &boundary);
    let mut arf = None;
    for part in parts {
        let (phead, pbody) = split_head(part);
        let Some(pfields) = parse_fields(phead) else {
            return Report::Unknown;
        };
        let kind = field(&pfields, "content-type").map(media_type);
        match kind.as_deref() {
            Some("message/delivery-status" | "message/global-delivery-status") => {
                let Some(decoded) = decode_part(&pfields, pbody) else {
                    return Report::Unknown;
                };
                return parse_dsn(&decoded);
            }
            Some("message/feedback-report") if arf.is_none() => {
                arf = Some((pfields, pbody));
            }
            _ => {}
        }
    }
    if let Some((pfields, pbody)) = arf {
        let Some(decoded) = decode_part(&pfields, pbody) else {
            return Report::Unknown;
        };
        return parse_arf(&decoded);
    }
    Report::Unknown
}

fn each_line(data: &[u8], mut f: impl FnMut(&[u8], usize, usize)) {
    let mut pos = 0;
    while pos < data.len() {
        if let Some(i) = data[pos..].iter().position(|&b| b == b'\n') {
            let end = pos + i;
            f(&data[pos..end], pos, end + 1);
            pos = end + 1;
        } else {
            f(&data[pos..], pos, data.len());
            break;
        }
    }
}

fn split_head(data: &[u8]) -> (&[u8], &[u8]) {
    let mut found = None;
    each_line(data, |line, start, next| {
        if found.is_none() && line.iter().all(|&b| b == b'\r') {
            found = Some((start, next));
        }
    });
    match found {
        Some((start, next)) => (&data[..start], &data[next.min(data.len())..]),
        None => (data, &data[..0]),
    }
}

fn parse_fields(data: &[u8]) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let flush = |cur: &mut Vec<u8>, out: &mut Vec<(String, String)>| {
        if cur.is_empty() {
            return Some(());
        }
        if cur.len() > MAX_FIELD {
            cur.clear();
            return Some(());
        }
        let text = String::from_utf8_lossy(cur);
        if let Some((name, value)) = text.split_once(':') {
            out.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        cur.clear();
        Some(())
    };
    let mut bad = false;
    each_line(data, |line, _, _| {
        if bad {
            return;
        }
        let line = match line.last() {
            Some(b'\r') => &line[..line.len() - 1],
            _ => line,
        };
        if matches!(line.first(), Some(b' ' | b'\t')) && !cur.is_empty() {
            cur.extend_from_slice(line);
        } else {
            if flush(&mut cur, &mut out).is_none() {
                bad = true;
                return;
            }
            cur.extend_from_slice(line);
        }
    });
    if bad {
        return None;
    }
    flush(&mut cur, &mut out)?;
    Some(out)
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn media_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn boundary_of(value: &str) -> Option<String> {
    if media_type(value) != "multipart/report" {
        return None;
    }
    for param in value.split(';').skip(1) {
        let Some((name, val)) = param.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("boundary") {
            let val = val.trim();
            let val = match val.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                Some(inner) => inner,
                None => val,
            };
            if val.is_empty() {
                return None;
            }
            return Some(val.to_string());
        }
    }
    None
}

fn split_parts<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delim = format!("--{boundary}");
    let close = format!("{delim}--");
    let mut parts = Vec::new();
    let mut start = None;
    let mut done = false;
    each_line(body, |line, at, next| {
        if done {
            return;
        }
        let line = match line.last() {
            Some(b'\r') => &line[..line.len() - 1],
            _ => line,
        };
        let Ok(text) = std::str::from_utf8(line) else {
            return;
        };
        let text = text.trim_end_matches([' ', '\t']);
        if text == delim || text == close {
            if let Some(s) = start.take() {
                parts.push(&body[s..at]);
            }
            if text == close {
                done = true;
            } else {
                start = Some(next);
            }
        }
    });
    parts
}

fn decode_part(fields: &[(String, String)], body: &[u8]) -> Option<Vec<u8>> {
    let encoding = field(fields, "content-transfer-encoding")
        .map_or_else(|| "7bit".to_string(), |v| v.trim().to_ascii_lowercase());
    match encoding.as_str() {
        "7bit" | "8bit" | "binary" => Some(body.to_vec()),
        "base64" => dkim::base64::decode(body),
        "quoted-printable" => qp_decode(body),
        _ => None,
    }
}

fn qp_decode(data: &[u8]) -> Option<Vec<u8>> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'=' {
            out.push(data[i]);
            i += 1;
            continue;
        }
        if i + 1 < data.len() && data[i + 1] == b'\n' {
            i += 2;
            continue;
        }
        if i + 2 < data.len() && data[i + 1] == b'\r' && data[i + 2] == b'\n' {
            i += 3;
            continue;
        }
        if i + 2 < data.len()
            && let (Some(hi), Some(lo)) = (hex(data[i + 1]), hex(data[i + 2]))
        {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        return None;
    }
    Some(out)
}

fn parse_dsn(body: &[u8]) -> Report {
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    each_line(body, |line, _, _| {
        let blank = line.iter().all(|&b| b == b'\r');
        if blank {
            if !cur.is_empty() {
                blocks.push(std::mem::take(&mut cur));
            }
        } else {
            cur.extend_from_slice(line);
            cur.push(b'\n');
        }
    });
    if !cur.is_empty() {
        blocks.push(cur);
    }
    let mut bounces = Vec::new();
    for block in blocks.iter().skip(1).take(MAX_BLOCKS) {
        let Some(fields) = parse_fields(block) else {
            return Report::Unknown;
        };
        let action = field(&fields, "action").unwrap_or("");
        if !action.trim().eq_ignore_ascii_case("failed") {
            continue;
        }
        let Some(status) = field(&fields, "status").and_then(parse_status) else {
            continue;
        };
        if status.0 != 5 {
            continue;
        }
        bounces.push(Bounce {
            status,
            original: address(field(&fields, "original-recipient")),
            recipient: address(field(&fields, "final-recipient")),
            diagnostic: diagnostic(field(&fields, "diagnostic-code")),
        });
    }
    if bounces.is_empty() {
        Report::Unknown
    } else {
        Report::Bounces(bounces)
    }
}

fn parse_status(value: &str) -> Option<(u8, u16, u16)> {
    let token = value.trim_start().split([' ', '(']).next()?;
    let mut parts = token.split('.');
    let a: u8 = parts.next()?.parse().ok()?;
    let b: u16 = parts.next()?.parse().ok()?;
    let c: u16 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || b > 999 || c > 999 {
        return None;
    }
    Some((a, b, c))
}

fn address(value: Option<&str>) -> Option<String> {
    let (kind, addr) = value?.split_once(';')?;
    let kind = kind.trim();
    if !kind.eq_ignore_ascii_case("rfc822") && !kind.eq_ignore_ascii_case("utf-8") {
        return None;
    }
    let addr = bare_address(addr);
    addr.contains('@').then_some(addr)
}

fn bare_address(addr: &str) -> String {
    let addr = addr.trim();
    let addr = match addr.strip_prefix('<').and_then(|a| a.strip_suffix('>')) {
        Some(inner) => inner.trim(),
        None => addr,
    };
    addr.to_string()
}

fn diagnostic(value: Option<&str>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let text = match value.split_once(';') {
        Some((_, after)) => after.trim(),
        None => value.trim(),
    };
    let mut end = text.len().min(MAX_DIAG);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn parse_arf(body: &[u8]) -> Report {
    let Some(fields) = parse_fields(body) else {
        return Report::Unknown;
    };
    let kind = field(&fields, "feedback-type").unwrap_or("");
    if !kind.trim().eq_ignore_ascii_case("abuse") {
        return Report::Unknown;
    }
    let recipient = field(&fields, "original-rcpt-to")
        .map(bare_address)
        .filter(|addr| addr.contains('@'));
    Report::Complaint { recipient }
}
