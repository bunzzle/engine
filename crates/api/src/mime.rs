use dkim::base64;

const LINE: usize = 76;
const FOLD: usize = 78;
const HARD: usize = 998;
const WORD: usize = 75;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Address,
    Header,
    ContentType,
    ContentId,
    Filename,
    Body,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    pub address: String,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
    pub content_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub from: Option<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<Attachment>,
}

const DENIED: [&str; 17] = [
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "sender",
    "subject",
    "date",
    "message-id",
    "mime-version",
    "received",
    "return-path",
    "dkim-signature",
    "authentication-results",
    "received-spf",
    "tls-required",
    "content-",
];

pub fn denied(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    DENIED.iter().any(|d| {
        if d.ends_with('-') {
            lower.starts_with(d)
        } else {
            lower == *d
        }
    }) || lower.starts_with("arc-")
}

pub fn address_ok(address: &str) -> bool {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    let atext = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b);
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && local
            .split('.')
            .all(|atom| !atom.is_empty() && atom.bytes().all(atext));
    let domain_ok = !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    local_ok && domain_ok
}

pub fn build(message: &Message, boundary: &str) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    let from = message.from.as_ref().ok_or(Fault::Address)?;
    addresses(&mut out, "From", std::slice::from_ref(from))?;
    addresses(&mut out, "To", &message.to)?;
    addresses(&mut out, "Cc", &message.cc)?;
    addresses(&mut out, "Reply-To", &message.reply_to)?;
    if !message.subject.is_empty() {
        unstructured(&mut out, "Subject", &message.subject)?;
    }
    for (name, value) in &message.headers {
        custom(&mut out, name, value)?;
    }
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    let body = body(message, boundary)?;
    write_part(&mut out, &body, boundary, 0);
    Ok(out)
}

enum Part<'a> {
    Text {
        subtype: &'static str,
        text: &'a str,
    },
    File(&'a Attachment),
    Multi {
        subtype: &'static str,
        parts: Vec<Part<'a>>,
    },
}

fn body<'a>(message: &'a Message, boundary: &str) -> Result<Part<'a>, Fault> {
    let mut texts = Vec::new();
    if let Some(text) = &message.text {
        texts.push(Part::Text {
            subtype: "plain",
            text,
        });
    }
    if let Some(html) = &message.html {
        texts.push(Part::Text {
            subtype: "html",
            text: html,
        });
    }
    let mut core = match texts.len() {
        0 => return Err(Fault::Body),
        1 => texts.remove(0),
        _ => Part::Multi {
            subtype: "alternative",
            parts: texts,
        },
    };
    for attachment in &message.attachments {
        check_attachment(attachment)?;
    }
    let inline: Vec<Part<'a>> = message
        .attachments
        .iter()
        .filter(|a| a.content_id.is_some())
        .map(Part::File)
        .collect();
    if !inline.is_empty() {
        let mut parts = vec![core];
        parts.extend(inline);
        core = Part::Multi {
            subtype: "related",
            parts,
        };
    }
    let files: Vec<Part<'a>> = message
        .attachments
        .iter()
        .filter(|a| a.content_id.is_none())
        .map(Part::File)
        .collect();
    if !files.is_empty() {
        let mut parts = vec![core];
        parts.extend(files);
        core = Part::Multi {
            subtype: "mixed",
            parts,
        };
    }
    if boundary.len() < 8
        || boundary.len() > 60
        || !boundary.starts_with("=_")
        || !boundary.bytes().skip(2).all(|b| b.is_ascii_alphanumeric())
    {
        return Err(Fault::Body);
    }
    Ok(core)
}

fn check_attachment(attachment: &Attachment) -> Result<(), Fault> {
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    match attachment.content_type.split_once('/') {
        Some((kind, sub)) if token(kind) && token(sub) && attachment.content_type.len() <= 127 => {}
        _ => return Err(Fault::ContentType),
    }
    if let Some(id) = &attachment.content_id {
        let inner = id
            .strip_prefix('<')
            .and_then(|i| i.strip_suffix('>'))
            .unwrap_or(id);
        let ok = inner.len() <= 250
            && inner
                .split_once('@')
                .is_some_and(|(l, r)| !l.is_empty() && !r.is_empty())
            && inner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.@".contains(&b));
        if !ok {
            return Err(Fault::ContentId);
        }
    }
    let name = &attachment.filename;
    if name.is_empty()
        || name.len() > 255
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
    {
        return Err(Fault::Filename);
    }
    Ok(())
}

fn write_part(out: &mut Vec<u8>, part: &Part<'_>, boundary: &str, depth: usize) {
    match part {
        Part::Text { subtype, text } => {
            let lines = normalize(text);
            let plain = lines
                .iter()
                .all(|l| l.len() <= HARD && l.is_ascii() && !l.contains("=_"));
            out.extend_from_slice(
                format!("Content-Type: text/{subtype}; charset=utf-8\r\n").as_bytes(),
            );
            if plain {
                out.extend_from_slice(b"Content-Transfer-Encoding: 7bit\r\n\r\n");
                for line in &lines {
                    out.extend_from_slice(line.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            } else {
                out.extend_from_slice(b"Content-Transfer-Encoding: quoted-printable\r\n\r\n");
                for line in &lines {
                    quoted_printable(out, line.as_bytes());
                }
            }
        }
        Part::File(attachment) => {
            out.extend_from_slice(
                format!("Content-Type: {}\r\n", attachment.content_type).as_bytes(),
            );
            out.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
            let kind = if attachment.content_id.is_some() {
                "inline"
            } else {
                "attachment"
            };
            out.extend_from_slice(format!("Content-Disposition: {kind}; ").as_bytes());
            filename(out, &attachment.filename);
            out.extend_from_slice(b"\r\n");
            if let Some(id) = &attachment.content_id {
                let inner = id
                    .strip_prefix('<')
                    .and_then(|i| i.strip_suffix('>'))
                    .unwrap_or(id);
                out.extend_from_slice(format!("Content-ID: <{inner}>\r\n").as_bytes());
            }
            out.extend_from_slice(b"\r\n");
            let encoded = base64::encode(&attachment.data);
            for line in encoded.as_bytes().chunks(LINE) {
                out.extend_from_slice(line);
                out.extend_from_slice(b"\r\n");
            }
        }
        Part::Multi { subtype, parts } => {
            let mark = format!("{boundary}{depth}");
            out.extend_from_slice(
                format!("Content-Type: multipart/{subtype};\r\n boundary=\"{mark}\"\r\n\r\n")
                    .as_bytes(),
            );
            for part in parts {
                out.extend_from_slice(format!("--{mark}\r\n").as_bytes());
                write_part(out, part, boundary, depth + 1);
            }
            out.extend_from_slice(format!("--{mark}--\r\n").as_bytes());
        }
    }
}

fn normalize(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(['\r', '\n']) {
        lines.push(&rest[..at]);
        let skip = if rest[at..].starts_with("\r\n") { 2 } else { 1 };
        rest = &rest[at + skip..];
    }
    if !rest.is_empty() {
        lines.push(rest);
    }
    lines
}

fn quoted_printable(out: &mut Vec<u8>, line: &[u8]) {
    let mut width = 0;
    for (i, &b) in line.iter().enumerate() {
        let last = i + 1 == line.len();
        let literal = (b == b' ' || b == b'\t') && !last || (0x21..=0x7e).contains(&b) && b != b'=';
        let size = if literal { 1 } else { 3 };
        if width + size > LINE - 1 {
            out.extend_from_slice(b"=\r\n");
            width = 0;
        }
        if literal {
            out.push(b);
        } else {
            out.extend_from_slice(format!("={b:02X}").as_bytes());
        }
        width += size;
    }
    out.extend_from_slice(b"\r\n");
}

fn header_value_ok(value: &str) -> bool {
    !value.chars().any(|c| c.is_control() && c != '\t')
}

fn custom(out: &mut Vec<u8>, name: &str, value: &str) -> Result<(), Fault> {
    let token = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    if name.is_empty()
        || !token
        || denied(name)
        || !value.is_ascii()
        || !header_value_ok(value)
        || name.len() + 2 + value.len() > HARD
    {
        return Err(Fault::Header);
    }
    out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    Ok(())
}

fn unstructured(out: &mut Vec<u8>, name: &str, value: &str) -> Result<(), Fault> {
    if !header_value_ok(value) {
        return Err(Fault::Header);
    }
    if value.is_ascii() && !value.contains("=?") && name.len() + 2 + value.len() <= FOLD {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        return Ok(());
    }
    out.extend_from_slice(format!("{name}:").as_bytes());
    let mut width = name.len() + 1;
    for word in encoded_words(value) {
        if width + 1 + word.len() > FOLD {
            out.extend_from_slice(b"\r\n");
            width = 0;
        }
        out.push(b' ');
        out.extend_from_slice(word.as_bytes());
        width += 1 + word.len();
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

fn encoded_words(value: &str) -> Vec<String> {
    let room = (WORD - "=?utf-8?B??=".len()) / 4 * 3;
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in value.chars() {
        if chunk.len() + c.len_utf8() > room {
            words.push(format!("=?utf-8?B?{}?=", base64::encode(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?utf-8?B?{}?=", base64::encode(chunk.as_bytes())));
    }
    words
}

fn addresses(out: &mut Vec<u8>, name: &str, list: &[Mailbox]) -> Result<(), Fault> {
    if list.is_empty() {
        return Ok(());
    }
    out.extend_from_slice(format!("{name}:").as_bytes());
    let mut width = name.len() + 1;
    for (i, mailbox) in list.iter().enumerate() {
        if !address_ok(&mailbox.address) {
            return Err(Fault::Address);
        }
        let mut pieces = Vec::new();
        if let Some(display) = mailbox.name.as_deref().filter(|n| !n.is_empty()) {
            if !header_value_ok(display) {
                return Err(Fault::Header);
            }
            if display.is_ascii() && !display.contains("=?") && display.len() <= 60 {
                let escaped = display.replace('\\', "\\\\").replace('"', "\\\"");
                pieces.push(format!("\"{escaped}\""));
            } else {
                pieces.extend(encoded_words(display));
            }
        }
        let end = i + 1 == list.len();
        let address = if pieces.is_empty() {
            mailbox.address.clone()
        } else {
            format!("<{}>", mailbox.address)
        };
        pieces.push(if end { address } else { format!("{address},") });
        for piece in pieces {
            if width + 1 + piece.len() > FOLD && width > name.len() + 1 {
                out.extend_from_slice(b"\r\n");
                width = 0;
            }
            out.push(b' ');
            out.extend_from_slice(piece.as_bytes());
            width += 1 + piece.len();
        }
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

fn filename(out: &mut Vec<u8>, name: &str) {
    let simple = name.is_ascii()
        && name.len() <= 60
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" !#$%&'()*+,-.;=@[]^_`{|}~".contains(&b));
    if simple {
        out.extend_from_slice(format!("filename=\"{name}\"").as_bytes());
        return;
    }
    out.extend_from_slice(b"\r\n filename*=utf-8''");
    for &b in name.as_bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
}
