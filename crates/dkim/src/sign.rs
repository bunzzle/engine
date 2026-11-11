use crypto::{DkimAlg, sha256};

use crate::canon::relaxed_field;
use crate::tags::{Tags, names};
use crate::{Error, Field, base64};

pub const SIGNED: [&str; 17] = [
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "message-id",
    "reply-to",
    "sender",
    "in-reply-to",
    "references",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "list-unsubscribe",
    "list-unsubscribe-post",
    "list-id",
    "feedback-id",
];

const WIDTH: usize = 78;

pub struct Template<'a> {
    pub alg: DkimAlg,
    pub domain: &'a str,
    pub selector: &'a str,
    pub time: u64,
    pub expiry: u64,
}

pub fn header_list(fields: &[Field]) -> Vec<&'static str> {
    let mut list = Vec::new();
    for name in SIGNED {
        let count = fields.iter().filter(|field| field.is(name)).count();
        list.extend(std::iter::repeat_n(name, count + 1));
    }
    list
}

pub fn unsigned(template: &Template, fields: &[Field], body: &[u8; 32]) -> Result<Vec<u8>, Error> {
    if !dns_name(template.domain) {
        return Err(Error::Domain);
    }
    if !dns_name(template.selector) {
        return Err(Error::Selector);
    }
    if template.expiry <= template.time {
        return Err(Error::Expiry);
    }
    let alg = match template.alg {
        DkimAlg::RsaSha256 => "rsa-sha256",
        DkimAlg::Ed25519Sha256 => "ed25519-sha256",
    };
    let mut out = Folder::new("DKIM-Signature:");
    for tag in [
        "v=1;".to_owned(),
        format!("a={alg};"),
        "c=relaxed/relaxed;".to_owned(),
        format!("d={};", template.domain),
        format!("s={};", template.selector),
        format!("t={};", template.time),
        format!("x={};", template.expiry),
    ] {
        out.word(&tag, true);
    }
    let list = header_list(fields);
    for (i, name) in list.iter().enumerate() {
        let end = if i + 1 == list.len() { ';' } else { ':' };
        if i == 0 {
            out.word(&format!("h={name}{end}"), true);
        } else {
            out.word(&format!("{name}{end}"), false);
        }
    }
    out.word(&format!("bh={};", base64::encode(body)), true);
    out.word("b=", true);
    Ok(out.finish())
}

pub fn signed(unsigned: &[u8], signature: &[u8]) -> Result<Vec<u8>, Error> {
    let head = unsigned.strip_suffix(b"b=\r\n").ok_or(Error::Unsigned)?;
    if head.last() != Some(&b' ') || signature.is_empty() {
        return Err(Error::Unsigned);
    }
    let line = head
        .windows(2)
        .rposition(|pair| pair == b"\r\n")
        .map_or(0, |at| at + 2);
    let mut out = Folder {
        out: head.to_vec(),
        col: head.len() - line,
    };
    out.word("b=", false);
    out.run(&base64::encode(signature));
    Ok(out.finish())
}

pub fn digest(fields: &[Field], at: usize) -> Result<[u8; 32], Error> {
    let field = fields.get(at).ok_or(Error::Missing("field"))?;
    let tags = Tags::parse(field)?;
    if tags.get("c") != Some(b"relaxed/relaxed") {
        return Err(Error::Canonicalization);
    }
    let list = tags.require("h")?;
    let b = tags.tag("b").ok_or(Error::Missing("b"))?;
    let mut used = vec![false; fields.len()];
    used[at] = true;
    let mut data = Vec::new();
    for name in names(list) {
        if name.is_empty() {
            return Err(Error::Tag);
        }
        if let Some(i) = (0..fields.len())
            .rev()
            .find(|&i| !used[i] && fields[i].name().eq_ignore_ascii_case(name))
        {
            used[i] = true;
            relaxed_field(fields[i].name(), fields[i].value(), &mut data);
        }
    }
    let raw = field.raw();
    let mut value = raw[field.colon() + 1..b.raw.start].to_vec();
    value.extend_from_slice(&raw[b.raw.end..]);
    relaxed_field(field.name(), &value, &mut data);
    data.truncate(data.len() - 2);
    Ok(sha256(&data))
}

fn dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

struct Folder {
    out: Vec<u8>,
    col: usize,
}

impl Folder {
    fn new(start: &str) -> Self {
        Self {
            out: start.as_bytes().to_vec(),
            col: start.len(),
        }
    }

    fn word(&mut self, word: &str, space: bool) {
        if self.col > 1 && self.col + word.len() + usize::from(space) > WIDTH {
            self.fold();
        } else if space {
            self.out.push(b' ');
            self.col += 1;
        }
        self.out.extend_from_slice(word.as_bytes());
        self.col += word.len();
    }

    fn run(&mut self, text: &str) {
        for &b in text.as_bytes() {
            if self.col >= WIDTH {
                self.fold();
            }
            self.out.push(b);
            self.col += 1;
        }
    }

    fn fold(&mut self) {
        self.out.extend_from_slice(b"\r\n ");
        self.col = 1;
    }

    fn finish(mut self) -> Vec<u8> {
        self.out.extend_from_slice(b"\r\n");
        self.out
    }
}
