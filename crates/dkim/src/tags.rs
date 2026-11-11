use std::ops::Range;

use crate::{Error, Field};

pub(crate) struct Tag {
    name: Range<usize>,
    value: Range<usize>,
    pub(crate) raw: Range<usize>,
}

pub(crate) struct Tags<'a> {
    raw: &'a [u8],
    list: Vec<Tag>,
}

impl<'a> Tags<'a> {
    pub(crate) fn parse(field: &Field<'a>) -> Result<Self, Error> {
        let raw = field.raw();
        let mut list: Vec<Tag> = Vec::new();
        let mut start = field.colon() + 1;
        loop {
            let end = raw[start..]
                .iter()
                .position(|&b| b == b';')
                .map_or(raw.len(), |at| start + at);
            let segment = trim(raw, start..end);
            if segment.is_empty() {
                if end != raw.len() {
                    return Err(Error::Tag);
                }
            } else {
                let eq = raw[segment.clone()]
                    .iter()
                    .position(|&b| b == b'=')
                    .ok_or(Error::Tag)?
                    + segment.start;
                let name = trim(raw, segment.start..eq);
                if !tag_name(&raw[name.clone()])
                    || list
                        .iter()
                        .any(|tag| raw[tag.name.clone()] == raw[name.clone()])
                {
                    return Err(Error::Tag);
                }
                list.push(Tag {
                    name,
                    value: trim(raw, eq + 1..segment.end),
                    raw: eq + 1..end,
                });
            }
            if end == raw.len() {
                break;
            }
            start = end + 1;
        }
        Ok(Self { raw, list })
    }

    pub(crate) fn tag(&self, name: &str) -> Option<&Tag> {
        self.list
            .iter()
            .find(|tag| &self.raw[tag.name.clone()] == name.as_bytes())
    }

    pub(crate) fn get(&self, name: &str) -> Option<&'a [u8]> {
        self.tag(name).map(|tag| &self.raw[tag.value.clone()])
    }

    pub(crate) fn require(&self, name: &'static str) -> Result<&'a [u8], Error> {
        self.get(name).ok_or(Error::Missing(name))
    }
}

pub(crate) fn names(list: &[u8]) -> impl Iterator<Item = &[u8]> {
    list.split(|&b| b == b':').map(|name| {
        let range = trim(name, 0..name.len());
        &name[range]
    })
}

fn tag_name(name: &[u8]) -> bool {
    name.first().is_some_and(u8::is_ascii_alphabetic)
        && name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

fn trim(raw: &[u8], range: Range<usize>) -> Range<usize> {
    let fws = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let part = &raw[range.clone()];
    let start = part.iter().position(|b| !fws(b)).unwrap_or(part.len());
    let end = part
        .iter()
        .rposition(|b| !fws(b))
        .map_or(start, |at| at + 1);
    range.start + start..range.start + end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    #[test]
    fn reads_tags_with_folding_and_a_trailing_semicolon() {
        let section =
            b"DKIM-Signature: v=1; a = rsa-sha256 ;\r\n h=from :\r\n to; b=ab\r\n cd;\r\n";
        let fields = parse(section).expect("parse");
        let tags = Tags::parse(&fields[0]).expect("tags");
        assert_eq!(tags.get("v"), Some(&b"1"[..]));
        assert_eq!(tags.get("a"), Some(&b"rsa-sha256"[..]));
        assert_eq!(tags.get("b"), Some(&b"ab\r\n cd"[..]));
        assert_eq!(tags.get("x"), None);
        let h = tags.get("h").expect("h");
        assert_eq!(names(h).collect::<Vec<_>>(), [&b"from"[..], b"to"]);
    }

    #[test]
    fn refuses_bad_tag_lists() {
        for value in ["a=1;;b=2", "a=1; a=2", "1a=x", "=x", "novalue"] {
            let section = format!("DKIM-Signature: {value}\r\n");
            let fields = parse(section.as_bytes()).expect("parse");
            assert!(Tags::parse(&fields[0]).is_err(), "{value}");
        }
    }
}
