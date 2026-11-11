use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    name: &'a [u8],
    raw: &'a [u8],
    colon: usize,
}

impl<'a> Field<'a> {
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn value(&self) -> &'a [u8] {
        &self.raw[self.colon + 1..]
    }

    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }

    pub(crate) fn colon(&self) -> usize {
        self.colon
    }
}

pub fn parse(section: &[u8]) -> Result<Vec<Field<'_>>, Error> {
    let mut fields = Vec::new();
    let mut open: Option<(usize, usize, usize)> = None;
    let mut at = 0;
    while at < section.len() {
        let end = line_end(section, at)?;
        let line = &section[at..end];
        match line.first() {
            None => return Err(Error::Empty),
            Some(b' ' | b'\t') => {
                if open.is_none() {
                    return Err(Error::Continuation);
                }
            }
            Some(_) => {
                if let Some((start, name, colon)) = open {
                    fields.push(field(section, start, name, colon, at));
                }
                let colon = line.iter().position(|&b| b == b':').ok_or(Error::Colon)?;
                let name = line[..colon]
                    .iter()
                    .rposition(|&b| b != b' ' && b != b'\t')
                    .map_or(0, |last| last + 1);
                if name == 0 || !line[..name].iter().all(|b| (33..=126).contains(b)) {
                    return Err(Error::Name);
                }
                open = Some((at, name, colon));
            }
        }
        at = end + 2;
    }
    if let Some((start, name, colon)) = open {
        fields.push(field(section, start, name, colon, at));
    }
    Ok(fields)
}

fn field(section: &[u8], start: usize, name: usize, colon: usize, end: usize) -> Field<'_> {
    Field {
        name: &section[start..start + name],
        raw: &section[start..end],
        colon,
    }
}

fn line_end(section: &[u8], from: usize) -> Result<usize, Error> {
    let mut at = from;
    while at < section.len() {
        match section[at] {
            b'\r' if section.get(at + 1) == Some(&b'\n') => return Ok(at),
            b'\r' | b'\n' => return Err(Error::Line),
            _ => at += 1,
        }
    }
    Err(Error::Line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_folded_fields() {
        let section = b"From: a@example.org\r\nSubject: one\r\n two\r\n\tthree\r\nX-Y : z\r\n";
        let fields = parse(section).expect("parse");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name(), b"From");
        assert_eq!(fields[1].raw(), b"Subject: one\r\n two\r\n\tthree\r\n");
        assert_eq!(fields[1].value(), b" one\r\n two\r\n\tthree\r\n");
        assert_eq!(fields[2].name(), b"X-Y");
        assert!(fields[2].is("x-y"));
        assert_eq!(parse(b"").expect("empty"), Vec::new());
    }

    #[test]
    fn refuses_malformed_sections() {
        let cases: [(&[u8], Error); 8] = [
            (b" a: b\r\n", Error::Continuation),
            (b"a: b\r\n\r\n", Error::Empty),
            (b"a b\r\n", Error::Colon),
            (b": b\r\n", Error::Name),
            (b"a\x01: b\r\n", Error::Name),
            (b"a: b\n", Error::Line),
            (b"a: b\rc\r\n", Error::Line),
            (b"a: b", Error::Line),
        ];
        for (section, error) in cases {
            assert_eq!(
                parse(section),
                Err(error),
                "{}",
                String::from_utf8_lossy(section)
            );
        }
    }
}
