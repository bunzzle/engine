const LOCAL: usize = 64;
const DOMAIN: usize = 255;
const MAILBOX: usize = 254;
const LABEL: usize = 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bad {
    Syntax,
    Utf8,
}

pub(crate) type Params<'a> = Vec<(String, Option<&'a [u8]>)>;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Path<'a> {
    pub(crate) mailbox: Option<String>,
    pub(crate) params: Params<'a>,
}

pub(crate) fn path(text: &[u8]) -> Result<Path<'_>, Bad> {
    if !text.is_ascii() {
        return Err(Bad::Utf8);
    }
    let mut at = Cursor { text, at: 0 };
    at.expect(b'<')?;
    let mailbox = if at.eat(b'>') {
        None
    } else {
        if at.peek() == Some(b'@') {
            route(&mut at)?;
        }
        let start = at.at;
        local(&mut at)?;
        if at.at - start > LOCAL {
            return Err(Bad::Syntax);
        }
        at.expect(b'@')?;
        let domain = at.at;
        if at.peek() == Some(b'[') {
            literal(&mut at)?;
        } else {
            name(&mut at)?;
        }
        if at.at - domain > DOMAIN || at.at - start > MAILBOX {
            return Err(Bad::Syntax);
        }
        let mailbox = String::from_utf8(text[start..at.at].to_vec()).map_err(|_| Bad::Utf8)?;
        at.expect(b'>')?;
        Some(mailbox)
    };
    let params = params(&text[at.at..])?;
    Ok(Path { mailbox, params })
}

fn params(text: &[u8]) -> Result<Params<'_>, Bad> {
    let mut out: Params<'_> = Vec::new();
    if text.is_empty() {
        return Ok(out);
    }
    if text[0] != b' ' {
        return Err(Bad::Syntax);
    }
    for param in text.split(|&b| b == b' ').filter(|p| !p.is_empty()) {
        let (keyword, value) = match param.iter().position(|&b| b == b'=') {
            Some(eq) => (&param[..eq], Some(&param[eq + 1..])),
            None => (param, None),
        };
        let keyword_ok = keyword.first().is_some_and(u8::is_ascii_alphanumeric)
            && keyword
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'-');
        let value_ok = value.is_none_or(|v| {
            !v.is_empty() && v.iter().all(|&b| (33..=126).contains(&b) && b != b'=')
        });
        if !keyword_ok || !value_ok {
            return Err(Bad::Syntax);
        }
        let keyword = String::from_utf8_lossy(keyword).to_ascii_uppercase();
        if out.iter().any(|(k, _)| *k == keyword) {
            return Err(Bad::Syntax);
        }
        out.push((keyword, value));
    }
    Ok(out)
}

struct Cursor<'a> {
    text: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        let hit = self.peek() == Some(byte);
        if hit {
            self.at += 1;
        }
        hit
    }

    fn expect(&mut self, byte: u8) -> Result<(), Bad> {
        if self.eat(byte) {
            Ok(())
        } else {
            Err(Bad::Syntax)
        }
    }

    fn many(&mut self, ok: impl Fn(u8) -> bool) -> usize {
        let start = self.at;
        while self.peek().is_some_and(&ok) {
            self.at += 1;
        }
        self.at - start
    }
}

fn atext(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b)
}

fn route(at: &mut Cursor<'_>) -> Result<(), Bad> {
    loop {
        at.expect(b'@')?;
        name(at)?;
        if at.eat(b':') {
            return Ok(());
        }
        at.expect(b',')?;
    }
}

fn local(at: &mut Cursor<'_>) -> Result<(), Bad> {
    if at.eat(b'"') {
        loop {
            match at.peek() {
                Some(b'"') => {
                    at.at += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    at.at += 1;
                    match at.peek() {
                        Some(32..=126) => at.at += 1,
                        _ => return Err(Bad::Syntax),
                    }
                }
                Some(32..=126) => at.at += 1,
                _ => return Err(Bad::Syntax),
            }
        }
    }
    loop {
        if at.many(atext) == 0 {
            return Err(Bad::Syntax);
        }
        if !at.eat(b'.') {
            return Ok(());
        }
    }
}

fn name(at: &mut Cursor<'_>) -> Result<(), Bad> {
    loop {
        let start = at.at;
        let len = at.many(|b| b.is_ascii_alphanumeric() || b == b'-');
        let label = &at.text[start..at.at];
        if len == 0 || len > LABEL || label[0] == b'-' || label[len - 1] == b'-' {
            return Err(Bad::Syntax);
        }
        if !at.eat(b'.') {
            return Ok(());
        }
    }
}

fn literal(at: &mut Cursor<'_>) -> Result<(), Bad> {
    at.expect(b'[')?;
    if at.many(|b| (33..=90).contains(&b) || (94..=126).contains(&b)) == 0 {
        return Err(Bad::Syntax);
    }
    at.expect(b']')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(text: &str) -> Result<Option<String>, Bad> {
        path(text.as_bytes()).map(|p| p.mailbox)
    }

    #[test]
    fn reads_mailboxes() {
        let ok = [
            ("<a@example.org>", "a@example.org"),
            ("<a.b+c@sub.example-1.org>", "a.b+c@sub.example-1.org"),
            ("<\"a b@\\\"c\"@example.org>", "\"a b@\\\"c\"@example.org"),
            ("<a@[192.0.2.1]>", "a@[192.0.2.1]"),
            (
                "<@relay.example,@other.example:a@example.org>",
                "a@example.org",
            ),
        ];
        for (text, want) in ok {
            assert_eq!(mailbox(text), Ok(Some(want.into())), "{text}");
        }
        assert_eq!(mailbox("<>"), Ok(None));
    }

    #[test]
    fn refuses_bad_mailboxes() {
        let bad = [
            "a@example.org",
            "<a@example.org",
            "<a@>",
            "<@example.org>",
            "<a..b@example.org>",
            "<.a@example.org>",
            "<a.@example.org>",
            "<a@example..org>",
            "<a@example.org.>",
            "<a@-example.org>",
            "<a@example-.org>",
            "<a b@example.org>",
            "<\"a@example.org>",
            "<a@[]>",
            "<a@example.org>x",
            "<@relay.example a@example.org>",
        ];
        for text in bad {
            assert_eq!(mailbox(text), Err(Bad::Syntax), "{text}");
        }
        assert_eq!(mailbox("<ü@example.org>"), Err(Bad::Utf8));
        let long = format!("<{}@example.org>", "a".repeat(65));
        assert_eq!(mailbox(&long), Err(Bad::Syntax));
        let label = format!("<a@{}.org>", "b".repeat(64));
        assert_eq!(mailbox(&label), Err(Bad::Syntax));
    }

    #[test]
    fn reads_parameters() {
        let found = path(b"<a@example.org> size=10  BODY=8BITMIME X-A").expect("path");
        assert_eq!(
            found.params,
            vec![
                ("SIZE".into(), Some(&b"10"[..])),
                ("BODY".into(), Some(&b"8BITMIME"[..])),
                ("X-A".into(), None),
            ]
        );
        for bad in [
            &b"<a@example.org> SIZE=1 size=2"[..],
            b"<a@example.org> SIZE=",
            b"<a@example.org> -A",
            b"<a@example.org> A=b=c",
        ] {
            assert_eq!(path(bad), Err(Bad::Syntax));
        }
    }
}
