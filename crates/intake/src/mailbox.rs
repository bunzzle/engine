const LOCAL: usize = 64;
const DOMAIN: usize = 255;
const LABEL: usize = 63;

pub fn from_domain(value: &[u8]) -> Option<String> {
    let (stripped, angle) = strip(value)?;
    let spec = match angle {
        Some(open) => {
            let text = stripped.trim_ascii_end();
            text.strip_suffix(b">")?.get(open + 1..)?
        }
        None => stripped.trim_ascii(),
    };
    addr_spec(spec)
}

fn strip(value: &[u8]) -> Option<(Vec<u8>, Option<usize>)> {
    let mut out = Vec::with_capacity(value.len());
    let mut quoted = false;
    let mut comment = 0usize;
    let mut angle = None;
    let mut closes = 0usize;
    let mut escaped = false;
    for &b in value {
        let b = if b == b'\r' || b == b'\n' { b' ' } else { b };
        if !b.is_ascii() || (b < 32 && b != b'\t') || b == 127 {
            return None;
        }
        if escaped {
            escaped = false;
            if comment == 0 {
                out.push(b);
            }
            continue;
        }
        if comment > 0 {
            match b {
                b'\\' => escaped = true,
                b'(' => comment += 1,
                b')' => comment -= 1,
                _ => {}
            }
            if comment == 0 {
                out.push(b' ');
            }
            continue;
        }
        if quoted {
            match b {
                b'\\' => escaped = true,
                b'"' => quoted = false,
                _ => {}
            }
            out.push(b);
            continue;
        }
        match b {
            b'"' => quoted = true,
            b'(' => {
                comment = 1;
                continue;
            }
            b')' | b',' | b':' | b';' => return None,
            b'<' => {
                if angle.is_some() {
                    return None;
                }
                angle = Some(out.len());
            }
            b'>' => {
                closes += 1;
                if angle.is_none() || closes > 1 {
                    return None;
                }
            }
            _ => {}
        }
        out.push(b);
    }
    let balanced = closes == usize::from(angle.is_some());
    (!quoted && comment == 0 && !escaped && balanced).then_some((out, angle))
}

fn addr_spec(spec: &[u8]) -> Option<String> {
    let at = spec.iter().rposition(|&b| b == b'@')?;
    let (local, domain) = (&spec[..at], &spec[at + 1..]);
    if local.is_empty() || local.len() > LOCAL || !local_ok(local) {
        return None;
    }
    if domain.len() > DOMAIN || !domain.split(|&b| b == b'.').all(label_ok) {
        return None;
    }
    Some(String::from_utf8_lossy(domain).to_ascii_lowercase())
}

fn local_ok(local: &[u8]) -> bool {
    if let [b'"', inner @ .., b'"'] = local {
        let mut escaped = false;
        for &b in inner {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' || !(32..=126).contains(&b) {
                return false;
            }
        }
        return !escaped;
    }
    local
        .split(|&b| b == b'.')
        .all(|atom| !atom.is_empty() && atom.iter().all(|&b| atext(b)))
}

fn atext(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b)
}

pub(crate) fn label_ok(label: &[u8]) -> bool {
    !label.is_empty()
        && label.len() <= LABEL
        && label[0] != b'-'
        && label[label.len() - 1] != b'-'
        && label
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(value: &str) -> Option<String> {
        from_domain(value.as_bytes())
    }

    #[test]
    fn reads_one_mailbox() {
        let ok = [
            (" a@example.org", "example.org"),
            (" Ann <a@Example.ORG>", "example.org"),
            (" \"Doe, Ann\" <a.b+c@mail.example.org>", "mail.example.org"),
            (" \"x@evil.test\" <a@example.org>", "example.org"),
            (" \"x <b@evil.test>\" <a@example.org>", "example.org"),
            (" <\"a>b\"@example.org>", "example.org"),
            (
                " Ann (work, <x@evil.test>) <a@example.org> (note)",
                "example.org",
            ),
            (" \"a\\\"b\"@example.org", "example.org"),
            ("\r\n <a@example.org>", "example.org"),
            (" Ann\r\n\t<a@example.org>", "example.org"),
            (" (a (nested) comment) a@example.org", "example.org"),
        ];
        for (value, expected) in ok {
            assert_eq!(domain(value).as_deref(), Some(expected), "{value}");
        }
    }

    #[test]
    fn refuses_anything_but_one_mailbox() {
        let bad = [
            "",
            " ",
            " a@example.org, b@example.org",
            " <a@example.org>, <b@example.org>",
            " group: a@example.org;",
            " undisclosed:;",
            " <a@example.org> <b@example.org>",
            " <a@example.org> trailing",
            " <<a@example.org>>",
            " \"x <a@evil.test>\"",
            " a> <b@example.org>",
            " <a@example.org>>",
            " <a@example.org",
            " a@example.org>",
            " a@[127.0.0.1]",
            " a@-example.org",
            " a@example..org",
            " a@example.org.",
            " a.@example.org",
            " .a@example.org",
            " @example.org",
            " a@",
            " a@b@example.org",
            " \"open@example.org",
            " (open a@example.org",
            " a b@example.org",
            " a@exa mple.org",
            " <a@example.org\\>",
            " a@exämple.org",
            " a@example.org\0",
            " <@route:a@example.org>",
        ];
        for value in bad {
            assert_eq!(domain(value), None, "{value:?}");
        }
    }

    #[test]
    fn caps_lengths() {
        let local = "a".repeat(LOCAL);
        assert!(domain(&format!(" {local}@example.org")).is_some());
        assert!(domain(&format!(" {local}a@example.org")).is_none());
        let label = "b".repeat(LABEL);
        assert!(domain(&format!(" a@{label}.org")).is_some());
        assert!(domain(&format!(" a@{label}b.org")).is_none());
        let long = [label.as_str(); 5].join(".");
        assert!(domain(&format!(" a@{long}")).is_none());
    }
}
