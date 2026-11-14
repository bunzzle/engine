const HEAD: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    More,
    Done(Vec<u8>),
    Bad,
}

pub(crate) fn request(host: &str, path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: text/plain\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

pub(crate) fn parse(bytes: &[u8], closed: bool, most: usize) -> Parsed {
    let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if closed || bytes.len() > HEAD {
            Parsed::Bad
        } else {
            Parsed::More
        };
    };
    if at > HEAD {
        return Parsed::Bad;
    }
    let Ok(head) = std::str::from_utf8(&bytes[..at]) else {
        return Parsed::Bad;
    };
    let rest = &bytes[at + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") || parts.next() != Some("200") {
        return Parsed::Bad;
    }
    let mut plain = false;
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Parsed::Bad;
        };
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-type" => {
                let media = value.split(';').next().unwrap_or_default().trim();
                plain = media.eq_ignore_ascii_case("text/plain");
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Parsed::Bad;
                }
                chunked = true;
            }
            "content-length" => {
                let Ok(n) = value.parse::<usize>() else {
                    return Parsed::Bad;
                };
                if length.is_some_and(|l| l != n) {
                    return Parsed::Bad;
                }
                length = Some(n);
            }
            _ => {}
        }
    }
    if !plain || (chunked && length.is_some()) {
        return Parsed::Bad;
    }
    let body = if chunked {
        match chunks(rest, most) {
            Ok(Some(body)) => body,
            Ok(None) if !closed => return Parsed::More,
            _ => return Parsed::Bad,
        }
    } else if let Some(n) = length {
        if n > most {
            return Parsed::Bad;
        }
        if rest.len() < n {
            return if closed { Parsed::Bad } else { Parsed::More };
        }
        rest[..n].to_vec()
    } else {
        if rest.len() > most {
            return Parsed::Bad;
        }
        if !closed {
            return Parsed::More;
        }
        rest.to_vec()
    };
    Parsed::Done(body)
}

fn chunks(mut rest: &[u8], most: usize) -> Result<Option<Vec<u8>>, ()> {
    let mut body = Vec::new();
    loop {
        let Some(at) = rest.windows(2).position(|w| w == b"\r\n") else {
            return if rest.len() > 32 { Err(()) } else { Ok(None) };
        };
        let line = std::str::from_utf8(&rest[..at]).map_err(|_| ())?;
        let size = line.split(';').next().unwrap_or_default().trim();
        if size.is_empty() || size.len() > 8 {
            return Err(());
        }
        let size = usize::from_str_radix(size, 16).map_err(|_| ())?;
        rest = &rest[at + 2..];
        if size == 0 {
            return Ok(Some(body));
        }
        if body.len() + size > most {
            return Err(());
        }
        if rest.len() < size + 2 {
            return Ok(None);
        }
        if &rest[size..size + 2] != b"\r\n" {
            return Err(());
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::{Parsed, parse};

    const OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n";

    fn whole(text: &str) -> Parsed {
        parse(text.as_bytes(), true, 64)
    }

    #[test]
    fn reads_a_body() {
        let text = format!("{OK}Content-Length: 5\r\n\r\nhello trailing");
        assert_eq!(whole(&text), Parsed::Done(b"hello".to_vec()));
        let text = format!("{OK}Content-Length: 5\r\n\r\nhel");
        assert_eq!(parse(text.as_bytes(), false, 64), Parsed::More);
        assert_eq!(whole(&text), Parsed::Bad);
        let text =
            format!("{OK}Transfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2;x=1\r\nlo\r\n0\r\n\r\n");
        assert_eq!(whole(&text), Parsed::Done(b"hello".to_vec()));
        let text = format!("{OK}\r\nhello");
        assert_eq!(whole(&text), Parsed::Done(b"hello".to_vec()));
        assert_eq!(parse(text.as_bytes(), false, 64), Parsed::More);
    }

    #[test]
    fn refuses_what_is_not_a_plain_policy() {
        let cases = [
            "HTTP/1.1 301 Moved\r\nLocation: https://elsewhere\r\nContent-Type: text/plain\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\n\r\nhello",
            "HTTP/2 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
        ];
        for case in cases {
            assert_eq!(whole(case), Parsed::Bad, "{case}");
        }
        let cases = [
            format!("{OK}Content-Length: 65\r\n\r\n"),
            format!("{OK}Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello!"),
            format!(
                "{OK}Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            ),
            format!("{OK}Transfer-Encoding: gzip\r\n\r\nhello"),
            format!(
                "{OK}Transfer-Encoding: chunked\r\n\r\n41\r\n{}\r\n0\r\n\r\n",
                "a".repeat(65)
            ),
            format!("{OK}Transfer-Encoding: chunked\r\n\r\n3\r\nhelxx"),
            format!("{OK}\r\n{}", "a".repeat(65)),
        ];
        for case in &cases {
            assert_eq!(whole(case), Parsed::Bad, "{case}");
        }
    }
}
