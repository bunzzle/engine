use crate::Format;

const RANGES: usize = 32;
const PARAMETERS: usize = 8;

pub fn negotiate(accept: Option<&[u8]>) -> Format {
    let mut best: Option<(u16, Format)> = None;
    for range in accept
        .unwrap_or_default()
        .split(|b| *b == b',')
        .take(RANGES)
    {
        if let Some((quality, format)) = parse(range)
            && quality > 0
            && best.is_none_or(|(top, _)| quality > top)
        {
            best = Some((quality, format));
        }
    }
    best.map_or(Format::Text, |(_, format)| format)
}

fn parse(range: &[u8]) -> Option<(u16, Format)> {
    let mut parts = range.split(|b| *b == b';');
    let media = parts.next()?.trim_ascii();
    let (format, version) = if media.eq_ignore_ascii_case(b"application/openmetrics-text") {
        (Format::OpenMetrics, Some(&b"1.0.0"[..]))
    } else if media.eq_ignore_ascii_case(b"text/plain") {
        (Format::Text, Some(&b"0.0.4"[..]))
    } else if media.eq_ignore_ascii_case(b"text/*") || media == b"*/*" {
        (Format::Text, None)
    } else {
        return None;
    };
    let mut quality = 1000;
    for parameter in parts.take(PARAMETERS) {
        let (key, value) = split_once(parameter, b'=')?;
        let key = key.trim_ascii();
        let value = unquote(value.trim_ascii());
        if key.eq_ignore_ascii_case(b"q") {
            quality = parse_quality(value)?;
        } else if key.eq_ignore_ascii_case(b"version") && version.is_some_and(|want| value != want)
        {
            return None;
        }
    }
    Some((quality, format))
}

fn split_once(bytes: &[u8], at: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(|b| *b == at)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

fn unquote(value: &[u8]) -> &[u8] {
    value
        .strip_prefix(b"\"")
        .and_then(|v| v.strip_suffix(b"\""))
        .unwrap_or(value)
}

fn parse_quality(value: &[u8]) -> Option<u16> {
    let (whole, fraction) = match split_once(value, b'.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (value, &b""[..]),
    };
    if fraction.len() > 3 || !fraction.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut thousandths: u16 = 0;
    for i in 0..3 {
        let digit = fraction.get(i).map_or(0, |d| u16::from(d - b'0'));
        thousandths = thousandths * 10 + digit;
    }
    match whole {
        b"0" => Some(thousandths),
        b"1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}
