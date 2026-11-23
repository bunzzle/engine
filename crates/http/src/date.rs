const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn imf(ms: u64) -> String {
    let seconds = ms / 1000;
    let days = seconds / 86_400;
    let time = seconds % 86_400;
    let (year, month, day) = civil(days);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[usize::try_from(days % 7).expect("small")],
        MONTHS[usize::try_from(month - 1).expect("small")],
        time / 3600,
        time % 3600 / 60,
        time % 60,
    )
}

pub fn rfc3339(ms: u64) -> String {
    let seconds = ms / 1000;
    let time = seconds % 86_400;
    let (year, month, day) = civil(seconds / 86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        time / 3600,
        time % 3600 / 60,
        time % 60,
        ms % 1000,
    )
}

pub fn parse_rfc3339(text: &[u8]) -> Option<u64> {
    let (head, rest) = text.split_first_chunk::<19>()?;
    let number = |range: std::ops::Range<usize>| -> Option<u64> {
        let digits = &head[range];
        digits
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| digits.iter().fold(0, |n, d| n * 10 + u64::from(d - b'0')))
    };
    let marks = [(4, b'-'), (7, b'-'), (13, b':'), (16, b':')];
    if marks.iter().any(|&(at, mark)| head[at] != mark) || !matches!(head[10], b'T' | b't') {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if year < 1970 || !(1..=12).contains(&month) || day == 0 || day > month_days(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let (fraction, zone) = match rest.split_first() {
        Some((b'.', tail)) => {
            let digits = tail.iter().take_while(|b| b.is_ascii_digit()).count();
            if !(1..=9).contains(&digits) {
                return None;
            }
            let ms = tail[..digits.min(3)]
                .iter()
                .fold(0, |n, d| n * 10 + u64::from(d - b'0'));
            (
                ms * 10u64.pow(3 - u32::try_from(digits.min(3)).ok()?),
                &tail[digits..],
            )
        }
        _ => (0, rest),
    };
    if !matches!(zone, b"Z" | b"z") {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(((days * 86_400 + hour * 3600 + minute * 60 + second) * 1000) + fraction)
}

fn month_days(year: u64, month: u64) -> u64 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_dates() {
        let cases = [
            (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (784_111_777_000, "Sun, 06 Nov 1994 08:49:37 GMT"),
            (951_782_400_000, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (1_709_251_199_999, "Thu, 29 Feb 2024 23:59:59 GMT"),
            (4_102_444_800_000, "Fri, 01 Jan 2100 00:00:00 GMT"),
        ];
        for (ms, text) in cases {
            assert_eq!(imf(ms), text);
        }
    }

    #[test]
    fn formats_rfc3339_times() {
        let cases = [
            (0, "1970-01-01T00:00:00.000Z"),
            (784_111_777_042, "1994-11-06T08:49:37.042Z"),
            (1_709_251_199_999, "2024-02-29T23:59:59.999Z"),
            (4_102_444_800_000, "2100-01-01T00:00:00.000Z"),
        ];
        for (ms, text) in cases {
            assert_eq!(rfc3339(ms), text);
        }
    }

    #[test]
    fn parses_rfc3339_times() {
        let cases = [
            (0, "1970-01-01T00:00:00.000Z"),
            (0, "1970-01-01t00:00:00z"),
            (784_111_777_042, "1994-11-06T08:49:37.042Z"),
            (784_111_777_040, "1994-11-06T08:49:37.04Z"),
            (784_111_777_000, "1994-11-06T08:49:37Z"),
            (784_111_777_042, "1994-11-06T08:49:37.042999999Z"),
            (1_709_251_199_999, "2024-02-29T23:59:59.999Z"),
            (951_782_400_000, "2000-02-29T00:00:00Z"),
            (4_102_444_800_000, "2100-01-01T00:00:00.000Z"),
        ];
        for (ms, text) in cases {
            assert_eq!(parse_rfc3339(text.as_bytes()), Some(ms), "{text}");
        }
        for ms in [
            0,
            1,
            86_399_999,
            1_709_251_199_999,
            4_102_444_800_000,
            253_402_300_799_999,
        ] {
            assert_eq!(parse_rfc3339(rfc3339(ms).as_bytes()), Some(ms));
        }
        for bad in [
            "",
            "1994-11-06T08:49:37",
            "1994-11-06 08:49:37Z",
            "1994-11-06T08:49:37+00:00",
            "1994-11-06T08:49:37.Z",
            "1994-11-06T08:49:37.0000000000Z",
            "1994-11-06T08:49:60Z",
            "1994-11-06T24:00:00Z",
            "1994-13-06T08:49:37Z",
            "1994-00-06T08:49:37Z",
            "1994-11-31T08:49:37Z",
            "2100-02-29T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "+994-11-06T08:49:37Z",
            "1994-11-06T08:49:37ZZ",
            "1994-11-06T08:49:3aZ",
        ] {
            assert_eq!(parse_rfc3339(bad.as_bytes()), None, "{bad}");
        }
    }
}
