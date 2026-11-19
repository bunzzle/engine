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
}
