const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn rfc5322(ms: u64) -> String {
    let seconds = ms / 1000;
    let days = seconds / 86_400;
    let time = seconds % 86_400;
    let (year, month, day) = civil(days);
    format!(
        "{}, {day} {} {year} {:02}:{:02}:{:02} +0000",
        DAYS[usize::try_from(days % 7).expect("small")],
        MONTHS[usize::try_from(month - 1).expect("small")],
        time / 3600,
        time % 3600 / 60,
        time % 60,
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
            (0, "Thu, 1 Jan 1970 00:00:00 +0000"),
            (951_782_400_000, "Tue, 29 Feb 2000 00:00:00 +0000"),
            (1_709_251_199_999, "Thu, 29 Feb 2024 23:59:59 +0000"),
            (1_794_478_400_000, "Thu, 12 Nov 2026 10:13:20 +0000"),
            (4_102_444_800_000, "Fri, 1 Jan 2100 00:00:00 +0000"),
        ];
        for (ms, text) in cases {
            assert_eq!(rfc5322(ms), text);
        }
    }

    #[test]
    fn days_follow_each_other() {
        let mut last = civil(0);
        for days in 1..200_000 {
            let next = civil(days);
            let rolled = next.2 == 1 && (next.1 == last.1 + 1 || (next.1 == 1 && last.1 == 12));
            assert!(next.2 == last.2 + 1 || rolled, "{last:?} {next:?}");
            last = next;
        }
    }
}
