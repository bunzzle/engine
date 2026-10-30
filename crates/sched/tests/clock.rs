use std::time::Duration;

use rt::Instant;
use sched::Clock;

#[test]
fn scheduler_time_follows_the_monotonic_clock_from_start() {
    let start = Instant::from_nanos(7_000_000_000);
    let clock = Clock::at(1_000_000, start);
    assert_eq!(clock.ms(start), 1_000_000);
    assert_eq!(clock.ms(start + Duration::from_millis(2_500)), 1_002_500);
    assert_eq!(clock.ms(Instant::from_nanos(0)), 1_000_000);
    assert_eq!(
        clock.instant(1_002_500),
        start + Duration::from_millis(2_500)
    );
    assert_eq!(clock.instant(5), start);
}
