use sched::{
    BACKOFF, CLASS_FULL, CLASS_GREYLIST, CLASS_RETRY_AFTER, CLASS_THROTTLE, Kind, LONGEST, clamp,
    delay,
};

const MINUTE: u64 = 60_000;

#[test]
fn temporary_failures_climb_the_backoff_ladder_and_stay_at_the_top() {
    for (attempts, expected) in (1..).zip(BACKOFF) {
        let (wait, class) = delay(Kind::Temporary, attempts);
        assert_eq!(wait, expected);
        assert_eq!(u16::from(class), attempts);
    }
    assert_eq!(delay(Kind::Temporary, 40), (LONGEST, 7));
    assert_eq!(delay(Kind::Temporary, 0), (MINUTE, 1));
}

#[test]
fn each_reply_kind_has_its_own_delay() {
    assert_eq!(delay(Kind::Greylisted, 1), (5 * MINUTE, CLASS_GREYLIST));
    assert_eq!(delay(Kind::Greylisted, 2), (5 * MINUTE, 2));
    assert_eq!(delay(Kind::Throttled, 1), (MINUTE, CLASS_THROTTLE));
    assert_eq!(delay(Kind::Throttled, 9), (15 * MINUTE, CLASS_THROTTLE));
    assert_eq!(delay(Kind::MailboxFull, 1), (60 * MINUTE, CLASS_FULL));
    assert_eq!(delay(Kind::MailboxFull, 5), (LONGEST, CLASS_FULL));
    assert_eq!(
        delay(Kind::RetryAfter(90_000), 1),
        (5 * MINUTE, CLASS_RETRY_AFTER)
    );
    assert_eq!(
        delay(Kind::RetryAfter(LONGEST * 3), 1),
        (LONGEST, CLASS_RETRY_AFTER)
    );
}

#[test]
fn due_times_past_the_longest_delay_are_clamped() {
    assert_eq!(clamp(500, 1_000), 500);
    assert_eq!(clamp(1_000 + LONGEST, 1_000), 1_000 + LONGEST);
    assert_eq!(clamp(u64::MAX, 1_000), 1_000 + LONGEST);
}
