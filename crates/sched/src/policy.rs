const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;

pub const BACKOFF: [u64; 7] = [
    MINUTE,
    5 * MINUTE,
    15 * MINUTE,
    30 * MINUTE,
    HOUR,
    2 * HOUR,
    4 * HOUR,
];
const THROTTLE: [u64; 3] = [MINUTE, 5 * MINUTE, 15 * MINUTE];
const FULL: [u64; 2] = [HOUR, 4 * HOUR];
const GREYLIST: u64 = 5 * MINUTE;

pub const LONGEST: u64 = 4 * HOUR;

pub const CLASS_GREYLIST: u8 = 8;
pub const CLASS_THROTTLE: u8 = 9;
pub const CLASS_FULL: u8 = 10;
pub const CLASS_RETRY_AFTER: u8 = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Temporary,
    Greylisted,
    Throttled,
    MailboxFull,
    RetryAfter(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Delivered,
    Failed,
    Deferred(Kind),
}

pub fn delay(kind: Kind, attempts: u16) -> (u64, u8) {
    let step = usize::from(attempts.max(1) - 1);
    match kind {
        Kind::Greylisted if attempts <= 1 => (GREYLIST, CLASS_GREYLIST),
        Kind::Temporary | Kind::Greylisted => backoff(step),
        Kind::Throttled => (ladder(&THROTTLE, step), CLASS_THROTTLE),
        Kind::MailboxFull => (ladder(&FULL, step), CLASS_FULL),
        Kind::RetryAfter(ms) => {
            let next = BACKOFF
                .iter()
                .copied()
                .find(|d| *d >= ms)
                .unwrap_or(LONGEST);
            (next, CLASS_RETRY_AFTER)
        }
    }
}

pub fn clamp(due: u64, now: u64) -> u64 {
    due.min(now.saturating_add(LONGEST))
}

fn backoff(step: usize) -> (u64, u8) {
    let index = step.min(BACKOFF.len() - 1);
    let class = u8::try_from(index + 1).expect("class fits");
    (BACKOFF[index], class)
}

fn ladder(steps: &[u64], step: usize) -> u64 {
    steps[step.min(steps.len() - 1)]
}
