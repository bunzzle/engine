use std::collections::BTreeMap;

use crate::sealing::Unsealable;

pub const DROPS_PER_MINUTE: u32 = 16;
const MINUTE: u64 = 60_000;
const TENANTS: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Drop,
    Hold,
    Quarantine,
    Defer,
}

pub fn action(fault: Unsealable, day: u32, oldest: Option<u32>) -> Action {
    match fault {
        Unsealable::Gone if oldest.is_some_and(|oldest| day < oldest) => Action::Drop,
        Unsealable::Gone | Unsealable::Unknown => Action::Hold,
        Unsealable::Bad => Action::Quarantine,
        Unsealable::Unavailable | Unsealable::Failed => Action::Defer,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnopenedStats {
    pub dropped: u64,
    pub held: u64,
    pub quarantined: u64,
    pub deferred: u64,
    pub trips: u64,
    pub tenants: BTreeMap<u32, u64>,
}

#[derive(Default)]
pub(crate) struct Breaker {
    start: u64,
    count: u32,
    pub(crate) stats: UnopenedStats,
}

impl Breaker {
    pub(crate) fn room(&mut self, now: u64) -> bool {
        let room = now.saturating_sub(self.start) >= MINUTE || self.count < DROPS_PER_MINUTE;
        if !room {
            self.stats.trips += 1;
        }
        room
    }

    pub(crate) fn decide(&mut self, tenant: u32, action: Action, now: u64) -> Action {
        let action = match action {
            Action::Drop if now.saturating_sub(self.start) >= MINUTE => {
                self.start = now;
                self.count = 1;
                Action::Drop
            }
            Action::Drop if self.count < DROPS_PER_MINUTE => {
                self.count += 1;
                Action::Drop
            }
            Action::Drop => {
                self.stats.trips += 1;
                Action::Hold
            }
            other => other,
        };
        match action {
            Action::Drop => {
                self.stats.dropped += 1;
                let tenants = &mut self.stats.tenants;
                if tenants.len() < TENANTS || tenants.contains_key(&tenant) {
                    *tenants.entry(tenant).or_default() += 1;
                }
            }
            Action::Hold => self.stats.held += 1,
            Action::Quarantine => self.stats.quarantined += 1,
            Action::Defer => self.stats.deferred += 1,
        }
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faults_map_to_actions() {
        let cases = [
            (Unsealable::Gone, 4, Some(5), Action::Drop),
            (Unsealable::Gone, 5, Some(5), Action::Hold),
            (Unsealable::Gone, 4, None, Action::Hold),
            (Unsealable::Unknown, 4, Some(5), Action::Hold),
            (Unsealable::Bad, 4, Some(5), Action::Quarantine),
            (Unsealable::Unavailable, 4, Some(5), Action::Defer),
            (Unsealable::Failed, 4, Some(5), Action::Defer),
        ];
        for (fault, day, oldest, expected) in cases {
            assert_eq!(
                action(fault, day, oldest),
                expected,
                "{fault:?} {day} {oldest:?}"
            );
        }
    }

    #[test]
    fn the_breaker_holds_drops_over_the_rate_until_a_minute_passes() {
        let mut breaker = Breaker::default();
        let now = 10 * MINUTE;
        for n in 0..DROPS_PER_MINUTE {
            let tenant = n % 2;
            assert_eq!(
                breaker.decide(tenant, Action::Drop, now + u64::from(n)),
                Action::Drop
            );
        }
        assert!(!breaker.room(now + 100));
        assert_eq!(breaker.decide(0, Action::Drop, now + 100), Action::Hold);
        assert_eq!(breaker.decide(0, Action::Defer, now + 100), Action::Defer);
        assert_eq!(breaker.decide(0, Action::Drop, now + MINUTE), Action::Drop);
        let stats = &breaker.stats;
        assert_eq!(
            (stats.dropped, stats.held, stats.deferred, stats.trips),
            (17, 1, 1, 2)
        );
        assert_eq!(stats.tenants.get(&0), Some(&9));
        assert_eq!(stats.tenants.get(&1), Some(&8));
        assert!(breaker.room(now + 2 * MINUTE));
    }
}
