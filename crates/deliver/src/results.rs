use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rt::wall_ms;

use crate::report::{Applied, Applies, Detail, ResultType};

pub(crate) const DETAILS: usize = 32;
pub(crate) const DOMAINS: usize = 10_000;
pub(crate) const POLICIES: usize = 4;
const KEPT_DAYS: u64 = 2;
const DAY_MS: u64 = 86_400_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Failure {
    pub(crate) result: ResultType,
    pub(crate) sending: IpAddr,
    pub(crate) mx: Option<String>,
    pub(crate) receiving: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub(crate) domain: String,
    pub(crate) policy: Applied,
    pub(crate) muted: bool,
}

#[derive(Default)]
struct Counts {
    success: u64,
    failure: u64,
    details: BTreeMap<Failure, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taken {
    pub day: u64,
    pub domain: String,
    pub policies: Vec<Applies>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResultStats {
    pub domains: u64,
    pub dropped: u64,
    pub overflow: u64,
}

#[derive(Default)]
pub(crate) struct Results {
    days: RefCell<BTreeMap<(u64, String), BTreeMap<Applied, Counts>>>,
    today: RefCell<(u64, BTreeSet<String>)>,
    dropped: Cell<u64>,
    overflow: Cell<u64>,
}

impl Results {
    pub(crate) fn success(&self, scope: &Scope) {
        self.counts(scope, |counts| counts.success += 1);
    }

    pub(crate) fn failure(&self, scope: &Scope, failure: Failure) {
        let overflow = &self.overflow;
        self.counts(scope, move |counts| {
            counts.failure += 1;
            let known = counts.details.contains_key(&failure);
            if known || counts.details.len() < DETAILS {
                *counts.details.entry(failure).or_default() += 1;
            } else {
                overflow.set(overflow.get() + 1);
            }
        });
    }

    fn counts(&self, scope: &Scope, change: impl FnOnce(&mut Counts)) {
        if scope.muted {
            return;
        }
        let day = wall_ms() / DAY_MS;
        let mut days = self.days.borrow_mut();
        let mut today = self.today.borrow_mut();
        if today.0 != day {
            *today = (day, BTreeSet::new());
            days.retain(|(kept, _), _| kept + KEPT_DAYS > day);
        }
        if !today.1.contains(&scope.domain) {
            if today.1.len() >= DOMAINS {
                self.dropped.set(self.dropped.get() + 1);
                return;
            }
            today.1.insert(scope.domain.clone());
        }
        let policies = days.entry((day, scope.domain.clone())).or_default();
        if !policies.contains_key(&scope.policy) && policies.len() >= POLICIES {
            self.dropped.set(self.dropped.get() + 1);
            return;
        }
        change(policies.entry(scope.policy.clone()).or_default());
    }

    pub(crate) fn take(&self) -> Vec<Taken> {
        let days = std::mem::take(&mut *self.days.borrow_mut());
        days.into_iter()
            .map(|((day, domain), policies)| Taken {
                day,
                domain,
                policies: policies
                    .into_iter()
                    .map(|(policy, counts)| Applies {
                        policy,
                        success: counts.success,
                        failure: counts.failure,
                        details: counts
                            .details
                            .into_iter()
                            .map(|(failure, count)| Detail {
                                result: failure.result,
                                sending: failure.sending,
                                mx: failure.mx,
                                receiving: failure.receiving,
                                count,
                                reason: None,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect()
    }

    pub(crate) fn stats(&self) -> ResultStats {
        ResultStats {
            domains: self.days.borrow().len() as u64,
            dropped: self.dropped.get(),
            overflow: self.overflow.get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::rc::Rc;

    use rt::Runtime;
    use rt::sim::{Config, SimDriver};

    use super::{DETAILS, DOMAINS, Failure, POLICIES, Results, Scope};
    use crate::report::{Applied, ResultType};

    fn scope(domain: &str) -> Scope {
        Scope {
            domain: domain.to_owned(),
            policy: Applied::None,
            muted: false,
        }
    }

    fn failure(n: u32) -> Failure {
        Failure {
            result: ResultType::StarttlsNotSupported,
            sending: IpAddr::V4(Ipv4Addr::from(n)),
            mx: None,
            receiving: None,
        }
    }

    fn run(test: impl FnOnce() + 'static) {
        let driver = Rc::new(SimDriver::new(1, Config::default()));
        Runtime::new(driver).block_on(async move { test() });
    }

    #[test]
    fn details_and_domains_are_bounded() {
        run(|| {
            let results = Results::default();
            let one = scope("a.example");
            for n in 0..40 {
                results.failure(&one, failure(n));
            }
            results.failure(&one, failure(0));
            results.success(&one);
            for n in 0..DOMAINS {
                results.success(&scope(&format!("d{n}.example")));
            }
            let stats = results.stats();
            assert_eq!(
                (stats.domains, stats.dropped, stats.overflow),
                (10_000, 1, 8)
            );
            let taken = results.take();
            let a = taken.iter().find(|t| t.domain == "a.example").expect("a");
            let applies = &a.policies[0];
            assert_eq!((applies.success, applies.failure), (1, 41));
            assert_eq!(applies.details.len(), DETAILS);
            assert_eq!(applies.details[0].count, 2);
            assert_eq!(results.take(), []);
            results.success(&scope("late.example"));
            results.success(&scope("d1.example"));
            assert_eq!(results.stats().domains, 1);
            assert_eq!(results.stats().dropped, 2);
            for n in 0..6 {
                let policy = Scope {
                    domain: "d1.example".into(),
                    policy: Applied::Tlsa {
                        records: vec![n.to_string()],
                    },
                    muted: false,
                };
                results.success(&policy);
            }
            let taken = results.take();
            assert_eq!(taken.len(), 1);
            assert_eq!(taken[0].policies.len(), POLICIES);
            assert_eq!(results.stats().dropped, 5);
        });
    }
}
