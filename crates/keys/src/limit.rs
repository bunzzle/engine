use std::collections::HashMap;

use rt::Instant;

const SCALE: u64 = 1_000_000_000;
const MAX_TENANTS: usize = 65_536;

#[derive(Clone, Copy, Debug)]
pub struct Rate {
    pub per_second: u64,
    pub burst: u64,
}

#[derive(Clone, Copy)]
struct Bucket {
    level: u64,
    at: Instant,
}

impl Bucket {
    fn full(rate: Rate, now: Instant) -> Self {
        Self {
            level: rate.burst * SCALE,
            at: now,
        }
    }

    fn refill(&mut self, rate: Rate, now: Instant) {
        let nanos =
            u64::try_from(now.saturating_duration_since(self.at).as_nanos()).unwrap_or(u64::MAX);
        self.level = self
            .level
            .saturating_add(nanos.saturating_mul(rate.per_second))
            .min(rate.burst * SCALE);
        self.at = now;
    }

    fn has(&self) -> bool {
        self.level >= SCALE
    }

    fn take(&mut self) {
        self.level -= SCALE;
    }
}

pub struct Limits {
    tenant: Rate,
    node: Rate,
    tenants: HashMap<u32, Bucket>,
    total: Bucket,
}

impl Limits {
    pub fn new(tenant: Rate, node: Rate, now: Instant) -> Self {
        Self {
            tenant,
            node,
            tenants: HashMap::new(),
            total: Bucket::full(node, now),
        }
    }

    pub fn take(&mut self, tenant: u32, now: Instant) -> bool {
        if self.tenants.len() >= MAX_TENANTS && !self.tenants.contains_key(&tenant) {
            let rate = self.tenant;
            self.tenants.retain(|_, bucket| {
                bucket.refill(rate, now);
                bucket.level < rate.burst * SCALE
            });
        }
        let rate = self.tenant;
        let bucket = self
            .tenants
            .entry(tenant)
            .or_insert_with(|| Bucket::full(rate, now));
        bucket.refill(rate, now);
        self.total.refill(self.node, now);
        if !bucket.has() || !self.total.has() {
            return false;
        }
        bucket.take();
        self.total.take();
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rt::Instant;

    use super::{Limits, Rate};

    #[test]
    fn tenant_and_node_rates_hold() {
        let start = Instant::default();
        let mut limits = Limits::new(
            Rate {
                per_second: 10,
                burst: 5,
            },
            Rate {
                per_second: 100,
                burst: 8,
            },
            start,
        );
        assert_eq!((0..10).filter(|_| limits.take(1, start)).count(), 5);
        assert_eq!((0..10).filter(|_| limits.take(2, start)).count(), 3);
        assert!(!limits.take(3, start));
        let later = start + Duration::from_millis(100);
        assert!(limits.take(1, later));
        assert!(!limits.take(1, later));
        let idle = start + Duration::from_secs(10);
        assert_eq!((0..10).filter(|_| limits.take(1, idle)).count(), 5);
    }
}
