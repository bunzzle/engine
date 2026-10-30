use std::time::Duration;

use rt::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    wall: u64,
    start: Instant,
}

impl Clock {
    pub fn start() -> Self {
        Self::at(rt::wall_ms(), rt::now())
    }

    pub fn at(wall: u64, start: Instant) -> Self {
        Self { wall, start }
    }

    pub fn now(&self) -> u64 {
        self.ms(rt::now())
    }

    pub fn ms(&self, instant: Instant) -> u64 {
        let since = instant.saturating_duration_since(self.start).as_millis();
        self.wall
            .saturating_add(u64::try_from(since).unwrap_or(u64::MAX))
    }

    pub fn instant(&self, ms: u64) -> Instant {
        self.start + Duration::from_millis(ms.saturating_sub(self.wall))
    }

    pub fn drift(&self) -> i64 {
        let wall = i128::from(rt::wall_ms());
        let now = i128::from(self.now());
        i64::try_from(wall - now).unwrap_or(if wall > now { i64::MAX } else { i64::MIN })
    }
}
