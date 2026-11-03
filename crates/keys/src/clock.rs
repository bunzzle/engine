use std::time::Duration;

use rt::Instant;

pub const MIN_GAP: Duration = Duration::from_hours(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Wait,
    Move,
    Behind,
    Ahead,
}

#[derive(Default)]
pub struct Clock {
    last_move: Option<Instant>,
}

impl Clock {
    pub fn step(&self, day: u32, wall_day: u32, now: Instant) -> Step {
        if wall_day < day {
            return Step::Behind;
        }
        if wall_day == day {
            return Step::Wait;
        }
        if wall_day > day + 1 {
            return Step::Ahead;
        }
        match self.last_move {
            Some(last) if now.saturating_duration_since(last) < MIN_GAP => Step::Wait,
            _ => Step::Move,
        }
    }

    pub fn moved(&mut self, now: Instant) {
        self.last_move = Some(now);
    }
}
