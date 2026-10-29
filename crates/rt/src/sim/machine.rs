use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use crate::driver::Driver;
use crate::executor::{Enter, Inner, JoinHandle, spawn};
use crate::sim::SimDriver;
use crate::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stalls {
    pub per_mille: u64,
    pub max: Duration,
}

struct Core {
    inner: Rc<Inner>,
    paused: Cell<Option<Instant>>,
}

pub struct Machine {
    sim: Rc<SimDriver>,
    cores: Vec<Core>,
    stalls: Stalls,
}

impl Machine {
    pub fn new(sim: Rc<SimDriver>, cores: usize, stalls: Stalls) -> Self {
        assert!(cores > 0, "a machine needs at least one core");
        let cores = (0..cores)
            .map(|_| Core {
                inner: Inner::new(Rc::clone(&sim) as Rc<dyn Driver>),
                paused: Cell::new(None),
            })
            .collect();
        Self { sim, cores, stalls }
    }

    pub fn cores(&self) -> usize {
        self.cores.len()
    }

    pub fn spawn_on<F>(&self, core: usize, future: F) -> JoinHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let _enter = Enter::swap(Rc::clone(&self.cores[core].inner));
        spawn(future)
    }

    pub fn block_on<F>(&self, core: usize, future: F) -> F::Output
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let slot = Rc::new(RefCell::new(None));
        let out = Rc::clone(&slot);
        drop(self.spawn_on(core, async move {
            let value = future.await;
            *out.borrow_mut() = Some(value);
        }));
        loop {
            for index in self.order() {
                self.step(index);
                if let Some(value) = slot.borrow_mut().take() {
                    return value;
                }
            }
            if self
                .cores
                .iter()
                .any(|c| c.paused.get().is_none() && c.inner.has_ready())
            {
                continue;
            }
            self.sim.park(self.deadline());
        }
    }

    fn order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.cores.len()).collect();
        for i in (1..order.len()).rev() {
            let bound = u64::try_from(i + 1).expect("fits");
            let j = usize::try_from(self.sim.random() % bound).expect("fits");
            order.swap(i, j);
        }
        order
    }

    fn step(&self, index: usize) {
        let core = &self.cores[index];
        let now = self.sim.now();
        if let Some(until) = core.paused.get() {
            if until > now {
                return;
            }
            core.paused.set(None);
        }
        let _enter = Enter::swap(Rc::clone(&core.inner));
        core.inner.fire_timers();
        if !core.inner.has_ready() {
            return;
        }
        if self.stalls.per_mille > 0 && self.sim.random() % 1000 < self.stalls.per_mille {
            let max = u64::try_from(self.stalls.max.as_nanos()).unwrap_or(u64::MAX);
            let pause = 1 + self.sim.random() % max.max(1);
            core.paused.set(Some(Instant::from_nanos(
                now.as_nanos().saturating_add(pause),
            )));
            return;
        }
        core.inner.run_ready();
    }

    fn deadline(&self) -> Option<Instant> {
        self.cores
            .iter()
            .filter_map(|core| match core.paused.get() {
                Some(until) => Some(until),
                None => core.inner.next_deadline(),
            })
            .min()
    }
}
