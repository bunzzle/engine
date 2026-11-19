use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

use rt::Notify;

#[derive(Default)]
pub struct Watch {
    head: Cell<u64>,
    fresh: RefCell<BTreeSet<(u8, u32)>>,
    notify: Notify,
}

impl Watch {
    pub(crate) fn starting(head: u64) -> Self {
        Self {
            head: Cell::new(head),
            ..Self::default()
        }
    }

    pub fn head(&self) -> u64 {
        self.head.get()
    }

    pub fn take(&self, kind: u8) -> BTreeSet<u32> {
        let mut fresh = self.fresh.borrow_mut();
        let rest = fresh.split_off(&(kind.saturating_add(1), 0));
        let taken = fresh
            .split_off(&(kind, 0))
            .into_iter()
            .map(|(_, tenant)| tenant)
            .collect();
        fresh.extend(rest);
        taken
    }

    pub async fn wait(&self) {
        self.notify.wait().await;
    }

    pub(crate) fn durable(&self, sequence: u64) {
        self.head.set(self.head.get().max(sequence));
    }

    pub(crate) fn indexed(&self, kind: u8, tenant: u32) {
        self.fresh.borrow_mut().insert((kind, tenant));
    }

    pub(crate) fn wake(&self) {
        self.notify.notify();
    }
}
