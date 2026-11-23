use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use rt::Notify;

#[derive(Default)]
pub struct Watch {
    head: Cell<u64>,
    fresh: RefCell<BTreeMap<u8, BTreeSet<u32>>>,
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
        self.fresh.borrow_mut().remove(&kind).unwrap_or_default()
    }

    pub async fn wait(&self) {
        self.notify.wait().await;
    }

    pub(crate) fn durable(&self, sequence: u64) {
        self.head.set(self.head.get().max(sequence));
    }

    pub(crate) fn indexed(&self, kind: u8, tenant: u32) {
        self.fresh
            .borrow_mut()
            .entry(kind)
            .or_default()
            .insert(tenant);
    }

    pub(crate) fn wake(&self) {
        self.notify.notify();
    }
}
