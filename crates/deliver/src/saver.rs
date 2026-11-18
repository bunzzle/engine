use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use rt::spawn;
use sched::Records;

pub(crate) type Slot = (u16, u32);

#[derive(Default)]
pub(crate) struct Saver {
    records: RefCell<Option<Rc<dyn Records>>>,
    taken: RefCell<BTreeSet<Slot>>,
    pending: RefCell<BTreeMap<Slot, Option<Vec<u8>>>>,
    busy: Cell<bool>,
    unsaved: Cell<u64>,
}

impl Saver {
    pub(crate) fn attach(&self, records: Rc<dyn Records>, taken: BTreeSet<Slot>) {
        *self.records.borrow_mut() = Some(records);
        *self.taken.borrow_mut() = taken;
    }

    pub(crate) fn unsaved(&self) -> u64 {
        self.unsaved.get()
    }

    pub(crate) fn take(&self, bound: usize) -> Option<Slot> {
        let home = self.records.borrow().as_ref()?.home();
        let mut taken = self.taken.borrow_mut();
        let id = (0..u32::try_from(bound).unwrap_or(u32::MAX))
            .find(|&id| !taken.contains(&(home, id)))?;
        taken.insert((home, id));
        Some((home, id))
    }

    pub(crate) fn save(self: &Rc<Self>, slot: Slot, data: Option<Vec<u8>>) {
        if data.is_none() {
            self.taken.borrow_mut().remove(&slot);
        }
        self.pending.borrow_mut().insert(slot, data);
        if !self.busy.replace(true) {
            drop(spawn(Rc::clone(self).drain()));
        }
    }

    async fn drain(self: Rc<Self>) {
        loop {
            let next = self.pending.borrow_mut().pop_first();
            let records = self.records.borrow().clone();
            let (Some(((shard, id), data)), Some(records)) = (next, records) else {
                self.busy.set(false);
                return;
            };
            let done = match data {
                Some(data) => records.put(shard, id, data).await,
                None => records.remove(shard, id).await,
            };
            if done.is_err() {
                self.unsaved.set(self.unsaved.get() + 1);
            }
        }
    }
}
