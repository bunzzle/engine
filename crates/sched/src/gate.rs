use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};

struct Slot {
    held: Cell<bool>,
    users: Cell<usize>,
    waiters: RefCell<Vec<Waker>>,
}

impl Slot {
    fn new() -> Self {
        Self {
            held: Cell::new(false),
            users: Cell::new(0),
            waiters: RefCell::new(Vec::new()),
        }
    }
}

pub(crate) struct Gate<K> {
    slots: Rc<RefCell<BTreeMap<K, Rc<Slot>>>>,
}

impl<K> Clone for Gate<K> {
    fn clone(&self) -> Self {
        Self {
            slots: Rc::clone(&self.slots),
        }
    }
}

impl<K> Default for Gate<K> {
    fn default() -> Self {
        Self {
            slots: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl<K: Copy + Ord> Gate<K> {
    pub(crate) async fn lock(&self, key: K) -> Guard<K> {
        let slot = {
            let mut slots = self.slots.borrow_mut();
            let slot = slots.entry(key).or_insert_with(|| Rc::new(Slot::new()));
            slot.users.set(slot.users.get() + 1);
            Rc::clone(slot)
        };
        let mut reservation = Reservation {
            gate: self.clone(),
            key,
            slot: Rc::clone(&slot),
            armed: true,
        };
        poll_fn(|cx| {
            if !slot.held.replace(true) {
                return Poll::Ready(());
            }
            slot.waiters.borrow_mut().push(cx.waker().clone());
            Poll::Pending
        })
        .await;
        reservation.armed = false;
        Guard {
            gate: self.clone(),
            key,
            slot: reservation.slot.clone(),
        }
    }
}

struct Reservation<K: Copy + Ord> {
    gate: Gate<K>,
    key: K,
    slot: Rc<Slot>,
    armed: bool,
}

impl<K: Copy + Ord> Drop for Reservation<K> {
    fn drop(&mut self) {
        if self.armed {
            release(&self.gate, self.key, &self.slot, false);
        }
    }
}

pub(crate) struct Guard<K: Copy + Ord> {
    gate: Gate<K>,
    key: K,
    slot: Rc<Slot>,
}

impl<K: Copy + Ord> Drop for Guard<K> {
    fn drop(&mut self) {
        release(&self.gate, self.key, &self.slot, true);
    }
}

fn release<K: Copy + Ord>(gate: &Gate<K>, key: K, slot: &Slot, held: bool) {
    if held {
        slot.held.set(false);
        for waiter in slot.waiters.borrow_mut().drain(..) {
            waiter.wake();
        }
    }
    let users = slot.users.get().saturating_sub(1);
    slot.users.set(users);
    if users == 0 {
        gate.slots.borrow_mut().remove(&key);
    }
}
