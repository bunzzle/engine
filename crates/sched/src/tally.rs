use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use control::Table;
use rt::{Notify, Sender, channel};
use store::Changes;

use crate::cursor::{Cursor, read_cursor, write_cursor};
use crate::events::{KIND_EVENT, sequence};
use crate::reader::{kept, stamped};

const PAGE: usize = 1024;

pub(crate) type Targets = BTreeMap<u32, (u32, u32, u8)>;

pub(crate) struct Watched {
    pub tenant: u32,
    pub generation: u32,
    pub events: u8,
    pub from: BTreeMap<u16, (u64, u32)>,
}

#[derive(Default)]
pub(crate) struct Tallies {
    attached: Cell<bool>,
    busy: Cell<bool>,
    asks: RefCell<Vec<(u32, Sender<bool>)>>,
    pub wake: Notify,
    idle: Notify,
}

struct Busy<'a>(&'a Tallies);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.busy.set(false);
        self.0.idle.notify();
    }
}

pub(crate) struct Attached<'a>(&'a Tallies);

impl Drop for Attached<'_> {
    fn drop(&mut self) {
        self.0.attached.set(false);
        self.0.asks.borrow_mut().clear();
    }
}

impl Tallies {
    pub async fn ask(&self, changes: &Changes, table: &RefCell<Table>, below: u32) -> bool {
        if self.attached.get() {
            let (reply, mut answer) = channel();
            self.asks.borrow_mut().push((below, reply));
            self.wake.notify();
            return answer.recv().await.unwrap_or(false);
        }
        self.busy.set(true);
        let _busy = Busy(self);
        let hooks = targets(&table.borrow());
        stored(changes, hooks, below).await
    }

    pub async fn attach(&self) -> Attached<'_> {
        while self.busy.get() {
            self.idle.wait().await;
        }
        self.attached.set(true);
        Attached(self)
    }

    pub fn take(&self) -> Vec<(u32, Sender<bool>)> {
        std::mem::take(&mut *self.asks.borrow_mut())
    }

    pub fn waiting(&self) -> bool {
        !self.asks.borrow().is_empty()
    }
}

pub(crate) fn targets(table: &Table) -> Targets {
    table
        .every_hook()
        .filter(|h| {
            table
                .tenant(h.tenant)
                .is_some_and(|t| t.generation == h.generation)
                && !table.gone(h.tenant, h.generation)
        })
        .map(|h| (h.id, (h.tenant, h.generation, h.events)))
        .collect()
}

pub(crate) async fn due(changes: &Changes, below: u32) -> Option<Vec<(u16, u32)>> {
    let kept = changes.partitions(KIND_EVENT).await.ok()?;
    Some(kept.into_iter().filter(|&(_, day)| day < below).collect())
}

pub(crate) async fn count(
    changes: &Changes,
    parts: &[(u16, u32)],
    hooks: &BTreeMap<u32, Watched>,
) -> Option<BTreeMap<(u32, u16), u64>> {
    let mut lost = BTreeMap::new();
    let tenants: BTreeSet<(u32, u32)> = hooks.values().map(|w| (w.tenant, w.generation)).collect();
    for &(shard, day) in parts {
        for &(tenant, generation) in &tenants {
            let due: Vec<(u32, u8, u64)> = hooks
                .iter()
                .filter(|(_, w)| (w.tenant, w.generation) == (tenant, generation))
                .filter_map(|(&hook, w)| {
                    let &(floor, counted) = w.from.get(&shard)?;
                    (day > counted).then_some((hook, w.events, floor))
                })
                .collect();
            let Some(mut from) = due.iter().map(|d| d.2).min() else {
                continue;
            };
            for &(hook, _, _) in &due {
                lost.entry((hook, shard)).or_insert(0u64);
            }
            loop {
                let range = stamped(tenant, from.saturating_add(1))..stamped(tenant, u64::MAX);
                let found = changes
                    .scan(shard, (KIND_EVENT, day), range, PAGE)
                    .await
                    .ok()?;
                let done = found.len() < PAGE;
                for entry in &found {
                    let at = sequence(&entry.key);
                    from = at;
                    let Some(event) = kept(entry, generation) else {
                        continue;
                    };
                    for &(hook, events, floor) in &due {
                        if at > floor && events & (1 << event.kind as u8) != 0 {
                            *lost.entry((hook, shard)).or_insert(0) += 1;
                        }
                    }
                }
                if done {
                    break;
                }
            }
        }
    }
    Some(lost)
}

pub(crate) async fn stored(changes: &Changes, hooks: Targets, below: u32) -> bool {
    let Some(parts) = due(changes, below).await else {
        return false;
    };
    if parts.is_empty() || hooks.is_empty() {
        return true;
    }
    let shards: BTreeSet<u16> = parts.iter().map(|p| p.0).collect();
    let mut cursors: BTreeMap<(u32, u16), Cursor> = BTreeMap::new();
    let mut watched = BTreeMap::new();
    for (hook, (tenant, generation, events)) in hooks {
        let mut from = BTreeMap::new();
        for &shard in &shards {
            let Ok(found) = read_cursor(changes, shard, tenant, hook).await else {
                return false;
            };
            if let Some(cursor) = found.filter(|c| c.generation == generation) {
                from.insert(shard, (cursor.acked, cursor.counted));
                cursors.insert((hook, shard), cursor);
            }
        }
        watched.insert(
            hook,
            Watched {
                tenant,
                generation,
                events,
                from,
            },
        );
    }
    let Some(lost) = count(changes, &parts, &watched).await else {
        return false;
    };
    for ((hook, shard), n) in lost {
        let (Some(mut cursor), Some(w)) =
            (cursors.get(&(hook, shard)).copied(), watched.get(&hook))
        else {
            continue;
        };
        cursor.lost = cursor.lost.saturating_add(n);
        cursor.counted = below - 1;
        if write_cursor(changes, shard, w.tenant, hook, &cursor)
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}
