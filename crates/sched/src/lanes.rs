use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;

use spool::MessageId;

pub type QueueId = u32;

const ENTRY_BYTES: usize = 96;
const RANGE_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub active: u32,
    pub queue: u32,
    pub batch: u32,
    pub bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            active: 20_000,
            queue: 100,
            batch: 100,
            bytes: 256 << 20,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub message: MessageId,
    pub recipients: Vec<Range<u32>>,
    pub forced: bool,
}

impl Entry {
    fn count(&self) -> u32 {
        self.recipients.iter().map(|r| r.end - r.start).sum()
    }

    fn bytes(&self) -> usize {
        ENTRY_BYTES + RANGE_BYTES * self.recipients.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Take {
    pub queue: QueueId,
    pub tenant: u32,
    pub count: u32,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    Idle,
    Timer(u64),
    Ring,
    Parked,
}

struct Queue {
    tenant: u32,
    entries: BTreeMap<(u64, u64), Entry>,
    in_flight: u32,
    place: Place,
}

impl Queue {
    fn head(&self) -> Option<u64> {
        self.entries.first_key_value().map(|((due, _), _)| *due)
    }
}

#[derive(Default)]
struct Tenant {
    due: VecDeque<QueueId>,
    queues: BTreeSet<QueueId>,
    in_ring: bool,
}

pub struct Lanes {
    limits: Limits,
    queues: BTreeMap<QueueId, Queue>,
    timers: BTreeSet<(u64, QueueId)>,
    ring: VecDeque<u32>,
    tenants: BTreeMap<u32, Tenant>,
    seq: u64,
    active: u32,
    recipients: u64,
    bytes: usize,
}

impl Lanes {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            queues: BTreeMap::new(),
            timers: BTreeSet::new(),
            ring: VecDeque::new(),
            tenants: BTreeMap::new(),
            seq: 0,
            active: 0,
            recipients: 0,
            bytes: 0,
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn active(&self) -> u32 {
        self.active
    }

    pub fn recipients(&self) -> u64 {
        self.recipients
    }

    pub fn entries(&self) -> usize {
        self.queues.values().map(|q| q.entries.len()).sum()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn over_budget(&self) -> bool {
        self.bytes > self.limits.bytes
    }

    pub fn queues(&self, tenant: u32) -> Vec<QueueId> {
        self.tenants
            .get(&tenant)
            .map(|t| t.queues.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn deadline(&self) -> Option<u64> {
        self.timers.first().map(|(due, _)| *due)
    }

    pub fn enqueue(&mut self, queue: QueueId, tenant: u32, entry: Entry, due: u64, now: u64) {
        let count = entry.count();
        if count == 0 {
            return;
        }
        let seq = self.next_seq();
        self.recipients += u64::from(count);
        self.bytes += entry.bytes();
        let state = self.queues.entry(queue).or_insert_with(|| Queue {
            tenant,
            entries: BTreeMap::new(),
            in_flight: 0,
            place: Place::Idle,
        });
        state.entries.insert((due, seq), entry);
        let tenant = state.tenant;
        self.tenants.entry(tenant).or_default().queues.insert(queue);
        match state.place {
            Place::Timer(at) if due < at => {
                self.timers.remove(&(at, queue));
                self.place(queue, now);
            }
            Place::Idle => self.place(queue, now),
            _ => {}
        }
    }

    pub fn next(&mut self, now: u64) -> Option<Take> {
        while let Some(&(due, queue)) = self.timers.first() {
            if due > now {
                break;
            }
            self.timers.pop_first();
            self.place(queue, now);
        }
        while self.active < self.limits.active {
            let tenant_id = self.ring.pop_front()?;
            let tenant = self.tenants.get_mut(&tenant_id).expect("tenant in ring");
            tenant.in_ring = false;
            let Some(queue) = tenant.due.pop_front() else {
                continue;
            };
            if !tenant.due.is_empty() {
                tenant.in_ring = true;
                self.ring.push_back(tenant_id);
            }
            let room = self.limits.active - self.active;
            let take = self.take(queue, now, room);
            self.place(queue, now);
            if let Some(take) = take {
                return Some(take);
            }
        }
        None
    }

    pub fn done(&mut self, queue: QueueId, count: u32, now: u64) {
        self.active -= count;
        let Some(state) = self.queues.get_mut(&queue) else {
            return;
        };
        state.in_flight -= count;
        if matches!(state.place, Place::Parked | Place::Idle) {
            self.place(queue, now);
        }
    }

    pub fn retry_now(&mut self, queue: QueueId, now: u64) {
        let Some(state) = self.queues.get_mut(&queue) else {
            return;
        };
        let entries = std::mem::take(&mut state.entries);
        for (_, mut entry) in entries {
            entry.forced = true;
            self.seq += 1;
            let seq = self.seq;
            let state = self.queues.get_mut(&queue).expect("queue");
            state.entries.insert((now, seq), entry);
        }
        let state = self.queues.get_mut(&queue).expect("queue");
        if let Place::Timer(at) = state.place {
            self.timers.remove(&(at, queue));
            self.place(queue, now);
        }
    }

    pub fn retry_tenant(&mut self, tenant: u32, now: u64) {
        for queue in self.queues(tenant) {
            self.retry_now(queue, now);
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn take(&mut self, queue: QueueId, now: u64, room: u32) -> Option<Take> {
        let limits = self.limits;
        let state = self.queues.get_mut(&queue)?;
        let mut want = limits
            .batch
            .min(limits.queue.saturating_sub(state.in_flight))
            .min(room);
        let mut entries = Vec::new();
        let mut count = 0;
        while want > 0 {
            let Some(mut first) = state.entries.first_entry() else {
                break;
            };
            if first.key().0 > now {
                break;
            }
            let entry = first.get_mut();
            let before = entry.bytes();
            let taken = split(&mut entry.recipients, want);
            let n: u32 = taken.iter().map(|r| r.end - r.start).sum();
            let message = entry.message;
            let forced = entry.forced;
            if entry.recipients.is_empty() {
                first.remove();
                self.bytes -= before;
            } else {
                self.bytes = self.bytes - before + entry.bytes();
            }
            want -= n;
            count += n;
            entries.push(Entry {
                message,
                recipients: taken,
                forced,
            });
        }
        if count == 0 {
            return None;
        }
        state.in_flight += count;
        self.active += count;
        self.recipients -= u64::from(count);
        Some(Take {
            queue,
            tenant: state.tenant,
            count,
            entries,
        })
    }

    fn place(&mut self, queue: QueueId, now: u64) {
        let Some(state) = self.queues.get_mut(&queue) else {
            return;
        };
        let place = match state.head() {
            None => Place::Idle,
            Some(_) if state.in_flight >= self.limits.queue => Place::Parked,
            Some(due) if due <= now => Place::Ring,
            Some(due) => Place::Timer(due),
        };
        state.place = place;
        let tenant_id = state.tenant;
        match place {
            Place::Idle if state.in_flight == 0 => {
                self.queues.remove(&queue);
                if let Some(tenant) = self.tenants.get_mut(&tenant_id) {
                    tenant.queues.remove(&queue);
                    if tenant.queues.is_empty() && !tenant.in_ring {
                        self.tenants.remove(&tenant_id);
                    }
                }
            }
            Place::Ring => {
                let tenant = self.tenants.entry(tenant_id).or_default();
                tenant.due.push_back(queue);
                if !tenant.in_ring {
                    tenant.in_ring = true;
                    self.ring.push_back(tenant_id);
                }
            }
            Place::Timer(due) => {
                self.timers.insert((due, queue));
            }
            Place::Idle | Place::Parked => {}
        }
    }
}

fn split(ranges: &mut Vec<Range<u32>>, want: u32) -> Vec<Range<u32>> {
    let mut taken = Vec::new();
    let mut left = want;
    let mut used = 0;
    for range in ranges.iter_mut() {
        if left == 0 {
            break;
        }
        let len = range.end - range.start;
        if len <= left {
            taken.push(range.clone());
            left -= len;
            used += 1;
        } else {
            taken.push(range.start..range.start + left);
            range.start += left;
            left = 0;
        }
    }
    ranges.drain(..used);
    taken
}

pub fn ranges(recipients: impl IntoIterator<Item = u32>) -> Vec<Range<u32>> {
    let mut out: Vec<Range<u32>> = Vec::new();
    for r in recipients {
        match out.last_mut() {
            Some(last) if last.end == r => last.end += 1,
            _ => out.push(r..r + 1),
        }
    }
    out
}
