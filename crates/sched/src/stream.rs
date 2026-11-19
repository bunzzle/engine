use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::pin::{Pin, pin};
use std::rc::{Rc, Weak};
use std::task::Poll;
use std::time::Duration;

use control::{HookState, State, tenant_keys};
use rt::{Instant, JoinHandle, Notify, spawn, timeout};

use crate::cursor::{Cursor, read_cursor, write_cursor};
use crate::events::{KIND_EVENT, sequence};
use crate::reader::{Read, event_id, kept, open, stamped};
use crate::start::{Inner, Node};
use crate::transport::Transport;

pub const BATCH_EVENTS: usize = 100;
pub const BATCH_BYTES: usize = 256 * 1024;
const FLUSH: Duration = Duration::from_secs(1);
const TICK: Duration = Duration::from_secs(1);
const PAUSE: Duration = Duration::from_secs(1);
const PAUSE_MAX: Duration = Duration::from_secs(60);
const PAGES: usize = 16;

pub struct Call {
    pub tenant: u32,
    pub generation: u32,
    pub hook: u32,
    pub events: Vec<Read>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Acked,
    Retry(Duration),
}

pub type Sending = Pin<Box<dyn Future<Output = Outcome>>>;

pub trait Deliver {
    fn deliver(&self, call: Rc<Call>) -> Sending;
}

struct Held {
    call: Rc<Call>,
    ends: BTreeMap<u16, u64>,
}

struct Stream {
    tenant: u32,
    generation: u32,
    events: u8,
    cursors: BTreeMap<u16, Cursor>,
    dirty: BTreeSet<u16>,
    held: Option<Held>,
    until: Option<Instant>,
    pause: Duration,
    sending: bool,
    ticket: u64,
    more: bool,
}

#[derive(Default)]
struct Shared {
    done: RefCell<Vec<(u32, u64, Outcome)>>,
    wake: Notify,
}

#[derive(Default)]
struct Streams {
    live: BTreeMap<u32, Stream>,
    draining: BTreeMap<u32, u64>,
    synced: Option<u64>,
    tickets: u64,
}

impl<T: Transport + 'static> Node<T> {
    pub fn start_hooks(&self, deliver: Rc<dyn Deliver>) -> JoinHandle<()> {
        spawn(run(Rc::downgrade(&self.inner), deliver))
    }
}

fn live<T>(inner: &Weak<Inner<T>>) -> Option<Node<T>> {
    let inner = inner.upgrade()?;
    (!inner.ticker.stopped.get()).then_some(Node { inner })
}

async fn run<T: Transport + 'static>(inner: Weak<Inner<T>>, deliver: Rc<dyn Deliver>) {
    let shared = Rc::new(Shared::default());
    let mut all = Streams::default();
    let mut flushed = rt::now();
    loop {
        let Some(node) = live(&inner) else {
            return;
        };
        let watch = Rc::clone(node.spool().changes().watch());
        let fresh = watch.take(KIND_EVENT);
        let done: Vec<_> = shared.done.borrow_mut().drain(..).collect();
        for (hook, ticket, outcome) in done {
            if all.draining.get(&hook) == Some(&ticket) {
                all.draining.remove(&hook);
                all.synced = None;
            } else if let Some(stream) = all.live.get_mut(&hook)
                && stream.sending
                && stream.ticket == ticket
            {
                settle(stream, outcome);
            }
        }
        sync(&node, &mut all).await;
        for (&hook, stream) in &mut all.live {
            if fresh.contains(&stream.tenant) {
                stream.more = true;
            }
            if stream.sending || stream.until.is_some_and(|until| rt::now() < until) {
                continue;
            }
            if stream.held.is_none() && stream.more {
                fill(&node, hook, stream).await;
            }
            if let Some(held) = &stream.held
                && stream.until.is_none_or(|until| rt::now() >= until)
            {
                all.tickets += 1;
                let ticket = all.tickets;
                stream.sending = true;
                stream.ticket = ticket;
                let (deliver, shared, call) = (
                    Rc::clone(&deliver),
                    Rc::clone(&shared),
                    Rc::clone(&held.call),
                );
                drop(spawn(async move {
                    let outcome = deliver.deliver(call).await;
                    shared.done.borrow_mut().push((hook, ticket, outcome));
                    shared.wake.notify();
                }));
            }
        }
        if rt::now().saturating_duration_since(flushed) >= FLUSH {
            flush(&node, &mut all.live).await;
            flushed = rt::now();
        }
        let streams = &all.live;
        let ready = streams.values().any(|s| {
            s.more && s.held.is_none() && !s.sending && s.until.is_none_or(|u| rt::now() >= u)
        });
        drop(node);
        if ready {
            continue;
        }
        let now = rt::now();
        let deadline = streams
            .values()
            .filter(|s| !s.sending)
            .filter_map(|s| s.until)
            .chain([flushed + FLUSH, now + TICK])
            .min()
            .unwrap_or(now + TICK);
        let wait = deadline.saturating_duration_since(now);
        let _ = timeout(wait, first(watch.wait(), shared.wake.wait())).await;
    }
}

async fn first(one: impl Future<Output = ()>, two: impl Future<Output = ()>) {
    let mut one = pin!(one);
    let mut two = pin!(two);
    poll_fn(|cx| {
        if one.as_mut().poll(cx).is_ready() || two.as_mut().poll(cx).is_ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

fn settle(stream: &mut Stream, outcome: Outcome) {
    stream.sending = false;
    match outcome {
        Outcome::Acked => {
            if let Some(held) = stream.held.take() {
                advance(stream, &held.ends);
            }
            stream.until = None;
            stream.more = true;
        }
        Outcome::Retry(pause) => stream.until = Some(rt::now() + pause.max(PAUSE)),
    }
}

fn back_off(stream: &mut Stream) {
    stream.until = Some(rt::now() + stream.pause);
    stream.pause = (stream.pause * 2).min(PAUSE_MAX);
}

fn advance(stream: &mut Stream, ends: &BTreeMap<u16, u64>) {
    for (&shard, &end) in ends {
        if let Some(cursor) = stream.cursors.get_mut(&shard)
            && end > cursor.acked
        {
            cursor.acked = end;
            stream.dirty.insert(shard);
        }
    }
}

async fn sync<T: Transport + 'static>(node: &Node<T>, all: &mut Streams) {
    let version = node.table().version();
    if all.synced == Some(version) {
        return;
    }
    let wanted: BTreeMap<u32, (u32, u32, u8)> = {
        let table = node.table();
        table
            .every_hook()
            .filter(|h| h.state == HookState::Active)
            .filter(|h| {
                table
                    .tenant(h.tenant)
                    .is_some_and(|t| t.state == State::Active && t.generation == h.generation)
            })
            .map(|h| (h.id, (h.tenant, h.generation, h.events)))
            .collect()
    };
    let gone: Vec<u32> = all
        .live
        .iter()
        .filter(|(id, s)| {
            wanted.get(id).is_none_or(|&(tenant, generation, _)| {
                (tenant, generation) != (s.tenant, s.generation)
            })
        })
        .map(|(&id, _)| id)
        .collect();
    for id in gone {
        let Some(mut stream) = all.live.remove(&id) else {
            continue;
        };
        if stream.sending {
            all.draining.insert(id, stream.ticket);
        }
        let current = node
            .hook(stream.tenant, id)
            .is_ok_and(|h| h.generation == stream.generation);
        if current {
            write_dirty(node, id, &mut stream).await;
        }
    }
    let mut complete = true;
    for (id, (tenant, generation, events)) in wanted {
        if let Some(stream) = all.live.get_mut(&id) {
            stream.events = events;
            continue;
        }
        if all.draining.contains_key(&id) {
            complete = false;
            continue;
        }
        let Some(cursors) = cursors(node, tenant, generation, id).await else {
            complete = false;
            continue;
        };
        all.live.insert(
            id,
            Stream {
                tenant,
                generation,
                events,
                cursors,
                dirty: BTreeSet::new(),
                held: None,
                until: None,
                pause: PAUSE,
                sending: false,
                ticket: 0,
                more: true,
            },
        );
    }
    all.synced = complete.then_some(version);
}

async fn cursors<T: Transport + 'static>(
    node: &Node<T>,
    tenant: u32,
    generation: u32,
    hook: u32,
) -> Option<BTreeMap<u16, Cursor>> {
    let changes = node.spool().changes();
    let mut found = BTreeMap::new();
    for shard in node.spool().shards() {
        let kept = read_cursor(changes, shard, tenant, hook).await.ok()?;
        let cursor = match kept {
            Some(cursor) if cursor.generation == generation => cursor,
            _ => {
                let cursor = Cursor {
                    generation,
                    acked: changes.watch().head(),
                    lost: 0,
                    counted: 0,
                };
                write_cursor(changes, shard, tenant, hook, &cursor)
                    .await
                    .ok()?;
                cursor
            }
        };
        found.insert(shard, cursor);
    }
    Some(found)
}

async fn fill<T: Transport + 'static>(node: &Node<T>, hook: u32, stream: &mut Stream) {
    let Some(start) = stream.cursors.values().map(|c| c.acked).min() else {
        stream.more = false;
        return;
    };
    let changes = node.spool().changes();
    let mut ends: BTreeMap<u16, u64> = BTreeMap::new();
    let mut taken = Vec::new();
    let mut bytes = 0usize;
    let mut from = start;
    let mut full = false;
    for page in 0..=PAGES {
        if page == PAGES {
            full = true;
            break;
        }
        let range =
            stamped(stream.tenant, from.saturating_add(1))..stamped(stream.tenant, u64::MAX);
        let Ok(found) = changes.scan_kind(KIND_EVENT, range, BATCH_EVENTS).await else {
            back_off(stream);
            return;
        };
        let last = found.len() < BATCH_EVENTS;
        for (shard, entry) in found {
            let at = sequence(&entry.key);
            from = at;
            let Some(cursor) = stream.cursors.get(&shard) else {
                continue;
            };
            if at <= cursor.acked {
                continue;
            }
            let event = kept(&entry, stream.generation)
                .filter(|event| stream.events & (1 << event.kind as u8) != 0);
            if let Some(event) = event {
                let size = entry.payload.len() + 128;
                if taken.len() >= BATCH_EVENTS || (!taken.is_empty() && bytes + size > BATCH_BYTES)
                {
                    full = true;
                    break;
                }
                bytes += size;
                taken.push((shard, at, event, entry.payload));
            }
            ends.insert(shard, at);
        }
        if full || last {
            break;
        }
    }
    if taken.is_empty() {
        advance(stream, &ends);
        stream.more = full;
        return;
    }
    let keys = node.keys();
    let Ok(naming) = tenant_keys(keys, stream.tenant, stream.generation).await else {
        back_off(stream);
        return;
    };
    let mut events = Vec::with_capacity(taken.len());
    for (shard, at, event, payload) in taken {
        let body = open(keys, stream.tenant, &event, &payload).await;
        events.push(Read {
            id: event_id(&naming, shard, at),
            shard,
            sequence: at,
            event,
            body,
        });
    }
    let call = Call {
        tenant: stream.tenant,
        generation: stream.generation,
        hook,
        events,
    };
    stream.held = Some(Held {
        call: Rc::new(call),
        ends,
    });
    stream.more = full;
    stream.pause = PAUSE;
}

async fn flush<T: Transport + 'static>(node: &Node<T>, streams: &mut BTreeMap<u32, Stream>) {
    for (&id, stream) in streams.iter_mut() {
        write_dirty(node, id, stream).await;
    }
}

async fn write_dirty<T: Transport + 'static>(node: &Node<T>, hook: u32, stream: &mut Stream) {
    let changes = node.spool().changes();
    for shard in std::mem::take(&mut stream.dirty) {
        let Some(cursor) = stream.cursors.get(&shard) else {
            continue;
        };
        if write_cursor(changes, shard, stream.tenant, hook, cursor)
            .await
            .is_err()
        {
            stream.dirty.insert(shard);
        }
    }
}
