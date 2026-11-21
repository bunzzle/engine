use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::pin::{Pin, pin};
use std::rc::{Rc, Weak};
use std::task::Poll;
use std::time::Duration;

use control::{HookState, State, tenant_keys};
use rt::{Instant, JoinHandle, Notify, spawn, timeout};

use crate::cursor::{Cursor, drop_cursor, read_cursor, write_cursor};
use crate::events::{Event, KIND_EVENT, sequence};
use crate::reader::{Read, event_id, kept, opened, stamped};
use crate::start::{Inner, Node};
use crate::tally::{Claim, Tallies, Targets, Watched, count, due, stored, targets};
use crate::transport::Transport;

pub const BATCH_EVENTS: usize = 100;
pub const BATCH_BYTES: usize = 256 * 1024;
const FLUSH: Duration = Duration::from_secs(1);
const TICK: Duration = Duration::from_secs(1);
const PAUSE: Duration = Duration::from_secs(1);
const PAUSE_MAX: Duration = Duration::from_secs(60);
const PAGES: usize = 16;
const DELIVERY_ID: &[u8; 5] = b"WHDEL";

#[derive(Clone)]
pub struct Sealed {
    pub id: [u8; 16],
    pub shard: u16,
    pub sequence: u64,
    pub event: Event,
    payload: Vec<u8>,
}

pub struct Call {
    pub tenant: u32,
    pub generation: u32,
    pub hook: u32,
    pub id: [u8; 16],
    pub lost: u64,
    pub events: Vec<Sealed>,
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
    lost: BTreeMap<u16, u64>,
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
    holders: BTreeMap<u32, (u32, u32)>,
    synced: Option<u64>,
    tickets: u64,
}

impl<T: Transport + 'static> Node<T> {
    pub fn start_hooks(&self, deliver: Rc<dyn Deliver>) -> JoinHandle<()> {
        let Some(claim) = Tallies::claim(self.requests().tallies()) else {
            return spawn(async {});
        };
        spawn(run(Rc::downgrade(&self.inner), deliver, claim))
    }

    pub async fn open_call(&self, call: &Call) -> Option<Vec<Read>> {
        let keys = self.keys();
        let mut events = Vec::with_capacity(call.events.len());
        for sealed in &call.events {
            events.push(Read {
                id: sealed.id,
                shard: sealed.shard,
                sequence: sealed.sequence,
                event: sealed.event,
                body: opened(keys, call.tenant, &sealed.event, &sealed.payload)
                    .await
                    .ok()?,
            });
        }
        Some(events)
    }
}

fn live<T>(inner: &Weak<Inner<T>>) -> Option<Node<T>> {
    let inner = inner.upgrade()?;
    (!inner.ticker.stopped.get()).then_some(Node { inner })
}

async fn run<T: Transport + 'static>(
    inner: Weak<Inner<T>>,
    deliver: Rc<dyn Deliver>,
    claim: Claim,
) {
    let shared = Rc::new(Shared::default());
    let mut all = Streams::default();
    if let Some(node) = live(&inner) {
        all.holders = std::mem::take(&mut *node.inner.cursored.borrow_mut());
    }
    let tallies = Rc::clone(&claim.0);
    let _attached = tallies.attach().await;
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
        for (below, reply) in tallies.take() {
            let counted = tally(&node, &mut all, below).await;
            let _ = reply.send(counted);
        }
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
            trim(stream);
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
        if ready || tallies.waiting() {
            continue;
        }
        let now = rt::now();
        let deadline = streams
            .values()
            .filter(|s| !s.sending)
            .filter_map(|s| s.until)
            .filter(|&until| until > now)
            .chain([flushed + FLUSH, now + TICK])
            .min()
            .unwrap_or(now + TICK);
        let wait = deadline.saturating_duration_since(now);
        let woken = first(watch.wait(), shared.wake.wait());
        let _ = timeout(wait, first(woken, tallies.wake.wait())).await;
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
                report(stream, &held.lost);
            }
            stream.until = None;
            stream.more = true;
        }
        Outcome::Retry(pause) => stream.until = Some(rt::now() + pause.max(PAUSE)),
    }
}

fn trim(stream: &mut Stream) {
    let cursors = &stream.cursors;
    let counted = |read: &Sealed| {
        cursors
            .get(&read.shard)
            .is_some_and(|c| read.event.partition() <= c.counted)
    };
    if !stream
        .held
        .as_ref()
        .is_some_and(|held| held.call.events.iter().any(counted))
    {
        return;
    }
    let Some(held) = stream.held.take() else {
        return;
    };
    let events: Vec<Sealed> = held
        .call
        .events
        .iter()
        .filter(|read| !counted(read))
        .cloned()
        .collect();
    if events.is_empty() && held.call.lost == 0 {
        advance(stream, &held.ends);
        stream.until = None;
        stream.more = true;
        return;
    }
    let call = Call {
        tenant: held.call.tenant,
        generation: held.call.generation,
        hook: held.call.hook,
        id: held.call.id,
        lost: held.call.lost,
        events,
    };
    stream.held = Some(Held {
        call: Rc::new(call),
        ends: held.ends,
        lost: held.lost,
    });
}

fn back_off(stream: &mut Stream) {
    stream.until = Some(rt::now() + stream.pause);
    stream.pause = (stream.pause * 2).min(PAUSE_MAX);
}

fn report(stream: &mut Stream, lost: &BTreeMap<u16, u64>) {
    for (&shard, &n) in lost {
        if let Some(cursor) = stream.cursors.get_mut(&shard) {
            cursor.lost = cursor.lost.saturating_sub(n);
            stream.dirty.insert(shard);
        }
    }
}

fn delivery_id(
    naming: &crypto::TenantKeys,
    hook: u32,
    stream: &Stream,
    lost: &BTreeMap<u16, u64>,
    ends: &BTreeMap<u16, u64>,
) -> [u8; 16] {
    let mut data = Vec::with_capacity(26 + lost.len() * 22 + ends.len() * 18);
    data.extend_from_slice(DELIVERY_ID);
    data.extend_from_slice(&hook.to_be_bytes());
    data.push(stream.events);
    data.extend_from_slice(&u16::try_from(lost.len()).unwrap_or(u16::MAX).to_be_bytes());
    for (&shard, &n) in lost {
        let (acked, counted) = stream
            .cursors
            .get(&shard)
            .map_or((0, 0), |c| (c.acked, c.counted));
        data.extend_from_slice(&shard.to_be_bytes());
        data.extend_from_slice(&n.to_be_bytes());
        data.extend_from_slice(&acked.to_be_bytes());
        data.extend_from_slice(&counted.to_be_bytes());
    }
    data.extend_from_slice(&u16::try_from(ends.len()).unwrap_or(u16::MAX).to_be_bytes());
    for (&shard, &end) in ends {
        let from = stream.cursors.get(&shard).map_or(0, |c| c.acked);
        data.extend_from_slice(&shard.to_be_bytes());
        data.extend_from_slice(&from.to_be_bytes());
        data.extend_from_slice(&end.to_be_bytes());
    }
    index::siphash128(naming.hash_key().expose(), &data)
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
        if current(node, id, stream.tenant, stream.generation) {
            write_dirty(node, id, &mut stream).await;
        }
    }
    let mut complete = sweep(node, all).await;
    for (id, (tenant, generation, events)) in wanted {
        if let Some(stream) = all.live.get_mut(&id) {
            stream.events = events;
            continue;
        }
        if all.draining.contains_key(&id) {
            complete = false;
            continue;
        }
        all.holders.insert(id, (tenant, generation));
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

fn current<T: Transport + 'static>(
    node: &Node<T>,
    hook: u32,
    tenant: u32,
    generation: u32,
) -> bool {
    let table = node.table();
    table
        .hook(tenant, hook)
        .is_some_and(|h| h.generation == generation)
        && !table.gone(tenant, generation)
}

async fn tally<T: Transport + 'static>(node: &Node<T>, all: &mut Streams, below: u32) -> bool {
    let changes = node.spool().changes();
    let (live, rest): (Targets, Targets) =
        targets(&node.table())
            .into_iter()
            .partition(|(id, (tenant, generation, _))| {
                all.live
                    .get(id)
                    .is_some_and(|s| (s.tenant, s.generation) == (*tenant, *generation))
            });
    if !stored(changes, rest, below).await {
        return false;
    }
    let Some(parts) = due(changes, below).await else {
        return false;
    };
    if parts.is_empty() || live.is_empty() {
        return true;
    }
    let watched: BTreeMap<u32, Watched> = live
        .iter()
        .filter_map(|(&id, &(tenant, generation, _))| {
            let stream = all.live.get(&id)?;
            let from = stream
                .cursors
                .iter()
                .map(|(&shard, cursor)| (shard, (cursor.acked, cursor.counted)))
                .collect();
            Some((
                id,
                Watched {
                    tenant,
                    generation,
                    events: stream.events,
                    from,
                },
            ))
        })
        .collect();
    let Some(lost) = count(changes, &parts, &watched).await else {
        return false;
    };
    for ((hook, shard), n) in lost {
        if let Some(stream) = all.live.get_mut(&hook)
            && let Some(cursor) = stream.cursors.get_mut(&shard)
        {
            cursor.lost = cursor.lost.saturating_add(n);
            cursor.counted = below - 1;
            stream.dirty.insert(shard);
        }
    }
    let mut clean = true;
    for (&id, stream) in &mut all.live {
        write_dirty(node, id, stream).await;
        clean &= stream.dirty.is_empty();
    }
    clean
}

async fn sweep<T: Transport + 'static>(node: &Node<T>, all: &mut Streams) -> bool {
    let stale: Vec<(u32, u32)> = all
        .holders
        .iter()
        .filter(|&(&hook, &(tenant, generation))| {
            !all.live.contains_key(&hook)
                && !all.draining.contains_key(&hook)
                && !current(node, hook, tenant, generation)
        })
        .map(|(&hook, &(tenant, _))| (hook, tenant))
        .collect();
    let changes = node.spool().changes();
    let mut complete = true;
    for (hook, tenant) in stale {
        let mut dropped = true;
        for shard in node.spool().shards() {
            dropped &= drop_cursor(changes, shard, tenant, hook).await.is_ok();
        }
        if dropped {
            all.holders.remove(&hook);
        } else {
            complete = false;
        }
    }
    complete
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
                .filter(|event| stream.events & (1 << event.kind as u8) != 0)
                .filter(|event| event.partition() > cursor.counted);
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
    let lost: BTreeMap<u16, u64> = stream
        .cursors
        .iter()
        .filter(|(_, c)| c.lost > 0)
        .map(|(&shard, c)| (shard, c.lost))
        .collect();
    let total = lost.values().fold(0u64, |sum, &n| sum.saturating_add(n));
    if taken.is_empty() && total == 0 {
        advance(stream, &ends);
        stream.more = full;
        return;
    }
    let Ok(naming) = tenant_keys(node.keys(), stream.tenant, stream.generation).await else {
        back_off(stream);
        return;
    };
    let events = taken
        .into_iter()
        .map(|(shard, at, event, payload)| Sealed {
            id: event_id(&naming, shard, at),
            shard,
            sequence: at,
            event,
            payload,
        })
        .collect();
    let call = Call {
        tenant: stream.tenant,
        generation: stream.generation,
        hook,
        id: delivery_id(&naming, hook, stream, &lost, &ends),
        lost: total,
        events,
    };
    stream.held = Some(Held {
        call: Rc::new(call),
        ends,
        lost,
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
