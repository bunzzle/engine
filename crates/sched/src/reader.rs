use std::cell::{Cell, OnceCell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use control::{State, Table, tenant_keys};
use index::Entry;
use rt::{Ends, JoinHandle, Peers, Sender, channel, spawn};
use store::Changes;

use crate::events::{Body, Event, KIND_EVENT, sealed, sequence};
use crate::finder::{self, Hits, Query, SEARCH_LIMIT, Scan};
use crate::sealing::{Keys, Unsealable, event_opener};
use crate::search;

pub const MAX_LIMIT: usize = 1000;
pub const PAGE_BYTES: usize = 1 << 20;
const CURSOR_KIND: u8 = 0xc0;
const CURSOR_FORMAT: u8 = 1;
const SEARCH_KIND: u8 = 0xc1;
const EVENT_ID: &[u8; 5] = b"event";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    Tenant,
    Limit,
    Cursor,
    Stale,
    Unavailable,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    pub id: [u8; 16],
    pub shard: u16,
    pub sequence: u64,
    pub event: Event,
    pub body: Option<Body>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventPage {
    pub events: Vec<Read>,
    pub next: String,
    pub more: bool,
}

pub struct Ask(Message);

enum Message {
    Ask {
        ticket: u64,
        tenant: u32,
        generation: u32,
        after: u64,
        limit: usize,
    },
    Answer {
        ticket: u64,
        part: Result<Part, ReadError>,
    },
    Search {
        ticket: u64,
        scan: Box<Scan>,
    },
    Found {
        ticket: u64,
        hits: Result<Hits, ReadError>,
    },
}

struct Part {
    entries: Vec<(u16, u64, Event, Vec<u8>)>,
    scanned: u64,
    full: bool,
}

struct Inner {
    changes: Changes,
    table: Rc<RefCell<Table>>,
    cores: u16,
    peers: OnceCell<Peers<Ask>>,
    waiting: RefCell<BTreeMap<u64, Sender<Result<Part, ReadError>>>>,
    searching: RefCell<BTreeMap<u64, Sender<Result<Hits, ReadError>>>>,
    tickets: Cell<u64>,
}

#[derive(Clone)]
pub struct Reader {
    inner: Rc<Inner>,
}

impl Reader {
    pub fn start(
        ends: Ends<Ask>,
        changes: Changes,
        table: Rc<RefCell<Table>>,
    ) -> (Self, JoinHandle<()>) {
        let reader = Self {
            inner: Rc::new(Inner {
                changes,
                table,
                cores: ends.cores(),
                peers: OnceCell::new(),
                waiting: RefCell::new(BTreeMap::new()),
                searching: RefCell::new(BTreeMap::new()),
                tickets: Cell::new(0),
            }),
        };
        let handler = reader.clone();
        let (peers, done) = ends.start(move |from, Ask(message)| handler.handle(from, message));
        let _ = reader.inner.peers.set(peers);
        (reader, done)
    }

    pub fn close(&self) {
        self.inner.waiting.borrow_mut().clear();
        self.inner.searching.borrow_mut().clear();
        if let Some(peers) = self.inner.peers.get() {
            peers.close();
        }
    }

    pub async fn read(
        &self,
        keys: &dyn Keys,
        tenant: u32,
        after: Option<&str>,
        limit: usize,
    ) -> Result<EventPage, ReadError> {
        if limit == 0 || limit > MAX_LIMIT {
            return Err(ReadError::Limit);
        }
        let generation = self.generation(tenant)?;
        let system = keys.system().await.map_err(|_| ReadError::Unavailable)?;
        let cores = usize::from(self.inner.cores);
        let label = label(&system, tenant, generation);
        let positions = match after {
            None => vec![0; cores],
            Some(text) => {
                let sealed = unhex(text).ok_or(ReadError::Cursor)?;
                let clear = system.open(&label, &sealed).map_err(|e| match e {
                    crypto::Error::Format("key version") => ReadError::Stale,
                    _ => ReadError::Cursor,
                })?;
                positions(&clear, cores).ok_or(ReadError::Cursor)?
            }
        };
        let mut asked = Vec::with_capacity(cores);
        for (core, &after) in (0..self.inner.cores).zip(&positions) {
            asked.push(self.send(core, tenant, generation, after, limit));
        }
        let mut parts = Vec::with_capacity(cores);
        for mut answer in asked {
            parts.push(answer.recv().await.ok_or(ReadError::Failed)??);
        }
        let (taken, next, more) = merge(parts, &positions, limit);
        let naming = tenant_keys(keys, tenant, generation)
            .await
            .map_err(|_| ReadError::Unavailable)?;
        let mut events = Vec::with_capacity(taken.len());
        for (shard, sequence, event, payload) in taken {
            let body = open(keys, tenant, &event, &payload).await;
            events.push(Read {
                id: event_id(&naming, shard, sequence),
                shard,
                sequence,
                event,
                body,
            });
        }
        let sealed = system
            .seal(&label, &cursor(&next))
            .map_err(|_| ReadError::Failed)?;
        Ok(EventPage {
            events,
            next: hex(&sealed),
            more,
        })
    }

    pub async fn search(
        &self,
        keys: &dyn Keys,
        tenant: u32,
        query: &Query,
        after: Option<&str>,
        limit: usize,
    ) -> Result<EventPage, ReadError> {
        if limit == 0 || limit > SEARCH_LIMIT {
            return Err(ReadError::Limit);
        }
        let generation = self.generation(tenant)?;
        let system = keys.system().await.map_err(|_| ReadError::Unavailable)?;
        let cores = usize::from(self.inner.cores);
        let mut label = label(&system, tenant, generation);
        label[8] = SEARCH_KIND;
        query.label(&mut label);
        let (query, positions) = match after {
            None => (query.clone(), vec![0; cores]),
            Some(text) => {
                let sealed = unhex(text).ok_or(ReadError::Cursor)?;
                let clear = system.open(&label, &sealed).map_err(|e| match e {
                    crypto::Error::Format("key version") => ReadError::Stale,
                    _ => ReadError::Cursor,
                })?;
                let (from, rest) = clear.split_first_chunk::<8>().ok_or(ReadError::Cursor)?;
                let (to, rest) = rest.split_first_chunk::<8>().ok_or(ReadError::Cursor)?;
                let query = query
                    .ranged(u64::from_le_bytes(*from), u64::from_le_bytes(*to))
                    .ok_or(ReadError::Cursor)?;
                (query, positions(rest, cores).ok_or(ReadError::Cursor)?)
            }
        };
        let query = &query;
        let day_keys = keys.search(tenant, generation).await.map_err(|e| match e {
            control::KeyError::Failed => ReadError::Failed,
            _ => ReadError::Unavailable,
        })?;
        let hashes: Vec<_> = query
            .days()
            .filter_map(|day| {
                let key = day_keys.get(day)?;
                Some((day, search::hash(key, query.field(), query.value())))
            })
            .collect();
        let only = query.shard().map(|shard| shard % self.inner.cores);
        let mut asked = Vec::with_capacity(cores);
        for (core, &after) in (0..self.inner.cores).zip(&positions) {
            if hashes.is_empty() || only.is_some_and(|only| only != core) {
                asked.push(None);
                continue;
            }
            let scan = Scan {
                tenant,
                generation,
                query: query.clone(),
                hashes: hashes.clone(),
                after,
                limit,
            };
            asked.push(Some(self.ask(core, scan)));
        }
        let mut parts = Vec::with_capacity(cores);
        for answer in asked {
            parts.push(match answer {
                Some(mut answer) => Some(answer.recv().await.ok_or(ReadError::Failed)??),
                None => None,
            });
        }
        let (taken, next, more) = finder::merge(parts, &positions, limit);
        let naming = tenant_keys(keys, tenant, generation)
            .await
            .map_err(|_| ReadError::Unavailable)?;
        let mut events = Vec::with_capacity(taken.len());
        for hit in taken {
            let body = match opened(keys, tenant, &hit.event, &hit.payload).await {
                Ok(Some(body)) => body,
                Ok(None) => continue,
                Err(Unsealable::Unavailable) => return Err(ReadError::Unavailable),
                Err(_) => return Err(ReadError::Failed),
            };
            if !query.verified(&hit.event, &body.address) {
                continue;
            }
            events.push(Read {
                id: event_id(&naming, hit.shard, hit.sequence),
                shard: hit.shard,
                sequence: hit.sequence,
                event: hit.event,
                body: Some(body),
            });
        }
        let sealed = system
            .seal(&label, &{
                let (from, to) = query.range();
                let mut clear = from.to_le_bytes().to_vec();
                clear.extend_from_slice(&to.to_le_bytes());
                clear.extend_from_slice(&cursor(&next));
                clear
            })
            .map_err(|_| ReadError::Failed)?;
        Ok(EventPage {
            events,
            next: hex(&sealed),
            more,
        })
    }

    fn ask(&self, core: u16, scan: Scan) -> rt::Receiver<Result<Hits, ReadError>> {
        let (reply, answer) = channel();
        let ticket = self.inner.tickets.get();
        self.inner.tickets.set(ticket + 1);
        self.inner.searching.borrow_mut().insert(ticket, reply);
        if let Some(peers) = self.inner.peers.get() {
            let message = Message::Search {
                ticket,
                scan: Box::new(scan),
            };
            peers.send(core, Ask(message));
        }
        answer
    }

    fn generation(&self, tenant: u32) -> Result<u32, ReadError> {
        self.inner
            .table
            .borrow()
            .tenant(tenant)
            .filter(|t| t.state == State::Active)
            .map(|t| t.generation)
            .ok_or(ReadError::Tenant)
    }

    fn send(
        &self,
        core: u16,
        tenant: u32,
        generation: u32,
        after: u64,
        limit: usize,
    ) -> rt::Receiver<Result<Part, ReadError>> {
        let (reply, answer) = channel();
        let ticket = self.inner.tickets.get();
        self.inner.tickets.set(ticket + 1);
        self.inner.waiting.borrow_mut().insert(ticket, reply);
        if let Some(peers) = self.inner.peers.get() {
            let message = Message::Ask {
                ticket,
                tenant,
                generation,
                after,
                limit,
            };
            peers.send(core, Ask(message));
        }
        answer
    }

    fn handle(&self, from: u16, message: Message) {
        match message {
            Message::Ask {
                ticket,
                tenant,
                generation,
                after,
                limit,
            } => {
                let reader = self.clone();
                drop(spawn(async move {
                    let part = reader.serve(tenant, generation, after, limit).await;
                    if let Some(peers) = reader.inner.peers.get() {
                        peers.send(from, Ask(Message::Answer { ticket, part }));
                    }
                }));
            }
            Message::Answer { ticket, part } => {
                if let Some(reply) = self.inner.waiting.borrow_mut().remove(&ticket) {
                    let _ = reply.send(part);
                }
            }
            Message::Search { ticket, scan } => {
                let reader = self.clone();
                drop(spawn(async move {
                    let hits = finder::serve(&reader.inner.changes, &scan).await;
                    if let Some(peers) = reader.inner.peers.get() {
                        peers.send(from, Ask(Message::Found { ticket, hits }));
                    }
                }));
            }
            Message::Found { ticket, hits } => {
                if let Some(reply) = self.inner.searching.borrow_mut().remove(&ticket) {
                    let _ = reply.send(hits);
                }
            }
        }
    }

    async fn serve(
        &self,
        tenant: u32,
        generation: u32,
        after: u64,
        limit: usize,
    ) -> Result<Part, ReadError> {
        let from = stamped(tenant, after.saturating_add(1));
        let to = stamped(tenant, u64::MAX);
        let found = self
            .inner
            .changes
            .scan_kind(KIND_EVENT, from..to, limit)
            .await
            .map_err(|_| ReadError::Failed)?;
        let mut full = found.len() >= limit;
        let mut scanned = after;
        let mut bytes = 0usize;
        let mut entries = Vec::with_capacity(found.len());
        for (shard, entry) in found {
            let size = entry.payload.len() + 128;
            if !entries.is_empty() && bytes + size > PAGE_BYTES {
                full = true;
                break;
            }
            let at = sequence(&entry.key);
            scanned = scanned.max(at);
            if let Some(event) = kept(&entry, generation) {
                bytes += size;
                entries.push((shard, at, event, entry.payload));
            }
        }
        Ok(Part {
            entries,
            scanned,
            full,
        })
    }
}

pub(crate) fn kept(entry: &Entry, generation: u32) -> Option<Event> {
    if entry.op != index::Op::Put {
        return None;
    }
    Event::decode(&entry.value).filter(|event| event.generation == generation)
}

pub(crate) fn stamped(tenant: u32, sequence: u64) -> index::Key {
    let mut hash = [0; 16];
    hash[..8].copy_from_slice(&sequence.to_be_bytes());
    index::key(tenant, hash)
}

type Taken = Vec<(u16, u64, Event, Vec<u8>)>;

fn merge(parts: Vec<Part>, positions: &[u64], limit: usize) -> (Taken, Vec<u64>, bool) {
    let mut next = positions.to_vec();
    let mut heads: Vec<_> = parts
        .into_iter()
        .map(|part| (part.entries.into_iter().peekable(), part.scanned, part.full))
        .collect();
    let mut taken = Vec::new();
    let mut bytes = 0usize;
    loop {
        let pick = heads
            .iter_mut()
            .enumerate()
            .filter_map(|(core, (entries, _, _))| {
                entries
                    .peek()
                    .map(|(shard, at, event, _)| ((event.time, core, *shard, *at), core))
            })
            .min()
            .map(|(_, core)| core);
        let Some(core) = pick else {
            break;
        };
        let size = heads[core]
            .0
            .peek()
            .map_or(0, |(_, _, _, payload)| payload.len() + 128);
        if taken.len() >= limit || (!taken.is_empty() && bytes + size > PAGE_BYTES) {
            break;
        }
        let entry = heads[core].0.next().expect("peeked");
        bytes += size;
        next[core] = entry.1;
        taken.push(entry);
    }
    let mut more = false;
    for (core, (entries, scanned, full)) in heads.iter_mut().enumerate() {
        if entries.peek().is_none() {
            next[core] = next[core].max(*scanned);
            more |= *full;
        } else {
            more = true;
        }
    }
    (taken, next, more)
}

pub(crate) fn event_id(keys: &crypto::TenantKeys, shard: u16, sequence: u64) -> [u8; 16] {
    let mut data = [0; 15];
    data[..5].copy_from_slice(EVENT_ID);
    data[5..7].copy_from_slice(&shard.to_be_bytes());
    data[7..].copy_from_slice(&sequence.to_be_bytes());
    index::siphash128(keys.hash_key().expose(), &data)
}

pub(crate) async fn open(
    keys: &dyn Keys,
    tenant: u32,
    event: &Event,
    payload: &[u8],
) -> Option<Body> {
    opened(keys, tenant, event, payload).await.ok().flatten()
}

pub(crate) async fn opened(
    keys: &dyn Keys,
    tenant: u32,
    event: &Event,
    payload: &[u8],
) -> Result<Option<Body>, Unsealable> {
    let Some((wrap, inner)) = sealed(payload) else {
        return Ok(None);
    };
    let opener = match event_opener(keys, tenant, event, wrap).await {
        Ok(opener) => opener,
        Err(fault @ (Unsealable::Unavailable | Unsealable::Failed)) => return Err(fault),
        Err(_) => return Ok(None),
    };
    let Ok(clear) = opener.open_event(event.recipient, event.stamp, inner) else {
        return Ok(None);
    };
    Ok(Body::decode(&clear).filter(|body| event.checked(body)))
}

fn label(system: &crypto::TenantKeys, tenant: u32, generation: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(&system.tenant().to_le_bytes());
    out.extend_from_slice(&system.generation().to_le_bytes());
    out.push(CURSOR_KIND);
    out.push(CURSOR_FORMAT);
    out.extend_from_slice(&tenant.to_le_bytes());
    out.extend_from_slice(&generation.to_le_bytes());
    out
}

fn cursor(positions: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + positions.len() * 4);
    out.extend_from_slice(
        &u16::try_from(positions.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    for &at in positions {
        let mut value = at;
        loop {
            let byte = u8::try_from(value & 0x7f).expect("seven bits");
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }
    out
}

fn positions(clear: &[u8], cores: usize) -> Option<Vec<u64>> {
    let (count, mut rest) = clear.split_first_chunk::<2>()?;
    let count = usize::from(u16::from_le_bytes(*count));
    let mut found = Vec::with_capacity(count);
    for _ in 0..count {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let (&byte, tail) = rest.split_first()?;
            rest = tail;
            if shift > 63 {
                return None;
            }
            value |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        found.push(value);
    }
    if !rest.is_empty() {
        return None;
    }
    if found.len() == cores {
        return Some(found);
    }
    let floor = found.iter().copied().min().unwrap_or(0);
    Some(vec![floor; cores])
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Kind;
    use spool::{MessageId, Stamp};

    #[test]
    fn event_ids_are_keyed_per_tenant() {
        let keys = |tenant, hash| {
            crypto::TenantKeys::new(
                tenant,
                1,
                &crypto::Secret::new([1; 32]),
                1,
                crypto::Secret::new([hash; 16]),
            )
        };
        let (one, two) = (keys(1, 3), keys(2, 4));
        let id = event_id(&one, 5, 77);
        assert_eq!(id, event_id(&keys(1, 3), 5, 77));
        assert_ne!(id, event_id(&one, 5, 78));
        assert_ne!(id, event_id(&one, 6, 77));
        assert_ne!(id, event_id(&two, 5, 77));
        assert!(!id.windows(8).any(|w| w == 77u64.to_be_bytes()));
    }

    fn event(time: u64) -> Event {
        Event {
            generation: 1,
            time,
            kind: Kind::Delivered,
            lost: 0,
            message: MessageId::from_bytes([1; 16]),
            recipient: 0,
            stamp: Stamp { boot: 1, write: 1 },
            batch: 1,
            day: 1,
        }
    }

    fn part(entries: &[(u64, u64)], scanned: u64, full: bool) -> Part {
        Part {
            entries: entries
                .iter()
                .map(|&(at, time)| (0, at, event(time), Vec::new()))
                .collect(),
            scanned,
            full,
        }
    }

    #[test]
    fn merges_keep_each_core_a_prefix_and_move_past_filtered_entries() {
        let parts = vec![
            part(&[(5, 30), (9, 10)], 12, false),
            part(&[(7, 20)], 7, false),
        ];
        let (taken, next, more) = merge(parts, &[1, 2], 2);
        let order: Vec<u64> = taken.iter().map(|t| t.1).collect();
        assert_eq!(order, [7, 5]);
        assert_eq!(next, [5, 7]);
        assert!(more);
        let parts = vec![part(&[], 40, false), part(&[(8, 1)], 9, false)];
        let (taken, next, more) = merge(parts, &[3, 4], 10);
        assert_eq!(taken.len(), 1);
        assert_eq!(next, [40, 9]);
        assert!(!more);
        let parts = vec![part(&[(6, 1)], 6, true)];
        assert!(merge(parts, &[0], 10).2);
    }

    #[test]
    fn a_page_always_takes_one_event_even_past_the_byte_budget() {
        let big = Part {
            entries: vec![
                (0, 3, event(1), vec![0; PAGE_BYTES]),
                (0, 4, event(2), vec![0; 10]),
            ],
            scanned: 4,
            full: false,
        };
        let (taken, next, more) = merge(vec![big], &[0], 10);
        assert_eq!(taken.len(), 1);
        assert_eq!(next, [3]);
        assert!(more);
    }

    #[test]
    fn cursors_round_trip_and_fall_back_on_another_core_count() {
        let positions = [0, 127, 128, u64::MAX];
        let clear = cursor(&positions);
        assert_eq!(super::positions(&clear, 4), Some(positions.to_vec()));
        assert_eq!(super::positions(&clear, 2), Some(vec![0, 0]));
        let mut long = clear.clone();
        long.push(0);
        assert_eq!(super::positions(&long, 4), None);
        assert_eq!(super::positions(&clear[..clear.len() - 1], 4), None);
        assert_eq!(unhex(&hex(&[0, 0xab, 0xff])), Some(vec![0, 0xab, 0xff]));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("AB"), None);
    }
}
