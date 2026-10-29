use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rt::{Receiver, Sender, channel, spawn};

use crate::boot::Core;
use crate::committer::{Body, Client, Lease, Location, Submission, Write};
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::journal::{Dead, Range};
use crate::keeper::Keeper;
use crate::reader::{Owner, Reader};
use crate::record::{Record, rebase};
use crate::regions::Claim;
use crate::session::{Event, Owned, Results, Session};
use crate::shard::{Change, HEAD_ITEM, Index, Item, KIND_STATE, Key};
use sys::crc32c::checksum;

enum Reply {
    Caller(Sender<Result<Vec<Location>, Error>>),
    Created(Sender<Result<Vec<Vec<Location>>, Error>>),
    Move,
}

impl Reply {
    fn refuse(self, error: Error) {
        match self {
            Self::Caller(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Created(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Move => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub item: u32,
    pub change: Change,
    pub clear: Vec<u8>,
    pub bodies: Vec<Range>,
    pub sealed: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub shard: u16,
    pub message: u64,
    pub tenant: u32,
    pub ops: Vec<Op>,
}

impl Batch {
    fn index(&self, op: &Op) -> Index {
        Index {
            key: Key::new(self.message, op.item),
            tenant: self.tenant,
            change: op.change,
        }
    }
}

struct Compacting {
    region: u32,
    epoch: u64,
    copying: bool,
    moves: usize,
    skipped: Vec<(u16, u64)>,
    leases: Vec<Lease>,
}

struct Copied {
    region: u32,
    epoch: u64,
    batches: Vec<Batch>,
    leases: Vec<Lease>,
}

#[derive(Default)]
struct Target {
    leases: Vec<Lease>,
    offset: u64,
}

struct Itself;

impl Owner for Itself {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        std::future::ready(None)
    }
}

struct Request {
    batches: Vec<Batch>,
    reply: Reply,
}

impl Request {
    fn keys(&self) -> impl Iterator<Item = (u16, u64)> + '_ {
        self.batches.iter().map(|b| (b.shard, b.message))
    }
}

enum Input {
    Change(Request),
    Event(Event),
    Copied(Copied),
    Close,
}

#[derive(Clone)]
pub struct Changes {
    sender: Sender<Input>,
}

impl Changes {
    pub async fn change(
        &self,
        shard: u16,
        index: Index,
        sealed: Vec<u8>,
    ) -> Result<Location, Error> {
        let batch = Batch {
            shard,
            message: index.key.message,
            tenant: index.tenant,
            ops: vec![Op {
                item: index.key.item,
                change: index.change,
                clear: Vec::new(),
                bodies: Vec::new(),
                sealed,
            }],
        };
        let locations = self.apply(batch).await?;
        Ok(locations[0])
    }

    pub async fn apply(&self, batch: Batch) -> Result<Vec<Location>, Error> {
        let (reply, mut answer) = channel();
        let request = Request {
            batches: vec![batch],
            reply: Reply::Caller(reply),
        };
        if self.sender.send(Input::Change(request)).is_err() {
            return Err(Error::Failed);
        }
        answer.recv().await.unwrap_or(Err(Error::Failed))
    }

    pub async fn create(&self, batches: Vec<Batch>) -> Result<Vec<Vec<Location>>, Error> {
        let (reply, mut answer) = channel();
        let request = Request {
            batches,
            reply: Reply::Created(reply),
        };
        if self.sender.send(Input::Change(request)).is_err() {
            return Err(Error::Failed);
        }
        answer.recv().await.unwrap_or(Err(Error::Failed))
    }

    pub fn close(&self) {
        let _ = self.sender.send(Input::Close);
    }
}

pub struct Shards {
    session: Session,
    results: Option<Results>,
    sender: Sender<Input>,
    file: CoreFile,
    keeper: Keeper,
    owned: Vec<u16>,
    inputs: Receiver<Input>,
    busy: BTreeMap<(u16, u64), VecDeque<Request>>,
    waiting: VecDeque<(u64, Submission)>,
    held: VecDeque<Request>,
    sent: BTreeMap<u64, Request>,
    tag: u64,
    compacting: Option<Compacting>,
    closing: bool,
}

impl Shards {
    pub fn new(core: Core) -> (Self, Changes) {
        let Core {
            shards,
            session,
            results,
            file,
            keeper,
            ..
        } = core;
        let (sender, inputs) = channel();
        let owner = Self {
            session,
            results: Some(results),
            sender: sender.clone(),
            file,
            keeper,
            owned: shards,
            inputs,
            busy: BTreeMap::new(),
            waiting: VecDeque::new(),
            held: VecDeque::new(),
            sent: BTreeMap::new(),
            tag: 0,
            compacting: None,
            closing: false,
        };
        (owner, Changes { sender })
    }

    pub async fn run(mut self) -> Keeper {
        if let Some(mut results) = self.results.take() {
            let events = self.sender.clone();
            spawn(async move {
                while let Some(event) = results.recv().await {
                    if events.send(Input::Event(event)).is_err() {
                        break;
                    }
                }
            });
        }
        while !(self.closing && self.busy.is_empty() && self.held.is_empty()) {
            let Some(input) = self.inputs.recv().await else {
                break;
            };
            match input {
                Input::Change(request) if self.compacting.as_ref().is_some_and(|c| c.copying) => {
                    self.held.push_back(request);
                }
                Input::Change(request) => self.request(request),
                Input::Event(event) => self.event(event).await,
                Input::Copied(copied) => self.copied(copied),
                Input::Close => self.closing = true,
            }
            self.flush();
        }
        self.keeper
    }

    fn request(&mut self, request: Request) {
        let error = if self.closing {
            Some(Error::Failed)
        } else if !request
            .batches
            .iter()
            .all(|b| self.owned.contains(&b.shard))
        {
            Some(Error::Invalid("owner"))
        } else if request.batches.is_empty() {
            Some(Error::Invalid("batch"))
        } else {
            None
        };
        if let Some(error) = error {
            request.reply.refuse(error);
            return;
        }
        if matches!(request.reply, Reply::Created(_)) {
            let mut keys = BTreeSet::new();
            let free = request
                .keys()
                .all(|key| keys.insert(key) && !self.busy.contains_key(&key));
            if !free {
                request.reply.refuse(Error::Invalid("busy"));
                return;
            }
            for key in keys {
                self.busy.insert(key, VecDeque::new());
            }
            self.start(request);
            return;
        }
        let key = (request.batches[0].shard, request.batches[0].message);
        if let Some(queue) = self.busy.get_mut(&key) {
            queue.push_back(request);
            return;
        }
        self.busy.insert(key, VecDeque::new());
        self.start(request);
    }

    fn start(&mut self, request: Request) {
        match self.merged(&request) {
            Ok(submission) => {
                self.tag += 1;
                self.sent.insert(self.tag, request);
                self.waiting.push_back((self.tag, submission));
            }
            Err(error) => self.finish(request, Err(error)),
        }
    }

    fn merged(&self, request: &Request) -> Result<Submission, Error> {
        let create = matches!(request.reply, Reply::Created(_));
        let mut merged: Option<Submission> = None;
        for batch in &request.batches {
            let next = self.submission(batch, create)?;
            match merged.as_mut() {
                None => merged = Some(next),
                Some(merged) => {
                    merged.records.extend(next.records);
                    merged.bodies.extend(next.bodies);
                    merged.dead.extend(next.dead);
                }
            }
        }
        merged.ok_or(Error::Invalid("batch"))
    }

    fn submission(&self, batch: &Batch, create: bool) -> Result<Submission, Error> {
        let state = self.keeper.state(batch.shard).expect("owned shard is kept");
        let ops = &batch.ops;
        let alone = |op: &Op| matches!(op.change, Change::Drop | Change::Move { .. });
        if ops.is_empty() || (ops.len() > 1 && ops.iter().any(alone)) {
            return Err(Error::Invalid("batch"));
        }
        let mut items = BTreeSet::new();
        if !ops.iter().all(|op| items.insert(op.item)) {
            return Err(Error::Invalid("item"));
        }
        let head = state.get(Key::head(batch.message));
        let creates = ops
            .iter()
            .any(|op| op.item == HEAD_ITEM && matches!(op.change, Change::Put(_)));
        match head {
            None if !creates => return Err(Error::NotFound),
            Some(_) if create => return Err(Error::Invalid("exists")),
            Some(head) if head.tenant != batch.tenant => return Err(Error::Invalid("tenant")),
            _ => {}
        }
        let tenant = batch.tenant;
        let mut dead = Vec::new();
        let mut bodies = Vec::new();
        let mut records = Vec::with_capacity(ops.len());
        for op in ops {
            let current = state.get(Key::new(batch.message, op.item));
            match op.change {
                Change::Delete | Change::Drop if !op.bodies.is_empty() => {
                    return Err(Error::Invalid("batch"));
                }
                Change::Delete if op.item == HEAD_ITEM => return Err(Error::Invalid("head")),
                Change::Delete if current.is_none() => return Err(Error::NotFound),
                Change::Move { old } if current.is_none_or(|item| item.location != old) => {
                    return Err(Error::Invalid("moved"));
                }
                Change::Put(_) | Change::Delete | Change::Move { .. } | Change::Drop => {}
            }
            let new: BTreeSet<Spot> = op.bodies.iter().map(spot).collect();
            if new.len() != op.bodies.len() {
                return Err(Error::Invalid("range"));
            }
            if matches!(op.change, Change::Drop) {
                for (_, item) in state.message(batch.message) {
                    dead.push(kill_record(tenant, item.location));
                    dead.extend(item.bodies.iter().map(|b| kill_body(tenant, b)));
                }
            } else if let Some(item) = current {
                let old: BTreeSet<Spot> = item.bodies.iter().map(spot).collect();
                dead.push(kill_record(tenant, item.location));
                dead.extend(
                    item.bodies
                        .iter()
                        .filter(|b| !new.contains(&spot(b)))
                        .map(|b| kill_body(tenant, b)),
                );
                bodies.extend(
                    op.bodies
                        .iter()
                        .filter(|b| !old.contains(&spot(b)))
                        .map(|&range| Body {
                            shard: batch.shard,
                            tenant,
                            range,
                        }),
                );
            } else {
                bodies.extend(op.bodies.iter().map(|&range| Body {
                    shard: batch.shard,
                    tenant,
                    range,
                }));
            }
            records.push(Write {
                kind: KIND_STATE,
                counted: matches!(op.change, Change::Put(_) | Change::Move { .. }),
                shard: batch.shard,
                tenant,
                payload: batch.index(op).record(&op.clear, &op.bodies, &op.sealed),
            });
        }
        let claim = match ops[0].change {
            Change::Move { .. } => Claim::Internal,
            _ if head.is_none() => Claim::Intake,
            _ => Claim::Control,
        };
        Ok(Submission {
            claim,
            records,
            bodies,
            dead,
        })
    }

    fn flush(&mut self) {
        while self.session.credits() > 0
            && let Some((tag, submission)) = self.waiting.pop_front()
        {
            if let Err(error) = self.session.submit(tag, submission) {
                let request = self.sent.remove(&tag).expect("sent");
                self.finish(request, Err(error));
            }
        }
    }

    async fn event(&mut self, event: Event) {
        match event {
            Event::Durable {
                tag,
                sequence,
                locations,
            } => {
                let request = self.sent.remove(&tag).expect("result for a sent change");
                let ops = request
                    .batches
                    .iter()
                    .flat_map(|batch| batch.ops.iter().map(move |op| (batch, op)));
                for ((batch, op), &location) in ops.zip(&locations) {
                    self.keeper.apply(
                        batch.shard,
                        &batch.index(op),
                        &op.clear,
                        &op.bodies,
                        location,
                        sequence,
                    );
                }
                self.finish(request, Ok(locations));
            }
            Event::Rejected { tag, error } => {
                let request = self.sent.remove(&tag).expect("result for a sent change");
                self.finish(request, Err(error));
            }
            Event::Cut { sequence } => {
                let _ = self.session.survey(sequence, self.owned_bytes());
                let _ = self.keeper.cut(&self.session, &self.file, sequence).await;
            }
            Event::Compact { region, epoch } => self.compact(region, epoch),
            Event::Published { sequence } => self.keeper.published(sequence),
            Event::Abandoned { sequence } => self.keeper.abandoned(sequence),
        }
    }

    fn finish(&mut self, request: Request, result: Result<Vec<Location>, Error>) {
        let keys: Vec<(u16, u64)> = request.keys().collect();
        let Request { batches, reply } = request;
        match reply {
            Reply::Caller(reply) => {
                let _ = reply.send(result);
            }
            Reply::Created(reply) => {
                let split = result.map(|locations| {
                    let mut rest = locations.as_slice();
                    batches
                        .iter()
                        .map(|batch| {
                            let (these, tail) = rest.split_at(batch.ops.len());
                            rest = tail;
                            these.to_vec()
                        })
                        .collect()
                });
                let _ = reply.send(split);
            }
            Reply::Move => {
                if let Some(compacting) = self.compacting.as_mut() {
                    compacting.moves -= 1;
                }
            }
        }
        for key in keys {
            let next = self.busy.get_mut(&key).and_then(VecDeque::pop_front);
            match next {
                Some(next) => self.start(next),
                None => {
                    self.busy.remove(&key);
                }
            }
        }
        self.settle_compaction();
    }

    fn owned_bytes(&self) -> Vec<Owned> {
        let mut owned = BTreeMap::<u32, Owned>::new();
        for &shard in &self.owned {
            let Some(state) = self.keeper.state(shard) else {
                continue;
            };
            for item in state.entries().values() {
                let records = std::iter::once((item.location.region, item.location.size));
                let bodies = item.bodies.iter().map(|b| (b.region, b.length));
                for (region, size) in records.chain(bodies) {
                    let entry = owned.entry(region).or_insert(Owned {
                        region,
                        ..Owned::default()
                    });
                    entry.extents += 1;
                    entry.bytes += u64::from(size);
                }
            }
        }
        owned.into_values().collect()
    }

    fn compact(&mut self, region: u32, epoch: u64) {
        let inside = |at: u32, at_epoch: u64| at == region && at_epoch == epoch;
        let mut found = Vec::new();
        let mut skipped = Vec::new();
        for &shard in &self.owned {
            let Some(state) = self.keeper.state(shard) else {
                continue;
            };
            for (&key, item) in state.entries() {
                let record = inside(item.location.region, item.location.epoch);
                if !record && !item.bodies.iter().any(|b| inside(b.region, b.epoch)) {
                    continue;
                }
                if self.busy.contains_key(&(shard, key.message)) {
                    skipped.push((shard, key.message));
                } else {
                    found.push((shard, key, item.clone()));
                }
            }
        }
        self.compacting = Some(Compacting {
            region,
            epoch,
            copying: true,
            moves: 0,
            skipped,
            leases: Vec::new(),
        });
        let file = self.file.clone();
        let client = self.session.client().clone();
        let sender = self.sender.clone();
        spawn(async move {
            let (batches, leases) = copy(&file, &client, region, epoch, found).await;
            let copied = Copied {
                region,
                epoch,
                batches,
                leases,
            };
            let _ = sender.send(Input::Copied(copied));
        });
    }

    fn copied(&mut self, copied: Copied) {
        let Some(compacting) = self.compacting.as_mut() else {
            return;
        };
        if (compacting.region, compacting.epoch) != (copied.region, copied.epoch) {
            return;
        }
        compacting.copying = false;
        compacting.moves = copied.batches.len();
        compacting.leases = copied.leases;
        for batch in copied.batches {
            self.request(Request {
                batches: vec![batch],
                reply: Reply::Move,
            });
        }
        while let Some(request) = self.held.pop_front() {
            self.request(request);
        }
        self.settle_compaction();
    }

    fn settle_compaction(&mut self) {
        let Some(compacting) = self.compacting.as_ref() else {
            return;
        };
        let resolved = !compacting.copying
            && compacting.moves == 0
            && compacting
                .skipped
                .iter()
                .all(|key| !self.busy.contains_key(key));
        if resolved {
            let _ = self.session.compacted(compacting.region, compacting.epoch);
            self.compacting = None;
        }
    }
}

type Spot = (u32, u64, u64, u32, u32);

fn spot(range: &Range) -> Spot {
    (
        range.region,
        range.epoch,
        range.offset,
        range.length,
        range.checksum,
    )
}

fn kill_record(tenant: u32, at: Location) -> Dead {
    Dead {
        tenant,
        region: at.region,
        epoch: at.epoch,
        offset: at.offset,
        length: at.size,
    }
}

fn kill_body(tenant: u32, range: &Range) -> Dead {
    Dead {
        tenant,
        region: range.region,
        epoch: range.epoch,
        offset: range.offset,
        length: range.length,
    }
}

async fn copy(
    file: &CoreFile,
    client: &Client,
    region: u32,
    epoch: u64,
    found: Vec<(u16, Key, Item)>,
) -> (Vec<Batch>, Vec<Lease>) {
    let reader = file.reader();
    let mut target = Target::default();
    let mut batches = Vec::new();
    'items: for (shard, key, item) in found {
        let Ok(buf) = reader.read(item.location, item.tenant, &Itself).await else {
            continue;
        };
        let Ok(record) = Record::decode(&buf) else {
            continue;
        };
        let Some(parts) = Index::parts(record.payload()) else {
            continue;
        };
        let mut bodies = Vec::with_capacity(item.bodies.len());
        for &body in &item.bodies {
            if body.region != region || body.epoch != epoch {
                bodies.push(body);
                continue;
            }
            match move_body(file, client, &reader, &mut target, body, item.tenant).await {
                Some(moved) => bodies.push(moved),
                None => continue 'items,
            }
        }
        batches.push(Batch {
            shard,
            message: key.message,
            tenant: item.tenant,
            ops: vec![Op {
                item: key.item,
                change: Change::Move { old: item.location },
                clear: parts.clear.to_vec(),
                bodies,
                sealed: parts.sealed.to_vec(),
            }],
        });
    }
    (batches, target.leases)
}

async fn move_body(
    file: &CoreFile,
    client: &Client,
    reader: &Reader,
    target: &mut Target,
    body: Range,
    tenant: u32,
) -> Option<Range> {
    let mut buf = reader.range(body).await.ok()?;
    let length = u64::from(body.length);
    if target.leases.is_empty() || target.offset + length > file.superblock().region_size() {
        let lease = client.allocate(Claim::Internal).await.ok()?;
        target.leases.push(lease);
        target.offset = 0;
    }
    let lease = target.leases.last()?;
    if !rebase(&mut buf, tenant, body.epoch, lease.epoch()) {
        return None;
    }
    let moved = Range {
        region: lease.region(),
        epoch: lease.epoch(),
        offset: target.offset,
        length: body.length,
        checksum: checksum(&buf),
    };
    let at = file.region_offset(moved.region) + moved.offset;
    let (written, _) = file.file().write_all_at(buf, at).await;
    written.ok()?;
    target.offset += length;
    Some(moved)
}
