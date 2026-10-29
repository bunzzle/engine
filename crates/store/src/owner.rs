use std::collections::{BTreeMap, VecDeque};

use rt::{Receiver, Sender, channel, spawn};

use crate::boot::Core;
use crate::committer::{Location, Submission, Write};
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::journal::Dead;
use crate::keeper::Keeper;
use crate::reader::Owner;
use crate::record::Record;
use crate::regions::Claim;
use crate::session::{Event, Owned, Results, Session};
use crate::shard::{Change, INDEX_SIZE, Index, KIND_STATE};

enum Reply {
    Caller(Sender<Result<Location, Error>>),
    Move,
}

struct Compacting {
    region: u32,
    epoch: u64,
    moves: usize,
    skipped: Vec<(u16, u64)>,
}

struct Itself;

impl Owner for Itself {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        std::future::ready(None)
    }
}

struct Request {
    shard: u16,
    index: Index,
    sealed: Vec<u8>,
    reply: Reply,
}

enum Input {
    Change(Request),
    Event(Event),
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
        let (reply, mut answer) = channel();
        let request = Request {
            shard,
            index,
            sealed,
            reply: Reply::Caller(reply),
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
    results: Option<(Results, Sender<Input>)>,
    file: CoreFile,
    keeper: Keeper,
    owned: Vec<u16>,
    inputs: Receiver<Input>,
    busy: BTreeMap<(u16, u64), VecDeque<Request>>,
    waiting: VecDeque<(u64, Submission)>,
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
            results: Some((results, sender.clone())),
            file,
            keeper,
            owned: shards,
            inputs,
            busy: BTreeMap::new(),
            waiting: VecDeque::new(),
            sent: BTreeMap::new(),
            tag: 0,
            compacting: None,
            closing: false,
        };
        (owner, Changes { sender })
    }

    pub async fn run(mut self) -> Keeper {
        if let Some((mut results, events)) = self.results.take() {
            spawn(async move {
                while let Some(event) = results.recv().await {
                    if events.send(Input::Event(event)).is_err() {
                        break;
                    }
                }
            });
        }
        while !(self.closing && self.busy.is_empty()) {
            let Some(input) = self.inputs.recv().await else {
                break;
            };
            match input {
                Input::Change(request) => self.request(request),
                Input::Event(event) => self.event(event).await,
                Input::Close => self.closing = true,
            }
            self.flush();
        }
        self.keeper
    }

    fn request(&mut self, request: Request) {
        if !self.owned.contains(&request.shard) || self.closing {
            let error = if self.closing {
                Error::Failed
            } else {
                Error::Invalid("owner")
            };
            if let Reply::Caller(reply) = request.reply {
                let _ = reply.send(Err(error));
            }
            return;
        }
        let key = (request.shard, request.index.key);
        if let Some(queue) = self.busy.get_mut(&key) {
            queue.push_back(request);
            return;
        }
        self.busy.insert(key, VecDeque::new());
        self.start(request);
    }

    fn start(&mut self, request: Request) {
        let current = self
            .keeper
            .state(request.shard)
            .and_then(|state| state.get(request.index.key))
            .map(|item| (item.tenant, item.location));
        let claim = match (request.index.change, current) {
            (Change::Move { .. }, _) => Claim::Internal,
            (Change::Put(_), None) => Claim::Intake,
            _ => Claim::Control,
        };
        let counted = match request.index.change {
            Change::Put(_) => true,
            Change::Delete => {
                if current.is_none() {
                    self.finish(request, Err(Error::NotFound));
                    return;
                }
                false
            }
            Change::Move { old } => {
                if current.is_none_or(|(_, at)| at != old) {
                    self.finish(request, Err(Error::Invalid("moved")));
                    return;
                }
                true
            }
        };
        let dead = current
            .map(|(tenant, at)| Dead {
                tenant,
                region: at.region,
                epoch: at.epoch,
                offset: at.offset,
                length: at.size,
            })
            .into_iter()
            .collect();
        let payload = request.index.payload(&request.sealed);
        let submission = Submission {
            claim,
            records: vec![Write {
                kind: KIND_STATE,
                counted,
                shard: request.shard,
                tenant: request.index.tenant,
                payload,
            }],
            bodies: Vec::new(),
            dead,
        };
        self.tag += 1;
        self.sent.insert(self.tag, request);
        self.waiting.push_back((self.tag, submission));
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
                let location = locations[0];
                self.keeper
                    .apply(request.shard, &request.index, location, sequence);
                self.finish(request, Ok(location));
            }
            Event::Rejected { tag, error } => {
                let request = self.sent.remove(&tag).expect("result for a sent change");
                self.finish(request, Err(error));
            }
            Event::Cut { sequence } => {
                let _ = self.session.survey(sequence, self.owned_bytes());
                let _ = self.keeper.cut(&self.session, &self.file, sequence).await;
            }
            Event::Compact { region, epoch } => self.compact(region, epoch).await,
            Event::Published { sequence } => self.keeper.published(sequence),
            Event::Abandoned { sequence } => self.keeper.abandoned(sequence),
        }
    }

    fn finish(&mut self, request: Request, result: Result<Location, Error>) {
        let Request {
            shard,
            index,
            reply,
            ..
        } = request;
        let key = (shard, index.key);
        match reply {
            Reply::Caller(reply) => {
                let _ = reply.send(result);
            }
            Reply::Move => {
                if let Some(compacting) = self.compacting.as_mut() {
                    compacting.moves -= 1;
                }
            }
        }
        let next = self.busy.get_mut(&key).and_then(VecDeque::pop_front);
        match next {
            Some(next) => self.start(next),
            None => {
                self.busy.remove(&key);
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
                let region = item.location.region;
                let entry = owned.entry(region).or_insert(Owned {
                    region,
                    ..Owned::default()
                });
                entry.extents += 1;
                entry.bytes += u64::from(item.location.size);
            }
        }
        owned.into_values().collect()
    }

    async fn compact(&mut self, region: u32, epoch: u64) {
        let mut found = Vec::new();
        for &shard in &self.owned {
            let Some(state) = self.keeper.state(shard) else {
                continue;
            };
            for (&key, item) in state.entries() {
                if item.location.region == region && item.location.epoch == epoch {
                    found.push((shard, key, *item));
                }
            }
        }
        let mut compacting = Compacting {
            region,
            epoch,
            moves: 0,
            skipped: Vec::new(),
        };
        let reader = self.file.reader();
        let mut moves = Vec::new();
        for (shard, key, item) in found {
            if self.busy.contains_key(&(shard, key)) {
                compacting.skipped.push((shard, key));
                continue;
            }
            let Ok(buf) = reader.read(item.location, item.tenant, &Itself).await else {
                continue;
            };
            let Ok(record) = Record::decode(&buf) else {
                continue;
            };
            let Some(sealed) = record.payload().get(INDEX_SIZE..) else {
                continue;
            };
            let index = Index {
                key,
                tenant: item.tenant,
                change: Change::Move { old: item.location },
            };
            moves.push(Request {
                shard,
                index,
                sealed: sealed.to_vec(),
                reply: Reply::Move,
            });
        }
        compacting.moves = moves.len();
        self.compacting = Some(compacting);
        for request in moves {
            self.request(request);
        }
        self.settle_compaction();
    }

    fn settle_compaction(&mut self) {
        let Some(compacting) = self.compacting.as_ref() else {
            return;
        };
        let resolved = compacting.moves == 0
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
