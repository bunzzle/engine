use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::rc::Rc;

use control::{KeyError, KeySource};
use crypto::{
    AAD, BatchKey, ChunkKey, Opener as ChunkOpener, Sealer as ChunkSealer, TAG, Wrap, aad,
};
use keys::Batch;
use spool::{
    BODY_ITEM, Body, HEAD_CLEAR, Head, HeadClear, MessageId, Slice, Stamp, WRAP, slice_item,
    state_item,
};
use store::{HEAD_ITEM, INDEX_SIZE, MAX_PAYLOAD};

use crate::error::Refusal;
use crate::intake::Draft;
use crate::start::Node;
use crate::transport::Transport;

pub const LABEL_HEAD: u8 = 1;
pub const LABEL_BODY: u8 = 2;
pub const LABEL_SLICE: u8 = 3;
pub const LABEL_REPLY: u8 = 4;

const HEAD_ROOM: usize = MAX_PAYLOAD - INDEX_SIZE - HEAD_CLEAR - WRAP - TAG - 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsealable {
    Unavailable,
    Gone,
    Unknown,
    Bad,
    Failed,
}

pub type Batched<'a> = Pin<Box<dyn Future<Output = Result<Rc<Batch>, KeyError>> + 'a>>;
pub type Oldest<'a> = Pin<Box<dyn Future<Output = Result<u32, KeyError>> + 'a>>;
pub type Unwrapped<'a> = Pin<Box<dyn Future<Output = Result<Rc<BatchKey>, Unsealable>> + 'a>>;

pub trait Keys: KeySource {
    fn tick(&self) {}

    fn settled(&self, _day: u32) {}

    fn oldest(&self, _tenant: u32, _generation: u32) -> Oldest<'_> {
        Box::pin(async { Err(KeyError::Unavailable) })
    }

    fn batch(&self, tenant: u32, generation: u32, shard: u16, first: u64) -> Batched<'_>;
    fn batch_key(
        &self,
        tenant: u32,
        generation: u32,
        shard: u16,
        id: u64,
        wrap: Wrap,
    ) -> Unwrapped<'_>;
}

#[derive(Clone, Default)]
pub(crate) struct Holds(Rc<RefCell<BTreeMap<u32, u64>>>, Rc<Cell<u64>>);

impl Holds {
    pub(crate) fn hold(&self, day: u32) -> DayHold {
        *self.0.borrow_mut().entry(day).or_default() += 1;
        DayHold {
            holds: self.clone(),
            day,
            kept: false,
        }
    }

    pub(crate) fn oldest(&self) -> Option<u32> {
        self.0.borrow().keys().next().copied()
    }

    pub(crate) fn kept(&self) -> u64 {
        self.1.get()
    }
}

pub(crate) struct DayHold {
    holds: Holds,
    day: u32,
    kept: bool,
}

impl DayHold {
    pub(crate) fn keep(mut self) {
        self.kept = true;
        self.holds.1.set(self.holds.1.get() + 1);
    }
}

impl Drop for DayHold {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        let mut days = self.holds.0.borrow_mut();
        if let Some(count) = days.get_mut(&self.day) {
            *count -= 1;
            if *count == 0 {
                days.remove(&self.day);
            }
        }
    }
}

pub struct Sealing {
    tenant: u32,
    generation: u32,
    id: MessageId,
    batch: Rc<Batch>,
    sealed: BTreeSet<u32>,
}

impl Sealing {
    pub fn id(&self) -> MessageId {
        self.id
    }

    pub fn tenant(&self) -> u32 {
        self.tenant
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn head(
        &mut self,
        clear: HeadClear,
        expiry: u64,
        envelope: &[u8],
        headers: &[u8],
    ) -> Result<Head, Refusal> {
        if envelope.len() + headers.len() > HEAD_ROOM {
            return Err(Refusal::Message);
        }
        let length = u32::try_from(envelope.len()).map_err(|_| Refusal::Message)?;
        let (key, aad) = self.key(HEAD_ITEM, LABEL_HEAD)?;
        let mut clear_bytes = Vec::with_capacity(4 + envelope.len() + headers.len());
        clear_bytes.extend_from_slice(&length.to_le_bytes());
        clear_bytes.extend_from_slice(envelope);
        clear_bytes.extend_from_slice(headers);
        Ok(Head {
            clear: HeadClear {
                batch_key: self.batch.id,
                day: self.batch.day,
                ..clear
            },
            expiry,
            wrap: self.batch.wrap,
            sealed: key.seal_one(&aad, &clear_bytes),
        })
    }

    pub fn inline_body(&mut self, body: &[u8]) -> Result<Body, Refusal> {
        let (key, aad) = self.key(BODY_ITEM, LABEL_BODY)?;
        Ok(Body::Inline(key.seal_one(&aad, body)))
    }

    pub fn body_chunks(&mut self) -> Result<ChunkSealer, Refusal> {
        let (key, aad) = self.key(BODY_ITEM, LABEL_BODY)?;
        Ok(ChunkSealer::new(key, &aad))
    }

    pub fn slice(&mut self, n: u32, queues: Vec<u32>, recipients: &[u8]) -> Result<Slice, Refusal> {
        let (key, aad) = self.key(slice_item(n), LABEL_SLICE)?;
        Ok(Slice {
            queues,
            sealed: key.seal_one(&aad, recipients),
        })
    }

    fn key(&mut self, item: u32, label: u8) -> Result<(ChunkKey, [u8; AAD]), Refusal> {
        if !self.sealed.insert(item) {
            return Err(Refusal::Message);
        }
        let message = self.id.bytes();
        Ok((
            self.batch.key.record(&message, item, label),
            aad(self.tenant, self.generation, &message, item, label),
        ))
    }
}

pub struct Opener {
    tenant: u32,
    generation: u32,
    message: [u8; 16],
    key: Rc<BatchKey>,
    replies: RefCell<BTreeSet<(u32, Stamp)>>,
}

impl Opener {
    pub fn head(&self, sealed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Unsealable> {
        let (key, aad) = self.key(HEAD_ITEM, LABEL_HEAD);
        let mut clear = key.open_one(&aad, sealed).map_err(|_| Unsealable::Bad)?;
        let (length, rest) = clear.split_first_chunk::<4>().ok_or(Unsealable::Bad)?;
        let length = usize::try_from(u32::from_le_bytes(*length)).map_err(|_| Unsealable::Bad)?;
        if length > rest.len() {
            return Err(Unsealable::Bad);
        }
        let headers = clear.split_off(4 + length);
        clear.drain(..4);
        Ok((clear, headers))
    }

    pub fn inline_body(&self, sealed: &[u8]) -> Result<Vec<u8>, Unsealable> {
        let (key, aad) = self.key(BODY_ITEM, LABEL_BODY);
        key.open_one(&aad, sealed).map_err(|_| Unsealable::Bad)
    }

    pub fn body_chunks(&self) -> ChunkOpener {
        let (key, aad) = self.key(BODY_ITEM, LABEL_BODY);
        ChunkOpener::new(key, &aad)
    }

    pub fn slice(&self, n: u32, sealed: &[u8]) -> Result<Vec<u8>, Unsealable> {
        let (key, aad) = self.key(slice_item(n), LABEL_SLICE);
        key.open_one(&aad, sealed).map_err(|_| Unsealable::Bad)
    }

    pub fn seal_reply(
        &self,
        recipient: u32,
        stamp: Stamp,
        reply: &[u8],
    ) -> Result<Vec<u8>, Unsealable> {
        if !self.replies.borrow_mut().insert((recipient, stamp)) {
            return Err(Unsealable::Bad);
        }
        let (key, aad) = self.reply_key(recipient, stamp);
        Ok(key.seal_one(&aad, reply))
    }

    pub fn open_reply(
        &self,
        recipient: u32,
        stamp: Stamp,
        sealed: &[u8],
    ) -> Result<Vec<u8>, Unsealable> {
        let (key, aad) = self.reply_key(recipient, stamp);
        key.open_one(&aad, sealed).map_err(|_| Unsealable::Bad)
    }

    fn reply_key(&self, recipient: u32, stamp: Stamp) -> (ChunkKey, [u8; AAD]) {
        let item = state_item(recipient);
        let key = self
            .key
            .stamped(&self.message, item, LABEL_REPLY, stamp.boot, stamp.write);
        let aad = aad(
            self.tenant,
            self.generation,
            &self.message,
            item,
            LABEL_REPLY,
        );
        (key, aad)
    }

    fn key(&self, item: u32, label: u8) -> (ChunkKey, [u8; AAD]) {
        (
            self.key.record(&self.message, item, label),
            aad(self.tenant, self.generation, &self.message, item, label),
        )
    }
}

impl<T: Transport + 'static> Node<T> {
    pub async fn sealing(&self, draft: &mut Draft, shard: u16) -> Result<Sealing, Refusal> {
        let (tenant, generation) = (draft.tenant(), draft.generation());
        let id = self.spool().id(shard).await.map_err(|_| Refusal::Failed)?;
        let batch = self
            .keys()
            .batch(tenant, generation, shard, id.key)
            .await
            .map_err(|_| Refusal::Keys)?;
        draft.hold(self.inner.holds.hold(batch.day));
        Ok(Sealing {
            tenant,
            generation,
            id,
            batch,
            sealed: BTreeSet::new(),
        })
    }

    pub async fn opener(
        &self,
        tenant: u32,
        generation: u32,
        id: MessageId,
        clear: &HeadClear,
        wrap: &[u8; WRAP],
    ) -> Result<Opener, Unsealable> {
        let decoded = Wrap::decode(wrap).map_err(|_| Unsealable::Bad)?;
        if (decoded.generation, decoded.shard, decoded.day) != (generation, id.shard, clear.day) {
            return Err(Unsealable::Bad);
        }
        let key = self
            .keys()
            .batch_key(tenant, generation, id.shard, clear.batch_key, decoded)
            .await?;
        Ok(Opener {
            tenant,
            generation,
            message: id.bytes(),
            key,
            replies: RefCell::new(BTreeSet::new()),
        })
    }
}
