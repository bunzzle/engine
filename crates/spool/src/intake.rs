use std::cell::RefCell;
use std::rc::Rc;

use store::{
    Batch, Change, Changes, Client, Core, Delivery, HEAD_ITEM, INDEX_SIZE, Ids, MAX_PAYLOAD, Op,
    Shards, fits, record_size, split_key,
};

use crate::bodies::{Writer, Written};
use crate::error::Error;
use crate::items::{BODY_ITEM, HeadClear, encode_slice, slice_item};
use crate::limits::{Bounds, Limits, SLICE};
use crate::pending::{self, Pending};
use crate::recipients::Table;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId {
    pub node: u32,
    pub shard: u16,
    pub key: u64,
}

impl MessageId {
    pub fn bytes(&self) -> [u8; 16] {
        let (boot, counter) = split_key(self.key);
        let mut out = [0; 16];
        out[0..4].copy_from_slice(&self.node.to_le_bytes());
        out[4..6].copy_from_slice(&self.shard.to_le_bytes());
        out[8..12].copy_from_slice(&boot.to_le_bytes());
        out[12..16].copy_from_slice(&counter.to_le_bytes());
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub clear: HeadClear,
    pub expiry: u64,
    pub sealed: Vec<u8>,
}

pub enum Body {
    Inline(Vec<u8>),
    Chain(Written),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slice {
    pub queues: Vec<u32>,
    pub sealed: Vec<u8>,
}

pub struct Message {
    pub id: MessageId,
    pub tenant: u32,
    pub head: Head,
    pub body: Body,
    pub slices: Vec<Slice>,
}

pub(crate) struct Inner {
    pub(crate) node: u32,
    limits: Limits,
    bounds: Bounds,
    pub(crate) region_size: u64,
    pub(crate) changes: Changes,
    client: Client,
    pub(crate) ids: RefCell<Ids>,
    writer: Writer,
    pub(crate) table: RefCell<Table>,
}

#[derive(Clone)]
pub struct Spool {
    pub(crate) inner: Rc<Inner>,
}

impl Spool {
    pub fn new(core: Core, node: u32, limits: Limits) -> Result<(Self, Shards), Error> {
        let table = Table::rebuild(&core.keeper, &core.shards)?;
        Self::build(core, node, limits, table)
    }

    pub async fn open(
        core: Core,
        node: u32,
        limits: Limits,
    ) -> Result<(Self, Shards, Vec<Pending>), Error> {
        limits.check(core.file.superblock().region_size())?;
        let table = Table::rebuild(&core.keeper, &core.shards)?;
        let pending = pending::read(&core, &table, node).await?;
        let (spool, shards) = Self::build(core, node, limits, table)?;
        Ok((spool, shards, pending))
    }

    fn build(core: Core, node: u32, limits: Limits, table: Table) -> Result<(Self, Shards), Error> {
        let region_size = core.file.superblock().region_size();
        let bounds = limits.check(region_size)?;
        let client = core.session.client().clone();
        let writer = Writer::new(client.clone(), core.file.clone());
        let ids = RefCell::new(core.ids.clone());
        let table = RefCell::new(table);
        let (shards, changes) = Shards::new(core);
        let inner = Inner {
            node,
            limits,
            bounds,
            region_size,
            changes,
            client,
            ids,
            writer,
            table,
        };
        Ok((
            Self {
                inner: Rc::new(inner),
            },
            shards,
        ))
    }

    pub fn changes(&self) -> &Changes {
        &self.inner.changes
    }

    pub fn limits(&self) -> Limits {
        self.inner.limits
    }

    pub fn chunk(&self) -> usize {
        self.inner.bounds.chunk
    }

    pub async fn id(&self, shard: u16) -> Result<MessageId, Error> {
        let inner = &self.inner;
        loop {
            let (next, boot) = {
                let mut ids = inner.ids.borrow_mut();
                (ids.next(shard), ids.boot(shard))
            };
            let Some(current) = boot else {
                return Err(store::Error::Invalid("owner").into());
            };
            if let Some(key) = next {
                return Ok(MessageId {
                    node: inner.node,
                    shard,
                    key,
                });
            }
            let renewed = inner.client.boot().await?;
            let mut ids = inner.ids.borrow_mut();
            if renewed > current && ids.boot(shard) == Some(current) {
                ids.renew(shard, renewed);
            }
        }
    }

    pub async fn body(
        &self,
        id: MessageId,
        tenant: u32,
        chunks: &[Vec<u8>],
    ) -> Result<Written, Error> {
        let inner = &self.inner;
        if chunks.is_empty() || chunks.iter().any(|c| c.len() > inner.bounds.chunk) {
            return Err(Error::Limit("chunk"));
        }
        let size: usize = chunks.iter().map(|c| record_size(16 + c.len())).sum();
        if size as u64 > inner.limits.body {
            return Err(Error::Limit("body"));
        }
        inner.writer.write(id.shard, tenant, id.key, chunks).await
    }

    pub async fn accept(&self, messages: Vec<Message>) -> Result<(), Error> {
        let mut batches = Vec::with_capacity(messages.len());
        let mut held = Vec::new();
        let mut bytes = 0;
        let mut records = 0;
        let mut ranges = 0;
        let mut entries = Vec::with_capacity(messages.len());
        for message in messages {
            entries.push((
                message.id,
                message.tenant,
                message.head.clear,
                message.head.expiry,
            ));
            let (batch, written) = self.batch(message)?;
            held.extend(written.into_iter().flat_map(|w| w.leases));
            bytes += batch
                .ops
                .iter()
                .map(|op| {
                    record_size(
                        INDEX_SIZE + op.clear.len() + op.sealed.len() + 32 * op.bodies.len(),
                    ) as u64
                })
                .sum::<u64>();
            records += batch.ops.len();
            ranges += batch.ops.iter().map(|op| op.bodies.len()).sum::<usize>();
            batches.push(batch);
        }
        if bytes > self.inner.region_size || !fits(1 + ranges, 1, records + ranges, 0) {
            return Err(Error::Limit("submission"));
        }
        let created = self.inner.changes.create(batches).await;
        drop(held);
        created?;
        let mut table = self.inner.table.borrow_mut();
        for (id, tenant, head, expiry) in entries {
            table.insert(id.shard, id.key, tenant, &head, expiry);
        }
        Ok(())
    }

    fn batch(&self, message: Message) -> Result<(Batch, Option<Written>), Error> {
        let inner = &self.inner;
        let Message {
            id,
            tenant,
            head,
            body,
            slices,
        } = message;
        let recipients: usize = slices.iter().map(|s| s.queues.len()).sum();
        let full = slice_sizes_ok(&slices);
        if recipients == 0 || recipients > inner.limits.recipients as usize || !full {
            return Err(Error::Limit("recipients"));
        }
        if u32::try_from(recipients).ok() != Some(head.clear.recipients) {
            return Err(Error::Limit("recipient total"));
        }
        let none = Delivery {
            status: 0,
            attempts: 0,
            due: 0,
        };
        let op = |item, change, clear: Vec<u8>, bodies, sealed: Vec<u8>| -> Result<Op, Error> {
            if INDEX_SIZE + clear.len() + sealed.len() > MAX_PAYLOAD {
                return Err(Error::Limit("record"));
            }
            Ok(Op {
                item,
                change,
                clear,
                bodies,
                sealed,
            })
        };
        let mut ops = Vec::with_capacity(2 + slices.len());
        let head_change = Change::Put(Delivery {
            due: head.expiry,
            ..none
        });
        ops.push(
            op(
                HEAD_ITEM,
                head_change,
                head.clear.encode(),
                Vec::new(),
                head.sealed,
            )
            .map_err(|_| Error::Limit("header"))?,
        );
        let (bodies, sealed, written) = match body {
            Body::Inline(sealed) if sealed.len() <= inner.limits.inline => {
                (Vec::new(), sealed, None)
            }
            Body::Inline(_) => return Err(Error::Limit("inline body")),
            Body::Chain(written) => {
                let matches =
                    (written.shard, written.message, written.tenant) == (id.shard, id.key, tenant);
                if !matches {
                    return Err(Error::Limit("body owner"));
                }
                if written.ranges.len() > inner.bounds.ranges {
                    return Err(Error::Limit("body"));
                }
                (written.ranges.clone(), Vec::new(), Some(written))
            }
        };
        ops.push(op(
            BODY_ITEM,
            Change::Put(none),
            Vec::new(),
            bodies,
            sealed,
        )?);
        for (n, slice) in (0u32..).zip(slices) {
            ops.push(op(
                slice_item(n),
                Change::Put(none),
                Vec::new(),
                Vec::new(),
                encode_slice(&slice.queues, &slice.sealed),
            )?);
        }
        let batch = Batch {
            shard: id.shard,
            message: id.key,
            tenant,
            ops,
        };
        Ok((batch, written))
    }
}

fn slice_sizes_ok(slices: &[Slice]) -> bool {
    let Some((last, full)) = slices.split_last() else {
        return false;
    };
    let size = SLICE as usize;
    full.iter().all(|s| s.queues.len() == size) && (1..=size).contains(&last.queues.len())
}
