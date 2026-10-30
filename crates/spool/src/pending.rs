use store::{Core, Index, Location, Owner, Record};

use crate::error::Error;
use crate::intake::MessageId;
use crate::items::{SLICE_BASE, STATE_BASE, slice_parts};
use crate::recipients::Table;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Open {
    pub recipient: u32,
    pub queue: u32,
    pub due: u64,
    pub class: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub id: MessageId,
    pub tenant: u32,
    pub recipients: Vec<Open>,
}

struct Fixed;

impl Owner for Fixed {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        std::future::ready(None)
    }
}

pub(crate) async fn read(core: &Core, table: &Table, node: u32) -> Result<Vec<Pending>, Error> {
    let reader = core.file.reader();
    let mut pending = Vec::new();
    for (shard, key, tenant, open) in table.open() {
        let state = core
            .keeper
            .state(shard)
            .ok_or(store::Error::Invalid("owner"))?;
        let mut queues = Vec::new();
        for (item_key, item) in state.message(key) {
            if item_key.item < SLICE_BASE || item_key.item >= STATE_BASE {
                continue;
            }
            let buf = reader.read(item.location, item.tenant, &Fixed).await?;
            let record = Record::decode(&buf).map_err(|_| Error::State("slice record"))?;
            let parts = Index::parts(record.payload()).ok_or(Error::State("slice index"))?;
            let (slice, _) = slice_parts(parts.sealed).ok_or(Error::State("slice"))?;
            queues.extend(slice);
        }
        let recipients = open
            .into_iter()
            .map(|(recipient, state)| {
                let queue = *queues.get(usize::try_from(recipient).ok()?)?;
                Some(Open {
                    recipient,
                    queue,
                    due: state.due,
                    class: state.class,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::State("slice"))?;
        pending.push(Pending {
            id: MessageId { node, shard, key },
            tenant,
            recipients,
        });
    }
    Ok(pending)
}
