use crypto::Wrap;
use spool::{MessageId, Spool, Status};

use crate::finder::{Query, SEARCH_DAYS};
use crate::reader::ReadError;
use crate::requests::DAY;
use crate::sealing::{Keys, Unsealable, opener};
use crate::search::Field;
use crate::sign::open_recipients;

pub const MESSAGE_LIMIT: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRecipient {
    pub index: u32,
    pub address: String,
    pub status: Status,
    pub attempts: u16,
    pub due: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessagePage {
    pub done: bool,
    pub recipients: Vec<MessageRecipient>,
    pub more: bool,
}

impl MessagePage {
    pub(crate) fn finished() -> Self {
        Self {
            done: true,
            recipients: Vec::new(),
            more: false,
        }
    }
}

pub(crate) async fn live(
    spool: &Spool,
    keys: &dyn Keys,
    (tenant, generation): (u32, u32),
    id: MessageId,
    after: Option<u32>,
    limit: usize,
) -> Result<Option<MessagePage>, ReadError> {
    let from = after.map_or(0, |a| a.saturating_add(1));
    let count = u32::try_from(limit).map_err(|_| ReadError::Limit)?;
    let Some(states) = spool.states(tenant, id, from, count) else {
        return Ok(None);
    };
    let wanted: Vec<u32> = states.recipients.iter().map(|(r, _)| *r).collect();
    let Some(stored) = spool
        .stored(id, &wanted)
        .await
        .ok()
        .filter(|s| s.tenant == tenant)
    else {
        return Ok(None);
    };
    let Ok(wrap) = spool.stored_wrap(&stored).await else {
        return Ok(None);
    };
    if Wrap::decode(&wrap).map_or(true, |w| w.generation != generation) {
        return Ok(None);
    }
    let slices = spool
        .open_slices(&stored)
        .await
        .map_err(|_| ReadError::Failed)?;
    let opener = opener(keys, tenant, generation, id, &stored.clear, &wrap)
        .await
        .map_err(unsealable)?;
    let addresses = open_recipients(&opener, &slices, stored.clear.recipients, &wanted)
        .map_err(|e| e.map_or(ReadError::Failed, unsealable))?;
    let end = from.saturating_add(u32::try_from(wanted.len()).unwrap_or(u32::MAX));
    let recipients = states
        .recipients
        .into_iter()
        .zip(addresses)
        .map(|((index, state), (_, recipient))| MessageRecipient {
            index,
            address: recipient.address,
            status: state.status,
            attempts: state.attempts,
            due: state.due,
        })
        .collect();
    Ok(Some(MessagePage {
        done: states.done,
        recipients,
        more: end < states.total,
    }))
}

pub(crate) fn finished_query(id: MessageId, now: u64) -> Option<Query> {
    let to = now.saturating_add(1);
    let from = ((to - 1) / DAY).saturating_sub(SEARCH_DAYS - 1) * DAY;
    Query::new(Field::Message, &id.bytes(), &[], from, to)
}

fn unsealable(error: Unsealable) -> ReadError {
    match error {
        Unsealable::Unavailable => ReadError::Unavailable,
        Unsealable::Gone | Unsealable::Unknown | Unsealable::Bad | Unsealable::Failed => {
            ReadError::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finished_messages_are_looked_up_over_the_longest_search_range() {
        let id = MessageId {
            node: 1,
            shard: 3,
            key: 9,
        };
        for now in [0, 5, DAY - 1, DAY, 20 * DAY + 7] {
            let query = finished_query(id, now).expect("query");
            let (from, to) = query.range();
            assert_eq!(to, now + 1);
            assert_eq!(from % DAY, 0);
            assert!((to - 1) / DAY - from / DAY < SEARCH_DAYS);
            assert_eq!(query.value(), id.bytes());
        }
        let (from, _) = finished_query(id, 20 * DAY + 7).expect("query").range();
        assert_eq!(from, 13 * DAY);
    }
}
