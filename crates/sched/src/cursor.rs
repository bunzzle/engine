use control::KIND_CURSOR;
use store::{Batch, Change, Changes, Delivery, HEAD_ITEM, Key, Op, control_key};

const FORMAT: u8 = 1;
const SIZE: usize = 25;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub generation: u32,
    pub acked: u64,
    pub lost: u64,
    pub counted: u32,
}

impl Cursor {
    pub fn encode(&self) -> [u8; SIZE] {
        let mut out = [0; SIZE];
        out[0] = FORMAT;
        out[1..5].copy_from_slice(&self.generation.to_le_bytes());
        out[5..13].copy_from_slice(&self.acked.to_le_bytes());
        out[13..21].copy_from_slice(&self.lost.to_le_bytes());
        out[21..25].copy_from_slice(&self.counted.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIZE || bytes[0] != FORMAT {
            return None;
        }
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        Some(Self {
            generation: word(1),
            acked: long(5),
            lost: long(13),
            counted: word(21),
        })
    }
}

fn batch(shard: u16, tenant: u32, hook: u32, change: Change, clear: Vec<u8>) -> Batch {
    Batch {
        shard,
        message: control_key(KIND_CURSOR, hook),
        tenant,
        ops: vec![Op {
            item: HEAD_ITEM,
            change,
            clear,
            bodies: Vec::new(),
            sealed: Vec::new(),
        }],
    }
}

pub async fn read_cursor(
    changes: &Changes,
    shard: u16,
    tenant: u32,
    hook: u32,
) -> Result<Option<Cursor>, store::Error> {
    let key = Key {
        message: control_key(KIND_CURSOR, hook),
        item: HEAD_ITEM,
    };
    let found = changes.items(shard, vec![key]).await?;
    Ok(found
        .into_iter()
        .flatten()
        .find(|item| item.tenant == tenant)
        .and_then(|item| Cursor::decode(&item.clear)))
}

pub async fn write_cursor(
    changes: &Changes,
    shard: u16,
    tenant: u32,
    hook: u32,
    cursor: &Cursor,
) -> Result<(), store::Error> {
    let put = Change::Put(Delivery {
        status: 0,
        attempts: 0,
        due: 0,
    });
    let batch = batch(shard, tenant, hook, put, cursor.encode().to_vec());
    changes.apply(batch).await.map(drop)
}

pub async fn drop_cursor(
    changes: &Changes,
    shard: u16,
    tenant: u32,
    hook: u32,
) -> Result<(), store::Error> {
    match changes
        .apply(batch(shard, tenant, hook, Change::Drop, Vec::new()))
        .await
    {
        Ok(_) | Err(store::Error::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}
