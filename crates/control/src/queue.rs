use std::pin::Pin;

use crypto::TenantKeys;

use crate::error::Error;
use crate::record::{KIND_QUEUE, SYSTEM};
use crate::siphash::siphash;

pub const MAX_DOMAIN: usize = 253;

const FORMAT: u8 = 1;
const CLEAR: usize = 24;
const LABEL: usize = 63;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name {
    pub tenant: u32,
    pub domain: Box<str>,
    pub generation: u32,
    pub pool: u32,
}

impl Name {
    pub fn check(&self) -> Result<(), Error> {
        if self.tenant == SYSTEM {
            return Err(Error::Invalid("tenant id"));
        }
        if !domain_ok(&self.domain) {
            return Err(Error::Invalid("domain"));
        }
        Ok(())
    }
}

pub fn domain_ok(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= MAX_DOMAIN
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= LABEL
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queue {
    pub id: u32,
    pub name: Name,
    pub draining: bool,
}

impl Queue {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; CLEAR];
        out[0] = FORMAT;
        out[1] = KIND_QUEUE;
        out[2] = u8::from(self.draining);
        out[4..8].copy_from_slice(&self.id.to_le_bytes());
        out[8..12].copy_from_slice(&self.name.tenant.to_le_bytes());
        out[12..16].copy_from_slice(&self.name.generation.to_le_bytes());
        out[16..20].copy_from_slice(&self.name.pool.to_le_bytes());
        out
    }

    pub fn decode(clear: &[u8], domain: Box<str>) -> Option<Self> {
        let head = Head::decode(clear)?;
        let queue = Self {
            id: head.id,
            name: Name {
                tenant: head.tenant,
                domain,
                generation: head.generation,
                pool: head.pool,
            },
            draining: head.draining,
        };
        queue.name.check().ok()?;
        Some(queue)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub id: u32,
    pub tenant: u32,
    pub generation: u32,
    pub pool: u32,
    pub draining: bool,
}

impl Head {
    pub fn decode(clear: &[u8]) -> Option<Self> {
        if clear.len() != CLEAR
            || clear[0] != FORMAT
            || clear[1] != KIND_QUEUE
            || clear[2] > 1
            || clear[3] != 0
            || clear[20..] != [0; 4]
        {
            return None;
        }
        let at = |i: usize| u32::from_le_bytes(clear[i..i + 4].try_into().expect("4 bytes"));
        Some(Self {
            id: at(4),
            tenant: at(8),
            generation: at(12),
            pool: at(16),
            draining: clear[2] == 1,
        })
    }
}

pub const LABEL_SIZE: usize = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label {
    pub tenant: u32,
    pub generation: u32,
    pub kind: u8,
    pub id: u32,
    pub hash: Option<[u8; 16]>,
}

impl Label {
    pub fn bytes(&self) -> [u8; LABEL_SIZE] {
        let mut out = [0; LABEL_SIZE];
        out[..4].copy_from_slice(&self.tenant.to_le_bytes());
        out[4..8].copy_from_slice(&self.generation.to_le_bytes());
        out[8] = self.kind;
        out[9..13].copy_from_slice(&self.id.to_le_bytes());
        if let Some(hash) = self.hash {
            out[13] = 1;
            out[14..].copy_from_slice(&hash);
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    Unavailable,
    Busy,
    Unknown,
    Failed,
    Conflict,
}

pub type Ready<'a> = Pin<Box<dyn Future<Output = Result<TenantKeys, KeyError>> + 'a>>;
pub type Created<'a> = Pin<Box<dyn Future<Output = Result<(), KeyError>> + 'a>>;

pub trait KeySource {
    fn get(&self, tenant: u32, generation: u32) -> Option<TenantKeys>;
    fn ready(&self, tenant: u32, generation: u32) -> Ready<'_>;
    fn create(&self, tenant: u32, generation: u32) -> Created<'_>;
}

pub async fn tenant_keys(
    source: &dyn KeySource,
    tenant: u32,
    generation: u32,
) -> Result<TenantKeys, KeyError> {
    match source.get(tenant, generation) {
        Some(keys) => Ok(keys),
        None => source.ready(tenant, generation).await,
    }
}

pub trait Tenancy {
    fn holder(&self, queue: u32) -> Option<(u32, u32)>;
}

pub fn mix(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x85eb_ca6b);
    x ^= x >> 13;
    x = x.wrapping_mul(0xc2b2_ae35);
    x ^ (x >> 16)
}

pub fn queue_shard(queue: u32, shards: u32) -> u16 {
    u16::try_from(mix(queue) % shards).expect("shard fits in u16")
}

pub fn naming_shard(key: &[u8; 16], tenant: u32, domain: &str, shards: u32) -> u16 {
    let mut data = Vec::with_capacity(4 + domain.len());
    data.extend_from_slice(&tenant.to_le_bytes());
    data.extend_from_slice(domain.as_bytes());
    u16::try_from(siphash(key, &data) % u64::from(shards)).expect("shard fits in u16")
}
