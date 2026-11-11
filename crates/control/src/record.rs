use std::net::{IpAddr, Ipv6Addr};

use crypto::DkimAlg;

use crate::error::Error;
use crate::queue::{MAX_DOMAIN, domain_ok};

pub const KIND_TENANT: u8 = 1;
pub const KIND_POOL: u8 = 2;
pub const KIND_QUEUE: u8 = 3;
pub const KIND_NODE: u8 = 4;
pub const KIND_DKIM: u8 = 5;
pub const SYSTEM: u32 = 0;
pub const MAX_POOLS: usize = 16;
pub const MAX_ADDRESSES: usize = 64;
pub const MAX_SELECTOR: usize = 63;
pub const MAX_PUBLIC: usize = 1024;
pub const MAX_BLOB: usize = 3072;

const FORMAT: u8 = 1;
const HEAD: usize = 16;
const TENANT: usize = 32;
const POOL: usize = 4;
const ADDRESS: usize = 20;
const DKIM: usize = 16;
const DOMAINKEY: &str = "._domainkey.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Active,
    Suspended,
    Deleting,
    Deleted,
}

impl State {
    pub fn deleted(self) -> bool {
        matches!(self, Self::Deleting | Self::Deleted)
    }

    fn code(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Suspended => 2,
            Self::Deleting => 3,
            Self::Deleted => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Active),
            2 => Some(Self::Suspended),
            3 => Some(Self::Deleting),
            4 => Some(Self::Deleted),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub rate: u32,
    pub burst: u32,
    pub queued: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub id: u32,
    pub generation: u32,
    pub state: State,
    pub default_pool: u32,
    pub pools: Vec<u32>,
    pub limits: Limits,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub id: u32,
    pub addresses: Vec<(IpAddr, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dkim {
    pub id: u32,
    pub tenant: u32,
    pub generation: u32,
    pub alg: DkimAlg,
    pub domain: Box<str>,
    pub selector: Box<str>,
    pub public: Vec<u8>,
    pub blob: Vec<u8>,
}

impl Dkim {
    pub fn check_name(domain: &str, selector: &str) -> Result<(), Error> {
        if !domain_ok(domain) {
            return Err(Error::Invalid("domain"));
        }
        if !domain_ok(selector)
            || selector.len() > MAX_SELECTOR
            || selector.len() + DOMAINKEY.len() + domain.len() > MAX_DOMAIN
        {
            return Err(Error::Invalid("selector"));
        }
        Ok(())
    }

    pub fn name(&self) -> String {
        format!("{}{DOMAINKEY}{}", self.selector, self.domain)
    }

    pub fn txt(&self) -> String {
        let k = match self.alg {
            DkimAlg::RsaSha256 => "rsa",
            DkimAlg::Ed25519Sha256 => "ed25519",
        };
        format!("v=DKIM1; k={k}; p={}", base64(&self.public))
    }

    fn check(&self) -> Result<(), Error> {
        if self.tenant == SYSTEM {
            return Err(Error::Invalid("tenant id"));
        }
        Self::check_name(&self.domain, &self.selector)?;
        let public_ok = match self.alg {
            DkimAlg::Ed25519Sha256 => self.public.len() == 32,
            DkimAlg::RsaSha256 => !self.public.is_empty() && self.public.len() <= MAX_PUBLIC,
        };
        if !public_ok {
            return Err(Error::Invalid("public key"));
        }
        if self.blob.is_empty() || self.blob.len() > MAX_BLOB {
            return Err(Error::Invalid("blob"));
        }
        Ok(())
    }
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(TABLE[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Tenant(Tenant),
    Pool(Pool),
    Dkim(Dkim),
}

impl Object {
    pub fn kind(&self) -> u8 {
        match self {
            Self::Tenant(_) => KIND_TENANT,
            Self::Pool(_) => KIND_POOL,
            Self::Dkim(_) => KIND_DKIM,
        }
    }

    pub fn id(&self) -> u32 {
        match self {
            Self::Tenant(t) => t.id,
            Self::Pool(p) => p.id,
            Self::Dkim(d) => d.id,
        }
    }

    pub fn tenant(&self) -> u32 {
        match self {
            Self::Tenant(t) => t.id,
            Self::Pool(_) => SYSTEM,
            Self::Dkim(d) => d.tenant,
        }
    }

    pub fn check(&self) -> Result<(), Error> {
        match self {
            Self::Tenant(t) => {
                if t.id == SYSTEM {
                    return Err(Error::Invalid("tenant id"));
                }
                if t.pools.is_empty() || t.pools.len() > MAX_POOLS {
                    return Err(Error::Invalid("pools"));
                }
                let mut sorted = t.pools.clone();
                sorted.sort_unstable();
                sorted.dedup();
                if sorted.len() != t.pools.len() {
                    return Err(Error::Invalid("pools"));
                }
                if !t.pools.contains(&t.default_pool) {
                    return Err(Error::Invalid("default pool"));
                }
            }
            Self::Pool(p) => {
                if p.addresses.len() > MAX_ADDRESSES || p.addresses.iter().any(|a| a.1 == 0) {
                    return Err(Error::Invalid("addresses"));
                }
            }
            Self::Dkim(d) => d.check()?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub version: u64,
    pub object: Object,
}

impl Update {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; HEAD];
        out[0] = FORMAT;
        out[1] = self.object.kind();
        out[4..8].copy_from_slice(&self.object.id().to_le_bytes());
        out[8..16].copy_from_slice(&self.version.to_le_bytes());
        match &self.object {
            Object::Tenant(t) => {
                let mut body = [0; TENANT];
                body[0..4].copy_from_slice(&t.generation.to_le_bytes());
                body[4] = t.state.code();
                body[5] = u8::try_from(t.pools.len()).expect("pools checked");
                body[8..12].copy_from_slice(&t.default_pool.to_le_bytes());
                body[12..16].copy_from_slice(&t.limits.rate.to_le_bytes());
                body[16..20].copy_from_slice(&t.limits.burst.to_le_bytes());
                body[24..32].copy_from_slice(&t.limits.queued.to_le_bytes());
                out.extend_from_slice(&body);
                for pool in &t.pools {
                    out.extend_from_slice(&pool.to_le_bytes());
                }
            }
            Object::Pool(p) => {
                let count = u16::try_from(p.addresses.len()).expect("addresses checked");
                out.extend_from_slice(&count.to_le_bytes());
                out.extend_from_slice(&[0; POOL - 2]);
                for (ip, weight) in &p.addresses {
                    let v6 = match ip {
                        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                        IpAddr::V6(v6) => *v6,
                    };
                    out.extend_from_slice(&v6.octets());
                    out.extend_from_slice(&weight.to_le_bytes());
                    out.extend_from_slice(&[0; ADDRESS - 18]);
                }
            }
            Object::Dkim(d) => {
                let mut body = [0; DKIM];
                body[0..4].copy_from_slice(&d.generation.to_le_bytes());
                body[4] = d.alg.code();
                body[5] = u8::try_from(d.domain.len()).expect("domain checked");
                body[6] = u8::try_from(d.selector.len()).expect("selector checked");
                let public = u16::try_from(d.public.len()).expect("public key checked");
                let blob = u16::try_from(d.blob.len()).expect("blob checked");
                body[8..10].copy_from_slice(&public.to_le_bytes());
                body[10..12].copy_from_slice(&blob.to_le_bytes());
                body[12..16].copy_from_slice(&d.tenant.to_le_bytes());
                out.extend_from_slice(&body);
                out.extend_from_slice(d.domain.as_bytes());
                out.extend_from_slice(d.selector.as_bytes());
                out.extend_from_slice(&d.public);
                out.extend_from_slice(&d.blob);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let head = bytes.get(..HEAD)?;
        if head[0] != FORMAT || head[2..4] != [0, 0] {
            return None;
        }
        let id = u32::from_le_bytes(head[4..8].try_into().ok()?);
        let version = u64::from_le_bytes(head[8..16].try_into().ok()?);
        let rest = &bytes[HEAD..];
        let object = match head[1] {
            KIND_TENANT => Object::Tenant(tenant(id, rest)?),
            KIND_POOL => Object::Pool(pool(id, rest)?),
            KIND_DKIM => Object::Dkim(dkim(id, rest)?),
            _ => return None,
        };
        object.check().ok()?;
        Some(Self { version, object })
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn tenant(id: u32, rest: &[u8]) -> Option<Tenant> {
    let body = rest.get(..TENANT)?;
    if body[6..8] != [0, 0] || body[20..24] != [0; 4] {
        return None;
    }
    let count = usize::from(body[5]);
    let list = &rest[TENANT..];
    if list.len() != count * 4 {
        return None;
    }
    let pools = (0..count)
        .map(|i| u32_at(list, i * 4))
        .collect::<Option<_>>()?;
    Some(Tenant {
        id,
        generation: u32_at(body, 0)?,
        state: State::from_code(body[4])?,
        default_pool: u32_at(body, 8)?,
        pools,
        limits: Limits {
            rate: u32_at(body, 12)?,
            burst: u32_at(body, 16)?,
            queued: u64::from_le_bytes(body[24..32].try_into().ok()?),
        },
    })
}

fn pool(id: u32, rest: &[u8]) -> Option<Pool> {
    let head = rest.get(..POOL)?;
    if head[2..4] != [0, 0] {
        return None;
    }
    let count = usize::from(u16::from_le_bytes(head[0..2].try_into().ok()?));
    let list = &rest[POOL..];
    if list.len() != count * ADDRESS {
        return None;
    }
    let addresses = list
        .as_chunks::<ADDRESS>()
        .0
        .iter()
        .map(|entry| {
            if entry[18..] != [0, 0] {
                return None;
            }
            let octets: [u8; 16] = entry[..16].try_into().ok()?;
            let weight = u16::from_le_bytes(entry[16..18].try_into().ok()?);
            Some((Ipv6Addr::from(octets).to_canonical(), weight))
        })
        .collect::<Option<_>>()?;
    Some(Pool { id, addresses })
}

fn dkim(id: u32, rest: &[u8]) -> Option<Dkim> {
    let body = rest.get(..DKIM)?;
    if body[7] != 0 {
        return None;
    }
    let lengths = [
        usize::from(body[5]),
        usize::from(body[6]),
        usize::from(u16::from_le_bytes(body[8..10].try_into().ok()?)),
        usize::from(u16::from_le_bytes(body[10..12].try_into().ok()?)),
    ];
    let mut list = &rest[DKIM..];
    if list.len() != lengths.iter().sum::<usize>() {
        return None;
    }
    let [domain, selector, public, blob] = lengths.map(|length| {
        let (part, next) = list.split_at(length);
        list = next;
        part
    });
    Some(Dkim {
        id,
        tenant: u32_at(body, 12)?,
        generation: u32_at(body, 0)?,
        alg: DkimAlg::from_code(body[4])?,
        domain: str::from_utf8(domain).ok()?.into(),
        selector: str::from_utf8(selector).ok()?.into(),
        public: public.to_vec(),
        blob: blob.to_vec(),
    })
}
