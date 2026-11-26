use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 64 * 1024;

const LEN: usize = 4;
const STATUS: u8 = 1;
const TENANT_CREATE: u8 = 2;
const TENANT_LIST: u8 = 3;
const TENANT_SUSPEND: u8 = 4;
const TENANT_RESUME: u8 = 5;
const POOL_SET: u8 = 6;
const POOL_LIST: u8 = 7;
const QUEUE_LIST: u8 = 8;
const QUEUE_RETRY: u8 = 9;
const QUEUE_REBIND: u8 = 10;
const KEY_CREATE: u8 = 11;
const KEY_REVOKE: u8 = 12;
const KEY_LIST: u8 = 13;
const SITE_LIST: u8 = 14;
const SITE_PAUSE: u8 = 15;
const SITE_RESUME: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Frame,
    Version,
    Command,
    Body,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Frame => "frame too large or empty",
            Self::Version => "unknown protocol version",
            Self::Command => "unknown command",
            Self::Body => "malformed request",
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantSpec {
    pub id: u32,
    pub pools: Vec<u32>,
    pub rate: u32,
    pub burst: u32,
    pub connections: u32,
    pub queued: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolSpec {
    pub id: u32,
    pub addresses: Vec<(IpAddr, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Status,
    TenantCreate(TenantSpec),
    TenantList(u32),
    TenantSuspend(u32),
    TenantResume(u32),
    PoolSet(PoolSpec),
    PoolList(u32),
    QueueList {
        tenant: u32,
        from: u32,
    },
    QueueRetry {
        tenant: u32,
        queue: u32,
    },
    QueueRebind {
        tenant: u32,
        queue: u32,
        pool: u32,
    },
    KeyCreate {
        tenant: u32,
        smtp: bool,
        api: bool,
        hooks: bool,
        pool: u32,
    },
    KeyRevoke {
        tenant: u32,
        id: u32,
    },
    KeyList {
        tenant: u32,
        from: u32,
    },
    SiteList {
        from: Option<(String, IpAddr)>,
    },
    SitePause {
        egress: IpAddr,
        site: String,
    },
    SiteResume {
        egress: IpAddr,
        site: String,
    },
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = vec![VERSION];
        match self {
            Self::Status => body.push(STATUS),
            Self::TenantCreate(spec) => {
                body.push(TENANT_CREATE);
                body.extend_from_slice(&spec.id.to_be_bytes());
                body.extend_from_slice(&spec.rate.to_be_bytes());
                body.extend_from_slice(&spec.burst.to_be_bytes());
                body.extend_from_slice(&spec.connections.to_be_bytes());
                body.extend_from_slice(&spec.queued.to_be_bytes());
                body.push(u8::try_from(spec.pools.len()).expect("at most 255 pools"));
                for pool in &spec.pools {
                    body.extend_from_slice(&pool.to_be_bytes());
                }
            }
            Self::TenantList(from) => {
                body.push(TENANT_LIST);
                body.extend_from_slice(&from.to_be_bytes());
            }
            Self::TenantSuspend(id) => {
                body.push(TENANT_SUSPEND);
                body.extend_from_slice(&id.to_be_bytes());
            }
            Self::TenantResume(id) => {
                body.push(TENANT_RESUME);
                body.extend_from_slice(&id.to_be_bytes());
            }
            Self::PoolSet(spec) => {
                body.push(POOL_SET);
                body.extend_from_slice(&spec.id.to_be_bytes());
                body.push(u8::try_from(spec.addresses.len()).expect("at most 255 addresses"));
                for (ip, weight) in &spec.addresses {
                    push_ip(&mut body, ip);
                    body.extend_from_slice(&weight.to_be_bytes());
                }
            }
            Self::PoolList(from) => {
                body.push(POOL_LIST);
                body.extend_from_slice(&from.to_be_bytes());
            }
            Self::QueueList { tenant, from } => {
                body.push(QUEUE_LIST);
                body.extend_from_slice(&tenant.to_be_bytes());
                body.extend_from_slice(&from.to_be_bytes());
            }
            Self::QueueRetry { tenant, queue } => {
                body.push(QUEUE_RETRY);
                body.extend_from_slice(&tenant.to_be_bytes());
                body.extend_from_slice(&queue.to_be_bytes());
            }
            Self::QueueRebind {
                tenant,
                queue,
                pool,
            } => {
                body.push(QUEUE_REBIND);
                body.extend_from_slice(&tenant.to_be_bytes());
                body.extend_from_slice(&queue.to_be_bytes());
                body.extend_from_slice(&pool.to_be_bytes());
            }
            Self::KeyCreate {
                tenant,
                smtp,
                api,
                hooks,
                pool,
            } => {
                body.push(KEY_CREATE);
                body.extend_from_slice(&tenant.to_be_bytes());
                body.push(u8::from(*smtp) | u8::from(*api) << 1 | u8::from(*hooks) << 2);
                body.extend_from_slice(&pool.to_be_bytes());
            }
            Self::KeyRevoke { tenant, id } => {
                body.push(KEY_REVOKE);
                body.extend_from_slice(&tenant.to_be_bytes());
                body.extend_from_slice(&id.to_be_bytes());
            }
            Self::KeyList { tenant, from } => {
                body.push(KEY_LIST);
                body.extend_from_slice(&tenant.to_be_bytes());
                body.extend_from_slice(&from.to_be_bytes());
            }
            Self::SiteList { from } => {
                body.push(SITE_LIST);
                match from {
                    None => body.push(0),
                    Some((site, ip)) => {
                        body.push(1);
                        push_site(&mut body, site);
                        push_ip(&mut body, ip);
                    }
                }
            }
            Self::SitePause { egress, site } => encode_site(&mut body, SITE_PAUSE, egress, site),
            Self::SiteResume { egress, site } => encode_site(&mut body, SITE_RESUME, egress, site),
        }
        framed(&body)
    }

    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let (version, op, rest) = head(body)?;
        if version != VERSION {
            return Err(Error::Version);
        }
        let mut fields = Fields(rest);
        let request = match op {
            STATUS => Self::Status,
            TENANT_CREATE => {
                let id = fields.u32()?;
                let rate = fields.u32()?;
                let burst = fields.u32()?;
                let connections = fields.u32()?;
                let queued = fields.u64()?;
                let count = fields.u8()?;
                let pools = (0..count).map(|_| fields.u32()).collect::<Result<_, _>>()?;
                Self::TenantCreate(TenantSpec {
                    id,
                    pools,
                    rate,
                    burst,
                    connections,
                    queued,
                })
            }
            TENANT_LIST => Self::TenantList(fields.u32()?),
            TENANT_SUSPEND => Self::TenantSuspend(fields.u32()?),
            TENANT_RESUME => Self::TenantResume(fields.u32()?),
            POOL_SET => {
                let id = fields.u32()?;
                let count = fields.u8()?;
                let addresses = (0..count)
                    .map(|_| Ok((fields.ip()?, fields.u16()?)))
                    .collect::<Result<_, _>>()?;
                Self::PoolSet(PoolSpec { id, addresses })
            }
            POOL_LIST => Self::PoolList(fields.u32()?),
            QUEUE_LIST => Self::QueueList {
                tenant: fields.u32()?,
                from: fields.u32()?,
            },
            QUEUE_RETRY => Self::QueueRetry {
                tenant: fields.u32()?,
                queue: fields.u32()?,
            },
            QUEUE_REBIND => Self::QueueRebind {
                tenant: fields.u32()?,
                queue: fields.u32()?,
                pool: fields.u32()?,
            },
            KEY_CREATE => {
                let tenant = fields.u32()?;
                let scopes = fields.u8()?;
                if scopes & !7 != 0 {
                    return Err(Error::Body);
                }
                Self::KeyCreate {
                    tenant,
                    smtp: scopes & 1 != 0,
                    api: scopes & 2 != 0,
                    hooks: scopes & 4 != 0,
                    pool: fields.u32()?,
                }
            }
            KEY_REVOKE => Self::KeyRevoke {
                tenant: fields.u32()?,
                id: fields.u32()?,
            },
            KEY_LIST => Self::KeyList {
                tenant: fields.u32()?,
                from: fields.u32()?,
            },
            SITE_LIST => {
                let from = match fields.u8()? {
                    0 => None,
                    1 => Some((fields.site()?, fields.ip()?)),
                    _ => return Err(Error::Body),
                };
                Self::SiteList { from }
            }
            SITE_PAUSE => Self::SitePause {
                egress: fields.ip()?,
                site: fields.site()?,
            },
            SITE_RESUME => Self::SiteResume {
                egress: fields.ip()?,
                site: fields.site()?,
            },
            _ => return Err(Error::Command),
        };
        if !fields.0.is_empty() {
            return Err(Error::Body);
        }
        Ok(request)
    }
}

struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (first, rest) = self.0.split_first_chunk::<N>().ok_or(Error::Body)?;
        self.0 = rest;
        Ok(*first)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn ip(&mut self) -> Result<IpAddr, Error> {
        match self.u8()? {
            4 => Ok(IpAddr::V4(Ipv4Addr::from(self.take::<4>()?))),
            6 => Ok(IpAddr::V6(Ipv6Addr::from(self.take::<16>()?))),
            _ => Err(Error::Body),
        }
    }

    fn site(&mut self) -> Result<String, Error> {
        let len = usize::from(self.u8()?);
        if len == 0 || self.0.len() < len {
            return Err(Error::Body);
        }
        let (bytes, rest) = self.0.split_at(len);
        let site = std::str::from_utf8(bytes).map_err(|_| Error::Body)?;
        self.0 = rest;
        Ok(site.to_owned())
    }
}

fn push_ip(body: &mut Vec<u8>, ip: &IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            body.push(4);
            body.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            body.push(6);
            body.extend_from_slice(&v6.octets());
        }
    }
}

fn push_site(body: &mut Vec<u8>, site: &str) {
    body.push(u8::try_from(site.len()).expect("site fits in a byte"));
    body.extend_from_slice(site.as_bytes());
}

fn encode_site(body: &mut Vec<u8>, command: u8, egress: &IpAddr, site: &str) {
    body.push(command);
    push_ip(body, egress);
    push_site(body, site);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Ok,
    Refused,
    NotFound,
    Busy,
    Failed,
}

impl Code {
    fn byte(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Refused => 1,
            Self::NotFound => 2,
            Self::Busy => 3,
            Self::Failed => 4,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Ok,
            1 => Self::Refused,
            2 => Self::NotFound,
            3 => Self::Busy,
            4 => Self::Failed,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: Code,
    pub text: String,
}

impl Reply {
    pub fn new(code: Code, text: impl Into<String>) -> Self {
        Self {
            code,
            text: text.into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let room = MAX_FRAME - 2;
        let mut end = self.text.len().min(room);
        while !self.text.is_char_boundary(end) {
            end -= 1;
        }
        let mut body = Vec::with_capacity(2 + end);
        body.extend_from_slice(&[VERSION, self.code.byte()]);
        body.extend_from_slice(&self.text.as_bytes()[..end]);
        framed(&body)
    }

    pub fn decode(body: &[u8]) -> Result<Self, Error> {
        let (version, code, rest) = head(body)?;
        if version != VERSION {
            return Err(Error::Version);
        }
        let code = Code::from_byte(code).ok_or(Error::Body)?;
        let text = std::str::from_utf8(rest).map_err(|_| Error::Body)?;
        Ok(Self::new(code, text))
    }
}

fn head(body: &[u8]) -> Result<(u8, u8, &[u8]), Error> {
    match body {
        [version, op, rest @ ..] => Ok((*version, *op, rest)),
        _ => Err(Error::Body),
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).expect("frame fits");
    let mut out = Vec::with_capacity(LEN + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[derive(Default)]
pub struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn pop(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let Some(len) = self.buf.first_chunk::<LEN>() else {
            return Ok(None);
        };
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| Error::Frame)?;
        if len == 0 || len > MAX_FRAME {
            return Err(Error::Frame);
        }
        if self.buf.len() < LEN + len {
            return Ok(None);
        }
        let body = self.buf[LEN..LEN + len].to_vec();
        self.buf.drain(..LEN + len);
        Ok(Some(body))
    }
}
