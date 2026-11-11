use crypto::{Plain, Secret, sha256};

use crate::error::Error;

pub const TOKEN: usize = 51;

const PREFIX: &[u8; 3] = b"bz_";
const RAW: usize = 36;
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Smtp,
    Api,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scopes {
    pub smtp: bool,
    pub api: bool,
}

impl Scopes {
    pub fn has(self, scope: Scope) -> bool {
        match scope {
            Scope::Smtp => self.smtp,
            Scope::Api => self.api,
        }
    }

    pub(crate) fn code(self) -> u8 {
        u8::from(self.smtp) | u8::from(self.api) << 1
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        (code & !3 == 0).then_some(Self {
            smtp: code & 1 != 0,
            api: code & 2 != 0,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub access: u32,
    pub tenant: u32,
    pub generation: u32,
    pub pool: u32,
}

pub struct Token {
    id: u32,
    secret: Secret<32>,
}

impl Token {
    pub fn new(id: u32) -> Result<Self, Error> {
        let secret = Secret::random().map_err(|_| Error::Invalid("random"))?;
        Ok(Self { id, secret })
    }

    pub fn parse(text: &[u8]) -> Option<Self> {
        let body = text.strip_prefix(PREFIX).filter(|b| b.len() == TOKEN - 3)?;
        let mut raw = Plain::with_capacity(RAW);
        for quad in body.as_chunks::<4>().0 {
            let mut n = 0_u32;
            for &c in quad {
                let value = ALPHABET.iter().position(|&a| a == c)?;
                n = n << 6 | u32::try_from(value).ok()?;
            }
            raw.extend_from_slice(&n.to_be_bytes()[1..]);
        }
        let id = u32::from_le_bytes(raw[..4].try_into().ok()?);
        let secret = Secret::from_slice(&raw[4..]).ok()?;
        Some(Self { id, secret })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256(self.secret.expose())
    }

    pub fn text(&self) -> Plain {
        let mut raw = Plain::with_capacity(RAW);
        raw.extend_from_slice(&self.id.to_le_bytes());
        raw.extend_from_slice(self.secret.expose());
        let mut out = Plain::with_capacity(TOKEN);
        out.extend_from_slice(PREFIX);
        for triple in raw.as_chunks::<3>().0 {
            let n = u32::from_be_bytes([0, triple[0], triple[1], triple[2]]);
            for shift in [18, 12, 6, 0] {
                out.push(ALPHABET[(n >> shift) as usize & 63]);
            }
        }
        out
    }
}
