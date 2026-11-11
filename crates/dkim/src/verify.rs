use crypto::DkimAlg;

use crate::tags::{Tags, names};
use crate::{Error, Field, base64, digest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub alg: DkimAlg,
    pub domain: String,
    pub selector: String,
    pub time: Option<u64>,
    pub expiry: Option<u64>,
    pub digest: [u8; 32],
    pub signature: Vec<u8>,
}

pub fn check(fields: &[Field], at: usize, body: &[u8; 32]) -> Result<Check, Error> {
    let field = fields.get(at).ok_or(Error::Missing("field"))?;
    let tags = Tags::parse(field)?;
    if tags.require("v")? != b"1" {
        return Err(Error::Version);
    }
    let alg = match tags.require("a")? {
        b"rsa-sha256" => DkimAlg::RsaSha256,
        b"ed25519-sha256" => DkimAlg::Ed25519Sha256,
        _ => return Err(Error::Algorithm),
    };
    if tags.get("l").is_some() {
        return Err(Error::Length);
    }
    if base64::decode(tags.require("bh")?).ok_or(Error::Base64)? != body {
        return Err(Error::BodyHash);
    }
    if !names(tags.require("h")?).any(|name| name.eq_ignore_ascii_case(b"from")) {
        return Err(Error::From);
    }
    let signature = base64::decode(tags.require("b")?).ok_or(Error::Base64)?;
    if signature.is_empty() {
        return Err(Error::Unsigned);
    }
    let text = |name: &'static str, error: Error| {
        tags.require(name)
            .and_then(|value| String::from_utf8(value.to_vec()).map_err(|_| error))
    };
    let number = |name: &str| {
        tags.get(name)
            .map(|value| {
                std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or(Error::Tag)
            })
            .transpose()
    };
    let time = number("t")?;
    let expiry = number("x")?;
    if let (Some(time), Some(expiry)) = (time, expiry)
        && expiry <= time
    {
        return Err(Error::Expiry);
    }
    Ok(Check {
        alg,
        domain: text("d", Error::Domain)?,
        selector: text("s", Error::Selector)?,
        time,
        expiry,
        digest: digest(fields, at)?,
        signature,
    })
}
