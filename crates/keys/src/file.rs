use crypto::{ChunkKey, Plain, Prk, Secret, TAG};

use crate::Error;

pub const MASTER: usize = 64;
pub const HEADER: usize = 64;
const MASTER_MAGIC: [u8; 4] = *b"bkm1";
const SLOT_MAGIC: [u8; 4] = *b"bks1";

pub struct Master {
    pub id: u64,
    pub key: Secret<32>,
}

impl Master {
    pub fn generate(id: u64) -> Result<Self, Error> {
        Ok(Self {
            id,
            key: Secret::random()?,
        })
    }

    pub fn encode(&self) -> Plain {
        let mut out = Plain::new(vec![0; MASTER]);
        out[..4].copy_from_slice(&MASTER_MAGIC);
        out[4..12].copy_from_slice(&self.id.to_le_bytes());
        out[12..44].copy_from_slice(self.key.expose());
        let crc = sys::crc32c::checksum(&out[..60]);
        out[60..].copy_from_slice(&crc.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MASTER || bytes[..4] != MASTER_MAGIC {
            return None;
        }
        let crc = u32::from_le_bytes(bytes[60..64].try_into().ok()?);
        if sys::crc32c::checksum(&bytes[..60]) != crc {
            return None;
        }
        let id = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        if id == 0 {
            return None;
        }
        Some(Self {
            id,
            key: Secret::from_slice(&bytes[12..44]).ok()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub sequence: u64,
    pub master: u64,
    pub salt: [u8; 32],
    pub length: u32,
}

impl Header {
    fn encode(&self) -> [u8; HEADER] {
        let mut out = [0; HEADER];
        out[..4].copy_from_slice(&SLOT_MAGIC);
        out[4..12].copy_from_slice(&self.sequence.to_le_bytes());
        out[12..20].copy_from_slice(&self.master.to_le_bytes());
        out[20..52].copy_from_slice(&self.salt);
        out[52..56].copy_from_slice(&self.length.to_le_bytes());
        let crc = sys::crc32c::checksum(&out[..60]);
        out[60..].copy_from_slice(&crc.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER || bytes[..4] != SLOT_MAGIC || bytes[56..60] != [0; 4] {
            return None;
        }
        let crc = u32::from_le_bytes(bytes[60..64].try_into().ok()?);
        if sys::crc32c::checksum(&bytes[..60]) != crc {
            return None;
        }
        Some(Self {
            sequence: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
            master: u64::from_le_bytes(bytes[12..20].try_into().ok()?),
            salt: bytes[20..52].try_into().ok()?,
            length: u32::from_le_bytes(bytes[52..56].try_into().ok()?),
        })
    }
}

fn slot_key(master: &Master, salt: &[u8; 32], sequence: u64) -> ChunkKey {
    ChunkKey::new(&Prk::from_secret(&master.key).expand::<32>(&[
        b"keyfile",
        salt,
        &sequence.to_le_bytes(),
    ]))
}

pub fn seal(master: &Master, sequence: u64, body: &[u8]) -> Result<Vec<u8>, Error> {
    let salt = Secret::<32>::random()?;
    let header = Header {
        sequence,
        master: master.id,
        salt: *salt.expose(),
        length: u32::try_from(body.len() + TAG).map_err(|_| Error::Corrupt("size"))?,
    }
    .encode();
    let sealed = slot_key(master, salt.expose(), sequence).seal_one(&header, body);
    let mut out = Vec::with_capacity(HEADER + sealed.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn open(master: &Master, bytes: &[u8]) -> Result<Plain, Error> {
    let header = Header::decode(bytes).ok_or(Error::Corrupt("header"))?;
    if header.master != master.id {
        return Err(Error::Corrupt("master"));
    }
    let end = HEADER + header.length as usize;
    if bytes.len() < end {
        return Err(Error::Corrupt("length"));
    }
    let clear = slot_key(master, &header.salt, header.sequence)
        .open_one(&bytes[..HEADER], &bytes[HEADER..end])
        .map_err(|_| Error::Corrupt("body"))?;
    Ok(Plain::new(clear))
}

pub fn sealed_len(bytes: &[u8]) -> Option<usize> {
    Header::decode(bytes).map(|header| HEADER + header.length as usize)
}

#[cfg(test)]
mod tests {
    use super::{HEADER, Header, MASTER, Master, open, seal};
    use crate::Error;

    #[test]
    fn master_round_trip_and_damage() {
        let master = Master::generate(7).expect("master");
        let bytes = master.encode();
        let back = Master::decode(&bytes).expect("decodes");
        assert_eq!(back.id, 7);
        assert!(back.key == master.key);
        for i in 0..MASTER {
            let mut bad = bytes.to_vec();
            bad[i] ^= 1;
            assert!(Master::decode(&bad).is_none(), "byte {i}");
        }
        assert!(Master::decode(&[0; MASTER]).is_none());
    }

    #[test]
    fn slot_round_trip_binds_master_and_header() {
        let master = Master::generate(3).expect("master");
        let bytes = seal(&master, 9, b"state").expect("seals");
        assert_eq!(&open(&master, &bytes).expect("opens")[..], b"state");
        let header = Header::decode(&bytes).expect("header");
        assert_eq!((header.sequence, header.master), (9, 3));
        let other = Master::generate(3).expect("master");
        assert_eq!(open(&other, &bytes).err(), Some(Error::Corrupt("body")));
        let wrong = Master::generate(4).expect("master");
        assert_eq!(open(&wrong, &bytes).err(), Some(Error::Corrupt("master")));
        for i in HEADER..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(open(&master, &bad).is_err(), "byte {i}");
        }
        assert_eq!(
            open(&master, &bytes[..bytes.len() - 1]).err(),
            Some(Error::Corrupt("length"))
        );
    }

    #[test]
    fn every_seal_draws_a_new_salt() {
        let master = Master::generate(3).expect("master");
        let a = seal(&master, 9, b"state").expect("seals");
        let b = seal(&master, 9, b"state").expect("seals");
        assert_ne!(
            Header::decode(&a).expect("a").salt,
            Header::decode(&b).expect("b").salt
        );
        assert_ne!(a[HEADER..], b[HEADER..]);
    }
}
