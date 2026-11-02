use crate::{ChunkKey, Error, Prk, Secret, TAG};

const FORMAT: u8 = 1;
const SALT: usize = 16;
const HEADER: usize = 2 + SALT;
pub const OVERHEAD: usize = HEADER + TAG;

pub struct DataKey {
    prk: Prk,
    version: u8,
}

impl DataKey {
    pub fn new(key: &Secret<32>, version: u8) -> Self {
        Self {
            prk: Prk::extract(b"bunzzle data v1", key.expose()),
            version,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn seal(&self, label: &[u8], clear: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.seal_salted(&Secret::<SALT>::random()?, label, clear))
    }

    pub(crate) fn seal_salted(&self, salt: &Secret<SALT>, label: &[u8], clear: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(OVERHEAD + clear.len());
        out.push(FORMAT);
        out.push(self.version);
        out.extend_from_slice(salt.expose());
        let mut body = clear.to_vec();
        self.key(salt.expose(), label)
            .seal(0, true, &aad(&out, label), &mut body);
        out.extend_from_slice(&body);
        out
    }

    pub fn open(&self, label: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
        if sealed.len() < OVERHEAD {
            return Err(Error::Format("length"));
        }
        if sealed[0] != FORMAT {
            return Err(Error::Format("format"));
        }
        if sealed[1] != self.version {
            return Err(Error::Format("key version"));
        }
        let (header, body) = sealed.split_at(HEADER);
        let mut body = body.to_vec();
        let len = self
            .key(&header[2..], label)
            .open(0, true, &aad(header, label), &mut body)?
            .len();
        body.truncate(len);
        Ok(body)
    }

    fn key(&self, salt: &[u8], label: &[u8]) -> ChunkKey {
        ChunkKey::new(&self.prk.expand::<32>(&[b"data", salt, label]))
    }
}

fn aad(header: &[u8], label: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + label.len());
    out.extend_from_slice(header);
    out.extend_from_slice(label);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{DataKey, OVERHEAD};
    use crate::{Error, Secret};

    pub(crate) fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn key() -> DataKey {
        DataKey::new(&Secret::new([3; 32]), 1)
    }

    #[test]
    fn round_trip_with_fresh_salt() {
        let a = key().seal(b"label", b"example.org").expect("seals");
        let b = key().seal(b"label", b"example.org").expect("seals");
        assert_eq!(a.len(), OVERHEAD + 11);
        assert_ne!(a, b);
        assert_eq!(key().open(b"label", &a).expect("opens"), b"example.org");
        assert_eq!(key().open(b"label", &b).expect("opens"), b"example.org");
    }

    #[test]
    fn label_key_and_version_are_bound() {
        let sealed = key().seal(b"label", b"x").expect("seals");
        assert_eq!(key().open(b"other", &sealed), Err(Error::Open));
        let other = DataKey::new(&Secret::new([4; 32]), 1);
        assert_eq!(other.open(b"label", &sealed), Err(Error::Open));
        let next = DataKey::new(&Secret::new([3; 32]), 2);
        assert_eq!(
            next.open(b"label", &sealed),
            Err(Error::Format("key version"))
        );
    }

    #[test]
    fn damage_is_refused() {
        let sealed = key().seal(b"label", b"payload").expect("seals");
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x10;
            assert!(key().open(b"label", &bad).is_err(), "byte {i}");
        }
        assert_eq!(
            key().open(b"label", &sealed[..OVERHEAD - 1]),
            Err(Error::Format("length"))
        );
        let mut bad = sealed.clone();
        bad[0] = 2;
        assert_eq!(key().open(b"label", &bad), Err(Error::Format("format")));
    }

    #[test]
    fn known_answer() {
        let sealed = key().seal_salted(&Secret::new([9; 16]), b"label", b"payload");
        assert_eq!(
            hex(&sealed),
            "010109090909090909090909090909090909b7e258daa39e15ab92d7ef6fd7e9532ad572f316de0b9a"
        );
    }
}
