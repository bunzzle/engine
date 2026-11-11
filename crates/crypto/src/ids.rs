use aws_lc_rs::cipher::{
    AES_128, DecryptingKey, DecryptionContext, EncryptingKey, UnboundCipherKey,
};

use crate::kdf::extract_into;
use crate::{Error, Prk, Secret};

pub const ID_TEXT: usize = 26;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn id_key(naming: &Secret<16>) -> Secret<16> {
    let mut prk = Secret::new([0; 32]);
    extract_into(b"bunzzle ids", &[naming.expose()], &mut prk);
    Prk::from_secret(&prk).expand(&[b"message id"])
}

pub struct Ids {
    encrypting: EncryptingKey,
    decrypting: DecryptingKey,
}

impl Ids {
    pub fn new(key: &Secret<16>) -> Result<Self, Error> {
        let unbound = || UnboundCipherKey::new(&AES_128, key.expose()).map_err(|_| Error::Key);
        Ok(Self {
            encrypting: EncryptingKey::ecb(unbound()?).map_err(|_| Error::Key)?,
            decrypting: DecryptingKey::ecb(unbound()?).map_err(|_| Error::Key)?,
        })
    }

    pub fn encode(&self, id: &[u8; 16]) -> String {
        let mut block = *id;
        self.encrypting.encrypt(&mut block).expect("one aes block");
        let n = u128::from_be_bytes(block);
        let last = (n << 2) as usize & 31;
        (0..ID_TEXT - 1)
            .map(|i| (n >> (123 - 5 * i)) as usize & 31)
            .chain([last])
            .map(|value| char::from(ALPHABET[value]))
            .collect()
    }

    pub fn decode(&self, text: &[u8]) -> Option<[u8; 16]> {
        if text.len() != ID_TEXT {
            return None;
        }
        let mut n = 0_u128;
        for (i, &c) in text.iter().enumerate() {
            let value = ALPHABET.iter().position(|&a| a == c)? as u128;
            n = if i < ID_TEXT - 1 {
                n << 5 | value
            } else if value.trailing_zeros() >= 2 {
                n << 3 | value >> 2
            } else {
                return None;
            };
        }
        let mut block = n.to_be_bytes();
        self.decrypting
            .decrypt(&mut block, DecryptionContext::None)
            .ok()?;
        Some(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::tests::hex;

    fn fips() -> Ids {
        let key: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).expect("small"));
        Ids::new(&Secret::new(key)).expect("ids")
    }

    #[test]
    fn ids_match_the_aes_and_base32_known_answers() {
        let ids = fips();
        let plain: [u8; 16] = std::array::from_fn(|i| u8::try_from(i * 0x11).expect("small"));
        assert_eq!(ids.encode(&plain), "nhcobwdkpmcdbwgnw6ahbngfli");
        assert_eq!(ids.decode(b"nhcobwdkpmcdbwgnw6ahbngfli"), Some(plain));
        assert_eq!(
            hex(id_key(&Secret::new([5; 16])).expose()),
            "1463924471d6bf581f8d2faadc50d075"
        );
    }

    #[test]
    fn ids_round_trip_and_decode_only_their_own_text() {
        let ids = fips();
        let other = Ids::new(&Secret::new([7; 16])).expect("ids");
        for id in [
            [0; 16],
            [0xff; 16],
            std::array::from_fn(|i| u8::try_from(i).expect("small")),
        ] {
            let text = ids.encode(&id);
            assert_eq!(text.len(), ID_TEXT);
            assert!(text.bytes().all(|c| ALPHABET.contains(&c)));
            assert!(text.ends_with(['a', 'e', 'i', 'm', 'q', 'u', 'y', '4']));
            assert_eq!(ids.decode(text.as_bytes()), Some(id));
            assert_ne!(other.encode(&id), text);
            assert_ne!(other.decode(text.as_bytes()), Some(id));
        }
        let text = ids.encode(&[3; 16]).into_bytes();
        for (at, c) in [
            (0, b'A'),
            (5, b'0'),
            (9, b'1'),
            (12, b'8'),
            (20, b'='),
            (25, b'b'),
            (25, b'7'),
        ] {
            let mut bad = text.clone();
            bad[at] = c;
            assert_eq!(ids.decode(&bad), None, "{at} {}", char::from(c));
        }
        assert_eq!(ids.decode(&text[..ID_TEXT - 1]), None);
        assert_eq!(ids.decode(&[&text[..], b"a"].concat()), None);
        assert_eq!(ids.decode(b""), None);
    }
}
