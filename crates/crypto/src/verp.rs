use crate::ids::ALPHABET;
use crate::{Secret, TenantKeys, hmac_sha256};

pub const ANY: u32 = u32::MAX;
pub const TOKEN_TEXT: usize = 55;

const MAC: usize = 10;
const BYTES: usize = 24 + MAC;

#[derive(Clone, Debug)]
pub struct Token {
    pub tenant: u32,
    pub recipient: u32,
    pub id: [u8; 16],
    mac: [u8; MAC],
}

impl Token {
    pub fn sign(keys: &TenantKeys, recipient: u32, id: [u8; 16]) -> Self {
        let tenant = keys.tenant();
        Self {
            tenant,
            recipient,
            id,
            mac: mac(keys.return_key(), tenant, recipient, &id),
        }
    }

    pub fn verify(&self, keys: &TenantKeys) -> bool {
        let expected = mac(keys.return_key(), self.tenant, self.recipient, &self.id);
        let same = Secret::new(self.mac) == Secret::new(expected);
        same & (keys.tenant() == self.tenant)
    }

    pub fn text(&self) -> String {
        let mut bytes = [0; BYTES];
        bytes[..4].copy_from_slice(&self.tenant.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.recipient.to_be_bytes());
        bytes[8..24].copy_from_slice(&self.id);
        bytes[24..].copy_from_slice(&self.mac);
        let mut out = String::with_capacity(TOKEN_TEXT);
        for i in 0..TOKEN_TEXT {
            out.push(char::from(ALPHABET[usize::from(five(&bytes, i * 5))]));
        }
        out
    }

    pub fn parse(text: &[u8]) -> Option<Self> {
        if text.len() != TOKEN_TEXT {
            return None;
        }
        let mut bytes = [0_u8; BYTES + 1];
        for (i, &c) in text.iter().enumerate() {
            let c = c.to_ascii_lowercase();
            let value = ALPHABET.iter().position(|&a| a == c)?;
            let value = u16::try_from(value).ok()? << 11;
            let (byte, shift) = (i * 5 / 8, i * 5 % 8);
            let [high, low] = (value >> shift).to_be_bytes();
            bytes[byte] |= high;
            bytes[byte + 1] |= low;
        }
        if bytes[BYTES] != 0 {
            return None;
        }
        Some(Self {
            tenant: u32::from_be_bytes(bytes[..4].try_into().ok()?),
            recipient: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
            id: bytes[8..24].try_into().ok()?,
            mac: bytes[24..BYTES].try_into().ok()?,
        })
    }
}

fn five(bytes: &[u8; BYTES], bit: usize) -> u8 {
    let (byte, shift) = (bit / 8, bit % 8);
    let high = u16::from(bytes[byte]) << 8;
    let low = bytes.get(byte + 1).copied().map_or(0, u16::from);
    let [value, _] = ((high | low) << shift).to_be_bytes();
    value >> 3
}

fn mac(key: &Secret<16>, tenant: u32, recipient: u32, id: &[u8; 16]) -> [u8; MAC] {
    let full = hmac_sha256(
        key.expose(),
        &[b"verp", &tenant.to_be_bytes(), &recipient.to_be_bytes(), id],
    );
    let mut out = [0; MAC];
    out.copy_from_slice(&full[..MAC]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Tenant, TenantKeys};

    fn keys(tenant: u32, generation: u32, root: u8) -> TenantKeys {
        TenantKeys::derive(
            tenant,
            generation,
            &Tenant::new(&Secret::new([root; 32])),
            1,
        )
    }

    fn id() -> [u8; 16] {
        std::array::from_fn(|i| u8::try_from(i * 0x11).expect("small"))
    }

    #[test]
    fn token_matches_the_known_answer() {
        let keys = TenantKeys::new(
            7,
            1,
            &Secret::new([0; 32]),
            1,
            Secret::new([0; 16]),
            Secret::new([3; 16]),
        );
        let token = Token::sign(&keys, 2, id());
        assert_eq!(
            token.text(),
            "aaaaabyaaaaaeaareizuivlgo6ejtkv3zto657z4imxq2dk3n2ul37q"
        );
    }

    #[test]
    fn token_round_trips_and_decodes_any_case() {
        let keys = keys(9, 4, 1);
        for recipient in [0, 1, 999, ANY] {
            let token = Token::sign(&keys, recipient, id());
            let text = token.text();
            assert_eq!(
                Token::parse(text.as_bytes()).map(|t| t.text()),
                Some(text.clone())
            );
            let upper = text.to_ascii_uppercase();
            let parsed = Token::parse(upper.as_bytes()).expect("upper case");
            assert!(parsed.verify(&keys));
            assert_eq!(
                (parsed.tenant, parsed.recipient, parsed.id),
                (9, recipient, id())
            );
        }
    }

    #[test]
    fn parse_rejects_bad_length_letters_and_padding_bits() {
        let text = Token::sign(&keys(9, 4, 1), 0, id()).text();
        assert!(Token::parse(&text.as_bytes()[1..]).is_none());
        assert!(Token::parse(format!("{text}a").as_bytes()).is_none());
        let mut bad = text.clone().into_bytes();
        bad[3] = b'1';
        assert!(Token::parse(&bad).is_none());
        let last = ALPHABET
            .iter()
            .position(|&a| a == text.as_bytes()[TOKEN_TEXT - 1])
            .expect("alphabet");
        for bit in [1, 2, 4] {
            let mut padded = text.clone().into_bytes();
            padded[TOKEN_TEXT - 1] = ALPHABET[last | bit];
            assert!(Token::parse(&padded).is_none());
        }
    }

    #[test]
    fn verify_fails_for_another_tenant_generation_root_or_changed_field() {
        let keys = keys(9, 4, 1);
        let token = Token::sign(&keys, 3, id());
        assert!(token.verify(&keys));
        assert!(!token.verify(&self::keys(9, 5, 1)));
        assert!(!token.verify(&self::keys(9, 4, 2)));
        assert!(!token.verify(&self::keys(8, 4, 1)));
        let mut moved = token.clone();
        moved.tenant = 8;
        assert!(!moved.verify(&self::keys(8, 4, 1)));
        let mut other = token.clone();
        other.recipient = ANY;
        assert!(!other.verify(&keys));
        let mut changed = token.clone();
        changed.id[15] ^= 1;
        assert!(!changed.verify(&keys));
        let mut flipped = token;
        flipped.mac[0] ^= 1;
        assert!(!flipped.verify(&keys));
    }
}
