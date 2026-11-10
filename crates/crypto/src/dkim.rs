use aws_lc_rs::digest::{Digest, SHA256};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

use crate::{DataKey, Error, Plain};

pub const DKIM_LABEL: usize = 13;
const RSA_MIN: usize = 256;
const RSA_MAX: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DkimAlg {
    RsaSha256,
    Ed25519Sha256,
}

impl DkimAlg {
    pub fn code(self) -> u8 {
        match self {
            Self::RsaSha256 => 1,
            Self::Ed25519Sha256 => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::RsaSha256),
            2 => Some(Self::Ed25519Sha256),
            _ => None,
        }
    }
}

pub fn dkim_label(tenant: u32, generation: u32, key: u32, alg: DkimAlg) -> [u8; DKIM_LABEL] {
    let mut label = [0; DKIM_LABEL];
    label[..4].copy_from_slice(&tenant.to_le_bytes());
    label[4..8].copy_from_slice(&generation.to_le_bytes());
    label[8..12].copy_from_slice(&key.to_le_bytes());
    label[12] = alg.code();
    label
}

enum Pair {
    Rsa(RsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

pub struct DkimKey {
    alg: DkimAlg,
    pair: Pair,
    pkcs8: Plain,
}

impl DkimKey {
    pub fn generate(alg: DkimAlg) -> Result<Self, Error> {
        let pkcs8 = match alg {
            DkimAlg::RsaSha256 => {
                let pair = RsaKeyPair::generate(KeySize::Rsa2048).map_err(|_| Error::Random)?;
                let der: Pkcs8V1Der<'static> = pair.as_der().map_err(|_| Error::Key)?;
                Plain::new(der.as_ref().to_vec())
            }
            DkimAlg::Ed25519Sha256 => {
                let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map_err(|_| Error::Random)?;
                Plain::new(document.as_ref().to_vec())
            }
        };
        Self::from_pkcs8(alg, pkcs8)
    }

    pub fn from_pkcs8(alg: DkimAlg, pkcs8: Plain) -> Result<Self, Error> {
        let pair = match alg {
            DkimAlg::RsaSha256 => {
                let pair = RsaKeyPair::from_pkcs8(&pkcs8).map_err(|_| Error::Key)?;
                if !(RSA_MIN..=RSA_MAX).contains(&pair.public_modulus_len()) {
                    return Err(Error::Key);
                }
                Pair::Rsa(pair)
            }
            DkimAlg::Ed25519Sha256 => {
                Pair::Ed25519(Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| Error::Key)?)
            }
        };
        Ok(Self { alg, pair, pkcs8 })
    }

    pub fn open(
        alg: DkimAlg,
        key: &DataKey,
        label: &[u8; DKIM_LABEL],
        blob: &[u8],
    ) -> Result<Self, Error> {
        if label[12] != alg.code() {
            return Err(Error::Label);
        }
        Self::from_pkcs8(alg, key.open_plain(label, blob)?)
    }

    pub fn seal(&self, key: &DataKey, label: &[u8; DKIM_LABEL]) -> Result<Vec<u8>, Error> {
        if label[12] != self.alg.code() {
            return Err(Error::Label);
        }
        key.seal(label, &self.pkcs8)
    }

    pub fn alg(&self) -> DkimAlg {
        self.alg
    }

    pub fn public(&self) -> Result<Vec<u8>, Error> {
        match &self.pair {
            Pair::Rsa(pair) => {
                let der: PublicKeyX509Der<'static> =
                    pair.public_key().as_der().map_err(|_| Error::Key)?;
                Ok(der.as_ref().to_vec())
            }
            Pair::Ed25519(pair) => Ok(pair.public_key().as_ref().to_vec()),
        }
    }

    pub fn sign(&self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
        match &self.pair {
            Pair::Rsa(pair) => {
                let digest = Digest::import_less_safe(digest, &SHA256).map_err(|_| Error::Key)?;
                let mut out = vec![0; pair.public_modulus_len()];
                pair.sign_digest(&RSA_PKCS1_SHA256, &digest, &mut out)
                    .map_err(|_| Error::Key)?;
                Ok(out)
            }
            Pair::Ed25519(pair) => Ok(pair.sign(digest).as_ref().to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::digest::digest;
    use aws_lc_rs::signature::{ED25519, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    use super::*;
    use crate::seal::tests::hex;
    use crate::{Secret, Tenant};

    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PKCS8_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn fixed_ed25519() -> DkimKey {
        let mut pkcs8 = PKCS8_PREFIX.to_vec();
        pkcs8.extend_from_slice(&unhex(SEED));
        DkimKey::from_pkcs8(DkimAlg::Ed25519Sha256, Plain::new(pkcs8)).expect("pkcs8")
    }

    fn sha256(message: &[u8]) -> [u8; 32] {
        digest(&SHA256, message)
            .as_ref()
            .try_into()
            .expect("32 bytes")
    }

    #[test]
    fn label_layout_is_fixed() {
        assert_eq!(
            hex(&dkim_label(7, 2, 0x0102_0304, DkimAlg::Ed25519Sha256)),
            "07000000020000000403020102"
        );
        assert_eq!(DkimAlg::from_code(1), Some(DkimAlg::RsaSha256));
        assert_eq!(DkimAlg::from_code(3), None);
    }

    #[test]
    fn ed25519_signs_the_hash_bytes_and_matches_the_known_key() {
        let key = fixed_ed25519();
        assert_eq!(
            hex(&key.public().expect("public")),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let hash = sha256(b"header data");
        let signature = key.sign(&hash).expect("sign");
        UnparsedPublicKey::new(&ED25519, key.public().expect("public"))
            .verify(&hash, &signature)
            .expect("verify");
        assert_eq!(key.sign(&hash).expect("sign"), signature);
    }

    #[test]
    fn rsa_signs_a_digest_that_verifies_over_the_message() {
        let key = DkimKey::generate(DkimAlg::RsaSha256).expect("generate");
        let message = b"from:a@example.org\r\nsubject:hi\r\n";
        let signature = key.sign(&sha256(message)).expect("sign");
        assert_eq!(signature.len(), 256);
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public().expect("public"))
            .verify(message, &signature)
            .expect("verify");
        let copy =
            DkimKey::from_pkcs8(DkimAlg::RsaSha256, Plain::new(key.pkcs8.to_vec())).expect("pkcs8");
        assert_eq!(
            copy.public().expect("public"),
            key.public().expect("public")
        );
        assert!(
            DkimKey::from_pkcs8(DkimAlg::Ed25519Sha256, Plain::new(key.pkcs8.to_vec())).is_err()
        );
    }

    #[test]
    fn blobs_open_only_under_their_label_alg_and_generation() {
        let root = Tenant::new(&Secret::new([5; 32]));
        let seal = root.dkim_key(1, 1);
        let key = fixed_ed25519();
        let label = dkim_label(3, 1, 9, DkimAlg::Ed25519Sha256);
        let blob = key.seal(&seal, &label).expect("seal");
        let opened = DkimKey::open(DkimAlg::Ed25519Sha256, &seal, &label, &blob).expect("open");
        assert_eq!(
            opened.public().expect("public"),
            key.public().expect("public")
        );
        let other_id = dkim_label(3, 1, 10, DkimAlg::Ed25519Sha256);
        assert!(DkimKey::open(DkimAlg::Ed25519Sha256, &seal, &other_id, &blob).is_err());
        let other_tenant = dkim_label(4, 1, 9, DkimAlg::Ed25519Sha256);
        assert!(DkimKey::open(DkimAlg::Ed25519Sha256, &seal, &other_tenant, &blob).is_err());
        let rsa_label = dkim_label(3, 1, 9, DkimAlg::RsaSha256);
        assert!(DkimKey::open(DkimAlg::RsaSha256, &seal, &rsa_label, &blob).is_err());
        assert_eq!(
            DkimKey::open(DkimAlg::RsaSha256, &seal, &label, &blob).err(),
            Some(Error::Label)
        );
        assert!(
            DkimKey::open(DkimAlg::Ed25519Sha256, &root.dkim_key(2, 1), &label, &blob).is_err()
        );
        assert!(key.seal(&seal, &rsa_label).is_err());
    }
}
