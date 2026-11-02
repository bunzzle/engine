use aws_lc_rs::hkdf::{self, HKDF_SHA256, KeyType, Salt};
use aws_lc_rs::hmac;

use crate::Secret;

pub struct Prk(hkdf::Prk);

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

impl Prk {
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        Self(Salt::new(HKDF_SHA256, salt).extract(ikm))
    }

    pub fn from_secret(prk: &Secret<32>) -> Self {
        Self(hkdf::Prk::new_less_safe(HKDF_SHA256, prk.expose()))
    }

    pub fn expand<const N: usize>(&self, info: &[&[u8]]) -> Secret<N> {
        let mut out = Secret::new([0; N]);
        self.0
            .expand(info, Len(N))
            .expect("output within the HKDF limit")
            .fill(out.expose_mut())
            .expect("output within the HKDF limit");
        out
    }
}

pub(crate) fn extract_into(salt: &[u8], ikm: &[&[u8]], out: &mut Secret<32>) {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&key);
    for part in ikm {
        ctx.update(part);
    }
    out.expose_mut().copy_from_slice(ctx.sign().as_ref());
}

#[cfg(test)]
pub(crate) fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Prk, extract_into, hex};
    use crate::Secret;

    fn check(ikm: &str, salt: &str, info: &str, prk: &str, okm: &str) {
        let (ikm, salt, info) = (hex(ikm), hex(salt), hex(info));
        let mut out = Secret::new([0; 32]);
        extract_into(&salt, &[&ikm], &mut out);
        assert_eq!(out.expose().to_vec(), hex(prk));
        let half = info.len() / 2;
        let from_secret = Prk::from_secret(&out).expand::<82>(&[&info[..half], &info[half..]]);
        let from_extract = Prk::extract(&salt, &ikm).expand::<82>(&[&info]);
        let okm = hex(okm);
        assert_eq!(&from_secret.expose()[..okm.len()], &okm[..]);
        assert_eq!(&from_extract.expose()[..okm.len()], &okm[..]);
    }

    #[test]
    fn rfc5869_case_one() {
        check(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
    }

    #[test]
    fn rfc5869_case_two_long_inputs() {
        check(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );
    }

    #[test]
    fn rfc5869_case_three_empty_salt_and_info() {
        check(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
    }
}
