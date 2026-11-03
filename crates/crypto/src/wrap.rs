use aws_lc_rs::aead::{self, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};

use crate::kdf::extract_into;
use crate::{Error, Prk, Secret, TAG};

const FORMAT: u8 = 1;
const KEM: [u8; 5] = *b"KEM\x00\x20";
const AES_256: u16 = 2;
pub const WRAP: usize = 11 + 32 + 32 + TAG;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrap {
    pub day: u32,
    pub shard: u16,
    pub generation: u32,
    pub enc: [u8; 32],
    pub sealed: [u8; 32 + TAG],
}

impl Wrap {
    pub fn encode(&self) -> [u8; WRAP] {
        let mut out = [0; WRAP];
        out[0] = FORMAT;
        out[1..5].copy_from_slice(&self.day.to_le_bytes());
        out[5..7].copy_from_slice(&self.shard.to_le_bytes());
        out[7..11].copy_from_slice(&self.generation.to_le_bytes());
        out[11..43].copy_from_slice(&self.enc);
        out[43..].copy_from_slice(&self.sealed);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != WRAP {
            return Err(Error::Format("wrap length"));
        }
        if bytes[0] != FORMAT {
            return Err(Error::Format("wrap format"));
        }
        let mut enc = [0; 32];
        enc.copy_from_slice(&bytes[11..43]);
        let mut sealed = [0; 32 + TAG];
        sealed.copy_from_slice(&bytes[43..]);
        Ok(Self {
            day: u32::from_le_bytes(bytes[1..5].try_into().expect("4 bytes")),
            shard: u16::from_le_bytes(bytes[5..7].try_into().expect("2 bytes")),
            generation: u32::from_le_bytes(bytes[7..11].try_into().expect("4 bytes")),
            enc,
            sealed,
        })
    }
}

pub fn seal_batch(
    public: &[u8; 32],
    tenant: u32,
    generation: u32,
    day: u32,
    shard: u16,
    batch: u64,
    key: &Secret<32>,
) -> Result<Wrap, Error> {
    seal_batch_with(
        &Secret::<32>::random()?,
        public,
        tenant,
        generation,
        day,
        shard,
        batch,
        key,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_batch_with(
    ephemeral: &Secret<32>,
    public: &[u8; 32],
    tenant: u32,
    generation: u32,
    day: u32,
    shard: u16,
    batch: u64,
    key: &Secret<32>,
) -> Result<Wrap, Error> {
    let context = context(tenant, generation, day, shard, batch);
    let (enc, body) = seal::<32>(
        &AES_256_GCM,
        AES_256,
        ephemeral,
        public,
        &context,
        &context,
        key.expose(),
    )?;
    let mut sealed = [0; 32 + TAG];
    sealed.copy_from_slice(&body);
    Ok(Wrap {
        day,
        shard,
        generation,
        enc,
        sealed,
    })
}

pub fn open_batch(
    secret: &Secret<32>,
    tenant: u32,
    batch: u64,
    wrap: &Wrap,
) -> Result<Secret<32>, Error> {
    let context = context(tenant, wrap.generation, wrap.day, wrap.shard, batch);
    let clear = open::<32>(
        &AES_256_GCM,
        AES_256,
        secret,
        &wrap.enc,
        &context,
        &context,
        &wrap.sealed,
    )?;
    let key = Secret::from_slice(clear.expose_slice());
    drop(clear);
    key
}

fn context(tenant: u32, generation: u32, day: u32, shard: u16, batch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(15 + 22);
    out.extend_from_slice(b"bunzzle wrap v1");
    out.extend_from_slice(&tenant.to_le_bytes());
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&day.to_le_bytes());
    out.extend_from_slice(&shard.to_le_bytes());
    out.extend_from_slice(&batch.to_le_bytes());
    out
}

struct Clear(Vec<u8>);

impl Clear {
    fn expose_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Clear {
    fn drop(&mut self) {
        sys::mem::wipe(&mut self.0);
    }
}

fn seal<const NK: usize>(
    algorithm: &'static aead::Algorithm,
    aead_id: u16,
    ephemeral: &Secret<32>,
    public: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    clear: &[u8],
) -> Result<([u8; 32], Vec<u8>), Error> {
    let ephemeral =
        PrivateKey::from_private_key(&X25519, ephemeral.expose()).map_err(|_| Error::Key)?;
    let enc: [u8; 32] = ephemeral
        .compute_public_key()
        .map_err(|_| Error::Key)?
        .as_ref()
        .try_into()
        .map_err(|_| Error::Key)?;
    let dh = agree(&ephemeral, public)?;
    let shared = shared_secret(&dh, &enc, public);
    let (key, nonce) = schedule::<NK>(aead_id, &shared, info);
    let key = LessSafeKey::new(UnboundKey::new(algorithm, key.expose()).map_err(|_| Error::Key)?);
    let mut body = clear.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(*nonce.expose()),
        Aad::from(aad),
        &mut body,
    )
    .map_err(|_| Error::Key)?;
    Ok((enc, body))
}

fn open<const NK: usize>(
    algorithm: &'static aead::Algorithm,
    aead_id: u16,
    secret: &Secret<32>,
    enc: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Clear, Error> {
    let private = PrivateKey::from_private_key(&X25519, secret.expose()).map_err(|_| Error::Key)?;
    let public: [u8; 32] = private
        .compute_public_key()
        .map_err(|_| Error::Key)?
        .as_ref()
        .try_into()
        .map_err(|_| Error::Key)?;
    let dh = agree(&private, enc)?;
    let shared = shared_secret(&dh, enc, &public);
    let (key, nonce) = schedule::<NK>(aead_id, &shared, info);
    let key = LessSafeKey::new(UnboundKey::new(algorithm, key.expose()).map_err(|_| Error::Key)?);
    let mut body = Clear(sealed.to_vec());
    let len = key
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce.expose()),
            Aad::from(aad),
            &mut body.0,
        )
        .map_err(|_| Error::Open)?
        .len();
    body.0.truncate(len);
    Ok(body)
}

fn agree(private: &PrivateKey, public: &[u8; 32]) -> Result<Secret<32>, Error> {
    agreement::agree(
        private,
        UnparsedPublicKey::new(&X25519, public),
        Error::Open,
        Secret::from_slice,
    )
}

fn shared_secret(dh: &Secret<32>, enc: &[u8; 32], public: &[u8; 32]) -> Secret<32> {
    let mut prk = Secret::new([0; 32]);
    labeled_extract_into(&KEM, &[], b"eae_prk", dh.expose(), &mut prk);
    labeled_expand(&KEM, &prk, b"shared_secret", &[enc, public])
}

fn schedule<const NK: usize>(
    aead_id: u16,
    shared: &Secret<32>,
    info: &[u8],
) -> (Secret<NK>, Secret<12>) {
    let mut suite = [0; 10];
    suite[..4].copy_from_slice(b"HPKE");
    suite[4..6].copy_from_slice(&0x0020u16.to_be_bytes());
    suite[6..8].copy_from_slice(&1u16.to_be_bytes());
    suite[8..].copy_from_slice(&aead_id.to_be_bytes());
    let mut psk_id_hash = Secret::new([0; 32]);
    labeled_extract_into(&suite, &[], b"psk_id_hash", &[], &mut psk_id_hash);
    let mut info_hash = Secret::new([0; 32]);
    labeled_extract_into(&suite, &[], b"info_hash", info, &mut info_hash);
    let mut secret = Secret::new([0; 32]);
    labeled_extract_into(&suite, shared.expose(), b"secret", &[], &mut secret);
    let context: [&[u8]; 3] = [&[0], psk_id_hash.expose(), info_hash.expose()];
    let key = labeled_expand(&suite, &secret, b"key", &context);
    let nonce = labeled_expand(&suite, &secret, b"base_nonce", &context);
    (key, nonce)
}

fn labeled_extract_into(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8], out: &mut Secret<32>) {
    extract_into(salt, &[b"HPKE-v1", suite, label, ikm], out);
}

fn labeled_expand<const N: usize>(
    suite: &[u8],
    prk: &Secret<32>,
    label: &[u8],
    info: &[&[u8]],
) -> Secret<N> {
    let length = u16::try_from(N).expect("short output").to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![&length, b"HPKE-v1", suite, label];
    parts.extend_from_slice(info);
    Prk::from_secret(prk).expand(&parts)
}

#[cfg(test)]
mod tests {
    use super::{AES_256_GCM, WRAP, Wrap, open, open_batch, seal, seal_batch, seal_batch_with};
    use crate::kdf::hex;
    use crate::{Error, Secret, day_public};
    use aws_lc_rs::aead::AES_128_GCM;

    struct Vector {
        sk_e: &'static str,
        pk_e: &'static str,
        sk_r: &'static str,
        pk_r: &'static str,
        ct: &'static str,
    }

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const AAD: &str = "436f756e742d30";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

    const AES_128: Vector = Vector {
        sk_e: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        pk_e: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        sk_r: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        pk_r: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        ct: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
    };

    const AES_256: Vector = Vector {
        sk_e: "179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11",
        pk_e: "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
        sk_r: "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d",
        pk_r: "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
        ct: "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
    };

    fn array(text: &str) -> [u8; 32] {
        hex(text).try_into().expect("32 bytes")
    }

    #[test]
    fn rfc9180_base_mode_vectors() {
        let (enc, ct) = seal::<16>(
            &AES_128_GCM,
            1,
            &Secret::new(array(AES_128.sk_e)),
            &array(AES_128.pk_r),
            &hex(INFO),
            &hex(AAD),
            &hex(PT),
        )
        .expect("seals");
        assert_eq!(enc, array(AES_128.pk_e));
        assert_eq!(ct, hex(AES_128.ct));
        let clear = open::<16>(
            &AES_128_GCM,
            1,
            &Secret::new(array(AES_128.sk_r)),
            &enc,
            &hex(INFO),
            &hex(AAD),
            &ct,
        )
        .expect("opens");
        assert_eq!(clear.expose_slice(), hex(PT));

        let (enc, ct) = seal::<32>(
            &AES_256_GCM,
            2,
            &Secret::new(array(AES_256.sk_e)),
            &array(AES_256.pk_r),
            &hex(INFO),
            &hex(AAD),
            &hex(PT),
        )
        .expect("seals");
        assert_eq!(enc, array(AES_256.pk_e));
        assert_eq!(ct, hex(AES_256.ct));
        let clear = open::<32>(
            &AES_256_GCM,
            2,
            &Secret::new(array(AES_256.sk_r)),
            &enc,
            &hex(INFO),
            &hex(AAD),
            &ct,
        )
        .expect("opens");
        assert_eq!(clear.expose_slice(), hex(PT));
    }

    #[test]
    fn batch_wrap_round_trip_and_binding() {
        let secret = Secret::new([11; 32]);
        let public = day_public(&secret).expect("public");
        let key = Secret::new([12; 32]);
        let wrap = seal_batch(&public, 7, 2, 20_000, 3, 99, &key).expect("wraps");
        let bytes = wrap.encode();
        assert_eq!(bytes.len(), WRAP);
        let wrap = Wrap::decode(&bytes).expect("decodes");
        assert!(open_batch(&secret, 7, 99, &wrap).expect("opens") == key);
        assert_eq!(open_batch(&secret, 8, 99, &wrap).err(), Some(Error::Open));
        assert_eq!(open_batch(&secret, 7, 98, &wrap).err(), Some(Error::Open));
        for change in 0..3 {
            let mut bad = wrap.clone();
            match change {
                0 => bad.day += 1,
                1 => bad.shard += 1,
                _ => bad.generation += 1,
            }
            assert_eq!(open_batch(&secret, 7, 99, &bad).err(), Some(Error::Open));
        }
        assert_eq!(
            open_batch(&Secret::new([13; 32]), 7, 99, &wrap).err(),
            Some(Error::Open)
        );
    }

    #[test]
    fn known_answer() {
        let secret = Secret::new([11; 32]);
        let public = day_public(&secret).expect("public");
        let wrap = seal_batch_with(
            &Secret::new([14; 32]),
            &public,
            7,
            2,
            20_000,
            3,
            99,
            &Secret::new([12; 32]),
        )
        .expect("wraps");
        assert_eq!(
            crate::seal::tests::hex(&wrap.encode()),
            "01204e00000300020000005855784cb3c8c796d84ac93e8f4a53dab0bb31e80960042cfa87f03a4293b308d68d894de02f2600ae258ffde22e41771520d3736b988f2a227a73198e5cf91b754a68ad1fbc6e3ad55f54fd3c79731d"
        );
    }

    #[test]
    fn low_order_points_are_refused() {
        let secret = Secret::new([11; 32]);
        let public = day_public(&secret).expect("public");
        let wrap = seal_batch(&public, 7, 2, 1, 3, 99, &Secret::new([12; 32])).expect("wraps");
        for point in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let mut bad = wrap.clone();
            bad.enc = array(point);
            assert_eq!(
                open_batch(&secret, 7, 99, &bad).err(),
                Some(Error::Open),
                "{point}"
            );
        }
    }

    #[test]
    fn wraps_are_fresh_and_damage_is_refused() {
        let secret = Secret::new([11; 32]);
        let public = day_public(&secret).expect("public");
        let key = Secret::new([12; 32]);
        let a = seal_batch(&public, 7, 2, 1, 3, 99, &key)
            .expect("wraps")
            .encode();
        let b = seal_batch(&public, 7, 2, 1, 3, 99, &key)
            .expect("wraps")
            .encode();
        assert_ne!(a, b);
        for i in 11..WRAP {
            let mut bad = a;
            bad[i] ^= 1;
            let wrap = Wrap::decode(&bad).expect("decodes");
            assert!(open_batch(&secret, 7, 99, &wrap).is_err(), "byte {i}");
        }
        let mut bad = a;
        bad[0] = 2;
        assert_eq!(Wrap::decode(&bad), Err(Error::Format("wrap format")));
        assert_eq!(Wrap::decode(&a[1..]), Err(Error::Format("wrap length")));
    }
}
