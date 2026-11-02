use crate::{ChunkKey, Prk, Secret};

pub const AAD: usize = 29;

pub fn aad(tenant: u32, generation: u32, message: &[u8; 16], item: u32, label: u8) -> [u8; AAD] {
    let mut out = [0; AAD];
    out[..4].copy_from_slice(&tenant.to_le_bytes());
    out[4..8].copy_from_slice(&generation.to_le_bytes());
    out[8..24].copy_from_slice(message);
    out[24..28].copy_from_slice(&item.to_le_bytes());
    out[28] = label;
    out
}

pub struct BatchKey(Prk);

impl BatchKey {
    pub fn new(key: &Secret<32>) -> Self {
        Self(Prk::extract(b"bunzzle batch v1", key.expose()))
    }

    pub fn record(&self, message: &[u8; 16], item: u32, label: u8) -> ChunkKey {
        let key = self
            .0
            .expand::<32>(&[b"rec", message, &item.to_le_bytes(), &[label]]);
        ChunkKey::new(&key)
    }

    pub fn stamped(
        &self,
        message: &[u8; 16],
        item: u32,
        label: u8,
        boot: u32,
        write: u64,
    ) -> ChunkKey {
        let key = self.0.expand::<32>(&[
            b"sta",
            message,
            &item.to_le_bytes(),
            &[label],
            &boot.to_le_bytes(),
            &write.to_le_bytes(),
        ]);
        ChunkKey::new(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::{BatchKey, aad};
    use crate::{Error, Secret};

    #[test]
    fn records_get_their_own_keys() {
        let batch = BatchKey::new(&Secret::new([1; 32]));
        let id = [9; 16];
        let a = aad(1, 1, &id, 0, 1);
        let sealed = batch.record(&id, 0, 1).seal_one(&a, b"head");
        assert_eq!(
            batch
                .record(&id, 0, 1)
                .open_one(&a, &sealed)
                .expect("opens"),
            b"head"
        );
        assert_eq!(
            batch.record(&id, 1, 1).open_one(&a, &sealed),
            Err(Error::Open)
        );
        assert_eq!(
            batch.record(&id, 0, 2).open_one(&a, &sealed),
            Err(Error::Open)
        );
        assert_eq!(
            batch.record(&[8; 16], 0, 1).open_one(&a, &sealed),
            Err(Error::Open)
        );
        assert_eq!(
            batch.stamped(&id, 0, 1, 0, 0).open_one(&a, &sealed),
            Err(Error::Open)
        );
        let other = BatchKey::new(&Secret::new([2; 32]));
        assert_eq!(
            other.record(&id, 0, 1).open_one(&a, &sealed),
            Err(Error::Open)
        );
    }

    #[test]
    fn stamps_change_the_key() {
        let batch = BatchKey::new(&Secret::new([1; 32]));
        let id = [9; 16];
        let a = aad(1, 1, &id, 65536, 3);
        let sealed = batch.stamped(&id, 65536, 3, 4, 5).seal_one(&a, b"reply");
        assert!(
            batch
                .stamped(&id, 65536, 3, 4, 5)
                .open_one(&a, &sealed)
                .is_ok()
        );
        assert!(
            batch
                .stamped(&id, 65536, 3, 4, 6)
                .open_one(&a, &sealed)
                .is_err()
        );
        assert!(
            batch
                .stamped(&id, 65536, 3, 5, 5)
                .open_one(&a, &sealed)
                .is_err()
        );
    }

    #[test]
    fn known_answer() {
        use crate::seal::tests::hex;
        let batch = BatchKey::new(&Secret::new([1; 32]));
        let id = [9; 16];
        let a = aad(1, 2, &id, 3, 4);
        let record = batch.record(&id, 3, 4).seal_one(&a, b"head");
        let stamped = batch.stamped(&id, 3, 4, 5, 6).seal_one(&a, b"head");
        assert_eq!(
            hex(&a),
            "0100000002000000090909090909090909090909090909090300000004"
        );
        assert_eq!(hex(&record), "14f9aa6033a6abd0dd5bf912ea5f274ac1fc9c00");
        assert_eq!(hex(&stamped), "b5c8b945641521a9143c97308c1fcab8ea2983f5");
    }

    #[test]
    fn aad_binds_tenant_and_generation() {
        let batch = BatchKey::new(&Secret::new([1; 32]));
        let id = [9; 16];
        let sealed = batch
            .record(&id, 0, 1)
            .seal_one(&aad(1, 1, &id, 0, 1), b"head");
        assert!(
            batch
                .record(&id, 0, 1)
                .open_one(&aad(2, 1, &id, 0, 1), &sealed)
                .is_err()
        );
        assert!(
            batch
                .record(&id, 0, 1)
                .open_one(&aad(1, 2, &id, 0, 1), &sealed)
                .is_err()
        );
    }
}
