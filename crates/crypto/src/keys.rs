use std::sync::Arc;

use crate::{DataKey, Error, Secret, Tenant};

#[derive(Clone)]
pub struct TenantKeys(Arc<Held>);

struct Held {
    tenant: u32,
    generation: u32,
    data: DataKey,
    hash: Secret<16>,
}

impl TenantKeys {
    pub fn new(
        tenant: u32,
        generation: u32,
        data: &Secret<32>,
        version: u8,
        hash: Secret<16>,
    ) -> Self {
        Self(Arc::new(Held {
            tenant,
            generation,
            data: DataKey::new(data, version),
            hash,
        }))
    }

    pub fn derive(tenant: u32, generation: u32, root: &Tenant, version: u8) -> Self {
        Self::new(
            tenant,
            generation,
            &root.data_secret(generation, version),
            version,
            root.hash_key(generation),
        )
    }

    pub fn tenant(&self) -> u32 {
        self.0.tenant
    }

    pub fn generation(&self) -> u32 {
        self.0.generation
    }

    pub fn hash_key(&self) -> &Secret<16> {
        &self.0.hash
    }

    pub fn seal(&self, label: &[u8], clear: &[u8]) -> Result<Vec<u8>, Error> {
        self.owns(label)?;
        self.0.data.seal(label, clear)
    }

    pub fn open(&self, label: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
        self.owns(label)?;
        self.0.data.open(label, sealed)
    }

    fn owns(&self, label: &[u8]) -> Result<(), Error> {
        let mut owner = [0; 8];
        owner[..4].copy_from_slice(&self.0.tenant.to_le_bytes());
        owner[4..].copy_from_slice(&self.0.generation.to_le_bytes());
        if label.get(..8) == Some(&owner[..]) {
            Ok(())
        } else {
            Err(Error::Label)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TenantKeys;
    use crate::{Error, Secret, Tenant};

    fn label(tenant: u32, generation: u32) -> Vec<u8> {
        [&tenant.to_le_bytes()[..], &generation.to_le_bytes(), &[9]].concat()
    }

    #[test]
    fn seals_open_only_under_their_own_tenant_and_generation() {
        let root = Tenant::new(&Secret::new([1; 32]));
        let keys = TenantKeys::derive(4, 2, &root, 1);
        let sealed = keys.seal(&label(4, 2), b"mail").expect("seal");
        assert_eq!(keys.open(&label(4, 2), &sealed).expect("open"), b"mail");
        assert_eq!(keys.seal(&label(5, 2), b"mail").err(), Some(Error::Label));
        assert_eq!(keys.seal(&label(4, 3), b"mail").err(), Some(Error::Label));
        assert_eq!(keys.open(&label(5, 2), &sealed).err(), Some(Error::Label));
        assert_eq!(keys.seal(&[4, 0, 0], b"mail").err(), Some(Error::Label));
        let other = TenantKeys::derive(4, 3, &root, 1);
        let moved = [&4u32.to_le_bytes()[..], &3u32.to_le_bytes(), &[9]].concat();
        assert_eq!(other.open(&moved, &sealed).err(), Some(Error::Open));
    }

    #[test]
    fn a_clone_outlives_the_original() {
        let root = Tenant::new(&Secret::new([1; 32]));
        let keys = TenantKeys::derive(4, 2, &root, 1);
        let held = keys.clone();
        drop(keys);
        assert_eq!((held.tenant(), held.generation()), (4, 2));
        assert!(*held.hash_key() == root.hash_key(2));
    }
}
