use control::{KeyError, KeySource, Ready};
use crypto::TenantKeys;
use keys::{Fault, Ring};

pub struct Keyring(Ring);

impl Keyring {
    pub fn new(ring: Ring) -> Self {
        Self(ring)
    }

    pub fn ring(&self) -> &Ring {
        &self.0
    }
}

impl KeySource for Keyring {
    fn get(&self, tenant: u32, generation: u32) -> Option<TenantKeys> {
        self.0.get(tenant, generation).map(|working| working.keys)
    }

    fn ready(&self, tenant: u32, generation: u32) -> Ready<'_> {
        Box::pin(async move {
            match self.0.open(tenant, generation).await {
                Ok(working) => Ok(working.keys),
                Err(Fault::Unknown) => Err(KeyError::Unknown),
                Err(Fault::Unavailable) => Err(KeyError::Unavailable),
                Err(Fault::Failed) => Err(KeyError::Failed),
            }
        })
    }
}
