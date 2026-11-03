use control::{Created, KeyError, KeySource, Ready};
use crypto::TenantKeys;
use keys::{Fault, Ring};

pub struct Keyring {
    ring: Ring,
    retention: u16,
}

impl Keyring {
    pub fn new(ring: Ring, retention: u16) -> Self {
        Self { ring, retention }
    }

    pub fn ring(&self) -> &Ring {
        &self.ring
    }
}

fn key_error(fault: Fault) -> KeyError {
    match fault {
        Fault::Unknown => KeyError::Unknown,
        Fault::Unavailable => KeyError::Unavailable,
        Fault::Failed => KeyError::Failed,
        Fault::Conflict => KeyError::Conflict,
    }
}

impl KeySource for Keyring {
    fn get(&self, tenant: u32, generation: u32) -> Option<TenantKeys> {
        self.ring
            .get(tenant, generation)
            .map(|working| working.keys)
    }

    fn ready(&self, tenant: u32, generation: u32) -> Ready<'_> {
        Box::pin(async move {
            self.ring
                .open(tenant, generation)
                .await
                .map(|working| working.keys)
                .map_err(key_error)
        })
    }

    fn create(&self, tenant: u32, generation: u32) -> Created<'_> {
        Box::pin(async move {
            self.ring
                .create(tenant, generation, self.retention)
                .await
                .map_err(key_error)
        })
    }
}
