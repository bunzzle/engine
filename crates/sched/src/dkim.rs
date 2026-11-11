use control::{Dkim, KeyError, Object, State};
use crypto::DkimAlg;

use crate::error::{Error, Refusal};
use crate::start::Node;
use crate::transport::Transport;

fn refusal(error: KeyError) -> Refusal {
    match error {
        KeyError::Unavailable | KeyError::Unknown => Refusal::Keys,
        KeyError::Busy => Refusal::Busy,
        KeyError::Failed | KeyError::Conflict => Refusal::Failed,
    }
}

impl<T: Transport + 'static> Node<T> {
    pub async fn dkim_new(
        &self,
        tenant: u32,
        alg: DkimAlg,
        domain: &str,
        selector: &str,
    ) -> Result<Dkim, Error> {
        Dkim::check_name(domain, selector)?;
        let node = self.clone();
        let (domain, selector) = (domain.into(), selector.into());
        rt::spawn(async move { node.dkim_held(tenant, alg, domain, selector).await }).await
    }

    async fn dkim_held(
        &self,
        tenant: u32,
        alg: DkimAlg,
        domain: Box<str>,
        selector: Box<str>,
    ) -> Result<Dkim, Error> {
        let generation = self
            .table()
            .tenant(tenant)
            .filter(|t| t.state == State::Active)
            .map(|t| t.generation)
            .ok_or(control::Error::Refused)?;
        let mut held = self.hold()?;
        let id = held.writer().reserve_dkim().await?;
        let (public, blob) = self
            .keys()
            .dkim_new(tenant, generation, id, alg)
            .await
            .map_err(|error| control::Error::Keys {
                tenant,
                generation,
                error,
            })?;
        let dkim = Dkim {
            id,
            tenant,
            generation,
            alg,
            domain,
            selector,
            public,
            blob,
        };
        let sealing = control::tenant_keys(self.keys(), tenant, generation)
            .await
            .map_err(|error| control::Error::Keys {
                tenant,
                generation,
                error,
            })?;
        let update = held
            .writer()
            .write_sealed(Object::Dkim(dkim.clone()), &sealing)
            .await?;
        self.apply(&update);
        drop(held);
        self.broadcast(&update);
        Ok(dkim)
    }

    pub async fn sign(&self, tenant: u32, key: u32, digest: [u8; 32]) -> Result<Vec<u8>, Refusal> {
        let (generation, alg) = self.signer(tenant, key, |d| (d.generation, d.alg))?;
        let keys = self.keys();
        match keys.sign(tenant, generation, key, alg, digest).await {
            Err(KeyError::Unknown) => {}
            signed => return signed.map_err(refusal),
        }
        let blob = self.signer(tenant, key, |d| d.blob.clone())?;
        keys.dkim_load(tenant, generation, key, alg, &blob)
            .await
            .map_err(refusal)?;
        keys.sign(tenant, generation, key, alg, digest)
            .await
            .map_err(refusal)
    }

    fn signer<R>(
        &self,
        tenant: u32,
        key: u32,
        take: impl FnOnce(&Dkim) -> R,
    ) -> Result<R, Refusal> {
        let table = self.table();
        let current = table
            .tenant(tenant)
            .filter(|t| t.state == State::Active)
            .ok_or(Refusal::Tenant)?;
        table
            .dkim(tenant, key)
            .filter(|d| d.generation == current.generation)
            .map(take)
            .ok_or(Refusal::Signer)
    }
}
