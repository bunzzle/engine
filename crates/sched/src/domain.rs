use control::{Domain, Object, Removal, State, Verification};
use crypto::DkimAlg;

use crate::error::Error;
use crate::start::{Held, Node};
use crate::transport::Transport;

impl<T: Transport + 'static> Node<T> {
    pub async fn domain_new(&self, tenant: u32, name: &str) -> Result<Domain, Error> {
        let name = name.to_ascii_lowercase();
        if !control::domain_ok(&name) {
            return Err(control::Error::Invalid("domain").into());
        }
        let node = self.clone();
        rt::spawn(async move {
            let mut held = node.hold()?;
            let generation = node.generation(tenant)?;
            if node.table().domains(tenant).any(|d| *d.name == name) {
                return Err(control::Error::Refused.into());
            }
            let id = held.writer().reserve_domain().await?;
            let domain = Domain {
                id,
                tenant,
                generation,
                state: Verification::Unverified,
                rsa: 0,
                ed25519: 0,
                name: name.into(),
            };
            node.write_domain(&mut held, domain).await
        })
        .await
    }

    pub async fn domain_write(&self, domain: Domain) -> Result<Domain, Error> {
        let node = self.clone();
        rt::spawn(async move {
            let mut held = node.hold()?;
            let generation = node.generation(domain.tenant)?;
            {
                let table = node.table();
                let known = table
                    .domain(domain.tenant, domain.id)
                    .is_some_and(|d| d.name == domain.name && d.generation == generation);
                if !known || domain.generation != generation {
                    return Err(control::Error::Refused.into());
                }
                if domain.state == Verification::Verified && !control::verifiable(&domain.name) {
                    return Err(control::Error::Invalid("public suffix").into());
                }
                for (key, alg) in [
                    (domain.rsa, DkimAlg::RsaSha256),
                    (domain.ed25519, DkimAlg::Ed25519Sha256),
                ] {
                    let fits = key == 0
                        || table.dkim(domain.tenant, key).is_some_and(|d| {
                            d.alg == alg && d.generation == generation && d.domain == domain.name
                        });
                    if !fits {
                        return Err(control::Error::Invalid("dkim keys").into());
                    }
                }
            }
            node.write_domain(&mut held, domain).await
        })
        .await
    }

    pub async fn dkim_remove(&self, tenant: u32, id: u32) -> Result<Removal, Error> {
        let node = self.clone();
        rt::spawn(async move {
            let mut held = node.hold()?;
            let dkim = {
                let table = node.table();
                if table.domains(tenant).any(|d| d.names(id)) {
                    return Err(control::Error::Refused.into());
                }
                table
                    .dkim(tenant, id)
                    .cloned()
                    .ok_or(control::Error::Refused)?
            };
            let removal = held.writer().remove(&Object::Dkim(dkim)).await?;
            node.note(control::Note::Remove(removal));
            drop(held);
            node.send(&control::Note::Remove(removal));
            Ok(removal)
        })
        .await
    }

    fn generation(&self, tenant: u32) -> Result<u32, Error> {
        self.table()
            .tenant(tenant)
            .filter(|t| t.state == State::Active)
            .map(|t| t.generation)
            .ok_or_else(|| control::Error::Refused.into())
    }

    async fn write_domain(&self, held: &mut Held<'_>, domain: Domain) -> Result<Domain, Error> {
        let (tenant, generation) = (domain.tenant, domain.generation);
        let sealing = control::tenant_keys(self.keys(), tenant, generation)
            .await
            .map_err(|error| control::Error::Keys {
                tenant,
                generation,
                error,
            })?;
        let update = held
            .writer()
            .write_sealed(Object::Domain(domain.clone()), &sealing)
            .await?;
        self.apply(&update);
        self.broadcast(&update);
        Ok(domain)
    }
}
