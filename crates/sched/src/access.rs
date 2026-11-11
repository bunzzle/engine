use control::{Access, Object, Removal, Scopes, State, Token};
use crypto::Plain;

use crate::error::Error;
use crate::start::Node;
use crate::transport::Transport;

impl<T: Transport + 'static> Node<T> {
    pub async fn access_new(
        &self,
        tenant: u32,
        scopes: Scopes,
        pool: u32,
    ) -> Result<(Access, Plain), Error> {
        let node = self.clone();
        rt::spawn(async move { node.access_held(tenant, scopes, pool).await }).await
    }

    async fn access_held(
        &self,
        tenant: u32,
        scopes: Scopes,
        pool: u32,
    ) -> Result<(Access, Plain), Error> {
        let generation = {
            let table = self.table();
            let current = table
                .tenant(tenant)
                .filter(|t| t.state == State::Active)
                .ok_or(control::Error::Refused)?;
            if pool != 0 && !current.pools.contains(&pool) {
                return Err(control::Error::Invalid("pool").into());
            }
            current.generation
        };
        if scopes == Scopes::default() {
            return Err(control::Error::Invalid("scopes").into());
        }
        let mut held = self.hold()?;
        let id = held.writer().reserve_access().await?;
        let token = Token::new(id)?;
        let access = Access {
            id,
            tenant,
            generation,
            scopes,
            pool,
            hash: token.hash(),
        };
        let update = held.writer().write(Object::Access(access.clone())).await?;
        self.apply(&update);
        drop(held);
        self.broadcast(&update);
        Ok((access, token.text()))
    }

    pub async fn access_revoke(&self, tenant: u32, id: u32) -> Result<Removal, Error> {
        let node = self.clone();
        rt::spawn(async move { node.revoke_held(tenant, id).await }).await
    }

    async fn revoke_held(&self, tenant: u32, id: u32) -> Result<Removal, Error> {
        let mut held = self.hold()?;
        let access = self
            .table()
            .access(id)
            .filter(|a| a.tenant == tenant)
            .cloned()
            .ok_or(control::Error::Refused)?;
        let removal = held.writer().remove(&Object::Access(access)).await?;
        self.note(control::Note::Remove(removal));
        drop(held);
        self.send(&control::Note::Remove(removal));
        Ok(removal)
    }
}
