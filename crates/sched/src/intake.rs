use control::{Leases, Name, State, Taken, Tenant, domain_ok};
use spool::Message;

use crate::error::Refusal;
use crate::node::Arrival;
use crate::start::Node;
use crate::transport::Transport;

pub trait Suppressions {
    fn suppressed(&self, tenant: u32, address: &str) -> bool;
}

pub struct Draft {
    tenant: u32,
    generation: u32,
    pool: u32,
    queues: Vec<u32>,
    taken: Vec<Taken>,
    leases: Leases<u32>,
}

impl Draft {
    pub fn tenant(&self) -> u32 {
        self.tenant
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn pool(&self) -> u32 {
        self.pool
    }

    pub fn queues(&self) -> &[u32] {
        &self.queues
    }
}

impl Drop for Draft {
    fn drop(&mut self) {
        for taken in self.taken.drain(..) {
            self.leases.give_back(&self.tenant, taken);
        }
    }
}

pub fn domain_of(address: &str) -> Option<Box<str>> {
    let (local, domain) = address.rsplit_once('@')?;
    let domain = domain.to_ascii_lowercase();
    (!local.is_empty() && domain_ok(&domain)).then(|| domain.into())
}

impl<T: Transport + 'static> Node<T> {
    pub fn draft(&self, tenant: u32, pool: Option<u32>) -> Result<Draft, Refusal> {
        let table = self.inner.table.borrow();
        let found = active(table.tenant(tenant))?;
        let pool = pool.unwrap_or(found.default_pool);
        if !found.pools.contains(&pool) || table.pool(pool).is_none() {
            return Err(Refusal::Pool);
        }
        Ok(Draft {
            tenant,
            generation: found.generation,
            pool,
            queues: Vec::new(),
            taken: Vec::new(),
            leases: self.inner.leases.clone(),
        })
    }

    pub async fn recipient(&self, draft: &mut Draft, address: &str) -> Result<u32, Refusal> {
        let inner = &self.inner;
        if draft.queues.len() >= inner.settings.spool.recipients as usize {
            return Err(Refusal::Recipients);
        }
        let domain = domain_of(address).ok_or(Refusal::Address)?;
        self.current(draft)?;
        if inner.suppressions.suppressed(draft.tenant, address) {
            return Err(Refusal::Suppressed);
        }
        let taken = match inner.leases.take(&draft.tenant).await {
            Ok(taken) => taken,
            Err(control::Error::Busy) => return Err(Refusal::Busy),
            Err(_) => return Err(Refusal::Tenant),
        };
        let name = Name {
            tenant: draft.tenant,
            domain,
            generation: draft.generation,
            pool: draft.pool,
        };
        let Ok(queue) = inner.queues.name(&name).await else {
            inner.leases.give_back(&draft.tenant, taken);
            return Err(Refusal::Failed);
        };
        draft.queues.push(queue);
        draft.taken.push(taken);
        Ok(queue)
    }

    pub async fn accept(&self, mut draft: Draft, message: Message) -> Result<(), Refusal> {
        let queues = message.slices.iter().flat_map(|s| s.queues.iter().copied());
        if message.tenant != draft.tenant
            || draft.queues.is_empty()
            || !queues.eq(draft.queues.iter().copied())
        {
            return Err(Refusal::Message);
        }
        self.current(&draft)?;
        let arrival = Arrival::of(&message, draft.generation);
        self.inner
            .spool
            .accept(vec![message])
            .await
            .map_err(|_| Refusal::Failed)?;
        draft.taken.clear();
        self.inner.sched.enqueue(arrival);
        Ok(())
    }

    fn current(&self, draft: &Draft) -> Result<(), Refusal> {
        let table = self.inner.table.borrow();
        let found = active(table.tenant(draft.tenant))?;
        if found.generation != draft.generation {
            return Err(Refusal::Tenant);
        }
        if !found.pools.contains(&draft.pool) {
            return Err(Refusal::Pool);
        }
        Ok(())
    }
}

fn active(tenant: Option<&Tenant>) -> Result<&Tenant, Refusal> {
    tenant
        .filter(|t| t.state == State::Active)
        .ok_or(Refusal::Tenant)
}
