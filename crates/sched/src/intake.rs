use control::{Leases, Name, State, Taken, Tenant, domain_ok};
use spool::Message;
use store::IndexRecord;

use crate::error::Refusal;
use crate::node::Arrival;
use crate::requests::{Begun, Ticket};
use crate::start::Node;
use crate::suppress::Hash;
use crate::transport::Transport;

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
        let mut added = self.recipients(draft, &[address]).await;
        added.pop().unwrap_or(Err(Refusal::Failed))
    }

    pub async fn recipients(
        &self,
        draft: &mut Draft,
        addresses: &[&str],
    ) -> Vec<Result<u32, Refusal>> {
        let mut out: Vec<Result<u32, Refusal>> = Vec::with_capacity(addresses.len());
        let mut domains = Vec::new();
        for address in addresses {
            match domain_of(address) {
                Some(domain) => {
                    domains.push((out.len(), *address, domain));
                    out.push(Ok(0));
                }
                None => out.push(Err(Refusal::Address)),
            }
        }
        let valid: Vec<&str> = domains.iter().map(|(_, address, _)| *address).collect();
        let checked = match self.current(draft) {
            Ok(()) if valid.is_empty() => Ok(Vec::new()),
            Ok(()) => {
                self.inner
                    .suppressions
                    .check(draft.tenant, draft.generation, &valid)
                    .await
            }
            Err(refusal) => Err(refusal),
        };
        let suppressed = match checked {
            Ok(suppressed) => suppressed,
            Err(refusal) => {
                for (at, _, _) in domains {
                    out[at] = Err(refusal);
                }
                return out;
            }
        };
        for ((at, _, domain), suppressed) in domains.into_iter().zip(suppressed) {
            out[at] = if suppressed {
                Err(Refusal::Suppressed)
            } else {
                self.named(draft, domain).await
            };
        }
        out
    }

    async fn named(&self, draft: &mut Draft, domain: Box<str>) -> Result<u32, Refusal> {
        let inner = &self.inner;
        if draft.queues.len() >= inner.settings.spool.recipients as usize {
            return Err(Refusal::Recipients);
        }
        self.current(draft)?;
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
        let queue = match inner.queues.name(&name).await {
            Ok(queue) => queue,
            Err(error) => {
                inner.leases.give_back(&draft.tenant, taken);
                return Err(match error {
                    control::Error::Keys { .. } => Refusal::Keys,
                    _ => Refusal::Failed,
                });
            }
        };
        draft.queues.push(queue);
        draft.taken.push(taken);
        Ok(queue)
    }

    pub async fn accept(&self, draft: Draft, message: Message) -> Result<(), Refusal> {
        self.accepted(draft, message, None).await
    }

    pub async fn request_shard(&self, tenant: u32, key: &[u8]) -> Result<u16, Refusal> {
        self.inner.requests.shard(tenant, key).await
    }

    pub async fn begin(&self, tenant: u32, key: &[u8], digest: Hash) -> Result<Begun, Refusal> {
        self.inner.requests.begin(tenant, key, digest).await
    }

    pub async fn accept_once(
        &self,
        ticket: Ticket,
        draft: Draft,
        message: Message,
    ) -> Result<(), Refusal> {
        if ticket.tenant() != draft.tenant
            || ticket.generation() != draft.generation
            || message.id.shard != ticket.shard()
        {
            return Err(Refusal::Message);
        }
        let record = self
            .inner
            .requests
            .record(&ticket, draft.generation, &[message.id])?;
        let result = self
            .accepted(draft, message, Some((ticket.shard(), vec![record])))
            .await;
        drop(ticket);
        result
    }

    async fn accepted(
        &self,
        mut draft: Draft,
        message: Message,
        index: Option<(u16, Vec<IndexRecord>)>,
    ) -> Result<(), Refusal> {
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
            .accept_indexed(vec![message], index)
            .await
            .map_err(|e| match e {
                spool::Error::Store(store::Error::Busy) => Refusal::Busy,
                _ => Refusal::Failed,
            })?;
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
