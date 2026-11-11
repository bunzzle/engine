use std::time::Duration;

use control::{Object, State, Tenant, Update};
use rt::{sleep, spawn};

use crate::error::Error;
use crate::start::Node;
use crate::transport::Transport;

const RETRY: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(30);

impl<T: Transport + 'static> Node<T> {
    pub async fn delete_tenant(&self, tenant: u32) -> Result<Update, Error> {
        let current = self
            .table()
            .tenant(tenant)
            .filter(|t| !t.state.deleted())
            .cloned()
            .ok_or(control::Error::Refused)?;
        let generation = current.generation;
        let deleting = Object::Tenant(Tenant {
            state: State::Deleting,
            ..current
        });
        let update = self.write(deleting).await?;
        self.drive_delete(tenant, generation);
        Ok(update)
    }

    pub fn tenant_drops(&self) -> u64 {
        self.inner.dropped.get()
    }

    pub(crate) fn resume_deletes(&self) {
        if !self.controls() {
            return;
        }
        let deleting: Vec<(u32, u32)> = self
            .table()
            .tenants()
            .filter(|t| t.state == State::Deleting)
            .map(|t| (t.id, t.generation))
            .collect();
        for (tenant, generation) in deleting {
            self.drive_delete(tenant, generation);
        }
    }

    pub(crate) async fn drop_tenant(&self, tenant: u32) {
        let spool = self.spool();
        for id in spool.messages_of(tenant) {
            if spool.cancel(id).await.is_ok() {
                self.inner.dropped.set(self.inner.dropped.get() + 1);
            }
        }
    }

    fn drive_delete(&self, tenant: u32, generation: u32) {
        let node = self.clone();
        drop(spawn(async move {
            let mut pause = RETRY;
            while node.keys().delete(tenant, generation).await.is_err() {
                if node.inner.ticker.stopped.get() {
                    return;
                }
                sleep(pause).await;
                pause = (pause * 2).min(RETRY_MAX);
            }
            loop {
                let current = node.table().tenant(tenant).cloned();
                let Some(current) = current.filter(|t| t.generation == generation) else {
                    return;
                };
                let written = match current.state {
                    State::Deleted => return,
                    State::Deleting => {
                        let deleted = Object::Tenant(Tenant {
                            state: State::Deleted,
                            ..current
                        });
                        node.write_trusted(deleted).await.is_ok()
                    }
                    State::Active | State::Suspended => false,
                };
                if written || node.inner.ticker.stopped.get() {
                    return;
                }
                sleep(RETRY).await;
            }
        }));
    }
}
