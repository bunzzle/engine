use std::rc::Weak;
use std::time::Duration;

use control::{State, Update};
use rt::{sleep, spawn};

use crate::error::Error;
use crate::start::{Inner, Node};

pub(crate) async fn sweep_queues<T: Transport + 'static>(inner: &Weak<Inner<T>>, tenant: u32) {
    let mut pause = RETRY;
    loop {
        let Some(node) = live(inner) else {
            return;
        };
        let queues = node.queues().clone();
        let table = std::rc::Rc::clone(&node.inner.table);
        drop(node);
        let swept = |tenant, generation| table.borrow().swept(tenant, generation);
        if queues.sweep(tenant, &swept).await.is_ok() {
            return;
        }
        if !nap(inner, pause).await {
            return;
        }
        pause = (pause * 2).min(RETRY_MAX);
    }
}
use crate::transport::Transport;

const RETRY: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(30);
const NAP: Duration = Duration::from_secs(1);

impl<T: Transport + 'static> Node<T> {
    pub async fn delete_tenant(&self, tenant: u32) -> Result<Update, Error> {
        let generation = self
            .table()
            .tenant(tenant)
            .map(|t| t.generation)
            .ok_or(control::Error::Refused)?;
        let update = self
            .write_state(tenant, generation, State::Deleting)
            .await?;
        self.drive_delete(tenant, generation);
        Ok(update)
    }

    pub fn tenant_drops(&self) -> u64 {
        self.inner.dropped.get()
    }

    pub fn delete_retries(&self) -> u64 {
        self.inner.delete_retries.get()
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
        let inner = std::rc::Rc::downgrade(&self.inner);
        drop(spawn(async move {
            let mut pause = RETRY;
            loop {
                let Some(node) = live(&inner) else {
                    return;
                };
                if node.keys().delete(tenant, generation).await.is_ok() {
                    break;
                }
                node.inner
                    .delete_retries
                    .set(node.inner.delete_retries.get() + 1);
                drop(node);
                if !nap(&inner, pause).await {
                    return;
                }
                pause = (pause * 2).min(RETRY_MAX);
            }
            loop {
                let Some(node) = live(&inner) else {
                    return;
                };
                match node.write_state(tenant, generation, State::Deleted).await {
                    Ok(_) | Err(Error::Control(control::Error::Refused)) => break,
                    Err(_) => {}
                }
                drop(node);
                if !nap(&inner, RETRY).await {
                    return;
                }
            }
            let mut pause = RETRY;
            loop {
                let Some(node) = live(&inner) else {
                    return;
                };
                if node.sweep_control().await.is_ok() {
                    return;
                }
                drop(node);
                if !nap(&inner, pause).await {
                    return;
                }
                pause = (pause * 2).min(RETRY_MAX);
            }
        }));
    }

    pub(crate) async fn sweep_control(&self) -> Result<usize, Error> {
        let node = self.clone();
        spawn(async move {
            let mut held = node.hold()?;
            let table = std::rc::Rc::clone(&node.inner.table);
            let swept = |tenant, generation| table.borrow().swept(tenant, generation);
            let mut removed = Vec::new();
            let result = held.writer().sweep(&swept, &mut removed).await;
            for &removal in &removed {
                node.note(control::Note::Remove(removal));
            }
            drop(held);
            for &removal in &removed {
                node.send(&control::Note::Remove(removal));
            }
            result?;
            Ok(removed.len())
        })
        .await
    }
}

fn live<T>(inner: &Weak<Inner<T>>) -> Option<Node<T>> {
    let inner = inner.upgrade()?;
    (!inner.ticker.stopped.get()).then_some(Node { inner })
}

async fn nap<T>(inner: &Weak<Inner<T>>, pause: Duration) -> bool {
    let mut left = pause;
    while !left.is_zero() {
        let step = left.min(NAP);
        sleep(step).await;
        left -= step;
        if inner.upgrade().is_none_or(|i| i.ticker.stopped.get()) {
            return false;
        }
    }
    true
}
