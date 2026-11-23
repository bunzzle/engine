use std::sync::Arc;

use control::{ALL_EVENTS, Hook, HookState, Object, Removal, State};
use crypto::Secret;

use crate::error::Error;
use crate::start::{Held, Node};
use crate::status::{Disable, HookStatus};
use crate::transport::Transport;

pub const MAX_HOOKS: usize = 8;
pub const ROTATION_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookChange {
    pub url: Option<Box<str>>,
    pub events: Option<u8>,
    pub enabled: Option<bool>,
}

fn events(mask: u8) -> Result<u8, Error> {
    match mask {
        0 => Ok(ALL_EVENTS),
        mask if mask & !ALL_EVENTS == 0 => Ok(mask),
        _ => Err(control::Error::Invalid("events").into()),
    }
}

fn url(url: &str) -> Result<Box<str>, Error> {
    if control::hook_url_ok(url) {
        Ok(url.into())
    } else {
        Err(control::Error::Invalid("url").into())
    }
}

impl<T: Transport + 'static> Node<T> {
    pub async fn hook_new(&self, tenant: u32, address: &str, mask: u8) -> Result<Hook, Error> {
        let address = url(address)?;
        let mask = events(mask)?;
        let node = self.clone();
        rt::spawn(async move {
            let mut held = node.hold()?;
            let generation = node.active_generation(tenant)?;
            if node.hooks(tenant).len() >= MAX_HOOKS {
                return Err(control::Error::Full.into());
            }
            let id = held.writer().reserve_hook().await?;
            let hook = Hook {
                id,
                tenant,
                generation,
                state: HookState::Active,
                events: mask,
                version: 1,
                previous_until: 0,
                url: address,
            };
            node.write_hook(&mut held, hook).await
        })
        .await
    }

    pub async fn hook_change(
        &self,
        tenant: u32,
        id: u32,
        change: HookChange,
    ) -> Result<Hook, Error> {
        let address = change.url.as_deref().map(url).transpose()?;
        let mask = change.events.map(events).transpose()?;
        let node = self.clone();
        rt::spawn(async move {
            let mut held = node.hold()?;
            let mut hook = node.hook(tenant, id)?;
            if let Some(address) = address {
                hook.url = address;
            }
            if let Some(mask) = mask {
                hook.events = mask;
            }
            match change.enabled {
                Some(true) => hook.state = HookState::Active,
                Some(false) => hook.state = HookState::Paused,
                None => {}
            }
            node.write_hook(&mut held, hook).await
        })
        .await
    }

    pub async fn hook_rotate(&self, tenant: u32, id: u32) -> Result<Hook, Error> {
        let node = self.clone();
        rt::spawn(async move {
            let mut held = node.hold()?;
            let mut hook = node.hook(tenant, id)?;
            hook.version = hook.version.checked_add(1).ok_or(control::Error::Full)?;
            hook.previous_until = node.inner.sched.clock().now().saturating_add(ROTATION_MS);
            node.write_hook(&mut held, hook).await
        })
        .await
    }

    pub async fn hook_remove(&self, tenant: u32, id: u32) -> Result<Removal, Error> {
        let node = self.clone();
        rt::spawn(async move {
            let mut held = node.hold()?;
            let hook = node.hook(tenant, id)?;
            let removal = held.writer().remove(&Object::Hook(hook)).await?;
            node.keys().forget_hook(tenant, id);
            node.note(control::Note::Remove(removal));
            drop(held);
            node.send(&control::Note::Remove(removal));
            Ok(removal)
        })
        .await
    }

    pub fn hook_versions(&self, tenant: u32, id: u32) -> Result<(Hook, Option<u8>), Error> {
        let hook = self.hook(tenant, id)?;
        let now = self.inner.sched.clock().now();
        let previous = (hook.version > 1 && now < hook.previous_until).then(|| hook.version - 1);
        Ok((hook, previous))
    }

    pub async fn hook_secret(
        &self,
        tenant: u32,
        id: u32,
        version: u8,
    ) -> Result<Arc<Secret<32>>, Error> {
        let (hook, previous) = self.hook_versions(tenant, id)?;
        if version != hook.version && Some(version) != previous {
            return Err(control::Error::Refused.into());
        }
        self.keys()
            .hook_secret(tenant, hook.generation, id, version)
            .await
            .map_err(|error| {
                control::Error::Keys {
                    tenant,
                    generation: hook.generation,
                    error,
                }
                .into()
            })
    }

    fn active_generation(&self, tenant: u32) -> Result<u32, Error> {
        self.table()
            .tenant(tenant)
            .filter(|t| t.state == State::Active)
            .map(|t| t.generation)
            .ok_or_else(|| control::Error::Refused.into())
    }

    pub fn hooks(&self, tenant: u32) -> Vec<Hook> {
        let Ok(generation) = self.active_generation(tenant) else {
            return Vec::new();
        };
        self.table()
            .hooks(tenant)
            .filter(|h| h.generation == generation)
            .cloned()
            .collect()
    }

    pub fn hook(&self, tenant: u32, id: u32) -> Result<Hook, Error> {
        let generation = self.active_generation(tenant)?;
        self.table()
            .hook(tenant, id)
            .filter(|h| h.generation == generation)
            .cloned()
            .ok_or_else(|| control::Error::Refused.into())
    }

    pub fn hook_status(&self, hook: &Hook) -> HookStatus {
        self.inner.hook_reports.borrow().status(hook)
    }

    pub(crate) async fn disable_hook(&self, disable: Disable) {
        let node = self.clone();
        let result = rt::spawn(async move {
            let mut held = node.hold()?;
            if !node.inner.hook_reports.borrow().current(&disable) {
                return Ok(false);
            }
            let Some(mut hook) = node
                .table()
                .hook(disable.tenant, disable.hook)
                .filter(|hook| {
                    hook.generation == disable.generation && hook.state == HookState::Active
                })
                .cloned()
            else {
                return Ok(false);
            };
            hook.state = disable.state;
            node.write_hook(&mut held, hook).await.map(|_| true)
        })
        .await;
        match result {
            Ok(true) => self.inner.hook_reports.borrow_mut().disabled(disable.state),
            Ok(false) | Err(Error::Control(control::Error::Busy)) => {}
            Err(error) => {
                self.inner.hook_reports.borrow_mut().write_failed();
                eprintln!("webhook state write failed: {error}");
            }
        }
    }

    async fn write_hook(&self, held: &mut Held<'_>, hook: Hook) -> Result<Hook, Error> {
        let (tenant, generation) = (hook.tenant, hook.generation);
        let sealing = control::tenant_keys(self.keys(), tenant, generation)
            .await
            .map_err(|error| control::Error::Keys {
                tenant,
                generation,
                error,
            })?;
        let update = held
            .writer()
            .write_sealed(Object::Hook(hook.clone()), &sealing)
            .await?;
        self.apply(&update);
        self.broadcast(&update);
        Ok(hook)
    }
}
