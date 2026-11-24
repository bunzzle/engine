use std::fmt::Write;
use std::rc::Rc;

use admin::{Admin, Code, Handler, PoolSpec, Reply, Request, TenantSpec};
use control::{Limits, Object, Pool, State, Tenant};
use rt::UnixListener;
use sched::{Node, Transport};

struct Ops<T: Transport + 'static> {
    node: Node<T>,
    cores: u16,
}

impl<T: Transport + 'static> Handler for Ops<T> {
    async fn handle(&self, request: Request) -> Reply {
        match request {
            Request::Status => self.status(),
            Request::TenantList => self.tenants(),
            Request::PoolList => self.pools(),
            Request::TenantCreate(spec) => self.create(spec).await,
            Request::TenantSuspend(id) => self.switch(id, State::Active, State::Suspended).await,
            Request::TenantResume(id) => self.switch(id, State::Suspended, State::Active).await,
            Request::PoolSet(spec) => self.pool(spec).await,
        }
    }
}

impl<T: Transport + 'static> Ops<T> {
    fn status(&self) -> Reply {
        let mut text = String::new();
        let _ = writeln!(text, "node {}", self.node.settings().node);
        let _ = writeln!(text, "cores {}", self.cores);
        let _ = writeln!(text, "control version {}", self.node.table().version());
        Reply::new(Code::Ok, text)
    }

    fn tenants(&self) -> Reply {
        let mut text = String::new();
        for t in self.node.table().tenants() {
            let pools: Vec<String> = t.pools.iter().map(u32::to_string).collect();
            let _ = writeln!(
                text,
                "tenant {} {} generation {} pools {} default {} connections {} queued {} rate {} burst {}",
                t.id,
                state(t.state),
                t.generation,
                pools.join(","),
                t.default_pool,
                t.limits.connections,
                t.limits.queued,
                t.limits.rate,
                t.limits.burst,
            );
        }
        Reply::new(Code::Ok, text)
    }

    fn pools(&self) -> Reply {
        let mut text = String::new();
        for p in self.node.table().pools() {
            let addresses: Vec<String> = p
                .addresses
                .iter()
                .map(|(ip, weight)| format!("{ip}={weight}"))
                .collect();
            let _ = writeln!(text, "pool {} addresses {}", p.id, addresses.join(","));
        }
        Reply::new(Code::Ok, text)
    }

    async fn create(&self, spec: TenantSpec) -> Reply {
        let tenant = {
            let table = self.node.table();
            if table.tenant(spec.id).is_some() {
                return Reply::new(Code::Refused, format!("tenant {} exists", spec.id));
            }
            if let Some(missing) = spec.pools.iter().find(|p| table.pool(**p).is_none()) {
                return Reply::new(Code::NotFound, format!("pool {missing} not found"));
            }
            Tenant {
                id: spec.id,
                generation: 1,
                state: State::Active,
                default_pool: spec.pools.first().copied().unwrap_or(0),
                pools: spec.pools,
                limits: Limits {
                    rate: spec.rate,
                    burst: spec.burst,
                    connections: spec.connections,
                    queued: spec.queued,
                },
            }
        };
        let id = tenant.id;
        self.write(Object::Tenant(tenant), format!("tenant {id} created"))
            .await
    }

    async fn switch(&self, id: u32, from: State, to: State) -> Reply {
        let tenant = {
            let table = self.node.table();
            let Some(tenant) = table.tenant(id) else {
                return Reply::new(Code::NotFound, format!("tenant {id} not found"));
            };
            if tenant.state == to {
                return Reply::new(Code::Ok, format!("tenant {id} already {}", state(to)));
            }
            if tenant.state != from {
                return Reply::new(
                    Code::Refused,
                    format!("tenant {id} is {}", state(tenant.state)),
                );
            }
            Tenant {
                state: to,
                ..tenant.clone()
            }
        };
        self.write(Object::Tenant(tenant), format!("tenant {id} {}", state(to)))
            .await
    }

    async fn pool(&self, spec: PoolSpec) -> Reply {
        let id = spec.id;
        let pool = Pool {
            id,
            addresses: spec.addresses,
        };
        self.write(Object::Pool(pool), format!("pool {id} set"))
            .await
    }

    async fn write(&self, object: Object, done: String) -> Reply {
        match self.node.write(object).await {
            Ok(update) => Reply::new(Code::Ok, format!("{done}, version {}\n", update.version)),
            Err(sched::Error::Control(control::Error::Busy)) => {
                Reply::new(Code::Busy, "another change is being written")
            }
            Err(sched::Error::Control(
                error @ (control::Error::Invalid(_) | control::Error::Refused),
            )) => Reply::new(Code::Refused, error.to_string()),
            Err(error) => Reply::new(Code::Failed, error.to_string()),
        }
    }
}

fn state(state: State) -> &'static str {
    match state {
        State::Active => "active",
        State::Suspended => "suspended",
        State::Deleting => "deleting",
        State::Deleted => "deleted",
    }
}

pub(crate) fn serve<T: Transport + 'static>(
    listener: Option<UnixListener>,
    node: &Node<T>,
    cores: u16,
    engine: u32,
) -> Option<Admin> {
    let listener = listener?;
    let ops = Ops {
        node: node.clone(),
        cores,
    };
    Some(admin::serve(listener, vec![engine, 0], Rc::new(ops)))
}
