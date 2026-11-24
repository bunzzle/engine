use std::fmt::Write;
use std::net::IpAddr;
use std::rc::Rc;

use admin::{Admin, Code, Handler, PoolSpec, Reply, Request, TenantSpec};
use control::{Limits, Object, Pool, State, Table, Tenant};
use rt::UnixListener;
use sched::{Node, Transport};

const LIST_BYTES: usize = 60 * 1024;

enum Stop {
    Reply(Reply),
    Error(sched::Error),
}

impl From<sched::Error> for Stop {
    fn from(error: sched::Error) -> Self {
        Self::Error(error)
    }
}

struct Ops<T: Transport + 'static> {
    node: Node<T>,
    cores: u16,
}

impl<T: Transport + 'static> Handler for Ops<T> {
    async fn handle(&self, request: Request) -> Reply {
        match request {
            Request::Status => self.status(),
            Request::TenantList(from) => self.tenants(from),
            Request::PoolList(from) => self.pools(from),
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

    fn tenants(&self, from: u32) -> Reply {
        let table = self.node.table();
        let lines = table.tenants().filter(|t| t.id >= from).map(|t| {
            let pools: Vec<String> = t.pools.iter().map(u32::to_string).collect();
            let line = format!(
                "tenant {} {} generation {} pools {} default {} connections {} queued {} rate {} burst {}\n",
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
            (t.id, line)
        });
        Reply::new(Code::Ok, listed(lines))
    }

    fn pools(&self, from: u32) -> Reply {
        let table = self.node.table();
        let lines = table.pools().filter(|p| p.id >= from).map(|p| {
            let addresses: Vec<String> = p
                .addresses
                .iter()
                .map(|(ip, weight)| format!("{ip}={weight}"))
                .collect();
            (
                p.id,
                format!("pool {} addresses {}\n", p.id, addresses.join(",")),
            )
        });
        Reply::new(Code::Ok, listed(lines))
    }

    async fn create(&self, spec: TenantSpec) -> Reply {
        let id = spec.id;
        let wanted = Tenant {
            id,
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
        };
        let command = format!("tenant create {id}");
        self.write(command, format!("tenant {id} created"), move |table| {
            if let Some(current) = table.tenant(id) {
                let reply = if *current == wanted {
                    Reply::new(Code::Ok, format!("tenant {id} exists with this spec"))
                } else {
                    Reply::new(Code::Refused, format!("tenant {id} exists"))
                };
                return Err(Stop::Reply(reply));
            }
            if let Some(missing) = wanted.pools.iter().find(|p| table.pool(**p).is_none()) {
                return Err(Stop::Reply(Reply::new(
                    Code::NotFound,
                    format!("pool {missing} not found"),
                )));
            }
            Ok(Object::Tenant(wanted))
        })
        .await
    }

    async fn switch(&self, id: u32, from: State, to: State) -> Reply {
        let command = format!("tenant {} {id}", verb(to));
        self.write(
            command,
            format!("tenant {id} {}", state(to)),
            move |table| {
                let Some(tenant) = table.tenant(id) else {
                    return Err(Stop::Reply(Reply::new(
                        Code::NotFound,
                        format!("tenant {id} not found"),
                    )));
                };
                if tenant.state == to {
                    return Err(Stop::Reply(Reply::new(
                        Code::Ok,
                        format!("tenant {id} already {}", state(to)),
                    )));
                }
                if tenant.state != from {
                    return Err(Stop::Reply(Reply::new(
                        Code::Refused,
                        format!("tenant {id} is {}", state(tenant.state)),
                    )));
                }
                Ok(Object::Tenant(Tenant {
                    state: to,
                    ..tenant.clone()
                }))
            },
        )
        .await
    }

    async fn pool(&self, spec: PoolSpec) -> Reply {
        let id = spec.id;
        let addresses: Vec<(IpAddr, u16)> = spec
            .addresses
            .into_iter()
            .map(|(ip, weight)| (ip.to_canonical(), weight))
            .collect();
        let mut ips: Vec<IpAddr> = addresses.iter().map(|a| a.0).collect();
        ips.sort_unstable();
        ips.dedup();
        if ips.len() != addresses.len()
            || ips
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Reply::new(Code::Refused, "invalid addresses");
        }
        let pool = Pool { id, addresses };
        self.write(
            format!("pool set {id}"),
            format!("pool {id} set"),
            move |_| Ok(Object::Pool(pool)),
        )
        .await
    }

    async fn write<F>(&self, command: String, done: String, build: F) -> Reply
    where
        F: FnOnce(&Table) -> Result<Object, Stop> + 'static,
    {
        let reply = match self.node.write_with(build).await {
            Ok(update) => Reply::new(Code::Ok, format!("{done}, version {}\n", update.version)),
            Err(Stop::Reply(reply)) => reply,
            Err(Stop::Error(sched::Error::Control(control::Error::Busy))) => {
                Reply::new(Code::Busy, "another change is being written")
            }
            Err(Stop::Error(sched::Error::Control(
                error @ (control::Error::Invalid(_) | control::Error::Refused),
            ))) => Reply::new(Code::Refused, error.to_string()),
            Err(Stop::Error(error)) => Reply::new(Code::Failed, error.to_string()),
        };
        eprintln!(
            "admin {command}: {:?} {}",
            reply.code,
            reply.text.trim_end()
        );
        reply
    }
}

fn listed(lines: impl Iterator<Item = (u32, String)>) -> String {
    let mut text = String::new();
    for (id, line) in lines {
        if text.len() + line.len() > LIST_BYTES {
            let _ = writeln!(text, "more from {id}");
            break;
        }
        text.push_str(&line);
    }
    text
}

fn verb(to: State) -> &'static str {
    match to {
        State::Suspended => "suspend",
        _ => "resume",
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
