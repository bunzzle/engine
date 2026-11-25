use std::fmt::Write;
use std::net::IpAddr;
use std::rc::Rc;

use admin::{Admin, Code, Handler, PoolSpec, Reply, Request, TenantSpec};
use control::{Limits, Object, Pool, Scopes, State, Table, Tenant};
use rt::UnixListener;
use sched::{Node, QueueDone, QueueRefusal, Transport};

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
            Request::QueueList { tenant, from } => self.queues(tenant, from).await,
            Request::QueueRetry { tenant, queue } => {
                let done = self.node.queue_retry(tenant, queue).await;
                queued(
                    &format!("queue retry {tenant} {queue}"),
                    tenant,
                    queue,
                    done,
                )
            }
            Request::QueueRebind {
                tenant,
                queue,
                pool,
            } => {
                let done = self.node.queue_rebind(tenant, queue, pool).await;
                queued(
                    &format!("queue rebind {tenant} {queue} {pool}"),
                    tenant,
                    queue,
                    done,
                )
            }
            Request::KeyCreate {
                tenant,
                smtp,
                api,
                hooks,
                pool,
            } => {
                self.key_create(tenant, Scopes { smtp, api, hooks }, pool)
                    .await
            }
            Request::KeyRevoke { tenant, id } => self.key_revoke(tenant, id).await,
            Request::KeyList { tenant, from } => self.keys(tenant, from),
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
        Reply::new(Code::Ok, listed(lines, None))
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
        Reply::new(Code::Ok, listed(lines, None))
    }

    fn keys(&self, tenant: u32, from: u32) -> Reply {
        let table = self.node.table();
        let Some(current) = table.tenant(tenant).filter(|t| !t.state.deleted()) else {
            return tenant_not_found(tenant);
        };
        let generation = current.generation;
        let lines = table
            .accesses(tenant)
            .filter(move |a| a.id >= from && a.generation == generation)
            .map(|a| {
                let line = format!(
                    "key {} scopes {} pool {} generation {}\n",
                    a.id,
                    scope_list(a.scopes),
                    a.pool,
                    a.generation,
                );
                (a.id, line)
            });
        Reply::new(Code::Ok, listed(lines, None))
    }

    async fn key_create(&self, tenant: u32, scopes: Scopes, pool: u32) -> Reply {
        {
            let table = self.node.table();
            let Some(current) = table.tenant(tenant).filter(|t| !t.state.deleted()) else {
                return tenant_not_found(tenant);
            };
            if current.state != State::Active {
                return Reply::new(Code::Refused, format!("tenant {tenant} is not active"));
            }
        }
        let (access, secret) = match self.node.access_new(tenant, scopes, pool).await {
            Ok(created) => created,
            Err(error) => {
                let reply = key_failed(error);
                eprintln!(
                    "admin key create {tenant}: {:?} {}",
                    reply.code,
                    reply.text.trim_end()
                );
                return reply;
            }
        };
        let id = access.id;
        eprintln!("admin key create {tenant}: Ok id {id}");
        let secret = std::str::from_utf8(&secret).expect("access tokens are ASCII");
        let mut text = String::with_capacity(secret.len() + 24);
        let _ = write!(text, "key {id} secret ");
        text.push_str(secret);
        text.push('\n');
        Reply::new(Code::Ok, text)
    }

    async fn key_revoke(&self, tenant: u32, id: u32) -> Reply {
        {
            let table = self.node.table();
            if table
                .tenant(tenant)
                .is_none_or(|tenant| tenant.state.deleted())
            {
                return tenant_not_found(tenant);
            }
            let Some(access) = table.access(id).filter(|a| a.tenant == tenant) else {
                return key_not_found(tenant, id);
            };
            if table.gone(tenant, access.generation) {
                return key_not_found(tenant, id);
            }
        }
        let reply = match self.node.access_revoke(tenant, id).await {
            Ok(removal) => Reply::new(
                Code::Ok,
                format!("key {id} revoked, version {}\n", removal.version),
            ),
            Err(sched::Error::Control(control::Error::Refused)) => key_not_found(tenant, id),
            Err(error) => key_failed(error),
        };
        eprintln!(
            "admin key revoke {tenant} {id}: {:?} {}",
            reply.code,
            reply.text.trim_end()
        );
        reply
    }

    async fn queues(&self, tenant: u32, from: u32) -> Reply {
        let known = self
            .node
            .table()
            .tenant(tenant)
            .is_some_and(|t| !t.state.deleted());
        if !known {
            return Reply::new(Code::NotFound, format!("tenant {tenant} not found"));
        }
        let page = match self.node.queue_list(tenant, from).await {
            Ok(page) => page,
            Err(refusal) => return refused(tenant, 0, refusal),
        };
        let lines = page.rows.iter().map(|row| {
            let draining = if row.draining { " draining" } else { "" };
            let line = format!(
                "queue {} domain {} generation {} pool {} waiting {} in-flight {}{draining}\n",
                row.id,
                row.domain,
                row.generation,
                row.pool,
                row.waiting.recipients,
                row.waiting.in_flight,
            );
            (row.id, line)
        });
        Reply::new(Code::Ok, listed(lines, page.next))
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

fn scope_list(scopes: Scopes) -> String {
    let mut names = Vec::new();
    if scopes.smtp {
        names.push("smtp");
    }
    if scopes.api {
        names.push("api");
    }
    if scopes.hooks {
        names.push("hooks");
    }
    names.join(",")
}

fn tenant_not_found(tenant: u32) -> Reply {
    Reply::new(Code::NotFound, format!("tenant {tenant} not found"))
}

fn key_not_found(tenant: u32, id: u32) -> Reply {
    Reply::new(
        Code::NotFound,
        format!("key {id} of tenant {tenant} not found"),
    )
}

fn key_failed(error: sched::Error) -> Reply {
    match error {
        sched::Error::Control(control::Error::Busy) => {
            Reply::new(Code::Busy, "another change is being written")
        }
        sched::Error::Control(error @ (control::Error::Invalid(_) | control::Error::Refused)) => {
            Reply::new(Code::Refused, error.to_string())
        }
        error => Reply::new(Code::Failed, error.to_string()),
    }
}

fn queued(command: &str, tenant: u32, queue: u32, done: Result<QueueDone, QueueRefusal>) -> Reply {
    let reply = match done {
        Ok(QueueDone::Retried(waiting)) => Reply::new(
            Code::Ok,
            format!("queue {queue} retry now, {waiting} recipients waiting\n"),
        ),
        Ok(QueueDone::Rebound(id)) => {
            Reply::new(Code::Ok, format!("queue {queue} rebound, now queue {id}\n"))
        }
        Err(refusal) => refused(tenant, queue, refusal),
    };
    eprintln!(
        "admin {command}: {:?} {}",
        reply.code,
        reply.text.trim_end()
    );
    reply
}

fn refused(tenant: u32, queue: u32, refusal: QueueRefusal) -> Reply {
    match refusal {
        QueueRefusal::NotFound => Reply::new(
            Code::NotFound,
            format!("queue {queue} of tenant {tenant} not found"),
        ),
        QueueRefusal::Tenant => Reply::new(Code::Refused, format!("tenant {tenant} is not active")),
        QueueRefusal::Pool => Reply::new(
            Code::Refused,
            format!("pool not allowed for tenant {tenant}"),
        ),
        QueueRefusal::Draining => Reply::new(
            Code::Refused,
            format!("queue {queue} is draining into another queue"),
        ),
        QueueRefusal::Unanswered => Reply::new(Code::Failed, "a core did not answer"),
        QueueRefusal::Failed(error) => Reply::new(Code::Failed, error.to_string()),
    }
}

fn listed(lines: impl Iterator<Item = (u32, String)>, next: Option<u32>) -> String {
    let mut text = String::new();
    for (id, line) in lines {
        if text.len() + line.len() > LIST_BYTES {
            let _ = writeln!(text, "more from {id}");
            return text;
        }
        text.push_str(&line);
    }
    if let Some(next) = next {
        let _ = writeln!(text, "more from {next}");
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
