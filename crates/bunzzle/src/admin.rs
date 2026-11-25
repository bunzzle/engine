use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use admin::{Code, PoolSpec, Reply, Request, TenantSpec};
use rt::{Native, Runtime};

pub const USAGE: &str = "usage: bunzzle admin <config> status
       bunzzle admin <config> tenant list [from <id>]
       bunzzle admin <config> tenant create <id> <pool>[,<pool>...] [rate=<n>] [burst=<n>] [connections=<n>] [queued=<n>]
       bunzzle admin <config> tenant suspend <id>
       bunzzle admin <config> tenant resume <id>
       bunzzle admin <config> pool list [from <id>]
       bunzzle admin <config> pool set <id> <ip>=<weight>[,<ip>=<weight>...]
       bunzzle admin <config> queue list <tenant> [from <id>]
       bunzzle admin <config> queue retry <tenant> <queue>
       bunzzle admin <config> queue rebind <tenant> <queue> <pool>
       bunzzle admin <config> key create <tenant> <scopes> [pool <id>]
       bunzzle admin <config> key revoke <tenant> <id>
       bunzzle admin <config> key list <tenant> [from <id>]";

const MAX_ITEMS: usize = 255;

const WAIT: Duration = Duration::from_secs(90);

pub fn parse(args: &[String]) -> Option<(&str, Request)> {
    let (config, rest) = args.split_first()?;
    let words: Vec<&str> = rest.iter().map(String::as_str).collect();
    let request = match words.as_slice() {
        ["status"] => Request::Status,
        ["tenant", "list"] => Request::TenantList(0),
        ["tenant", "list", "from", id] => Request::TenantList(id.parse().ok()?),
        ["pool", "list"] => Request::PoolList(0),
        ["pool", "list", "from", id] => Request::PoolList(id.parse().ok()?),
        ["queue", "list", tenant] => Request::QueueList {
            tenant: tenant.parse().ok()?,
            from: 0,
        },
        ["queue", "list", tenant, "from", from] => Request::QueueList {
            tenant: tenant.parse().ok()?,
            from: from.parse().ok()?,
        },
        ["queue", "retry", tenant, queue] => Request::QueueRetry {
            tenant: tenant.parse().ok()?,
            queue: queue.parse().ok()?,
        },
        ["queue", "rebind", tenant, queue, pool] => Request::QueueRebind {
            tenant: tenant.parse().ok()?,
            queue: queue.parse().ok()?,
            pool: pool.parse().ok()?,
        },
        ["key", "create", tenant, scopes] => key_create(tenant, scopes, 0)?,
        ["key", "create", tenant, scopes, "pool", pool] => {
            key_create(tenant, scopes, pool.parse().ok()?)?
        }
        ["key", "revoke", tenant, id] => Request::KeyRevoke {
            tenant: tenant.parse().ok()?,
            id: id.parse().ok()?,
        },
        ["key", "list", tenant] => Request::KeyList {
            tenant: tenant.parse().ok()?,
            from: 0,
        },
        ["key", "list", tenant, "from", from] => Request::KeyList {
            tenant: tenant.parse().ok()?,
            from: from.parse().ok()?,
        },
        ["tenant", "suspend", id] => Request::TenantSuspend(id.parse().ok()?),
        ["tenant", "resume", id] => Request::TenantResume(id.parse().ok()?),
        ["tenant", "create", id, pools, options @ ..] => {
            Request::TenantCreate(tenant(id, pools, options)?)
        }
        ["pool", "set", id, addresses] => Request::PoolSet(PoolSpec {
            id: id.parse().ok()?,
            addresses: list(addresses, |item| {
                let (ip, weight) = item.split_once('=')?;
                Some((ip.parse().ok()?, weight.parse().ok()?))
            })?,
        }),
        _ => return None,
    };
    Some((config, request))
}

fn tenant(id: &str, pools: &str, options: &[&str]) -> Option<TenantSpec> {
    let mut spec = TenantSpec {
        id: id.parse().ok()?,
        pools: list(pools, |pool| pool.parse().ok())?,
        ..TenantSpec::default()
    };
    let mut seen = Vec::new();
    for option in options {
        let (name, value) = option.split_once('=')?;
        if seen.contains(&name) {
            return None;
        }
        seen.push(name);
        match name {
            "rate" => spec.rate = value.parse().ok()?,
            "burst" => spec.burst = value.parse().ok()?,
            "connections" => spec.connections = value.parse().ok()?,
            "queued" => spec.queued = value.parse().ok()?,
            _ => return None,
        }
    }
    Some(spec)
}

fn key_create(tenant: &str, scopes: &str, pool: u32) -> Option<Request> {
    let mut smtp = false;
    let mut api = false;
    let mut hooks = false;
    for scope in scopes.split(',') {
        let seen = match scope {
            "smtp" => &mut smtp,
            "api" => &mut api,
            "hooks" => &mut hooks,
            _ => return None,
        };
        if *seen {
            return None;
        }
        *seen = true;
    }
    Some(Request::KeyCreate {
        tenant: tenant.parse().ok()?,
        smtp,
        api,
        hooks,
        pool,
    })
}

fn list<T>(text: &str, item: impl Fn(&str) -> Option<T>) -> Option<Vec<T>> {
    let items: Vec<T> = text.split(',').map(item).collect::<Option<_>>()?;
    (items.len() <= MAX_ITEMS).then_some(items)
}

pub fn exit(reply: &Reply) -> ExitCode {
    match reply.code {
        Code::Ok => ExitCode::SUCCESS,
        Code::Refused | Code::NotFound => ExitCode::from(1),
        Code::Busy | Code::Failed => ExitCode::from(2),
    }
}

pub fn run(config: &Path, request: &Request) -> Result<Reply, String> {
    let text = fs::read_to_string(config).map_err(|e| format!("{}: {e}", config.display()))?;
    let parsed = node::parse(&text).map_err(|e| format!("{}: {e}", config.display()))?;
    let Some(settings) = parsed.admin else {
        return Err(format!("{}: no [admin] section", config.display()));
    };
    let meta = fs::symlink_metadata(&settings.socket)
        .map_err(|e| format!("{}: {e}", settings.socket.display()))?;
    let owner = meta.uid();
    let socket = node::socket_path(&settings.socket, owner)?;
    let driver = Native::new().map_err(|e| format!("cannot start the runtime: {e}"))?;
    let request = request.clone();
    Runtime::new(Rc::new(driver)).block_on(async move {
        admin::call(&socket, owner, &request, WAIT)
            .await
            .map_err(|e| format!("{}: {e}", socket.display()))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use admin::{Code, Handler, PoolSpec, Reply, Request, TenantSpec};
    use rt::{Native, Runtime, UnixListener, sleep, yield_now};

    use super::{exit, parse, run};

    const CONFIG: &str = "[node]\nid = 7\nname = \"mx.example.org\"\n[store]\npath = \"/var/lib/bunzzle\"\n\
        [keys]\nsocket = \"/run/bunzzle/keys.sock\"\n[tls]\nchain = \"/etc/c.pem\"\nkey = \"/etc/k.pem\"\n\
        [dns]\nservers = [\"127.0.0.1\"]\n[[listen]]\naddress = \"0.0.0.0:25\"\n";

    struct Fixed;

    impl Handler for Fixed {
        async fn handle(&self, _: Request) -> Reply {
            yield_now().await;
            Reply::new(Code::Ok, "node 7\n")
        }
    }

    #[test]
    fn status_reaches_a_live_admin_socket() {
        let dir = std::env::temp_dir().join(format!("bunzzle-admin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        let dir = fs::canonicalize(&dir).expect("real");
        let socket = dir.join("a.sock");
        let config = dir.join("c.toml");
        fs::write(&config, CONFIG).expect("write");
        let missing = run(&config, &Request::Status).expect_err("no section");
        assert!(missing.ends_with("no [admin] section"), "{missing}");
        fs::write(
            &config,
            format!("{CONFIG}[admin]\nsocket = \"{}\"\n", socket.display()),
        )
        .expect("write");
        assert!(run(&config, &Request::Status).is_err());
        let (ready, wait) = mpsc::channel();
        let path = socket.clone();
        thread::spawn(move || {
            let driver = Native::new().expect("runtime");
            Runtime::new(Rc::new(driver)).block_on(async move {
                let listener = UnixListener::bind(&path).await.expect("bind");
                let served = admin::serve(listener, vec![sys::process::euid()], Rc::new(Fixed));
                ready.send(()).expect("ready");
                sleep(Duration::from_secs(600)).await;
                served.close().await;
            });
        });
        wait.recv().expect("ready");
        let reply = run(&config, &Request::Status).expect("reply");
        assert_eq!(reply, Reply::new(Code::Ok, "node 7\n"));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).expect("chmod");
        assert!(run(&config, &Request::Status).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn parsed(list: &[&str]) -> Option<Request> {
        let mut all = vec!["/etc/bunzzle.toml"];
        all.extend_from_slice(list);
        parse(&args(&all)).map(|(config, request)| {
            assert_eq!(config, "/etc/bunzzle.toml");
            request
        })
    }

    #[test]
    fn parses_every_command() {
        assert_eq!(parsed(&["status"]), Some(Request::Status));
        assert_eq!(parsed(&["tenant", "list"]), Some(Request::TenantList(0)));
        assert_eq!(
            parsed(&["tenant", "list", "from", "9"]),
            Some(Request::TenantList(9))
        );
        assert_eq!(parsed(&["pool", "list"]), Some(Request::PoolList(0)));
        assert_eq!(
            parsed(&["queue", "list", "5"]),
            Some(Request::QueueList { tenant: 5, from: 0 })
        );
        assert_eq!(
            parsed(&["queue", "list", "5", "from", "40"]),
            Some(Request::QueueList {
                tenant: 5,
                from: 40
            })
        );
        assert_eq!(
            parsed(&["queue", "retry", "5", "40"]),
            Some(Request::QueueRetry {
                tenant: 5,
                queue: 40
            })
        );
        assert_eq!(
            parsed(&["queue", "rebind", "5", "40", "2"]),
            Some(Request::QueueRebind {
                tenant: 5,
                queue: 40,
                pool: 2
            })
        );
        assert_eq!(
            parsed(&["key", "create", "5", "hooks,smtp,api"]),
            Some(Request::KeyCreate {
                tenant: 5,
                smtp: true,
                api: true,
                hooks: true,
                pool: 0,
            })
        );
        assert_eq!(
            parsed(&["key", "create", "5", "api", "pool", "2"]),
            Some(Request::KeyCreate {
                tenant: 5,
                smtp: false,
                api: true,
                hooks: false,
                pool: 2,
            })
        );
        assert_eq!(
            parsed(&["key", "revoke", "5", "9"]),
            Some(Request::KeyRevoke { tenant: 5, id: 9 })
        );
        assert_eq!(
            parsed(&["key", "list", "5"]),
            Some(Request::KeyList { tenant: 5, from: 0 })
        );
        assert_eq!(
            parsed(&["key", "list", "5", "from", "9"]),
            Some(Request::KeyList { tenant: 5, from: 9 })
        );
        assert_eq!(parsed(&["queue", "list"]), None);
        assert_eq!(parsed(&["queue", "retry", "5"]), None);
        assert_eq!(
            parsed(&["pool", "list", "from", "3"]),
            Some(Request::PoolList(3))
        );
        assert_eq!(
            parsed(&["tenant", "suspend", "7"]),
            Some(Request::TenantSuspend(7))
        );
        assert_eq!(
            parsed(&["tenant", "resume", "7"]),
            Some(Request::TenantResume(7))
        );
        assert_eq!(
            parsed(&["tenant", "create", "7", "2,1", "queued=10", "connections=3"]),
            Some(Request::TenantCreate(TenantSpec {
                id: 7,
                pools: vec![2, 1],
                connections: 3,
                queued: 10,
                ..TenantSpec::default()
            }))
        );
        assert_eq!(
            parsed(&["pool", "set", "1", "192.0.2.1=1,2001:db8::1=3"]),
            Some(Request::PoolSet(PoolSpec {
                id: 1,
                addresses: vec![
                    ("192.0.2.1".parse().expect("ip"), 1),
                    ("2001:db8::1".parse().expect("ip"), 3),
                ],
            }))
        );
    }

    #[test]
    fn refuses_bad_commands() {
        for bad in [
            &[][..],
            &["status", "x"],
            &["other"],
            &["tenant", "suspend", "x"],
            &["tenant", "suspend", "-1"],
            &["tenant", "create", "7"],
            &["tenant", "create", "7", "1,x"],
            &["tenant", "create", "7", "1", "rate"],
            &["tenant", "create", "7", "1", "colour=3"],
            &["tenant", "create", "7", "1", "rate=1", "rate=2"],
            &["pool", "set", "1", "192.0.2.1"],
            &["pool", "set", "1", "192.0.2.1=70000"],
            &["pool", "set", "1", "host=1"],
            &["key", "create", "5", ""],
            &["key", "create", "5", "smtp,smtp"],
            &["key", "create", "5", "smtp,unknown"],
            &["key", "create", "5", "smtp", "pool"],
            &["key", "create", "5", "smtp", "pool=2"],
            &["key", "revoke", "5"],
            &["key", "list", "5", "from"],
        ] {
            assert_eq!(parsed(bad), None, "{bad:?}");
        }
        let many: Vec<String> = (0..256).map(|n| n.to_string()).collect();
        assert_eq!(parsed(&["tenant", "create", "7", &many.join(",")]), None);
        assert_eq!(parse(&[]), None);
    }

    #[test]
    fn codes_map_to_exit_codes() {
        for (code, want) in [
            (Code::Ok, std::process::ExitCode::SUCCESS),
            (Code::Refused, std::process::ExitCode::from(1)),
            (Code::NotFound, std::process::ExitCode::from(1)),
            (Code::Busy, std::process::ExitCode::from(2)),
            (Code::Failed, std::process::ExitCode::from(2)),
        ] {
            assert_eq!(exit(&Reply::new(code, "")), want);
        }
    }
}
