use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use admin::{Code, Reply, Request};
use rt::{Native, Runtime};

pub const USAGE: &str = "usage: bunzzle admin <config> status";

const WAIT: Duration = Duration::from_secs(30);

pub fn parse(args: &[String]) -> Option<(&str, Request)> {
    match args {
        [config, command] if command == "status" => Some((config, Request::Status)),
        _ => None,
    }
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

    use admin::{Code, Handler, Reply, Request};
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

    #[test]
    fn parses_status_only() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            parse(&args(&["/etc/bunzzle.toml", "status"])),
            Some(("/etc/bunzzle.toml", Request::Status))
        );
        assert_eq!(parse(&args(&["/etc/bunzzle.toml"])), None);
        assert_eq!(parse(&args(&["/etc/bunzzle.toml", "other"])), None);
        assert_eq!(parse(&args(&["/etc/bunzzle.toml", "status", "x"])), None);
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
