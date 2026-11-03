use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use keys::{Audit, Server, Settings, Vault};
use rt::{Native, Runtime, UnixListener};

const DAY_MS: u64 = 86_400_000;
const SOCKET_MODE: u32 = 0o666;

pub enum Command {
    Init {
        dir: PathBuf,
    },
    Run {
        dir: PathBuf,
        socket: PathBuf,
        engine: u32,
    },
}

pub const USAGE: &str =
    "usage: bunzzle keys init <dir>\n       bunzzle keys run <dir> <socket> <engine uid>";

impl Command {
    pub fn parse(args: &[String]) -> Option<Self> {
        match args {
            [init, dir] if init == "init" => Some(Self::Init { dir: dir.into() }),
            [run, dir, socket, engine] if run == "run" => Some(Self::Run {
                dir: dir.into(),
                socket: socket.into(),
                engine: engine.parse().ok()?,
            }),
            _ => None,
        }
    }
}

pub fn private_dir(dir: &Path, uid: u32) -> Result<(), String> {
    let meta = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != uid {
        return Err(format!("{} belongs to another user", dir.display()));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!("{} must have mode 0700", dir.display()));
    }
    Ok(())
}

pub fn socket_dir(socket: &Path, uid: u32) -> Result<(), String> {
    let parent = match socket.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let meta = fs::metadata(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    if meta.uid() != uid && meta.uid() != 0 {
        return Err(format!("{} belongs to another user", parent.display()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} must not be writable by group or others",
            parent.display()
        ));
    }
    Ok(())
}

pub fn clear_socket(socket: &Path) -> Result<(), String> {
    let meta = match fs::symlink_metadata(socket) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", socket.display())),
    };
    if !meta.file_type().is_socket() {
        return Err(format!("{} exists and is not a socket", socket.display()));
    }
    if std::os::unix::net::UnixStream::connect(socket).is_ok() {
        return Err(format!("keys already listens on {}", socket.display()));
    }
    fs::remove_file(socket).map_err(|e| format!("{}: {e}", socket.display()))
}

fn harden() -> Result<(), String> {
    sys::process::private_umask();
    sys::process::no_core_dumps().map_err(|e| format!("cannot turn off core dumps: {e}"))?;
    if let Err(e) = sys::process::lock_memory() {
        eprintln!("warning: memory not locked, secrets may reach swap: {e}");
    }
    Ok(())
}

fn runtime() -> Result<Runtime, String> {
    let driver = Native::new().map_err(|e| format!("cannot start the runtime: {e}"))?;
    Ok(Runtime::new(Rc::new(driver)))
}

pub fn run(command: Command) -> Result<(), String> {
    harden()?;
    let uid = sys::process::euid();
    match command {
        Command::Init { dir } => {
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
                    return Err(format!("{}: {e}", dir.display()));
                }
                _ => {}
            }
            private_dir(&dir, uid)?;
            let day = u32::try_from(wall_ms() / DAY_MS).unwrap_or(u32::MAX);
            runtime()?.block_on(async move {
                Vault::init(&dir, day)
                    .await
                    .map(drop)
                    .map_err(|e| e.to_string())
            })
        }
        Command::Run {
            dir,
            socket,
            engine,
        } => {
            if engine == uid {
                return Err("keys must run as another user than the engine".into());
            }
            private_dir(&dir, uid)?;
            socket_dir(&socket, uid)?;
            clear_socket(&socket)?;
            runtime()?.block_on(serve(dir, socket, engine))
        }
    }
}

fn wall_ms() -> u64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
}

async fn serve(dir: PathBuf, socket: PathBuf, engine: u32) -> Result<(), String> {
    let vault = Vault::open(&dir).await.map_err(|e| e.to_string())?;
    let audit = Audit::open(&dir).await.map_err(|e| e.to_string())?;
    let listener = UnixListener::bind(&socket)
        .await
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    let server = Server::start(vault, audit, Settings::default());
    server.listen(listener, engine);
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use super::{Command, clear_socket, private_dir, socket_dir};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bunzzle-keys-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn mode(dir: &PathBuf, mode: u32) {
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn parses_init_and_run() {
        let args = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(matches!(
            Command::parse(&args(&["init", "/k"])),
            Some(Command::Init { .. })
        ));
        assert!(matches!(
            Command::parse(&args(&["run", "/k", "/s", "80"])),
            Some(Command::Run { engine: 80, .. })
        ));
        assert!(Command::parse(&args(&["run", "/k", "/s", "x"])).is_none());
        assert!(Command::parse(&args(&["run", "/k"])).is_none());
        assert!(Command::parse(&args(&[])).is_none());
    }

    #[test]
    fn the_key_directory_must_be_private_and_ours() {
        let dir = scratch("private");
        let uid = sys::process::euid();
        mode(&dir, 0o700);
        assert!(private_dir(&dir, uid).is_ok());
        mode(&dir, 0o750);
        assert!(private_dir(&dir, uid).is_err());
        mode(&dir, 0o700);
        assert!(private_dir(&dir, uid.wrapping_add(1)).is_err());
        let file = dir.join("file");
        fs::write(&file, b"").expect("file");
        assert!(private_dir(&file, uid).is_err());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&dir, &link).expect("symlink");
        assert!(private_dir(&link, uid).is_err());
        fs::remove_dir_all(&dir).expect("clean");
    }

    #[test]
    fn the_socket_directory_must_not_be_shared() {
        let dir = scratch("socket-dir");
        let uid = sys::process::euid();
        let socket = dir.join("keys.sock");
        mode(&dir, 0o755);
        assert!(socket_dir(&socket, uid).is_ok());
        mode(&dir, 0o775);
        assert!(socket_dir(&socket, uid).is_err());
        mode(&dir, 0o757);
        assert!(socket_dir(&socket, uid).is_err());
        mode(&dir, 0o755);
        assert!(socket_dir(&socket, uid.wrapping_add(1)).is_err());
        fs::remove_dir_all(&dir).expect("clean");
    }

    #[test]
    fn stale_sockets_go_and_live_ones_stay() {
        let dir = scratch("stale");
        let socket = dir.join("keys.sock");
        assert!(clear_socket(&socket).is_ok());
        let live = UnixListener::bind(&socket).expect("bind");
        assert!(clear_socket(&socket).is_err());
        assert!(socket.exists());
        drop(live);
        assert!(clear_socket(&socket).is_ok());
        assert!(!socket.exists());
        fs::write(&socket, b"").expect("file");
        assert!(clear_socket(&socket).is_err());
        fs::remove_dir_all(&dir).expect("clean");
    }
}
