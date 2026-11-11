use std::fmt::Write;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use keys::{Audit, Listed, Server, Settings, Vault};
use rt::{Native, Runtime, UnixListener};

const DAY_MS: u64 = 86_400_000;
const SOCKET_MODE: u32 = 0o666;
const STICKY: u32 = 0o1000;

pub enum Command {
    Init {
        dir: PathBuf,
    },
    List {
        dir: PathBuf,
    },
    Run {
        dir: PathBuf,
        socket: PathBuf,
        engine: u32,
    },
}

pub const USAGE: &str = "usage: bunzzle keys init <dir>\n       bunzzle keys list <dir>\n       bunzzle keys run <dir> <socket> <engine uid>";

impl Command {
    pub fn parse(args: &[String]) -> Option<Self> {
        match args {
            [init, dir] if init == "init" => Some(Self::Init { dir: dir.into() }),
            [list, dir] if list == "list" => Some(Self::List { dir: dir.into() }),
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

pub fn socket_path(socket: &Path, uid: u32) -> Result<PathBuf, String> {
    let (Some(parent), Some(name)) = (socket.parent(), socket.file_name()) else {
        return Err(format!("{} is not a socket path", socket.display()));
    };
    if !socket.is_absolute() {
        return Err(format!("{} must be an absolute path", socket.display()));
    }
    let real = fs::canonicalize(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    for (depth, dir) in real.ancestors().enumerate() {
        let meta = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if meta.uid() != uid && meta.uid() != 0 {
            return Err(format!("{} belongs to another user", dir.display()));
        }
        let shared = meta.mode() & 0o022 != 0;
        if shared && (depth == 0 || meta.mode() & STICKY == 0) {
            return Err(format!(
                "{} must not be writable by group or others",
                dir.display()
            ));
        }
    }
    Ok(real.join(name))
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
    match sys::net::unix_connect(socket) {
        Ok(_) => Err(format!("keys already listens on {}", socket.display())),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            Err(format!("keys already listens on {}", socket.display()))
        }
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            fs::remove_file(socket).map_err(|e| format!("{}: {e}", socket.display()))
        }
        Err(e) => Err(format!("{}: {e}", socket.display())),
    }
}

pub fn lock(dir: &Path) -> Result<fs::File, String> {
    let path = dir.join("lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(keys::MODE)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => {
            Err(format!("another keys process uses {}", dir.display()))
        }
        Err(fs::TryLockError::Error(e)) => Err(format!("{}: {e}", path.display())),
    }
}

pub async fn bind(socket: &Path) -> Result<UnixListener, String> {
    let listener = UnixListener::bind(socket)
        .await
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    Ok(listener)
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
            let _lock = lock(&dir)?;
            let day = u32::try_from(wall_ms() / DAY_MS).unwrap_or(u32::MAX);
            runtime()?.block_on(async move {
                Vault::init(&dir, day)
                    .await
                    .map(drop)
                    .map_err(|e| e.to_string())
            })
        }
        Command::List { dir } => {
            private_dir(&dir, uid)?;
            let _lock = lock(&dir)?;
            let listed = runtime()?.block_on(async move {
                Vault::open(&dir)
                    .await
                    .map(|vault| (vault.day(), vault.listed()))
                    .map_err(|e| e.to_string())
            })?;
            print!("{}", listing(listed.0, &listed.1));
            Ok(())
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
            let _lock = lock(&dir)?;
            let socket = socket_path(&socket, uid)?;
            clear_socket(&socket)?;
            runtime()?.block_on(serve(dir, socket, engine))
        }
    }
}

pub fn listing(day: u32, listed: &[Listed]) -> String {
    let mut out = format!("day {day}\ntenant generation retention oldest\n");
    for entry in listed {
        let _ = writeln!(
            out,
            "{} {} {} {}",
            entry.tenant, entry.generation, entry.retention, entry.oldest
        );
    }
    out
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
    let listener = bind(&socket).await?;
    let signers = std::thread::available_parallelism().map_or(1, usize::from);
    let settings = Settings {
        signers,
        ..Settings::default()
    };
    let server = Server::start(vault, audit, settings);
    let error = server.listen(listener, engine).await;
    Err(format!("{}: {error}", socket.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use keys::Listed;

    use super::{Command, bind, clear_socket, listing, lock, private_dir, socket_path};

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
        assert!(matches!(
            Command::parse(&args(&["list", "/k"])),
            Some(Command::List { .. })
        ));
        assert!(Command::parse(&args(&["run", "/k", "/s", "x"])).is_none());
        assert!(Command::parse(&args(&["run", "/k"])).is_none());
        assert!(Command::parse(&args(&[])).is_none());
    }

    #[test]
    fn the_listing_shows_tenants_without_key_material() {
        let listed = [
            Listed {
                tenant: 4,
                generation: 2,
                retention: 30,
                oldest: 20_100,
            },
            Listed {
                tenant: 9,
                generation: 1,
                retention: 7,
                oldest: 20_110,
            },
        ];
        assert_eq!(
            listing(20_120, &listed),
            "day 20120\ntenant generation retention oldest\n4 2 30 20100\n9 1 7 20110\n"
        );
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
        let dir = fs::canonicalize(scratch("socket-dir")).expect("real");
        let uid = sys::process::euid();
        let socket = dir.join("keys.sock");
        mode(&dir, 0o755);
        assert_eq!(socket_path(&socket, uid), Ok(socket.clone()));
        mode(&dir, 0o775);
        assert!(socket_path(&socket, uid).is_err());
        mode(&dir, 0o1757);
        assert!(socket_path(&socket, uid).is_err());
        mode(&dir, 0o755);
        assert!(socket_path(&socket, uid.wrapping_add(1)).is_err());
        assert!(socket_path(std::path::Path::new("keys.sock"), uid).is_err());
        fs::remove_dir_all(&dir).expect("clean");
    }

    #[test]
    fn every_directory_above_the_socket_is_checked() {
        let dir = fs::canonicalize(scratch("ancestors")).expect("real");
        let uid = sys::process::euid();
        let inner = dir.join("inner");
        fs::create_dir(&inner).expect("inner");
        mode(&inner, 0o755);
        mode(&dir, 0o777);
        assert!(socket_path(&inner.join("keys.sock"), uid).is_err());
        mode(&dir, 0o1777);
        assert!(socket_path(&inner.join("keys.sock"), uid).is_ok());
        mode(&dir, 0o755);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&inner, &link).expect("symlink");
        assert_eq!(
            socket_path(&link.join("keys.sock"), uid),
            Ok(inner.join("keys.sock"))
        );
        fs::remove_dir_all(&dir).expect("clean");
    }

    #[test]
    fn one_process_holds_the_key_directory() {
        let dir = scratch("lock");
        let held = lock(&dir).expect("lock");
        assert!(lock(&dir).is_err());
        drop(held);
        assert!(lock(&dir).is_ok());
        fs::remove_dir_all(&dir).expect("clean");
    }

    #[test]
    fn the_socket_is_open_to_every_user() {
        let dir = scratch("bind");
        let socket = dir.join("keys.sock");
        let path = socket.clone();
        let driver = rt::Native::new().expect("driver");
        rt::Runtime::new(std::rc::Rc::new(driver)).block_on(async move {
            let _listener = bind(&path).await.expect("bind");
            let mode = fs::metadata(&path).expect("socket").permissions().mode();
            assert_eq!(mode & 0o777, 0o666);
        });
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
