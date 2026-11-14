use std::fs;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use keys::{Audit, Server, Settings, Vault};
use rt::{Native, Runtime, UnixListener};
use sched::{Answered, Attempt, Transport};
use store::{DataFile, Options, SLOT_SIZE};
use sys::signal::{Signal, raise};

const CHILD: &str = "NODE_NATIVE_CHILD";
const CHAIN: &[u8] = include_bytes!("data/a.pem");
const KEY: &[u8] = include_bytes!("data/a.key");
const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 96,
    shards: 4,
};

struct Idle;

impl Transport for Idle {
    fn send(&self, _: Attempt) -> impl Future<Output = Vec<Answered>> {
        std::future::ready(Vec::new())
    }
}

fn scratch_of(pid: u32) -> PathBuf {
    std::env::temp_dir().join(format!("node-native-{pid}"))
}

fn scratch() -> PathBuf {
    let dir = scratch_of(std::process::id());
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn runtime() -> Runtime {
    Runtime::new(Rc::new(Native::new().expect("driver")))
}

fn keys_up(dir: &Path, uid: u32) -> PathBuf {
    let socket = dir.join("keys.sock");
    let (bound, ready) = mpsc::channel();
    let (vault, at) = (dir.join("keys"), socket.clone());
    thread::spawn(move || {
        runtime().block_on(async move {
            fs::create_dir_all(&vault).expect("keys dir");
            let keys = Vault::init(&vault, 20_000).await.expect("init");
            let audit = Audit::open(&vault).await.expect("audit");
            let server = Server::start(keys, audit, Settings::default());
            let listener = UnixListener::bind(&at).await.expect("bind");
            bound.send(()).expect("bound");
            server.listen(listener, uid).await;
        });
    });
    ready.recv().expect("keys up");
    socket
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
    probe.local_addr().expect("address").port()
}

fn node_config(dir: &Path, address: SocketAddr) -> PathBuf {
    let uid = fs::metadata(dir).expect("dir").uid();
    let store = dir.join("store");
    let path = store.clone();
    runtime().block_on(async move {
        DataFile::create(&path, &OPTIONS).await.expect("create");
    });
    let socket = keys_up(dir, uid);
    let (chain, key) = (dir.join("a.pem"), dir.join("a.key"));
    fs::write(&chain, CHAIN).expect("chain");
    fs::write(&key, KEY).expect("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("mode");
    let config = dir.join("node.toml");
    let text = format!(
        "[node]\nid = 1\nname = \"mx1.example.net\"\ncores = 2\n\
         [store]\npath = \"{}\"\n\
         [keys]\nsocket = \"{}\"\nserver = {uid}\n\
         [tls]\nchain = \"{}\"\nkey = \"{}\"\n\
         [intake]\ndrain = \"1s\"\n\
         [[listen]]\naddress = \"{address}\"\n",
        store.display(),
        socket.display(),
        chain.display(),
        key.display(),
    );
    fs::write(&config, text).expect("config");
    config
}

#[test]
fn serve_boots_on_threads_and_stops_on_sigterm() {
    let dir = scratch();
    let address = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let config = node_config(&dir, address);

    let client = thread::spawn(move || {
        let mut stream = (0..300)
            .find_map(|_| {
                TcpStream::connect(address).ok().or_else(|| {
                    thread::sleep(Duration::from_millis(50));
                    None
                })
            })
            .expect("served");
        let mut banner = [0; 64];
        let read = stream.read(&mut banner).expect("banner");
        let banner = String::from_utf8_lossy(&banner[..read]).into_owned();
        raise(Signal::Terminate).expect("raise");
        banner
    });
    node::serve(&config, |_| Idle).expect("serve");
    let banner = client.join().expect("client");
    assert!(banner.starts_with("220 mx1.example.net"), "{banner}");
    assert!(TcpStream::connect(address).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_core_failing_to_start_exits_the_process_with_status_one() {
    let name = "a_core_failing_to_start_exits_the_process_with_status_one";
    if std::env::var_os(CHILD).is_some() {
        let dir = scratch();
        let held = std::net::TcpListener::bind("127.0.0.1:0").expect("hold");
        let config = node_config(&dir, held.local_addr().expect("address"));
        let ended = node::serve(&config, |_| Idle);
        panic!("serve returned {ended:?}");
    }
    let child = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("child");
    let dir = scratch_of(child.id());
    let output = child.wait_with_output().expect("exit");
    let _ = fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("listen on 127.0.0.1:"), "{stderr}");
}
