use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use keys::{Audit, Server, Settings, Vault};
use node::{Config, Error, Plan, naming, parse, run};
use rt::sim::{Config as SimConfig, Machine, SimDriver, Stalls};
use rt::{Buf, JoinHandle, Signal, TcpStream, UnixListener, sleep, timeout};
use sched::{Answered, Attempt, Transport};
use store::{Committer, DataFile, Options, SLOT_SIZE, Setup, boot};
use tls::{Certs, simulated};

const PATH: &str = "/data/store";
const KEYS: &str = "/keys";
const SOCKET: &str = "/run/keys.sock";
const UID: u32 = 1000;
const CORES: u16 = 2;
const SMTP: &str = "10.0.0.1:587";
const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 96,
    shards: 8,
};
const CHAIN: &[u8] = include_bytes!("data/a.pem");
const KEY: &[u8] = include_bytes!("data/a.key");

struct Idle;

impl Transport for Idle {
    fn send(&self, _: Attempt) -> impl Future<Output = Vec<Answered>> {
        std::future::ready(Vec::new())
    }
}

fn config(id: u32) -> Config {
    let text = format!(
        "[node]\nid = {id}\nname = \"mx1.example.net\"\ncores = {CORES}\nboot_deadline = \"30s\"\n\
         [store]\npath = \"{PATH}\"\n\
         [keys]\nsocket = \"{SOCKET}\"\nserver = {UID}\n\
         [tls]\nchain = \"/etc/a.pem\"\nkey = \"/etc/a.key\"\n\
         [intake]\ndrain = \"2s\"\n\
         [[listen]]\naddress = \"{SMTP}\"\n"
    );
    parse(&text).expect("config")
}

fn created(seed: u64) -> Rc<SimDriver> {
    let driver = Rc::new(SimDriver::new(seed, SimConfig::default()));
    driver.set_uid(UID);
    let erased: Rc<dyn rt::Driver> = driver.clone();
    rt::Runtime::new(erased).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    driver
}

fn keys_up(machine: &Machine) {
    let (server, listener) = machine.block_on(0, async {
        let dir = Path::new(KEYS);
        let vault = match Vault::open(dir).await {
            Ok(vault) => vault,
            Err(_) => Vault::init(dir, 20_000).await.expect("init"),
        };
        let audit = Audit::open(dir).await.expect("audit");
        let server = Server::start(vault, audit, Settings::default());
        let listener = UnixListener::bind(Path::new(SOCKET)).await.expect("bind");
        (server, listener)
    });
    drop(machine.spawn_on(0, async move {
        server.listen(listener, UID).await;
    }));
}

struct Booted {
    machine: Machine,
    cores: Vec<JoinHandle<Result<(), Error>>>,
    committer: JoinHandle<Committer>,
}

fn booted(driver: &Rc<SimDriver>, config: Config, cores: u16) -> Booted {
    let machine = Machine::new(Rc::clone(driver), usize::from(CORES) + 1, Stalls::default());
    keys_up(&machine);
    let probe = config.clone();
    let naming = machine
        .block_on(0, async move { naming(&probe).await })
        .expect("naming");
    let setup = Setup {
        cores: CORES,
        credits: 4,
        reserve: 4,
        flush: 1,
    };
    let store = machine.block_on(0, boot(PATH, setup)).expect("boot");
    let committer = machine.spawn_on(0, store.committer.run());
    drop(store.client);
    let certs = Arc::new(Certs::new(CHAIN, KEY).expect("certs"));
    let plan = Arc::new(Plan::new(config, certs, simulated(5), naming, [7; 16]));
    let cores = store
        .starts
        .into_iter()
        .take(usize::from(cores))
        .map(|start| {
            let plan = Arc::clone(&plan);
            let core = usize::from(start.index()) + 1;
            machine.spawn_on(core, async move {
                let core = start.open().await.map_err(Error::Store)?;
                run(core, plan, Idle).await
            })
        })
        .collect();
    Booted {
        machine,
        cores,
        committer,
    }
}

async fn banner(stream: &TcpStream) -> String {
    let (read, buf) = stream.read(Buf::new(512)).await;
    let read = read.expect("read");
    String::from_utf8_lossy(&buf[..read]).into_owned()
}

fn smtp() -> SocketAddr {
    SMTP.parse().expect("address")
}

async fn serving() -> TcpStream {
    for _ in 0..600 {
        if let Ok(stream) = TcpStream::connect(smtp()).await {
            return stream;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("never served");
}

fn stopped(driver: &Rc<SimDriver>, node: Booted) {
    let Booted {
        machine,
        cores,
        committer,
    } = node;
    let signals = Rc::clone(driver);
    machine.block_on(0, async move {
        drop(serving().await);
        signals.raise(Signal::Terminate);
        for core in cores {
            core.await.expect("stopped");
        }
        drop(committer.await);
    });
}

#[test]
fn a_node_boots_serves_and_drains_on_sigterm() {
    let driver = created(1);
    let node = booted(&driver, config(7), CORES);
    let signals = Rc::clone(&driver);
    let Booted {
        machine,
        cores,
        committer,
    } = node;
    machine.block_on(0, async move {
        let first = serving().await;
        assert!(banner(&first).await.starts_with("220 mx1.example.net"));
        drop(first);
        let open = TcpStream::connect(smtp()).await.expect("connect");
        assert!(banner(&open).await.starts_with("220 "));
        let asked = rt::now();
        signals.raise(Signal::Terminate);
        loop {
            let (read, _) = open.read(Buf::new(512)).await;
            if read.expect("read") == 0 {
                break;
            }
        }
        assert!(rt::now().saturating_duration_since(asked) >= Duration::from_secs(2));
        for core in cores {
            core.await.expect("stopped");
        }
        drop(committer.await);
        assert!(TcpStream::connect(smtp()).await.is_err());
    });
}

#[test]
fn a_core_that_fails_to_start_fails_the_boot() {
    let driver = created(2);
    stopped(&driver, booted(&driver, config(7), CORES));
    let driver = Rc::new(SimDriver::with_disk(
        3,
        SimConfig::default(),
        driver.crash(),
    ));
    driver.set_uid(UID);
    let Booted {
        machine, mut cores, ..
    } = booted(&driver, config(8), CORES);
    let first = cores.remove(0);
    let failed = machine.block_on(0, first);
    assert!(
        matches!(&failed, Err(Error::Core(_, message)) if message.contains("node id")),
        "{failed:?}"
    );
}

#[test]
fn a_core_that_never_starts_fails_the_boot_at_the_deadline() {
    let driver = created(4);
    let Booted {
        machine, mut cores, ..
    } = booted(&driver, config(7), 1);
    let first = cores.remove(0);
    let (failed, waited) = machine.block_on(0, async move {
        let started = rt::now();
        (first.await, rt::now().saturating_duration_since(started))
    });
    assert!(matches!(failed, Err(Error::Deadline)), "{failed:?}");
    assert!(waited >= Duration::from_secs(29), "{waited:?}");
}

#[test]
fn boot_stops_when_keys_does_not_answer() {
    let driver = created(6);
    let machine = Machine::new(Rc::clone(&driver), 1, Stalls::default());
    let config = config(7);
    let failed = machine.block_on(0, async move {
        timeout(Duration::from_secs(60), naming(&config)).await
    });
    assert!(matches!(failed, Ok(Err(Error::Keys(_)))), "{failed:?}");
}
