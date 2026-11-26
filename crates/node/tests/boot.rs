use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use intake::Conn;
use keys::{Audit, Server, Settings, Vault};
use node::{Config, Error, Plan, naming, parse, run};
use rt::sim::{Config as SimConfig, Machine, SimDriver, Stalls, check};
use rt::{Buf, JoinHandle, Signal, TcpStream, UnixListener, sleep, spawn, timeout};
use sched::{Answered, Attempt, OwnStats, Transport};
use store::{Committer, DataFile, Options, SLOT_SIZE, Setup, boot};
use tls::rustls::client::Resumption;
use tls::rustls::pki_types::pem::PemObject;
use tls::rustls::pki_types::{CertificateDer, ServerName};
use tls::rustls::{ClientConfig, ClientConnection, RootCertStore};
use tls::{Certs, Clock as TlsClock, Stream, simulated};

const PATH: &str = "/data/store";
const KEYS: &str = "/keys";
const SOCKET: &str = "/run/keys.sock";
const UID: u32 = 1000;
const CORES: u16 = 2;
const SMTP: &str = "10.0.0.1:587";
const API: &str = "127.0.0.1:8080";
const METRICS: &str = "127.0.0.1:9464";
const ADMIN: &str = "/run/admin.sock";
const WAIT: Duration = Duration::from_secs(5);
const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 96,
    shards: 8,
};
const CHAIN: &[u8] = include_bytes!("data/a.pem");
const KEY: &[u8] = include_bytes!("data/a.key");
const CA: &[u8] = include_bytes!("data/ca.pem");

struct Idle;

impl Transport for Idle {
    fn send(&self, _: Attempt) -> impl Future<Output = Vec<Answered>> {
        std::future::ready(Vec::new())
    }
}

struct Probed {
    calls: Arc<AtomicUsize>,
}

impl Transport for Probed {
    fn send(&self, _: Attempt) -> impl Future<Output = Vec<Answered>> {
        std::future::ready(Vec::new())
    }

    fn probe_own(&self) -> impl Future<Output = OwnStats> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        std::future::ready(OwnStats {
            ipv4_off: false,
            ipv6_off: true,
            unclear: 5,
            partly_refused: 0,
        })
    }
}

fn config(id: u32) -> Config {
    config_with(id, "")
}

fn config_with(id: u32, extra: &str) -> Config {
    let text = format!(
        "[node]\nid = {id}\nname = \"mx1.example.net\"\ncores = {CORES}\nboot_deadline = \"30s\"\n\
         [store]\npath = \"{PATH}\"\n\
         [keys]\nsocket = \"{SOCKET}\"\nserver = {UID}\n\
         [tls]\nchain = \"/etc/a.pem\"\nkey = \"/etc/a.key\"\n\
         [intake]\ndrain = \"2s\"\n\
         [api]\nplain = [\"{API}\"]\ndrain = \"2s\"\n\
         [metrics]\nlisten = [\"{METRICS}\"]\n\
         [dns]\nservers = [\"127.0.0.1\"]\n\
         [[listen]]\naddress = \"{SMTP}\"\n{extra}"
    );
    parse(&text).expect("config")
}

fn created(seed: u64) -> Rc<SimDriver> {
    created_with(seed, SimConfig::default())
}

fn created_with(seed: u64, config: SimConfig) -> Rc<SimDriver> {
    let driver = Rc::new(SimDriver::new(seed, config));
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
    let certs = Arc::new(Certs::new(CHAIN, KEY).expect("certs"));
    let plan = Arc::new(Plan::new(config, certs, simulated(5), naming, [7; 16]).with_engine(UID));
    let mut committer = store.committer;
    if let Some(slab) = plan.metrics().and_then(|board| board.node()) {
        committer.observe(Arc::clone(slab));
    }
    let committer = machine.spawn_on(0, committer.run());
    drop(store.client);
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

fn probed(driver: &Rc<SimDriver>, config: Config, cores: u16, calls: &Arc<AtomicUsize>) -> Booted {
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
    let certs = Arc::new(Certs::new(CHAIN, KEY).expect("certs"));
    let plan = Arc::new(Plan::new(config, certs, simulated(5), naming, [7; 16]));
    let mut committer = store.committer;
    if let Some(slab) = plan.metrics().and_then(|board| board.node()) {
        committer.observe(Arc::clone(slab));
    }
    let committer = machine.spawn_on(0, committer.run());
    drop(store.client);
    let cores = store
        .starts
        .into_iter()
        .take(usize::from(cores))
        .map(|start| {
            let plan = Arc::clone(&plan);
            let calls = Arc::clone(calls);
            let core = usize::from(start.index()) + 1;
            machine.spawn_on(core, async move {
                let core = start.open().await.map_err(Error::Store)?;
                run(core, plan, Probed { calls }).await
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

async fn health() -> String {
    let stream = TcpStream::connect(API.parse().expect("address"))
        .await
        .expect("connect");
    let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream
        .write_all(Buf::from_slice(request))
        .await
        .0
        .expect("write");
    let (read, buf) = stream.read(Buf::new(512)).await;
    let n = read.expect("read");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

async fn scrape(request: &str) -> String {
    let stream = TcpStream::connect(METRICS.parse().expect("address"))
        .await
        .expect("connect");
    stream
        .write_all(Buf::from_slice(request.as_bytes()))
        .await
        .0
        .expect("write");
    let mut out = Vec::new();
    loop {
        let (read, buf) = stream.read(Buf::new(4096)).await;
        let n = read.expect("read");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    String::from_utf8(out).expect("utf-8")
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
        let first = serving().await;
        assert!(banner(&first).await.starts_with("220 "));
        drop(first);
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
        assert!(health().await.starts_with("HTTP/1.1 200 OK\r\n"));
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
        assert!(
            TcpStream::connect(API.parse().expect("address"))
                .await
                .is_err()
        );
    });
}

#[test]
fn boot_probes_own_addresses_on_every_core() {
    let driver = created(11);
    let calls = Arc::new(AtomicUsize::new(0));
    let Booted {
        machine,
        cores,
        committer,
    } = probed(&driver, config(7), CORES, &calls);
    let signals = Rc::clone(&driver);
    machine.block_on(0, async move {
        drop(serving().await);
        assert_eq!(calls.load(Ordering::Relaxed), usize::from(CORES));
        signals.raise(Signal::Terminate);
        for core in cores {
            core.await.expect("stopped");
        }
        drop(committer.await);
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

#[test]
fn a_failed_signal_watch_stops_the_node_with_the_error() {
    let driver = created(8);
    let signals = Rc::clone(&driver);
    let Booted {
        machine,
        cores,
        committer,
    } = booted(&driver, config(7), CORES);
    machine.block_on(0, async move {
        drop(serving().await);
        signals.fail_signals();
        let mut cores = cores.into_iter();
        let first = cores.next().expect("core 0").await;
        assert!(matches!(first, Err(Error::Io(_))), "{first:?}");
        for core in cores {
            core.await.expect("stopped");
        }
        drop(committer.await);
        assert!(TcpStream::connect(smtp()).await.is_err());
        assert!(
            TcpStream::connect(API.parse().expect("address"))
                .await
                .is_err()
        );
    });
}

#[test]
fn a_connection_queued_during_boot_waits_for_every_core() {
    check(0..10, |seed| {
        let slow = SimConfig {
            io_latency: (Duration::from_millis(1), Duration::from_millis(50)),
            ..SimConfig::default()
        };
        let driver = created_with(seed, slow);
        let probe = Rc::clone(&driver);
        let Booted {
            machine,
            cores,
            committer,
        } = booted(&driver, config(7), CORES);
        let machine = Rc::new(machine);
        let threads = Rc::clone(&machine);
        machine.block_on(0, async move {
            while probe.listening(smtp()) == 0 {
                sleep(Duration::from_micros(100)).await;
            }
            assert_eq!(probe.listening(smtp()), 1);
            let held = rt::now();
            threads.pause(1, Duration::from_secs(5));
            while probe.listening(smtp()) < 2 {
                sleep(Duration::from_micros(100)).await;
            }
            let mut served = Vec::new();
            for _ in 0..8 {
                let queued = TcpStream::connect(smtp()).await.expect("connect");
                served.push(spawn(async move {
                    assert!(banner(&queued).await.starts_with("220 mx1.example.net"));
                    rt::now()
                }));
            }
            for at in served {
                assert!(at.await.saturating_duration_since(held) >= Duration::from_secs(5));
            }
            probe.raise(Signal::Terminate);
            for core in cores {
                core.await.expect("stopped");
            }
            drop(committer.await);
        });
    });
}

#[test]
fn metrics_are_served_for_every_core() {
    let driver = created(9);
    let node = booted(&driver, config(7), CORES);
    let machine = &node.machine;
    machine.block_on(0, async {
        drop(serving().await);
        sleep(Duration::from_secs(2)).await;
        let text = scrape("GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"));
        for core in 0..CORES {
            assert!(text.contains(&format!("bunzzle_core_up{{core=\"{core}\"}} 1\n")));
            assert!(text.contains(&format!("bunzzle_queue_recipients{{core=\"{core}\"}} 0\n")));
        }
        assert!(text.contains("# TYPE bunzzle_smtp_refused_total counter\n"));
        assert!(text.contains("bunzzle_recipients_delivered_total{core=\"0\"} 0\n"));
        assert!(text.contains("# TYPE bunzzle_paths_down gauge\n"));
        assert!(text.contains("# TYPE bunzzle_store_commit_seconds histogram\n"));
        assert!(text.contains("bunzzle_store_sync_seconds_bucket{le=\"+Inf\"} "));
        assert!(text.contains("bunzzle_store_failed 0\n"));
        assert!(text.contains("bunzzle_store_write_started_seconds 0\n"));
        assert!(!text.contains("store_commits_total{"));
        assert!(!text.contains("# EOF"));

        let open = scrape(
            "GET /metrics HTTP/1.1\r\nHost: x\r\nAccept: application/openmetrics-text;version=1.0.0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(open.contains("Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\n"));
        assert!(open.contains("# TYPE bunzzle_smtp_refused counter\n"));
        assert!(open.ends_with("# EOF\n"));

        let head = scrape("HEAD /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        let missing = scrape("GET /other HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        assert!(missing.starts_with("HTTP/1.1 404 "));
        let posted = scrape("POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        assert!(posted.starts_with("HTTP/1.1 405 "));
        assert!(posted.contains("Allow: GET, HEAD\r\n"));
        let piped = scrape(
            "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\nGET /metrics HTTP/1.1\r\nHost: x\r\n\r\nGET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(piped.matches("HTTP/1.1 200 OK\r\n").count(), 3);
        assert_eq!(piped.matches("bunzzle_core_up{core=\"0\"} 1\n").count(), 3);
        let broken = scrape("GARBAGE\r\n\r\n").await;
        assert!(broken.starts_with("HTTP/1.1 400 "));
    });
    stopped(&driver, node);
}

#[test]
fn guard_and_webhook_metrics_follow_open_sessions() {
    let driver = created(10);
    let node = booted(&driver, config(7), CORES);
    let machine = &node.machine;
    machine.block_on(0, async {
        let held = serving().await;
        assert!(banner(&held).await.starts_with("220 "));
        sleep(Duration::from_secs(2)).await;
        let text = scrape("GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        let sessions: u64 = text
            .lines()
            .filter_map(|line| line.strip_prefix("bunzzle_guard_sessions{"))
            .filter_map(|rest| rest.split(' ').nth(1)?.parse::<u64>().ok())
            .sum();
        assert_eq!(sessions, 1, "{text}");
        for family in [
            "# TYPE bunzzle_guard_reserved_bytes gauge\n",
            "# TYPE bunzzle_guard_open_limit_total counter\n",
            "# TYPE bunzzle_guard_session_limit_total counter\n",
            "# TYPE bunzzle_webhook_acked_total counter\n",
            "# TYPE bunzzle_webhook_streams gauge\n",
            "# TYPE bunzzle_webhooks_disabled_gone_total counter\n",
        ] {
            assert!(text.contains(family), "{family}");
        }
        drop(held);
        sleep(Duration::from_secs(2)).await;
        let text = scrape("GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        for core in 0..CORES {
            assert!(text.contains(&format!("bunzzle_guard_sessions{{core=\"{core}\"}} 0\n")));
        }
    });
    stopped(&driver, node);
}

#[test]
fn a_connection_over_the_address_limit_is_counted() {
    let driver = created(11);
    let node = booted(&driver, config_with(7, "[guard]\nper_net = 1\n"), CORES);
    let machine = &node.machine;
    machine.block_on(0, async {
        let held = serving().await;
        assert!(banner(&held).await.starts_with("220 "));
        let over = TcpStream::connect(smtp()).await.expect("connect");
        assert!(!banner(&over).await.starts_with("220 "));
        sleep(Duration::from_secs(2)).await;
        let text = scrape("GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        let total = |family: &str| -> u64 {
            text.lines()
                .filter_map(|line| line.strip_prefix(family)?.strip_prefix('{'))
                .filter_map(|rest| rest.split(' ').nth(1)?.parse::<u64>().ok())
                .sum()
        };
        assert_eq!(total("bunzzle_guard_open_limit_total"), 1, "{text}");
        assert_eq!(total("bunzzle_guard_session_limit_total"), 0);
        assert_eq!(total("bunzzle_smtp_refused_total"), 1);
        drop((held, over));
        sleep(Duration::from_secs(2)).await;
    });
    stopped(&driver, node);
}

#[test]
fn key_ring_metrics_count_the_first_key_server_connect() {
    let driver = created(12);
    let node = booted(&driver, config(7), CORES);
    let machine = &node.machine;
    machine.block_on(0, async {
        drop(serving().await);
        let connects = |text: &str| -> u64 {
            text.lines()
                .filter_map(|line| line.strip_prefix("bunzzle_keys_connects_total{"))
                .filter_map(|rest| rest.split(' ').nth(1)?.parse::<u64>().ok())
                .sum()
        };
        let mut text = String::new();
        for _ in 0..60 {
            sleep(Duration::from_secs(10)).await;
            text = scrape("GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
            if connects(&text) > 0 {
                break;
            }
        }
        assert!(connects(&text) >= 1, "{text}");
        for core in 0..CORES {
            assert!(text.contains(&format!(
                "bunzzle_keys_refused_total{{core=\"{core}\"}} 0\n"
            )));
            assert!(text.contains(&format!("bunzzle_keys_drops_total{{core=\"{core}\"}} 0\n")));
            assert!(text.contains(&format!(
                "bunzzle_batches_mismatched_total{{core=\"{core}\"}} 0\n"
            )));
        }
        for family in [
            "# TYPE bunzzle_keys_days_behind gauge\n",
            "# TYPE bunzzle_keys_tenant_cache_hits_total counter\n",
            "# TYPE bunzzle_batch_cache_evicted_total counter\n",
        ] {
            assert!(text.contains(family), "{family}");
        }
    });
    stopped(&driver, node);
}

#[test]
fn listed_tenants_get_their_own_series() {
    let driver = created(12);
    let mut settings = config(7);
    settings.metrics.as_mut().expect("metrics").tenants = vec![42, 5];
    let node = booted(&driver, settings, CORES);
    let machine = &node.machine;
    machine.block_on(0, async {
        drop(serving().await);
        sleep(Duration::from_secs(2)).await;
        let text = scrape("GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        assert!(
            text.contains("# TYPE bunzzle_tenant_queue_recipients gauge\n"),
            "{text}"
        );
        assert!(text.contains("# TYPE bunzzle_tenant_messages_accepted_total counter\n"));
        for core in 0..CORES {
            for tenant in [42, 5] {
                let labels = format!("{{core=\"{core}\",tenant=\"{tenant}\"}}");
                assert!(text.contains(&format!("bunzzle_tenant_queue_recipients{labels} 0\n")));
                assert!(text.contains(&format!(
                    "bunzzle_tenant_recipients_later_total{labels} 0\n"
                )));
            }
        }
        assert_eq!(
            text.matches("tenant=\"").count(),
            2 * 6 * usize::from(CORES)
        );
    });
    stopped(&driver, node);
}

#[test]
fn unlisted_tenants_add_no_series() {
    let driver = created(13);
    let node = booted(&driver, config(7), CORES);
    let machine = &node.machine;
    machine.block_on(0, async {
        drop(serving().await);
        sleep(Duration::from_secs(2)).await;
        let text = scrape("GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        assert!(text.contains("bunzzle_core_up{core=\"0\"} 1\n"), "{text}");
        assert!(!text.contains("bunzzle_tenant_"));
    });
    stopped(&driver, node);
}

#[test]
fn a_silent_metrics_client_is_dropped() {
    let driver = created(10);
    let node = booted(&driver, config(7), CORES);
    let machine = &node.machine;
    machine.block_on(0, async {
        drop(serving().await);
        let stream = TcpStream::connect(METRICS.parse().expect("address"))
            .await
            .expect("connect");
        let started = rt::now();
        let (read, _) = stream.read(Buf::new(64)).await;
        assert_eq!(read.expect("read"), 0);
        let waited = rt::now().saturating_duration_since(started);
        assert!(waited >= Duration::from_secs(10) && waited < Duration::from_secs(12));
    });
    stopped(&driver, node);
}

#[test]
fn the_admin_socket_answers_status_on_the_control_core() {
    let driver = created(21);
    let extra = format!("[admin]\nsocket = \"{ADMIN}\"\n");
    let node = booted(&driver, config_with(7, &extra), CORES);
    let control = Rc::clone(&driver);
    node.machine.block_on(0, async move {
        drop(serving().await);
        let socket = Path::new(ADMIN);
        let reply = admin::call(socket, UID, &admin::Request::Status, WAIT)
            .await
            .expect("status");
        assert_eq!(reply.code, admin::Code::Ok);
        assert!(
            reply.text.starts_with("node 7\ncores 2\ncontrol version "),
            "{}",
            reply.text
        );
        control.set_uid(UID + 1);
        assert!(
            admin::call(socket, UID, &admin::Request::Status, WAIT)
                .await
                .is_err()
        );
        control.set_uid(UID);
    });
    stopped(&driver, node);
    let machine = Machine::new(Rc::clone(&driver), 1, Stalls::default());
    machine.block_on(0, async {
        let refused = rt::UnixStream::connect(Path::new(ADMIN)).await;
        assert!(refused.is_err());
    });
}

async fn ask(request: admin::Request) -> (admin::Code, String) {
    let reply = admin::call(Path::new(ADMIN), UID, &request, WAIT)
        .await
        .expect("reply");
    (reply.code, reply.text)
}

fn tenant(id: u32, pools: &[u32]) -> admin::Request {
    admin::Request::TenantCreate(admin::TenantSpec {
        id,
        pools: pools.to_vec(),
        queued: 100,
        ..admin::TenantSpec::default()
    })
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(TABLE[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn tls_client() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA).expect("ca"))
        .expect("root");
    let mut config = ClientConfig::builder_with_provider(simulated(105))
        .with_protocol_versions(&[&tls::rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.time_provider = Arc::new(TlsClock);
    Arc::new(config)
}

async fn handshake(io: TcpStream, tls: &Arc<ClientConfig>) -> Stream {
    let name = ServerName::try_from("mail.test").expect("name");
    let conn = ClientConnection::new(Arc::clone(tls), name).expect("client");
    let mut stream = Stream::new(io, conn.into());
    stream.handshake().await.expect("handshake");
    stream
}

struct Smtp {
    conn: Conn,
    input: Vec<u8>,
    tls: Arc<ClientConfig>,
}

impl Smtp {
    async fn connect(tls: &Arc<ClientConfig>) -> Self {
        let io = TcpStream::connect(smtp()).await.expect("connect");
        let mut smtp = Self {
            conn: Conn::plain(io),
            input: Vec::new(),
            tls: Arc::clone(tls),
        };
        assert!(smtp.reply().await.starts_with("220 "));
        smtp
    }

    async fn send(&mut self, data: &[u8]) {
        self.conn.write_all(data).await.expect("write");
    }

    async fn reply(&mut self) -> String {
        loop {
            if let Some(end) = self.input.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.input.drain(..end + 2).collect();
                let line = String::from_utf8(line).expect("ascii");
                if line.as_bytes().get(3) != Some(&b'-') {
                    return line.trim_end().to_string();
                }
                continue;
            }
            let mut more = Vec::new();
            match self.conn.read(&mut more).await {
                Ok(0) | Err(_) => return String::new(),
                Ok(_) => self.input.extend_from_slice(&more),
            }
        }
    }

    async fn command(&mut self, line: &str) -> String {
        self.send(format!("{line}\r\n").as_bytes()).await;
        self.reply().await
    }

    async fn login(mut self, token: &str) -> String {
        assert!(self.command("EHLO client.test").await.starts_with("250 "));
        assert!(self.command("STARTTLS").await.starts_with("220 "));
        let Conn::Plain { io, .. } = self.conn else {
            unreachable!()
        };
        self.conn = Conn::tls(handshake(io, &self.tls).await);
        assert!(self.command("EHLO client.test").await.starts_with("250 "));
        let mut plain = vec![0];
        plain.extend_from_slice(b"user\0");
        plain.extend_from_slice(token.as_bytes());
        self.command(&format!("AUTH PLAIN {}", base64(&plain)))
            .await
    }
}

async fn unknown_queues() {
    use admin::Code::{NotFound, Ok};
    use admin::Request::{QueueList, QueueRebind, QueueRetry};
    assert_eq!(
        ask(QueueList { tenant: 5, from: 0 }).await,
        (Ok, String::new())
    );
    assert_eq!(
        ask(QueueList { tenant: 7, from: 0 }).await,
        (NotFound, "tenant 7 not found".into())
    );
    assert_eq!(
        ask(QueueRetry {
            tenant: 5,
            queue: 1
        })
        .await,
        (NotFound, "queue 1 of tenant 5 not found".into())
    );
    let rebind = QueueRebind {
        tenant: 5,
        queue: 1,
        pool: 1,
    };
    assert_eq!(ask(rebind).await.0, NotFound);
}

#[test]
fn admin_creates_lists_and_revokes_keys() {
    use admin::Code::{NotFound, Ok, Refused};
    use admin::Request::{KeyCreate, KeyList, KeyRevoke, PoolSet, TenantResume, TenantSuspend};
    let driver = created(23);
    let extra = format!("[admin]\nsocket = \"{ADMIN}\"\n");
    let node = booted(&driver, config_with(7, &extra), CORES);
    node.machine.block_on(0, async move {
        drop(serving().await);
        let key = |tenant, smtp, api, hooks, pool| KeyCreate {
            tenant,
            smtp,
            api,
            hooks,
            pool,
        };
        assert_eq!(
            ask(key(7, true, false, false, 0)).await,
            (NotFound, "tenant 7 not found".into())
        );
        assert_eq!(
            ask(KeyList { tenant: 7, from: 0 }).await,
            (NotFound, "tenant 7 not found".into())
        );
        assert_eq!(
            ask(KeyRevoke { tenant: 7, id: 1 }).await,
            (NotFound, "tenant 7 not found".into())
        );

        let pool = admin::PoolSpec {
            id: 1,
            addresses: vec![("192.0.2.1".parse().expect("ip"), 1)],
        };
        assert_eq!(ask(PoolSet(pool)).await.0, Ok);
        assert_eq!(ask(tenant(5, &[1])).await.0, Ok);
        assert_eq!(ask(tenant(6, &[1])).await.0, Ok);
        assert_eq!(ask(TenantSuspend(5)).await.0, Ok);
        assert_eq!(
            ask(key(5, true, false, false, 1)).await,
            (Refused, "tenant 5 is not active".into())
        );
        assert_eq!(ask(TenantResume(5)).await.0, Ok);
        assert_eq!(
            ask(key(5, false, false, false, 0)).await,
            (Refused, "invalid scopes".into())
        );
        assert_eq!(
            ask(key(5, false, false, true, 1)).await,
            (Refused, "invalid scopes".into())
        );
        assert_eq!(
            ask(key(5, true, false, false, 2)).await,
            (Refused, "invalid pool".into())
        );

        let (code, text) = ask(key(5, true, true, false, 1)).await;
        assert_eq!(code, Ok);
        let secret = text
            .strip_prefix("key 1 secret ")
            .and_then(|text| text.strip_suffix('\n'))
            .expect("create reply");
        assert!(secret.starts_with("bz_"));
        assert_eq!(
            ask(KeyList { tenant: 5, from: 0 }).await,
            (Ok, "key 1 scopes smtp,api pool 1 generation 1\n".into())
        );

        assert_eq!(ask(key(6, false, false, true, 0)).await.0, Ok);
        assert_eq!(
            ask(KeyRevoke { tenant: 5, id: 2 }).await,
            (NotFound, "key 2 of tenant 5 not found".into())
        );
        assert_eq!(ask(KeyRevoke { tenant: 5, id: 1 }).await.0, Ok);
        assert_eq!(
            ask(KeyList { tenant: 5, from: 0 }).await,
            (Ok, String::new())
        );
        assert_eq!(
            ask(KeyRevoke { tenant: 5, id: 1 }).await,
            (NotFound, "key 1 of tenant 5 not found".into())
        );
        assert_eq!(
            ask(KeyList { tenant: 6, from: 0 }).await,
            (Ok, "key 2 scopes hooks pool 0 generation 1\n".into())
        );
    });
    stopped(&driver, node);
}

#[test]
fn an_admin_key_signs_in_until_revoked() {
    use admin::Code::Ok;
    use admin::Request::{KeyCreate, KeyRevoke, PoolSet};
    let driver = created(26);
    let extra = format!("[admin]\nsocket = \"{ADMIN}\"\n");
    let node = booted(&driver, config_with(7, &extra), CORES);
    node.machine.block_on(0, async move {
        drop(serving().await);
        let pool = admin::PoolSpec {
            id: 1,
            addresses: vec![("192.0.2.1".parse().expect("ip"), 1)],
        };
        assert_eq!(ask(PoolSet(pool)).await.0, Ok);
        assert_eq!(ask(tenant(5, &[1])).await.0, Ok);
        let key = |smtp, hooks, pool| KeyCreate {
            tenant: 5,
            smtp,
            api: false,
            hooks,
            pool,
        };
        let secret_of = |id: u32, text: String| {
            text.strip_prefix(&format!("key {id} secret "))
                .and_then(|text| text.strip_suffix('\n'))
                .expect("create reply")
                .to_owned()
        };
        let (code, text) = ask(key(true, false, 1)).await;
        assert_eq!(code, Ok);
        let secret = secret_of(1, text);
        assert!(secret.starts_with("bz_"));
        let tls = tls_client();

        let mut granted = String::new();
        for _ in 0..20 {
            let reply = Smtp::connect(&tls).await.login(&secret).await;
            if reply.starts_with("235 ") {
                granted = reply;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(granted.starts_with("235 "), "{granted}");

        let (code, text) = ask(key(false, true, 0)).await;
        assert_eq!(code, Ok);
        let hooks_only = secret_of(2, text);
        let reply = Smtp::connect(&tls).await.login(&hooks_only).await;
        assert!(reply.starts_with("535 "), "{reply}");

        assert_eq!(ask(KeyRevoke { tenant: 5, id: 1 }).await.0, Ok);
        let mut refused = String::new();
        for _ in 0..20 {
            let reply = Smtp::connect(&tls).await.login(&secret).await;
            if reply.starts_with("535 ") {
                refused = reply;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(refused.starts_with("535 "), "{refused}");
    });
    stopped(&driver, node);
}

#[test]
fn key_list_pages_by_bytes() {
    use admin::Code::Ok;
    use admin::Request::{KeyCreate, KeyList, PoolSet};
    const TOTAL: u32 = 1700;
    let driver = created(27);
    let extra = format!("[admin]\nsocket = \"{ADMIN}\"\n");
    let node = booted(&driver, config_with(7, &extra), CORES);
    node.machine.block_on(0, async move {
        drop(serving().await);
        let pool = admin::PoolSpec {
            id: 1,
            addresses: vec![("192.0.2.1".parse().expect("ip"), 1)],
        };
        assert_eq!(ask(PoolSet(pool)).await.0, Ok);
        assert_eq!(ask(tenant(5, &[1])).await.0, Ok);
        for _ in 0..TOTAL {
            let key = KeyCreate {
                tenant: 5,
                smtp: true,
                api: false,
                hooks: false,
                pool: 1,
            };
            assert_eq!(ask(key).await.0, Ok);
        }
        let ids = |page: &str| -> Vec<u32> {
            page.lines()
                .filter_map(|line| line.strip_prefix("key "))
                .map(|rest| {
                    rest.split(' ')
                        .next()
                        .and_then(|id| id.parse().ok())
                        .expect("key id")
                })
                .collect()
        };
        let first = ask(KeyList { tenant: 5, from: 0 }).await.1;
        let more = first.lines().last().expect("page");
        let from: u32 = more
            .strip_prefix("more from ")
            .expect("paged")
            .parse()
            .expect("id");
        let head = ids(&first);
        assert_eq!(head.len() + 1, usize::try_from(from).expect("fits"));
        let second = ask(KeyList { tenant: 5, from }).await.1;
        assert!(!second.contains("more from"), "{second}");
        let mut listed = head;
        listed.extend(ids(&second));
        let expected: Vec<u32> = (1..=TOTAL).collect();
        assert_eq!(listed, expected);
    });
    stopped(&driver, node);
}

#[test]
fn admin_creates_suspends_and_resumes_tenants() {
    use admin::Code::{NotFound, Ok, Refused};
    use admin::Request::{PoolList, PoolSet, TenantList, TenantResume, TenantSuspend};
    let driver = created(22);
    let extra = format!("[admin]\nsocket = \"{ADMIN}\"\n");
    let node = booted(&driver, config_with(7, &extra), CORES);
    node.machine.block_on(0, async move {
        drop(serving().await);
        let (code, text) = ask(tenant(5, &[1])).await;
        assert_eq!((code, text.as_str()), (NotFound, "pool 1 not found"));
        let pool = admin::PoolSpec {
            id: 1,
            addresses: vec![("192.0.2.1".parse().expect("ip"), 1)],
        };
        assert_eq!(ask(PoolSet(pool)).await.0, Ok);
        let bad = admin::PoolSpec {
            id: 2,
            addresses: vec![("192.0.2.2".parse().expect("ip"), 0)],
        };
        assert_eq!(ask(PoolSet(bad)).await, (Refused, "invalid addresses".into()));
        let twice = admin::PoolSpec {
            id: 2,
            addresses: vec![
                ("192.0.2.2".parse().expect("ip"), 1),
                ("::ffff:192.0.2.2".parse().expect("ip"), 1),
            ],
        };
        assert_eq!(ask(PoolSet(twice)).await, (Refused, "invalid addresses".into()));
        let unspecified = admin::PoolSpec {
            id: 2,
            addresses: vec![("::".parse().expect("ip"), 1)],
        };
        assert_eq!(ask(PoolSet(unspecified)).await.0, Refused);
        let mapped = admin::PoolSpec {
            id: 2,
            addresses: vec![("::ffff:192.0.2.3".parse().expect("ip"), 2)],
        };
        assert_eq!(ask(PoolSet(mapped)).await.0, Ok);
        assert_eq!(
            ask(PoolList(0)).await.1,
            "pool 1 addresses 192.0.2.1=1\npool 2 addresses 192.0.2.3=2\n"
        );
        assert_eq!(ask(PoolList(2)).await.1, "pool 2 addresses 192.0.2.3=2\n");

        assert_eq!(ask(tenant(5, &[1])).await.0, Ok);
        assert_eq!(ask(tenant(6, &[1])).await.0, Ok);
        assert_eq!(
            ask(tenant(5, &[1])).await,
            (Ok, "tenant 5 exists with this spec".into())
        );
        assert_eq!(ask(tenant(5, &[2])).await, (Refused, "tenant 5 exists".into()));
        assert_eq!(ask(tenant(8, &[1, 1])).await, (Refused, "invalid pools".into()));
        assert_eq!(ask(tenant(0, &[1])).await, (Refused, "invalid tenant id".into()));
        assert_eq!(ask(tenant(9, &[])).await, (Refused, "invalid pools".into()));

        assert_eq!(ask(TenantSuspend(5)).await.0, Ok);
        let listed = ask(TenantList(0)).await.1;
        assert_eq!(
            listed,
            "tenant 5 suspended generation 1 pools 1 default 1 connections 0 queued 100 rate 0 burst 0\n\
             tenant 6 active generation 1 pools 1 default 1 connections 0 queued 100 rate 0 burst 0\n"
        );
        assert_eq!(ask(TenantSuspend(5)).await, (Ok, "tenant 5 already suspended".into()));
        assert_eq!(ask(TenantResume(6)).await, (Ok, "tenant 6 already active".into()));
        assert_eq!(ask(TenantSuspend(7)).await, (NotFound, "tenant 7 not found".into()));
        assert_eq!(ask(TenantResume(7)).await, (NotFound, "tenant 7 not found".into()));
        assert_eq!(ask(TenantResume(5)).await.0, Ok);
        assert!(ask(TenantList(0)).await.1.starts_with("tenant 5 active generation 1"));
        assert!(ask(TenantList(6)).await.1.starts_with("tenant 6 active generation 1"));
        unknown_queues().await;
        assert_eq!(ask(TenantSuspend(6)).await.0, Ok);
    });
    stopped(&driver, node);

    let node = booted(&driver, config_with(7, &extra), CORES);
    node.machine.block_on(0, async move {
        drop(serving().await);
        assert_eq!(
            ask(TenantList(0)).await.1,
            "tenant 5 active generation 1 pools 1 default 1 connections 0 queued 100 rate 0 burst 0\n\
             tenant 6 suspended generation 1 pools 1 default 1 connections 0 queued 100 rate 0 burst 0\n"
        );
        assert_eq!(
            ask(PoolList(0)).await.1,
            "pool 1 addresses 192.0.2.1=1\npool 2 addresses 192.0.2.3=2\n"
        );
    });
    stopped(&driver, node);

    let machine = Machine::new(Rc::clone(&driver), 1, Stalls::default());
    machine.block_on(0, async {
        let vault = Vault::open(Path::new(KEYS)).await.expect("vault");
        let mut tenants: Vec<u32> = vault.listed().iter().map(|l| l.tenant).collect();
        tenants.sort_unstable();
        assert_eq!(tenants, [5, 6]);
    });
}

#[test]
fn admin_lists_and_pauses_sites() {
    use admin::Code::{Ok, Refused};
    use admin::Request::{SiteList, SitePause, SiteResume};
    let driver = created(25);
    let extra = format!("[admin]\nsocket = \"{ADMIN}\"\n");
    let node = booted(&driver, config_with(7, &extra), CORES);
    node.machine.block_on(0, async move {
        drop(serving().await);
        assert_eq!(ask(SiteList { from: None }).await, (Ok, String::new()));
        let egress = "192.0.2.1".parse().expect("ip");
        let site = || "example.com".to_owned();
        assert_eq!(
            ask(SitePause {
                egress,
                site: site()
            })
            .await,
            (Refused, "site control is off".into())
        );
        assert_eq!(
            ask(SiteResume {
                egress,
                site: site()
            })
            .await,
            (Refused, "site control is off".into())
        );
    });
    stopped(&driver, node);
}

#[test]
fn the_admin_simulation_runs_every_command_and_stops() {
    use admin::Code::{NotFound, Ok};
    use admin::Request::{
        KeyCreate, KeyList, KeyRevoke, PoolList, PoolSet, QueueList, QueueRebind, QueueRetry,
        Status, TenantList, TenantResume, TenantSuspend,
    };
    let driver = created(24);
    let extra = format!("[admin]\nsocket = \"{ADMIN}\"\n");
    let node = booted(&driver, config_with(7, &extra), CORES);
    let machine = &node.machine;
    machine.block_on(0, async {
        drop(serving().await);
        assert_eq!(ask(Status).await.0, Ok);
        let pool = admin::PoolSpec {
            id: 1,
            addresses: vec![("192.0.2.1".parse().expect("ip"), 1)],
        };
        assert_eq!(ask(PoolSet(pool)).await.0, Ok);
        assert_eq!(ask(PoolList(0)).await.0, Ok);
        assert_eq!(ask(tenant(5, &[1])).await.0, Ok);
        assert_eq!(ask(TenantList(0)).await.0, Ok);
        assert_eq!(ask(TenantSuspend(5)).await.0, Ok);
        assert_eq!(ask(TenantResume(5)).await.0, Ok);
        let key = KeyCreate {
            tenant: 5,
            smtp: true,
            api: false,
            hooks: false,
            pool: 1,
        };
        assert_eq!(ask(key).await.0, Ok);
        assert_eq!(ask(KeyList { tenant: 5, from: 0 }).await.0, Ok);
        assert_eq!(ask(KeyRevoke { tenant: 5, id: 1 }).await.0, Ok);
        assert_eq!(ask(QueueList { tenant: 5, from: 0 }).await.0, Ok);
        assert_eq!(
            ask(QueueRetry {
                tenant: 5,
                queue: 1
            })
            .await
            .0,
            NotFound
        );
        let rebind = QueueRebind {
            tenant: 5,
            queue: 1,
            pool: 1,
        };
        assert_eq!(ask(rebind).await.0, NotFound);

        sleep(Duration::from_secs(2)).await;
        let text = scrape("GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
        let total = |family: &str| -> u64 {
            text.lines()
                .filter_map(|line| line.strip_prefix(family)?.strip_prefix('{'))
                .filter_map(|rest| rest.split(' ').nth(1)?.parse::<u64>().ok())
                .sum()
        };
        assert_eq!(total("bunzzle_admin_requests_total"), 13, "{text}");
        assert_eq!(total("bunzzle_admin_requests_malformed_total"), 0);
        assert_eq!(total("bunzzle_admin_connections_accepted_total"), 13);
        assert_eq!(total("bunzzle_admin_connections_refused_total"), 0);
        assert_eq!(total("bunzzle_admin_connections_full_total"), 0);
    });
    stopped(&driver, node);
    let machine = Machine::new(Rc::clone(&driver), 1, Stalls::default());
    machine.block_on(0, async {
        let refused = rt::UnixStream::connect(Path::new(ADMIN)).await;
        assert!(refused.is_err());
    });
}
