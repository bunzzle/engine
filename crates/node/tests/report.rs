use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use control::{Domain, Limits, Object, Pool, State, Tenant, Verification};
use crypto::DkimAlg;
use intake::Origin;
use keys::{
    Audit, BatchSettings, Client as KeyClient, Connect, Ring, RingSettings, Server as KeyServer,
    Settings as KeySettings, Vault,
};
use node::{Tlsrpt, submit_report};
use rt::sim::{Config, Disk, Machine, SimDriver, Stalls};
use rt::{Runtime, TcpListener, TcpStream, sleep, timeout};
use sched::{
    Answered, Attempt, Clock, Keyring, Keys, Meshes, Node, Parts, ReportMail, Reported, Settings,
    Transport,
};
use store::{DataFile, Options, SLOT_SIZE, Setup, boot};

const PATH: &str = "/data/store";
const SHARDS: u16 = 4;
const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 96,
    shards: SHARDS as u32,
};
const KEYS_DIR: &str = "/keys";
const KEYS_AT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 7000);

#[derive(Default)]
struct Seen {
    sent: RefCell<Vec<(bool, String, String)>>,
}

struct Capture(Rc<Seen>);

impl Transport for Capture {
    async fn send(&self, attempt: Attempt) -> Vec<Answered> {
        if let Ok(prepared) = attempt.outgoing.prepare().await {
            let header = String::from_utf8_lossy(prepared.header()).into_owned();
            self.0.sent.borrow_mut().push((
                prepared.envelope.required.tls_optional(),
                prepared.envelope.sender.clone(),
                header,
            ));
        }
        Vec::new()
    }
}

fn created() -> Disk {
    let setup = Rc::new(SimDriver::new(5, Config::default()));
    Runtime::new(setup.clone()).block_on(async move {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

fn settings() -> Settings {
    Settings {
        node: 3,
        spool: spool::Limits {
            recipients: 100,
            inline: 2048,
            body: 1024 * 1024,
            read: 1024 * 1024,
        },
        naming: control::Naming {
            key: *b"naming key 16 by",
            shards: u32::from(SHARDS),
            cache: 16,
        },
        sched: sched::Config::new(u32::from(SHARDS)),
        budget: usize::try_from(OPTIONS.region_size / 2).expect("fits"),
        watched: Vec::new(),
    }
}

fn keyring() -> Rc<dyn Keys> {
    let connect: Connect =
        Rc::new(|| Box::pin(async { Ok(KeyClient::new(TcpStream::connect(KEYS_AT).await?)) }));
    Rc::new(Keyring::new(
        Ring::new(connect, RingSettings::new(1)),
        30,
        BatchSettings::default(),
    ))
}

fn tenant(id: u32, state: State) -> Object {
    Object::Tenant(Tenant {
        id,
        generation: 1,
        state,
        default_pool: 1,
        pools: vec![1],
        limits: Limits {
            rate: 1000,
            burst: 1000,
            connections: 10,
            queued: 1000,
        },
    })
}

fn mail(from: &str) -> ReportMail {
    let message = format!(
        "From: {from}\r\nTo: tls@example.com\r\nSubject: Report Domain: example.com\r\n\
         TLS-Report-Domain: example.com\r\n\r\nreport\r\n"
    );
    ReportMail {
        day: 20_000,
        domain: "example.com".into(),
        from: from.into(),
        to: vec!["tls@example.com".into()],
        message: message.into_bytes(),
    }
}

async fn prepare(node: &Node<Capture>) {
    for _ in 0..100 {
        if TcpStream::connect(KEYS_AT).await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let pool = Object::Pool(Pool {
        id: 1,
        addresses: vec![(IpAddr::from([192, 0, 2, 1]), 1)],
    });
    for object in [pool, tenant(1, State::Active), tenant(2, State::Suspended)] {
        node.write(object).await.expect("write");
    }
    let key = node
        .dkim_new(1, DkimAlg::Ed25519Sha256, "sender.example", "t1")
        .await
        .expect("dkim");
    let domain = node.domain_new(1, "sender.example").await.expect("domain");
    node.domain_write(Domain {
        return_path: false,
        state: Verification::Verified,
        ed25519: key.id,
        ..domain
    })
    .await
    .expect("verify");
    for _ in 0..1000 {
        let ready = node
            .table()
            .sender(1, "sender.example")
            .is_some_and(|d| d.ed25519 != 0);
        if ready {
            return;
        }
        sleep(Duration::from_millis(5)).await;
    }
    panic!("sender not ready");
}

#[test]
fn reports_are_submitted_as_the_report_tenant_with_tls_optional() {
    let driver = Rc::new(SimDriver::with_disk(6, Config::default(), created()));
    let machine = Machine::new(Rc::clone(&driver), 2, Stalls::default());
    let setup = Setup {
        cores: 1,
        credits: 4,
        reserve: 4,
        flush: 1,
    };
    let booted = machine
        .block_on(0, async move {
            timeout(Duration::from_secs(60), boot(PATH, setup)).await
        })
        .expect("in time")
        .expect("boot");
    drop(machine.spawn_on(0, booted.committer.run()));
    drop(machine.spawn_on(0, async move {
        let dir = Path::new(KEYS_DIR);
        let vault = Vault::init(dir, 20_000).await.expect("init");
        let audit = Audit::open(dir).await.expect("audit");
        let server = Rc::new(KeyServer::start(vault, audit, KeySettings::default()));
        let listener = TcpListener::bind(KEYS_AT, 16).await.expect("bind");
        while let Ok((stream, _)) = listener.accept().await {
            server.serve(stream);
        }
    }));
    let seen = Rc::new(Seen::default());
    let meshes = Arc::new(Meshes::new(1));
    let start = booted.starts.into_iter().next().expect("core");
    let transport = Capture(Rc::clone(&seen));
    let results = machine.block_on(1, async move {
        let core = start.open().await.expect("open");
        let parts = Parts {
            keys: keyring(),
            transport,
            clock: Clock::at(rt::wall_ms(), rt::now()),
        };
        let links = meshes.take(0).expect("links");
        let (node, _running) = Node::start(core, links, settings(), parts)
            .await
            .expect("start");
        prepare(&node).await;
        let origin = Origin {
            node: "mx.sender.example",
            with: "LOCAL",
            lifetime: 86_400_000,
        };
        let report = |tenant| Tlsrpt {
            tenant,
            from: "tlsrpt@sender.example".into(),
        };
        let mut results = Vec::new();
        for (tenant, from) in [
            (1, "tlsrpt@sender.example"),
            (2, "tlsrpt@sender.example"),
            (9, "tlsrpt@sender.example"),
            (1, "tlsrpt@other.example"),
        ] {
            let done = submit_report(&node, &report(tenant), (&origin, 1), &mail(from)).await;
            results.push(done);
        }
        for _ in 0..1000 {
            if !seen.sent.borrow().is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        node.close();
        (results, seen.sent.borrow().clone())
    });
    let (results, sent) = results;
    assert_eq!(
        results,
        [
            Reported::Sent,
            Reported::Dropped,
            Reported::Dropped,
            Reported::Dropped
        ]
    );
    assert_eq!(sent.len(), 1);
    let (optional, sender, header) = &sent[0];
    assert!(optional);
    assert_eq!(sender, "tlsrpt@sender.example");
    assert!(header.contains("DKIM-Signature:"), "{header}");
    assert!(
        header.contains("TLS-Report-Domain: example.com"),
        "{header}"
    );
}
