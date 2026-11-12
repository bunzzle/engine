use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use aws_lc_rs::digest::{Digest, SHA256};
use aws_lc_rs::signature::{ED25519, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use control::{Domain, Object, Pool, Scopes, State, Tenant, Verification};
use crypto::{DkimAlg, Ids};
use dkim::BodyHash;
use intake::{Config as SessionConfig, Conn, End, Listener, listen};
use keys::{
    Audit, BatchSettings, Client as KeyClient, Connect, Ring, RingSettings, Server as KeyServer,
    Settings as KeySettings, Vault,
};
use rt::sim::{Config, Disk, Machine, SimDriver, Stalls, check};
use rt::{JoinHandle, Runtime, TcpListener, TcpStream, sleep, spawn, timeout};
use sched::{
    Answer, Answered, Attempt, Body, Claimed, Clock, Fault, Keyring, Keys, Meshes, Node, Parts,
    Running, Settings, Transport,
};
use spool::MessageId;
use store::{Client, Committer, DataFile, Options, SLOT_SIZE, Setup, boot};
use tls::rustls::client::Resumption;
use tls::rustls::crypto::CryptoProvider;
use tls::rustls::pki_types::pem::PemObject;
use tls::rustls::pki_types::{CertificateDer, ServerName};
use tls::rustls::{ClientConfig, ClientConnection, RootCertStore};
use tls::{Acceptor, Certs, Clock as TlsClock, Stream, simulated};

const PATH: &str = "/data/store";
const SHARDS: u16 = 8;
const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 96,
    shards: SHARDS as u32,
};
const NAMING: [u8; 16] = *b"naming key 16 by";
const KEYS_DIR: &str = "/keys";
const KEYS_AT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 7000);
const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SUBMIT: u16 = 587;
const IMPLICIT: u16 = 465;
const CA: &[u8] = include_bytes!("data/ca.pem");
const CERT: &[u8] = include_bytes!("data/a.pem");
const KEY: &str = "302e020100300506032b65700422042098cded488e5305ce6644e0188d522eac4a19a7722043c25e621026562f2dda6d";

#[derive(Default)]
struct Seen {
    publics: RefCell<BTreeMap<String, Vec<u8>>>,
    verified: RefCell<BTreeMap<MessageId, usize>>,
    delivered: RefCell<BTreeSet<MessageId>>,
    faults: RefCell<Vec<&'static str>>,
    deliver: Cell<bool>,
    hold: Cell<bool>,
}

struct Idle(Rc<Seen>);

impl Transport for Idle {
    async fn send(&self, attempt: Attempt) -> Vec<Answered> {
        let seen = &self.0;
        let claimed = attempt.recipients.clone();
        if seen.hold.get() {
            return answered(&claimed, Answer::Later(1_000));
        }
        let mut prepared = match attempt.outgoing.prepare().await {
            Ok(prepared) => prepared,
            Err(fault) => {
                seen.faults.borrow_mut().push(match fault {
                    Fault::Unopened { .. } => "unopened",
                    Fault::Keys => "keys",
                    Fault::Signer(_) => "signer",
                    Fault::Format(_) => "format",
                });
                return fault.answers(&claimed);
            }
        };
        let mut hash = BodyHash::new();
        match &mut prepared.body {
            Body::Inline(body) => hash.update(body),
            Body::Chain(plain) => {
                while let Some(chunk) = plain.next().await.expect("plain chunk") {
                    hash.update(&chunk);
                }
            }
        }
        let count = verified(prepared.header(), &hash.finish(), &seen.publics.borrow());
        seen.verified.borrow_mut().insert(attempt.message, count);
        if !seen.deliver.get() {
            return Vec::new();
        }
        seen.delivered.borrow_mut().insert(attempt.message);
        answered(&claimed, Answer::Delivered)
    }
}

fn answered(claimed: &[Claimed], answer: Answer) -> Vec<Answered> {
    claimed
        .iter()
        .map(|c| Answered {
            recipient: c.recipient,
            answer,
            reply: Vec::new(),
        })
        .collect()
}

fn verified(header: &[u8], body: &[u8; 32], publics: &BTreeMap<String, Vec<u8>>) -> usize {
    let fields = dkim::parse(header).expect("header");
    assert!(fields[0].is("received"), "received first");
    let mut count = 0;
    for at in 0..fields.len() {
        if !fields[at].is("dkim-signature") {
            continue;
        }
        let check = dkim::check(&fields, at, body).expect("signature");
        if let Some(public) = publics.get(&check.selector) {
            let valid = match check.alg {
                DkimAlg::Ed25519Sha256 => UnparsedPublicKey::new(&ED25519, public)
                    .verify(&check.digest, &check.signature)
                    .is_ok(),
                DkimAlg::RsaSha256 => {
                    let digest = Digest::import_less_safe(&check.digest, &SHA256).expect("digest");
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public)
                        .verify_digest(&digest, &check.signature)
                        .is_ok()
                }
            };
            assert!(valid, "signature by {}", check.selector);
        }
        count += 1;
    }
    count
}

struct Cluster {
    seen: Rc<Seen>,
    keys: Rc<RefCell<Vec<SocketAddr>>>,
    machine: Machine,
    nodes: Vec<Node<Idle>>,
    runnings: Vec<Running>,
    client: Client,
    committer: JoinHandle<Committer>,
}

impl Cluster {
    fn run<T: 'static>(&self, future: impl Future<Output = T> + 'static) -> T {
        self.machine.block_on(1, future)
    }

    fn stop(self) {
        let Self {
            seen: _,
            keys: _,
            machine,
            nodes,
            runnings,
            client,
            committer,
        } = self;
        machine.block_on(0, async move {
            for node in &nodes {
                node.close();
            }
            for running in runnings {
                drop(running.stop().await);
            }
            drop(nodes);
            drop(client);
            drop(committer.await);
        });
    }
}

fn created(seed: u64) -> Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
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
            key: NAMING,
            shards: u32::from(SHARDS),
            cache: 16,
        },
        sched: sched::Config::new(u32::from(SHARDS)),
        budget: usize::try_from(OPTIONS.region_size / 2).expect("fits"),
    }
}

fn keys_up(machine: &Machine) -> Rc<RefCell<Vec<SocketAddr>>> {
    let peers = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&peers);
    drop(machine.spawn_on(0, async move {
        let dir = Path::new(KEYS_DIR);
        let vault = match Vault::open(dir).await {
            Ok(vault) => vault,
            Err(_) => Vault::init(dir, 20_000).await.expect("init"),
        };
        let audit = Audit::open(dir).await.expect("audit");
        let server = Rc::new(KeyServer::start(vault, audit, KeySettings::default()));
        let listener = TcpListener::bind(KEYS_AT, 16).await.expect("bind");
        while let Ok((stream, peer)) = listener.accept().await {
            seen.borrow_mut().push(peer);
            server.serve(stream);
        }
    }));
    peers
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

fn started(driver: &Rc<SimDriver>, cores: u16) -> Option<Cluster> {
    let machine = Machine::new(Rc::clone(driver), usize::from(cores) + 1, Stalls::default());
    let setup = Setup {
        cores,
        credits: 4,
        reserve: 4,
        flush: 1,
    };
    let booted = machine
        .block_on(0, async move {
            timeout(Duration::from_secs(60), boot(PATH, setup)).await
        })
        .ok()?
        .ok()?;
    let committer = machine.spawn_on(0, booted.committer.run());
    let keys = keys_up(&machine);
    let seen = Rc::new(Seen::default());
    let meshes = Arc::new(Meshes::new(cores));
    let mut tasks = Vec::new();
    for start in booted.starts {
        let index = start.index();
        let links = meshes.take(index).expect("links");
        let transport = Idle(Rc::clone(&seen));
        tasks.push(machine.spawn_on(usize::from(index) + 1, async move {
            let core = timeout(Duration::from_secs(60), start.open())
                .await
                .ok()?
                .ok()?;
            let parts = Parts {
                keys: keyring(),
                transport,
                clock: Clock::at(rt::wall_ms(), rt::now()),
            };
            let started = Node::start(core, links, settings(), parts);
            timeout(Duration::from_secs(60), started).await.ok()?.ok()
        }));
    }
    let started = machine.block_on(0, async move {
        let mut started = Vec::new();
        for task in tasks {
            started.push(task.await);
        }
        started
    });
    let (nodes, runnings) = started
        .into_iter()
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .unzip();
    Some(Cluster {
        seen,
        keys,
        machine,
        nodes,
        runnings,
        client: booted.client,
        committer,
    })
}

fn control_of(nodes: &[Node<Idle>]) -> &Node<Idle> {
    nodes.iter().find(|n| n.controls()).expect("control core")
}

async fn until(name: &str, what: impl Fn() -> bool) {
    within(name, Duration::from_secs(50), what).await;
}

async fn within(name: &str, limit: Duration, what: impl Fn() -> bool) {
    let step = Duration::from_millis(5);
    for _ in 0..limit.as_millis() / step.as_millis() {
        if what() {
            return;
        }
        sleep(step).await;
    }
    panic!("{name} not reached");
}

struct Tokens {
    first: Vec<u8>,
    second: Vec<u8>,
    publics: BTreeMap<String, Vec<u8>>,
    domain: Domain,
}

async fn prepare(nodes: &[Node<Idle>]) -> Tokens {
    for _ in 0..100 {
        if TcpStream::connect(KEYS_AT).await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let control = control_of(nodes);
    let objects = [
        Object::Pool(Pool {
            id: 1,
            addresses: vec![(IpAddr::from([192, 0, 2, 1]), 1)],
        }),
        tenant(1),
        tenant(2),
    ];
    for object in objects {
        control.write(object).await.expect("write");
    }
    until("tenants", || {
        nodes.iter().all(|n| n.table().tenant(2).is_some())
    })
    .await;
    let ed = control
        .dkim_new(1, DkimAlg::Ed25519Sha256, "example.org", "e1")
        .await
        .expect("ed25519");
    let rsa = control
        .dkim_new(1, DkimAlg::RsaSha256, "example.org", "r1")
        .await
        .expect("rsa");
    until("dkim", || {
        nodes.iter().all(|n| n.table().dkim(1, rsa.id).is_some())
    })
    .await;
    let domain = control.domain_new(1, "example.org").await.expect("domain");
    let domain = control
        .domain_write(Domain {
            state: Verification::Verified,
            rsa: rsa.id,
            ed25519: ed.id,
            ..domain
        })
        .await
        .expect("verify");
    let other = control.domain_new(2, "example.net").await.expect("domain");
    control
        .domain_write(Domain {
            state: Verification::Verified,
            ..other
        })
        .await
        .expect("verify");
    let smtp = Scopes {
        smtp: true,
        api: false,
    };
    let (first, first_token) = control.access_new(1, smtp, 0).await.expect("access");
    let (second, second_token) = control.access_new(2, smtp, 0).await.expect("access");
    until("records", || {
        nodes.iter().all(|n| {
            let table = n.table();
            table.access(first.id).is_some()
                && table.access(second.id).is_some()
                && table.sender(1, "example.org").is_some_and(|d| d.rsa != 0)
                && table.sender(2, "example.net").is_some()
        })
    })
    .await;
    Tokens {
        first: first_token.to_vec(),
        second: second_token.to_vec(),
        publics: [("e1".into(), ed.public), ("r1".into(), rsa.public)].into(),
        domain,
    }
}

fn tenant(id: u32) -> Object {
    Object::Tenant(Tenant {
        id,
        generation: 1,
        state: State::Active,
        default_pool: 1,
        pools: vec![1],
        limits: control::Limits {
            queued: 1000,
            ..control::Limits::default()
        },
    })
}

fn pem(hex: &str) -> Vec<u8> {
    let der: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let kind = "PRIVATE KEY";
    let body = dkim::base64::encode(&der);
    format!("-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n").into_bytes()
}

fn acceptor(seed: u64) -> Rc<Acceptor> {
    let certs = Arc::new(Certs::new(CERT, &pem(KEY)).expect("certs"));
    Rc::new(Acceptor::new(simulated(seed), certs).expect("acceptor"))
}

fn client_config(provider: Arc<CryptoProvider>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA).expect("ca"))
        .expect("root");
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tls::rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.time_provider = Arc::new(TlsClock);
    Arc::new(config)
}

struct Ports(Vec<Listener>);

impl Ports {
    fn ended(&self, end: End) -> u64 {
        self.0.iter().map(|l| l.ended(end)).sum()
    }

    fn refused(&self) -> u64 {
        self.0.iter().map(Listener::refused).sum()
    }

    async fn close(self) {
        for listener in self.0 {
            listener.close().await;
        }
    }
}

async fn listen_with(node: &Node<Idle>, seed: u64, config: SessionConfig) -> Ports {
    let config = Rc::new(config);
    let acceptor = acceptor(seed);
    let mut listeners = Vec::new();
    for (port, implicit) in [(SUBMIT, false), (IMPLICIT, true)] {
        let socket = TcpListener::bind(SocketAddr::from((HOST, port)), 64)
            .await
            .expect("bind");
        listeners.push(listen(
            node.clone(),
            socket,
            Rc::clone(&acceptor),
            Rc::clone(&config),
            implicit,
        ));
    }
    Ports(listeners)
}

async fn listen_on(node: &Node<Idle>, seed: u64) -> Ports {
    listen_with(node, seed, SessionConfig::new("mx1.example.net".into())).await
}

struct Smtp {
    conn: Option<Conn>,
    input: Vec<u8>,
    tls: Arc<ClientConfig>,
}

impl Smtp {
    async fn connect(port: u16, tls: &Arc<ClientConfig>) -> Self {
        let io = TcpStream::connect(SocketAddr::from((HOST, port)))
            .await
            .expect("connect");
        let conn = if port == IMPLICIT {
            Conn::tls(handshake(io, tls).await)
        } else {
            Conn::plain(io)
        };
        let mut smtp = Self {
            conn: Some(conn),
            input: Vec::new(),
            tls: Arc::clone(tls),
        };
        assert!(smtp.reply().await.starts_with("220 "));
        smtp
    }

    async fn send(&mut self, data: &[u8]) {
        let conn = self.conn.as_mut().expect("conn");
        conn.write_all(data).await.expect("write");
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
            match self.conn.as_mut().expect("conn").read(&mut more).await {
                Ok(0) | Err(_) => return String::new(),
                Ok(_) => self.input.extend_from_slice(&more),
            }
        }
    }

    async fn command(&mut self, line: &str) -> String {
        self.send(format!("{line}\r\n").as_bytes()).await;
        self.reply().await
    }

    async fn login(&mut self, token: &[u8]) -> String {
        if !self.conn.as_ref().is_some_and(Conn::secure) {
            assert!(self.command("EHLO client.test").await.starts_with("250 "));
            assert!(self.command("STARTTLS").await.starts_with("220 "));
            let Some(Conn::Plain { io, .. }) = self.conn.take() else {
                unreachable!()
            };
            self.conn = Some(Conn::tls(handshake(io, &self.tls).await));
        }
        assert!(self.command("EHLO client.test").await.starts_with("250 "));
        let mut plain = vec![0];
        plain.extend_from_slice(b"user\0");
        plain.extend_from_slice(token);
        self.command(&format!("AUTH PLAIN {}", dkim::base64::encode(&plain)))
            .await
    }

    async fn transaction(&mut self, from: &str, to: &[&str]) -> Vec<String> {
        let mut replies = vec![self.command(&format!("MAIL FROM:<{from}>")).await];
        for rcpt in to {
            replies.push(self.command(&format!("RCPT TO:<{rcpt}>")).await);
        }
        replies
    }

    async fn data(&mut self, message: &[u8]) -> String {
        let go = self.command("DATA").await;
        if !go.starts_with("354") {
            return go;
        }
        self.send(&stuffed(message)).await;
        self.reply().await
    }
}

async fn handshake(io: TcpStream, config: &Arc<ClientConfig>) -> Stream {
    let name = ServerName::try_from("mail.test").expect("name");
    let conn = ClientConnection::new(Arc::clone(config), name).expect("client");
    let mut stream = Stream::new(io, conn.into());
    stream.handshake().await.expect("handshake");
    stream
}

fn stuffed(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 8);
    for line in message.split_inclusive(|&b| b == b'\n') {
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn message(from: &str, extra: &str, body: usize, seed: u64) -> Vec<u8> {
    let mut out = format!("From: {from}\r\nTo: a@example.com\r\nSubject: s{seed}\r\n{extra}\r\n")
        .into_bytes();
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    while out.len() < body {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let width = 1 + usize::try_from(state % 76).expect("small");
        let line: Vec<u8> = (0..width)
            .map(|i| {
                b"abcdefghij.KLMNOP 0123456789"
                    [(usize::try_from(state >> (i % 50)).expect("fits")) % 28]
            })
            .collect();
        out.extend_from_slice(&line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn opaque_id(node: &Node<Idle>, reply: &str) -> MessageId {
    let text = reply.strip_prefix("250 2.0.0 ").expect("accepted");
    let ids = Ids::new(&node.ids().expect("ids")).expect("ids");
    MessageId::from_bytes(ids.decode(text.as_bytes()).expect("opaque id"))
}

fn stored(nodes: &[Node<Idle>]) -> BTreeSet<MessageId> {
    nodes
        .iter()
        .flat_map(|n| n.spool().messages_of(1))
        .collect()
}

#[test]
fn accepted_messages_survive_a_restart_and_refusals_store_nothing() {
    check(0..3, |seed| {
        let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
        let cluster = started(&driver, 2).expect("start");
        let nodes = cluster.nodes.clone();
        let (accepted, used) = cluster.run(async move {
            let tokens = prepare(&nodes).await;
            let listening = listen_on(&nodes[0], seed).await;
            let tls = client_config(simulated(seed + 100));
            let mut accepted = BTreeSet::new();
            let mut smtp = Smtp::connect(SUBMIT, &tls).await;
            assert!(smtp.login(&tokens.first).await.starts_with("235 "));
            for (n, size) in [200, 1990, 2100, 70_000, 300_000].into_iter().enumerate() {
                let to = ["a@example.com", "b@example.net", "c@example.com"];
                let replies = smtp.transaction("bounce@example.org", &to).await;
                assert!(replies.iter().all(|r| r.starts_with("250 ")), "{replies:?}");
                let body = message("Ann <ann@example.org>", "", size, seed * 10 + n as u64);
                let reply = smtp.data(&body).await;
                assert!(reply.starts_with("250 2.0.0 "), "{size}: {reply}");
                accepted.insert(opaque_id(&nodes[0], &reply));
            }
            let refusals = [
                ("Ann <ann@example.com>", "", "550 5.7.1"),
                ("ann@example.org", "Bcc: x@example.com\r\n", "554 5.6.0"),
                ("a@example.org, b@example.org", "", "554 5.6.0"),
            ];
            for (from, extra, code) in refusals {
                smtp.transaction("bounce@example.org", &["a@example.com"])
                    .await;
                let reply = smtp.data(&message(from, extra, 90_000, seed)).await;
                assert!(reply.starts_with(code), "{from}: {reply}");
            }
            let replies = smtp.transaction("bounce@example.com", &[]).await;
            assert!(replies[0].starts_with("550 5.7.1"), "{replies:?}");
            smtp.transaction("bounce@example.org", &["a@example.com"])
                .await;
            let body = message("ann@sub.example.org", "", 500, seed);
            smtp.send(format!("BDAT {} LAST\r\n", body.len()).as_bytes())
                .await;
            smtp.send(&body).await;
            let reply = smtp.reply().await;
            assert!(reply.starts_with("250 2.0.0 "), "{reply}");
            accepted.insert(opaque_id(&nodes[0], &reply));
            assert!(smtp.command("QUIT").await.starts_with("221 "));

            let mut wrong = Smtp::connect(SUBMIT, &tls).await;
            let mut bad = tokens.first.clone();
            let last = bad.len() - 1;
            bad[last] = if bad[last] == b'A' { b'B' } else { b'A' };
            assert!(wrong.login(&bad).await.starts_with("535 5.7.8"));
            assert!(wrong.command("QUIT").await.starts_with("221 "));

            let mut other = Smtp::connect(IMPLICIT, &tls).await;
            assert!(other.login(&tokens.second).await.starts_with("235 "));
            let replies = other.transaction("bounce@example.org", &[]).await;
            assert!(replies[0].starts_with("550 5.7.1"), "{replies:?}");
            assert!(other.command("QUIT").await.starts_with("221 "));

            let mut implicit = Smtp::connect(IMPLICIT, &tls).await;
            assert!(implicit.login(&tokens.first).await.starts_with("235 "));
            implicit
                .transaction("bounce@example.org", &["d@example.com"])
                .await;
            let reply = implicit
                .data(&message("ann@example.org", "", 5000, seed))
                .await;
            assert!(reply.starts_with("250 2.0.0 "), "{reply}");
            accepted.insert(opaque_id(&nodes[0], &reply));
            assert!(implicit.command("QUIT").await.starts_with("221 "));
            assert_eq!(listening.ended(End::Io), 0, "seed {seed}");
            listening.close().await;
            assert_eq!(stored(&nodes), accepted, "seed {seed}");
            (accepted, nodes[0].leases().used(&1))
        });
        assert_eq!(used, 17, "seed {seed}: slots kept");
        cluster.stop();
        let driver = Rc::new(SimDriver::with_disk(
            seed + 1,
            Config::default(),
            driver.crash(),
        ));
        let restarted = started(&driver, 2).expect("restart");
        let nodes = restarted.nodes.clone();
        restarted.run(async move {
            assert_eq!(stored(&nodes), accepted, "seed {seed}");
            for id in &accepted {
                let node = nodes.iter().find(|n| n.spool().messages_of(1).contains(id));
                assert!(node.expect("owner").spool().recipient(*id, 0).is_some());
            }
        });
        restarted.stop();
    });
}

fn attempts(nodes: &[Node<Idle>], id: MessageId) -> Option<u16> {
    let node = nodes
        .iter()
        .find(|n| n.spool().messages_of(1).contains(&id))?;
    let spool = node.spool();
    Some(spool.recipient(id, 0)?.attempts + spool.recipient(id, 1)?.attempts)
}

#[test]
fn attempts_carry_verified_signatures_and_wait_for_keys() {
    check(0..2, |seed| {
        let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
        let cluster = started(&driver, 2).expect("start");
        let nodes = cluster.nodes.clone();
        let seen = Rc::clone(&cluster.seen);
        let peers = Rc::clone(&cluster.keys);
        let sim = Rc::clone(&driver);
        cluster.run(async move {
            let tokens = prepare(&nodes).await;
            seen.publics.replace(tokens.publics.clone());
            seen.deliver.set(true);
            let listening = listen_on(&nodes[0], seed).await;
            let tls = client_config(simulated(seed + 100));
            let mut smtp = Smtp::connect(SUBMIT, &tls).await;
            assert!(smtp.login(&tokens.first).await.starts_with("235 "));
            let to = ["a@example.com", "b@example.net"];
            let mut sent = Vec::new();
            for (n, size) in [200, 70_000, 300_000].into_iter().enumerate() {
                smtp.transaction("bounce@example.org", &to).await;
                let body = message("Ann <ann@example.org>", "", size, seed * 10 + n as u64);
                let reply = smtp.data(&body).await;
                assert!(reply.starts_with("250 2.0.0 "), "{reply}");
                sent.push(opaque_id(&nodes[0], &reply));
            }
            until("signed and delivered", || {
                let verified = seen.verified.borrow();
                sent.iter().all(|id| verified.get(id) == Some(&2)) && stored(&nodes).is_empty()
            })
            .await;

            seen.hold.set(true);
            smtp.transaction("bounce@example.org", &to).await;
            let reply = smtp.data(&message("ann@example.org", "", 9000, seed)).await;
            let waiting = opaque_id(&nodes[0], &reply);
            sim.set_reachable(KEYS_AT.ip(), false);
            for peer in peers.borrow().iter() {
                sim.reset_connection(*peer);
            }
            seen.hold.set(false);
            until("keys down", || seen.faults.borrow().contains(&"keys")).await;
            assert_eq!(attempts(&nodes, waiting), Some(0), "seed {seed}");
            assert!(!seen.verified.borrow().contains_key(&waiting));
            sim.set_reachable(KEYS_AT.ip(), true);
            within(
                "signed after keys came back",
                Duration::from_secs(300),
                || seen.verified.borrow().get(&waiting) == Some(&2) && stored(&nodes).is_empty(),
            )
            .await;

            seen.deliver.set(false);
            smtp.transaction("bounce@example.org", &to).await;
            let reply = smtp.data(&message("ann@example.org", "", 300, seed)).await;
            let orphan = opaque_id(&nodes[0], &reply);
            until("signed once", || {
                seen.verified.borrow().contains_key(&orphan)
            })
            .await;
            let control = control_of(&nodes);
            let old = tokens.domain.rsa;
            let fresh = control
                .dkim_new(1, DkimAlg::RsaSha256, "example.org", "r2")
                .await
                .expect("rsa");
            control
                .domain_write(Domain {
                    rsa: fresh.id,
                    ..tokens.domain.clone()
                })
                .await
                .expect("rotate");
            control.dkim_remove(1, old).await.expect("remove");
            until("removed", || {
                nodes.iter().all(|n| n.table().dkim(1, old).is_none())
            })
            .await;
            seen.deliver.set(true);
            within(
                "failed with the removed key",
                Duration::from_secs(300),
                || stored(&nodes).is_empty(),
            )
            .await;
            assert!(seen.faults.borrow().contains(&"signer"), "seed {seed}");
            assert!(!seen.delivered.borrow().contains(&orphan), "seed {seed}");
            assert!(nodes.iter().all(|n| n.sched().unsigned() == 0));
            assert!(smtp.command("QUIT").await.starts_with("221 "));
            listening.close().await;
        });
        cluster.stop();
    });
}

#[test]
fn idle_sessions_close_without_a_reply() {
    check(0..2, |seed| {
        let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
        let cluster = started(&driver, 1).expect("start");
        let nodes = cluster.nodes.clone();
        cluster.run(async move {
            prepare(&nodes).await;
            let listening = listen_on(&nodes[0], seed).await;
            let tls = client_config(simulated(seed + 100));
            let mut idle = Smtp::connect(SUBMIT, &tls).await;
            let started = rt::now();
            assert_eq!(idle.reply().await, "");
            let waited = rt::now().saturating_duration_since(started);
            assert!(
                waited >= Duration::from_secs(59) && waited <= Duration::from_secs(61),
                "{waited:?}"
            );
            until("ended", || listening.ended(End::Timeout) == 1).await;
            assert_eq!(
                listening.ended(End::Done) + listening.ended(End::Dropped),
                0
            );
            listening.close().await;
        });
        cluster.stop();
    });
}

#[derive(Default)]
struct Load {
    accepted: BTreeSet<MessageId>,
    ended: usize,
}

async fn client(
    node: Node<Idle>,
    token: Vec<u8>,
    tls: Arc<ClientConfig>,
    n: u64,
    load: Rc<RefCell<Load>>,
) {
    let port = if n.is_multiple_of(2) {
        SUBMIT
    } else {
        IMPLICIT
    };
    let mut smtp = Smtp::connect(port, &tls).await;
    if !smtp.login(&token).await.starts_with("235 ") {
        return;
    }
    for m in 0..5u64 {
        let replies = smtp
            .transaction("bounce@example.org", &["a@example.com", "b@example.net"])
            .await;
        if !replies.iter().all(|r| r.starts_with("250 ")) {
            return;
        }
        let size = [300, 3000, 90_000, 200_000, 1000][usize::try_from((n + m) % 5).expect("small")];
        let body = stuffed(&message("ann@example.org", "", size, n * 100 + m));
        if !smtp.command("DATA").await.starts_with("354") {
            return;
        }
        if n == 3 && m == 2 {
            smtp.send(&body[..body.len() / 2]).await;
            return;
        }
        smtp.send(&body).await;
        load.borrow_mut().ended += 1;
        let reply = smtp.reply().await;
        if reply.starts_with("250 ") {
            let id = opaque_id(&node, &reply);
            load.borrow_mut().accepted.insert(id);
        }
    }
    smtp.command("QUIT").await;
}

async fn halted(driver: Rc<SimDriver>) {
    while !driver.is_halted() {
        sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn answered_messages_survive_a_crash_during_sessions() {
    let crashed_with_mail = Rc::new(Cell::new(0u32));
    let counted = Rc::clone(&crashed_with_mail);
    check(0..8, move |seed| {
        let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
        let cluster = started(&driver, 2).expect("start");
        let nodes = cluster.nodes.clone();
        let tokens = cluster.run(async move { prepare(&nodes).await });
        cluster.stop();

        let config = Config {
            halt_after: Some(60 + seed * 37 % 150),
            ..Config::default()
        };
        let driver = Rc::new(SimDriver::with_disk(seed + 1, config, driver.crash()));
        let load: Rc<RefCell<Load>> = Rc::default();
        if let Some(cluster) = started(&driver, 2) {
            let nodes = cluster.nodes.clone();
            let (seen, power, token) = (Rc::clone(&load), Rc::clone(&driver), tokens.first);
            cluster.run(async move {
                let _listening = listen_on(&nodes[0], seed).await;
                let tls = client_config(simulated(seed + 100));
                let clients: Vec<_> = (0..4)
                    .map(|n| {
                        spawn(client(
                            nodes[0].clone(),
                            token.clone(),
                            Arc::clone(&tls),
                            n,
                            Rc::clone(&seen),
                        ))
                    })
                    .collect();
                let mut all = pin!(async move {
                    for task in clients {
                        task.await;
                    }
                });
                let mut halt = pin!(halted(power));
                let race = poll_fn(|cx| {
                    if all.as_mut().poll(cx).is_ready() || halt.as_mut().poll(cx).is_ready() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                });
                let _ = timeout(Duration::from_secs(3600), race).await;
            });
        }
        let halted = driver.is_halted();
        let driver = Rc::new(SimDriver::with_disk(
            seed + 2,
            Config::default(),
            driver.crash(),
        ));
        let restarted = started(&driver, 2).expect("restart");
        let nodes = restarted.nodes.clone();
        let load = Rc::try_unwrap(load).ok().expect("one owner").into_inner();
        if halted && !load.accepted.is_empty() {
            counted.set(counted.get() + 1);
        }
        restarted.run(async move {
            let stored = stored(&nodes);
            assert!(
                load.accepted.is_subset(&stored),
                "seed {seed}: answered message lost"
            );
            assert!(
                stored.len() <= load.ended,
                "seed {seed}: {} stored, {} sent",
                stored.len(),
                load.ended
            );
        });
        restarted.stop();
    });
    assert!(
        crashed_with_mail.get() > 0,
        "no crash after an accepted message"
    );
}

#[test]
fn listeners_cap_connections_time_out_handshakes_and_close() {
    check(0..2, |seed| {
        let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
        let cluster = started(&driver, 1).expect("start");
        let nodes = cluster.nodes.clone();
        cluster.run(async move {
            prepare(&nodes).await;
            let mut config = SessionConfig::new("mx1.example.net".into());
            config.connections = 2;
            let listening = listen_with(&nodes[0], seed, config).await;
            let tls = client_config(simulated(seed + 100));
            let first = Smtp::connect(SUBMIT, &tls).await;
            let second = Smtp::connect(SUBMIT, &tls).await;
            let io = TcpStream::connect(SocketAddr::from((HOST, SUBMIT)))
                .await
                .expect("connect");
            let mut third = Conn::plain(io);
            let mut seen = Vec::new();
            assert!(matches!(third.read(&mut seen).await, Ok(0) | Err(_)));
            assert_eq!(listening.refused(), 1);

            let silent = TcpStream::connect(SocketAddr::from((HOST, IMPLICIT)))
                .await
                .expect("connect");
            let started = rt::now();
            until("handshake", || listening.ended(End::Tls) == 1).await;
            let waited = rt::now().saturating_duration_since(started);
            assert!(
                waited >= Duration::from_secs(9) && waited <= Duration::from_secs(11),
                "{waited:?}"
            );
            drop((first, second, silent, third));
            until("dropped", || listening.ended(End::Dropped) == 2).await;
            listening.close().await;
            let late = TcpStream::connect(SocketAddr::from((HOST, SUBMIT))).await;
            assert!(late.is_err());
        });
        cluster.stop();
    });
}
