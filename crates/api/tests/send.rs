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

use api::json::{self, Value};
use api::{Api, Config as ApiConfig, Forward, Route, Socket, start};
use aws_lc_rs::digest::{Digest, SHA256};
use aws_lc_rs::signature::{ED25519, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use control::{Domain, Object, Pool, Scopes, State, Tenant, Verification};
use crypto::{DkimAlg, Ids};
use dkim::BodyHash;
use intake::{Conn, End, Guard, Limits};
use keys::{
    Audit, BatchSettings, Client as KeyClient, Connect, Ring, RingSettings, Server as KeyServer,
    Settings as KeySettings, Vault,
};
use rt::sim::{Config, Disk, Machine, SimDriver, Stalls, check};
use rt::{Ends, JoinHandle, Mesh, Notify, Runtime, TcpListener, TcpStream, sleep, spawn, timeout};
use sched::{
    Answer, Answered, Attempt, Body, Clock, EventBody, EventKind, Keyring, Keys, Meshes, Node,
    Parts, Reason, Running, Settings, Transport,
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
const HTTPS: u16 = 443;
const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
const CA: &[u8] = include_bytes!("data/ca.pem");
const CERT: &[u8] = include_bytes!("data/a.pem");
const KEY: &str = "302e020100300506032b65700422042098cded488e5305ce6644e0188d522eac4a19a7722043c25e621026562f2dda6d";

#[derive(Default)]
struct Seen {
    publics: RefCell<BTreeMap<String, Vec<u8>>>,
    headers: RefCell<BTreeMap<MessageId, (Vec<u8>, usize)>>,
    routed: RefCell<BTreeSet<String>>,
    optional: Cell<u32>,
    deliver: Cell<Option<Clock>>,
}

struct Idle(Rc<Seen>);

impl Transport for Idle {
    async fn send(&self, attempt: Attempt) -> Vec<Answered> {
        let seen = &self.0;
        let Ok(mut prepared) = attempt.outgoing.prepare().await else {
            return Vec::new();
        };
        for (_, recipient) in &prepared.recipients {
            seen.routed.borrow_mut().insert(recipient.address.clone());
        }
        if prepared.envelope.required.tls_optional() {
            seen.optional.set(seen.optional.get() + 1);
        }
        let mut hash = BodyHash::new();
        match &mut prepared.body {
            Body::Inline(body) => hash.update(body),
            Body::Chain(plain) => {
                while let Some(chunk) = plain.next().await.expect("plain chunk") {
                    hash.update(&chunk);
                }
            }
        }
        let header = prepared.header().to_vec();
        let count = verified(&header, &hash.finish(), &seen.publics.borrow());
        seen.headers
            .borrow_mut()
            .insert(attempt.message, (header, count));
        let Some(clock) = seen.deliver.get() else {
            return Vec::new();
        };
        attempt
            .recipients
            .iter()
            .map(|c| {
                let address = prepared
                    .recipients
                    .iter()
                    .find(|(r, _)| *r == c.recipient)
                    .map(|(_, r)| r.address.as_bytes().to_vec())
                    .unwrap_or_default();
                let body = EventBody {
                    kind: EventKind::Delivered,
                    time: clock.now(),
                    address,
                    reply: b"250 2.0.0 ok".to_vec(),
                    attempts: c.attempts.saturating_add(1),
                    class: c.class,
                };
                Answered {
                    recipient: c.recipient,
                    answer: Answer::Delivered,
                    reply: Vec::new(),
                    event: prepared.opener.event(c.recipient, c.stamp, &body).ok(),
                }
            })
            .collect()
    }
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
        let Some(public) = publics.get(&check.selector) else {
            continue;
        };
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
        count += 1;
    }
    count
}

struct Cluster {
    seen: Rc<Seen>,
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

fn keys_up(machine: &Machine) {
    drop(machine.spawn_on(0, async move {
        let dir = Path::new(KEYS_DIR);
        let vault = match Vault::open(dir).await {
            Ok(vault) => vault,
            Err(_) => Vault::init(dir, 20_000).await.expect("init"),
        };
        let audit = Audit::open(dir).await.expect("audit");
        let server = Rc::new(KeyServer::start(vault, audit, KeySettings::default()));
        let listener = TcpListener::bind(KEYS_AT, 16).await.expect("bind");
        while let Ok((stream, _)) = listener.accept().await {
            server.serve(stream);
        }
    }));
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

fn started(run: u64, cores: u16) -> Cluster {
    let driver = Rc::new(SimDriver::with_disk(run, Config::default(), created(run)));
    started_on(&driver, cores).expect("start")
}

fn started_on(driver: &Rc<SimDriver>, cores: u16) -> Option<Cluster> {
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
    keys_up(&machine);
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
        machine,
        nodes,
        runnings,
        client: booted.client,
        committer,
    })
}

async fn until(name: &str, what: impl Fn() -> bool) {
    let step = Duration::from_millis(5);
    for _ in 0..10_000 {
        if what() {
            return;
        }
        sleep(step).await;
    }
    panic!("{name} not reached");
}

struct Tokens {
    first: String,
    second: String,
    smtp: String,
    third: String,
    publics: BTreeMap<String, Vec<u8>>,
}

async fn verify_domain(control: &Node<Idle>, tenant: u32, name: &str, rsa: u32, ed25519: u32) {
    let domain = control.domain_new(tenant, name).await.expect("domain");
    control
        .domain_write(Domain {
            state: Verification::Verified,
            rsa,
            ed25519,
            ..domain
        })
        .await
        .expect("verify");
}

async fn prepare(nodes: &[Node<Idle>]) -> Tokens {
    for _ in 0..100 {
        if TcpStream::connect(KEYS_AT).await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let control = nodes.iter().find(|n| n.controls()).expect("control core");
    let objects = [
        Object::Pool(Pool {
            id: 1,
            addresses: vec![(IpAddr::from([192, 0, 2, 1]), 1)],
        }),
        tenant(1),
        tenant(2),
        tenant(3),
    ];
    for object in objects {
        control.write(object).await.expect("write");
    }
    until("tenants", || {
        nodes.iter().all(|n| n.table().tenant(3).is_some())
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
    verify_domain(control, 1, "example.org", rsa.id, ed.id).await;
    verify_domain(control, 2, "example.net", 0, 0).await;
    let info = control
        .dkim_new(3, DkimAlg::Ed25519Sha256, "example.info", "e3")
        .await
        .expect("ed25519");
    verify_domain(control, 3, "example.info", 0, info.id).await;
    let api = Scopes {
        smtp: false,
        api: true,
    };
    let smtp = Scopes {
        smtp: true,
        api: false,
    };
    let (first, first_token) = control.access_new(1, api, 0).await.expect("access");
    let (second, second_token) = control.access_new(2, api, 0).await.expect("access");
    let (third, smtp_token) = control.access_new(1, smtp, 0).await.expect("access");
    let (fourth, third_token) = control.access_new(3, api, 0).await.expect("access");
    until("records", || {
        nodes.iter().all(|n| {
            let table = n.table();
            [first.id, second.id, third.id, fourth.id]
                .iter()
                .all(|id| table.access(*id).is_some())
                && table.sender(1, "example.org").is_some_and(|d| d.rsa != 0)
                && table.dkim(1, rsa.id).is_some()
                && table.sender(2, "example.net").is_some()
                && table
                    .sender(3, "example.info")
                    .is_some_and(|d| d.ed25519 != 0)
                && table.dkim(3, info.id).is_some()
        })
    })
    .await;
    let text = |token: &[u8]| String::from_utf8(token.to_vec()).expect("ascii token");
    Tokens {
        first: text(&first_token),
        second: text(&second_token),
        smtp: text(&smtp_token),
        third: text(&third_token),
        publics: [
            ("e1".into(), ed.public),
            ("r1".into(), rsa.public),
            ("e3".into(), info.public),
        ]
        .into(),
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

fn guard() -> Guard {
    let mesh = Mesh::new(1);
    let ends = mesh.take(0).expect("ends");
    Guard::start(ends, [7; 16], Limits::default()).0
}

struct Ports(Api);

impl Ports {
    fn count(&self, route: Route, status: u16) -> u64 {
        self.0.count(route, status)
    }

    fn ended(&self, end: End) -> u64 {
        self.0.ended(end)
    }

    async fn close(self) {
        self.0.close().await;
    }
}

async fn serve(node: &Node<Idle>, seed: u64, config: ApiConfig) -> Ports {
    let forwards = Mesh::new(2);
    serve_with(node, seed, config, forwards.take(0).expect("ends")).await
}

async fn serve_with(node: &Node<Idle>, seed: u64, config: ApiConfig, ends: Ends<Forward>) -> Ports {
    let secure = TcpListener::bind(SocketAddr::from((HOST, HTTPS)), 64)
        .await
        .expect("bind");
    let plain = TcpListener::bind(LOOPBACK, 64).await.expect("bind");
    let sockets = vec![
        Socket {
            socket: secure,
            acceptor: Some(acceptor(seed)),
            loopback: false,
        },
        Socket {
            socket: plain,
            acceptor: None,
            loopback: true,
        },
    ];
    Ports(start(
        node.clone(),
        sockets,
        Rc::new(config),
        &guard(),
        ends,
    ))
}

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        json::parse(&self.body, json::Limits::default()).expect("json body")
    }

    fn code(&self) -> String {
        let value = self.json();
        let error = value.get("error").expect("error");
        assert_eq!(
            error.get("request").and_then(Value::as_str),
            self.header("request-id"),
            "request id in body and header"
        );
        error
            .get("code")
            .and_then(Value::as_str)
            .expect("code")
            .to_owned()
    }

    fn id(&self) -> String {
        assert_eq!(self.status, 200, "{self:?}");
        let value = self.json();
        value
            .get("id")
            .and_then(Value::as_str)
            .expect("id")
            .to_owned()
    }
}

struct Http {
    conn: Conn,
    input: Vec<u8>,
}

impl Http {
    async fn tls(tls: &Arc<ClientConfig>) -> Self {
        let io = TcpStream::connect(SocketAddr::from((HOST, HTTPS)))
            .await
            .expect("connect");
        let name = ServerName::try_from("mail.test").expect("name");
        let conn = ClientConnection::new(Arc::clone(tls), name).expect("client");
        let mut stream = Stream::new(io, conn.into());
        stream.handshake().await.expect("handshake");
        Self {
            conn: Conn::tls(stream),
            input: Vec::new(),
        }
    }

    async fn plain() -> Self {
        let io = TcpStream::connect(LOOPBACK).await.expect("connect");
        Self {
            conn: Conn::plain(io),
            input: Vec::new(),
        }
    }

    async fn send(&mut self, data: &[u8]) {
        self.conn.write_all(data).await.expect("write");
    }

    async fn fill(&mut self) -> bool {
        let mut more = Vec::new();
        match self.conn.read(&mut more).await {
            Ok(0) | Err(_) => false,
            Ok(_) => {
                self.input.extend_from_slice(&more);
                true
            }
        }
    }

    async fn reply(&mut self) -> Option<Reply> {
        let end = loop {
            if let Some(end) = self.input.windows(4).position(|w| w == b"\r\n\r\n") {
                break end;
            }
            if !self.fill().await {
                return None;
            }
        };
        let head: Vec<u8> = self.input.drain(..end + 4).collect();
        let head = String::from_utf8(head).expect("ascii head");
        let mut lines = head.split("\r\n");
        let status = lines.next().expect("status line")[9..12]
            .parse()
            .expect("status");
        let headers: Vec<(String, String)> = lines
            .filter(|l| !l.is_empty())
            .map(|l| {
                let (n, v) = l.split_once(": ").expect("field");
                (n.to_owned(), v.to_owned())
            })
            .collect();
        let length: usize = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, v)| v.parse().expect("length"));
        while self.input.len() < length {
            if !self.fill().await {
                return None;
            }
        }
        let body = self.input.drain(..length).collect();
        Some(Reply {
            status,
            headers,
            body,
        })
    }

    async fn try_send(&mut self, data: &[u8]) -> bool {
        self.conn.write_all(data).await.is_ok()
    }

    async fn send_reply(&mut self, request: &[u8]) -> Reply {
        self.send(request).await;
        self.reply().await.expect("reply")
    }

    async fn post(&mut self, token: &str, body: &str) -> Reply {
        self.send(&post(token, body)).await;
        self.reply().await.expect("reply")
    }

    async fn closed(&mut self) -> bool {
        self.input.is_empty() && !self.fill().await
    }
}

fn post(token: &str, body: &str) -> Vec<u8> {
    format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn opaque(node: &Node<Idle>, id: &str) -> MessageId {
    let ids = Ids::new(&node.ids().expect("ids")).expect("ids");
    MessageId::from_bytes(ids.decode(id.as_bytes()).expect("opaque id"))
}

fn stored(nodes: &[Node<Idle>]) -> BTreeSet<MessageId> {
    nodes
        .iter()
        .flat_map(|n| [1, 2, 3].into_iter().flat_map(|t| n.spool().messages_of(t)))
        .collect()
}

const FULL: &str = r#"{
    "from": { "address": "ann@example.org", "name": "Ann Öz" },
    "to": ["a@example.com", { "address": "b@example.net", "name": "Bob" }],
    "cc": "c@example.com",
    "bcc": ["hidden@example.com", "A@example.com"],
    "reply_to": "help@example.org",
    "subject": "Grüße",
    "text": "Hello\nthere",
    "html": "<p>Hello</p>",
    "headers": { "X-Campaign": "c1" },
    "attachments": [
        { "filename": "a.txt", "content_type": "text/plain", "data": "aGVsbG8=" },
        { "filename": "l.png", "content_type": "image/png", "data": "iVBORw0K", "content_id": "logo@x" }
    ],
    "require_tls": true
}"#;

#[test]
fn json_messages_are_signed_stored_and_routed() {
    check(0..2, |seed| {
        let cluster = started(seed, 2);
        let nodes = cluster.nodes.clone();
        let seen = Rc::clone(&cluster.seen);
        cluster.run(async move {
            let tokens = prepare(&nodes).await;
            seen.publics.replace(tokens.publics.clone());
            let ports = serve(&nodes[0], seed, ApiConfig::new("mx1.example.net".into())).await;
            let tls = client_config(simulated(seed + 100));
            let mut http = Http::tls(&tls).await;
            let reply = http.post(&tokens.first, FULL).await;
            assert_eq!(reply.header("request-id").map(str::len), Some(32));
            let full = opaque(&nodes[0], &reply.id());

            let body = r#"{"from":"ann@example.org","to":"d@example.com","text":"x"}"#;
            let request = format!(
                "POST /v1/messages HTTP/1.1\r\nHost: api.test\r\nAuthorization: bearer {}\r\n\
                 Content-Type: application/json; charset=utf-8\r\nExpect: 100-continue\r\n\
                 Transfer-Encoding: chunked\r\n\r\n",
                tokens.first
            );
            http.send(request.as_bytes()).await;
            let interim = http.reply().await.expect("interim");
            assert_eq!(interim.status, 100);
            let (left, right) = body.split_at(20);
            let chunked = format!(
                "{:x}\r\n{left}\r\n{:x}\r\n{right}\r\n0\r\n\r\n",
                left.len(),
                right.len()
            );
            http.send(chunked.as_bytes()).await;
            let small = opaque(&nodes[0], &http.reply().await.expect("reply").id());

            let mut plain = Http::plain().await;
            let health = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
            plain.send(health).await;
            let reply = plain.reply().await.expect("health");
            assert_eq!(reply.status, 200);
            let local = opaque(&nodes[0], &plain.post(&tokens.first, body).await.id());

            let ids: BTreeSet<MessageId> = [full, small, local].into();
            assert_eq!(stored(&nodes), ids);
            until("attempted", || seen.headers.borrow().len() == 3).await;
            let headers = seen.headers.borrow().clone();
            let (header, signatures) = &headers[&full];
            assert_eq!(*signatures, 2);
            let header = String::from_utf8_lossy(header);
            assert!(header.contains("with HTTPS id"), "{header}");
            assert!(header.contains("Subject: =?utf-8?"), "{header}");
            assert!(header.contains("X-Campaign: c1"), "{header}");
            assert_eq!(seen.optional.get(), 0);
            let bcc = header
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("bcc:"));
            assert!(!bcc, "{header}");
            let (header, _) = &headers[&local];
            assert!(String::from_utf8_lossy(header).contains("with HTTP id"));
            let routed = seen.routed.borrow().clone();
            for address in [
                "a@example.com",
                "b@example.net",
                "c@example.com",
                "hidden@example.com",
                "d@example.com",
            ] {
                assert!(routed.contains(address), "{address} in {routed:?}");
            }
            assert_eq!(routed.len(), 5, "{routed:?}");
            assert_eq!(ports.count(Route::Messages, 200), 3);
            assert_eq!(ports.count(Route::Health, 200), 1);
            ports.close().await;
        });
        cluster.stop();
    });
}

#[test]
fn refusals_answer_stable_codes_and_store_nothing() {
    check(0..2, |seed| {
        let cluster = started(seed, 2);
        let nodes = cluster.nodes.clone();
        cluster.run(async move {
            let tokens = prepare(&nodes).await;
            nodes[0]
                .suppressions()
                .add(1, "gone@example.com", Reason::Bounce, None)
                .await
                .expect("suppress");
            let ports = serve(&nodes[0], seed, ApiConfig::new("mx1.example.net".into())).await;
            let tls = client_config(simulated(seed + 100));
            let first = tokens.first.as_str();
            let ok = r#"{"from":"ann@example.org","to":"a@example.com","text":"x"}"#;
            let cases: Vec<(&str, String, u16, &str)> = vec![
                ("nobody", ok.into(), 401, "unauthorized"),
                (&tokens.smtp, ok.into(), 401, "unauthorized"),
                (first, "{".into(), 400, "bad_request"),
                (first, "[]".into(), 400, "bad_request"),
                (first, r#"{"from":"ann@example.org","to":"a@example.com","text":"x","tags":[]}"#.into(), 400, "bad_request"),
                (first, r#"{"from":"ann@example.org","to":"a@example.com","text":1}"#.into(), 400, "bad_request"),
                (first, r#"{"to":"a@example.com","text":"x"}"#.into(), 400, "bad_request"),
                (first, r#"{"from":"ann@example.org","to":"a@example.com"}"#.into(), 400, "bad_message"),
                (first, r#"{"from":"ann@example.org","to":"bad","text":"x"}"#.into(), 400, "bad_address"),
                (first, r#"{"from":"ann@example.org","to":"jörg@example.com","text":"x"}"#.into(), 400, "bad_address"),
                (first, r#"{"from":"ann@example.org","to":"a@example.com","text":"x","headers":{"Bcc":"x@example.com"}}"#.into(), 400, "bad_header"),
                (first, r#"{"from":"ann@example.org","to":"a@example.com","text":"x","headers":{"TLS-Required":"No"}}"#.into(), 400, "bad_header"),
                (first, r#"{"from":"ann@example.org","to":"a@example.com","text":"x","headers":{"X-A":"a\r\nBcc: x@example.com"}}"#.into(), 400, "bad_header"),
                (first, r#"{"from":"ann@example.org","to":"a@example.com","text":"x","attachments":[{"filename":"a","content_type":"text/plain","data":"aGVs bG8="}]}"#.into(), 400, "bad_message"),
                (first, r#"{"from":"ann@example.org","text":"x"}"#.into(), 422, "no_recipients"),
                (first, r#"{"from":"ann@example.org","to":["a@example.com","gone@example.com","x@example.com"],"text":"x"}"#.into(), 422, "recipients_refused"),
                (first, r#"{"from":"ann@example.com","to":"a@example.com","text":"x"}"#.into(), 403, "sender_not_allowed"),
                (first, r#"{"from":"ann@example.org","envelope_from":"b@example.net","to":"a@example.com","text":"x"}"#.into(), 403, "sender_not_allowed"),
                (&tokens.second, ok.into(), 403, "sender_not_allowed"),
                (&tokens.second, r#"{"from":"ann@example.net","to":"a@example.com","text":"x"}"#.into(), 403, "sender_not_allowed"),
            ];
            for (token, body, status, code) in cases {
                let mut http = Http::tls(&tls).await;
                let reply = http.post(token, &body).await;
                assert_eq!((reply.status, reply.code().as_str()), (status, code), "{body}");
                if status == 401 {
                    assert_eq!(reply.header("www-authenticate"), Some("Bearer"));
                }
                if code == "recipients_refused" {
                    let value = reply.json();
                    let refused = value.get("error").and_then(|e| e.get("refused")).expect("refused");
                    let refused = refused.as_array().expect("list");
                    assert_eq!(refused.len(), 1);
                    assert_eq!(refused[0].get("address").and_then(Value::as_str), Some("gone@example.com"));
                    assert_eq!(refused[0].get("code").and_then(Value::as_str), Some("suppressed"));
                }
                let close = reply.header("connection") == Some("close");
                assert_eq!(close, status == 401, "{body}");
            }

            let mut http = Http::tls(&tls).await;
            let wrong = format!(
                "POST /v1/messages HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {first}\r\n\
                 Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi"
            );
            http.send(wrong.as_bytes()).await;
            let reply = http.reply().await.expect("reply");
            assert_eq!((reply.status, reply.code().as_str()), (415, "unsupported_media_type"));
            assert_eq!(reply.header("connection"), Some("close"));
            assert!(http.closed().await);

            let mut http = Http::tls(&tls).await;
            let huge = format!(
                "POST /v1/messages HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {first}\r\n\
                 Content-Type: application/json\r\nContent-Length: 999999999\r\n\r\n"
            );
            http.send(huge.as_bytes()).await;
            let reply = http.reply().await.expect("reply");
            assert_eq!((reply.status, reply.code().as_str()), (413, "too_large"));
            assert!(http.closed().await);

            let mut http = Http::tls(&tls).await;
            for (request, status, code) in [
                ("GET /v1/messages HTTP/1.1\r\nHost: a\r\n\r\n", 405, "method_not_allowed"),
                ("GET /nope HTTP/1.1\r\nHost: a\r\n\r\n", 404, "not_found"),
                ("GET /healthz HTTP/1.1\r\nHost: a\r\n\r\n", 404, "not_found"),
            ] {
                http.send(request.as_bytes()).await;
                let reply = http.reply().await.expect("reply");
                assert_eq!((reply.status, reply.code().as_str()), (status, code));
                if status == 405 {
                    assert_eq!(reply.header("allow"), Some("POST"));
                }
            }
            http.send(b"POST /v1/messages HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n").await;
            let reply = http.reply().await.expect("reply");
            assert_eq!((reply.status, reply.code().as_str()), (400, "bad_request"));
            assert!(http.closed().await);

            assert!(stored(&nodes).is_empty());
            assert_eq!(ports.count(Route::Messages, 200), 0);
            assert_eq!(ports.count(Route::Messages, 401), 2);
            ports.close().await;
        });
        cluster.stop();
    });
}

#[test]
fn slow_and_idle_connections_time_out() {
    let cluster = started(7, 1);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        let tokens = prepare(&nodes).await;
        let ports = serve(&nodes[0], 7, ApiConfig::new("mx1.example.net".into())).await;
        let mut http = Http::plain().await;
        http.send(b"POST /v1/messages HTTP/1.1\r\nHost:").await;
        let reply = http.reply().await.expect("timeout reply");
        assert_eq!((reply.status, reply.code().as_str()), (408, "timeout"));
        assert!(http.closed().await);

        let mut http = Http::plain().await;
        let request = post(
            &tokens.first,
            r#"{"from":"ann@example.org","to":"a@example.com","text":"x"}"#,
        );
        http.send(&request[..request.len() - 5]).await;
        let reply = http.reply().await.expect("timeout reply");
        assert_eq!(reply.status, 408);
        assert!(http.closed().await);

        let mut http = Http::plain().await;
        let reply = http
            .post(
                &tokens.first,
                r#"{"from":"ann@example.org","to":"a@example.com","text":"x"}"#,
            )
            .await;
        reply.id();
        let waited = rt::now();
        assert!(http.closed().await);
        assert!(rt::now().saturating_duration_since(waited) >= Duration::from_secs(59));
        assert_eq!(ports.ended(End::Timeout), 3);
        ports.close().await;
    });
    cluster.stop();
}

fn raw(token: &str, envelope: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "POST /v1/messages/raw HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: message/rfc822\r\n{envelope}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn message(from: &str, extra: &str, size: usize, seed: u64) -> Vec<u8> {
    let mut out = format!("From: {from}\r\nTo: a@example.com\r\nSubject: s{seed}\r\n{extra}\r\n")
        .into_bytes();
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    while out.len() < size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let width = 1 + usize::try_from(state % 76).expect("small");
        let line: Vec<u8> = (0..width)
            .map(|i| {
                b"abcdefghij.KLMNOP 0123456789"
                    [usize::try_from((state >> (i % 50)) % 28).expect("fits")]
            })
            .collect();
        out.extend_from_slice(&line);
        out.extend_from_slice(if state.is_multiple_of(3) {
            b"\n"
        } else {
            b"\r\n"
        });
    }
    out
}

#[test]
fn raw_messages_stream_under_the_smtp_line_rules() {
    check(0..2, |seed| {
        let cluster = started(seed, 2);
        let nodes = cluster.nodes.clone();
        let seen = Rc::clone(&cluster.seen);
        cluster.run(async move {
            let tokens = prepare(&nodes).await;
            seen.publics.replace(tokens.publics.clone());
            let ports = serve(&nodes[0], seed, ApiConfig::new("mx1.example.net".into())).await;
            let tls = client_config(simulated(seed + 100));
            let first = tokens.first.as_str();
            let envelope = "Envelope-From: bounce@example.org\r\n\
                            Envelope-To: a@example.com, b@example.net\r\n\
                            Envelope-To: c@example.com\r\nRequire-TLS: 1\r\n";
            let mut http = Http::tls(&tls).await;
            let mut ids = BTreeSet::new();
            for (n, size) in [300, 5000, 300_000].into_iter().enumerate() {
                let body = message("Ann <ann@example.org>", "", size, seed * 10 + n as u64);
                http.send(&raw(first, envelope, &body)).await;
                let reply = http.reply().await.expect("reply");
                ids.insert(opaque(&nodes[0], &reply.id()));
            }
            let body = message("ann@example.org", "", 2000, seed);
            let head = format!(
                "POST /v1/messages/raw HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {first}\r\n\
                 Content-Type: message/rfc822\r\nEnvelope-From: ann@example.org\r\n\
                 Envelope-To: d@example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            );
            http.send(head.as_bytes()).await;
            for part in body.chunks(700) {
                http.send(format!("{:x}\r\n", part.len()).as_bytes()).await;
                http.send(part).await;
                http.send(b"\r\n").await;
            }
            http.send(b"0\r\n\r\n").await;
            ids.insert(opaque(&nodes[0], &http.reply().await.expect("reply").id()));

            raw_refusals(&tokens, &tls, seed).await;

            assert_eq!(stored(&nodes), ids);
            until("attempted", || seen.headers.borrow().len() == ids.len()).await;
            let headers = seen.headers.borrow().clone();
            for id in &ids {
                let (header, signatures) = &headers[id];
                assert_eq!(*signatures, 2);
                assert!(String::from_utf8_lossy(header).contains("with HTTPS id"));
            }
            let routed = seen.routed.borrow().clone();
            let want: BTreeSet<String> = [
                "a@example.com",
                "b@example.net",
                "c@example.com",
                "d@example.com",
            ]
            .map(String::from)
            .into();
            assert_eq!(routed, want);
            assert_eq!(ports.count(Route::Raw, 200), 4);
            ports.close().await;
        });
        cluster.stop();
    });
}

async fn raw_refusals(tokens: &Tokens, tls: &Arc<ClientConfig>, seed: u64) {
    let first = tokens.first.as_str();
    let ok = "Envelope-From: ann@example.org\r\nEnvelope-To: a@example.com\r\n";
    let plain = message("ann@example.org", "", 500, seed);
    let envelopes = [
        ("Envelope-To: a@example.com\r\n", 400, "bad_request"),
        (
            "Envelope-From: a@example.org\r\nEnvelope-From: b@example.org\r\n",
            400,
            "bad_request",
        ),
        (
            "Envelope-From: ann@example.org\r\nEnvelope-To: a@example.com, bad\r\n",
            400,
            "bad_address",
        ),
        ("Envelope-From: ann@example.org\r\n", 422, "no_recipients"),
        (
            "Envelope-From: ann@example.org\r\nEnvelope-To: a@example.com\r\nRequire-TLS: yes\r\n",
            400,
            "bad_request",
        ),
        (
            "Envelope-From: ann@example.com\r\nEnvelope-To: a@example.com\r\n",
            403,
            "sender_not_allowed",
        ),
    ];
    let mut long = plain.clone();
    long.extend_from_slice(&[b'x'; 1000]);
    long.extend_from_slice(b"\r\n");
    let bodies = [
        (
            message("ann@example.com", "", 500, seed),
            403,
            "sender_not_allowed",
        ),
        (
            message("ann@example.org", "Bcc: x@example.com\r\n", 500, seed),
            400,
            "bad_header",
        ),
        (
            b"From: ann@example.org\r\n\r\na\rb\r\n".to_vec(),
            400,
            "bad_message",
        ),
        (
            b"From: ann@example.org\r\n\r\na\0b\r\n".to_vec(),
            400,
            "bad_message",
        ),
        (long, 400, "bad_message"),
    ];
    let requests = envelopes
        .into_iter()
        .map(|(envelope, status, code)| (raw(first, envelope, &plain), status, code))
        .chain(
            bodies
                .into_iter()
                .map(|(body, status, code)| (raw(first, ok, &body), status, code)),
        )
        .chain([
            (raw(&tokens.second, ok, &plain), 403, "sender_not_allowed"),
            (raw("nobody", ok, &plain), 401, "unauthorized"),
        ]);
    for (request, status, code) in requests {
        let mut http = Http::tls(tls).await;
        http.send(&request).await;
        let reply = http.reply().await.expect("reply");
        assert_eq!((reply.status, reply.code().as_str()), (status, code));
    }
    let mut http = Http::tls(tls).await;
    let json = format!(
        "POST /v1/messages/raw HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {first}\r\n\
         Content-Type: application/json\r\n{ok}Content-Length: 2\r\n\r\n{{}}"
    );
    http.send(json.as_bytes()).await;
    let reply = http.reply().await.expect("reply");
    assert_eq!(
        (reply.status, reply.code().as_str()),
        (415, "unsupported_media_type")
    );
}

struct Owners {
    apis: Vec<Rc<RefCell<Option<Api>>>>,
    stops: Vec<Rc<Notify>>,
    held: RefCell<Vec<JoinHandle<()>>>,
}

impl Owners {
    fn sum(&self, of: impl Fn(&Api) -> u64) -> u64 {
        self.apis
            .iter()
            .filter_map(|api| api.borrow().as_ref().map(&of))
            .sum()
    }

    fn served(&self) -> u64 {
        self.sum(Api::served)
    }

    fn serving(&self) -> u64 {
        self.sum(|api| api.serving() as u64)
    }

    fn stop(&self) {
        for stop in &self.stops {
            stop.notify();
        }
    }

    fn join(&self, machine: &Machine) {
        for held in self.held.take() {
            machine.block_on(0, held);
        }
    }
}

fn owners(cluster: &Cluster, forwards: &Mesh<Forward>) -> Rc<Owners> {
    let mut owners = Owners {
        apis: Vec::new(),
        stops: Vec::new(),
        held: RefCell::new(Vec::new()),
    };
    for (core, node) in (1u16..).zip(&cluster.nodes[1..]) {
        let api: Rc<RefCell<Option<Api>>> = Rc::default();
        let stop = Rc::new(Notify::default());
        let ends = forwards.take(core).expect("ends");
        let (node, slot, wait) = (node.clone(), Rc::clone(&api), Rc::clone(&stop));
        let held = cluster.machine.spawn_on(usize::from(core) + 1, async move {
            let config = Rc::new(ApiConfig::new("mx1.example.net".into()));
            slot.replace(Some(start(node, Vec::new(), config, &guard(), ends)));
            wait.wait().await;
            let api = slot.borrow_mut().take().expect("owner api");
            api.close().await;
        });
        owners.apis.push(api);
        owners.stops.push(stop);
        owners.held.get_mut().push(held);
    }
    Rc::new(owners)
}

async fn owned_key(node: &Node<Idle>, name: &str, core: u16) -> String {
    for n in 0.. {
        let key = format!("{name}-{n}");
        let shard = node
            .requests()
            .shard(1, key.as_bytes())
            .await
            .expect("shard");
        if shard % 2 == core {
            return key;
        }
    }
    unreachable!()
}

fn keyed(token: &str, key: &str, body: &str) -> Vec<u8> {
    format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {token}\r\n\
         Idempotency-Key: {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn keyed_requests_run_on_the_owner_core() {
    check(0..2, |seed| {
        let cluster = started(seed, 2);
        let nodes = cluster.nodes.clone();
        let seen = Rc::clone(&cluster.seen);
        let forwards = Mesh::new(2);
        let owners = owners(&cluster, &forwards);
        let ends = forwards.take(0).expect("ends");
        let watched = Rc::clone(&owners);
        cluster.run(async move {
            let owners = watched;
            let tokens = prepare(&nodes).await;
            seen.publics.replace(tokens.publics.clone());
            let config = ApiConfig::new("mx1.example.net".into());
            let ports = serve_with(&nodes[0], seed, config, ends).await;
            let first = tokens.first.as_str();
            let body = r#"{"from":"ann@example.org","to":"d@example.com","text":"x"}"#;
            let mut http = Http::plain().await;
            let mut ids = BTreeSet::new();
            let mut cores = [0u64; 2];
            let mut spare = Vec::new();
            for n in 0..256 {
                let key = format!("k{seed}-{n}");
                let requests = nodes[0].requests();
                let shard = requests.shard(1, key.as_bytes()).await.expect("shard");
                let core = usize::from(shard % 2);
                if cores[core] == 3 {
                    if core == 1 && spare.len() < 3 {
                        spare.push(key);
                    }
                    if spare.len() == 3 && cores[0] == 3 {
                        break;
                    }
                    continue;
                }
                http.send(&keyed(first, &key, body)).await;
                let id = opaque(&nodes[0], &http.reply().await.expect("reply").id());
                assert_eq!(id.shard, shard);
                ids.insert(id);
                cores[core] += 1;
            }
            assert_eq!(cores, [3, 3]);
            assert_eq!(spare.len(), 3);

            let tls = client_config(simulated(seed + 100));
            let mut secure = Http::tls(&tls).await;
            let big = message("Ann <ann@example.org>", "", 300_000, seed);
            let envelope = "Envelope-From: bounce@example.org\r\nEnvelope-To: a@example.com\r\n";
            let fields = format!("Idempotency-Key: {}\r\n{envelope}", spare[0]);
            secure.send(&raw(first, &fields, &big)).await;
            let streamed = opaque(&nodes[0], &secure.reply().await.expect("reply").id());
            ids.insert(streamed);

            let small = message("Ann <ann@example.org>", "", 300, seed);
            let fields = format!(
                "Idempotency-Key: {}\r\nEnvelope-From: a@unknown.test\r\nEnvelope-To: a@example.com\r\n",
                spare[1]
            );
            http.send(&raw(first, &fields, &small)).await;
            let reply = http.reply().await.expect("reply");
            assert_eq!((reply.status, reply.code().as_str()), (403, "sender_not_allowed"));
            assert!(http.closed().await);

            let mut http = Http::plain().await;
            http.send(&keyed(first, &"x".repeat(256), body)).await;
            let reply = http.reply().await.expect("reply");
            assert_eq!((reply.status, reply.code().as_str()), (400, "bad_request"));

            let mut http = Http::plain().await;
            let fields = format!("Idempotency-Key: {}\r\n{envelope}", spare[2]);
            let partial = raw(first, &fields, &big);
            http.send(&partial[..partial.len() / 2]).await;
            let serving = |n| {
                let owners = Rc::clone(&owners);
                move || owners.serving() == n
            };
            until("forwarded body", serving(1)).await;
            drop(http);
            until("owner released", serving(0)).await;

            assert_eq!(stored(&nodes), ids);
            until("attempted", || seen.headers.borrow().len() == ids.len()).await;
            let header = seen.headers.borrow()[&streamed].0.clone();
            assert!(String::from_utf8_lossy(&header).contains("with HTTPS id"));
            assert_eq!(ports.0.forwarded(), 6);
            assert_eq!(owners.served(), 6);
            owners.stop();
            ports.close().await;
        });
        owners.join(&cluster.machine);
        cluster.stop();
    });
}

#[test]
fn idempotency_keys_replay_and_refuse_conflicts() {
    check(0..2, |seed| {
        let cluster = started(seed, 2);
        let nodes = cluster.nodes.clone();
        let forwards = Mesh::new(2);
        let owners = owners(&cluster, &forwards);
        let ends = forwards.take(0).expect("ends");
        let watched = Rc::clone(&owners);
        cluster.run(async move {
            let owners = watched;
            let tokens = prepare(&nodes).await;
            let config = ApiConfig::new("mx1.example.net".into());
            let ports = serve_with(&nodes[0], seed, config, ends).await;
            let first = tokens.first.as_str();
            let body = r#"{"from":"ann@example.org","to":"d@example.com","text":"x"}"#;
            let other = r#"{"from":"ann@example.org","to":"e@example.com","text":"x"}"#;
            let small = message("Ann <ann@example.org>", "", 3000, seed);
            let to_a = "Envelope-From: ann@example.org\r\nEnvelope-To: a@example.com\r\n";
            let to_b = "Envelope-From: ann@example.org\r\nEnvelope-To: b@example.com\r\n";
            let mut ids = BTreeSet::new();
            for core in [0, 1] {
                let key = owned_key(&nodes[0], &format!("json{seed}"), core).await;
                let mut http = Http::plain().await;
                let reply = http.send_reply(&keyed(first, &key, body)).await;
                assert_eq!(reply.header("idempotent-replayed"), None);
                let id = reply.id();
                let again = http.send_reply(&keyed(first, &key, body)).await;
                assert_eq!(again.header("idempotent-replayed"), Some("true"));
                assert_eq!(again.id(), id);
                let refused = http.send_reply(&keyed(first, &key, other)).await;
                assert_eq!(
                    (refused.status, refused.code().as_str()),
                    (422, "idempotency_conflict")
                );
                ids.insert(opaque(&nodes[0], &id));

                let key = owned_key(&nodes[0], &format!("raw{seed}"), core).await;
                let fields = |envelope: &str| format!("Idempotency-Key: {key}\r\n{envelope}");
                let reply = http.send_reply(&raw(first, &fields(to_a), &small)).await;
                let id = reply.id();
                let again = http.send_reply(&raw(first, &fields(to_a), &small)).await;
                assert_eq!(again.header("idempotent-replayed"), Some("true"));
                assert_eq!(again.id(), id);
                let refused = http.send_reply(&raw(first, &fields(to_b), &small)).await;
                assert_eq!(
                    (refused.status, refused.code().as_str()),
                    (422, "idempotency_conflict")
                );
                ids.insert(opaque(&nodes[0], &id));

                let key = owned_key(&nodes[0], &format!("race{seed}"), core).await;
                let mut one = Http::plain().await;
                let mut two = Http::plain().await;
                one.send(&keyed(first, &key, body)).await;
                two.send(&keyed(first, &key, body)).await;
                let (one, two) = (
                    one.reply().await.expect("one"),
                    two.reply().await.expect("two"),
                );
                assert_eq!(one.id(), two.id());
                let replayed = [&one, &two]
                    .iter()
                    .filter(|r| r.header("idempotent-replayed").is_some())
                    .count();
                assert_eq!(replayed, 1);
                ids.insert(opaque(&nodes[0], &one.id()));
            }
            assert_eq!(stored(&nodes), ids);
            assert_eq!(owners.serving(), 0);
            owners.stop();
            ports.close().await;
        });
        owners.join(&cluster.machine);
        cluster.stop();
    });
}

fn json(token: &str, fields: &str, body: &str) -> Vec<u8> {
    format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {token}\r\n\
         {fields}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn mixed(token: &str, from: &str, key: Option<&str>, n: u64, m: u64) -> Vec<u8> {
    let fields = key
        .map(|key| format!("Idempotency-Key: {key}\r\n"))
        .unwrap_or_default();
    if (n + m).is_multiple_of(2) {
        let body = format!(
            r#"{{"from":"{from}","to":["a@example.com","b@example.net"],"text":"m{n}-{m}"}}"#
        );
        json(token, &fields, &body)
    } else {
        let size = [300, 3000, 90_000, 200_000][usize::try_from((n + m) % 4).expect("small")];
        let envelope = format!("{fields}Envelope-From: {from}\r\nEnvelope-To: a@example.com\r\n");
        raw(token, &envelope, &message(from, "", size, n * 100 + m))
    }
}

#[derive(Default)]
struct Calls {
    keyed: BTreeMap<String, (Vec<u8>, Option<MessageId>)>,
    unkeyed: BTreeSet<MessageId>,
    sent: usize,
}

async fn api_client(
    node: Node<Idle>,
    tokens: Rc<(String, String)>,
    tls: Arc<ClientConfig>,
    n: u64,
    calls: Rc<RefCell<Calls>>,
) {
    let mut http = if n.is_multiple_of(2) {
        Http::plain().await
    } else {
        Http::tls(&tls).await
    };
    for m in 0..6u64 {
        let keyed = !(n + m).is_multiple_of(3);
        let (token, from) = if keyed {
            (&tokens.0, "ann@example.org")
        } else {
            (&tokens.1, "ann@example.info")
        };
        let key = keyed.then(|| format!("c{n}-{m}"));
        let request = mixed(token, from, key.as_deref(), n, m);
        if let Some(key) = &key {
            let entry = (request.clone(), None);
            calls.borrow_mut().keyed.insert(key.clone(), entry);
        }
        if !http.try_send(&request).await {
            return;
        }
        if !keyed {
            calls.borrow_mut().sent += 1;
        }
        let Some(reply) = http.reply().await else {
            return;
        };
        if reply.status != 200 {
            return;
        }
        let id = opaque(&node, &reply.id());
        let Some(key) = key else {
            calls.borrow_mut().unkeyed.insert(id);
            continue;
        };
        if let Some(entry) = calls.borrow_mut().keyed.get_mut(&key) {
            entry.1 = Some(id);
        }
        if m.is_multiple_of(2) {
            if !http.try_send(&request).await {
                return;
            }
            let Some(again) = http.reply().await else {
                return;
            };
            if again.status == 200 {
                assert_eq!(opaque(&node, &again.id()), id, "retry of {key}");
                assert_eq!(again.header("idempotent-replayed"), Some("true"));
            }
        }
    }
}

async fn halted(driver: Rc<SimDriver>) {
    while !driver.is_halted() {
        sleep(Duration::from_millis(50)).await;
    }
}

async fn until_accepted(request: &[u8]) -> Reply {
    for _ in 0..50 {
        let mut http = Http::plain().await;
        if http.try_send(request).await
            && let Some(reply) = http.reply().await
            && reply.status == 200
        {
            return reply;
        }
        sleep(Duration::from_millis(200)).await;
    }
    panic!("request never accepted");
}

fn load_until_halt(cluster: &Cluster, driver: &Rc<SimDriver>, seed: u64, tokens: &Tokens) -> Calls {
    let calls: Rc<RefCell<Calls>> = Rc::default();
    let forwards = Mesh::new(u16::try_from(cluster.nodes.len()).expect("cores"));
    let _owners = owners(cluster, &forwards);
    let ends = forwards.take(0).expect("ends");
    let nodes = cluster.nodes.clone();
    let tokens = Rc::new((tokens.first.clone(), tokens.third.clone()));
    let (shared, power) = (Rc::clone(&calls), Rc::clone(driver));
    cluster.run(async move {
        let config = ApiConfig::new("mx1.example.net".into());
        let _ports = serve_with(&nodes[0], seed, config, ends).await;
        let tls = client_config(simulated(seed + 100));
        let clients: Vec<_> = (0..4)
            .map(|n| {
                let tokens = Rc::clone(&tokens);
                spawn(api_client(
                    nodes[0].clone(),
                    tokens,
                    Arc::clone(&tls),
                    n,
                    Rc::clone(&shared),
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
    std::mem::take(&mut *calls.borrow_mut())
}

fn api_crash(seed: u64, cores: u16, crashed: &Cell<u32>) {
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started_on(&driver, cores).expect("start");
    let nodes = cluster.nodes.clone();
    let tokens = cluster.run(async move { prepare(&nodes).await });
    cluster.stop();

    let config = Config {
        halt_after: Some(80 + seed * 53 % 400),
        ..Config::default()
    };
    let driver = Rc::new(SimDriver::with_disk(seed + 1, config, driver.crash()));
    let calls = match started_on(&driver, cores) {
        Some(cluster) => load_until_halt(&cluster, &driver, seed, &tokens),
        None => Calls::default(),
    };
    let answered = calls.keyed.values().any(|(_, id)| id.is_some()) || !calls.unkeyed.is_empty();
    if driver.is_halted() && answered {
        crashed.set(crashed.get() + 1);
    }

    let driver = Rc::new(SimDriver::with_disk(
        seed + 2,
        Config::default(),
        driver.crash(),
    ));
    let restarted = started_on(&driver, cores).expect("restart");
    let forwards = Mesh::new(cores);
    let owners = owners(&restarted, &forwards);
    let ends = forwards.take(0).expect("ends");
    let nodes = restarted.nodes.clone();
    let watched = Rc::clone(&owners);
    let first = tokens.first.clone();
    restarted.run(async move {
        let owners = watched;
        let config = ApiConfig::new("mx1.example.net".into());
        let ports = serve_with(&nodes[0], seed, config, ends).await;
        let mut ids = BTreeSet::new();
        for (key, (request, answered)) in &calls.keyed {
            let reply = until_accepted(request).await;
            let id = opaque(&nodes[0], &reply.id());
            if let Some(answered) = answered {
                assert_eq!(
                    id, *answered,
                    "seed {seed}: {key} answered again with another id"
                );
                assert_eq!(reply.header("idempotent-replayed"), Some("true"));
            }
            ids.insert(id);
        }
        let of = |tenant| -> BTreeSet<MessageId> {
            nodes
                .iter()
                .flat_map(|n| n.spool().messages_of(tenant))
                .collect()
        };
        assert_eq!(
            of(1),
            ids,
            "seed {seed}: keyed messages differ from the answers"
        );
        let unkeyed = of(3);
        assert!(
            calls.unkeyed.is_subset(&unkeyed),
            "seed {seed}: answered message lost"
        );
        assert!(
            unkeyed.len() <= calls.sent,
            "seed {seed}: unkeyed stored twice"
        );
        if let Some(key) = calls.keyed.keys().next() {
            let mut http = Http::plain().await;
            let other = r#"{"from":"ann@example.org","to":"z@example.com","text":"other"}"#;
            let fields = format!("Idempotency-Key: {key}\r\n");
            let refused = http.send_reply(&json(&first, &fields, other)).await;
            assert_eq!(
                (refused.status, refused.code().as_str()),
                (422, "idempotency_conflict")
            );
        }
        assert_eq!(owners.serving(), 0);
        owners.stop();
        ports.close().await;
    });
    owners.join(&restarted.machine);
    restarted.stop();
}

#[test]
fn keyed_requests_survive_crashes_on_two_cores() {
    let crashed = Rc::new(Cell::new(0));
    let counted = Rc::clone(&crashed);
    check(0..6, move |seed| api_crash(seed, 2, &counted));
    assert!(crashed.get() > 0, "no crash after an answered request");
}

#[test]
fn keyed_requests_survive_crashes_on_four_cores() {
    let crashed = Rc::new(Cell::new(0));
    let counted = Rc::clone(&crashed);
    check(0..4, move |seed| api_crash(seed, 4, &counted));
    assert!(crashed.get() > 0, "no crash after an answered request");
}

#[test]
fn tenants_never_share_keys_or_senders() {
    check(0..2, |seed| {
        let cluster = started(seed, 2);
        let nodes = cluster.nodes.clone();
        let forwards = Mesh::new(2);
        let owners = owners(&cluster, &forwards);
        let ends = forwards.take(0).expect("ends");
        let watched = Rc::clone(&owners);
        cluster.run(async move {
            let owners = watched;
            let tokens = prepare(&nodes).await;
            let config = ApiConfig::new("mx1.example.net".into());
            let ports = serve_with(&nodes[0], seed, config, ends).await;
            let (first, third) = (tokens.first.as_str(), tokens.third.as_str());
            let mut http = Http::plain().await;
            let mut ours = BTreeSet::new();
            let mut theirs = BTreeSet::new();
            for core in [0, 1] {
                let key = owned_key(&nodes[0], &format!("shared{seed}"), core).await;
                let fields = format!("Idempotency-Key: {key}\r\n");
                let body = r#"{"from":"ann@example.org","to":"a@example.com","text":"x"}"#;
                let one = http.send_reply(&json(first, &fields, body)).await;
                ours.insert(opaque(&nodes[0], &one.id()));
                let mut other = Http::plain().await;
                let refused = other.send_reply(&json(third, &fields, body)).await;
                assert_eq!((refused.status, refused.code().as_str()), (403, "sender_not_allowed"));
                let own = r#"{"from":"ann@example.info","to":"a@example.com","text":"x"}"#;
                let three = http.send_reply(&json(third, &fields, own)).await;
                assert_eq!(three.header("idempotent-replayed"), None);
                assert_ne!(three.id(), one.id());
                theirs.insert(opaque(&nodes[0], &three.id()));

                let key = owned_key(&nodes[0], &format!("raw{seed}"), core).await;
                let small = message("Ann <ann@example.org>", "", 500, seed);
                let envelope = format!(
                    "Idempotency-Key: {key}\r\nEnvelope-From: ann@example.org\r\nEnvelope-To: a@example.com\r\n"
                );
                let one = http.send_reply(&raw(first, &envelope, &small)).await;
                ours.insert(opaque(&nodes[0], &one.id()));
                let mut other = Http::plain().await;
                let refused = other.send_reply(&raw(third, &envelope, &small)).await;
                assert_eq!((refused.status, refused.code().as_str()), (403, "sender_not_allowed"));
                let mine = message("Ann <ann@example.info>", "", 500, seed);
                let envelope = format!(
                    "Idempotency-Key: {key}\r\nEnvelope-From: ann@example.info\r\nEnvelope-To: a@example.com\r\n"
                );
                let three = http.send_reply(&raw(third, &envelope, &mine)).await;
                assert_eq!(three.header("idempotent-replayed"), None);
                theirs.insert(opaque(&nodes[0], &three.id()));
            }
            let of = |tenant| -> BTreeSet<MessageId> {
                nodes.iter().flat_map(|n| n.spool().messages_of(tenant)).collect()
            };
            assert_eq!(of(1), ours);
            assert_eq!(of(3), theirs);
            let mut plain = Http::plain().await;
            let health = format!(
                "GET /healthz HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {third}\r\n\r\n"
            );
            let reply = plain.send_reply(health.as_bytes()).await;
            assert_eq!(reply.body, b"{\"status\":\"ok\"}");
            owners.stop();
            ports.close().await;
        });
        owners.join(&cluster.machine);
        cluster.stop();
    });
}

fn get(token: &str, query: &str) -> Vec<u8> {
    format!(
        "GET /v1/events{query} HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
    .into_bytes()
}

fn page(reply: &Reply) -> (Vec<Value>, String, bool) {
    assert_eq!(reply.status, 200, "{reply:?}");
    let value = reply.json();
    let events = value
        .get("events")
        .and_then(Value::as_array)
        .expect("events")
        .to_vec();
    let next = value
        .get("next")
        .and_then(Value::as_str)
        .expect("next")
        .to_owned();
    let more = value.get("more").and_then(Value::as_bool).expect("more");
    (events, next, more)
}

#[test]
fn events_are_read_in_pages_over_http() {
    check(0..2, |seed| {
        let cluster = started(seed, 2);
        let nodes = cluster.nodes.clone();
        let seen = Rc::clone(&cluster.seen);
        cluster.run(async move {
            let tokens = prepare(&nodes).await;
            seen.deliver.set(Some(nodes[0].sched().clock()));
            let ports = serve(&nodes[0], seed, ApiConfig::new("mx1.example.net".into())).await;
            let mut http = Http::plain().await;
            let mut expected = BTreeSet::new();
            for to in [
                r#"["a@example.com","b@example.com"]"#,
                r#""c@example.com""#,
                r#"["d@example.com","e@example.com"]"#,
            ] {
                let body = format!(r#"{{"from":"ann@example.org","to":{to},"text":"x"}}"#);
                let id = http.post(&tokens.first, &body).await.id();
                let count = to.matches('@').count();
                for recipient in 0..count {
                    expected.insert((id.clone(), recipient as u64));
                }
            }

            let mut found = Vec::new();
            let mut cursor = String::new();
            for _ in 0..2000 {
                let query = if cursor.is_empty() {
                    "?limit=2".to_owned()
                } else {
                    format!("?limit=2&after={cursor}")
                };
                let (events, next, more) =
                    page(&http.send_reply(&get(&tokens.first, &query)).await);
                assert!(events.len() <= 2);
                found.extend(events);
                cursor = next;
                if found.len() >= expected.len() && !more {
                    break;
                }
                if !more {
                    sleep(Duration::from_millis(10)).await;
                }
            }
            let mut keys = BTreeSet::new();
            for event in &found {
                let text = |name: &str| {
                    event
                        .get(name)
                        .and_then(Value::as_str)
                        .expect(name)
                        .to_owned()
                };
                let number = |name: &str| event.get(name).and_then(Value::as_u64).expect(name);
                assert_eq!(text("type"), "delivered");
                let time = text("time");
                assert!(time.len() == 24 && time.ends_with('Z'), "{time}");
                assert!(text("address").ends_with("@example.com"));
                assert_eq!(text("reply"), "250 2.0.0 ok");
                assert_eq!(number("attempts"), 1);
                assert!(event.get("lost").is_none());
                keys.insert((text("message_id"), number("recipient")));
            }
            assert_eq!(found.len(), expected.len());
            assert_eq!(keys, expected);
            let after = format!("?after={cursor}");
            let (events, _, more) = page(&http.send_reply(&get(&tokens.first, &after)).await);
            assert!(events.is_empty() && !more);

            let (events, _, more) = page(&http.send_reply(&get(&tokens.second, "")).await);
            assert!(events.is_empty() && !more);
            let reply = http.send_reply(&get(&tokens.second, &after)).await;
            assert_eq!((reply.status, reply.code().as_str()), (400, "bad_cursor"));
            assert_eq!(ports.count(Route::Events, 400), 1);
            ports.close().await;
        });
        cluster.stop();
    });
}

#[test]
fn event_reads_refuse_bad_queries_and_parallel_reads() {
    check(0..2, |seed| {
        let cluster = started(seed, 2);
        let nodes = cluster.nodes.clone();
        cluster.run(async move {
            let tokens = prepare(&nodes).await;
            let ports = serve(&nodes[0], seed, ApiConfig::new("mx1.example.net".into())).await;
            let mut http = Http::plain().await;
            let (_, cursor, _) = page(&http.send_reply(&get(&tokens.first, "")).await);
            let reply = http
                .send_reply(&get(&tokens.second, &format!("?after={cursor}")))
                .await;
            assert_eq!((reply.status, reply.code().as_str()), (400, "bad_cursor"));
            for query in ["?after=zz", "?after="] {
                let reply = http.send_reply(&get(&tokens.first, query)).await;
                assert_eq!(
                    (reply.status, reply.code().as_str()),
                    (400, "bad_cursor"),
                    "{query}"
                );
            }
            for query in [
                "?limit=0",
                "?limit=1001",
                "?limit=+5",
                "?limit=",
                "?limit=99999999999999999999999",
                "?limit=1&limit=1",
                "?other=1",
                "?limit",
                "?limit=1&",
            ] {
                let reply = http.send_reply(&get(&tokens.first, query)).await;
                assert_eq!(
                    (reply.status, reply.code().as_str()),
                    (400, "bad_request"),
                    "{query}"
                );
            }
            let reply = http.send_reply(&get(&tokens.first, "?")).await;
            assert_eq!(reply.status, 200);
            let reply = http.send_reply(&get(&tokens.smtp, "")).await;
            assert_eq!(reply.status, 401);
            for method in ["POST", "OPTIONS", "DELETE"] {
                let request = format!(
                    "{method} /v1/events HTTP/1.1\r\nHost: api.test\r\nContent-Length: 0\r\n\r\n"
                );
                let reply = http.send_reply(request.as_bytes()).await;
                assert_eq!(reply.status, 405, "{method}");
                assert_eq!(reply.header("allow"), Some("GET, HEAD"));
            }

            let head = format!(
                "HEAD /v1/events HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {}\r\n\
                 Connection: close\r\n\r\n",
                tokens.first
            );
            let mut probe = Http::plain().await;
            probe.send(head.as_bytes()).await;
            while probe.fill().await {}
            let text = String::from_utf8(probe.input.clone()).expect("ascii");
            assert!(text.starts_with("HTTP/1.1 200"), "{text}");
            assert!(text.ends_with("\r\n\r\n"), "{text}");
            assert!(ports.count(Route::Events, 200) >= 3);
            ports.close().await;
        });
        cluster.stop();
    });
}
