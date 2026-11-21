mod common;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aws_lc_rs::hmac;
use common::Zone;
use control::{Created, KeyError, KeySource, Object, Pool, Ready, State, Tenant};
use crypto::{BatchKey, Secret, Tenant as Root, TenantKeys, Wrap, day_public, open_batch};
use deliver::{Cidr, Dns, HookSettings, Hooks, Local};
use dns::{Error, Found, Lookup, Name, Record, Type};
use keys::{BatchSettings, Batches, Working};
use rt::sim::{Config, Disk, Machine, SimDriver, Stalls};
use rt::{Instant, JoinHandle, Runtime, TcpListener, TcpStream, now, sleep, spawn};
use sched::{
    Answered, Attempt, Batched, Clock, Cursor, HookChange, HookSecret, KIND_EVENT, Keys, Meshes,
    Node, Parts, ROTATION_MS, Recipient, Restore, Running, Settings, Transport, Unsealable,
    Unwrapped, encode_slice, event_sequence, read_cursor, write_cursor,
};
use spool::{HeadClear, Message};
use store::{Committer, DataFile, Options, SLOT_SIZE, Setup, boot};
use tls::{Acceptor, Certs, Connector, simulated};

const PATH: &str = "/data/store";
const SHARDS: u16 = 8;

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 8 * SLOT_SIZE,
    region_count: 96,
    shards: SHARDS as u32,
};

const NAMING: [u8; 16] = *b"naming key 16 by";

const CERT: &[u8] = include_bytes!("data/hook.pem");
const ROOTS: &[u8] = include_bytes!("data/hook-ca.pem");
const KEY: &str = "302e020100300506032b657004220420b04b8347668a2cc5e9e19dc162da5f289c84fc8bd9dfa7c4e7e90a6a77b234e8";

fn key() -> Vec<u8> {
    let der: Vec<u8> = (0..KEY.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&KEY[i..i + 2], 16).expect("hex"))
        .collect();
    let label = "PRIVATE KEY";
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        dkim::base64::encode(&der)
    )
    .into_bytes()
}

fn a(ips: &[IpAddr]) -> Found {
    Found::Records(
        ips.iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => Record::A(*v4),
                IpAddr::V6(v6) => Record::Aaaa(*v6),
            })
            .collect(),
    )
}

fn b64(data: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let high = u32::from(chunk[0]);
        let mid = u32::from(*chunk.get(1).unwrap_or(&0));
        let low = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = high << 16 | mid << 8 | low;
        out.push(DIGITS[(n >> 18) as usize & 63] as char);
        out.push(DIGITS[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            DIGITS[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            DIGITS[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn signed(id: &str, stamp: &str, body: &[u8], secret: &Secret<32>) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose());
    let mut data = Vec::new();
    data.extend_from_slice(id.as_bytes());
    data.push(b'.');
    data.extend_from_slice(stamp.as_bytes());
    data.push(b'.');
    data.extend_from_slice(body);
    b64(hmac::sign(&key, &data).as_ref())
}

struct Toy {
    batches: RefCell<Batches>,
    down: Arc<AtomicBool>,
}

impl Toy {
    fn new(down: Arc<AtomicBool>) -> Self {
        Self {
            batches: RefCell::new(Batches::new(BatchSettings::default())),
            down,
        }
    }
}

impl KeySource for Toy {
    fn get(&self, tenant: u32, generation: u32) -> Option<TenantKeys> {
        let root = Root::new(&Secret::new(
            [u8::try_from(tenant % 200).expect("small"); 32],
        ));
        Some(TenantKeys::derive(tenant, generation, &root, 1))
    }

    fn create(&self, _tenant: u32, _: u32) -> Created<'_> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn ready(&self, tenant: u32, generation: u32) -> Ready<'_> {
        Box::pin(std::future::ready(
            self.get(tenant, generation).ok_or(KeyError::Unknown),
        ))
    }
}

const TOY_DAY: u32 = 20_000;

fn toy_day_secret(tenant: u32, day: u32) -> Secret<32> {
    let mut bytes = [9; 32];
    bytes[..4].copy_from_slice(&tenant.to_le_bytes());
    bytes[4..8].copy_from_slice(&day.to_le_bytes());
    Secret::new(bytes)
}

impl Keys for Toy {
    fn system(&self) -> Ready<'_> {
        Box::pin(std::future::ready(Ok(TenantKeys::derive(
            0,
            0,
            &Root::new(&Secret::new([42; 32])),
            1,
        ))))
    }

    fn batch(&self, tenant: u32, generation: u32, shard: u16, first: u64) -> Batched<'_> {
        let batch = match self.get(tenant, generation) {
            Some(keys) => {
                let public = |day| day_public(&toy_day_secret(tenant, day)).expect("public");
                let working = Working {
                    keys,
                    day: TOY_DAY,
                    oldest: TOY_DAY,
                    today: public(TOY_DAY),
                    tomorrow: public(TOY_DAY + 1),
                    seen: TOY_DAY,
                };
                self.batches
                    .borrow_mut()
                    .seal(&working, shard, first, now())
                    .map_err(|_| KeyError::Unavailable)
            }
            None => Err(KeyError::Unavailable),
        };
        Box::pin(std::future::ready(batch))
    }

    fn batch_key(
        &self,
        tenant: u32,
        generation: u32,
        shard: u16,
        id: u64,
        wrap: Wrap,
    ) -> Unwrapped<'_> {
        let key = if self.down.load(Ordering::SeqCst) {
            Err(Unsealable::Unavailable)
        } else if (wrap.generation, wrap.shard) == (generation, shard) {
            open_batch(&toy_day_secret(tenant, wrap.day), tenant, id, &wrap)
                .map(|secret| Rc::new(BatchKey::new(&secret)))
                .map_err(|_| Unsealable::Bad)
        } else {
            Err(Unsealable::Bad)
        };
        Box::pin(std::future::ready(key))
    }

    fn hook_secret(&self, tenant: u32, generation: u32, hook: u32, version: u8) -> HookSecret<'_> {
        let root = Root::new(&Secret::new(
            [u8::try_from(tenant % 200).expect("small"); 32],
        ));
        Box::pin(std::future::ready(Ok(Arc::new(
            root.hook_secret(generation, hook, version),
        ))))
    }

    fn ids(&self) -> Option<Secret<16>> {
        Some(Secret::new([7; 16]))
    }
}

struct Idle;

impl Transport for Idle {
    fn send(&self, _attempt: Attempt) -> impl Future<Output = Vec<Answered>> {
        std::future::ready(Vec::new())
    }

    fn restore(&self, _restore: Restore) -> impl Future<Output = ()> {
        std::future::ready(())
    }

    fn tick(&self) -> impl Future<Output = ()> {
        std::future::ready(())
    }
}

struct Cluster {
    machine: Machine,
    nodes: Vec<Node<Idle>>,
    runnings: Vec<Running>,
    committer: JoinHandle<Committer>,
}

impl Cluster {
    fn run<T: 'static>(&self, future: impl Future<Output = T> + 'static) -> T {
        self.machine.block_on(1, future)
    }

    fn stop(self) {
        let Self {
            machine,
            nodes,
            runnings,
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

fn settings_named(key: [u8; 16]) -> Settings {
    Settings {
        node: 3,
        spool: spool::Limits {
            recipients: 100,
            inline: 2048,
            body: 64 * 1024,
            read: 1024 * 1024,
        },
        naming: control::Naming {
            key,
            shards: u32::from(SHARDS),
            cache: 16,
        },
        sched: sched::Config::new(u32::from(SHARDS)),
        budget: usize::try_from(OPTIONS.region_size / 2).expect("fits"),
    }
}

fn started(seed: u64) -> Cluster {
    started_with(seed, &Arc::default())
}

fn started_with(seed: u64, down: &Arc<AtomicBool>) -> Cluster {
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cores = 1;
    let machine = Machine::new(Rc::clone(&driver), cores + 1, Stalls::default());
    let setup = Setup {
        cores: 1,
        credits: 4,
        reserve: 4,
        flush: 1,
    };
    let booted = machine
        .block_on(0, async move {
            rt::timeout(Duration::from_secs(60), boot(PATH, setup)).await
        })
        .expect("timeout")
        .expect("boot");
    let committer = machine.spawn_on(0, booted.committer.run());
    drop(booted.client);
    let meshes = Arc::new(Meshes::new(1));
    let mut tasks = Vec::new();
    for start in booted.starts {
        let index = start.index();
        let links = meshes.take(index).expect("links");
        let down = Arc::clone(down);
        tasks.push(machine.spawn_on(usize::from(index) + 1, async move {
            let core = rt::timeout(Duration::from_secs(60), start.open())
                .await
                .expect("timeout")
                .expect("open");
            let parts = Parts {
                keys: Rc::new(Toy::new(down)),
                transport: Idle,
                clock: Clock::at(rt::wall_ms(), now()),
            };
            rt::timeout(
                Duration::from_secs(60),
                Node::start(core, links, settings_named(NAMING), parts),
            )
            .await
            .expect("timeout")
            .expect("node")
        }));
    }
    let (nodes, runnings) = machine
        .block_on(0, async move {
            let mut started = Vec::new();
            for task in tasks {
                started.push(task.await);
            }
            started
        })
        .into_iter()
        .unzip();
    Cluster {
        machine,
        nodes,
        runnings,
        committer,
    }
}

fn tenant(id: u32, generation: u32, state: State) -> Object {
    Object::Tenant(Tenant {
        id,
        generation,
        state,
        default_pool: 1,
        pools: vec![1],
        limits: control::Limits::default(),
    })
}

async fn configure(nodes: &[Node<Idle>], objects: Vec<Object>) {
    let control = nodes.iter().find(|n| n.controls()).expect("control core");
    for object in objects {
        control.write(object).await.expect("write");
    }
}

async fn wait_for(nodes: &[Node<Idle>], tenant: u32, generation: u32, state: State) {
    for node in nodes {
        while !node
            .table()
            .tenant(tenant)
            .is_some_and(|t| t.generation == generation && t.state == state)
        {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

async fn ready(nodes: &[Node<Idle>]) {
    let pool = Object::Pool(Pool {
        id: 1,
        addresses: vec![(IpAddr::from([192, 0, 2, 1]), 1)],
    });
    let missing: Vec<Object> = {
        let control = nodes.iter().find(|n| n.controls()).expect("control core");
        let table = control.table();
        let mut objects = Vec::new();
        if table.pool(1).is_none() {
            objects.push(pool);
        }
        for id in [1, 2] {
            if table.tenant(id).is_none() {
                objects.push(tenant(id, 1, State::Active));
            }
        }
        objects
    };
    configure(nodes, missing).await;
    wait_for(nodes, 1, 1, State::Active).await;
    wait_for(nodes, 2, 1, State::Active).await;
}

async fn owned_shard(node: &Node<Idle>) -> u16 {
    for shard in 0..SHARDS {
        if node.spool().id(shard).await.is_ok() {
            return shard;
        }
    }
    panic!("no shard on this core");
}

async fn expire_one(node: &Node<Idle>, tenant: u32, n: u8) {
    let shard = owned_shard(node).await;
    let address = format!("x{n}@example.org");
    let mut draft = node.draft(tenant, None).expect("draft");
    node.recipient(&mut draft, &address)
        .await
        .expect("recipient");
    let mut sealing = node.sealing(&mut draft, shard).await.expect("sealing");
    let clear = HeadClear {
        recipients: 1,
        accepted: 5,
        ..HeadClear::default()
    };
    let head = sealing
        .head(clear, 1, &[n; 10], b"Subject: hi\r\n")
        .expect("head");
    let body = sealing.inline_body(&[n; 30]).expect("body");
    let listed = vec![Recipient {
        address: address.clone(),
        orcpt: Vec::new(),
        notify: 0,
    }];
    let plain = encode_slice(&listed).expect("slice");
    let slice = sealing
        .slice(0, draft.queues().to_vec(), &plain)
        .expect("slice");
    let id = sealing.id();
    let message = Message {
        id,
        tenant,
        head,
        body,
        slices: vec![slice],
    };
    node.accept(draft, message).await.expect("accept");
    for _ in 0..20_000 {
        if node.spool().tenant(id).is_none() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("message not swept");
}

async fn acked(node: &Node<Idle>, tenant: u32, hook: u32) -> BTreeMap<u16, u64> {
    let mut found = BTreeMap::new();
    for shard in node.spool().shards() {
        let cursor = read_cursor(node.spool().changes(), shard, tenant, hook)
            .await
            .expect("read");
        found.insert(shard, cursor.map_or(0, |c| c.acked));
    }
    found
}

fn event_key(tenant: u32, sequence: u64) -> [u8; 20] {
    let mut key = [0; 20];
    key[..4].copy_from_slice(&tenant.to_be_bytes());
    key[4..12].copy_from_slice(&sequence.to_be_bytes());
    key
}

async fn event_ends(node: &Node<Idle>, tenant: u32) -> BTreeMap<u16, u64> {
    let range = event_key(tenant, 0)..event_key(tenant, u64::MAX);
    let found = node
        .spool()
        .changes()
        .scan_kind(KIND_EVENT, range, 1000)
        .await
        .expect("scan");
    let mut ends = BTreeMap::new();
    for (shard, entry) in found {
        let end = ends.entry(shard).or_insert(0);
        *end = (*end).max(event_sequence(&entry.key));
    }
    ends
}

async fn acked_through_events(
    node: &Node<Idle>,
    tenant: u32,
    hook: u32,
    before: &BTreeMap<u16, u64>,
) {
    let mut want = before.clone();
    let ends = event_ends(node, tenant).await;
    assert!(!ends.is_empty(), "no events were stored");
    for (shard, end) in ends {
        want.insert(shard, end);
    }
    assert_ne!(&want, before, "the events are not past the cursor");
    for _ in 0..30_000 {
        if acked(node, tenant, hook).await == want {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let found = acked(node, tenant, hook).await;
    panic!("cursor is {found:?}, want {want:?}");
}

fn http_date(ms: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rest = secs % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[usize::try_from(days % 7).expect("small")],
        MONTHS[usize::try_from(month - 1).expect("small")],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
    )
}

#[derive(Default)]
struct Owns(Vec<IpAddr>);

impl Local for Owns {
    fn bound(&self, ip: IpAddr) -> impl Future<Output = bool> {
        std::future::ready(self.0.contains(&ip))
    }
}

#[derive(Clone)]
struct Slow {
    zone: Zone,
    delay: Duration,
    started: Rc<Cell<u32>>,
}

impl Dns for Slow {
    async fn lookup(&self, name: &Name, kind: Type) -> Result<Rc<Lookup>, Error> {
        self.started.set(self.started.get() + 1);
        sleep(self.delay).await;
        self.zone.lookup(name, kind).await
    }
}

fn connector() -> Connector {
    Connector::new(simulated(2), Some(ROOTS)).expect("connector")
}

fn sender(
    node: &Node<Idle>,
    zone: &Zone,
    settings: HookSettings,
    seed: u64,
) -> Hooks<Idle, Zone, Owns> {
    Hooks::with_local(
        node.clone(),
        zone.clone(),
        connector(),
        settings,
        seed,
        Owns::default(),
    )
}

struct Got {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    peer: IpAddr,
    at: Instant,
}

impl Got {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, v)| v.as_str())
    }
}

#[derive(Clone)]
struct Answer {
    status: u16,
    headers: Vec<String>,
    early: Vec<String>,
    delay: Duration,
}

impl Answer {
    fn ok() -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            early: Vec::new(),
            delay: Duration::ZERO,
        }
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::ok()
        }
    }
}

#[derive(Default)]
struct Server {
    got: RefCell<Vec<Got>>,
    open: Cell<u32>,
    live: Cell<u32>,
    most: Cell<u32>,
    hangups: Cell<u32>,
}

impl Server {
    fn gap(&self, n: usize) -> Duration {
        let got = self.got.borrow();
        got[n + 1].at.saturating_duration_since(got[n].at)
    }
}

struct Guard(Rc<Server>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.live.set(self.0.live.get() - 1);
    }
}

fn serve(ip: IpAddr, port: u16, script: Rc<dyn Fn(usize) -> Answer>) -> Rc<Server> {
    serve_tls_late(ip, port, Duration::ZERO, script)
}

fn serve_tls_late(
    ip: IpAddr,
    port: u16,
    tls_delay: Duration,
    script: Rc<dyn Fn(usize) -> Answer>,
) -> Rc<Server> {
    let server = Rc::new(Server::default());
    let shared = Rc::clone(&server);
    let certs = Arc::new(Certs::new(CERT, &key()).expect("certs"));
    let acceptor = Rc::new(Acceptor::new(simulated(1), certs).expect("acceptor"));
    drop(spawn(async move {
        let listener = TcpListener::bind(SocketAddr::new(ip, port), 16)
            .await
            .expect("bind");
        while let Ok((io, peer)) = listener.accept().await {
            shared.open.set(shared.open.get() + 1);
            shared.live.set(shared.live.get() + 1);
            shared.most.set(shared.most.get().max(shared.live.get()));
            let session = session(
                io,
                peer.ip(),
                tls_delay,
                Rc::clone(&acceptor),
                Rc::clone(&script),
                Rc::clone(&shared),
            );
            drop(spawn(session));
        }
    }));
    server
}

async fn session(
    io: TcpStream,
    peer: IpAddr,
    tls_delay: Duration,
    acceptor: Rc<Acceptor>,
    script: Rc<dyn Fn(usize) -> Answer>,
    server: Rc<Server>,
) {
    let _guard = Guard(Rc::clone(&server));
    sleep(tls_delay).await;
    let Ok(mut stream) = acceptor.accept(io).await else {
        return;
    };
    let mut buf = Vec::new();
    let mut chunk = [0; 4096];
    let end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buf.len() > 64 * 1024 {
            return;
        }
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            server.hangups.set(server.hangups.get() + 1);
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    buf.drain(..end);
    let mut lines = head.split("\r\n");
    let line = lines.next().unwrap_or_default().to_owned();
    let mut length = 0;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        if name == "content-length" {
            length = value.parse().unwrap_or(0);
        }
        headers.push((name, value));
    }
    while buf.len() < length {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let n = server.got.borrow().len();
    server.got.borrow_mut().push(Got {
        line,
        headers,
        body: buf[..length].to_vec(),
        peer,
        at: now(),
    });
    let answer = script(n);
    for early in &answer.early {
        if stream.write_all(early.as_bytes()).await.is_err() {
            return;
        }
    }
    sleep(answer.delay).await;
    let mut response = format!("HTTP/1.1 {} x\r\n", answer.status);
    for header in &answer.headers {
        response.push_str(header);
        response.push_str("\r\n");
    }
    response.push_str("Content-Length: 0\r\n\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn serve_plain(ip: IpAddr) -> Rc<Cell<u32>> {
    let open = Rc::new(Cell::new(0));
    let shared = Rc::clone(&open);
    drop(spawn(async move {
        let listener = TcpListener::bind(SocketAddr::new(ip, 443), 16)
            .await
            .expect("bind");
        while let Ok((io, _)) = listener.accept().await {
            shared.set(shared.get() + 1);
            drop(io);
        }
    }));
    open
}

async fn got(server: &Server, n: usize) {
    for _ in 0..1_200 {
        if server.got.borrow().len() >= n {
            return;
        }
        sleep(Duration::from_secs(6)).await;
    }
    panic!(
        "only {} requests, {} connections",
        server.got.borrow().len(),
        server.open.get()
    );
}

async fn hooks_ready(node: &Node<Idle>, tenant: u32, hooks: &[u32]) {
    let shard = *node.spool().shards().last().expect("shard");
    for &hook in hooks {
        let mut found = false;
        for _ in 0..30_000 {
            found = read_cursor(node.spool().changes(), shard, tenant, hook)
                .await
                .expect("read")
                .is_some();
            if found {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(found, "hook {hook} never got a cursor");
    }
}

fn pause_is(server: &Server, n: usize, want: Duration) {
    let gap = server.gap(n);
    assert!(
        gap >= want && gap < want + Duration::from_secs(2),
        "gap {n} was {gap:?}, want {want:?}"
    );
}

#[test]
fn posts_a_signed_batch_and_acks() {
    let cluster = started(1);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 11)));
        hooks_ready(node, 1, &[hook]).await;
        let before_cursor = acked(node, 1, hook).await;
        let before = node.sched().clock().now() / 1000;
        expire_one(node, 1, 1).await;
        got(&server, 1).await;
        let after = node.sched().clock().now() / 1000;
        let (line, id, stamp, signature, body, length, host, rtype, agent, close) = {
            let got = server.got.borrow();
            let first = &got[0];
            (
                first.line.clone(),
                first.header("webhook-id").to_owned(),
                first.header("webhook-timestamp").to_owned(),
                first.header("webhook-signature").to_owned(),
                first.body.clone(),
                first.header("content-length").to_owned(),
                first.header("host").to_owned(),
                first.header("content-type").to_owned(),
                first.header("user-agent").to_owned(),
                first.header("connection").to_owned(),
            )
        };
        assert_eq!(line, "POST /in HTTP/1.1");
        assert_eq!(host, "hooks.example.org");
        assert_eq!(rtype, "application/json");
        assert_eq!(agent, "webhooks");
        assert_eq!(close, "close");
        assert_eq!(length.parse::<usize>(), Ok(body.len()));
        assert!(id.starts_with("wh_") && id.len() == 35, "{id}");
        let seconds = stamp.parse::<u64>().expect("timestamp");
        assert!(before <= seconds && seconds <= after, "{stamp}");
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(text.starts_with("{\"events\":[{"), "{text}");
        assert!(text.contains("\"type\":\"expired\""), "{text}");
        assert!(text.contains("\"address\":\"x1@example.org\""), "{text}");
        assert!(!text.contains("\"lost\""), "{text}");
        let secret = node.hook_secret(1, hook, 1).await.expect("secret");
        assert_eq!(
            signature,
            format!("v1,{}", signed(&id, &stamp, &body, &secret))
        );
        acked_through_events(node, 1, hook, &before_cursor).await;
        drop(task);
    });
    cluster.stop();
}

#[test]
fn the_host_header_carries_a_non_default_port() {
    let cluster = started(2);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 5])]),
        );
        let server = serve(IpAddr::from([1, 1, 1, 5]), 8443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://hooks.example.org:8443/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 12)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        got(&server, 1).await;
        let got = server.got.borrow();
        assert_eq!(got[0].line, "POST /in HTTP/1.1");
        assert_eq!(got[0].header("host"), "hooks.example.org:8443");
        drop(got);
        drop(task);
    });
    cluster.stop();
}

fn entry(got: &Got, secret: &Secret<32>) -> String {
    format!(
        "v1,{}",
        signed(
            got.header("webhook-id"),
            got.header("webhook-timestamp"),
            &got.body,
            secret,
        )
    )
}

#[test]
fn a_rotated_secret_signs_both_versions_for_a_day() {
    let cluster = started(3);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 13)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        got(&server, 1).await;
        let rotated = node.hook_rotate(1, hook).await.expect("rotate");
        assert_eq!(rotated.version, 2);
        let old = node.hook_secret(1, hook, 1).await.expect("old");
        let new = node.hook_secret(1, hook, 2).await.expect("new");
        expire_one(node, 1, 2).await;
        got(&server, 2).await;
        {
            let got = server.got.borrow();
            let entries: Vec<&str> = got[1].header("webhook-signature").split(' ').collect();
            assert_eq!(entries.len(), 2, "{}", got[1].header("webhook-signature"));
            assert_eq!(entries[0], entry(&got[1], &new), "current first");
            assert_eq!(entries[1], entry(&got[1], &old), "previous second");
            let first: Vec<&str> = got[0].header("webhook-signature").split(' ').collect();
            assert_eq!(first, [entry(&got[0], &old)]);
        }
        sleep(Duration::from_millis(ROTATION_MS + 60_000)).await;
        expire_one(node, 1, 3).await;
        got(&server, 3).await;
        let got = server.got.borrow();
        let entries: Vec<&str> = got[2].header("webhook-signature").split(' ').collect();
        assert_eq!(entries, [entry(&got[2], &new)], "previous retired");
        drop(got);
        drop(task);
    });
    cluster.stop();
}

#[test]
fn failures_back_off_and_a_success_resets() {
    let cluster = started(4);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|n: usize| {
            if n < 6 || n == 7 {
                Answer::status(500)
            } else {
                Answer::ok()
            }
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 14)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        got(&server, 7).await;
        let ten = Duration::from_secs(10);
        let slack = Duration::from_secs(2);
        pause_is(&server, 0, ten);
        for i in 1..6u32 {
            let gap = server.gap(i as usize);
            assert!(
                gap >= ten && gap <= ten * (1 << i) + slack,
                "gap {i} out of bounds: {gap:?}"
            );
        }
        assert!(
            (1..6).any(|i| server.gap(i) > ten + slack),
            "the backoff never grew"
        );
        expire_one(node, 1, 2).await;
        got(&server, 9).await;
        pause_is(&server, 7, ten);
        drop(task);
    });
    cluster.stop();
}

#[test]
fn retry_after_is_honored_only_as_clamped_delta_seconds() {
    let cluster = started(5);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|n: usize| match n {
            0 => Answer {
                status: 503,
                headers: vec!["Retry-After: Wed, 21 Oct 2015 07:28:00 GMT".to_owned()],
                ..Answer::ok()
            },
            1 => Answer {
                status: 429,
                headers: vec!["Retry-After: 120".to_owned()],
                ..Answer::ok()
            },
            2 => Answer {
                status: 503,
                headers: vec!["Retry-After: 2".to_owned()],
                ..Answer::ok()
            },
            3 => Answer {
                status: 429,
                headers: vec!["Retry-After: 99999".to_owned()],
                ..Answer::ok()
            },
            4 => Answer {
                status: 503,
                headers: vec![format!(
                    "Retry-After: {}",
                    http_date(rt::wall_ms() + 2 * 3600 * 1000)
                )],
                ..Answer::ok()
            },
            _ => Answer::ok(),
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 15)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        got(&server, 6).await;
        pause_is(&server, 0, Duration::from_secs(10));
        pause_is(&server, 1, Duration::from_secs(120));
        pause_is(&server, 2, Duration::from_secs(10));
        pause_is(&server, 3, Duration::from_secs(3600));
        let future = server.gap(4);
        assert!(
            future >= Duration::from_secs(10) && future <= Duration::from_secs(160 + 2),
            "a future http date was honored: {future:?}"
        );
        drop(task);
    });
    cluster.stop();
}

#[test]
fn a_gone_endpoint_waits_an_hour() {
    let cluster = started(6);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|n: usize| {
            if n == 0 {
                Answer::status(410)
            } else {
                Answer::ok()
            }
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 16)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        got(&server, 2).await;
        pause_is(&server, 0, Duration::from_secs(3600));
        drop(task);
    });
    cluster.stop();
}

#[test]
fn interim_replies_are_skipped() {
    let cluster = started(7);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|_| Answer {
            status: 200,
            early: vec!["HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n".to_owned()],
            ..Answer::ok()
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 17)));
        hooks_ready(node, 1, &[hook]).await;
        let before_cursor = acked(node, 1, hook).await;
        expire_one(node, 1, 1).await;
        got(&server, 1).await;
        acked_through_events(node, 1, hook, &before_cursor).await;
        sleep(Duration::from_secs(10 + 2)).await;
        assert_eq!(
            server.got.borrow().len(),
            1,
            "the interim reply was counted"
        );
        drop(task);
    });
    cluster.stop();
}

#[test]
fn redirects_are_not_followed() {
    let cluster = started(8);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        zone.set(
            "other.example.org",
            Type::A,
            a(&[IpAddr::from([2, 2, 2, 2])]),
        );
        let script = Rc::new(|_| Answer {
            status: 302,
            headers: vec!["Location: https://other.example.org/in".to_owned()],
            ..Answer::ok()
        });
        let first = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let other = serve(IpAddr::from([2, 2, 2, 2]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 18)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        sleep(Duration::from_secs(35)).await;
        assert!(
            first.got.borrow().len() >= 2,
            "no retry against the same host"
        );
        assert_eq!(other.open.get(), 0, "the redirect was followed");
        drop(task);
    });
    cluster.stop();
}

#[test]
fn a_slow_answer_times_out_and_retries() {
    let cluster = started(9);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|n: usize| {
            if n == 0 {
                Answer {
                    delay: Duration::from_secs(31),
                    ..Answer::ok()
                }
            } else {
                Answer::ok()
            }
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 19)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        got(&server, 2).await;
        let gap = server.gap(0);
        assert!(
            (39..=45).contains(&gap.as_secs()),
            "timeout plus floor retry: {gap:?}"
        );
        drop(task);
    });
    cluster.stop();
}

#[test]
fn a_refused_connection_retries_until_the_server_appears() {
    let cluster = started(10);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 20)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        let begin = now();
        sleep(Duration::from_secs(15)).await;
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, Rc::new(|_| Answer::ok()));
        got(&server, 1).await;
        let at = server.got.borrow()[0].at;
        assert!(
            at.saturating_duration_since(begin) >= Duration::from_secs(15),
            "the server was reached before it listened"
        );
        drop(task);
    });
    cluster.stop();
}

#[test]
fn a_tls_failure_retries_without_posting() {
    let cluster = started(11);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let plain = serve_plain(IpAddr::from([1, 1, 1, 1]));
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 21)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        sleep(Duration::from_secs(25)).await;
        assert!(plain.get() >= 2, "only {} tries", plain.get());
        drop(task);
    });
    cluster.stop();
}

#[test]
fn a_too_large_answer_head_retries() {
    let cluster = started(12);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|n: usize| {
            if n == 0 {
                Answer {
                    status: 200,
                    headers: vec![format!("X-Pad: {}", "y".repeat(9000))],
                    ..Answer::ok()
                }
            } else {
                Answer::ok()
            }
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 22)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        got(&server, 2).await;
        pause_is(&server, 0, Duration::from_secs(10));
        drop(task);
    });
    cluster.stop();
}

#[test]
fn a_not_found_status_retries() {
    let cluster = started(30);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|n: usize| {
            if n == 0 {
                Answer::status(404)
            } else {
                Answer::ok()
            }
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 31)));
        hooks_ready(node, 1, &[hook]).await;
        let before_cursor = acked(node, 1, hook).await;
        expire_one(node, 1, 1).await;
        got(&server, 2).await;
        pause_is(&server, 0, Duration::from_secs(10));
        acked_through_events(node, 1, hook, &before_cursor).await;
        drop(task);
    });
    cluster.stop();
}

async fn hangups(server: &Server, n: u32) {
    for _ in 0..1_200 {
        if server.hangups.get() >= n {
            return;
        }
        sleep(Duration::from_secs(1)).await;
    }
    panic!(
        "only {} attempts without a request, {} connections",
        server.hangups.get(),
        server.open.get()
    );
}

#[test]
fn an_unavailable_key_retries_without_acking_and_the_batch_arrives_later() {
    let down = Arc::new(AtomicBool::new(false));
    let cluster = started_with(32, &down);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 32)));
        hooks_ready(node, 1, &[hook]).await;
        let before = acked(node, 1, hook).await;
        let enabled = |on| HookChange {
            enabled: Some(on),
            ..HookChange::default()
        };
        node.hook_change(1, hook, enabled(false))
            .await
            .expect("pause");
        expire_one(node, 1, 1).await;
        down.store(true, Ordering::SeqCst);
        node.hook_change(1, hook, enabled(true))
            .await
            .expect("resume");
        hangups(&server, 1).await;
        sleep(Duration::from_secs(3)).await;
        assert_eq!(acked(node, 1, hook).await, before, "acked without bodies");
        hangups(&server, 2).await;
        sleep(Duration::from_secs(3)).await;
        assert_eq!(acked(node, 1, hook).await, before, "acked without bodies");
        assert!(server.got.borrow().is_empty(), "a request went out");
        down.store(false, Ordering::SeqCst);
        got(&server, 1).await;
        {
            let got = server.got.borrow();
            let body = String::from_utf8_lossy(&got[0].body).into_owned();
            assert!(body.contains("\"address\":\"x1@example.org\""), "{body}");
        }
        acked_through_events(node, 1, hook, &before).await;
        drop(task);
    });
    cluster.stop();
}

#[test]
fn the_floor_holds_when_allowed_and_own_addresses_are_refused() {
    let cluster = started(13);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().expect("ip");
        let own_mapped: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(
            0x64, 0xff9b, 0, 0, 0, 0, 0x0b00, 0x0209,
        ));
        let cases: [(&str, IpAddr, bool); 8] = [
            ("loopback.example.org", IpAddr::from([127, 0, 0, 1]), false),
            ("mapped.example.org", mapped, false),
            (
                "link4.example.org",
                IpAddr::from([169, 254, 169, 254]),
                false,
            ),
            ("link6.example.org", "fe80::1".parse().expect("ip"), false),
            ("lan4.example.org", IpAddr::from([10, 1, 2, 3]), true),
            ("lan6.example.org", "fd00::1".parse().expect("ip"), true),
            ("own4.example.org", IpAddr::from([11, 0, 2, 9]), false),
            ("own6.example.org", own_mapped, false),
        ];
        let zone = Zone::default();
        let mut servers = Vec::new();
        for (name, ip, _) in &cases {
            let kind = if ip.is_ipv4() { Type::A } else { Type::Aaaa };
            zone.set(name, kind, a(&[*ip]));
            servers.push(serve(*ip, 443, Rc::new(|_| Answer::ok())));
        }
        let mut ids = Vec::new();
        for (name, _, _) in &cases {
            ids.push(
                node.hook_new(1, &format!("https://{name}/in"), 0)
                    .await
                    .expect("new")
                    .id,
            );
        }
        let settings = HookSettings {
            egress: None,
            allow: vec![
                Cidr::parse("0.0.0.0/0").expect("cidr"),
                Cidr::parse("::/0").expect("cidr"),
            ],
        };
        let hooks = Hooks::with_local(
            node.clone(),
            zone,
            connector(),
            settings,
            23,
            Owns(vec![IpAddr::from([11, 0, 2, 9])]),
        );
        let task = node.start_hooks(Rc::new(hooks));
        hooks_ready(node, 1, &ids).await;
        expire_one(node, 1, 1).await;
        got(&servers[4], 1).await;
        got(&servers[5], 1).await;
        sleep(Duration::from_secs(30)).await;
        for (server, (_, _, allowed)) in servers.iter().zip(&cases) {
            assert_eq!(
                server.open.get() == 0,
                !allowed,
                "{} connections",
                server.open.get()
            );
        }
        drop(task);
    });
    cluster.stop();
}

#[test]
fn without_an_allow_list_only_global_addresses_are_called() {
    let cluster = started(14);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "global.example.org",
            Type::A,
            a(&[IpAddr::from([9, 9, 9, 9])]),
        );
        zone.set(
            "private.example.org",
            Type::A,
            a(&[IpAddr::from([10, 2, 3, 4])]),
        );
        zone.set(
            "lan192.example.org",
            Type::A,
            a(&[IpAddr::from([192, 168, 1, 2])]),
        );
        let global = serve(IpAddr::from([9, 9, 9, 9]), 443, Rc::new(|_| Answer::ok()));
        let private = serve(IpAddr::from([10, 2, 3, 4]), 443, Rc::new(|_| Answer::ok()));
        let lan192 = serve(
            IpAddr::from([192, 168, 1, 2]),
            443,
            Rc::new(|_| Answer::ok()),
        );
        let mut ids = Vec::new();
        for name in [
            "global.example.org",
            "private.example.org",
            "lan192.example.org",
        ] {
            ids.push(
                node.hook_new(1, &format!("https://{name}/in"), 0)
                    .await
                    .expect("new")
                    .id,
            );
        }
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 24)));
        hooks_ready(node, 1, &ids).await;
        expire_one(node, 1, 1).await;
        got(&global, 1).await;
        sleep(Duration::from_secs(30)).await;
        assert_eq!(private.open.get(), 0, "a private address was called");
        assert_eq!(lan192.open.get(), 0, "a 192.168 address was called");
        drop(task);
    });
    cluster.stop();
}

fn egress_case(seed: u64, egress: IpAddr, at: IpAddr, wanted: Type, skipped: Type) {
    let cluster = started(seed);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set("eg.example.org", Type::A, a(&[IpAddr::from([1, 1, 1, 1])]));
        zone.set(
            "eg.example.org",
            Type::Aaaa,
            a(&["2606:4700::1".parse().expect("ip")]),
        );
        let server = serve(at, 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://eg.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let settings = HookSettings {
            egress: Some(egress),
            allow: Vec::new(),
        };
        let task = node.start_hooks(Rc::new(sender(node, &zone, settings, seed)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        got(&server, 1).await;
        assert_eq!(server.got.borrow()[0].peer, egress, "wrong source address");
        let asked = zone.asked.borrow();
        assert!(
            asked
                .iter()
                .any(|(n, k)| n == "eg.example.org" && *k == wanted),
            "family not asked: {asked:?}"
        );
        assert!(
            !asked
                .iter()
                .any(|(n, k)| n == "eg.example.org" && *k == skipped),
            "both families asked: {asked:?}"
        );
        drop(asked);
        drop(task);
    });
    cluster.stop();
}

#[test]
fn egress_picks_the_family_and_the_source_address() {
    egress_case(
        15,
        IpAddr::from([9, 9, 9, 9]),
        IpAddr::from([1, 1, 1, 1]),
        Type::A,
        Type::Aaaa,
    );
    egress_case(
        16,
        "2001:4860::1".parse().expect("ip"),
        "2606:4700::1".parse().expect("ip"),
        Type::Aaaa,
        Type::A,
    );
}

fn slow_hooks(node: &Node<Idle>, zone: Zone, delay: Duration) -> (Slow, Hooks<Idle, Slow, Owns>) {
    let slow = Slow {
        zone,
        delay,
        started: Rc::new(Cell::new(0)),
    };
    let hooks = Hooks::with_local(
        node.clone(),
        slow.clone(),
        connector(),
        HookSettings::default(),
        25,
        Owns::default(),
    );
    (slow, hooks)
}

async fn lookup_started(slow: &Slow) {
    for _ in 0..30_000 {
        if slow.started.get() > 0 {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("no lookup started");
}

#[test]
fn pausing_during_the_lookup_stops_the_call() {
    let cluster = started(17);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "slowd.example.org",
            Type::A,
            a(&[IpAddr::from([1, 2, 3, 4])]),
        );
        let server = serve(IpAddr::from([1, 2, 3, 4]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://slowd.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let (slow, hooks) = slow_hooks(node, zone, Duration::from_secs(5));
        let task = node.start_hooks(Rc::new(hooks));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        lookup_started(&slow).await;
        let paused = node
            .hook_change(
                1,
                hook,
                HookChange {
                    enabled: Some(false),
                    ..HookChange::default()
                },
            )
            .await
            .expect("pause");
        assert_eq!(paused.state, control::HookState::Paused);
        sleep(Duration::from_secs(20)).await;
        assert_eq!(server.open.get(), 0, "the call went out while paused");
        node.hook_change(
            1,
            hook,
            HookChange {
                enabled: Some(true),
                ..HookChange::default()
            },
        )
        .await
        .expect("resume");
        got(&server, 1).await;
        drop(task);
    });
    cluster.stop();
}

#[test]
fn pausing_during_the_handshake_stops_the_call() {
    let cluster = started(32);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "slowd.example.org",
            Type::A,
            a(&[IpAddr::from([1, 2, 3, 4])]),
        );
        let server = serve_tls_late(
            IpAddr::from([1, 2, 3, 4]),
            443,
            Duration::from_secs(5),
            Rc::new(|_| Answer::ok()),
        );
        let hook = node
            .hook_new(1, "https://slowd.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 33)));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        for _ in 0..30_000 {
            if server.open.get() > 0 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.open.get(), 1, "no connection reached the server");
        node.hook_change(
            1,
            hook,
            HookChange {
                enabled: Some(false),
                ..HookChange::default()
            },
        )
        .await
        .expect("pause");
        sleep(Duration::from_secs(20)).await;
        assert_eq!(server.got.borrow().len(), 0, "the request went out paused");
        node.hook_change(
            1,
            hook,
            HookChange {
                enabled: Some(true),
                ..HookChange::default()
            },
        )
        .await
        .expect("resume");
        got(&server, 1).await;
        drop(task);
    });
    cluster.stop();
}

#[test]
fn removing_during_the_lookup_stops_the_call() {
    let cluster = started(18);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "slowd.example.org",
            Type::A,
            a(&[IpAddr::from([1, 2, 3, 4])]),
        );
        let server = serve(IpAddr::from([1, 2, 3, 4]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://slowd.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let (slow, hooks) = slow_hooks(node, zone, Duration::from_secs(5));
        let task = node.start_hooks(Rc::new(hooks));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        lookup_started(&slow).await;
        node.hook_remove(1, hook).await.expect("remove");
        sleep(Duration::from_secs(30)).await;
        assert_eq!(server.open.get(), 0, "the call went out after removal");
        drop(task);
    });
    cluster.stop();
}

#[test]
fn deleting_the_tenant_during_the_lookup_stops_the_call() {
    let cluster = started(19);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        configure(&nodes, vec![tenant(3, 1, State::Active)]).await;
        wait_for(&nodes, 3, 1, State::Active).await;
        let zone = Zone::default();
        zone.set(
            "slowd.example.org",
            Type::A,
            a(&[IpAddr::from([1, 2, 3, 4])]),
        );
        let server = serve(IpAddr::from([1, 2, 3, 4]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(3, "https://slowd.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let (slow, hooks) = slow_hooks(node, zone, Duration::from_secs(5));
        let task = node.start_hooks(Rc::new(hooks));
        hooks_ready(node, 3, &[hook]).await;
        expire_one(node, 3, 1).await;
        lookup_started(&slow).await;
        node.delete_tenant(3).await.expect("delete");
        wait_for(&nodes, 3, 1, State::Deleted).await;
        sleep(Duration::from_secs(20)).await;
        assert_eq!(server.open.get(), 0, "the call went out after deletion");
        drop(task);
    });
    cluster.stop();
}

#[test]
fn changing_the_url_during_the_lookup_redirects_the_retry() {
    let cluster = started(20);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "slowd.example.org",
            Type::A,
            a(&[IpAddr::from([1, 2, 3, 4])]),
        );
        zone.set(
            "fastd.example.org",
            Type::A,
            a(&[IpAddr::from([5, 6, 7, 8])]),
        );
        let old = serve(IpAddr::from([1, 2, 3, 4]), 443, Rc::new(|_| Answer::ok()));
        let new = serve(IpAddr::from([5, 6, 7, 8]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://slowd.example.org/old", 0)
            .await
            .expect("new")
            .id;
        let (slow, hooks) = slow_hooks(node, zone, Duration::from_secs(5));
        let task = node.start_hooks(Rc::new(hooks));
        hooks_ready(node, 1, &[hook]).await;
        expire_one(node, 1, 1).await;
        lookup_started(&slow).await;
        node.hook_change(
            1,
            hook,
            HookChange {
                url: Some("https://fastd.example.org/new".into()),
                ..HookChange::default()
            },
        )
        .await
        .expect("change");
        got(&new, 1).await;
        assert_eq!(old.open.get(), 0, "the old address was called");
        assert_eq!(new.got.borrow()[0].line, "POST /new HTTP/1.1");
        drop(task);
    });
    cluster.stop();
}

#[test]
fn tenant_calls_are_capped_at_four() {
    let cluster = started(21);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|_| Answer {
            delay: Duration::from_secs(10),
            ..Answer::ok()
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let mut hooks = Vec::new();
        for _ in 0..5 {
            hooks.push(
                node.hook_new(1, "https://hooks.example.org/in", 0)
                    .await
                    .expect("new")
                    .id,
            );
        }
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 26)));
        hooks_ready(node, 1, &hooks).await;
        expire_one(node, 1, 1).await;
        got(&server, 5).await;
        assert_eq!(server.most.get(), 4, "the tenant cap did not hold");
        drop(task);
    });
    cluster.stop();
}

#[test]
fn core_calls_are_capped_at_sixty_four() {
    let cluster = started(22);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        for id in 3..=18 {
            configure(&nodes, vec![tenant(id, 1, State::Active)]).await;
            wait_for(&nodes, id, 1, State::Active).await;
        }
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let script = Rc::new(|_| Answer {
            delay: Duration::from_secs(20),
            ..Answer::ok()
        });
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, script);
        let mut by_tenant: Vec<(u32, Vec<u32>)> = Vec::new();
        for id in 1..=18 {
            let mut ids = Vec::new();
            for _ in 0..4 {
                ids.push(
                    node.hook_new(id, "https://hooks.example.org/in", 0)
                        .await
                        .expect("new")
                        .id,
                );
            }
            by_tenant.push((id, ids));
        }
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 27)));
        for (tenant, ids) in &by_tenant {
            hooks_ready(node, *tenant, ids).await;
        }
        for id in 1..=18u32 {
            expire_one(node, id, u8::try_from(id).expect("small")).await;
        }
        got(&server, 72).await;
        assert_eq!(server.most.get(), 64, "the core cap did not hold");
        drop(task);
    });
    cluster.stop();
}

#[test]
fn tenants_sign_with_their_own_secrets_only() {
    let cluster = started(23);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set("sig.example.org", Type::A, a(&[IpAddr::from([1, 1, 1, 1])]));
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, Rc::new(|_| Answer::ok()));
        let one = node
            .hook_new(1, "https://sig.example.org/t1", 0)
            .await
            .expect("new")
            .id;
        let two = node
            .hook_new(2, "https://sig.example.org/t2", 0)
            .await
            .expect("new")
            .id;
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 28)));
        hooks_ready(node, 1, &[one]).await;
        hooks_ready(node, 2, &[two]).await;
        expire_one(node, 1, 1).await;
        expire_one(node, 2, 2).await;
        got(&server, 2).await;
        let first = node.hook_secret(1, one, 1).await.expect("secret");
        let second = node.hook_secret(2, two, 1).await.expect("secret");
        let mut seen = (false, false);
        for got in server.got.borrow().iter() {
            let body = String::from_utf8_lossy(&got.body).into_owned();
            if got.line == "POST /t1 HTTP/1.1" {
                assert!(
                    got.header("webhook-signature")
                        .contains(&entry(got, &first)[..])
                );
                assert_ne!(got.header("webhook-signature"), entry(got, &second));
                assert!(body.contains("x1@example.org") && !body.contains("x2@example.org"));
                seen.0 = true;
            } else if got.line == "POST /t2 HTTP/1.1" {
                assert_eq!(got.header("webhook-signature"), entry(got, &second));
                assert_ne!(got.header("webhook-signature"), entry(got, &first));
                assert!(body.contains("x2@example.org") && !body.contains("x1@example.org"));
                seen.1 = true;
            } else {
                panic!("unexpected request {}", got.line);
            }
        }
        assert_eq!(seen, (true, true));
        drop(task);
    });
    cluster.stop();
}

#[test]
fn lost_events_are_reported_once_in_the_body() {
    let cluster = started(24);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        let node = &nodes[0];
        let zone = Zone::default();
        zone.set(
            "hooks.example.org",
            Type::A,
            a(&[IpAddr::from([1, 1, 1, 1])]),
        );
        let server = serve(IpAddr::from([1, 1, 1, 1]), 443, Rc::new(|_| Answer::ok()));
        let hook = node
            .hook_new(1, "https://hooks.example.org/in", 0)
            .await
            .expect("new")
            .id;
        let changes = node.spool().changes();
        let shard = node.spool().shards()[0];
        let cursor = Cursor {
            generation: 1,
            acked: changes.watch().head(),
            lost: 5,
            counted: 0,
        };
        write_cursor(changes, shard, 1, hook, &cursor)
            .await
            .expect("cursor");
        let task = node.start_hooks(Rc::new(sender(node, &zone, HookSettings::default(), 29)));
        hooks_ready(node, 1, &[hook]).await;
        got(&server, 1).await;
        {
            let got = server.got.borrow();
            assert_eq!(got[0].body, b"{\"events\":[],\"lost\":5}");
        }
        expire_one(node, 1, 1).await;
        got(&server, 2).await;
        let got = server.got.borrow();
        let body = String::from_utf8_lossy(&got[1].body).into_owned();
        assert!(body.contains("\"type\":\"expired\""), "{body}");
        assert!(!body.contains("\"lost\""), "{body}");
        drop(got);
        drop(task);
    });
    cluster.stop();
}
