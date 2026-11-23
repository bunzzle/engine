use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use control::{Hook, HookState};
use crypto::{Ids, Secret, hmac_sha256};
use dkim::base64;
use dns::Name;
use rt::{Instant, TcpStream, timeout};
use sched::{Call, Deliver, Node, Outcome, Sending, Transport, event_json};
use tls::{Connector, Verify};

use crate::address::{Bind, Cidr, Local, Own};
use crate::mx::{self, Addresses, Dns};
use crate::upload::{Target, target};

const CORE_CALLS: usize = 64;
const TENANT_CALLS: usize = 4;
const CALL: Duration = Duration::from_secs(30);
const CONNECT: Duration = Duration::from_secs(10);
const CLOSE: Duration = Duration::from_secs(5);
const ADDRESSES: usize = 4;
const HEAD: usize = 8 * 1024;
const READ: usize = 4096;
const PAUSE_MIN: Duration = Duration::from_secs(10);
const PAUSE_MAX: Duration = Duration::from_hours(1);
const DOUBLINGS: u32 = 9;
const IDLE: Duration = Duration::from_hours(2);
const PRUNE: Duration = Duration::from_secs(60);
const KEEP: Duration = Duration::from_secs(15);
const KEEP_AGE: Duration = Duration::from_mins(10);
const KEEP_MAX: usize = 256;
const DRAIN: usize = 16 * 1024;
const DRAIN_TIME: Duration = Duration::from_secs(5);
const LINE: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookSettings {
    pub egress: Option<IpAddr>,
    pub allow: Vec<Cidr>,
    pub nat64: Vec<Cidr>,
}

pub struct Hooks<T, D, L = Bind> {
    inner: Rc<Inner<T, D, L>>,
}

struct Inner<T, D, L> {
    node: Node<T>,
    dns: D,
    tls: Connector,
    settings: HookSettings,
    core: Rc<Gate>,
    tenants: RefCell<BTreeMap<u32, Rc<Gate>>>,
    failures: RefCell<BTreeMap<Key, (u32, Instant)>>,
    idle: RefCell<BTreeMap<Key, Kept>>,
    pruned: Cell<Instant>,
    own: Own<L>,
    random: Cell<u64>,
}

impl<T: Transport + 'static, D: Dns + 'static> Hooks<T, D> {
    pub fn new(node: Node<T>, dns: D, tls: Connector, settings: HookSettings, seed: u64) -> Self {
        Self::with_local(node, dns, tls, settings, seed, Bind)
    }
}

impl<T: Transport + 'static, D: Dns + 'static, L: Local + 'static> Hooks<T, D, L> {
    pub fn with_local(
        node: Node<T>,
        dns: D,
        tls: Connector,
        settings: HookSettings,
        seed: u64,
        local: L,
    ) -> Self {
        Self {
            inner: Rc::new(Inner {
                node,
                dns,
                tls,
                settings,
                core: Gate::new(CORE_CALLS),
                tenants: RefCell::default(),
                failures: RefCell::default(),
                idle: RefCell::default(),
                pruned: Cell::new(rt::now()),
                own: Own::new(local),
                random: Cell::new(seed | 1),
            }),
        }
    }

    pub fn own_stats(&self) -> crate::address::OwnStats {
        self.inner.own.stats()
    }
}

impl<T: Transport + 'static, D: Dns + 'static, L: Local + 'static> Deliver for Hooks<T, D, L> {
    fn deliver(&self, call: Rc<Call>) -> Sending {
        let inner = Rc::clone(&self.inner);
        Box::pin(async move { inner.call(&call).await })
    }
}

type Key = (u32, u32, u32);

struct Kept {
    stream: tls::Stream,
    url: Box<str>,
    born: Instant,
    since: Instant,
}

struct Open {
    stream: tls::Stream,
    url: Box<str>,
    born: Instant,
    rest: Option<(Frame, Vec<u8>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    Empty,
    Length(usize),
    Chunked,
}

#[derive(Debug, PartialEq, Eq)]
enum End {
    More,
    At(usize),
    Bad,
}

enum Read {
    Got(Sent, Option<(Frame, Vec<u8>)>),
    Nothing,
}

#[derive(Clone, Copy)]
enum Sent {
    Status(u16, Option<Duration>),
    Refused,
    Internal,
    Failed(&'static str),
}

fn failure(call: &Call, sent: &Sent) -> Option<String> {
    let (tenant, hook) = (call.tenant, call.hook);
    match sent {
        Sent::Status(status, _) if !(200..=299).contains(status) => Some(format!(
            "webhook call failed: tenant={tenant} hook={hook} status={status}"
        )),
        Sent::Internal => Some(format!(
            "webhook call failed: tenant={tenant} hook={hook} reason=internal"
        )),
        Sent::Failed(reason) => Some(format!(
            "webhook call failed: tenant={tenant} hook={hook} reason={reason}"
        )),
        _ => None,
    }
}

impl<T: Transport + 'static, D: Dns + 'static, L: Local + 'static> Inner<T, D, L> {
    async fn call(&self, call: &Call) -> Outcome {
        let gate = Rc::clone(
            self.tenants
                .borrow_mut()
                .entry(call.tenant)
                .or_insert_with(|| Gate::new(TENANT_CALLS)),
        );
        let sent = {
            let _tenant = Gate::enter(&gate).await;
            let _core = Gate::enter(&self.core).await;
            let mut open = None;
            let started = rt::now();
            let sent = timeout(CALL, self.attempt(call, &mut open))
                .await
                .unwrap_or(Sent::Failed("timeout"));
            if let Some(open) = open {
                let left = CALL.saturating_sub(rt::now().saturating_duration_since(started));
                self.finish(call, open, left.min(DRAIN_TIME)).await;
            }
            sent
        };
        if gate.idle() && Rc::strong_count(&gate) == 2 {
            self.tenants.borrow_mut().remove(&call.tenant);
        }
        drop(gate);
        self.outcome(call, sent)
    }

    async fn finish(&self, call: &Call, mut open: Open, budget: Duration) {
        let kept = match open.rest.take() {
            Some((frame, rest)) => matches!(
                timeout(budget, drain(&mut open.stream, frame, rest)).await,
                Ok(true)
            ),
            None => false,
        };
        let now = rt::now();
        if !kept || now.saturating_duration_since(open.born) >= KEEP_AGE {
            let _ = timeout(CLOSE, open.stream.shutdown()).await;
            return;
        }
        let mut idle = self.idle.borrow_mut();
        idle.insert(
            (call.tenant, call.generation, call.hook),
            Kept {
                stream: open.stream,
                url: open.url,
                born: open.born,
                since: now,
            },
        );
        if idle.len() > KEEP_MAX
            && let Some(oldest) = idle
                .iter()
                .min_by_key(|(_, k)| k.since)
                .map(|(key, _)| *key)
        {
            idle.remove(&oldest);
        }
    }

    fn take(&self, key: &Key, url: &str) -> Option<Kept> {
        let kept = self.idle.borrow_mut().remove(key)?;
        let now = rt::now();
        (kept.url.as_ref() == url
            && now.saturating_duration_since(kept.since) < KEEP
            && now.saturating_duration_since(kept.born) < KEEP_AGE)
            .then_some(kept)
    }

    fn outcome(&self, call: &Call, sent: Sent) -> Outcome {
        let key = (call.tenant, call.generation, call.hook);
        self.prune();
        if matches!(sent, Sent::Refused | Sent::Status(410, _)) {
            self.idle.borrow_mut().remove(&key);
        }
        if let Some(line) = failure(call, &sent) {
            eprintln!("{line}");
        }
        match sent {
            Sent::Status(status @ 200..=299, _) => {
                self.failures.borrow_mut().remove(&key);
                Outcome::Acked { status }
            }
            Sent::Refused => {
                self.failures.borrow_mut().remove(&key);
                Outcome::Refused(PAUSE_MIN)
            }
            Sent::Status(410, _) => Outcome::Gone,
            Sent::Status(status @ (429 | 503), Some(after)) => {
                self.failed(key);
                Outcome::Retry {
                    after: after.clamp(PAUSE_MIN, PAUSE_MAX),
                    status: Some(status),
                }
            }
            Sent::Status(status, _) => {
                let n = self.failed(key);
                Outcome::Retry {
                    after: self.pause(n),
                    status: Some(status),
                }
            }
            Sent::Internal => {
                let n = self.failed(key);
                Outcome::Refused(self.pause(n))
            }
            Sent::Failed(_) => {
                let n = self.failed(key);
                Outcome::Retry {
                    after: self.pause(n),
                    status: None,
                }
            }
        }
    }

    fn failed(&self, key: Key) -> u32 {
        let mut failures = self.failures.borrow_mut();
        let entry = failures.entry(key).or_insert((0, rt::now()));
        let n = entry.0;
        *entry = (n.saturating_add(1), rt::now());
        n
    }

    fn pause(&self, n: u32) -> Duration {
        let cap = (PAUSE_MIN * (1 << n.min(DOUBLINGS))).min(PAUSE_MAX);
        let span = u64::try_from(cap.saturating_sub(PAUSE_MIN).as_millis()).unwrap_or(u64::MAX);
        PAUSE_MIN + Duration::from_millis(self.next() % span.saturating_add(1))
    }

    fn next(&self) -> u64 {
        let mut x = self.random.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.random.set(x);
        x
    }

    fn prune(&self) {
        let now = rt::now();
        if now.saturating_duration_since(self.pruned.get()) < PRUNE {
            return;
        }
        self.pruned.set(now);
        self.failures
            .borrow_mut()
            .retain(|_, (_, at)| now.saturating_duration_since(*at) < IDLE);
        self.idle
            .borrow_mut()
            .retain(|_, kept| now.saturating_duration_since(kept.since) < KEEP);
    }

    fn snapshot(&self, call: &Call) -> Option<(Hook, Option<u8>)> {
        let (hook, previous) = self.node.hook_versions(call.tenant, call.hook).ok()?;
        (hook.generation == call.generation && hook.state == HookState::Active)
            .then_some((hook, previous))
    }

    fn same(&self, call: &Call, first: &(Hook, Option<u8>)) -> bool {
        self.snapshot(call).is_some_and(|now| {
            let (hook, previous) = &now;
            let (was, before) = first;
            (&hook.url, hook.version, previous) == (&was.url, was.version, before)
        })
    }

    async fn attempt(&self, call: &Call, open: &mut Option<Open>) -> Sent {
        let Some(first) = self.snapshot(call) else {
            return Sent::Refused;
        };
        if !self.tls.webpki() {
            return Sent::Failed("no-roots");
        }
        let Some(target) = target(&first.0.url) else {
            return Sent::Failed("url");
        };
        let Some(secrets) = self.secrets(call, &first).await else {
            return Sent::Internal;
        };
        let Some(ids) = self.node.ids() else {
            return Sent::Internal;
        };
        let Ok(ids) = Ids::new(&ids) else {
            return Sent::Internal;
        };
        let key = (call.tenant, call.generation, call.hook);
        let mut request = None;
        if let Some(mut kept) = self.take(&key, &first.0.url) {
            let Some(bytes) = self.request(call, &target, &ids, &secrets).await else {
                return Sent::Internal;
            };
            if !self.same(call, &first) {
                return Sent::Refused;
            }
            if kept.stream.write_all(&bytes).await.is_ok()
                && let Read::Got(sent, rest) = read_status(&mut kept.stream).await
            {
                *open = Some(Open {
                    stream: kept.stream,
                    url: kept.url,
                    born: kept.born,
                    rest,
                });
                return sent;
            }
            request = Some(bytes);
        }
        let Ok(name) = Name::parse(&target.host) else {
            return Sent::Failed("name");
        };
        let (ips, mismatch) = self.addresses(&name).await;
        if ips.is_empty() && mismatch {
            return Sent::Failed("egress-family");
        }
        let mut failed = "no-address";
        for ip in ips {
            if !self.same(call, &first) {
                return Sent::Refused;
            }
            let Ok(Ok(io)) = timeout(CONNECT, self.connect(ip, &target)).await else {
                failed = "connect";
                continue;
            };
            let Ok(Ok(mut stream)) =
                timeout(CONNECT, self.tls.connect(io, &target.host, Verify::WebPki)).await
            else {
                failed = "tls";
                continue;
            };
            let bytes = match request.take() {
                Some(bytes) => bytes,
                None => match self.request(call, &target, &ids, &secrets).await {
                    Some(bytes) => bytes,
                    None => return Sent::Internal,
                },
            };
            if !self.same(call, &first) {
                return Sent::Refused;
            }
            if stream.write_all(&bytes).await.is_err() {
                return Sent::Failed("write");
            }
            drop(bytes);
            let (sent, rest) = match read_status(&mut stream).await {
                Read::Got(sent, rest) => (sent, rest),
                Read::Nothing => (Sent::Failed("answer"), None),
            };
            *open = Some(Open {
                stream,
                url: first.0.url.clone(),
                born: rt::now(),
                rest,
            });
            return sent;
        }
        Sent::Failed(failed)
    }

    async fn secrets(
        &self,
        call: &Call,
        (hook, previous): &(Hook, Option<u8>),
    ) -> Option<Vec<Arc<Secret<32>>>> {
        let mut out = Vec::with_capacity(2);
        for version in std::iter::once(hook.version).chain(*previous) {
            let secret = self.node.hook_secret(call.tenant, call.hook, version).await;
            out.push(secret.ok()?);
        }
        Some(out)
    }

    async fn addresses(&self, name: &Name) -> (Vec<IpAddr>, bool) {
        let families: &[bool] = match self.settings.egress {
            Some(egress) => &[egress.is_ipv6()],
            None => &[false, true],
        };
        let mut out = Vec::new();
        for &v6 in families {
            let keep =
                |ip: &IpAddr| crate::address::keep(ip, &self.settings.allow, &self.settings.nat64);
            if let Addresses::Found { ips, .. } = mx::filtered(&self.dns, name, v6, keep).await {
                out.extend(ips);
            }
        }
        let mut kept = Vec::with_capacity(ADDRESSES);
        for ip in out {
            if kept.len() == ADDRESSES {
                break;
            }
            if !self.own.own(ip, &self.settings.nat64).await {
                kept.push(ip);
            }
        }
        let mut mismatch = false;
        if kept.is_empty()
            && let Some(egress) = self.settings.egress
        {
            let keep =
                |ip: &IpAddr| crate::address::keep(ip, &self.settings.allow, &self.settings.nat64);
            if let Addresses::Found { ips, .. } =
                mx::filtered(&self.dns, name, !egress.is_ipv6(), keep).await
            {
                mismatch = !ips.is_empty();
            }
        }
        (kept, mismatch)
    }

    async fn connect(&self, ip: IpAddr, target: &Target) -> std::io::Result<TcpStream> {
        let to = std::net::SocketAddr::new(ip, target.port);
        match self.settings.egress {
            Some(egress) => TcpStream::connect_from(egress, to).await,
            None => TcpStream::connect(to).await,
        }
    }

    async fn request(
        &self,
        call: &Call,
        target: &Target,
        ids: &Ids,
        secrets: &[Arc<Secret<32>>],
    ) -> Option<Vec<u8>> {
        let events = self.node.open_call(call).await?;
        let mut body = String::from("{\"events\":[");
        for (n, read) in events.iter().enumerate() {
            if n > 0 {
                body.push(',');
            }
            event_json(read, ids, &mut body);
        }
        drop(events);
        body.push(']');
        if call.lost > 0 {
            let _ = write!(body, ",\"lost\":{}", call.lost);
        }
        body.push('}');
        let id = delivery_id(&call.id);
        let stamp = (self.node.sched().clock().now() / 1000).to_string();
        let signature = signature(&id, &stamp, body.as_bytes(), secrets);
        let host = if target.port == 443 {
            target.host.clone()
        } else {
            format!("{}:{}", target.host, target.port)
        };
        let mut out = format!(
            "POST {} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nUser-Agent: webhooks\r\n\
             webhook-id: {id}\r\nwebhook-timestamp: {stamp}\r\nwebhook-signature: {signature}\r\n\r\n",
            target.path,
            body.len(),
        )
        .into_bytes();
        out.extend_from_slice(body.as_bytes());
        Some(out)
    }
}

pub fn delivery_id(id: &[u8; 16]) -> String {
    let mut out = String::from("wh_");
    for byte in id {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn signature(id: &str, stamp: &str, body: &[u8], secrets: &[Arc<Secret<32>>]) -> String {
    let mut out = String::new();
    for secret in secrets {
        if !out.is_empty() {
            out.push(' ');
        }
        let mac = hmac_sha256(
            secret.expose(),
            &[id.as_bytes(), b".", stamp.as_bytes(), b".", body],
        );
        out.push_str("v1,");
        out.push_str(&base64::encode(&mac));
    }
    out
}

async fn read_status(stream: &mut tls::Stream) -> Read {
    let mut bytes = Vec::new();
    let mut buf = [0; READ];
    let mut any = false;
    loop {
        let end = loop {
            if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            if bytes.len() >= HEAD {
                return Read::Got(Sent::Failed("answer"), None);
            }
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) if !any => return Read::Nothing,
                Ok(0) | Err(_) => return Read::Got(Sent::Failed("answer"), None),
                Ok(n) => {
                    any = true;
                    bytes.extend_from_slice(&buf[..n]);
                }
            }
        };
        if end > HEAD {
            return Read::Got(Sent::Failed("answer"), None);
        }
        let Some(code) = crate::https::status(&bytes[..end]) else {
            return Read::Got(Sent::Failed("answer"), None);
        };
        if (100..200).contains(&code) {
            bytes.drain(..end);
            continue;
        }
        let sent = Sent::Status(code, retry_after(&bytes[..end]));
        let rest = frame(&bytes[..end], code).map(|f| (f, bytes[end..].to_vec()));
        return Read::Got(sent, rest);
    }
}

fn frame(head: &[u8], status: u16) -> Option<Frame> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    if !lines.next()?.starts_with("HTTP/1.1 ") {
        return None;
    }
    let (mut length, mut chunked) = (None, false);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("connection") {
            let close = value
                .split(',')
                .any(|t| t.trim_matches([' ', '\t']).eq_ignore_ascii_case("close"));
            if close {
                return None;
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return None;
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n = value.parse().ok()?;
            if length.is_some_and(|l| l != n) {
                return None;
            }
            length = Some(n);
        }
    }
    if status == 204 || status == 304 {
        return Some(Frame::Empty);
    }
    match (chunked, length) {
        (true, None) => Some(Frame::Chunked),
        (false, Some(n)) if n <= DRAIN => Some(Frame::Length(n)),
        _ => None,
    }
}

fn framed(bytes: &[u8], frame: Frame) -> End {
    match frame {
        Frame::Empty => End::At(0),
        Frame::Length(n) if bytes.len() >= n => End::At(n),
        Frame::Length(_) => End::More,
        Frame::Chunked => chunked(bytes),
    }
}

fn line(bytes: &[u8]) -> Result<Option<usize>, ()> {
    match bytes.windows(2).position(|w| w == b"\r\n") {
        Some(at) if at <= LINE => Ok(Some(at)),
        Some(_) => Err(()),
        None if bytes.len() > LINE => Err(()),
        None => Ok(None),
    }
}

fn chunked(bytes: &[u8]) -> End {
    let mut at = 0;
    let mut body = 0;
    loop {
        let size = match line(&bytes[at..]) {
            Ok(Some(n)) => n,
            Ok(None) => return End::More,
            Err(()) => return End::Bad,
        };
        let digits = bytes[at..at + size]
            .split(|&b| b == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii();
        if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_hexdigit) {
            return End::Bad;
        }
        let Some(n) = std::str::from_utf8(digits)
            .ok()
            .and_then(|d| usize::from_str_radix(d, 16).ok())
        else {
            return End::Bad;
        };
        at += size + 2;
        if n == 0 {
            loop {
                match line(&bytes[at..]) {
                    Ok(Some(0)) => return End::At(at + 2),
                    Ok(Some(n)) => at += n + 2,
                    Ok(None) => return End::More,
                    Err(()) => return End::Bad,
                }
            }
        }
        body += n;
        if body > DRAIN {
            return End::Bad;
        }
        if bytes.len() < at + n + 2 {
            return End::More;
        }
        if &bytes[at + n..at + n + 2] != b"\r\n" {
            return End::Bad;
        }
        at += n + 2;
    }
}

async fn drain(stream: &mut tls::Stream, frame: Frame, mut bytes: Vec<u8>) -> bool {
    let mut buf = [0; READ];
    loop {
        match framed(&bytes, frame) {
            End::At(end) => return end == bytes.len(),
            End::Bad => return false,
            End::More if bytes.len() > 2 * DRAIN => return false,
            End::More => {}
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
        }
    }
}

fn retry_after(head: &[u8]) -> Option<Duration> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("retry-after") {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)))
    })
}

struct Gate {
    cap: usize,
    used: Cell<usize>,
    next: Cell<u64>,
    queue: RefCell<VecDeque<u64>>,
    wakers: RefCell<BTreeMap<u64, Waker>>,
}

impl Gate {
    fn new(cap: usize) -> Rc<Self> {
        Rc::new(Self {
            cap,
            used: Cell::new(0),
            next: Cell::new(0),
            queue: RefCell::default(),
            wakers: RefCell::default(),
        })
    }

    fn idle(&self) -> bool {
        self.used.get() == 0 && self.queue.borrow().is_empty()
    }

    async fn enter(gate: &Rc<Self>) -> Permit {
        let ticket = gate.next.get();
        gate.next.set(ticket + 1);
        gate.queue.borrow_mut().push_back(ticket);
        Waiting {
            gate: Rc::clone(gate),
            ticket,
            done: false,
        }
        .await;
        Permit(Rc::clone(gate))
    }

    fn wake_front(&self) {
        let front = self.queue.borrow().front().copied();
        if let Some(ticket) = front
            && let Some(waker) = self.wakers.borrow_mut().remove(&ticket)
        {
            waker.wake();
        }
    }
}

struct Waiting {
    gate: Rc<Gate>,
    ticket: u64,
    done: bool,
}

impl Future for Waiting {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let gate = Rc::clone(&self.gate);
        let front = gate.queue.borrow().front() == Some(&self.ticket);
        if front && gate.used.get() < gate.cap {
            gate.queue.borrow_mut().pop_front();
            gate.used.set(gate.used.get() + 1);
            self.done = true;
            gate.wake_front();
            return Poll::Ready(());
        }
        gate.wakers
            .borrow_mut()
            .insert(self.ticket, cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let ticket = self.ticket;
        self.gate.queue.borrow_mut().retain(|&t| t != ticket);
        self.gate.wakers.borrow_mut().remove(&ticket);
        self.gate.wake_front();
    }
}

struct Permit(Rc<Gate>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.used.set(self.0.used.get() - 1);
        self.0.wake_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_lines_carry_tenant_hook_and_a_status_or_reason() {
        let call = Call {
            tenant: 7,
            generation: 1,
            hook: 9,
            id: [0; 16],
            lost: 0,
            events: Vec::new(),
        };
        assert_eq!(failure(&call, &Sent::Status(200, None)), None);
        assert_eq!(failure(&call, &Sent::Refused), None);
        assert_eq!(
            failure(&call, &Sent::Status(500, None)).as_deref(),
            Some("webhook call failed: tenant=7 hook=9 status=500")
        );
        assert_eq!(
            failure(&call, &Sent::Status(410, None)).as_deref(),
            Some("webhook call failed: tenant=7 hook=9 status=410")
        );
        assert_eq!(
            failure(&call, &Sent::Failed("egress-family")).as_deref(),
            Some("webhook call failed: tenant=7 hook=9 reason=egress-family")
        );
        assert_eq!(
            failure(&call, &Sent::Internal).as_deref(),
            Some("webhook call failed: tenant=7 hook=9 reason=internal")
        );
    }

    #[test]
    fn only_framed_keep_alive_answers_are_kept() {
        let ok = |extra: &str| format!("HTTP/1.1 200 OK\r\n{extra}\r\n").into_bytes();
        assert_eq!(
            frame(&ok("Content-Length: 2\r\n"), 200),
            Some(Frame::Length(2))
        );
        assert_eq!(
            frame(&ok("transfer-encoding: Chunked\r\n"), 202),
            Some(Frame::Chunked)
        );
        assert_eq!(frame(&ok(""), 204), Some(Frame::Empty));
        let refused = [
            ok(""),
            ok("Connection: keep-alive, Close\r\nContent-Length: 0\r\n"),
            ok("Content-Length: 1\r\nContent-Length: 2\r\n"),
            ok("Content-Length: +1\r\n"),
            ok(&format!("Content-Length: {}\r\n", DRAIN + 1)),
            ok("Transfer-Encoding: gzip, chunked\r\n"),
            ok("Transfer-Encoding: chunked\r\nContent-Length: 2\r\n"),
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ];
        for head in &refused {
            assert_eq!(frame(head, 200), None, "{}", String::from_utf8_lossy(head));
        }
    }

    #[test]
    fn chunked_bodies_end_exactly() {
        assert_eq!(chunked(b"2\r\nok\r\n0\r\n\r\n"), End::At(12));
        assert_eq!(
            chunked(b"2;x=1\r\nok\r\n0\r\nT: 1\r\n\r\nmore"),
            End::At(22)
        );
        assert_eq!(chunked(b"2\r\nok\r\n0\r\n"), End::More);
        assert_eq!(chunked(b"2\r\no"), End::More);
        assert_eq!(chunked(b""), End::More);
        assert_eq!(chunked(b"2\r\nokxx"), End::Bad);
        assert_eq!(chunked(b"zz\r\n"), End::Bad);
        assert_eq!(chunked(b"+2\r\nok\r\n"), End::Bad);
        assert_eq!(chunked(format!("{:x}\r\n", DRAIN + 1).as_bytes()), End::Bad);
        assert_eq!(chunked(&vec![b'1'; LINE + 1]), End::Bad);
        assert_eq!(framed(b"okmore", Frame::Length(2)), End::At(2));
        assert_eq!(framed(b"o", Frame::Length(2)), End::More);
        assert_eq!(framed(b"", Frame::Empty), End::At(0));
    }

    #[test]
    fn retry_after_takes_only_delta_seconds() {
        let head = b"HTTP/1.1 429 Too Many\r\nRetry-After: 120\r\n\r\n";
        assert_eq!(retry_after(head), Some(Duration::from_secs(120)));
        let date = b"HTTP/1.1 503 x\r\nretry-after: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\n";
        assert_eq!(retry_after(date), None);
        assert_eq!(retry_after(b"HTTP/1.1 503 x\r\n\r\n"), None);
    }
}
