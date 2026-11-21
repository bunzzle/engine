use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use control::{Hook, HookState};
use crypto::{Ids, Secret, hmac_sha256};
use dkim::base64;
use dns::Name;
use rt::{Instant, TcpStream, UdpSocket, timeout};
use sched::{Call, Deliver, Node, Outcome, Sending, Transport, event_json};
use tls::{Connector, Verify};

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
const OWN: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Self> {
        let (ip, prefix) = match text.split_once('/') {
            Some((ip, prefix))
                if !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()) =>
            {
                (ip.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?)
            }
            Some(_) => return None,
            None => {
                let ip = text.parse::<IpAddr>().ok()?;
                (ip, if ip.is_ipv4() { 32 } else { 128 })
            }
        };
        let most = if ip.is_ipv4() { 32 } else { 128 };
        (prefix <= most).then_some(Self { ip, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let (net, ip, bits) = match (self.ip, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => (
                u128::from(u32::from(net)) << 96,
                u128::from(u32::from(*ip)) << 96,
                self.prefix,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => (u128::from(net), u128::from(*ip), self.prefix),
            _ => return false,
        };
        let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
        net & mask == ip & mask
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookSettings {
    pub egress: Option<IpAddr>,
    pub allow: Vec<Cidr>,
}

pub trait Local {
    fn bound(&self, ip: IpAddr) -> impl Future<Output = bool>;
}

pub struct Bind;

impl Local for Bind {
    async fn bound(&self, ip: IpAddr) -> bool {
        UdpSocket::bind(SocketAddr::new(ip, 0)).await.is_ok()
    }
}

pub struct Hooks<T, D, L = Bind> {
    inner: Rc<Inner<T, D, L>>,
}

struct Inner<T, D, L> {
    node: Node<T>,
    dns: D,
    tls: Connector,
    settings: HookSettings,
    local: L,
    core: Rc<Gate>,
    tenants: RefCell<BTreeMap<u32, Rc<Gate>>>,
    failures: RefCell<BTreeMap<Key, (u32, Instant)>>,
    pruned: Cell<Instant>,
    own: RefCell<BTreeMap<IpAddr, bool>>,
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
                local,
                core: Gate::new(CORE_CALLS),
                tenants: RefCell::default(),
                failures: RefCell::default(),
                pruned: Cell::new(rt::now()),
                own: RefCell::default(),
                random: Cell::new(seed | 1),
            }),
        }
    }
}

impl<T: Transport + 'static, D: Dns + 'static, L: Local + 'static> Deliver for Hooks<T, D, L> {
    fn deliver(&self, call: Rc<Call>) -> Sending {
        let inner = Rc::clone(&self.inner);
        Box::pin(async move { inner.call(&call).await })
    }
}

type Key = (u32, u32, u32);

#[derive(Clone, Copy)]
enum Sent {
    Status(u16, Option<Duration>),
    Refused,
    Failed,
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
            let sent = timeout(CALL, self.attempt(call, &mut open))
                .await
                .unwrap_or(Sent::Failed);
            if let Some(mut stream) = open {
                let _ = timeout(CLOSE, stream.shutdown()).await;
            }
            sent
        };
        if gate.idle() && Rc::strong_count(&gate) == 2 {
            self.tenants.borrow_mut().remove(&call.tenant);
        }
        drop(gate);
        self.outcome(call, sent)
    }

    fn outcome(&self, call: &Call, sent: Sent) -> Outcome {
        let key = (call.tenant, call.generation, call.hook);
        self.prune();
        match sent {
            Sent::Status(200..=299, _) => {
                self.failures.borrow_mut().remove(&key);
                Outcome::Acked
            }
            Sent::Refused => {
                self.failures.borrow_mut().remove(&key);
                Outcome::Retry(PAUSE_MIN)
            }
            Sent::Status(410, _) => {
                self.failed(key);
                Outcome::Retry(PAUSE_MAX)
            }
            Sent::Status(429 | 503, Some(after)) => {
                self.failed(key);
                Outcome::Retry(after.clamp(PAUSE_MIN, PAUSE_MAX))
            }
            Sent::Status(..) | Sent::Failed => {
                let n = self.failed(key);
                Outcome::Retry(self.pause(n))
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

    async fn attempt(&self, call: &Call, open: &mut Option<tls::Stream>) -> Sent {
        let Some(first) = self.snapshot(call) else {
            return Sent::Refused;
        };
        let Some(target) = target(&first.0.url) else {
            return Sent::Failed;
        };
        let Some(secrets) = self.secrets(call, &first).await else {
            return Sent::Failed;
        };
        let Some(ids) = self.node.ids() else {
            return Sent::Failed;
        };
        let Ok(ids) = Ids::new(&ids) else {
            return Sent::Failed;
        };
        let Ok(name) = Name::parse(&target.host) else {
            return Sent::Failed;
        };
        for ip in self.addresses(&name).await {
            if !self.same(call, &first) {
                return Sent::Refused;
            }
            let Ok(Ok(io)) = timeout(CONNECT, self.connect(ip, &target)).await else {
                continue;
            };
            let Ok(Ok(mut stream)) =
                timeout(CONNECT, self.tls.connect(io, &target.host, Verify::WebPki)).await
            else {
                continue;
            };
            let Some(request) = self.request(call, &target, &ids, &secrets).await else {
                return Sent::Failed;
            };
            if !self.same(call, &first) {
                return Sent::Refused;
            }
            if stream.write_all(&request).await.is_err() {
                return Sent::Failed;
            }
            drop(request);
            let sent = read_status(&mut stream).await;
            *open = Some(stream);
            return sent;
        }
        Sent::Failed
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

    async fn addresses(&self, name: &Name) -> Vec<IpAddr> {
        let families: &[bool] = match self.settings.egress {
            Some(egress) => &[egress.is_ipv6()],
            None => &[false, true],
        };
        let mut out = Vec::new();
        for &v6 in families {
            let keep = |ip: &IpAddr| keep(ip, &self.settings.allow);
            if let Addresses::Found { ips, .. } = mx::filtered(&self.dns, name, v6, keep).await {
                out.extend(ips);
            }
        }
        let mut kept = Vec::with_capacity(ADDRESSES);
        for ip in out {
            if kept.len() == ADDRESSES {
                break;
            }
            if !self.own(ip).await {
                kept.push(ip);
            }
        }
        kept
    }

    async fn connect(&self, ip: IpAddr, target: &Target) -> std::io::Result<TcpStream> {
        let to = SocketAddr::new(ip, target.port);
        match self.settings.egress {
            Some(egress) => TcpStream::connect_from(egress, to).await,
            None => TcpStream::connect(to).await,
        }
    }

    async fn own(&self, ip: IpAddr) -> bool {
        for ip in std::iter::once(ip).chain(embedded(ip).map(IpAddr::V4)) {
            let known = self.own.borrow().get(&ip).copied();
            let own = if let Some(own) = known {
                own
            } else {
                let own = self.local.bound(ip).await;
                let mut cache = self.own.borrow_mut();
                if cache.len() >= OWN {
                    cache.clear();
                }
                cache.insert(ip, own);
                own
            };
            if own {
                return true;
            }
        }
        false
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
             Content-Length: {}\r\nUser-Agent: webhooks\r\nConnection: close\r\n\
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

async fn read_status(stream: &mut tls::Stream) -> Sent {
    let mut bytes = Vec::new();
    let mut buf = [0; READ];
    loop {
        let end = loop {
            if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            if bytes.len() >= HEAD {
                return Sent::Failed;
            }
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return Sent::Failed,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
            }
        };
        if end > HEAD {
            return Sent::Failed;
        }
        let Some(code) = crate::https::status(&bytes[..end]) else {
            return Sent::Failed;
        };
        if (100..200).contains(&code) {
            bytes.drain(..end);
            continue;
        }
        return Sent::Status(code, retry_after(&bytes[..end]));
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

pub(crate) fn keep(ip: &IpAddr, allow: &[Cidr]) -> bool {
    if floor(ip) {
        return false;
    }
    mx::global(ip) || (embedded(*ip).is_none() && allow.iter().any(|cidr| cidr.contains(ip)))
}

fn floor(ip: &IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(v6) => embedded(IpAddr::V6(*v6)),
    };
    let link = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    !mx::usable(ip)
        || link
        || v4.is_some_and(|v4| !mx::usable(&IpAddr::V4(v4)) || v4.is_link_local())
}

fn embedded(ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else {
        return None;
    };
    let segments = v6.segments();
    let pair = match segments {
        [0, 0, 0, 0, 0, 0 | 0xffff, ..]
            if v6 != Ipv6Addr::UNSPECIFIED && v6 != Ipv6Addr::LOCALHOST =>
        {
            (segments[6], segments[7])
        }
        [0x64, 0xff9b, 0, 0, 0, 0, ..] | [0x64, 0xff9b, 1, ..] => (segments[6], segments[7]),
        [0x2002, high, low, ..] => (high, low),
        _ => return None,
    };
    let [first, second] = pair.0.to_be_bytes();
    let [third, fourth] = pair.1.to_be_bytes();
    Some(Ipv4Addr::new(first, second, third, fourth))
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

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    #[test]
    fn allowed_addresses_never_pass_the_floor() {
        let allow = [
            Cidr::parse("10.0.0.0/8").expect("cidr"),
            Cidr::parse("fd00::/8").expect("cidr"),
            Cidr::parse("127.0.0.0/8").expect("cidr"),
            Cidr::parse("169.254.0.0/16").expect("cidr"),
            Cidr::parse("::/0").expect("cidr"),
        ];
        for good in ["8.8.8.8", "10.1.2.3", "fd00::1", "64:ff9b::8.8.8.8"] {
            assert!(keep(&ip(good), &allow), "{good}");
        }
        for bad in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:169.254.169.254",
            "64:ff9b::10.0.0.1",
            "64:ff9b::127.0.0.1",
            "2002:7f00:0001::1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!keep(&ip(bad), &allow), "{bad}");
        }
        assert!(!keep(&ip("10.1.2.3"), &[]));
        assert!(!keep(&ip("fd00::1"), &[]));
    }

    #[test]
    fn cidrs_match_by_prefix() {
        let net = Cidr::parse("192.168.4.0/22").expect("cidr");
        assert!(net.contains(&ip("192.168.7.255")));
        assert!(!net.contains(&ip("192.168.8.0")));
        assert!(!net.contains(&ip("::ffff:192.168.4.1")));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .expect("all")
                .contains(&ip("1.2.3.4"))
        );
        assert_eq!(Cidr::parse("10.0.0.1").map(|c| c.prefix), Some(32));
        for bad in ["10.0.0.0/33", "::/129", "x/8", "10.0.0.0/", "10.0.0.0/+8"] {
            assert!(Cidr::parse(bad).is_none(), "{bad}");
        }
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
