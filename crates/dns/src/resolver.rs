use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Duration;

use crypto::{Prk, Secret};
use rt::{Buf, Instant, TcpStream, UdpSocket, now, spawn, timeout};

use crate::wire::{self, Rcode, Record, Reply, Type};
use crate::{Error, Name};

const MAX_TTL: u32 = 86_400;
const MAX_NEGATIVE: u32 = 300;
const UDP_BUF: usize = 4096;
const TCP_READ: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub servers: Vec<SocketAddr>,
    pub dnssec: bool,
    pub timeout: Duration,
    pub tries: u8,
    pub cache: usize,
}

impl Settings {
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            dnssec: false,
            timeout: Duration::from_secs(2),
            tries: 3,
            cache: 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    Records(Vec<Record>),
    NoData,
    NxDomain,
}

#[derive(Debug)]
pub struct Lookup {
    pub name: Name,
    pub found: Found,
    pub secure: bool,
    pub expires: Instant,
}

#[derive(Clone)]
pub struct Resolver {
    inner: Rc<Inner>,
}

struct Inner {
    settings: Settings,
    ids: Prk,
    sent: Cell<u64>,
    cache: RefCell<Cache>,
    flights: RefCell<BTreeMap<(Name, Type), Rc<Flight>>>,
}

impl Resolver {
    pub fn new(settings: Settings, seed: &Secret<32>) -> Self {
        let cache = Cache::new(settings.cache);
        Self {
            inner: Rc::new(Inner {
                settings,
                ids: Prk::from_secret(seed),
                sent: Cell::new(0),
                cache: RefCell::new(cache),
                flights: RefCell::new(BTreeMap::new()),
            }),
        }
    }

    pub fn cached(&self) -> usize {
        self.inner.cache.borrow().entries.len()
    }

    pub fn sent(&self) -> u64 {
        self.inner.sent.get()
    }

    pub async fn lookup(&self, name: &Name, kind: Type) -> Result<Rc<Lookup>, Error> {
        let key = (name.clone(), kind);
        if let Some(found) = self.inner.cache.borrow().get(&key, now()) {
            return Ok(found);
        }
        let joined = self.inner.flights.borrow().get(&key).cloned();
        let flight = if let Some(flight) = joined {
            flight
        } else {
            let flight = Rc::new(Flight::default());
            self.inner
                .flights
                .borrow_mut()
                .insert(key.clone(), Rc::clone(&flight));
            let (resolver, done) = (self.clone(), Rc::clone(&flight));
            drop(spawn(async move {
                let result = resolver.resolve(&key.0, key.1).await;
                resolver.inner.flights.borrow_mut().remove(&key);
                if let Ok(found) = &result {
                    resolver
                        .inner
                        .cache
                        .borrow_mut()
                        .put(key, Rc::clone(found), now());
                }
                done.finish(result);
            }));
            flight
        };
        flight.wait().await
    }

    async fn resolve(&self, name: &Name, kind: Type) -> Result<Rc<Lookup>, Error> {
        let settings = &self.inner.settings;
        let mut last = Error::Timeout;
        for _ in 0..settings.tries {
            for &server in &settings.servers {
                match self.ask(server, name, kind).await {
                    Ok(reply) => match reply.rcode {
                        Rcode::NoError | Rcode::NxDomain => {
                            return Ok(Rc::new(self.finish(reply)));
                        }
                        Rcode::ServFail => last = Error::ServFail,
                        Rcode::Refused | Rcode::Other(_) => last = Error::Refused,
                    },
                    Err(error) => last = error,
                }
            }
        }
        Err(last)
    }

    fn finish(&self, reply: Reply) -> Lookup {
        let (found, ttl) = if reply.rcode == Rcode::NxDomain {
            (Found::NxDomain, None)
        } else if reply.records.is_empty() {
            (Found::NoData, None)
        } else {
            (Found::Records(reply.records), Some(reply.ttl.min(MAX_TTL)))
        };
        let ttl = ttl.unwrap_or_else(|| reply.negative_ttl.unwrap_or(0).min(MAX_NEGATIVE));
        Lookup {
            name: reply.name,
            found,
            secure: self.inner.settings.dnssec && reply.authentic,
            expires: now() + Duration::from_secs(u64::from(ttl)),
        }
    }

    fn next_id(&self) -> u16 {
        let sent = self.inner.sent.get() + 1;
        self.inner.sent.set(sent);
        let id = self
            .inner
            .ids
            .expand::<2>(&[b"dns id", &sent.to_le_bytes()]);
        u16::from_be_bytes(*id.expose())
    }

    async fn ask(&self, server: SocketAddr, name: &Name, kind: Type) -> Result<Reply, Error> {
        let settings = &self.inner.settings;
        let id = self.next_id();
        let packet = wire::query(id, name, kind, settings.dnssec);
        let reply = timeout(settings.timeout, udp(server, id, name, kind, &packet))
            .await
            .map_err(|_| Error::Timeout)??;
        if !reply.truncated {
            return Ok(reply);
        }
        timeout(settings.timeout, tcp(server, id, name, kind, &packet))
            .await
            .map_err(|_| Error::Timeout)?
    }
}

fn io_error(error: &io::Error) -> Error {
    Error::Io(error.kind())
}

async fn udp(
    server: SocketAddr,
    id: u16,
    name: &Name,
    kind: Type,
    packet: &[u8],
) -> Result<Reply, Error> {
    let local = if server.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(local).await.map_err(|e| io_error(&e))?;
    let (sent, _) = socket.send_to(Buf::from_slice(packet), server).await;
    sent.map_err(|e| io_error(&e))?;
    let mut buf = Buf::new(UDP_BUF);
    loop {
        let (got, back) = socket.recv_from(buf).await;
        buf = back;
        let (_, from) = got.map_err(|e| io_error(&e))?;
        if from.ip() != server.ip()
            || from.port() != server.port()
            || !wire::matches(id, name, kind, &buf)
        {
            continue;
        }
        return wire::parse(id, name, kind, &buf);
    }
}

async fn tcp(
    server: SocketAddr,
    id: u16,
    name: &Name,
    kind: Type,
    packet: &[u8],
) -> Result<Reply, Error> {
    let stream = TcpStream::connect(server).await.map_err(|e| io_error(&e))?;
    let len = u16::try_from(packet.len()).map_err(|_| Error::Name)?;
    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(packet);
    let (written, _) = stream.write_all(Buf::from_slice(&framed)).await;
    written.map_err(|e| io_error(&e))?;
    let mut data = Vec::new();
    let end = loop {
        if data.len() >= 2 {
            let end = 2 + usize::from(u16::from_be_bytes([data[0], data[1]]));
            if data.len() >= end {
                break end;
            }
        }
        let (read, buf) = stream.read(Buf::new(TCP_READ)).await;
        if read.map_err(|e| io_error(&e))? == 0 {
            return Err(Error::Malformed);
        }
        data.extend_from_slice(&buf);
    };
    let reply = wire::parse(id, name, kind, &data[2..end])?;
    if reply.truncated {
        return Err(Error::Malformed);
    }
    Ok(reply)
}

struct Cache {
    entries: BTreeMap<(Name, Type), Rc<Lookup>>,
    order: VecDeque<(Name, Type)>,
    limit: usize,
}

impl Cache {
    fn new(limit: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            limit,
        }
    }

    fn get(&self, key: &(Name, Type), now: Instant) -> Option<Rc<Lookup>> {
        self.entries
            .get(key)
            .filter(|found| found.expires > now)
            .cloned()
    }

    fn put(&mut self, key: (Name, Type), found: Rc<Lookup>, now: Instant) {
        if found.expires <= now || self.limit == 0 {
            return;
        }
        if self.entries.insert(key.clone(), found).is_none() {
            self.order.push_back(key);
        }
        while self.entries.len() > self.limit {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
    }
}

#[derive(Default)]
struct Flight {
    done: RefCell<Option<Result<Rc<Lookup>, Error>>>,
    waiters: RefCell<Vec<Waker>>,
}

impl Flight {
    fn finish(&self, result: Result<Rc<Lookup>, Error>) {
        *self.done.borrow_mut() = Some(result);
        for waker in self.waiters.take() {
            waker.wake();
        }
    }

    async fn wait(&self) -> Result<Rc<Lookup>, Error> {
        poll_fn(|cx| {
            if let Some(result) = &*self.done.borrow() {
                return Poll::Ready(result.clone());
            }
            let mut waiters = self.waiters.borrow_mut();
            if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                waiters.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await
    }
}
