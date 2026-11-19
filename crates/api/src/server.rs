use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::future::poll_fn;
use std::net::IpAddr;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

use control::{Grant, Scope};
use crypto::Secret;
use http::{Event, Framing, Limits, Phase, Request, Response, Server, Status, Timeouts};
use intake::{Conn, End, Guard, Refused, Slot};
use rt::{Instant, TcpStream, now, timeout};
use sched::{Node, Transport};
use tls::Acceptor;

use crate::events;
use crate::forward::{Ahead, Back, Forwarder, Inbound, Link, Open, Remote};
use crate::handler::{Handler, Source, chunk, key, ok, refusal};
use crate::problem::Problem;

#[derive(Clone, Debug)]
pub struct Config {
    pub name: String,
    pub lifetime: u64,
    pub limits: Limits,
    pub timeouts: Timeouts,
    pub max_body: Option<u64>,
    pub drain: Duration,
}

impl Config {
    pub fn new(name: String) -> Self {
        Self {
            name,
            lifetime: 5 * 86_400_000,
            limits: Limits::default(),
            timeouts: Timeouts::default(),
            max_body: None,
            drain: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Route {
    Messages,
    Raw,
    Events,
    Health,
    Other,
}

#[derive(Default)]
pub(crate) struct Stats {
    pub(crate) counts: RefCell<BTreeMap<(Route, u16), u64>>,
    pub(crate) closing: Cell<bool>,
}

pub(crate) struct Context<T> {
    pub(crate) node: Node<T>,
    pub(crate) config: Rc<Config>,
    pub(crate) guard: Guard,
    pub(crate) stats: Rc<Stats>,
    pub(crate) forward: Rc<Forwarder>,
    pub(crate) reading: RefCell<BTreeSet<u32>>,
}

pub(crate) struct Port {
    pub(crate) acceptor: Option<Rc<Acceptor>>,
    pub(crate) loopback: bool,
}

pub(crate) enum Stop {
    Problem(Problem),
    End(End),
}

impl From<Problem> for Stop {
    fn from(problem: Problem) -> Self {
        Self::Problem(problem)
    }
}

pub(crate) async fn connection<T: Transport + 'static>(
    context: Rc<Context<T>>,
    port: Rc<Port>,
    io: TcpStream,
    ip: IpAddr,
    shard: usize,
) -> End {
    let Ok(net) = context.guard.open(ip).await else {
        let _ = io.shutdown().await;
        return End::Refused;
    };
    let handshake = context.config.timeouts.handshake;
    let conn = match &port.acceptor {
        Some(acceptor) => match timeout(handshake, acceptor.accept(io)).await {
            Ok(Ok(stream)) => Conn::tls(stream),
            _ => return End::Tls,
        },
        None => Conn::plain(io),
    };
    let mut session = Session {
        server: Server::new(context.config.limits),
        context: &context,
        loopback: port.loopback,
        ip,
        net: Some(net),
        tenant: None,
        conn: Some(conn),
        shard,
        head: now(),
        last: now(),
        body: None,
    };
    let end = session.run().await;
    if let Some(conn) = session.conn.as_mut() {
        conn.shutdown().await;
    }
    end
}

pub(crate) async fn serve<T: Transport + 'static>(
    context: Rc<Context<T>>,
    inbound: Rc<Inbound>,
    open: Box<Open>,
) {
    let key = inbound.key();
    let work = async {
        let Open {
            route,
            request,
            grant,
            id,
            secure: _,
            shard,
        } = *open;
        let mut source = Remote::new(Rc::clone(&inbound), context.config.timeouts.body);
        let mut handler = Handler {
            context: &context,
            source: &mut source,
            grant,
            shard,
        };
        let response = match handler.run(route, &request, &id).await {
            Ok(response) => response,
            Err(Stop::Problem(problem)) => problem.response(&id),
            Err(Stop::End(_)) => return,
        };
        inbound.reply(response);
    };
    context.forward.until_stopped(key, work).await;
}

struct Session<'a, T> {
    context: &'a Context<T>,
    loopback: bool,
    ip: IpAddr,
    net: Option<Slot>,
    tenant: Option<(u32, Option<Slot>)>,
    conn: Option<Conn>,
    server: Server,
    shard: usize,
    head: Instant,
    last: Instant,
    body: Option<(Instant, u64)>,
}

enum Piece {
    Body(Vec<u8>),
    End,
    Replied,
}

impl<T: Transport + 'static> Session<'_, T> {
    async fn run(&mut self) -> End {
        loop {
            while let Some(event) = self.server.event() {
                let (route, response) = match event {
                    Event::Request(request) => match self.request(&request).await {
                        Ok(answer) => answer,
                        Err(end) => return end,
                    },
                    Event::Fault(status) => {
                        (Route::Other, Problem::framing(status).response(&id()))
                    }
                    Event::Body(_) | Event::End => continue,
                };
                self.respond(route, &response);
            }
            if let Err(end) = self.flush().await {
                return end;
            }
            if self.server.closed() {
                return End::Done;
            }
            if let Err(end) = self.read().await {
                return end;
            }
        }
    }

    fn respond(&mut self, route: Route, response: &Response) {
        let clock = self.context.node.sched().clock().now();
        self.server.respond(response, clock);
        let key = (route, response.status().code());
        *self
            .context
            .stats
            .counts
            .borrow_mut()
            .entry(key)
            .or_default() += 1;
        self.head = now();
        self.body = None;
    }

    async fn flush(&mut self) -> Result<(), End> {
        let output = self.server.output();
        if output.is_empty() {
            return Ok(());
        }
        let conn = self.conn.as_mut().ok_or(End::Io)?;
        if conn.write_all(&output).await.is_err() {
            self.conn = None;
            return Err(End::Io);
        }
        Ok(())
    }

    fn deadline(&self) -> Instant {
        let t = &self.context.config.timeouts;
        match (self.server.phase(), self.body) {
            (Phase::Idle, _) => self.last + t.idle,
            (Phase::Body, Some((start, expected))) => {
                let paced = Duration::from_secs(expected / t.rate.max(1));
                (self.last + t.body).min(start + t.grace + paced)
            }
            (Phase::Body, None) => self.last + t.body,
            _ => self.head + t.head,
        }
    }

    async fn read(&mut self) -> Result<(), End> {
        let phase = self.server.phase();
        let wait = self.deadline().saturating_duration_since(now());
        let conn = self.conn.as_mut().ok_or(End::Io)?;
        let mut input = Vec::new();
        match timeout(wait, conn.read(&mut input)).await {
            Err(_) => {
                if phase != Phase::Idle {
                    let response = Problem::framing(Status::REQUEST_TIMEOUT).response(&id());
                    self.respond(Route::Other, &response);
                    let _ = timeout(Duration::from_secs(1), self.flush()).await;
                }
                Err(End::Timeout)
            }
            Ok(Err(_)) => {
                self.conn = None;
                Err(End::Io)
            }
            Ok(Ok(0)) => Err(End::Dropped),
            Ok(Ok(_)) => {
                self.last = now();
                if phase == Phase::Idle {
                    self.head = self.last;
                }
                self.server.input(&input);
                Ok(())
            }
        }
    }

    async fn request(&mut self, request: &Request) -> Result<(Route, Response), End> {
        let id = id();
        let (route, answer) = match request.path.as_str() {
            "/healthz" => (Route::Health, self.health(request, &id)),
            "/v1/messages" if request.method == "POST" => (
                Route::Messages,
                self.post(Route::Messages, request, &id).await,
            ),
            "/v1/messages" => (Route::Messages, Err(Problem::method("POST").into())),
            "/v1/messages/raw" if request.method == "POST" => {
                (Route::Raw, self.post(Route::Raw, request, &id).await)
            }
            "/v1/messages/raw" => (Route::Raw, Err(Problem::method("POST").into())),
            "/v1/events" if request.method == "GET" || request.method == "HEAD" => {
                (Route::Events, self.events(request, &id).await)
            }
            "/v1/events" => (Route::Events, Err(Problem::method("GET, HEAD").into())),
            _ => (Route::Other, Err(Problem::not_found().into())),
        };
        match answer {
            Ok(response) => Ok((route, response)),
            Err(Stop::Problem(problem)) => Ok((route, problem.response(&id))),
            Err(Stop::End(end)) => Err(end),
        }
    }

    fn health(&self, request: &Request, id: &str) -> Result<Response, Stop> {
        if !self.loopback {
            return Err(Problem::not_found().into());
        }
        if request.method != "GET" && request.method != "HEAD" {
            return Err(Problem::method("GET, HEAD").into());
        }
        if self.context.stats.closing.get() {
            return Err(Problem::unavailable().into());
        }
        Ok(ok(id, "{\"status\":\"ok\"}".into()))
    }

    async fn events(&mut self, request: &Request, id: &str) -> Result<Response, Stop> {
        let grant = self.auth(request).await?;
        events::read(self.context, grant.tenant, request, id).await
    }

    async fn post(&mut self, route: Route, request: &Request, id: &str) -> Result<Response, Stop> {
        let grant = self.auth(request).await?;
        let context = self.context;
        let shard = match key(request)? {
            None => self.next_shard()?,
            Some(key) => {
                let requests = context.node.requests();
                let shard = requests.shard(grant.tenant, key).await.map_err(refusal)?;
                let owner = context.forward.owner(shard);
                if owner != context.forward.index() {
                    let open = Open {
                        route,
                        request: request.clone(),
                        grant,
                        id: id.to_owned(),
                        secure: self.secure(),
                        shard,
                    };
                    return self.forward(owner, open).await;
                }
                shard
            }
        };
        let mut handler = Handler {
            context,
            source: self,
            grant,
            shard,
        };
        handler.run(route, request, id).await
    }

    fn next_shard(&mut self) -> Result<u16, Problem> {
        let shards = self.context.node.spool().shards();
        let shard = *shards
            .get(self.shard % shards.len().max(1))
            .ok_or_else(Problem::unavailable)?;
        self.shard = self.shard.wrapping_add(1);
        Ok(shard)
    }

    async fn forward(&mut self, owner: u16, open: Open) -> Result<Response, Stop> {
        let context = self.context;
        let size = usize::try_from(chunk(&context.node)).unwrap_or(usize::MAX);
        let Some(_hold) = context.guard.reserve(size.saturating_mul(2)) else {
            return Err(Problem::unavailable().close().into());
        };
        let request = open.request.clone();
        let wait = context.guard.limits().ask;
        let mut link = context.forward.open(owner, open);
        let mut credits = 0u32;
        let mut started = false;
        let mut ended = false;
        let mut pending = Vec::new();
        loop {
            let back = if let Some(back) = link.pipe().try_take() {
                Some(back)
            } else if started && !ended && credits > 0 {
                if !pending.is_empty() {
                    let end = pending.len().min(size.max(1));
                    let rest = pending.split_off(end);
                    link.send(Ahead::Chunk(std::mem::replace(&mut pending, rest)));
                    credits -= 1;
                    continue;
                }
                match self.next_or(&link).await? {
                    Piece::Body(bytes) => {
                        pending = bytes;
                        continue;
                    }
                    Piece::End => {
                        link.send(Ahead::End);
                        ended = true;
                        continue;
                    }
                    Piece::Replied => link.pipe().take().await,
                }
            } else if ended {
                link.pipe().take().await
            } else {
                timeout(wait, link.pipe().take())
                    .await
                    .map_err(|_| Problem::unavailable().close())?
            };
            match back {
                None => return Err(Problem::unavailable().close().into()),
                Some(Back::Start(max)) => {
                    self.start(&request, max)?;
                    started = true;
                    credits = 2;
                }
                Some(Back::Credit) => credits += 1,
                Some(Back::Reply(response)) => {
                    link.done();
                    return Ok(*response);
                }
            }
        }
    }

    async fn next_or(&mut self, link: &Link) -> Result<Piece, Stop> {
        loop {
            match self.server.event() {
                Some(Event::Body(bytes)) => return Ok(Piece::Body(bytes)),
                Some(Event::End) => return Ok(Piece::End),
                Some(Event::Fault(status)) => return Err(Problem::framing(status).into()),
                Some(Event::Request(_)) => {
                    return Err(Problem::framing(Status::BAD_REQUEST).into());
                }
                None => {
                    self.flush().await.map_err(Stop::End)?;
                    let mut read = pin!(self.read());
                    let mut replied = pin!(link.reply());
                    let raced = poll_fn(|cx| {
                        if replied.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(None);
                        }
                        read.as_mut().poll(cx).map(Some)
                    })
                    .await;
                    match raced {
                        None => return Ok(Piece::Replied),
                        Some(read) => read.map_err(Stop::End)?,
                    }
                }
            }
        }
    }

    async fn auth(&mut self, request: &Request) -> Result<Grant, Stop> {
        let token = match request.headers.count("authorization") {
            1 => request.headers.get("authorization").and_then(bearer),
            _ => None,
        };
        let grant = token.and_then(|token| self.context.node.table().check(token, Scope::Api));
        let Some(grant) = grant else {
            return Err(match self.context.guard.failed(self.ip).await {
                Ok(false) => Problem::unauthorized(),
                Ok(true) => Problem::unauthorized().close(),
                Err(_) => Problem::unavailable(),
            }
            .into());
        };
        if self.tenant.as_ref().is_none_or(|(t, _)| *t != grant.tenant) {
            self.tenant = None;
            let limit = self
                .context
                .node
                .table()
                .tenant(grant.tenant)
                .map_or(0, |tenant| tenant.limits.connections);
            let slot = if limit > 0 {
                let opened = self.context.guard.open_tenant(grant.tenant, limit).await;
                Some(opened.map_err(|refused| match refused {
                    Refused::Unanswered => Problem::unavailable(),
                    Refused::Full | Refused::Banned => Problem::rate_limited(),
                })?)
            } else {
                None
            };
            self.tenant = Some((grant.tenant, slot));
        }
        self.net = None;
        Ok(grant)
    }
}

impl<T: Transport + 'static> Source for Session<'_, T> {
    fn start(&mut self, request: &Request, max: u64) -> Result<(), Stop> {
        self.server.accept_body(max).map_err(Problem::framing)?;
        let expected = match request.body {
            Framing::Length(n) => n,
            Framing::None => 0,
            Framing::Chunked => max,
        };
        self.body = Some((now(), expected));
        Ok(())
    }

    async fn next(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        loop {
            match self.server.event() {
                Some(Event::Body(bytes)) => return Ok(Some(bytes)),
                Some(Event::End) => return Ok(None),
                Some(Event::Fault(status)) => return Err(Problem::framing(status).into()),
                Some(Event::Request(_)) => {
                    return Err(Problem::framing(Status::BAD_REQUEST).into());
                }
                None => {
                    self.flush().await.map_err(Stop::End)?;
                    self.read().await.map_err(Stop::End)?;
                }
            }
        }
    }

    fn secure(&self) -> bool {
        self.conn.as_ref().is_some_and(Conn::secure)
    }
}

fn id() -> String {
    let mut out = String::with_capacity(32);
    if let Ok(secret) = Secret::<16>::random() {
        for byte in secret.expose() {
            let _ = write!(out, "{byte:02x}");
        }
    }
    out
}

fn bearer(value: &[u8]) -> Option<&[u8]> {
    let (scheme, token) = value.split_at_checked(7)?;
    if !scheme.eq_ignore_ascii_case(b"bearer ") {
        return None;
    }
    let token = token.trim_ascii();
    (!token.is_empty()).then_some(token)
}
