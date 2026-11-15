use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use control::{Grant, Scope};
use crypto::Secret;
use http::{Event, Framing, Limits, Phase, Request, Response, Server, Status, Timeouts};
use intake::{
    Conn, End, Envelope, Failure, Fault, Guard, Origin, Refused, Required, Slot, Submission,
    message_limit,
};
use rt::{Instant, TcpStream, now, timeout};
use sched::{Node, Refusal, Transport, domain_of};
use tls::Acceptor;

use crate::json;
use crate::mime;
use crate::problem::Problem;
use crate::send;

const SLACK: u64 = 64 * 1024;

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
    pub(crate) acceptor: Option<Rc<Acceptor>>,
    pub(crate) config: Rc<Config>,
    pub(crate) guard: Guard,
    pub(crate) loopback: bool,
    pub(crate) stats: Rc<Stats>,
}

enum Stop {
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
    io: TcpStream,
    ip: IpAddr,
    shard: usize,
) -> End {
    let Ok(net) = context.guard.open(ip).await else {
        let _ = io.shutdown().await;
        return End::Refused;
    };
    let handshake = context.config.timeouts.handshake;
    let conn = match &context.acceptor {
        Some(acceptor) => match timeout(handshake, acceptor.accept(io)).await {
            Ok(Ok(stream)) => Conn::tls(stream),
            _ => return End::Tls,
        },
        None => Conn::plain(io),
    };
    let mut session = Session {
        server: Server::new(context.config.limits),
        context: &context,
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

struct Session<'a, T> {
    context: &'a Context<T>,
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
            "/v1/messages" if request.method == "POST" => {
                (Route::Messages, self.send(request, &id).await)
            }
            "/v1/messages" => (Route::Messages, Err(Problem::method("POST").into())),
            _ => (Route::Other, Err(Problem::not_found().into())),
        };
        match answer {
            Ok(response) => Ok((route, response)),
            Err(Stop::Problem(problem)) => Ok((route, problem.response(&id))),
            Err(Stop::End(end)) => Err(end),
        }
    }

    fn health(&self, request: &Request, id: &str) -> Result<Response, Stop> {
        if !self.context.loopback {
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

    async fn send(&mut self, request: &Request, id: &str) -> Result<Response, Stop> {
        let grant = self.auth(request).await?;
        let json = request
            .headers
            .get("content-type")
            .is_some_and(|value| media(value) == "application/json");
        if !json {
            return Err(Problem::media_type().into());
        }
        let node = &self.context.node;
        let limit = message_limit(node);
        let max = self
            .context
            .config
            .max_body
            .unwrap_or(limit / 3 * 4 + SLACK);
        let spool = node.spool();
        let chunk = spool.stream_chunk().max(spool.limits().inline) as u64;
        let hold = max + 2 * limit + 2 * chunk;
        let hold = usize::try_from(hold).unwrap_or(usize::MAX);
        let Some(_hold) = self.context.guard.reserve(hold) else {
            return Err(Problem::unavailable().close().into());
        };
        let body = self.body(request, max).await?;
        let recipients = spool.limits().recipients as usize;
        let send = send::parse(&body, recipients, limit)?;
        drop(body);
        let message = self.submit(grant, send, limit).await?;
        let mut out = String::from("{\"id\":");
        json::string(&message, &mut out);
        out.push('}');
        Ok(ok(id, out))
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

    async fn body(&mut self, request: &Request, max: u64) -> Result<Vec<u8>, Stop> {
        self.server.accept_body(max).map_err(Problem::framing)?;
        let expected = match request.body {
            Framing::Length(n) => n,
            Framing::None => 0,
            Framing::Chunked => max,
        };
        self.body = Some((now(), expected));
        let mut body = Vec::new();
        loop {
            match self.server.event() {
                Some(Event::Body(bytes)) => body.extend_from_slice(&bytes),
                Some(Event::End) => return Ok(body),
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

    async fn submit(&mut self, grant: Grant, send: send::Send, limit: u64) -> Result<String, Stop> {
        let node = &self.context.node;
        let domain =
            domain_of(&send.sender).ok_or_else(|| Problem::bad_address("envelope_from"))?;
        if node.table().sender(grant.tenant, &domain).is_none() {
            return Err(Problem::sender().into());
        }
        let mut draft = node
            .draft(grant.tenant, Some(grant.pool))
            .map_err(refusal)?;
        if draft.generation() != grant.generation {
            return Err(Problem::suspended().into());
        }
        let addresses: Vec<&str> = send.recipients.iter().map(String::as_str).collect();
        let results = node.recipients(&mut draft, &addresses).await;
        let mut refused = Vec::new();
        for (address, result) in addresses.iter().zip(results) {
            match result {
                Ok(_) => {}
                Err(Refusal::Address) => refused.push(((*address).to_owned(), "bad_address")),
                Err(Refusal::Suppressed) => refused.push(((*address).to_owned(), "suppressed")),
                Err(other) => return Err(refusal(other).into()),
            }
        }
        if !refused.is_empty() {
            return Err(Problem::refused(refused).into());
        }
        let shards = node.spool().shards();
        let shard = *shards
            .get(self.shard % shards.len().max(1))
            .ok_or_else(Problem::unavailable)?;
        self.shard = self.shard.wrapping_add(1);
        let mut submission = Submission::open(node, &mut draft, shard)
            .await
            .map_err(failure)?;
        let boundary = format!("=_{}", submission.id());
        let built = mime::build(&send.message, &boundary).map_err(mime_fault)?;
        if built.len() as u64 > limit {
            return Err(Problem::too_large().into());
        }
        submission
            .push(node, grant, &built)
            .await
            .map_err(failure)?;
        drop(built);
        let with = match self.conn.as_ref() {
            Some(conn) if conn.secure() => "HTTPS",
            _ => "HTTP",
        };
        let origin = Origin {
            node: &self.context.config.name,
            with,
            lifetime: self.context.config.lifetime,
        };
        let envelope = Envelope {
            sender: send.sender,
            required: Required {
                requiretls: send.require_tls,
                ..Required::default()
            },
            ..Envelope::default()
        };
        let accepted = submission
            .finish(node, grant, &origin, draft, envelope, &send.recipients)
            .await
            .map_err(failure)?;
        Ok(accepted)
    }
}

fn ok(request: &str, body: String) -> Response {
    Response::new(Status::OK)
        .header("Request-Id", request)
        .and_then(|r| r.body("application/json", body.into_bytes()))
        .unwrap_or_else(|_| Response::new(Status::INTERNAL))
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

fn media(value: &[u8]) -> String {
    let end = value.iter().position(|&b| b == b';').unwrap_or(value.len());
    String::from_utf8_lossy(value[..end].trim_ascii()).to_ascii_lowercase()
}

fn refusal(refusal: Refusal) -> Problem {
    match refusal {
        Refusal::Tenant => Problem::suspended(),
        Refusal::Pool => Problem::pool(),
        Refusal::Recipients => Problem::too_many_recipients(),
        Refusal::Address => Problem::bad_address("to"),
        Refusal::Suppressed => Problem::refused(Vec::new()),
        Refusal::Busy => Problem::rate_limited(),
        Refusal::Conflict
        | Refusal::Message
        | Refusal::Keys
        | Refusal::Signer
        | Refusal::Failed => Problem::unavailable(),
    }
}

fn failure(failure: Failure) -> Problem {
    match failure {
        Failure::Header(Fault::TooLarge) | Failure::TooBig => Problem::too_large(),
        Failure::Header(Fault::Signer) | Failure::Temporary => Problem::unavailable(),
        Failure::Header(_) => Problem::bad_header(),
        Failure::FromDomain | Failure::NoKey => Problem::sender(),
        Failure::Refused(r) => refusal(r),
    }
}

fn mime_fault(fault: mime::Fault) -> Problem {
    match fault {
        mime::Fault::Address => Problem::bad_address("from"),
        mime::Fault::Header => Problem::bad_header(),
        mime::Fault::ContentType => Problem::bad_message("`attachments.content_type` not accepted"),
        mime::Fault::ContentId => Problem::bad_message("`attachments.content_id` not accepted"),
        mime::Fault::Filename => Problem::bad_message("`attachments.filename` not accepted"),
        mime::Fault::Body => Problem::bad_message("message body not accepted"),
    }
}
