use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use http::{Event, Limits, Phase, Request, Response, Server, Status};
use intake::{Conn, End, Listener};
use metrics::{Board, Def, Kind, Slab, negotiate};
use rt::{Instant, JoinHandle, Notify, TcpListener, now, sleep, spawn, timeout, wall_ms};
use sched::{Node, Transport};

use crate::Metrics;

pub(crate) const PREFIX: &str = "bunzzle";
const HEAD: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(60);
const WRITE: Duration = Duration::from_secs(10);
const STALE: u32 = 3;
const SESSIONS: usize = 16;
const REQUESTS: u32 = 100;

macro_rules! catalog {
    ($($id:ident: $kind:ident, $name:literal, $help:literal;)*) => {
        #[derive(Clone, Copy)]
        enum Id {
            $($id,)*
        }

        pub(crate) static CATALOG: &[Def] = &[
            $(Def { name: $name, help: $help, kind: Kind::$kind },)*
        ];
    };
}

catalog! {
    QueueRecipients: Gauge, "queue_recipients", "Recipients waiting in delivery lanes";
    AttemptsOverdue: Gauge, "attempts_overdue", "Delivery attempts running past their bound";
    MessagesExpired: Counter, "messages_expired", "Messages expired before delivery";
    AttemptsUnrouted: Counter, "attempts_unrouted", "Delivery attempts that found no route";
    AttemptsUnreadable: Counter, "attempts_unreadable", "Delivery attempts skipped because the message could not be read";
    SigningFaults: Counter, "signing_faults", "Signing attempts refused for a message format fault";
    SchedRefused: Counter, "sched_refused", "Scheduler entries and notes refused as stale or invalid";
    RecipientsDelivered: Counter, "recipients_delivered", "Recipient attempts answered as delivered";
    RecipientsFailed: Counter, "recipients_failed", "Recipient attempts answered as failed";
    RecipientsDeferred: Counter, "recipients_deferred", "Recipient attempts answered as deferred";
    RecipientsLater: Counter, "recipients_later", "Recipient attempts put off by local limits or retried at once";
    PooledConnections: Gauge, "pooled_connections", "Open outbound connections kept in the pool";
    PathsDown: Gauge, "paths_down", "Source and remote address pairs marked down";
    TicksLate: Counter, "ticks_late", "Scheduler ticks that ran late";
    SmtpSessions: Gauge, "smtp_sessions", "Open SMTP sessions";
    SmtpRefused: Counter, "smtp_refused", "SMTP connections refused by connection limits";
    SmtpTimeouts: Counter, "smtp_timeouts", "SMTP sessions ended by a timeout";
    SmtpTlsFailures: Counter, "smtp_tls_failures", "SMTP sessions ended by a TLS failure";
    ApiSessions: Gauge, "api_sessions", "Open API sessions";
    ApiRefused: Counter, "api_refused", "API connections refused by connection limits";
    ApiForwarded: Counter, "api_forwarded", "API requests forwarded to another core";
    ApiServed: Counter, "api_served", "API requests served for another core";
    EventsLost: Counter, "events_lost", "Delivery events lost before they were written";
    SearchSkipped: Counter, "search_skipped", "Search entries not written";
    SearchScans: Counter, "search_scans", "Search scans run";
    SearchBlocks: Counter, "search_blocks", "Index blocks read by search scans";
    SystemRecordsFailed: Counter, "system_records_failed", "System record writes that failed";
}

pub(crate) fn board(cores: u16) -> Arc<Board> {
    Arc::new(Board::new(PREFIX, CATALOG, cores).expect("metrics catalog"))
}

pub(crate) struct Sources<'a, T> {
    pub node: &'a Node<T>,
    pub smtp: &'a [Listener],
    pub api: Option<&'a api::Api>,
}

impl<T: Transport + 'static> Sources<'_, T> {
    fn write(&self, slab: &Slab) {
        let set = |id: Id, value: u64| slab.set(id as usize, value);
        let wide = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        let sched = self.node.sched();
        set(Id::QueueRecipients, sched.queued());
        set(Id::AttemptsOverdue, wide(sched.overdue()));
        set(Id::MessagesExpired, sched.expired());
        set(Id::AttemptsUnrouted, sched.unrouted());
        set(Id::AttemptsUnreadable, sched.unreadable());
        set(Id::SigningFaults, sched.unsigned());
        set(Id::SchedRefused, sched.refused());
        set(Id::TicksLate, self.node.ticks_late());
        let answers = sched.answers();
        set(Id::RecipientsDelivered, answers.delivered);
        set(Id::RecipientsFailed, answers.failed);
        set(Id::RecipientsDeferred, answers.deferred);
        set(Id::RecipientsLater, answers.later);
        let transport = sched.transport().stats();
        set(Id::PooledConnections, transport.pooled);
        set(Id::PathsDown, transport.dead_hosts);
        let smtp = self.smtp;
        set(
            Id::SmtpSessions,
            wide(smtp.iter().map(Listener::sessions).sum()),
        );
        set(
            Id::SmtpRefused,
            smtp.iter()
                .map(|l| l.refused() + l.ended(End::Refused))
                .sum(),
        );
        set(
            Id::SmtpTimeouts,
            smtp.iter().map(|l| l.ended(End::Timeout)).sum(),
        );
        set(
            Id::SmtpTlsFailures,
            smtp.iter().map(|l| l.ended(End::Tls)).sum(),
        );
        if let Some(api) = self.api {
            set(Id::ApiSessions, wide(api.sessions()));
            set(Id::ApiRefused, api.refused() + api.ended(End::Refused));
            set(Id::ApiForwarded, api.forwarded());
            set(Id::ApiServed, api.served());
        }
        let events = self.node.event_stats();
        set(Id::EventsLost, events.lost);
        set(Id::SearchSkipped, events.search_skipped);
        let search = self.node.search_stats();
        set(Id::SearchScans, search.scans);
        set(Id::SearchBlocks, search.blocks);
        set(Id::SystemRecordsFailed, self.node.system_records().failed);
    }
}

async fn publish<T: Transport + 'static>(slab: &Slab, interval: Duration, sources: Sources<'_, T>) {
    loop {
        sources.write(slab);
        slab.publish(wall_ms());
        sleep(interval).await;
    }
}

pub(crate) fn publishing<'a, T: Transport + 'static>(
    metrics: Option<(&'a Arc<Board>, &Metrics)>,
    core: u16,
    sources: Sources<'a, T>,
) -> Option<impl Future<Output = ()> + 'a> {
    let (board, settings) = metrics?;
    let slab = board.slab(core)?;
    Some(publish(slab, settings.interval, sources))
}

pub(crate) fn listeners(
    metrics: Option<(&Arc<Board>, &Metrics)>,
    sockets: Vec<TcpListener>,
) -> Vec<Scrapes> {
    let Some((board, settings)) = metrics else {
        return Vec::new();
    };
    sockets
        .into_iter()
        .map(|socket| Scrapes::start(socket, Arc::clone(board), settings.interval))
        .collect()
}

pub(crate) async fn alongside<F: Future, S: Future<Output = ()>>(
    main: F,
    side: Option<S>,
) -> F::Output {
    let mut main = pin!(main);
    let mut side = pin!(side);
    poll_fn(|cx| {
        if let Poll::Ready(value) = main.as_mut().poll(cx) {
            return Poll::Ready(value);
        }
        if let Some(running) = side.as_mut().as_pin_mut()
            && running.poll(cx).is_ready()
        {
            side.set(None);
        }
        Poll::Pending
    })
    .await
}

struct Scrape {
    board: Arc<Board>,
    stale: u64,
    size: Cell<usize>,
}

#[derive(Default)]
struct Shared {
    stop: Notify,
    closing: Cell<bool>,
    sessions: RefCell<BTreeMap<u64, Rc<Notify>>>,
    idle: Notify,
}

pub(crate) struct Scrapes {
    shared: Rc<Shared>,
    task: JoinHandle<()>,
}

impl Scrapes {
    fn start(socket: TcpListener, board: Arc<Board>, interval: Duration) -> Self {
        let interval = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        let scrape = Rc::new(Scrape {
            board,
            stale: interval.saturating_mul(u64::from(STALE)),
            size: Cell::new(4096),
        });
        let shared = Rc::new(Shared::default());
        let state = Rc::clone(&shared);
        let task = spawn(async move {
            let mut count = 0u64;
            loop {
                let Some(accepted) = stoppable(&state.stop, &state.closing, socket.accept()).await
                else {
                    return;
                };
                let Ok((io, _)) = accepted else {
                    continue;
                };
                if state.sessions.borrow().len() >= SESSIONS {
                    drop(io);
                    continue;
                }
                count += 1;
                let stop = Rc::new(Notify::default());
                state.sessions.borrow_mut().insert(count, Rc::clone(&stop));
                let (scrape, state) = (Rc::clone(&scrape), Rc::clone(&state));
                spawn(async move {
                    let mut conn = Conn::plain(io);
                    let ended = stoppable(&stop, &state.closing, session(&scrape, &mut conn)).await;
                    if ended.is_some() {
                        conn.shutdown().await;
                    }
                    let mut sessions = state.sessions.borrow_mut();
                    sessions.remove(&count);
                    if sessions.is_empty() {
                        state.idle.notify();
                    }
                });
            }
        });
        Self { shared, task }
    }

    pub(crate) async fn close(self) {
        let shared = self.shared;
        shared.closing.set(true);
        shared.stop.notify();
        self.task.await;
        for stop in shared.sessions.borrow().values() {
            stop.notify();
        }
        while !shared.sessions.borrow().is_empty() {
            shared.idle.wait().await;
        }
    }
}

async fn stoppable<F: Future>(stop: &Notify, closing: &Cell<bool>, work: F) -> Option<F::Output> {
    let mut work = pin!(work);
    loop {
        if closing.get() {
            return None;
        }
        let mut wait = pin!(stop.wait());
        let done = poll_fn(|cx| {
            if let Poll::Ready(value) = work.as_mut().poll(cx) {
                return Poll::Ready(Some(value));
            }
            wait.as_mut().poll(cx).map(|()| None)
        })
        .await;
        if done.is_some() {
            return done;
        }
    }
}

async fn session(scrape: &Scrape, conn: &mut Conn) {
    let mut server = Server::new(Limits {
        requests: REQUESTS,
        ..Limits::default()
    });
    let mut head = now();
    let mut last = head;
    loop {
        if let Some(event) = server.event() {
            let response = match event {
                Event::Request(request) => answer(scrape, &request),
                Event::Fault(status) => Response::new(status).close(),
                Event::Body(_) | Event::End => continue,
            };
            server.respond(&response, wall_ms());
            head = now();
            let output = server.output();
            if !matches!(timeout(WRITE, conn.write_all(&output)).await, Ok(Ok(()))) {
                return;
            }
            continue;
        }
        if server.closed() || !server.wants_input() {
            return;
        }
        let phase = server.phase();
        let deadline: Instant = if phase == Phase::Idle {
            last + IDLE
        } else {
            head + HEAD
        };
        let mut input = Vec::new();
        match timeout(
            deadline.saturating_duration_since(now()),
            conn.read(&mut input),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                last = now();
                if phase == Phase::Idle {
                    head = last;
                }
                server.input(&input);
            }
            _ => return,
        }
    }
}

fn answer(scrape: &Scrape, request: &Request) -> Response {
    if request.path != "/metrics" {
        return Response::new(Status::NOT_FOUND);
    }
    if request.method != "GET" && request.method != "HEAD" {
        return Response::new(Status::METHOD_NOT_ALLOWED)
            .header("Allow", "GET, HEAD")
            .unwrap_or_else(|_| Response::new(Status::METHOD_NOT_ALLOWED));
    }
    let format = negotiate(request.headers.get("accept"));
    let mut text = String::with_capacity(scrape.size.get());
    scrape
        .board
        .render(format, wall_ms(), scrape.stale, &mut text);
    scrape.size.set(text.len().saturating_add(1024));
    Response::new(Status::OK)
        .body(format.content_type(), text.into_bytes())
        .unwrap_or_else(|_| Response::new(Status::INTERNAL))
}
