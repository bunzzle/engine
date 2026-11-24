use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use http::{Event, Limits, Phase, Request, Response, Server, Status};
use intake::{Conn, End, Guard, Listener};
use metrics::{Board, Def, Kind, Slab, negotiate};
use rt::{Instant, JoinHandle, Notify, TcpListener, now, sleep, spawn, timeout, wall_ms};
use sched::{Keyring, Node, Transport};

use crate::Metrics;

pub(crate) const PREFIX: &str = "bunzzle";
const HEAD: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(60);
const WRITE: Duration = Duration::from_secs(10);
const STALE: u32 = 3;
const SESSIONS: usize = 16;
const REQUESTS: u32 = 100;

macro_rules! catalog {
    ($enum:ident, $list:ident; $($id:ident: $kind:ident, $name:literal, $help:literal;)*) => {
        #[derive(Clone, Copy)]
        enum $enum {
            $($id,)*
        }

        pub(crate) static $list: &[Def] = &[
            $(Def { name: $name, help: $help, kind: Kind::$kind },)*
        ];
    };
}

catalog! {
    TenantId, TENANT_CATALOG;
    Queued: Gauge, "tenant_queue_recipients", "Recipients of the tenant waiting in delivery lanes";
    Accepted: Counter, "tenant_messages_accepted", "Messages of the tenant accepted into the spool";
    Delivered: Counter, "tenant_recipients_delivered", "Recipient attempts of the tenant answered as delivered";
    Failed: Counter, "tenant_recipients_failed", "Recipient attempts of the tenant answered as failed";
    Deferred: Counter, "tenant_recipients_deferred", "Recipient attempts of the tenant answered as deferred";
    Later: Counter, "tenant_recipients_later", "Recipient attempts of the tenant put back for later";
}

catalog! {
    Id, CATALOG;
    QueueRecipients: Gauge, "queue_recipients", "Recipients waiting in delivery lanes";
    AttemptsOverdue: Gauge, "attempts_overdue", "Delivery attempts running past their bound";
    MessagesExpired: Counter, "messages_expired", "Messages expired before delivery";
    AttemptsUnrouted: Counter, "attempts_unrouted", "Delivery attempts that found no route";
    AttemptsUnreadable: Counter, "attempts_unreadable", "Delivery attempts skipped because the message could not be read";
    SigningFaults: Counter, "signing_faults", "Signing attempts refused for a message format fault";
    SuppressionsBounced: Counter, "suppressions_bounced", "Recipients suppressed after a mailbox-level hard failure";
    SuppressionsBounceFailed: Counter, "suppressions_bounce_failed", "Mailbox-level hard failures that could not be suppressed";
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
    GuardSessions: Gauge, "guard_sessions", "Sessions held by the connection guard";
    GuardReservedBytes: Gauge, "guard_reserved_bytes", "Memory reserved by sessions";
    GuardPeakReservedBytes: Gauge, "guard_peak_reserved_bytes", "Highest memory reserved by sessions since start";
    GuardWaiting: Gauge, "guard_waiting", "Guard asks waiting for an owner answer";
    GuardEntries: Gauge, "guard_entries", "Address entries tracked by this core";
    GuardSessionLimit: Counter, "guard_session_limit", "Sessions refused by the session limit, a cause within smtp_refused and api_refused";
    GuardMemoryLimit: Counter, "guard_memory_limit", "Reservations refused by the memory budget, a cause within smtp_refused and api_refused";
    GuardOpenLimit: Counter, "guard_open_limit", "Connections refused by the per-address or per-tenant limit, a cause within smtp_refused and api_refused";
    GuardBanned: Counter, "guard_banned", "Connections refused from banned addresses, a cause within smtp_refused and api_refused";
    GuardUnanswered: Counter, "guard_unanswered", "Guard asks with no owner answer in time";
    GuardFailures: Counter, "guard_failures", "Failures recorded against addresses";
    GuardBans: Counter, "guard_bans", "Address bans started";
    GuardTableFull: Counter, "guard_table_full", "Address entries not stored because the table was full";
    GuardEvicted: Counter, "guard_evicted", "Address entries evicted for new ones";
    WebhookAcked: Counter, "webhook_acked", "Webhook calls answered with success";
    WebhookRetried: Counter, "webhook_retried", "Webhook calls that failed and will be retried";
    WebhookRefused: Counter, "webhook_refused", "Webhook calls not sent because the hook was not current or an internal fault";
    WebhookGone: Counter, "webhook_gone", "Webhook calls answered as gone";
    WebhooksDisabledGone: Counter, "webhooks_disabled_gone", "Webhooks disabled as gone";
    WebhooksDisabledFailing: Counter, "webhooks_disabled_failing", "Webhooks disabled after failing too long";
    WebhookReportsFailed: Counter, "webhook_reports_failed", "Webhook status writes that failed";
    WebhookStreams: Gauge, "webhook_streams", "Webhook streams running";
    WebhookStreamsFailing: Gauge, "webhook_streams_failing", "Webhook streams with failing calls";
    KeysConnects: Counter, "keys_connects", "Connections made to the key server";
    KeysDrops: Counter, "keys_drops", "Key server connections dropped";
    KeysSlow: Counter, "keys_slow", "Key server calls past their deadline";
    KeysRefused: Counter, "keys_refused", "Key calls refused because the key ring failed";
    KeysUnknown: Counter, "keys_unknown", "Key calls answered as unknown or conflicting";
    KeysUnavailable: Counter, "keys_unavailable", "Key calls with no answer from the key server";
    KeysBusy: Counter, "keys_busy", "Key calls answered as busy";
    KeysFailed: Counter, "keys_failed", "Key calls answered as failed";
    KeysGone: Counter, "keys_gone", "Key calls for tenants or generations that are gone";
    KeysBad: Counter, "keys_bad", "Key answers that could not be opened or used";
    KeysOpens: Counter, "keys_opens", "Tenant keys opened from the key server";
    KeysUnwraps: Counter, "keys_unwraps", "Batch keys unwrapped by the key server";
    KeysRefreshes: Counter, "keys_refreshes", "Tenant key refreshes started";
    KeysDkimNew: Counter, "keys_dkim_new", "DKIM keys created";
    KeysLoads: Counter, "keys_loads", "DKIM keys loaded";
    KeysSigns: Counter, "keys_signs", "Signatures made by the key server";
    KeysHookSecrets: Counter, "keys_hook_secrets", "Webhook secrets fetched";
    KeysSearchEvicted: Counter, "keys_search_evicted", "Times search day keys past retention were dropped from a held tenant key";
    KeysDaysBehind: Gauge, "keys_days_behind", "Days the last sealing key was behind the wall clock";
    KeysHooksHeld: Gauge, "keys_hooks_held", "Webhook secrets held in memory";
    KeysTenantHits: Counter, "keys_tenant_cache_hits", "Tenant key cache hits";
    KeysTenantMisses: Counter, "keys_tenant_cache_misses", "Tenant key cache misses";
    KeysTenantEvicted: Counter, "keys_tenant_cache_evicted", "Tenant keys evicted from the cache";
    KeysHookHits: Counter, "keys_hook_cache_hits", "Webhook secret cache hits";
    KeysHookMisses: Counter, "keys_hook_cache_misses", "Webhook secret cache misses";
    KeysHookEvicted: Counter, "keys_hook_cache_evicted", "Webhook secrets evicted from the cache";
    BatchesCreated: Counter, "batches_created", "Sealing batches created";
    BatchesFull: Counter, "batches_full", "Sealing batches closed because they were full";
    BatchesAged: Counter, "batches_aged", "Sealing batches closed because they were old";
    BatchesDay: Counter, "batches_day", "Sealing batches closed because the key day ended";
    BatchesMismatched: Counter, "batches_mismatched", "Batch key lookups refused because the tenant or generation did not match";
    BatchCacheHits: Counter, "batch_cache_hits", "Batch key cache hits";
    BatchCacheMisses: Counter, "batch_cache_misses", "Batch key cache misses";
    BatchCacheEvicted: Counter, "batch_cache_evicted", "Batch keys evicted from the cache";
    EventsLost: Counter, "events_lost", "Delivery events lost before they were written";
    SearchSkipped: Counter, "search_skipped", "Search entries not written";
    SearchScans: Counter, "search_scans", "Search scans run";
    SearchBlocks: Counter, "search_blocks", "Index blocks read by search scans";
    SystemRecordsFailed: Counter, "system_records_failed", "System record writes that failed";
}

pub(crate) fn board(cores: u16, tenants: &[u32]) -> Arc<Board> {
    Arc::new(
        Board::new(PREFIX, CATALOG, cores)
            .and_then(|board| board.with_node(store::metrics_slab()))
            .and_then(|board| board.with_tenants(TENANT_CATALOG, tenants))
            .expect("metrics catalog"),
    )
}

pub(crate) struct Sources<'a, T> {
    pub node: &'a Node<T>,
    pub smtp: &'a [Listener],
    pub guard: &'a Guard,
    pub keys: &'a Keyring,
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
        set(Id::SuppressionsBounced, sched.bounced());
        set(Id::SuppressionsBounceFailed, sched.bounce_failed());
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
        let guard = self.guard.stats();
        set(Id::GuardSessions, wide(guard.sessions));
        set(Id::GuardReservedBytes, wide(guard.reserved));
        set(Id::GuardPeakReservedBytes, wide(guard.peak));
        set(Id::GuardWaiting, wide(guard.waiting));
        set(
            Id::GuardEntries,
            wide(guard.owner.nets.saturating_add(guard.owner.wides)),
        );
        set(Id::GuardSessionLimit, guard.refused);
        set(Id::GuardMemoryLimit, guard.busy);
        set(Id::GuardOpenLimit, guard.owner.full);
        set(Id::GuardBanned, guard.owner.banned);
        set(Id::GuardUnanswered, guard.unanswered);
        set(Id::GuardFailures, guard.owner.failures);
        set(Id::GuardBans, guard.owner.bans);
        set(Id::GuardTableFull, guard.owner.table_full);
        set(Id::GuardEvicted, guard.owner.evicted);
        let calls = self.node.call_stats();
        set(Id::WebhookAcked, calls.acked);
        set(Id::WebhookRetried, calls.retried);
        set(Id::WebhookRefused, calls.refused);
        set(Id::WebhookGone, calls.gone);
        set(Id::WebhookStreams, calls.streams);
        set(Id::WebhookStreamsFailing, calls.failing);
        let hooks = self.node.hook_stats();
        set(Id::WebhooksDisabledGone, hooks.gone);
        set(Id::WebhooksDisabledFailing, hooks.failing);
        set(Id::WebhookReportsFailed, hooks.write_failed);
        self.write_keys(slab);
        let events = self.node.event_stats();
        set(Id::EventsLost, events.lost);
        set(Id::SearchSkipped, events.search_skipped);
        let search = self.node.search_stats();
        set(Id::SearchScans, search.scans);
        set(Id::SearchBlocks, search.blocks);
        set(Id::SystemRecordsFailed, self.node.system_records().failed);
    }

    fn write_tenants(&self, board: &Board, core: u16) {
        let sched = self.node.sched();
        for (index, tenant) in board.tenants().iter().enumerate() {
            let Some(slab) = board.tenant_slab(core, index) else {
                continue;
            };
            let set = |id: TenantId, value: u64| slab.set(id as usize, value);
            let stats = sched.tenant_stats(*tenant);
            set(TenantId::Queued, stats.queued);
            set(TenantId::Accepted, stats.accepted);
            set(TenantId::Delivered, stats.answers.delivered);
            set(TenantId::Failed, stats.answers.failed);
            set(TenantId::Deferred, stats.answers.deferred);
            set(TenantId::Later, stats.answers.later);
        }
    }
}

impl<T> Sources<'_, T> {
    fn write_keys(&self, slab: &Slab) {
        let set = |id: Id, value: u64| slab.set(id as usize, value);
        let ring = self.keys.ring().stats();
        set(Id::KeysConnects, ring.connects);
        set(Id::KeysDrops, ring.drops);
        set(Id::KeysSlow, ring.slow);
        set(Id::KeysRefused, ring.refused);
        set(Id::KeysUnknown, ring.unknown);
        set(Id::KeysUnavailable, ring.unavailable);
        set(Id::KeysBusy, ring.busy);
        set(Id::KeysFailed, ring.failed);
        set(Id::KeysGone, ring.gone);
        set(Id::KeysBad, ring.bad);
        set(Id::KeysOpens, ring.opens);
        set(Id::KeysUnwraps, ring.unwraps);
        set(Id::KeysRefreshes, ring.refreshes);
        set(Id::KeysDkimNew, ring.dkim_new);
        set(Id::KeysLoads, ring.loads);
        set(Id::KeysSigns, ring.signs);
        set(Id::KeysHookSecrets, ring.hook_secrets);
        set(Id::KeysSearchEvicted, ring.search_evicted);
        set(Id::KeysDaysBehind, u64::from(ring.behind));
        set(
            Id::KeysHooksHeld,
            u64::try_from(ring.held_hooks).unwrap_or(u64::MAX),
        );
        set(Id::KeysTenantHits, ring.tenants.hits);
        set(Id::KeysTenantMisses, ring.tenants.misses);
        set(Id::KeysTenantEvicted, ring.tenants.evicted);
        set(Id::KeysHookHits, ring.hooks.hits);
        set(Id::KeysHookMisses, ring.hooks.misses);
        set(Id::KeysHookEvicted, ring.hooks.evicted);
        let batches = self.keys.batch_stats();
        set(Id::BatchesCreated, batches.created);
        set(Id::BatchesFull, batches.full);
        set(Id::BatchesAged, batches.aged);
        set(Id::BatchesDay, batches.day);
        set(Id::BatchesMismatched, batches.mismatched);
        set(Id::BatchCacheHits, batches.cache.hits);
        set(Id::BatchCacheMisses, batches.cache.misses);
        set(Id::BatchCacheEvicted, batches.cache.evicted);
    }
}

async fn publish<T: Transport + 'static>(
    board: &Board,
    core: u16,
    slab: &Slab,
    interval: Duration,
    sources: Sources<'_, T>,
) {
    loop {
        sources.write(slab);
        sources.write_tenants(board, core);
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
    Some(publish(board, core, slab, settings.interval, sources))
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
