use std::cell::{Cell, OnceCell};

use control::{KeyError, Verification};
use crypto::{Ids, Token};
use rt::{Instant, now, timeout};
use sched::{Node, RETURN_PREFIX, Refusal, ReportOutcome, Transport};
use smtp::{Event, Reply, Server, reply};
use spool::MessageId;
use tls::Acceptor;

use crate::conn::Conn;
use crate::guard::{Guard, Reserved, Slot};
use crate::session::{Config, End, message_limit};

pub const KEEP: usize = 1 << 20;
pub const HOLD: usize = 3 * KEEP + 2 * smtp::CHUNK;
pub const LOADS: usize = 8;

const UNKNOWN: Reply = Reply::new(550, "5.1.1", "No such recipient");
const BUSY: Reply = Reply::new(451, "4.3.2", "System busy");
const PERMANENT: Reply = Reply::new(550, "5.0.0", "Permanent failure");

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReportStats {
    pub accepted: u64,
    pub refused: u64,
    pub busy: u64,
    pub held: u64,
    pub unmatched: u64,
    pub gone: u64,
}

pub struct Reports {
    loads: Cell<usize>,
    cap: usize,
    ids: OnceCell<Ids>,
    accepted: Cell<u64>,
    refused: Cell<u64>,
    busy: Cell<u64>,
    held: Cell<u64>,
    unmatched: Cell<u64>,
    gone: Cell<u64>,
}

impl Reports {
    pub fn new(cap: usize) -> Self {
        Self {
            loads: Cell::new(0),
            cap,
            ids: OnceCell::new(),
            accepted: Cell::new(0),
            refused: Cell::new(0),
            busy: Cell::new(0),
            held: Cell::new(0),
            unmatched: Cell::new(0),
            gone: Cell::new(0),
        }
    }

    pub fn stats(&self) -> ReportStats {
        ReportStats {
            accepted: self.accepted.get(),
            refused: self.refused.get(),
            busy: self.busy.get(),
            held: self.held.get(),
            unmatched: self.unmatched.get(),
            gone: self.gone.get(),
        }
    }

    async fn ids<T: Transport + 'static>(&self, node: &Node<T>) -> Result<&Ids, Reply> {
        if self.ids.get().is_none() {
            let secret = if let Some(secret) = node.ids() {
                secret
            } else {
                let _load = Load::take(&self.loads, self.cap).ok_or(BUSY)?;
                node.load_ids().await.ok_or(reply::TEMPORARY)?
            };
            let ids = Ids::new(&secret).map_err(|_| reply::TEMPORARY)?;
            let _ = self.ids.set(ids);
        }
        self.ids.get().ok_or(reply::TEMPORARY)
    }

    pub async fn check<T: Transport + 'static>(
        &self,
        node: &Node<T>,
        address: &str,
    ) -> Result<(Token, u32), Reply> {
        let checked = self.verify(node, address).await;
        let count = match &checked {
            Ok(_) => &self.accepted,
            Err(reply) if reply.code() >= 500 => &self.refused,
            Err(_) => &self.busy,
        };
        count.set(count.get() + 1);
        checked
    }

    async fn verify<T: Transport + 'static>(
        &self,
        node: &Node<T>,
        address: &str,
    ) -> Result<(Token, u32), Reply> {
        let (local, domain) = address.rsplit_once('@').ok_or(UNKNOWN)?;
        let text = local.strip_prefix(['b', 'B']).ok_or(UNKNOWN)?;
        let token = Token::parse(text.as_bytes()).ok_or(UNKNOWN)?;
        let generation = {
            let table = node.table();
            let generation = table
                .tenant(token.tenant)
                .filter(|tenant| !tenant.state.deleted())
                .map(|tenant| tenant.generation)
                .ok_or(UNKNOWN)?;
            let (prefix, name) = domain.split_once('.').ok_or(UNKNOWN)?;
            if !prefix.eq_ignore_ascii_case(RETURN_PREFIX)
                || !table.domains(token.tenant).any(|record| {
                    record.state == Verification::Verified
                        && record.generation == generation
                        && name.eq_ignore_ascii_case(&record.name)
                })
            {
                return Err(UNKNOWN);
            }
            generation
        };
        let ids = self.ids(node).await?;
        let raw = ids.reveal(&token.id).ok_or(UNKNOWN)?;
        let ours = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) == node.spool().node();
        if !ours || raw[6..8] != [0, 0] {
            return Err(UNKNOWN);
        }
        let keys = if let Some(keys) = node.cached_keys(token.tenant, generation) {
            keys
        } else {
            let _load = Load::take(&self.loads, self.cap).ok_or(BUSY)?;
            node.load_keys(token.tenant, generation)
                .await
                .map_err(|error| match error {
                    KeyError::Unknown => UNKNOWN,
                    _ => reply::TEMPORARY,
                })?
        };
        if !token.verify(&keys) {
            return Err(UNKNOWN);
        }
        Ok((token, generation))
    }
}

struct Load<'a>(&'a Cell<usize>);

impl<'a> Load<'a> {
    fn take(loads: &'a Cell<usize>, cap: usize) -> Option<Self> {
        if loads.get() >= cap {
            return None;
        }
        loads.set(loads.get() + 1);
        Some(Self(loads))
    }
}

impl Drop for Load<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

pub async fn serve<T: Transport + 'static>(
    node: &Node<T>,
    acceptor: &Acceptor,
    conn: Conn,
    config: &Config,
    guard: &Guard,
    net: Slot,
    reports: &Reports,
) -> End {
    let server = Server::new(smtp::Config {
        name: config.name.clone(),
        message: message_limit(node),
        implicit: conn.secure(),
        messages: config.messages,
        mx: true,
    });
    let mut session = Session {
        node,
        acceptor,
        config,
        guard,
        reports,
        _net: net,
        conn: Some(conn),
        server,
        tx: None,
        start: now(),
        last: now(),
    };
    let end = session.run().await;
    if let Some(conn) = session.conn.as_mut() {
        let _ = timeout(config.handshake, conn.shutdown()).await;
    }
    end
}

struct Session<'a, T> {
    node: &'a Node<T>,
    acceptor: &'a Acceptor,
    config: &'a Config,
    guard: &'a Guard,
    reports: &'a Reports,
    _net: Slot,
    conn: Option<Conn>,
    server: Server,
    tx: Option<Tx>,
    start: Instant,
    last: Instant,
}

#[derive(Default)]
struct Tx {
    token: Option<(Token, u32)>,
    body: Vec<u8>,
    hold: Option<Reserved>,
}

impl<T: Transport + 'static> Session<'_, T> {
    async fn run(&mut self) -> End {
        let mut input = Vec::new();
        loop {
            while let Some(event) = self.server.poll() {
                if let Err(end) = self.event(event).await {
                    return end;
                }
            }
            if let Err(end) = self.flush().await {
                return end;
            }
            if self.server.closed() {
                return End::Done;
            }
            let wait = self.deadline().saturating_duration_since(now());
            let Some(conn) = self.conn.as_mut() else {
                return End::Io;
            };
            input.clear();
            match timeout(wait, conn.read(&mut input)).await {
                Err(_) => {
                    self.conn = None;
                    return End::Timeout;
                }
                Ok(Err(_)) => {
                    self.conn = None;
                    return End::Io;
                }
                Ok(Ok(0)) => return End::Dropped,
                Ok(Ok(_)) => {
                    self.last = now();
                    self.server.input(&input);
                }
            }
        }
    }

    fn deadline(&self) -> Instant {
        let inside = self.tx.as_ref().is_some_and(|tx| tx.hold.is_some());
        let idle = if inside {
            self.config.data
        } else {
            self.config.idle
        };
        (self.last + idle).min(self.start + self.config.session)
    }

    async fn flush(&mut self) -> Result<(), End> {
        let output = self.server.output();
        if output.is_empty() {
            return Ok(());
        }
        let wait = self.deadline().saturating_duration_since(now());
        let conn = self.conn.as_mut().ok_or(End::Io)?;
        match timeout(wait, conn.write_all(&output)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => {
                self.conn = None;
                Err(End::Io)
            }
            Err(_) => {
                self.conn = None;
                Err(End::Timeout)
            }
        }
    }

    async fn event(&mut self, event: Event) -> Result<(), End> {
        match event {
            Event::Starttls => self.starttls().await?,
            Event::Auth(_) => self.server.auth(Err(reply::NOT_IMPLEMENTED)),
            Event::Mail { .. } => {
                self.tx = Some(Tx::default());
                self.server.mail(Ok(()));
            }
            Event::Recipients(group) => {
                self.flush().await?;
                let answers = self.recipients(group).await;
                self.server.recipients(answers);
            }
            Event::Data => {
                let answer = self.data();
                self.server.data(answer);
            }
            Event::Body(bytes) => {
                if let Some(tx) = self.tx.as_mut() {
                    let room = KEEP.saturating_sub(tx.body.len());
                    tx.body.extend_from_slice(&bytes[..room.min(bytes.len())]);
                }
            }
            Event::End { .. } => {
                let reply = self.finish().await;
                self.server.message(&reply);
            }
            Event::Reset => self.tx = None,
            Event::Close => {}
        }
        Ok(())
    }

    async fn starttls(&mut self) -> Result<(), End> {
        self.flush().await?;
        let conn = self.conn.take().ok_or(End::Io)?;
        let upgraded = timeout(self.config.handshake, conn.upgrade(self.acceptor)).await;
        match upgraded {
            Ok(Ok(conn)) => {
                self.conn = Some(conn);
                self.server.secured();
                Ok(())
            }
            _ => Err(End::Tls),
        }
    }

    async fn recipients(&mut self, group: Vec<String>) -> Vec<Result<(), Reply>> {
        let mut answers = Vec::with_capacity(group.len());
        for address in &group {
            if self.tx.as_ref().is_none_or(|tx| tx.token.is_some()) {
                answers.push(Err(reply::TOO_MANY_RECIPIENTS));
                continue;
            }
            let answer = self.reports.check(self.node, address).await;
            answers.push(match (answer, self.tx.as_mut()) {
                (Ok(token), Some(tx)) => {
                    tx.token = Some(token);
                    Ok(())
                }
                (Ok(_), None) => Err(reply::SEQUENCE),
                (Err(reply), _) => Err(reply),
            });
        }
        answers
    }

    fn data(&mut self) -> Result<(), Reply> {
        let tx = self.tx.as_mut().ok_or(reply::SEQUENCE)?;
        if tx.token.is_none() {
            return Err(reply::NO_RECIPIENTS);
        }
        let hold = self.guard.reserve(HOLD).ok_or(BUSY)?;
        tx.body = Vec::with_capacity(KEEP);
        tx.hold = Some(hold);
        Ok(())
    }

    async fn finish(&mut self) -> Reply {
        let Some(tx) = self.tx.take() else {
            return reply::TEMPORARY;
        };
        let Some(hold) = tx.hold else {
            return reply::TEMPORARY;
        };
        self.reports.held.set(self.reports.held.get() + 1);
        let Some((token, generation)) = tx.token else {
            return reply::TEMPORARY;
        };
        let report = smtp::report::parse(&tx.body);
        let ids = match self.reports.ids(self.node).await {
            Ok(ids) => ids,
            Err(reply) => return reply,
        };
        let Some(raw) = ids.reveal(&token.id) else {
            return reply::TEMPORARY;
        };
        let id = MessageId::from_bytes(raw);
        let Some(inbound) = crate::inbound::inbound(&token, id, generation, report) else {
            return reply::OK;
        };
        let outcome = self.node.report(inbound).await;
        drop(hold);
        let count = match outcome {
            Ok(ReportOutcome::Unmatched) => Some(&self.reports.unmatched),
            Err(Refusal::Tenant) => Some(&self.reports.gone),
            _ => None,
        };
        if let Some(count) = count {
            count.set(count.get() + 1);
        }
        match outcome {
            Ok(ReportOutcome::Written(_) | ReportOutcome::Duplicate | ReportOutcome::Unmatched)
            | Err(Refusal::Tenant) => reply::OK,
            Err(refusal) if refusal.temporary() => reply::TEMPORARY,
            Err(_) => PERMANENT,
        }
    }
}
