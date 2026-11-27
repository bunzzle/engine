use std::net::IpAddr;
use std::time::Duration;

use control::{Grant, Scope};
use crypto::TAG;
use rt::{Instant, now, timeout};
use sched::{Draft, Envelope, Node, Refusal, Transport, domain_of};
use smtp::{BodyType, Event, Reply, Server, reply};
use tls::Acceptor;

use crate::conn::Conn;
use crate::guard::{Guard, Refused, Reserved, Slot};
use crate::header::{Fault, HEADER_CAP};
use crate::submit::{Failure, Origin, Submission};

const SENDER_DOMAIN: Reply = Reply::new(550, "5.7.1", "Sender domain not verified");
const FROM_DOMAIN: Reply = Reply::new(550, "5.7.1", "From domain not verified");
const NO_KEY: Reply = Reply::new(550, "5.7.1", "No signing key for the From domain");
const TENANT: Reply = Reply::new(554, "5.7.1", "Account not active");
const POOL: Reply = Reply::new(550, "5.7.1", "Pool not allowed");
const SUPPRESSED: Reply = Reply::new(550, "5.7.1", "Recipient suppressed");
const HEADER: Reply = Reply::new(554, "5.6.0", "Message header not accepted");
const LOOP: Reply = Reply::new(554, "5.4.6", "Too many Received fields");
const TENANT_FULL: Reply = Reply::new(421, "4.7.0", "Too many connections");
const BUSY: Reply = Reply::new(451, "4.3.2", "System busy");

#[derive(Clone, Debug)]
pub struct Config {
    pub name: String,
    pub lifetime: u64,
    pub messages: u32,
    pub handshake: Duration,
    pub auth: Duration,
    pub idle: Duration,
    pub data: Duration,
    pub session: Duration,
    pub drain: Duration,
}

impl Config {
    pub fn new(name: String) -> Self {
        Self {
            name,
            lifetime: 5 * 86_400_000,
            messages: 1000,
            handshake: Duration::from_secs(10),
            auth: Duration::from_secs(60),
            idle: Duration::from_secs(300),
            data: Duration::from_secs(180),
            session: Duration::from_secs(3600),
            drain: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Done,
    Dropped,
    Timeout,
    Io,
    Tls,
    Refused,
    Closed,
}

pub fn message_limit<T: Transport + 'static>(node: &Node<T>) -> u64 {
    let spool = node.spool();
    let plain = (spool.stream_chunk() - TAG) as u64;
    HEADER_CAP as u64 + spool.stream_records() * plain
}

pub fn data_hold<T: Transport + 'static>(node: &Node<T>) -> usize {
    let spool = node.spool();
    HEADER_CAP + 2 * smtp::CHUNK + 2 * spool.stream_chunk().max(spool.limits().inline)
}

pub async fn serve<T: Transport + 'static>(
    node: &Node<T>,
    acceptor: &Acceptor,
    conn: Conn,
    config: &Config,
    guard: &Guard,
    (ip, net): (IpAddr, Slot),
    shard: usize,
) -> End {
    let server = Server::new(smtp::Config {
        name: config.name.clone(),
        message: message_limit(node),
        implicit: conn.secure(),
        messages: config.messages,
        mx: false,
    });
    let mut session = Session {
        node,
        acceptor,
        config,
        guard,
        ip,
        net: Some(net),
        tenant: None,
        hold: data_hold(node),
        conn: Some(conn),
        server,
        grant: None,
        tx: None,
        shard,
        start: now(),
        last: now(),
    };
    let end = session.run().await;
    if let Some(conn) = session.conn.as_mut() {
        conn.shutdown().await;
    }
    end
}

struct Session<'a, T> {
    node: &'a Node<T>,
    acceptor: &'a Acceptor,
    config: &'a Config,
    guard: &'a Guard,
    ip: IpAddr,
    net: Option<Slot>,
    tenant: Option<Slot>,
    hold: usize,
    conn: Option<Conn>,
    server: Server,
    grant: Option<Grant>,
    tx: Option<Tx>,
    shard: usize,
    start: Instant,
    last: Instant,
}

struct Tx {
    draft: Draft,
    sender: String,
    declared: bool,
    recipients: Vec<String>,
    data: Option<Data>,
}

struct Data {
    submission: Submission,
    refused: Option<Reply>,
    _hold: Reserved,
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
        let inside = self.tx.as_ref().is_some_and(|tx| tx.data.is_some());
        let idle = if inside {
            self.config.data
        } else {
            self.config.idle
        };
        let mut deadline = (self.last + idle).min(self.start + self.config.session);
        if !self.server.authenticated() {
            deadline = deadline.min(self.start + self.config.auth);
        }
        deadline
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

    async fn event(&mut self, event: Event) -> Result<(), End> {
        match event {
            Event::Starttls => self.starttls().await?,
            Event::Auth(secret) => {
                self.flush().await?;
                let grant = self.node.table().check(secret.expose(), Scope::Smtp);
                let answer = match grant {
                    Some(grant) => self.admit(grant).await,
                    None => Err(self.failed().await),
                };
                self.server.auth(answer);
            }
            Event::Mail { from, body, .. } => {
                let answer = self.mail(from, body == Some(BodyType::EightBit));
                self.server.mail(answer);
            }
            Event::Recipients(group) => {
                self.flush().await?;
                let answers = self.recipients(group).await;
                self.server.recipients(answers);
            }
            Event::Data => {
                self.flush().await?;
                let answer = self.data().await;
                self.server.data(answer);
            }
            Event::Body(bytes) => {
                if let Err(reply) = self.body(&bytes).await {
                    self.refuse(reply);
                }
            }
            Event::End { .. } => {
                let reply = match self.finish().await {
                    Ok(reply) | Err(reply) => reply,
                };
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

    async fn admit(&mut self, grant: Grant) -> Result<(), Reply> {
        let limit = self
            .node
            .table()
            .tenant(grant.tenant)
            .map_or(0, |tenant| tenant.limits.connections);
        if limit > 0 {
            let slot =
                self.guard.open_tenant(grant.tenant, limit).await.map_err(
                    |refused| match refused {
                        Refused::Unanswered => reply::AUTH_TEMPORARY,
                        Refused::Full | Refused::Banned => TENANT_FULL,
                    },
                )?;
            self.tenant = Some(slot);
        }
        self.grant = Some(grant);
        self.net = None;
        Ok(())
    }

    async fn failed(&mut self) -> Reply {
        match self.guard.failed(self.ip).await {
            Ok(false) => reply::AUTH_FAILED,
            Ok(true) => reply::AUTH_FAILURES,
            Err(_) => reply::AUTH_TEMPORARY,
        }
    }

    fn mail(&mut self, from: String, declared: bool) -> Result<(), Reply> {
        let grant = self.grant.ok_or(reply::AUTH_FIRST)?;
        let domain = domain_of(&from).ok_or(reply::SENDER_SYNTAX)?;
        if self.node.table().sender(grant.tenant, &domain).is_none() {
            return Err(SENDER_DOMAIN);
        }
        let draft = self
            .node
            .draft(grant.tenant, Some(grant.pool))
            .map_err(refusal)?;
        if draft.generation() != grant.generation {
            return Err(TENANT);
        }
        self.tx = Some(Tx {
            draft,
            sender: from,
            declared,
            recipients: Vec::new(),
            data: None,
        });
        Ok(())
    }

    async fn recipients(&mut self, group: Vec<String>) -> Vec<Result<(), Reply>> {
        let Some(tx) = self.tx.as_mut() else {
            return vec![Err(reply::SEQUENCE); group.len()];
        };
        let addresses: Vec<&str> = group.iter().map(String::as_str).collect();
        let results = self.node.recipients(&mut tx.draft, &addresses).await;
        let mut answers = Vec::with_capacity(group.len());
        for (address, result) in group.iter().zip(results) {
            answers.push(match result {
                Ok(_) => {
                    tx.recipients.push(address.clone());
                    Ok(())
                }
                Err(Refusal::Address) => Err(reply::RECIPIENT_SYNTAX),
                Err(Refusal::Suppressed) => Err(SUPPRESSED),
                Err(Refusal::Recipients) => Err(reply::TOO_MANY_RECIPIENTS),
                Err(other) => Err(refusal(other)),
            });
        }
        answers
    }

    async fn data(&mut self) -> Result<(), Reply> {
        let Some(tx) = self.tx.as_mut() else {
            return Err(reply::SEQUENCE);
        };
        let hold = self.guard.reserve(self.hold).ok_or(BUSY)?;
        let shards = self.node.spool().shards();
        let shard = *shards
            .get(self.shard % shards.len().max(1))
            .ok_or(reply::TEMPORARY)?;
        self.shard = self.shard.wrapping_add(1);
        let submission = Submission::open(self.node, &mut tx.draft, shard)
            .await
            .map_err(failure)?;
        tx.data = Some(Data {
            submission,
            refused: None,
            _hold: hold,
        });
        Ok(())
    }

    fn refuse(&mut self, reply: Reply) {
        if let Some(data) = self.tx.as_mut().and_then(|tx| tx.data.as_mut()) {
            data.submission.discard();
            data.refused = Some(reply.clone());
        }
        self.server.refuse(reply);
    }

    async fn body(&mut self, bytes: &[u8]) -> Result<(), Reply> {
        let grant = self.grant.ok_or(reply::SEQUENCE)?;
        let Some(data) = self.tx.as_mut().and_then(|tx| tx.data.as_mut()) else {
            return Ok(());
        };
        if data.refused.is_some() {
            return Ok(());
        }
        data.submission
            .push(self.node, grant, bytes)
            .await
            .map_err(failure)
    }

    async fn finish(&mut self) -> Result<Reply, Reply> {
        let grant = self.grant.ok_or(reply::TEMPORARY)?;
        let mut tx = self.tx.take().ok_or(reply::TEMPORARY)?;
        let data = tx.data.take().ok_or(reply::TEMPORARY)?;
        if let Some(reply) = data.refused {
            return Err(reply);
        }
        let origin = Origin {
            node: &self.config.name,
            with: "ESMTPSA",
            lifetime: self.config.lifetime,
        };
        let envelope = Envelope {
            sender: tx.sender,
            declared: tx.declared,
            ..Envelope::default()
        };
        let id = data
            .submission
            .finish(
                self.node,
                grant,
                &origin,
                tx.draft,
                envelope,
                &tx.recipients,
            )
            .await
            .map_err(failure)?;
        Ok(Reply::owned(250, "2.0.0", id))
    }
}

fn fault(fault: Fault) -> Reply {
    match fault {
        Fault::TooLarge => reply::TOO_BIG,
        Fault::Loop => LOOP,
        Fault::Signer => reply::TEMPORARY,
        Fault::Malformed | Fault::Hidden | Fault::Repeated | Fault::From => HEADER,
    }
}

fn refusal(refusal: Refusal) -> Reply {
    match refusal {
        Refusal::Tenant => TENANT,
        Refusal::Pool => POOL,
        Refusal::Suppressed => SUPPRESSED,
        Refusal::Recipients => reply::TOO_MANY_RECIPIENTS,
        Refusal::Address => reply::RECIPIENT_SYNTAX,
        _ => reply::TEMPORARY,
    }
}

fn failure(failure: Failure) -> Reply {
    match failure {
        Failure::Header(f) => fault(f),
        Failure::FromDomain => FROM_DOMAIN,
        Failure::NoKey => NO_KEY,
        Failure::Refused(r) => refusal(r),
        Failure::TooBig => reply::TOO_BIG,
        Failure::Temporary => reply::TEMPORARY,
    }
}
