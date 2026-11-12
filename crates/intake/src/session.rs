use std::time::Duration;

use control::{Grant, Scope};
use crypto::{DkimAlg, Ids, Sealer, TAG};
use dkim::BodyHash;
use rt::{Instant, now, timeout};
use sched::{Draft, Node, Refusal, Sealing, Transport, domain_of};
use smtp::{BodyType, Event, Reply, Server, reply};
use spool::{Body, BodyWriter, HeadClear, Message, SLICE};
use tls::Acceptor;

use crate::assemble::{Signer, Stamp, assemble};
use crate::conn::Conn;
use crate::envelope::{Envelope, Recipient, encode_slice};
use crate::header::{Checked, Fault, HEADER_CAP, HeaderBuffer, check};

const SENDER_DOMAIN: Reply = Reply::new(550, "5.7.1", "Sender domain not verified");
const FROM_DOMAIN: Reply = Reply::new(550, "5.7.1", "From domain not verified");
const NO_KEY: Reply = Reply::new(550, "5.7.1", "No signing key for the From domain");
const TENANT: Reply = Reply::new(554, "5.7.1", "Account not active");
const POOL: Reply = Reply::new(550, "5.7.1", "Pool not allowed");
const SUPPRESSED: Reply = Reply::new(550, "5.7.1", "Recipient suppressed");
const HEADER: Reply = Reply::new(554, "5.6.0", "Message header not accepted");
const LOOP: Reply = Reply::new(554, "5.4.6", "Too many Received fields");

#[derive(Clone, Debug)]
pub struct Config {
    pub name: String,
    pub lifetime: u64,
    pub handshake: Duration,
    pub auth: Duration,
    pub idle: Duration,
    pub data: Duration,
    pub session: Duration,
}

impl Config {
    pub fn new(name: String) -> Self {
        Self {
            name,
            lifetime: 5 * 86_400_000,
            handshake: Duration::from_secs(10),
            auth: Duration::from_secs(60),
            idle: Duration::from_secs(300),
            data: Duration::from_secs(180),
            session: Duration::from_secs(3600),
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
}

pub fn message_limit<T: Transport + 'static>(node: &Node<T>) -> u64 {
    let spool = node.spool();
    let plain = (spool.stream_chunk() - TAG) as u64;
    HEADER_CAP as u64 + spool.stream_records() * plain
}

pub async fn serve<T: Transport + 'static>(
    node: &Node<T>,
    acceptor: &Acceptor,
    conn: Conn,
    config: &Config,
    shard: usize,
) -> End {
    let server = Server::new(smtp::Config {
        name: config.name.clone(),
        message: message_limit(node),
        implicit: conn.secure(),
    });
    let mut session = Session {
        node,
        acceptor,
        config,
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
    sealing: Sealing,
    id: String,
    header: HeaderBuffer,
    ready: Option<Ready>,
    hash: BodyHash,
    eight_bit: bool,
    size: u64,
    pending: Vec<u8>,
    stream: Option<(Sealer, BodyWriter)>,
    refused: Option<Reply>,
}

struct Ready {
    checked: Checked,
    keys: Vec<Key>,
}

struct Key {
    id: u32,
    alg: DkimAlg,
    domain: String,
    selector: String,
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
                self.grant = self.node.table().check(secret.expose(), Scope::Smtp);
                let answer = if self.grant.is_some() {
                    Ok(())
                } else {
                    Err(reply::AUTH_FAILED)
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
        let shards = self.node.spool().shards();
        let shard = *shards
            .get(self.shard % shards.len().max(1))
            .ok_or(reply::TEMPORARY)?;
        self.shard = self.shard.wrapping_add(1);
        let sealing = self
            .node
            .sealing(&mut tx.draft, shard)
            .await
            .map_err(refusal)?;
        let ids = self.node.ids().ok_or(reply::TEMPORARY)?;
        let ids = Ids::new(&ids).map_err(|_| reply::TEMPORARY)?;
        tx.data = Some(Data {
            id: ids.encode(&sealing.id().bytes()),
            sealing,
            header: HeaderBuffer::default(),
            ready: None,
            hash: BodyHash::new(),
            eight_bit: false,
            size: 0,
            pending: Vec::new(),
            stream: None,
            refused: None,
        });
        Ok(())
    }

    fn refuse(&mut self, reply: Reply) {
        if let Some(data) = self.tx.as_mut().and_then(|tx| tx.data.as_mut()) {
            data.stream = None;
            data.pending = Vec::new();
            data.refused = Some(reply.clone());
        }
        self.server.refuse(reply);
    }

    async fn body(&mut self, bytes: &[u8]) -> Result<(), Reply> {
        let grant = self.grant.ok_or(reply::SEQUENCE)?;
        let node = self.node;
        let Some(data) = self.tx.as_mut().and_then(|tx| tx.data.as_mut()) else {
            return Ok(());
        };
        if data.refused.is_some() {
            return Ok(());
        }
        let rest = data.header.push(bytes).map_err(fault)?;
        if data.header.done() && data.ready.is_none() {
            data.ready = Some(ready(node, grant, data.header.section())?);
        }
        if rest.is_empty() {
            return Ok(());
        }
        data.eight_bit |= rest.iter().any(|&b| b >= 0x80);
        data.hash.update(rest);
        data.size += rest.len() as u64;
        data.pending.extend_from_slice(rest);
        let spool = node.spool();
        let inline = spool.limits().inline.saturating_sub(TAG);
        if data.stream.is_none() && data.pending.len() > inline {
            let sealer = data.sealing.body_chunks().map_err(refusal)?;
            let writer = spool.body_stream(data.sealing.id(), grant.tenant);
            data.stream = Some((sealer, writer));
        }
        let plain = spool.stream_chunk() - TAG;
        if let Some((sealer, writer)) = data.stream.as_mut() {
            while data.pending.len() > plain {
                let mut chunk: Vec<u8> = data.pending.drain(..plain).collect();
                sealer.seal(&mut chunk).map_err(|_| reply::TEMPORARY)?;
                writer.push(&chunk).await.map_err(|e| spool_error(&e))?;
            }
        }
        Ok(())
    }

    async fn finish(&mut self) -> Result<Reply, Reply> {
        let grant = self.grant.ok_or(reply::TEMPORARY)?;
        let node = self.node;
        let mut tx = self.tx.take().ok_or(reply::TEMPORARY)?;
        let mut data = tx.data.take().ok_or(reply::TEMPORARY)?;
        if let Some(reply) = data.refused {
            return Err(reply);
        }
        let ready = match data.ready.take() {
            Some(ready) => ready,
            None => ready(node, grant, data.header.section())?,
        };
        let body = match data.stream.take() {
            None => data.sealing.inline_body(&data.pending).map_err(refusal)?,
            Some((sealer, mut writer)) => {
                let mut last = std::mem::take(&mut data.pending);
                sealer.seal_last(&mut last);
                writer.push(&last).await.map_err(|e| spool_error(&e))?;
                Body::Chain(writer.finish().map_err(|e| spool_error(&e))?)
            }
        };
        let accepted = node.sched().clock().now();
        let signers: Vec<Signer> = ready
            .keys
            .iter()
            .map(|key| Signer {
                key: key.id,
                alg: key.alg,
                domain: &key.domain,
                selector: &key.selector,
            })
            .collect();
        let stamp = Stamp {
            node: &self.config.name,
            id: &data.id,
            now: accepted,
            lifetime: self.config.lifetime,
        };
        let section = assemble(
            data.header.section(),
            &ready.checked,
            &stamp,
            &signers,
            &data.hash.finish(),
        )
        .map_err(fault)?;
        let envelope = Envelope {
            sender: tx.sender,
            eight_bit: data.eight_bit,
            declared: tx.declared,
            signatures: ready.keys.iter().map(|key| (key.id, key.alg)).collect(),
            ..Envelope::default()
        }
        .encode()
        .ok_or(reply::TEMPORARY)?;
        let count = u32::try_from(tx.recipients.len()).map_err(|_| reply::TEMPORARY)?;
        let clear = HeadClear {
            recipients: count,
            body_size: data.size,
            accepted,
            ..HeadClear::default()
        };
        let head = data
            .sealing
            .head(clear, accepted + self.config.lifetime, &envelope, &section)
            .map_err(refusal)?;
        let mut slices = Vec::new();
        let groups = tx.draft.queues().chunks(SLICE as usize);
        for (n, (queues, addresses)) in
            (0u32..).zip(groups.zip(tx.recipients.chunks(SLICE as usize)))
        {
            let recipients: Vec<Recipient> = addresses
                .iter()
                .map(|address| Recipient {
                    address: address.clone(),
                    ..Recipient::default()
                })
                .collect();
            let plain = encode_slice(&recipients).ok_or(reply::TEMPORARY)?;
            slices.push(
                data.sealing
                    .slice(n, queues.to_vec(), &plain)
                    .map_err(refusal)?,
            );
        }
        let message = Message {
            id: data.sealing.id(),
            tenant: tx.draft.tenant(),
            head,
            body,
            slices,
        };
        node.accept(tx.draft, message).await.map_err(refusal)?;
        Ok(Reply::owned(250, "2.0.0", data.id))
    }
}

fn ready<T: Transport + 'static>(
    node: &Node<T>,
    grant: Grant,
    section: &[u8],
) -> Result<Ready, Reply> {
    let checked = check(section).map_err(fault)?;
    let table = node.table();
    let domain = table
        .sender(grant.tenant, &checked.from)
        .ok_or(FROM_DOMAIN)?;
    let keys: Vec<Key> = [domain.rsa, domain.ed25519]
        .into_iter()
        .filter(|&id| id != 0)
        .filter_map(|id| table.dkim(grant.tenant, id))
        .filter(|dkim| dkim.generation == grant.generation)
        .map(|dkim| Key {
            id: dkim.id,
            alg: dkim.alg,
            domain: dkim.domain.to_string(),
            selector: dkim.selector.to_string(),
        })
        .collect();
    if keys.is_empty() {
        return Err(NO_KEY);
    }
    Ok(Ready { checked, keys })
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

fn spool_error(error: &spool::Error) -> Reply {
    match error {
        spool::Error::Limit("body" | "chunk" | "inline body") => reply::TOO_BIG,
        _ => reply::TEMPORARY,
    }
}
