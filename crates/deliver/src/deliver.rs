use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use control::Leases;
use dns::Name;
use rt::{Instant, now, timeout};
use sched::{
    Answer, Answered, Attempt, Body, Destination, Envelope, Kind, Recipient, Ret, Transport,
};
use smtp::client::{
    self, Answer as Reply, Capabilities, Dots, Mail, Rcpt, Refused, Response, Step, Transaction,
};
use tls::Connector;

use crate::classify;
use crate::conn::{Conn, Lost, left};
use crate::mx::{self, Addresses, Dns, Hosts};
use crate::pool::{Key, Link, Pool, Remote, Slot};
use crate::settings::{EightBit, Settings};

const ADDRESSES: usize = 10;
const CHUNK: usize = 64 * 1024;
const DEAD_MOST: usize = 10_000;
const TEMPORARY: Answer = Answer::Deferred(Kind::Temporary);

const NO_EGRESS: &[u8] = b"451 4.3.0 No egress address";
const BAD_DOMAIN: &[u8] = b"550 5.1.2 Recipient domain is not valid";
const NO_DOMAIN: &[u8] = b"550 5.1.2 Recipient domain does not exist";
const NULL_MX: &[u8] = b"556 5.1.10 Recipient domain does not accept mail";
const MX_FAILED: &[u8] = b"451 4.4.3 MX lookup failed";
const HOST_FAILED: &[u8] = b"451 4.4.3 Mail server address lookup failed";
const NO_HOST: &[u8] = b"451 4.4.4 No mail server address";
const DEAD: &[u8] = b"451 4.4.1 Mail server recently unreachable";
const BUSY: &[u8] = b"451 4.4.5 Connection limit reached";
const REQUIRETLS: &[u8] = b"550 5.7.30 REQUIRETLS not possible";
const SMTPUTF8: &[u8] = b"553 5.6.7 Receiving server does not support SMTPUTF8";
const EIGHT_BIT: &[u8] = b"554 5.6.3 Receiving server does not support 8BITMIME";
const TOO_BIG: &[u8] = b"552 5.3.4 Message too big for the receiving server";
const UNSAFE: &[u8] = b"550 5.1.3 Address cannot be sent";

pub struct Message<'a> {
    pub envelope: &'a Envelope,
    pub recipients: &'a [(u32, Recipient)],
    pub header: &'a [u8],
    pub body: &'a mut Body,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub recipient: u32,
    pub answer: Answer,
    pub reply: Vec<u8>,
}

pub struct Deliver<D> {
    dns: D,
    tls: Connector,
    settings: Settings,
    leases: Option<Leases<Remote>>,
    pool: Pool,
    dead: RefCell<BTreeMap<(IpAddr, IpAddr), Instant>>,
    ehlo: Vec<u8>,
    helo: Vec<u8>,
    random: Cell<u64>,
    turn: Cell<u64>,
}

enum Tried {
    Next(Vec<u8>),
    Busy,
    Done(Vec<Outcome>),
}

impl<D: Dns> Deliver<D> {
    pub fn new(
        dns: D,
        tls: Connector,
        settings: Settings,
        leases: Option<Leases<Remote>>,
        seed: u64,
    ) -> Result<Self, Refused> {
        let ehlo = client::ehlo(&settings.ehlo)?;
        let helo = client::helo(&settings.ehlo)?;
        let pool = Pool::new(settings.idle, settings.pooled);
        Ok(Self {
            dns,
            tls,
            settings,
            leases,
            pool,
            dead: RefCell::new(BTreeMap::new()),
            ehlo,
            helo,
            random: Cell::new(seed | 1),
            turn: Cell::new(0),
        })
    }

    pub fn pooled(&self) -> usize {
        self.pool.len()
    }

    pub fn dead_hosts(&self) -> usize {
        self.dead.borrow().len()
    }

    pub async fn deliver(
        &self,
        destination: &Destination,
        mut message: Message<'_>,
    ) -> Vec<Outcome> {
        let deadline = self.settings.deadline;
        let end = now() + deadline;
        let recipients = message.recipients;
        let every = |answer, reply: &[u8]| all(recipients, answer, reply);
        let egress = self
            .pool
            .egress(&destination.domain, &destination.egress)
            .or_else(|| self.egress(&destination.egress));
        let Some(egress) = egress else {
            return every(TEMPORARY, NO_EGRESS);
        };
        if message.envelope.required.requiretls {
            return every(Answer::Failed, REQUIRETLS);
        }
        let Ok(domain) = Name::parse(&destination.domain) else {
            return every(Answer::Failed, BAD_DOMAIN);
        };
        let mut pick = |n| self.pick(n);
        let hosts = match timeout(deadline, mx::hosts(&self.dns, &domain, &mut pick)).await {
            Ok(Hosts::Found(hosts)) => hosts,
            Ok(Hosts::NullMx) => return every(Answer::Failed, NULL_MX),
            Ok(Hosts::NoDomain) => return every(Answer::Failed, NO_DOMAIN),
            Ok(Hosts::Failed) => return every(TEMPORARY, MX_FAILED),
            Err(_) => return every(TEMPORARY, Lost::Timeout.text()),
        };
        let remote: Remote = (egress, destination.domain.clone());
        let mut slot = None;
        let mut last = NO_HOST.to_vec();
        let mut tried = 0;
        'hosts: for host in &hosts {
            let lookup = mx::addresses(&self.dns, host, egress.is_ipv6());
            let found = match timeout(left(end, deadline), lookup).await {
                Ok(Addresses::Found(found)) => found,
                Ok(Addresses::Failed) => {
                    if tried == 0 {
                        last = HOST_FAILED.to_vec();
                    }
                    continue;
                }
                Err(_) => break,
            };
            for ip in found {
                if tried == ADDRESSES || now() >= end {
                    break 'hosts;
                }
                tried += 1;
                let key = Key {
                    egress,
                    domain: destination.domain.clone(),
                    host: host.clone(),
                    remote: ip,
                };
                match self
                    .session(end, &key, &remote, &mut slot, &mut message)
                    .await
                {
                    Tried::Done(outcomes) => return outcomes,
                    Tried::Busy => {
                        let wait = u64::try_from(self.settings.wait.as_millis()).unwrap_or(0);
                        return every(Answer::Later(wait), BUSY);
                    }
                    Tried::Next(reply) => last = reply,
                }
            }
        }
        if now() >= end {
            last = Lost::Timeout.text().to_vec();
        }
        every(TEMPORARY, &last)
    }

    async fn session(
        &self,
        end: Instant,
        key: &Key,
        remote: &Remote,
        slot: &mut Option<Slot>,
        message: &mut Message<'_>,
    ) -> Tried {
        let mut link = if let Some(link) = self.reuse(key, end).await {
            drop(slot.take());
            link
        } else {
            if self.is_dead(key.egress, key.remote) {
                return Tried::Next(DEAD.to_vec());
            }
            if slot.is_none() {
                match self.slot(remote, end).await {
                    Ok(taken) => *slot = taken,
                    Err(()) => return Tried::Busy,
                }
            }
            match self.open(end, key).await {
                Ok((conn, caps)) => Link {
                    conn,
                    caps,
                    used: 0,
                    _slot: slot.take(),
                },
                Err(reply) => return Tried::Next(reply),
            }
        };
        let caps = link.caps;
        let envelope = message.envelope;
        let refusal = if envelope.required.smtputf8 && !caps.smtputf8 {
            Some(SMTPUTF8)
        } else if envelope.eight_bit && !caps.eight_bit && self.settings.eight_bit == EightBit::Fail
        {
            Some(EIGHT_BIT)
        } else if caps.size.is_some_and(|max| max > 0 && message.size > max) {
            Some(TOO_BIG)
        } else {
            None
        };
        let transaction = match refusal {
            Some(text) => Err(text),
            None => Transaction::new(&caps, &mail(envelope, message.size), &rcpts(message))
                .map_err(|_| UNSAFE),
        };
        let mut transaction = match transaction {
            Ok(transaction) => transaction,
            Err(text) => {
                self.pool.park(key.clone(), link).await;
                return Tried::Done(all(message.recipients, Answer::Failed, text));
            }
        };
        let run = self
            .transact(&mut link.conn, &mut transaction, message)
            .await;
        let finished = run.is_ok();
        let answers = transaction.answers();
        let delivered = finished && answers.iter().any(|a| a == &Some(Reply::Accepted));
        let mut closing = false;
        let (done, lost) = match &run {
            Ok(last) => {
                closing = last.as_ref().is_some_and(|r| r.code == 421);
                (last.as_ref().map(Response::text), Lost::Closed)
            }
            Err(lost) => (None, *lost),
        };
        let outcomes = message
            .recipients
            .iter()
            .zip(answers)
            .map(|((recipient, _), answer)| {
                let (answer, reply) = match answer {
                    Some(Reply::Accepted) if finished => (
                        Answer::Delivered,
                        done.clone().unwrap_or_default().into_bytes(),
                    ),
                    Some(Reply::Refused(r)) => {
                        closing |= r.code == 421;
                        (classify::answer(&r), r.text().into_bytes())
                    }
                    Some(Reply::Again(r)) if delivered => (Answer::Later(0), r.text().into_bytes()),
                    Some(Reply::Again(r)) => (TEMPORARY, r.text().into_bytes()),
                    _ => (TEMPORARY, lost.text().to_vec()),
                };
                Outcome {
                    recipient: *recipient,
                    answer,
                    reply,
                }
            })
            .collect();
        link.used += 1;
        if finished && transaction.reusable() && !closing && link.used < self.settings.reuse {
            self.pool.park(key.clone(), link).await;
        } else if finished && !closing {
            link.conn.quit().await;
        }
        Tried::Done(outcomes)
    }

    async fn reuse(&self, key: &Key, end: Instant) -> Option<Link> {
        loop {
            let mut link = self.pool.take(key)?;
            link.conn.renew(end);
            let rset = command(&mut link.conn, client::RSET, self.settings.timeouts.rset).await;
            if rset.is_ok_and(|r| r.code / 100 == 2) {
                return Some(link);
            }
        }
    }

    async fn slot(&self, remote: &Remote, end: Instant) -> Result<Option<Slot>, ()> {
        let Some(leases) = &self.leases else {
            return Ok(None);
        };
        match leases
            .take_within(remote, left(end, self.settings.wait))
            .await
        {
            Ok(taken) if taken.slot => Ok(Some(Slot::new(leases.clone(), remote.clone()))),
            Ok(_) | Err(control::Error::Invalid(_)) => Ok(None),
            Err(_) => Err(()),
        }
    }

    async fn open(&self, end: Instant, key: &Key) -> Result<(Conn, Capabilities), Vec<u8>> {
        let t = &self.settings.timeouts;
        let to = SocketAddr::new(key.remote, self.settings.port);
        let mut conn = match Conn::open(key.egress, to, end, t.connect).await {
            Ok(conn) => conn,
            Err(lost) => {
                self.mark_dead(key.egress, key.remote);
                return Err(lost.text().to_vec());
            }
        };
        match conn.response(t.banner).await {
            Ok(banner) if banner.code == 220 => {}
            failed => return Err(next(conn, failed).await),
        }
        let mut caps = match self.hello(&mut conn).await {
            Ok(caps) => caps,
            Err(failed) => return Err(next(conn, failed).await),
        };
        if caps.starttls {
            match command(&mut conn, client::STARTTLS, t.starttls).await {
                Ok(reply) if reply.code == 220 => {
                    conn = conn
                        .starttls(&self.tls, &key.host.to_string(), t.starttls)
                        .await
                        .map_err(|lost| lost.text().to_vec())?;
                    caps = match self.hello(&mut conn).await {
                        Ok(caps) => caps,
                        Err(failed) => return Err(next(conn, failed).await),
                    };
                }
                Ok(_) => {}
                Err(lost) => return Err(lost.text().to_vec()),
            }
        }
        Ok((conn, caps))
    }

    fn is_dead(&self, egress: IpAddr, remote: IpAddr) -> bool {
        let mut dead = self.dead.borrow_mut();
        match dead.get(&(egress, remote)) {
            Some(until) if *until > now() => true,
            Some(_) => {
                dead.remove(&(egress, remote));
                false
            }
            None => false,
        }
    }

    fn mark_dead(&self, egress: IpAddr, remote: IpAddr) {
        let now = now();
        let mut dead = self.dead.borrow_mut();
        if dead.len() >= DEAD_MOST {
            dead.retain(|_, until| *until > now);
        }
        if dead.len() < DEAD_MOST {
            dead.insert((egress, remote), now + self.settings.dead);
        }
    }

    async fn hello(&self, conn: &mut Conn) -> Result<Capabilities, Result<Response, Lost>> {
        let limit = self.settings.timeouts.ehlo;
        let reply = command(conn, &self.ehlo, limit).await.map_err(Err)?;
        if reply.code / 100 == 2 {
            return Ok(Capabilities::parse(&reply));
        }
        if !matches!(reply.code, 500 | 501 | 502 | 504) {
            return Err(Ok(reply));
        }
        let reply = command(conn, &self.helo, limit).await.map_err(Err)?;
        if reply.code / 100 == 2 {
            Ok(Capabilities::default())
        } else {
            Err(Ok(reply))
        }
    }

    async fn transact(
        &self,
        conn: &mut Conn,
        transaction: &mut Transaction,
        message: &mut Message<'_>,
    ) -> Result<Option<Response>, Lost> {
        let t = &self.settings.timeouts;
        let mut step = Step::Send(transaction.start());
        let mut sent = false;
        let mut last = None;
        loop {
            step = match step {
                Step::Send(bytes) => {
                    conn.write(&bytes, t.command).await?;
                    Step::Wait
                }
                Step::Wait => {
                    let limit = if sent { t.final_reply } else { t.command };
                    let reply = conn.response(limit).await?;
                    let next = transaction.reply(&reply);
                    last = Some(reply);
                    next
                }
                Step::Body => {
                    body(conn, message, t.body).await?;
                    sent = true;
                    Step::Wait
                }
                Step::Done => return Ok(last),
            };
        }
    }

    fn egress(&self, egress: &[(IpAddr, u16)]) -> Option<IpAddr> {
        let total: u64 = egress.iter().map(|(_, weight)| u64::from(*weight)).sum();
        if total == 0 {
            return None;
        }
        let turn = self.turn.get();
        self.turn.set(turn.wrapping_add(1));
        let mut at = turn % total;
        egress.iter().find_map(|(ip, weight)| {
            let weight = u64::from(*weight);
            if at < weight {
                return Some(*ip);
            }
            at -= weight;
            None
        })
    }

    fn pick(&self, n: usize) -> usize {
        let mut x = self.random.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.random.set(x);
        usize::try_from(x >> 32).unwrap_or(0) % n
    }
}

impl<D: Dns> Transport for Deliver<D> {
    async fn send(&self, attempt: Attempt) -> Vec<Answered> {
        let Attempt {
            destination,
            recipients: claimed,
            outgoing,
            ..
        } = attempt;
        let body_size = outgoing.stored.clear.body_size;
        let mut prepared = match outgoing.prepare().await {
            Ok(prepared) => prepared,
            Err(fault) => return fault.answers(&claimed),
        };
        let mut body = mem::replace(&mut prepared.body, Body::Inline(Vec::new()));
        let header = prepared.header();
        let size = u64::try_from(header.len())
            .unwrap_or(u64::MAX)
            .saturating_add(2)
            .saturating_add(body_size);
        let message = Message {
            envelope: &prepared.envelope,
            recipients: &prepared.recipients,
            header,
            body: &mut body,
            size,
        };
        let outcomes = self.deliver(&destination, message).await;
        claimed
            .iter()
            .map(|c| {
                let outcome = outcomes.iter().find(|o| o.recipient == c.recipient);
                let (answer, reply) = outcome.map_or((TEMPORARY, Lost::Closed.text()), |o| {
                    (o.answer, o.reply.as_slice())
                });
                Answered {
                    recipient: c.recipient,
                    answer,
                    reply: prepared
                        .opener
                        .seal_reply(c.recipient, c.stamp, reply)
                        .unwrap_or_default(),
                }
            })
            .collect()
    }
}

fn all(recipients: &[(u32, Recipient)], answer: Answer, reply: &[u8]) -> Vec<Outcome> {
    recipients
        .iter()
        .map(|(recipient, _)| Outcome {
            recipient: *recipient,
            answer,
            reply: reply.to_vec(),
        })
        .collect()
}

fn mail(envelope: &Envelope, size: u64) -> Mail {
    Mail {
        sender: envelope.sender.clone(),
        size,
        eight_bit: envelope.eight_bit,
        smtputf8: envelope.required.smtputf8,
        requiretls: envelope.required.requiretls,
        ret: match envelope.ret {
            Ret::None => None,
            Ret::Full => Some(client::Ret::Full),
            Ret::Headers => Some(client::Ret::Headers),
        },
        envid: envelope.envid.clone(),
    }
}

fn rcpts(message: &Message<'_>) -> Vec<Rcpt> {
    message
        .recipients
        .iter()
        .map(|(_, recipient)| Rcpt {
            address: recipient.address.clone(),
            notify: None,
            orcpt: recipient.orcpt.clone(),
        })
        .collect()
}

async fn next(conn: Conn, failed: Result<Response, Lost>) -> Vec<u8> {
    match failed {
        Ok(reply) => {
            conn.quit().await;
            reply.text().into_bytes()
        }
        Err(lost) => lost.text().to_vec(),
    }
}

async fn command(conn: &mut Conn, bytes: &[u8], limit: Duration) -> Result<Response, Lost> {
    conn.write(bytes, limit).await?;
    conn.response(limit).await
}

async fn body(conn: &mut Conn, message: &mut Message<'_>, limit: Duration) -> Result<(), Lost> {
    let mut dots = Dots::default();
    let mut out = Vec::with_capacity(CHUNK + CHUNK / 8);
    dots.encode(message.header, &mut out);
    dots.encode(b"\r\n", &mut out);
    match &mut *message.body {
        Body::Inline(bytes) => {
            for part in bytes.chunks(CHUNK) {
                dots.encode(part, &mut out);
                if out.len() >= CHUNK {
                    conn.write(&out, limit).await?;
                    out.clear();
                }
            }
        }
        Body::Chain(plain) => {
            while let Some(chunk) = plain.next().await.map_err(|_| Lost::Store)? {
                dots.encode(&chunk, &mut out);
                if out.len() >= CHUNK {
                    conn.write(&out, limit).await?;
                    out.clear();
                }
            }
        }
    }
    dots.finish(&mut out);
    conn.write(&out, limit).await
}
