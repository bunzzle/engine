use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use control::{KIND_RPT, KIND_STS, Leases};
use dns::Name;
use rt::{Ends, Instant, JoinHandle, now, timeout};
use sched::{
    Answer, Answered, Attempt, Body, Destination, Envelope, Kind, Recipient, Restore, Ret,
    Transport,
};
use smtp::client::{
    self, Answer as Reply, Capabilities, Dots, Mail, Rcpt, Refused, Response, Step, Transaction,
};
use tls::{Connector, Observed, Refusal, Tlsa, Verify};

use crate::classify;
use crate::conn::{Conn, Lost, left};
use crate::dane::{self, Dane};
use crate::mx::{self, Addresses, Dns, Hosts};
use crate::owners::{OwnerStats, Owners};
use crate::pool::{Key, Level, Link, Pool, Remote, Slot};
use crate::report::{Applied, ResultType};
use crate::results::{Failure, ResultStats, Results, Scope, Taken};
use crate::settings::{EightBit, Settings};
use crate::sts::{Got, Mode, PolicyStats, Sts};

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
const NO_STARTTLS: &[u8] = b"451 4.7.4 Mail server does not offer STARTTLS";
const TLSA_FAILED: &[u8] = b"451 4.4.3 TLSA lookup failed";
const STS_BUSY: &[u8] = b"451 4.4.5 Too many MTA-STS policy fetches";
const STS_NO_MX: &[u8] = b"451 4.4.4 No mail server matches the MTA-STS policy";
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
    sts: Sts,
    results: Results,
    owners: Owners,
    dead: RefCell<BTreeMap<(IpAddr, IpAddr), Instant>>,
    ehlo: Vec<u8>,
    helo: Vec<u8>,
    random: Cell<u64>,
    turn: Cell<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Check {
    Off,
    Observe,
    Enforce,
}

enum Need {
    Any,
    Encrypt,
    Observe,
    Sts,
    Dane {
        names: Vec<String>,
        records: Vec<Tlsa>,
    },
}

impl Need {
    fn scope(&self, target: &Name) -> Option<Scope> {
        let Self::Dane { records, .. } = self else {
            return None;
        };
        let records = records
            .iter()
            .map(|r| {
                let mut line = format!("{} {} {} ", r.usage, r.selector, r.matching);
                for byte in &r.data {
                    let _ = write!(line, "{byte:02x}");
                }
                line
            })
            .collect();
        Some(Scope {
            domain: text(target),
            policy: Applied::Tlsa { records },
        })
    }

    fn level(&self) -> Level {
        match self {
            Self::Any | Self::Observe => Level::Any,
            Self::Encrypt => Level::Encrypt,
            Self::Sts => Level::Sts,
            Self::Dane { .. } => Level::Dane,
        }
    }

    fn verify(&self, host: &Name) -> (String, Verify) {
        match self {
            Self::Any | Self::Encrypt => (host.to_string(), Verify::Any),
            Self::Sts => (host.to_string(), Verify::WebPki),
            Self::Observe => (
                host.to_string(),
                Verify::Observe(Arc::new(Observed::default())),
            ),
            Self::Dane { names, records } => (
                names.first().cloned().unwrap_or_else(|| host.to_string()),
                Verify::Dane {
                    names: names.clone(),
                    records: records.clone(),
                },
            ),
        }
    }
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
            sts: Sts::default(),
            results: Results::default(),
            owners: Owners::default(),
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

    pub fn policies(&self) -> usize {
        self.sts.len()
    }

    pub fn policy_stats(&self) -> PolicyStats {
        self.sts.stats()
    }

    pub fn reports(&mut self, ends: Ends<Taken>) -> JoinHandle<()> {
        self.owners.start(ends)
    }

    pub fn take_results(&self) -> Vec<Taken> {
        self.results.take()
    }

    pub fn owned_reports(&self) -> Vec<Taken> {
        self.owners.owned()
    }

    pub fn owner_stats(&self) -> OwnerStats {
        self.owners.stats()
    }

    pub fn result_stats(&self) -> ResultStats {
        self.results.stats()
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
        let requiretls = message.envelope.required.requiretls;
        let Ok(domain) = Name::parse(&destination.domain) else {
            return every(Answer::Failed, BAD_DOMAIN);
        };
        let mut pick = |n| self.pick(n);
        let (mut hosts, secure) =
            match timeout(deadline, mx::hosts(&self.dns, &domain, &mut pick)).await {
                Ok(Hosts::Found(hosts, secure)) => (hosts, secure),
                Ok(Hosts::NullMx) => return every(Answer::Failed, NULL_MX),
                Ok(Hosts::NoDomain) => return every(Answer::Failed, NO_DOMAIN),
                Ok(Hosts::Failed) => return every(TEMPORARY, MX_FAILED),
                Err(_) => return every(TEMPORARY, Lost::Timeout.text()),
            };
        let (sts, scope) = match self.enforce(egress, &domain, &mut hosts, end).await {
            Ok(enforced) => enforced,
            Err((answer, reply)) => return every(answer, reply),
        };
        if requiretls && !secure && sts != Check::Enforce {
            return every(Answer::Failed, REQUIRETLS);
        }
        let remote: Remote = (egress, destination.domain.clone());
        let mut slot = None;
        let mut last = NO_HOST.to_vec();
        let mut tried = 0;
        let mut others = false;
        'hosts: for host in &hosts {
            let lookup = mx::addresses(&self.dns, host, egress.is_ipv6());
            let (found, target, dnssec) = match timeout(left(end, deadline), lookup).await {
                Ok(Addresses::Found {
                    ips,
                    secure: dnssec,
                    target,
                }) => (ips, target, dnssec),
                Ok(Addresses::Failed) => {
                    if tried == 0 {
                        last = HOST_FAILED.to_vec();
                    }
                    others = true;
                    continue;
                }
                Err(_) => {
                    others = true;
                    break;
                }
            };
            let dane = secure && dnssec && !found.is_empty();
            let Some(need) = self.need(end, (egress, host), &target, dane, sts).await else {
                last = TLSA_FAILED.to_vec();
                others = true;
                continue;
            };
            let scope = need.scope(&target).unwrap_or_else(|| scope.clone());
            if requiretls && matches!(need, Need::Any | Need::Encrypt) {
                last = REQUIRETLS.to_vec();
                continue;
            }
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
                    level: need.level(),
                };
                match self
                    .session(end, &key, (&need, &scope), &remote, &mut slot, &mut message)
                    .await
                {
                    Tried::Done(outcomes) => return outcomes,
                    Tried::Busy => return every(Answer::Later(self.wait()), BUSY),
                    Tried::Next(reply) => {
                        others |= reply != REQUIRETLS;
                        last = reply;
                    }
                }
            }
        }
        if now() >= end {
            last = Lost::Timeout.text().to_vec();
        } else if requiretls && !others && last == REQUIRETLS {
            return every(Answer::Failed, REQUIRETLS);
        }
        every(TEMPORARY, &last)
    }

    async fn enforce(
        &self,
        egress: IpAddr,
        domain: &Name,
        hosts: &mut Vec<Name>,
        end: Instant,
    ) -> Result<(Check, Scope), (Answer, &'static [u8])> {
        let scope = |policy| Scope {
            domain: text(domain),
            policy,
        };
        if !self.settings.mta_sts {
            return Ok((Check::Off, scope(Applied::None)));
        }
        let got = self
            .sts
            .policy(&self.dns, &self.tls, egress, domain, end)
            .await;
        match got {
            Got::Busy => Err((Answer::Later(self.wait()), STS_BUSY)),
            Got::Failed(result) => {
                let failed = scope(Applied::Sts {
                    lines: Vec::new(),
                    mx: Vec::new(),
                });
                self.results
                    .failure(&failed, failure(result, egress, None, None));
                Ok((Check::Off, scope(Applied::None)))
            }
            Got::Policy(policy) if policy.mode == Mode::Enforce => {
                let applied = scope(policy.applied());
                hosts.retain(|host| policy.allows(host));
                if hosts.is_empty() {
                    let mismatch = failure(ResultType::ValidationFailure, egress, None, None);
                    self.results.failure(&applied, mismatch);
                    return Err((TEMPORARY, STS_NO_MX));
                }
                Ok((Check::Enforce, applied))
            }
            Got::Policy(policy) if policy.mode == Mode::Testing && self.settings.tlsrpt => {
                let applied = scope(policy.applied());
                for host in hosts.iter().filter(|host| !policy.allows(host)) {
                    let mismatch = failure(ResultType::ValidationFailure, egress, Some(host), None);
                    self.results.failure(&applied, mismatch);
                }
                Ok((Check::Observe, applied))
            }
            Got::Policy(policy) => Ok((Check::Off, scope(policy.applied()))),
            Got::None => Ok((Check::Off, scope(Applied::None))),
        }
    }

    async fn need(
        &self,
        end: Instant,
        (egress, host): (IpAddr, &Name),
        target: &Name,
        dane: bool,
        sts: Check,
    ) -> Option<Need> {
        let found = if dane {
            let lookup = dane::lookup(&self.dns, self.settings.port, host, target);
            timeout(left(end, self.settings.deadline), lookup)
                .await
                .unwrap_or(Dane::Failed { bogus: false })
        } else {
            Dane::None
        };
        match found {
            Dane::Failed { bogus: false } => None,
            Dane::Failed { bogus: true } => {
                let tlsa = Scope {
                    domain: text(target),
                    policy: Applied::Tlsa {
                        records: Vec::new(),
                    },
                };
                let bogus = failure(ResultType::DnssecInvalid, egress, Some(host), None);
                self.results.failure(&tlsa, bogus);
                None
            }
            Dane::Verify { names, records } => Some(Need::Dane { names, records }),
            _ if sts == Check::Enforce => Some(Need::Sts),
            _ if sts == Check::Observe => Some(Need::Observe),
            Dane::Encrypt => Some(Need::Encrypt),
            Dane::None => Some(Need::Any),
        }
    }

    fn wait(&self) -> u64 {
        u64::try_from(self.settings.wait.as_millis()).unwrap_or(0)
    }

    async fn session(
        &self,
        end: Instant,
        key: &Key,
        (need, scope): (&Need, &Scope),
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
            match self.open(end, key, need, scope).await {
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
        if envelope.required.requiretls && !caps.requiretls {
            self.pool.park(key.clone(), link).await;
            return Tried::Next(REQUIRETLS.to_vec());
        }
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

    async fn open(
        &self,
        end: Instant,
        key: &Key,
        need: &Need,
        scope: &Scope,
    ) -> Result<(Conn, Capabilities), Vec<u8>> {
        let failed = |result| {
            let detail = failure(result, key.egress, Some(&key.host), Some(key.remote));
            self.results.failure(scope, detail);
        };
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
        let required = key.level != Level::Any;
        if !caps.starttls {
            failed(ResultType::StarttlsNotSupported);
            if required {
                conn.quit().await;
                return Err(NO_STARTTLS.to_vec());
            }
            return Ok((conn, caps));
        }
        match command(&mut conn, client::STARTTLS, t.starttls).await {
            Ok(reply) if reply.code == 220 => {
                let (name, verify) = need.verify(&key.host);
                let observed = match &verify {
                    Verify::Observe(observed) => Some(Arc::clone(observed)),
                    _ => None,
                };
                conn = match conn.starttls(&self.tls, &name, verify, t.starttls).await {
                    Ok(conn) => conn,
                    Err(lost) => {
                        if let Lost::Tls(refused) = lost
                            && let Some(result) = refused_type(refused)
                        {
                            failed(result);
                        }
                        return Err(lost.text().to_vec());
                    }
                };
                let verdict = observed.and_then(|observed| observed.verdict());
                match verdict.and_then(Result::err).and_then(refused_type) {
                    Some(result) => failed(result),
                    None => self.results.success(scope),
                }
                caps = match self.hello(&mut conn).await {
                    Ok(caps) => caps,
                    Err(failed) => return Err(next(conn, failed).await),
                };
            }
            Ok(reply) if required => {
                if reply.code >= 500 {
                    failed(ResultType::StarttlsNotSupported);
                }
                return Err(next(conn, Ok(reply)).await);
            }
            Ok(reply) => {
                if reply.code >= 500 {
                    failed(ResultType::StarttlsNotSupported);
                }
            }
            Err(lost) => return Err(lost.text().to_vec()),
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

fn text(name: &Name) -> String {
    name.to_string().trim_end_matches('.').to_ascii_lowercase()
}

fn failure(
    result: ResultType,
    sending: IpAddr,
    mx: Option<&Name>,
    receiving: Option<IpAddr>,
) -> Failure {
    Failure {
        result,
        sending,
        mx: mx.map(text),
        receiving,
    }
}

fn refused_type(refused: Refusal) -> Option<ResultType> {
    match refused {
        Refusal::Expired => Some(ResultType::CertificateExpired),
        Refusal::NameMismatch => Some(ResultType::CertificateHostMismatch),
        Refusal::Untrusted => Some(ResultType::CertificateNotTrusted),
        Refusal::Unverified => Some(ResultType::ValidationFailure),
        Refusal::Lost => None,
    }
}

impl<D: Dns> Transport for Deliver<D> {
    fn restore(&self, restore: Restore) -> impl Future<Output = ()> {
        match restore.kind {
            KIND_STS => self.sts.restore(restore),
            KIND_RPT => self.owners.restore(restore),
            _ => {}
        }
        std::future::ready(())
    }

    async fn tick(&self) {
        if self.owners.due() {
            let taken = self.results.take();
            if self.settings.tlsrpt {
                self.owners.flush(taken);
            }
            self.owners.prune();
        }
        if self.settings.mta_sts {
            let jitter = |n: u64| {
                let n = usize::try_from(n).unwrap_or(usize::MAX);
                u64::try_from(self.pick(n)).unwrap_or(0)
            };
            self.sts.refresh(&self.dns, &self.tls, jitter).await;
        }
    }

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
