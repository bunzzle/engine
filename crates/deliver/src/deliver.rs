use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use control::{KIND_RPT, KIND_STS, Leases, Rate, Signal};
use dns::{Found, Name, Record, Type};
use rt::{Ends, Instant, JoinHandle, now, timeout, wall_ms};
use sched::{
    Answer, Answered, Attempt, Body, Bounced, Destination, Envelope, EventBody, EventKind, Kind,
    OwnStats, Recipient, ReportMail, Reported, Required, Restore, Ret, SiteRow, Transport,
    TransportStats,
};
use smtp::client::{
    self, Answer as Reply, Capabilities, Dots, Mail, Rcpt, Refused, Response, Step, Transaction,
};
use tls::{Connector, Observed, Refusal, Tlsa, Verify};

use crate::address::{Bind, Local, Own, Rule};
use crate::classify;
use crate::conn::{Conn, Lost, left};
use crate::dane::{self, Dane};
use crate::gzip::gzip;
use crate::mail::{MAX_JSON, report_mail};
use crate::mx::{self, Addresses, Dns, Hosts};
use crate::owners::{OwnerStats, Owners, State};
use crate::pool::{Key, Level, Link, Pool, Remote, Slot};
use crate::report::{Applied, Report, ResultType, Rua, rua};
use crate::results::{Failure, ResultStats, Results, Scope, Taken};
use crate::settings::{EightBit, Settings, Site};
use crate::site;
use crate::sts::{Got, Mode, PolicyStats, Sts};
use crate::upload::upload;

const ADDRESSES: usize = 10;
const LOOKUP: Duration = Duration::from_secs(30);
const CHUNK: usize = 64 * 1024;
const DEAD_MOST: usize = 10_000;
const TEMPORARY: Answer = Answer::Deferred(Kind::Temporary);

const NO_EGRESS: &[u8] = b"451 4.3.0 No egress address";
const WARMING: &[u8] = b"451 4.4.5 Egress warm-up cap reached";
const BAD_DOMAIN: &[u8] = b"550 5.1.2 Recipient domain is not valid";
const NO_DOMAIN: &[u8] = b"550 5.1.2 Recipient domain does not exist";
const NULL_MX: &[u8] = b"556 5.1.10 Recipient domain does not accept mail";
const MX_FAILED: &[u8] = b"451 4.4.3 MX lookup failed";
const HOST_FAILED: &[u8] = b"451 4.4.3 Mail server address lookup failed";
const NO_HOST: &[u8] = b"451 4.4.4 No mail server address";
const NOT_ALLOWED: &[u8] = b"550 5.4.4 No allowed mail server address";
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
    pub gone: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Due {
    pub report: Report,
    pub rua: Rua,
}

pub struct Deliver<D, L = Bind> {
    dns: D,
    tls: Connector,
    settings: Settings,
    leases: Option<Leases<Remote>>,
    pool: Pool,
    sts: Sts,
    results: Results,
    owners: Owners,
    own: Own<L>,
    last: Cell<Option<IpAddr>>,
    dead: RefCell<BTreeMap<(IpAddr, IpAddr), Instant>>,
    capped: RefCell<BTreeMap<IpAddr, Instant>>,
    ehlo: Vec<u8>,
    helo: Vec<u8>,
    random: Cell<u64>,
    turn: Cell<u64>,
    warmup_skips: Cell<u64>,
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
            muted: false,
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

enum Kept {
    Found {
        ips: Vec<IpAddr>,
        target: Name,
        dnssec: bool,
    },
    Refused,
    Failed,
    Timeout,
}

enum Tried {
    Next(Vec<u8>),
    Busy,
    Warming,
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
        Self::with_local(dns, tls, settings, leases, seed, Bind)
    }
}

impl<D: Dns, L: Local> Deliver<D, L> {
    pub fn with_local(
        dns: D,
        tls: Connector,
        settings: Settings,
        leases: Option<Leases<Remote>>,
        seed: u64,
        local: L,
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
            own: Own::new(local),
            last: Cell::new(None),
            dead: RefCell::new(BTreeMap::new()),
            capped: RefCell::new(BTreeMap::new()),
            ehlo,
            helo,
            random: Cell::new(seed | 1),
            turn: Cell::new(0),
            warmup_skips: Cell::new(0),
        })
    }

    pub fn pooled(&self) -> usize {
        self.pool.len()
    }

    pub fn dead_hosts(&self) -> usize {
        match &self.leases {
            Some(leases) => leases.dead_hosts(),
            None => self.dead.borrow().len(),
        }
    }

    pub fn policies(&self) -> usize {
        self.sts.len()
    }

    pub fn policy_stats(&self) -> PolicyStats {
        self.sts.stats()
    }

    pub fn own_stats(&self) -> OwnStats {
        self.own.stats()
    }

    pub fn report_mesh(&mut self, ends: Ends<Taken>) -> JoinHandle<()> {
        self.owners.start(ends)
    }

    pub fn take_results(&self) -> Vec<Taken> {
        self.results.take()
    }

    pub async fn due_reports(&self) -> Vec<Due> {
        let mut due = Vec::new();
        for taken in self.owners.reports() {
            let name = Name::parse(&taken.domain)
                .and_then(|name| name.prefixed("_tls"))
                .and_then(|name| name.prefixed("_smtp"));
            let Ok(name) = name else {
                self.owners.mark(taken.day, &taken.domain, State::Dropped);
                continue;
            };
            let Ok(Ok(lookup)) = timeout(LOOKUP, self.dns.lookup(&name, Type::Txt)).await else {
                self.owners.retry(taken.day, &taken.domain);
                continue;
            };
            let Some(rua) = reporting(&lookup.found) else {
                self.owners.mark(taken.day, &taken.domain, State::Dropped);
                continue;
            };
            let reporter = &self.settings.reporter;
            let report = Report {
                organization: reporter.organization.clone(),
                contact: reporter.contact.clone(),
                submitter: reporter.submitter.clone(),
                domain: taken.domain,
                day: taken.day,
                policies: taken.policies,
            };
            due.push(Due { report, rua });
        }
        due
    }

    fn rule(&self) -> Rule<'_, L> {
        Rule {
            allow: &self.settings.allow,
            nat64: &self.settings.nat64,
            own: &self.own,
        }
    }

    async fn upload(&self, due: &Due) -> bool {
        let fixed = self.settings.egress.or(self.last.get());
        let (Some(egress), false) = (fixed, due.rua.https.is_empty()) else {
            return false;
        };
        let json = due.report.json();
        if json.len() > MAX_JSON {
            return false;
        }
        let body = gzip(json.as_bytes());
        let mut any = false;
        for uri in &due.rua.https {
            any |= upload(&self.dns, &self.tls, &self.rule(), egress, uri, &body).await;
        }
        any
    }

    pub fn report_sent(&self, day: u64, domain: &str) {
        self.owners.mark(day, domain, State::Sent);
    }

    pub fn report_dropped(&self, day: u64, domain: &str) {
        self.owners.mark(day, domain, State::Dropped);
    }

    pub fn report_failed(&self, day: u64, domain: &str) {
        self.owners.retry(day, domain);
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
        let egress = match self.egress(recipients, destination) {
            Ok(egress) => egress,
            Err(outcomes) => return outcomes,
        };
        self.last.set(Some(egress));
        let envelope = message.envelope;
        let Ok(domain) = Name::parse(&destination.domain) else {
            return every(Answer::Failed, BAD_DOMAIN);
        };
        let mut pick = |n| self.pick(n);
        let (mut hosts, secure) = match self.hosts(&domain, deadline, &mut pick).await {
            Ok(hosts) => hosts,
            Err((answer, reply)) => return every(answer, reply),
        };
        let site = site::name(&destination.domain, &hosts, &self.settings.sites);
        let rule = self.settings.sites.iter().find(|rule| rule.name == site);
        let enforced = self.enforce(egress, &domain, (&mut hosts, secure), (end, envelope));
        let (sts, scope) = match enforced.await {
            Ok(enforced) => enforced,
            Err((answer, reply)) => return every(answer, reply),
        };
        let remote = Remote::Site(egress, site.clone().into());
        let send = (rule, &remote);
        let mut slot = None;
        let mut last = NO_HOST.to_vec();
        let (mut tried, mut others, mut refused) = (0, false, 0);
        'hosts: for host in &hosts {
            let found = self
                .kept(host, egress, end, deadline, &destination.egress)
                .await;
            let (kept, target, dnssec) = match found {
                Kept::Found {
                    ips,
                    target,
                    dnssec,
                } => (ips, target, dnssec),
                Kept::Refused => {
                    refused += 1;
                    continue;
                }
                Kept::Failed => {
                    if tried == 0 {
                        last = HOST_FAILED.to_vec();
                    }
                    others = true;
                    continue;
                }
                Kept::Timeout => {
                    others = true;
                    break;
                }
            };
            let dane = secure && dnssec && !kept.is_empty() && !scope.muted;
            let Some(need) = self.need(end, (egress, host), &target, dane, sts).await else {
                last = TLSA_FAILED.to_vec();
                others = true;
                continue;
            };
            let scope = need.scope(&target).unwrap_or_else(|| scope.clone());
            if envelope.required.requiretls && matches!(need, Need::Any | Need::Encrypt) {
                last = REQUIRETLS.to_vec();
                continue;
            }
            for ip in kept {
                if tried == ADDRESSES || now() >= end {
                    break 'hosts;
                }
                tried += 1;
                let key = Key {
                    egress,
                    domain: destination.domain.clone(),
                    site: site.clone().into(),
                    host: host.clone(),
                    remote: ip,
                    level: need.level(),
                };
                match self
                    .session(end, &key, (&need, &scope), send, &mut slot, &mut message)
                    .await
                {
                    Tried::Done(outcomes) => return outcomes,
                    Tried::Busy => return every(Answer::Later(self.wait()), BUSY),
                    Tried::Warming => return every(Answer::Later(self.wait()), WARMING),
                    Tried::Next(reply) => {
                        others |= reply != REQUIRETLS;
                        last = reply;
                    }
                }
            }
        }
        let refused =
            refused == hosts.len() && !hosts.is_empty() && one_family(egress, &destination.egress);
        finished(recipients, envelope.required, end, (refused, others, last))
    }

    async fn hosts(
        &self,
        domain: &Name,
        deadline: Duration,
        pick: &mut impl FnMut(usize) -> usize,
    ) -> Result<(Vec<Name>, bool), (Answer, &'static [u8])> {
        match timeout(deadline, mx::hosts(&self.dns, domain, pick)).await {
            Ok(Hosts::Found(hosts, secure)) => Ok((hosts, secure)),
            Ok(Hosts::NullMx) => Err((Answer::Failed, NULL_MX)),
            Ok(Hosts::NoDomain) => Err((Answer::Failed, NO_DOMAIN)),
            Ok(Hosts::Failed) => Err((TEMPORARY, MX_FAILED)),
            Err(_) => Err((TEMPORARY, Lost::Timeout.text())),
        }
    }

    async fn kept(
        &self,
        host: &Name,
        egress: IpAddr,
        end: Instant,
        deadline: Duration,
        egresses: &[(IpAddr, u16)],
    ) -> Kept {
        let resolved = Cell::new(false);
        let passed = Cell::new(false);
        let refused = Cell::new(false);
        let lookup = mx::filtered(&self.dns, host, egress.is_ipv6(), |ip| {
            resolved.set(true);
            let keep = crate::address::keep(ip, &self.settings.allow, &self.settings.nat64);
            passed.set(passed.get() || keep);
            refused.set(refused.get() || !keep);
            keep
        });
        let (found, target, dnssec) = match timeout(left(end, deadline), lookup).await {
            Ok(Addresses::Found {
                ips,
                secure: dnssec,
                target,
            }) => (ips, target, dnssec),
            Ok(Addresses::Failed) => return Kept::Failed,
            Err(_) => return Kept::Timeout,
        };
        if passed.get() && refused.get() {
            self.own.partly_refused();
        }
        let mut kept = Vec::with_capacity(found.len());
        for ip in found {
            if self.own.own(ip, &self.settings.nat64).await {
                continue;
            }
            if !egresses.iter().any(|(egress, _)| *egress == ip) {
                kept.push(ip);
            }
        }
        if resolved.get() && !passed.get() {
            return Kept::Refused;
        }
        Kept::Found {
            ips: kept,
            target,
            dnssec,
        }
    }

    async fn enforce(
        &self,
        egress: IpAddr,
        domain: &Name,
        (hosts, secure): (&mut Vec<Name>, bool),
        (end, envelope): (Instant, &Envelope),
    ) -> Result<(Check, Scope), (Answer, &'static [u8])> {
        let relaxed = envelope.required.tls_optional();
        let (check, scope) = self.policy(egress, domain, hosts, (end, relaxed)).await?;
        if envelope.required.requiretls && !secure && check != Check::Enforce {
            return Err((Answer::Failed, REQUIRETLS));
        }
        Ok((check, scope))
    }

    async fn policy(
        &self,
        egress: IpAddr,
        domain: &Name,
        hosts: &mut Vec<Name>,
        (end, relaxed): (Instant, bool),
    ) -> Result<(Check, Scope), (Answer, &'static [u8])> {
        let scope = |policy| Scope {
            domain: text(domain),
            policy,
            muted: relaxed,
        };
        if relaxed || !self.settings.mta_sts {
            return Ok((Check::Off, scope(Applied::None)));
        }
        let got = self
            .sts
            .policy(&self.dns, &self.tls, &self.rule(), egress, domain, end)
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
                    muted: false,
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

    fn feedback(&self, remote: &Remote, signal: Signal) {
        if let Some(leases) = &self.leases {
            leases.feedback(remote, signal);
        }
    }

    async fn fresh(
        &self,
        end: Instant,
        key: &Key,
        (need, scope): (&Need, &Scope),
        remote: &Remote,
        slot: &mut Option<Slot>,
    ) -> Result<Link, Tried> {
        if self.is_dead(key.egress, key.remote) {
            return Err(Tried::Next(DEAD.to_vec()));
        }
        if slot.is_none() {
            match self.slot(remote, end).await {
                Ok(taken) => *slot = taken,
                Err(()) => return Err(Tried::Busy),
            }
        }
        match self.open(end, key, need, scope, remote).await {
            Ok((conn, caps)) => Ok(Link {
                conn,
                caps,
                used: 0,
                _slot: slot.take(),
            }),
            Err(reply) => Err(Tried::Next(reply)),
        }
    }

    async fn held(&self, end: Instant, key: &Key, rule: Option<&Site>) -> bool {
        let (Some(leases), Some(rule)) = (&self.leases, rule) else {
            return false;
        };
        if rule.rate.is_none() {
            return false;
        }
        let send = Remote::Send(key.egress, key.site.clone());
        match leases
            .take_token_within(&send, left(end, self.settings.wait))
            .await
        {
            Ok(_) | Err(control::Error::Invalid(_)) => false,
            Err(_) => true,
        }
    }

    async fn allowed(
        &self,
        end: Instant,
        key: &Key,
        rule: Option<&Site>,
        link: Link,
    ) -> Result<Link, Tried> {
        let Ok(token) = self.warm_token(end, key.egress).await else {
            self.pool.park(key.clone(), link).await;
            return Err(Tried::Warming);
        };
        if !self.held(end, key, rule).await {
            return Ok(link);
        }
        if let (Some(leases), Some(taken)) = (&self.leases, token) {
            leases.give_back(&Remote::Egress(key.egress), taken);
        }
        self.pool.park(key.clone(), link).await;
        Err(Tried::Busy)
    }

    async fn session(
        &self,
        end: Instant,
        key: &Key,
        (need, scope): (&Need, &Scope),
        (rule, remote): (Option<&Site>, &Remote),
        slot: &mut Option<Slot>,
        message: &mut Message<'_>,
    ) -> Tried {
        let paused = self.leases.as_ref().is_some_and(|l| l.blocked(remote));
        let reused = if paused {
            None
        } else {
            self.reuse(key, end).await
        };
        let link = match reused {
            Some(link) => {
                drop(slot.take());
                link
            }
            None => match self.fresh(end, key, (need, scope), remote, slot).await {
                Ok(link) => link,
                Err(tried) => return tried,
            },
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
        let mut link = match self.allowed(end, key, rule, link).await {
            Ok(link) => link,
            Err(tried) => return tried,
        };
        let run = self
            .transact(&mut link.conn, &mut transaction, message)
            .await;
        let finished = run.is_ok();
        let mut throttled = false;
        if let Ok(last) = &run {
            throttled = transaction
                .answers()
                .into_iter()
                .flatten()
                .filter_map(|answer| match answer {
                    Reply::Refused(reply) | Reply::Again(reply) => Some(reply),
                    Reply::Accepted => None,
                })
                .chain(transaction.mail_refused().cloned())
                .chain(last.clone())
                .any(|reply| classify::kind(&reply) == Kind::Throttled);
            if throttled {
                self.feedback(remote, Signal::Throttle);
                self.pool.close(key.egress, &key.site).await;
            } else {
                self.feedback(remote, Signal::Success);
            }
        }
        let (done, lost, mut closing) = match &run {
            Ok(last) => (
                last.as_ref().map(Response::text),
                Lost::Closed,
                last.as_ref().is_some_and(|r| r.code == 421),
            ),
            Err(lost) => (None, *lost, false),
        };
        let (outcomes, refused_closing) = transacted(
            message.recipients,
            &transaction,
            finished,
            done.as_deref(),
            lost,
        );
        closing |= refused_closing || throttled;
        link.used += 1;
        let reuse = rule
            .and_then(|rule| rule.reuse)
            .unwrap_or(self.settings.reuse);
        if finished && transaction.reusable() && !closing && link.used < reuse {
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
        remote: &Remote,
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
                self.feedback(remote, Signal::Failure);
                return Err(lost.text().to_vec());
            }
        };
        match conn.response(t.banner).await {
            Ok(banner) if banner.code == 220 => {}
            failed => {
                let busy = matches!(&failed, Ok(reply) if reply.code / 100 == 4);
                self.refused(key, remote, &failed, busy).await;
                return Err(next(conn, failed).await);
            }
        }
        let mut caps = match self.hello(&mut conn).await {
            Ok(caps) => caps,
            Err(failed) => {
                self.refused(key, remote, &failed, false).await;
                return Err(next(conn, failed).await);
            }
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
                        self.feedback(remote, Signal::Failure);
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
                    Err(failed) => {
                        self.refused(key, remote, &failed, false).await;
                        return Err(next(conn, failed).await);
                    }
                };
            }
            Ok(reply) if required => {
                if reply.code >= 500 {
                    failed(ResultType::StarttlsNotSupported);
                }
                if classify::kind(&reply) == Kind::Throttled {
                    self.refused(key, remote, &Ok(reply.clone()), true).await;
                }
                return Err(next(conn, Ok(reply)).await);
            }
            Ok(reply) => {
                if reply.code >= 500 {
                    failed(ResultType::StarttlsNotSupported);
                }
            }
            Err(lost) => {
                self.feedback(remote, Signal::Failure);
                return Err(lost.text().to_vec());
            }
        }
        Ok((conn, caps))
    }

    async fn refused(
        &self,
        key: &Key,
        remote: &Remote,
        failed: &Result<Response, Lost>,
        busy: bool,
    ) {
        let throttled = match failed {
            Ok(reply) => busy || classify::kind(reply) == Kind::Throttled,
            Err(_) => false,
        };
        if throttled {
            self.feedback(remote, Signal::Throttle);
            self.pool.close(key.egress, &key.site).await;
        } else {
            let dead = match failed {
                Ok(reply) => reply.code / 100 == 5,
                Err(_) => true,
            };
            if dead {
                self.mark_dead(key.egress, key.remote);
            }
            self.feedback(remote, Signal::Failure);
        }
    }

    fn is_dead(&self, egress: IpAddr, remote: IpAddr) -> bool {
        if let Some(leases) = &self.leases {
            return leases.is_dead(egress, remote);
        }
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
        if let Some(leases) = &self.leases {
            leases.mark_dead(egress, remote, self.settings.dead);
            return;
        }
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

    fn egress(
        &self,
        recipients: &[(u32, Recipient)],
        destination: &Destination,
    ) -> Result<IpAddr, Vec<Outcome>> {
        let every = |answer, reply: &[u8]| all(recipients, answer, reply);
        let pooled = self.pool.egress(&destination.domain, &destination.egress);
        let candidates = self.candidates(pooled, &destination.egress);
        if candidates.is_empty() {
            return Err(every(TEMPORARY, NO_EGRESS));
        }
        let mut capped = 0;
        for candidate in candidates {
            if self.is_capped(candidate) {
                capped += 1;
                continue;
            }
            return Ok(candidate);
        }
        self.warmup_skips.set(self.warmup_skips.get() + capped);
        Err(every(Answer::Later(self.wait()), WARMING))
    }

    fn is_capped(&self, ip: IpAddr) -> bool {
        let mut capped = self.capped.borrow_mut();
        match capped.get(&ip) {
            Some(until) if *until > now() => true,
            Some(_) => {
                capped.remove(&ip);
                false
            }
            None => false,
        }
    }

    async fn warm_token(&self, end: Instant, ip: IpAddr) -> Result<Option<control::Taken>, ()> {
        let Some(warmup) = self
            .settings
            .warmups
            .iter()
            .find(|warmup| warmup.egress == ip)
        else {
            return Ok(None);
        };
        let Some(leases) = &self.leases else {
            return Ok(None);
        };
        let taken = leases
            .take_token_within(&Remote::Egress(ip), left(end, self.settings.wait))
            .await;
        match taken {
            Ok(taken) => Ok(Some(taken)),
            Err(control::Error::Invalid(_)) => Ok(None),
            Err(_) => {
                let period = warmup
                    .cap(wall_ms() / 86_400_000)
                    .and_then(|cap| Rate::per(cap, Duration::from_hours(24)).period())
                    .unwrap_or(Duration::from_mins(1));
                self.capped.borrow_mut().insert(ip, now() + period);
                self.warmup_skips.set(self.warmup_skips.get() + 1);
                Err(())
            }
        }
    }

    fn candidates(&self, pooled: Option<IpAddr>, egress: &[(IpAddr, u16)]) -> Vec<IpAddr> {
        let mut out = Vec::new();
        if let Some(ip) = pooled {
            out.push(ip);
        }
        let total: u64 = egress.iter().map(|(_, weight)| u64::from(*weight)).sum();
        if total == 0 {
            return out;
        }
        let turn = self.turn.get();
        self.turn.set(turn.wrapping_add(1));
        let mut at = turn % total;
        let mut start = 0;
        for (index, (_, weight)) in egress.iter().enumerate() {
            let weight = u64::from(*weight);
            if at < weight {
                start = index;
                break;
            }
            at -= weight;
        }
        for offset in 0..egress.len() {
            let (ip, weight) = &egress[(start + offset) % egress.len()];
            if *weight > 0 && !out.contains(ip) {
                out.push(*ip);
            }
        }
        out
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

fn reporting(found: &Found) -> Option<Rua> {
    let Found::Records(records) = found else {
        return None;
    };
    let texts: Vec<&[u8]> = records
        .iter()
        .filter_map(|record| match record {
            Record::Txt(text) => Some(text.as_slice()),
            _ => None,
        })
        .collect();
    rua(&texts)
}

fn honoured(required: Required, tenant: u32, report: Option<u32>) -> Required {
    if required.tls_optional() && report != Some(tenant) {
        Required::new(required.smtputf8, required.requiretls)
    } else {
        required
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

impl<D: Dns, L: Local> Transport for Deliver<D, L> {
    async fn probe_own(&self) -> OwnStats {
        self.own.probe_families().await;
        self.own.stats()
    }

    fn own_stats(&self) -> OwnStats {
        self.own.stats()
    }

    fn stats(&self) -> TransportStats {
        let wide = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let leases = self.leases.as_ref();
        let (tracked, dead) = leases.map_or((0, 0), Leases::sites);
        TransportStats {
            pooled: wide(self.pooled()),
            dead_hosts: wide(self.dead_hosts()),
            window_cuts: leases.map_or(0, |l| l.stats().cuts),
            warmup_skips: self.warmup_skips.get(),
            sites_dead: dead,
            sites_tracked: tracked,
        }
    }

    fn sites(&self) -> Vec<SiteRow> {
        let Some(leases) = &self.leases else {
            return Vec::new();
        };
        leases
            .site_views()
            .into_iter()
            .filter_map(|view| {
                let Remote::Site(egress, name) = view.key else {
                    return None;
                };
                let rate = self
                    .settings
                    .sites
                    .iter()
                    .find(|rule| rule.name == *name)
                    .and_then(|rule| rule.rate);
                Some(SiteRow {
                    egress,
                    site: name,
                    window: view.window,
                    limit: view.limit,
                    in_use: view.in_use,
                    health: view.health,
                    paused: view.paused,
                    rate,
                })
            })
            .collect()
    }

    fn pause_site(&self, egress: IpAddr, site: &str, on: bool) -> bool {
        let Some(leases) = &self.leases else {
            return false;
        };
        let key = Remote::Site(egress, site.into());
        if on {
            leases.block(&key);
        } else {
            leases.unblock(&key);
        }
        true
    }

    fn restore(&self, restore: Restore) -> impl Future<Output = ()> {
        match restore.kind {
            KIND_STS => self.sts.restore(restore),
            KIND_RPT => self.owners.restore(restore),
            _ => {}
        }
        std::future::ready(())
    }

    async fn reports(&self) -> Vec<ReportMail> {
        let from = self.settings.reporter.from.clone();
        let mut mails = Vec::new();
        for due in self.due_reports().await {
            let (day, domain) = (due.report.day, due.report.domain.clone());
            let uploaded = self.upload(&due).await;
            if due.rua.mailto.is_empty() {
                if uploaded {
                    self.report_sent(day, &domain);
                } else {
                    self.report_failed(day, &domain);
                }
                continue;
            }
            match report_mail(&due.report, &from, &due.rua.mailto) {
                Some(message) => mails.push(ReportMail {
                    day,
                    domain,
                    from: from.clone(),
                    to: due.rua.mailto,
                    message,
                }),
                None => self.report_dropped(day, &domain),
            }
        }
        mails
    }

    fn reported(&self, day: u64, domain: &str, done: Reported) {
        match done {
            Reported::Sent => self.report_sent(day, domain),
            Reported::Dropped => self.report_dropped(day, domain),
            Reported::Failed => self.report_failed(day, domain),
        }
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
            self.sts
                .refresh(
                    &self.dns,
                    &self.tls,
                    &self.rule(),
                    self.settings.egress,
                    jitter,
                )
                .await;
        }
    }

    async fn send(&self, attempt: Attempt) -> Vec<Answered> {
        let Attempt {
            tenant,
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
        prepared.envelope.required = honoured(
            prepared.envelope.required,
            tenant,
            self.settings.report_tenant,
        );
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
        let time = wall_ms();
        claimed
            .iter()
            .map(|c| {
                let outcome = outcomes.iter().find(|o| o.recipient == c.recipient);
                let (answer, reply) = outcome.map_or((TEMPORARY, Lost::Closed.text()), |o| {
                    (o.answer, o.reply.as_slice())
                });
                let found = address_of(&prepared.recipients, c.recipient);
                let bounced = bounced(found, outcome, prepared.opener.generation());
                let address = found.map(|a| a.as_bytes().to_vec()).unwrap_or_default();
                let event = EventKind::of(answer).and_then(|kind| {
                    let body = EventBody {
                        kind,
                        time,
                        address,
                        reply: reply.to_vec(),
                        attempts: c.attempts.saturating_add(1),
                        class: c.class,
                    };
                    prepared.opener.event(c.recipient, c.stamp, &body).ok()
                });
                Answered {
                    recipient: c.recipient,
                    answer,
                    reply: prepared
                        .opener
                        .seal_reply(c.recipient, c.stamp, reply)
                        .unwrap_or_default(),
                    event,
                    bounced,
                }
            })
            .collect()
    }
}

fn one_family(egress: IpAddr, egresses: &[(IpAddr, u16)]) -> bool {
    egresses
        .iter()
        .filter(|(_, weight)| *weight > 0)
        .all(|(ip, _)| ip.is_ipv6() == egress.is_ipv6())
}

fn finished(
    recipients: &[(u32, Recipient)],
    required: Required,
    end: Instant,
    (refused, others, last): (bool, bool, Vec<u8>),
) -> Vec<Outcome> {
    if refused {
        return all(recipients, Answer::Failed, NOT_ALLOWED);
    }
    if now() >= end {
        return all(recipients, TEMPORARY, Lost::Timeout.text());
    }
    if required.requiretls && !others && last == REQUIRETLS {
        return all(recipients, Answer::Failed, REQUIRETLS);
    }
    all(recipients, TEMPORARY, &last)
}

fn address_of(recipients: &[(u32, Recipient)], recipient: u32) -> Option<&str> {
    recipients
        .iter()
        .find(|(r, _)| *r == recipient)
        .map(|(_, r)| r.address.as_str())
}

fn bounced(address: Option<&str>, outcome: Option<&Outcome>, generation: u32) -> Option<Bounced> {
    address
        .filter(|_| outcome.is_some_and(|o| o.gone && o.answer == Answer::Failed))
        .map(|address| Bounced {
            generation,
            address: address.into(),
        })
}

fn transacted(
    recipients: &[(u32, Recipient)],
    transaction: &Transaction,
    finished: bool,
    done: Option<&str>,
    lost: Lost,
) -> (Vec<Outcome>, bool) {
    let answers = transaction.answers();
    let delivered = finished && answers.iter().any(|a| a == &Some(Reply::Accepted));
    let mut closing = false;
    let outcomes = recipients
        .iter()
        .zip(answers)
        .zip(transaction.refused_at_rcpt())
        .map(|(((recipient, _), answer), at_rcpt)| {
            let gone = at_rcpt && matches!(&answer, Some(Reply::Refused(r)) if classify::gone(r));
            let (answer, reply) = match answer {
                Some(Reply::Accepted) if finished => (
                    Answer::Delivered,
                    done.unwrap_or_default().as_bytes().to_vec(),
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
                gone,
            }
        })
        .collect();
    (outcomes, closing)
}

fn all(recipients: &[(u32, Recipient)], answer: Answer, reply: &[u8]) -> Vec<Outcome> {
    recipients
        .iter()
        .map(|(recipient, _)| Outcome {
            recipient: *recipient,
            answer,
            reply: reply.to_vec(),
            gone: false,
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

#[cfg(test)]
mod tests {
    use sched::{Answer, Bounced, Kind, Recipient, Required};

    use super::{Outcome, address_of, bounced, honoured};

    #[test]
    fn only_a_gone_failure_names_its_own_address_and_generation() {
        let recipients: Vec<(u32, Recipient)> = [(4, "a@example.com"), (9, "b@example.com")]
            .into_iter()
            .map(|(r, address)| {
                let recipient = Recipient {
                    address: address.to_owned(),
                    ..Recipient::default()
                };
                (r, recipient)
            })
            .collect();
        let outcome = |answer, gone| Outcome {
            recipient: 9,
            answer,
            reply: Vec::new(),
            gone,
        };
        let gone = outcome(Answer::Failed, true);
        assert_eq!(
            bounced(address_of(&recipients, 9), Some(&gone), 7),
            Some(Bounced {
                generation: 7,
                address: "b@example.com".into(),
            })
        );
        assert_eq!(address_of(&recipients, 4), Some("a@example.com"));
        assert_eq!(address_of(&recipients, 5), None);
        assert_eq!(bounced(None, Some(&gone), 7), None);
        assert_eq!(bounced(address_of(&recipients, 9), None, 7), None);
        for other in [
            outcome(Answer::Failed, false),
            outcome(Answer::Deferred(Kind::Temporary), true),
            outcome(Answer::Delivered, true),
        ] {
            assert_eq!(bounced(address_of(&recipients, 9), Some(&other), 7), None);
        }
    }

    #[test]
    fn only_the_report_tenant_keeps_tls_optional() {
        let report = Required::report();
        assert!(honoured(report, 4, Some(4)).tls_optional());
        assert!(!honoured(report, 5, Some(4)).tls_optional());
        assert!(!honoured(report, 4, None).tls_optional());
        let plain = Required::new(true, true);
        assert_eq!(honoured(plain, 4, Some(4)), plain);
        assert_eq!(honoured(plain, 5, Some(4)), plain);
    }
}
