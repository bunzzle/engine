use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::ops::Range;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;

use rt::{Ends, JoinHandle, Notify, Peers, sleep_until, spawn};
use spool::{Done, Error, Message, MessageId, Outcome, Pending, Reply, Report, Spool, Stamp};

use crate::clock::Clock;
use crate::lanes::{Entry, Lanes, Limits, QueueId, Take, ranges};
use crate::policy::{Answer, BACKOFF, Kind, clamp, delay};
use crate::transport::{Answered, Attempt, Claimed, Transport};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub shards: u32,
    pub limits: Limits,
    pub slack: u64,
    pub bound: u64,
    pub ending: u64,
}

impl Config {
    pub fn new(shards: u32) -> Self {
        Self {
            shards,
            limits: Limits::default(),
            slack: 1_000,
            bound: 600_000,
            ending: 60_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    Claimed {
        attempts: u16,
        class: u8,
        notified: bool,
        stamp: Stamp,
    },
    Early(u64),
    Ending,
    Gone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub queue: QueueId,
    pub tenant: u32,
    pub message: MessageId,
}

pub enum Note {
    Enqueue {
        queue: QueueId,
        tenant: u32,
        entry: Entry,
        due: u64,
    },
    Claim {
        route: Route,
        recipients: Vec<Range<u32>>,
        forced: bool,
    },
    Claimed {
        route: Route,
        answers: Vec<(u32, Claim)>,
    },
    Report {
        route: Route,
        reports: Vec<Report>,
    },
    Reported {
        route: Route,
        reports: Vec<(u32, Option<u64>)>,
        done: Option<Done>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrival {
    pub id: MessageId,
    pub tenant: u32,
    pub due: u64,
    pub queues: Vec<QueueId>,
}

impl Arrival {
    pub fn of(message: &Message) -> Self {
        let clear = &message.head.clear;
        Self {
            id: message.id,
            tenant: message.tenant,
            due: clear.accepted.max(clear.not_before),
            queues: message
                .slices
                .iter()
                .flat_map(|s| s.queues.iter().copied())
                .collect(),
        }
    }
}

pub fn queue_core(queue: QueueId, shards: u32, cores: u16) -> u16 {
    let shard = mix(queue) % shards;
    u16::try_from(shard % u32::from(cores)).expect("core fits in u16")
}

fn mix(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x85eb_ca6b);
    x ^= x >> 13;
    x = x.wrapping_mul(0xc2b2_ae35);
    x ^ (x >> 16)
}

struct Inner<T> {
    config: Config,
    cores: u16,
    clock: Clock,
    spool: Spool,
    transport: T,
    lanes: RefCell<Lanes>,
    peers: OnceCell<Peers<Note>>,
    notify: Notify,
    expiry: Notify,
    expiring: RefCell<BTreeSet<MessageId>>,
    expired: Cell<u64>,
    closed: Cell<bool>,
    attempts: RefCell<BTreeMap<u64, u64>>,
    next_attempt: Cell<u64>,
    report_errors: Cell<u64>,
}

pub struct Sched<T> {
    inner: Rc<Inner<T>>,
}

impl<T> Clone for Sched<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<T: Transport + 'static> Sched<T> {
    pub fn start(
        ends: Ends<Note>,
        spool: Spool,
        transport: T,
        clock: Clock,
        config: Config,
    ) -> (Self, JoinHandle<()>) {
        let inner = Rc::new(Inner {
            config,
            cores: ends.cores(),
            clock,
            spool,
            transport,
            lanes: RefCell::new(Lanes::new(config.limits)),
            peers: OnceCell::new(),
            notify: Notify::default(),
            expiry: Notify::default(),
            expiring: RefCell::new(BTreeSet::new()),
            expired: Cell::new(0),
            closed: Cell::new(false),
            attempts: RefCell::new(BTreeMap::new()),
            next_attempt: Cell::new(0),
            report_errors: Cell::new(0),
        });
        let sched = Self { inner };
        let handler = sched.clone();
        let (peers, mesh) = ends.start(move |_, note| handler.handle(note));
        let _ = sched.inner.peers.set(peers);
        let runner = sched.clone();
        let run = spawn(async move { runner.run().await });
        let expirer = sched.clone();
        let expiry = spawn(async move { expirer.expire().await });
        let done = spawn(async move {
            run.await;
            expiry.await;
            mesh.await;
        });
        (sched, done)
    }

    pub fn clock(&self) -> Clock {
        self.inner.clock
    }

    pub fn active(&self) -> u32 {
        self.inner.lanes.borrow().active()
    }

    pub fn queued(&self) -> u64 {
        self.inner.lanes.borrow().recipients()
    }

    pub fn overdue(&self) -> usize {
        let now = self.inner.clock.now();
        let bound = self.inner.config.bound;
        self.inner
            .attempts
            .borrow()
            .values()
            .filter(|started| now > **started + bound)
            .count()
    }

    pub fn report_errors(&self) -> u64 {
        self.inner.report_errors.get()
    }

    pub fn retry_now(&self, queue: QueueId) {
        let now = self.inner.clock.now();
        self.inner.lanes.borrow_mut().retry_now(queue, now);
        self.inner.notify.notify();
    }

    pub fn enqueue(&self, arrival: Arrival) {
        let mut by_queue: BTreeMap<QueueId, Vec<u32>> = BTreeMap::new();
        for (r, queue) in (0..).zip(arrival.queues) {
            by_queue.entry(queue).or_default().push(r);
        }
        for (queue, recipients) in by_queue {
            let entry = Entry {
                message: arrival.id,
                recipients: ranges(recipients),
                forced: false,
            };
            self.send(
                queue_core(queue, self.inner.config.shards, self.inner.cores),
                Note::Enqueue {
                    queue,
                    tenant: arrival.tenant,
                    entry,
                    due: arrival.due,
                },
            );
        }
        self.inner.expiry.notify();
    }

    pub fn restore(&self, pending: Vec<Pending>) {
        let now = self.inner.clock.now();
        for message in pending {
            let mut groups: BTreeMap<(QueueId, u64), Vec<u32>> = BTreeMap::new();
            for open in message.recipients {
                let due = clamp(open.due, now);
                groups
                    .entry((open.queue, due))
                    .or_default()
                    .push(open.recipient);
            }
            for ((queue, due), recipients) in groups {
                let entry = Entry {
                    message: message.id,
                    recipients: ranges(recipients),
                    forced: false,
                };
                self.send(
                    queue_core(queue, self.inner.config.shards, self.inner.cores),
                    Note::Enqueue {
                        queue,
                        tenant: message.tenant,
                        entry,
                        due,
                    },
                );
            }
        }
        self.inner.expiry.notify();
    }

    pub fn retry_tenant(&self, tenant: u32) {
        let now = self.inner.clock.now();
        self.inner.lanes.borrow_mut().retry_tenant(tenant, now);
        self.inner.notify.notify();
    }

    pub fn expired(&self) -> u64 {
        self.inner.expired.get()
    }

    pub fn close(&self) {
        self.inner.closed.set(true);
        self.inner.notify.notify();
        self.inner.expiry.notify();
        if let Some(peers) = self.inner.peers.get() {
            peers.close();
        }
    }

    fn send(&self, core: u16, note: Note) {
        if let Some(peers) = self.inner.peers.get() {
            peers.send(core, note);
        }
    }

    fn owner(&self, message: MessageId) -> u16 {
        message.shard % self.inner.cores
    }

    fn handle(&self, note: Note) {
        match note {
            Note::Enqueue {
                queue,
                tenant,
                entry,
                due,
            } => {
                let now = self.inner.clock.now();
                self.inner
                    .lanes
                    .borrow_mut()
                    .enqueue(queue, tenant, entry, due, now);
                self.inner.notify.notify();
            }
            Note::Claim {
                route,
                recipients,
                forced,
            } => self.claim(route, &recipients, forced),
            Note::Claimed { route, answers } => self.claimed(route, answers),
            Note::Report { route, reports } => self.report(route, reports),
            Note::Reported {
                route,
                reports,
                done,
            } => self.reported(route, &reports, done),
        }
    }

    fn claim(&self, route: Route, recipients: &[Range<u32>], forced: bool) {
        let spool = &self.inner.spool;
        let now = self.inner.clock.now();
        let id = route.message;
        let mut answers = Vec::new();
        for r in recipients.iter().flat_map(Clone::clone) {
            let answer = match spool.recipient(id, r) {
                None => Claim::Gone,
                Some(state) if state.status.is_final() => Claim::Gone,
                Some(state) if !forced && state.due > now + self.inner.config.slack => {
                    Claim::Early(state.due)
                }
                Some(_) => match spool.claim(id, r) {
                    Ok(state) => {
                        if let Ok(stamp) = spool.stamp(id.shard) {
                            Claim::Claimed {
                                attempts: state.attempts,
                                class: state.class,
                                notified: state.notified,
                                stamp,
                            }
                        } else {
                            spool.release(id, &[r]);
                            Claim::Gone
                        }
                    }
                    Err(Error::State("ending")) => Claim::Ending,
                    Err(_) => Claim::Gone,
                },
            };
            answers.push((r, answer));
        }
        let core = queue_core(route.queue, self.inner.config.shards, self.inner.cores);
        self.send(core, Note::Claimed { route, answers });
    }

    fn claimed(&self, route: Route, answers: Vec<(u32, Claim)>) {
        let now = self.inner.clock.now();
        let mut relane = Vec::new();
        let mut claimed = Vec::new();
        let mut refused = 0;
        for (recipient, answer) in answers {
            match answer {
                Claim::Claimed {
                    attempts,
                    class,
                    notified,
                    stamp,
                } => claimed.push(Claimed {
                    recipient,
                    attempts,
                    class,
                    notified,
                    stamp,
                }),
                Claim::Early(due) => {
                    relane.push((recipient, due));
                    refused += 1;
                }
                Claim::Ending => {
                    relane.push((recipient, now + self.inner.config.ending));
                    refused += 1;
                }
                Claim::Gone => refused += 1,
            }
        }
        self.relane(route, relane, now);
        self.inner
            .lanes
            .borrow_mut()
            .done(route.queue, refused, now);
        self.inner.notify.notify();
        if claimed.is_empty() {
            return;
        }
        let sched = self.clone();
        drop(spawn(async move { sched.attempt(route, claimed).await }));
    }

    async fn attempt(&self, route: Route, claimed: Vec<Claimed>) {
        let id = self.inner.next_attempt.get();
        self.inner.next_attempt.set(id + 1);
        let started = self.inner.clock.now();
        self.inner.attempts.borrow_mut().insert(id, started);
        let attempt = Attempt {
            queue: route.queue,
            tenant: route.tenant,
            message: route.message,
            recipients: claimed.clone(),
        };
        let answers = self.inner.transport.send(attempt).await;
        self.inner.attempts.borrow_mut().remove(&id);
        let now = self.inner.clock.now();
        let mut by_recipient: BTreeMap<u32, Answered> =
            answers.into_iter().map(|a| (a.recipient, a)).collect();
        let reports = claimed
            .iter()
            .map(|c| {
                let answered = by_recipient.remove(&c.recipient);
                let answer = answered
                    .as_ref()
                    .map_or(Answer::Deferred(Kind::Temporary), |a| a.answer);
                let outcome = match answer {
                    Answer::Delivered => Outcome::Delivered,
                    Answer::Failed => Outcome::Failed,
                    Answer::Deferred(kind) => {
                        let (wait, class) = delay(kind, c.attempts.saturating_add(1));
                        Outcome::Deferred {
                            due: now + wait,
                            class,
                            notified: c.notified,
                        }
                    }
                };
                let reply = answered.filter(|a| !a.reply.is_empty()).map(|a| Reply {
                    stamp: c.stamp,
                    sealed: a.reply,
                });
                Report {
                    recipient: c.recipient,
                    outcome,
                    reply,
                }
            })
            .collect();
        self.send(self.owner(route.message), Note::Report { route, reports });
    }

    fn report(&self, route: Route, reports: Vec<Report>) {
        let sched = self.clone();
        drop(spawn(async move {
            let back: Vec<(u32, Option<u64>)> = reports
                .iter()
                .map(|r| match r.outcome {
                    Outcome::Deferred { due, .. } => (r.recipient, Some(due)),
                    Outcome::Delivered | Outcome::Failed => (r.recipient, None),
                })
                .collect();
            let recipients: Vec<u32> = back.iter().map(|(r, _)| *r).collect();
            let spool = &sched.inner.spool;
            let done = spool.report(route.message, reports).await.ok();
            if done.is_none() {
                spool.release(route.message, &recipients);
                sched
                    .inner
                    .report_errors
                    .set(sched.inner.report_errors.get() + 1);
            }
            let core = queue_core(route.queue, sched.inner.config.shards, sched.inner.cores);
            sched.send(
                core,
                Note::Reported {
                    route,
                    reports: back,
                    done,
                },
            );
        }));
    }

    fn reported(&self, route: Route, reports: &[(u32, Option<u64>)], done: Option<Done>) {
        let now = self.inner.clock.now();
        let relane = match done {
            Some(Done::Kept) => reports
                .iter()
                .filter_map(|(r, due)| due.map(|due| (*r, due)))
                .collect(),
            Some(Done::Dropped) => Vec::new(),
            None => reports
                .iter()
                .map(|(r, _)| (*r, now + BACKOFF[0]))
                .collect(),
        };
        self.relane(route, relane, now);
        let count = u32::try_from(reports.len()).expect("batch fits");
        self.inner.lanes.borrow_mut().done(route.queue, count, now);
        self.inner.notify.notify();
    }

    fn relane(&self, route: Route, recipients: Vec<(u32, u64)>, now: u64) {
        let mut by_due: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
        for (r, due) in recipients {
            by_due.entry(due).or_default().push(r);
        }
        let mut lanes = self.inner.lanes.borrow_mut();
        for (due, mut recipients) in by_due {
            recipients.sort_unstable();
            let entry = Entry {
                message: route.message,
                recipients: ranges(recipients),
                forced: false,
            };
            lanes.enqueue(route.queue, route.tenant, entry, due, now);
        }
    }

    fn dispatch(&self, take: &Take) {
        for entry in &take.entries {
            let route = Route {
                queue: take.queue,
                tenant: take.tenant,
                message: entry.message,
            };
            self.send(
                self.owner(entry.message),
                Note::Claim {
                    route,
                    recipients: entry.recipients.clone(),
                    forced: entry.forced,
                },
            );
        }
    }

    async fn expire(&self) {
        let inner = &self.inner;
        while !inner.closed.get() {
            let now = inner.clock.now();
            for id in inner.spool.expired(now) {
                if !inner.expiring.borrow_mut().insert(id) {
                    continue;
                }
                let sched = self.clone();
                drop(spawn(async move {
                    let inner = &sched.inner;
                    if inner.spool.expire(id, now).await.is_ok() {
                        inner.expired.set(inner.expired.get() + 1);
                    } else {
                        rt::sleep(std::time::Duration::from_millis(inner.config.ending)).await;
                    }
                    inner.expiring.borrow_mut().remove(&id);
                    inner.expiry.notify();
                }));
            }
            let next = inner.spool.next_expiry(now);
            self.wait(&inner.expiry, next).await;
        }
    }

    async fn wait(&self, notify: &Notify, deadline: Option<u64>) {
        let mut wake = pin!(notify.wait());
        match deadline {
            None => wake.await,
            Some(at) => {
                let mut timer = pin!(sleep_until(self.inner.clock.instant(at)));
                poll_fn(|cx| {
                    if wake.as_mut().poll(cx).is_ready() || timer.as_mut().poll(cx).is_ready() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
        }
    }

    async fn run(&self) {
        let inner = &self.inner;
        while !inner.closed.get() {
            let now = inner.clock.now();
            loop {
                let take = inner.lanes.borrow_mut().next(now);
                let Some(take) = take else { break };
                self.dispatch(&take);
            }
            let deadline = inner.lanes.borrow().deadline();
            self.wait(&inner.notify, deadline).await;
        }
    }
}
