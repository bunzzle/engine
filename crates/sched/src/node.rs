use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::ops::Range;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;

use control::{Tenancy, queue_shard};
use rt::{Ends, JoinHandle, Notify, Peers, sleep_until, spawn};
use spool::{
    Done, Error, Message, MessageId, Outcome, Pending, Reply, Report, Spool, Stamp, Stored,
};

use crate::clock::Clock;
use crate::lanes::{Entry, Lanes, Limits, QueueId, Take, ranges};
use crate::policy::{Answer, BACKOFF, Kind, clamp, delay, report_retry};
use crate::sealing::{Keys, Unsealable};
use crate::transport::{Answered, Attempt, Claimed, Transport};
use crate::unopened::{Action, Breaker, UnopenedStats, action};

const HOLD: u64 = 3_600_000;
const QUARANTINE: u64 = u64::MAX / 2;
const UNREADABLE: u64 = 30_000;
const DAMAGED_TRIES: u8 = 3;
const DAMAGED_KEPT: usize = 4096;

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
        generation: u32,
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
        stored: Option<Stored>,
    },
    Report {
        route: Route,
        reports: Vec<Report>,
    },
    Reported {
        route: Route,
        reports: Vec<(u32, Option<u64>)>,
        done: Option<Done>,
        wait: u64,
    },
    Low {
        core: u16,
        day: u32,
    },
    Released {
        route: Route,
        recipients: Vec<(u32, u64)>,
    },
    Dropped {
        route: Route,
        recipients: Vec<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrival {
    pub id: MessageId,
    pub tenant: u32,
    pub generation: u32,
    pub due: u64,
    pub queues: Vec<QueueId>,
}

impl Arrival {
    pub fn of(message: &Message, generation: u32) -> Self {
        let clear = &message.head.clear;
        Self {
            id: message.id,
            tenant: message.tenant,
            generation,
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
    queue_shard(queue, shards) % cores
}

struct Inner<T> {
    config: Config,
    index: u16,
    cores: u16,
    lows: RefCell<BTreeMap<u16, u32>>,
    keys: OnceCell<Rc<dyn Keys>>,
    breaker: RefCell<Breaker>,
    clock: Clock,
    spool: Spool,
    transport: T,
    tenancy: Rc<dyn Tenancy>,
    lanes: RefCell<Lanes>,
    peers: OnceCell<Peers<Note>>,
    notify: Notify,
    expiry: Notify,
    expiring: RefCell<BTreeSet<MessageId>>,
    expired: Cell<u64>,
    closed: Cell<bool>,
    attempts: RefCell<BTreeMap<u64, u64>>,
    next_attempt: Cell<u64>,
    report_errors: Cell<ReportErrors>,
    report_streak: Cell<u32>,
    refused: Cell<u64>,
    unreadable: Cell<u64>,
    damaged: RefCell<BTreeMap<MessageId, u8>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReportErrors {
    pub space: u64,
    pub busy: u64,
    pub failed: u64,
    pub other: u64,
}

impl ReportErrors {
    pub fn total(self) -> u64 {
        self.space + self.busy + self.failed + self.other
    }

    pub fn count(&mut self, error: &Error) {
        use store::Error as E;
        match error {
            Error::Store(E::Full | E::Reserve | E::JournalFull) => self.space += 1,
            Error::Store(E::Busy) => self.busy += 1,
            Error::Store(E::Failed | E::Io(_)) => self.failed += 1,
            _ => self.other += 1,
        }
    }
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
        tenancy: Rc<dyn Tenancy>,
        clock: Clock,
        config: Config,
    ) -> (Self, JoinHandle<()>) {
        let inner = Rc::new(Inner {
            config,
            index: ends.index(),
            cores: ends.cores(),
            lows: RefCell::new(BTreeMap::new()),
            keys: OnceCell::new(),
            breaker: RefCell::new(Breaker::default()),
            clock,
            spool,
            transport,
            tenancy,
            lanes: RefCell::new(Lanes::new(config.limits)),
            peers: OnceCell::new(),
            notify: Notify::default(),
            expiry: Notify::default(),
            expiring: RefCell::new(BTreeSet::new()),
            expired: Cell::new(0),
            closed: Cell::new(false),
            attempts: RefCell::new(BTreeMap::new()),
            next_attempt: Cell::new(0),
            report_errors: Cell::new(ReportErrors::default()),
            report_streak: Cell::new(0),
            refused: Cell::new(0),
            unreadable: Cell::new(0),
            damaged: RefCell::new(BTreeMap::new()),
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

    pub fn report_errors(&self) -> ReportErrors {
        self.inner.report_errors.get()
    }

    pub fn refused(&self) -> u64 {
        self.inner.refused.get()
    }

    pub fn unreadable(&self) -> u64 {
        self.inner.unreadable.get()
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
                    generation: arrival.generation,
                    entry,
                    due: arrival.due,
                },
            );
        }
        self.inner.expiry.notify();
    }

    pub fn restore(&self, pending: Vec<Pending>, generation: impl Fn(u32) -> Option<u32>) {
        let now = self.inner.clock.now();
        for message in pending {
            let Some(generation) = generation(message.tenant) else {
                self.refuse();
                continue;
            };
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
                        generation,
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

    pub fn use_keys(&self, keys: Rc<dyn Keys>) {
        let _ = self.inner.keys.set(keys);
    }

    pub fn unopened_stats(&self) -> UnopenedStats {
        self.inner.breaker.borrow().stats.clone()
    }

    pub fn report_low(&self, day: u32) {
        match self.inner.index {
            0 => {
                self.inner.lows.borrow_mut().insert(0, day);
            }
            core => self.send(0, Note::Low { core, day }),
        }
    }

    pub fn settled_low(&self) -> Option<u32> {
        let lows = self.inner.lows.borrow();
        if lows.len() < usize::from(self.inner.cores) {
            return None;
        }
        lows.values().copied().min()
    }

    fn send(&self, core: u16, note: Note) {
        if let Some(peers) = self.inner.peers.get() {
            peers.send(core, note);
        }
    }

    fn refuse(&self) {
        self.inner.refused.set(self.inner.refused.get() + 1);
    }

    fn owner(&self, message: MessageId) -> u16 {
        message.shard % self.inner.cores
    }

    fn handle(&self, note: Note) {
        match note {
            Note::Enqueue {
                queue,
                tenant,
                generation,
                entry,
                due,
            } => {
                if self.inner.tenancy.holder(queue) != Some((tenant, generation)) {
                    self.refuse();
                    return;
                }
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
            Note::Claimed {
                route,
                answers,
                stored,
            } => self.claimed(route, answers, stored),
            Note::Report { route, reports } => self.report(route, reports),
            Note::Reported {
                route,
                reports,
                done,
                wait,
            } => self.reported(route, &reports, done, wait),
            Note::Low { core, day } => {
                if self.inner.index != 0 || core >= self.inner.cores {
                    self.refuse();
                    return;
                }
                self.inner.lows.borrow_mut().insert(core, day);
            }
            Note::Released { route, recipients } => self.released(route, recipients),
            Note::Dropped { route, recipients } => self.dropped(route, recipients),
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
        if !answers
            .iter()
            .any(|(_, a)| matches!(a, Claim::Claimed { .. }))
        {
            self.send(
                core,
                Note::Claimed {
                    route,
                    answers,
                    stored: None,
                },
            );
            return;
        }
        let sched = self.clone();
        drop(spawn(async move {
            let spool = &sched.inner.spool;
            let stored = spool.stored(id).await.ok();
            if stored.is_none() {
                let due = sched.inner.clock.now() + UNREADABLE;
                for (r, answer) in &mut answers {
                    if matches!(answer, Claim::Claimed { .. }) {
                        spool.release(id, &[*r]);
                        *answer = Claim::Early(due);
                    }
                }
            }
            sched.send(
                core,
                Note::Claimed {
                    route,
                    answers,
                    stored,
                },
            );
        }));
    }

    fn claimed(&self, route: Route, answers: Vec<(u32, Claim)>, stored: Option<Stored>) {
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
        let Some(stored) = stored.filter(|_| !claimed.is_empty()) else {
            return;
        };
        let sched = self.clone();
        drop(spawn(
            async move { sched.attempt(route, claimed, stored).await },
        ));
    }

    async fn attempt(&self, route: Route, mut claimed: Vec<Claimed>, stored: Stored) {
        let opened = if stored.tenant == route.tenant && stored.id == route.message {
            self.inner.spool.open_stored(&stored).await
        } else {
            Err(Error::State("tenant"))
        };
        let message = match opened {
            Ok(message) => {
                self.inner.damaged.borrow_mut().remove(&route.message);
                message
            }
            Err(error) => {
                self.skip(route, &claimed, &error);
                return;
            }
        };
        let id = self.inner.next_attempt.get();
        self.inner.next_attempt.set(id + 1);
        let started = self.inner.clock.now();
        self.inner.attempts.borrow_mut().insert(id, started);
        let attempt = Attempt {
            queue: route.queue,
            tenant: route.tenant,
            message: route.message,
            recipients: claimed.clone(),
            stored: message,
        };
        let answers = self.inner.transport.send(attempt).await;
        self.inner.attempts.borrow_mut().remove(&id);
        let now = self.inner.clock.now();
        let mut by_recipient: BTreeMap<u32, Answered> =
            answers.into_iter().map(|a| (a.recipient, a)).collect();
        let unopened = by_recipient.values().find_map(|a| match a.answer {
            Answer::Unopened {
                fault,
                generation,
                day,
            } => Some((fault, generation, day)),
            _ => None,
        });
        if let Some((fault, generation, day)) = unopened {
            let (shut, open): (Vec<Claimed>, Vec<Claimed>) = claimed.into_iter().partition(|c| {
                by_recipient
                    .get(&c.recipient)
                    .is_some_and(|a| matches!(a.answer, Answer::Unopened { .. }))
            });
            let mixed = !open.is_empty();
            self.unopened(route, &shut, fault, generation, day, mixed)
                .await;
            if !mixed {
                return;
            }
            claimed = open;
        }
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
                    Answer::Unopened { .. } => {
                        let (wait, class) = delay(Kind::Temporary, c.attempts.saturating_add(1));
                        Outcome::Deferred {
                            due: now + wait,
                            class,
                            notified: c.notified,
                        }
                    }
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

    fn skip(&self, route: Route, claimed: &[Claimed], error: &Error) {
        self.inner.unreadable.set(self.inner.unreadable.get() + 1);
        let now = self.inner.clock.now();
        let tries = if matches!(error, Error::Store(store::Error::Damaged { .. })) {
            let mut damaged = self.inner.damaged.borrow_mut();
            if damaged.len() >= DAMAGED_KEPT && !damaged.contains_key(&route.message) {
                damaged.clear();
            }
            let tries = damaged.entry(route.message).or_default();
            *tries += 1;
            *tries
        } else {
            0
        };
        let note = if tries >= DAMAGED_TRIES {
            self.inner.damaged.borrow_mut().remove(&route.message);
            Note::Report {
                route,
                reports: claimed
                    .iter()
                    .map(|c| {
                        let (wait, class) = delay(Kind::Temporary, c.attempts.saturating_add(1));
                        Report {
                            recipient: c.recipient,
                            outcome: Outcome::Deferred {
                                due: now + wait,
                                class,
                                notified: c.notified,
                            },
                            reply: None,
                        }
                    })
                    .collect(),
            }
        } else {
            Note::Released {
                route,
                recipients: claimed
                    .iter()
                    .map(|c| (c.recipient, now + UNREADABLE))
                    .collect(),
            }
        };
        self.send(self.owner(route.message), note);
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
            let written = spool.report(route.message, reports).await;
            let streak = &sched.inner.report_streak;
            let wait = match &written {
                Ok(_) => {
                    streak.set(0);
                    0
                }
                Err(error) => {
                    spool.release(route.message, &recipients);
                    let mut errors = sched.inner.report_errors.get();
                    errors.count(error);
                    sched.inner.report_errors.set(errors);
                    streak.set(streak.get().saturating_add(1));
                    report_retry(streak.get())
                }
            };
            let core = queue_core(route.queue, sched.inner.config.shards, sched.inner.cores);
            sched.send(
                core,
                Note::Reported {
                    route,
                    reports: back,
                    done: written.ok(),
                    wait,
                },
            );
        }));
    }

    fn reported(
        &self,
        route: Route,
        reports: &[(u32, Option<u64>)],
        done: Option<Done>,
        wait: u64,
    ) {
        let now = self.inner.clock.now();
        let relane = match done {
            Some(Done::Kept) => reports
                .iter()
                .filter_map(|(r, due)| due.map(|due| (*r, due)))
                .collect(),
            Some(Done::Dropped) => Vec::new(),
            None => reports
                .iter()
                .map(|(r, due)| (*r, due.unwrap_or(0).max(now + wait)))
                .collect(),
        };
        self.relane(route, relane, now);
        let count = u32::try_from(reports.len()).expect("batch fits");
        self.inner.lanes.borrow_mut().done(route.queue, count, now);
        self.inner.notify.notify();
    }

    async fn unopened(
        &self,
        route: Route,
        claimed: &[Claimed],
        fault: Unsealable,
        generation: u32,
        day: u32,
        mixed: bool,
    ) {
        let now = self.inner.clock.now();
        let mut oldest = None;
        if fault == Unsealable::Gone && !mixed {
            let room = self.inner.breaker.borrow_mut().room(now);
            if let (true, Some(keys)) = (room, self.inner.keys.get()) {
                oldest = keys.oldest(route.tenant, generation).await.ok();
            }
        }
        let now = self.inner.clock.now();
        let forgotten = self
            .inner
            .keys
            .get()
            .is_some_and(|keys| keys.forgotten(route.tenant, generation));
        let chosen = if forgotten {
            self.inner.breaker.borrow_mut().forgotten()
        } else {
            self.inner
                .breaker
                .borrow_mut()
                .decide(route.tenant, action(fault, day, oldest), now)
        };
        let note = match chosen {
            Action::Drop => Note::Dropped {
                route,
                recipients: claimed.iter().map(|c| c.recipient).collect(),
            },
            Action::Quarantine => Note::Report {
                route,
                reports: claimed
                    .iter()
                    .map(|c| Report {
                        recipient: c.recipient,
                        outcome: Outcome::Deferred {
                            due: QUARANTINE,
                            class: c.class,
                            notified: c.notified,
                        },
                        reply: None,
                    })
                    .collect(),
            },
            Action::Hold | Action::Defer => {
                let wait = if chosen == Action::Hold {
                    HOLD
                } else {
                    BACKOFF[0]
                };
                Note::Released {
                    route,
                    recipients: claimed.iter().map(|c| (c.recipient, now + wait)).collect(),
                }
            }
        };
        self.send(self.owner(route.message), note);
    }

    fn released(&self, route: Route, recipients: Vec<(u32, u64)>) {
        let ids: Vec<u32> = recipients.iter().map(|(r, _)| *r).collect();
        self.inner.spool.release(route.message, &ids);
        let core = queue_core(route.queue, self.inner.config.shards, self.inner.cores);
        self.send(
            core,
            Note::Reported {
                route,
                reports: recipients
                    .into_iter()
                    .map(|(r, due)| (r, Some(due)))
                    .collect(),
                done: None,
                wait: 0,
            },
        );
    }

    fn dropped(&self, route: Route, recipients: Vec<u32>) {
        let sched = self.clone();
        drop(spawn(async move {
            let spool = &sched.inner.spool;
            spool.release(route.message, &recipients);
            let done = spool
                .cancel(route.message)
                .await
                .ok()
                .map(|()| Done::Dropped);
            let now = sched.inner.clock.now();
            let reports = recipients
                .into_iter()
                .map(|r| (r, done.is_none().then_some(now + HOLD)))
                .collect();
            let core = queue_core(route.queue, sched.inner.config.shards, sched.inner.cores);
            sched.send(
                core,
                Note::Reported {
                    route,
                    reports,
                    done,
                    wait: BACKOFF[0],
                },
            );
        }));
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
