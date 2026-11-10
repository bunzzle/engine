use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crypto::{DkimKey, Plain, Secret};
use rt::{Buf, Instant, Notify, Receiver, Sender};

use crate::audit::{Audit, Op};
use crate::cache::Cache;
use crate::limit::{Limits, Rate};
use crate::proto::{Answer, Frames, MAX_FRAME, Request};
use crate::signers::{Done, Job, Signers};
use crate::{Clock, Error, Keys, Step, Vault};

const DAY_MS: u64 = 86_400_000;
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
const IN_FLIGHT: usize = 1_024;
const DKIM_KEYS: usize = 4_096;

pub trait Stream {
    fn read(&self, buf: Buf) -> impl Future<Output = (io::Result<usize>, Buf)>;
    fn write_all(&self, buf: Buf) -> impl Future<Output = (io::Result<()>, Buf)>;
    fn shutdown(&self) -> impl Future<Output = io::Result<()>>;
}

impl Stream for rt::TcpStream {
    fn read(&self, buf: Buf) -> impl Future<Output = (io::Result<usize>, Buf)> {
        rt::TcpStream::read(self, buf)
    }

    fn write_all(&self, buf: Buf) -> impl Future<Output = (io::Result<()>, Buf)> {
        rt::TcpStream::write_all(self, buf)
    }

    fn shutdown(&self) -> impl Future<Output = io::Result<()>> {
        rt::TcpStream::shutdown(self)
    }
}

impl Stream for rt::UnixStream {
    fn read(&self, buf: Buf) -> impl Future<Output = (io::Result<usize>, Buf)> {
        rt::UnixStream::read(self, buf)
    }

    fn write_all(&self, buf: Buf) -> impl Future<Output = (io::Result<()>, Buf)> {
        rt::UnixStream::write_all(self, buf)
    }

    fn shutdown(&self) -> impl Future<Output = io::Result<()>> {
        rt::UnixStream::shutdown(self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub tenant: Rate,
    pub node: Rate,
    pub pace: Duration,
    pub force_after: Duration,
    pub tick: Duration,
    pub signers: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tenant: Rate {
                per_second: 1_000,
                burst: 10_000,
            },
            node: Rate {
                per_second: 20_000,
                burst: 50_000,
            },
            pace: Duration::from_secs(1),
            force_after: Duration::from_hours(6),
            tick: Duration::from_millis(100),
            signers: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub days: u64,
    pub behind: u64,
    pub ahead: u64,
    pub busy: u64,
    pub forced: u64,
    pub failed: u64,
    pub refused: u64,
    pub dkim_new: u64,
    pub loads: u64,
    pub signs: u64,
    pub dkim_busy: u64,
    pub conflicts: u64,
}

enum Command {
    Call(Request, Sender<Answer>),
    Refused(u32),
    Tick,
    Dkim(Finished),
}

struct Finished {
    reply: Sender<Answer>,
    id: (u32, u32, u32),
    blob: Option<Arc<[u8]>>,
    deletes: u64,
    done: Done,
}

#[derive(Clone)]
struct DkimEntry {
    key: Arc<DkimKey>,
    blob: Arc<[u8]>,
}

pub struct Server {
    commands: Sender<Command>,
    stats: Rc<RefCell<Stats>>,
}

impl Server {
    pub fn start(vault: Vault, audit: Audit, settings: Settings) -> Self {
        let (commands, receiver) = rt::channel();
        let stats = Rc::new(RefCell::new(Stats::default()));
        let core = Core {
            limits: Limits::new(settings.tenant, settings.node, rt::now()),
            vault,
            audit,
            settings,
            stats: Rc::clone(&stats),
            waiting: Vec::new(),
            last_write: None,
            clock: Clock::default(),
            last_step: Step::Wait,
            settled: None,
            force_at: None,
            commands: commands.clone(),
            signers: Signers::new(settings.signers),
            dkim: Cache::new(DKIM_KEYS),
            jobs: 0,
            deletes: 0,
        };
        rt::spawn(core.run(receiver));
        let ticker = commands.clone();
        rt::spawn(async move {
            loop {
                rt::sleep(settings.tick).await;
                if ticker.send(Command::Tick).is_err() {
                    break;
                }
            }
        });
        Self { commands, stats }
    }

    pub fn serve<S: Stream + 'static>(&self, stream: S) {
        rt::spawn(connection(stream, self.commands.clone()));
    }

    pub fn listen(&self, listener: rt::UnixListener, peer: u32) -> rt::JoinHandle<io::Error> {
        rt::spawn(accept(listener, peer, self.commands.clone()))
    }

    pub fn stats(&self) -> Stats {
        *self.stats.borrow()
    }
}

struct Core {
    vault: Vault,
    audit: Audit,
    limits: Limits,
    settings: Settings,
    stats: Rc<RefCell<Stats>>,
    waiting: Vec<(u32, u32, Sender<Answer>)>,
    last_write: Option<Instant>,
    clock: Clock,
    last_step: Step,
    settled: Option<u32>,
    force_at: Option<Instant>,
    commands: Sender<Command>,
    signers: Signers,
    dkim: Cache<(u32, u32, u32), DkimEntry>,
    jobs: usize,
    deletes: u64,
}

fn keys_answer(keys: Keys) -> Answer {
    Answer::Keys {
        day: keys.day,
        oldest: keys.oldest,
        version: keys.version,
        data: keys.data,
        hash: keys.hash,
        today: keys.today,
        tomorrow: keys.tomorrow,
    }
}

impl Core {
    async fn run(mut self, mut commands: Receiver<Command>) {
        while let Some(command) = commands.recv().await {
            match command {
                Command::Call(request, reply) => {
                    if let Some(answer) = self.call(request, &reply).await {
                        let _ = reply.send(answer);
                    }
                }
                Command::Refused(uid) => {
                    self.stats.borrow_mut().refused += 1;
                    self.audit.note(Op::Refused, uid, 0, self.vault.day());
                }
                Command::Tick => self.tick().await,
                Command::Dkim(finished) => {
                    let reply = finished.reply.clone();
                    let _ = reply.send(self.finished(finished));
                }
            }
            self.answer_waiting();
        }
    }

    fn refused(&self, error: Error) -> Answer {
        if error == Error::Failed {
            self.stats.borrow_mut().failed += 1;
        }
        Answer::Refused(error)
    }

    async fn call(&mut self, request: Request, reply: &Sender<Answer>) -> Option<Answer> {
        let answer = match request {
            Request::Hello { .. } => match Secret::from_slice(self.vault.naming().expose()) {
                Ok(naming) => Answer::Hello {
                    day: self.vault.day(),
                    naming,
                },
                Err(_) => self.refused(Error::Failed),
            },
            Request::Create {
                tenant,
                generation,
                retention,
            } => match self.vault.create(tenant, generation, retention) {
                Ok(()) => {
                    self.audit
                        .note(Op::Create, tenant, generation, self.vault.day());
                    match self.vault.keys(tenant, generation) {
                        Ok(keys) => keys_answer(keys),
                        Err(Error::Pending) => {
                            self.waiting.push((tenant, generation, reply.clone()));
                            return None;
                        }
                        Err(error) => self.refused(error),
                    }
                }
                Err(error) => self.refused(error),
            },
            Request::Open { tenant, generation } => {
                self.audit
                    .note(Op::Open, tenant, generation, self.vault.day());
                match self.vault.keys(tenant, generation) {
                    Ok(keys) => keys_answer(keys),
                    Err(error) => self.refused(error),
                }
            }
            Request::Unwrap {
                tenant,
                batch,
                wrap,
            } => {
                if self.limits.take(tenant, rt::now()) {
                    self.audit
                        .note(Op::Unwrap, tenant, wrap.generation, wrap.day);
                    match self.vault.unwrap(tenant, batch, &wrap) {
                        Ok(key) => Answer::Key(key),
                        Err(error) => self.refused(error),
                    }
                } else {
                    self.stats.borrow_mut().busy += 1;
                    self.audit.note(Op::Busy, tenant, wrap.generation, wrap.day);
                    Answer::Refused(Error::Busy)
                }
            }
            Request::Retention {
                tenant,
                generation,
                days,
            } => match self.vault.set_retention(tenant, generation, days).await {
                Ok(()) => {
                    self.audit
                        .note(Op::Retention, tenant, generation, u32::from(days));
                    Answer::Done
                }
                Err(error) => self.refused(error),
            },
            Request::Settled { day } => {
                self.settled = Some(self.settled.map_or(day, |known| known.max(day)));
                if self.force_at.is_some() {
                    match self.vault.shred(self.settled, false).await {
                        Ok(true) => self.audit.note(Op::Shred, 0, 0, self.vault.day()),
                        Ok(false) => {}
                        Err(error) => return Some(self.refused(error)),
                    }
                }
                Answer::Done
            }
            Request::DkimNew { .. } | Request::Load { .. } | Request::Sign { .. } => {
                return self.dkim_call(request, reply);
            }
            Request::Delete { tenant, generation } => {
                self.dkim.retain(|id, _| id.0 != tenant);
                if self.vault.holds(tenant, generation) {
                    self.deletes += 1;
                }
                match self.vault.delete(tenant, generation).await {
                    Ok(()) => {
                        self.audit
                            .note(Op::Delete, tenant, generation, self.vault.day());
                        Answer::Done
                    }
                    Err(error) => self.refused(error),
                }
            }
        };
        Some(answer)
    }

    fn dkim_call(&mut self, request: Request, reply: &Sender<Answer>) -> Option<Answer> {
        match request {
            Request::DkimNew {
                tenant,
                generation,
                key,
                alg,
            } => {
                let seal = match self.vault.dkim(tenant, generation) {
                    Ok(seal) => seal,
                    Err(error) => return Some(self.refused(error)),
                };
                if self.dkim.peek(&(tenant, generation, key)).is_some() {
                    self.stats.borrow_mut().conflicts += 1;
                    return Some(Answer::Refused(Error::Conflict));
                }
                let job = Job::New {
                    tenant,
                    generation,
                    key,
                    alg,
                    seal,
                };
                self.submit(job, reply, (tenant, generation, key), None)
            }
            Request::Load {
                tenant,
                generation,
                key,
                alg,
                blob,
            } => {
                let seal = match self.vault.dkim(tenant, generation) {
                    Ok(seal) => seal,
                    Err(error) => return Some(self.refused(error)),
                };
                if let Some(cached) = self.dkim.peek(&(tenant, generation, key)) {
                    if cached.key.alg() == alg && *cached.blob == blob[..] {
                        return Some(Answer::Done);
                    }
                    self.stats.borrow_mut().conflicts += 1;
                    return Some(Answer::Refused(Error::Conflict));
                }
                let blob: Arc<[u8]> = blob.into();
                let job = Job::Load {
                    tenant,
                    generation,
                    key,
                    alg,
                    blob: Arc::clone(&blob),
                    seal,
                };
                self.submit(job, reply, (tenant, generation, key), Some(blob))
            }
            Request::Sign {
                tenant,
                generation,
                key,
                alg,
                digest,
            } => {
                if let Err(error) = self.vault.active(tenant, generation) {
                    return Some(self.refused(error));
                }
                let Some(cached) = self.dkim.get(&(tenant, generation, key)) else {
                    return Some(Answer::Refused(Error::Unknown));
                };
                if cached.key.alg() != alg {
                    return Some(Answer::Refused(Error::Open));
                }
                let job = Job::Sign {
                    key: cached.key,
                    digest,
                };
                self.submit(job, reply, (tenant, generation, key), None)
            }
            _ => Some(Answer::Refused(Error::Bad)),
        }
    }

    fn submit(
        &mut self,
        job: Job,
        reply: &Sender<Answer>,
        id: (u32, u32, u32),
        blob: Option<Arc<[u8]>>,
    ) -> Option<Answer> {
        if self.jobs >= self.signers.limit() {
            self.stats.borrow_mut().dkim_busy += 1;
            return Some(Answer::Refused(Error::Busy));
        }
        self.jobs += 1;
        let commands = self.commands.clone();
        let reply = reply.clone();
        let deletes = self.deletes;
        self.signers.submit(job, move |done| {
            let _ = commands.send(Command::Dkim(Finished {
                reply,
                id,
                blob,
                deletes,
                done,
            }));
        });
        None
    }

    fn finished(&mut self, finished: Finished) -> Answer {
        self.jobs -= 1;
        let Finished {
            id,
            blob,
            deletes,
            done,
            ..
        } = finished;
        if deletes != self.deletes {
            return Answer::Refused(Error::Busy);
        }
        let (tenant, generation, key) = id;
        match done {
            Done::New(Some((made, public, sealed))) => {
                if self.dkim.peek(&id).is_some() {
                    self.stats.borrow_mut().conflicts += 1;
                    return Answer::Refused(Error::Conflict);
                }
                let entry = DkimEntry {
                    key: made,
                    blob: sealed.clone().into(),
                };
                self.dkim.put(id, entry);
                self.stats.borrow_mut().dkim_new += 1;
                self.audit.note(Op::DkimNew, tenant, generation, key);
                Answer::Dkim {
                    public,
                    blob: sealed,
                }
            }
            Done::Loaded(Some(opened)) => {
                let blob = blob.unwrap_or_else(|| Arc::from(Vec::new()));
                if let Some(cached) = self.dkim.peek(&id) {
                    if cached.key.alg() == opened.alg() && cached.blob == blob {
                        return Answer::Done;
                    }
                    self.stats.borrow_mut().conflicts += 1;
                    return Answer::Refused(Error::Conflict);
                }
                self.dkim.put(id, DkimEntry { key: opened, blob });
                self.stats.borrow_mut().loads += 1;
                self.audit.note(Op::Load, tenant, generation, key);
                Answer::Done
            }
            Done::Signed(Some(signature)) => {
                self.stats.borrow_mut().signs += 1;
                Answer::Signature(signature)
            }
            Done::Loaded(None) => Answer::Refused(Error::Open),
            Done::New(None) | Done::Signed(None) => self.refused(Error::Failed),
        }
    }

    async fn tick(&mut self) {
        let now = rt::now();
        let wall_ms = rt::wall_ms();
        if self.vault.is_dirty()
            && self
                .last_write
                .is_none_or(|at| now.saturating_duration_since(at) >= self.settings.pace)
            && self.vault.flush().await.is_ok()
        {
            self.last_write = Some(now);
        }
        let wall_day = u32::try_from(wall_ms / DAY_MS).unwrap_or(u32::MAX);
        let step = self.clock.step(self.vault.day(), wall_day, now);
        match step {
            Step::Move => {
                if self.vault.new_day(self.settled, false).await.is_ok() {
                    self.clock.moved(now);
                    self.force_at = Some(now + self.settings.force_after);
                    self.last_write = Some(now);
                    self.stats.borrow_mut().days += 1;
                    self.audit.note(Op::Day, 0, 0, self.vault.day());
                }
            }
            Step::Behind if self.last_step != Step::Behind => self.stats.borrow_mut().behind += 1,
            Step::Ahead if self.last_step != Step::Ahead => self.stats.borrow_mut().ahead += 1,
            _ => {}
        }
        self.last_step = step;
        if self.force_at.is_some_and(|at| now >= at) {
            self.force_at = None;
            if let Ok(true) = self.vault.shred(self.settled, true).await {
                self.stats.borrow_mut().forced += 1;
                self.audit.note(Op::Forced, 0, 0, self.vault.day());
            }
        }
        let _ = self.audit.flush(wall_ms).await;
    }

    fn answer_waiting(&mut self) {
        let vault = &self.vault;
        self.waiting.retain(
            |(tenant, generation, reply)| match vault.keys(*tenant, *generation) {
                Err(Error::Pending) => true,
                Ok(keys) => {
                    let _ = reply.send(keys_answer(keys));
                    false
                }
                Err(error) => {
                    let _ = reply.send(Answer::Refused(error));
                    false
                }
            },
        );
    }
}

async fn accept(listener: rt::UnixListener, peer: u32, commands: Sender<Command>) -> io::Error {
    loop {
        match listener.accept().await {
            Ok((stream, uid)) if uid == peer => {
                rt::spawn(connection(stream, commands.clone()));
            }
            Ok((stream, uid)) => {
                drop(stream);
                let _ = commands.send(Command::Refused(uid));
            }
            Err(error) if sys::net::transient(&error) => rt::sleep(ACCEPT_PAUSE).await,
            Err(error) => return error,
        }
    }
}

struct Room {
    free: Cell<usize>,
    freed: Notify,
    closed: Cell<bool>,
}

async fn connection<S: Stream + 'static>(stream: S, commands: Sender<Command>) {
    let stream = Rc::new(stream);
    let room = Rc::new(Room {
        free: Cell::new(IN_FLIGHT),
        freed: Notify::default(),
        closed: Cell::new(false),
    });
    let (answers, outgoing) = rt::channel();
    rt::spawn(write_answers(
        Rc::clone(&stream),
        outgoing,
        Rc::clone(&room),
    ));
    let mut frames = Frames::default();
    loop {
        let (read, buf) = stream.read(Buf::new(MAX_FRAME)).await;
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        frames.push(&buf[..n]);
        loop {
            let (op, id, body) = match frames.pop() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => {
                    room.closed.set(true);
                    return;
                }
            };
            while room.free.get() == 0 && !room.closed.get() {
                room.freed.wait().await;
            }
            if room.closed.get() {
                return;
            }
            room.free.set(room.free.get() - 1);
            match Request::decode(op, &body) {
                Ok(request) => {
                    let (reply, mut answer) = rt::channel();
                    if commands.send(Command::Call(request, reply)).is_err() {
                        room.closed.set(true);
                        return;
                    }
                    let answers = answers.clone();
                    rt::spawn(async move {
                        let answer = answer
                            .recv()
                            .await
                            .unwrap_or(Answer::Refused(Error::Failed));
                        let _ = answers.send((id, answer));
                    });
                }
                Err(error) => {
                    let _ = answers.send((id, Answer::Refused(error)));
                }
            }
        }
    }
    room.closed.set(true);
    room.freed.notify();
}

async fn write_answers<S: Stream>(
    stream: Rc<S>,
    mut outgoing: Receiver<(u32, Answer)>,
    room: Rc<Room>,
) {
    while let Some(first) = outgoing.recv().await {
        let mut batch = vec![first];
        while let Some(more) = outgoing.try_recv() {
            batch.push(more);
        }
        let mut out = Plain::with_capacity(batch.iter().map(|(_, a)| a.size()).sum());
        for (id, answer) in &batch {
            answer.encode(*id, &mut out);
        }
        let count = batch.len();
        drop(batch);
        let (written, mut buf) = stream.write_all(Buf::from_slice(&out)).await;
        sys::mem::wipe(&mut buf);
        if written.is_err() {
            room.closed.set(true);
            room.freed.notify();
            return;
        }
        room.free.set(room.free.get() + count);
        room.freed.notify();
    }
}
