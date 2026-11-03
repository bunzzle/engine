use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::time::Duration;

use crypto::{Plain, Secret};
use rt::{Buf, Instant, Receiver, Sender};

use crate::audit::{Audit, Op};
use crate::limit::{Limits, Rate};
use crate::proto::{Answer, Frames, MAX_FRAME, Request};
use crate::{Clock, Error, Keys, Step, Vault};

const DAY_MS: u64 = 86_400_000;
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

pub trait Stream {
    fn read(&self, buf: Buf) -> impl Future<Output = (io::Result<usize>, Buf)>;
    fn write_all(&self, buf: Buf) -> impl Future<Output = (io::Result<()>, Buf)>;
}

impl Stream for rt::TcpStream {
    fn read(&self, buf: Buf) -> impl Future<Output = (io::Result<usize>, Buf)> {
        rt::TcpStream::read(self, buf)
    }

    fn write_all(&self, buf: Buf) -> impl Future<Output = (io::Result<()>, Buf)> {
        rt::TcpStream::write_all(self, buf)
    }
}

impl Stream for rt::UnixStream {
    fn read(&self, buf: Buf) -> impl Future<Output = (io::Result<usize>, Buf)> {
        rt::UnixStream::read(self, buf)
    }

    fn write_all(&self, buf: Buf) -> impl Future<Output = (io::Result<()>, Buf)> {
        rt::UnixStream::write_all(self, buf)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub tenant: Rate,
    pub node: Rate,
    pub pace: Duration,
    pub force_after: Duration,
    pub tick: Duration,
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
}

enum Command {
    Call(Request, Sender<Answer>),
    Tick,
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

    pub fn listen(&self, listener: rt::UnixListener, peer: u32) {
        rt::spawn(accept(
            listener,
            peer,
            self.commands.clone(),
            Rc::clone(&self.stats),
        ));
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
}

fn keys_answer(keys: Keys) -> Answer {
    Answer::Keys {
        day: keys.day,
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
                Command::Tick => self.tick().await,
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
            Request::Delete { tenant, generation } => {
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

async fn accept(
    listener: rt::UnixListener,
    peer: u32,
    commands: Sender<Command>,
    stats: Rc<RefCell<Stats>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, uid)) if uid == peer => {
                rt::spawn(connection(stream, commands.clone()));
            }
            Ok(_) => stats.borrow_mut().refused += 1,
            Err(_) => rt::sleep(ACCEPT_PAUSE).await,
        }
    }
}

enum Call {
    Waiting(Receiver<Answer>),
    Ready(Answer),
}

async fn connection<S: Stream>(stream: S, commands: Sender<Command>) {
    let mut frames = Frames::default();
    loop {
        let (read, buf) = stream.read(Buf::new(MAX_FRAME)).await;
        let n = match read {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        frames.push(&buf[..n]);
        let mut calls = Vec::new();
        loop {
            match frames.pop() {
                Ok(Some((op, id, body))) => match Request::decode(op, &body) {
                    Ok(request) => {
                        let (reply, answer) = rt::channel();
                        if commands.send(Command::Call(request, reply)).is_err() {
                            return;
                        }
                        calls.push((id, Call::Waiting(answer)));
                    }
                    Err(error) => calls.push((id, Call::Ready(Answer::Refused(error)))),
                },
                Ok(None) => break,
                Err(_) => return,
            }
        }
        let mut answers = Vec::with_capacity(calls.len());
        for (id, call) in calls {
            let answer = match call {
                Call::Waiting(mut answer) => answer
                    .recv()
                    .await
                    .unwrap_or(Answer::Refused(Error::Failed)),
                Call::Ready(answer) => answer,
            };
            answers.push((id, answer));
        }
        let mut out = Plain::with_capacity(answers.iter().map(|(_, a)| a.size()).sum());
        for (id, answer) in &answers {
            answer.encode(*id, &mut out);
        }
        drop(answers);
        let (written, mut buf) = stream.write_all(Buf::from_slice(&out)).await;
        sys::mem::wipe(&mut buf);
        if written.is_err() {
            return;
        }
    }
}
