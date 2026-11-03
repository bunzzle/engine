use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use crypto::Plain;
use rt::{Buf, Receiver, Sender};

use crate::Error;
use crate::proto::{Answer, Frames, MAX_FRAME, Request};
use crate::server::Stream;

const REQUEST: usize = 128;
const CONNECT_TRIES: u32 = 8;
const CONNECT_PAUSE: Duration = Duration::from_millis(10);

pub struct Client {
    close: Box<dyn Fn()>,
    next: Cell<u32>,
    waiting: Rc<RefCell<HashMap<u32, Sender<Answer>>>>,
    frames: Sender<Plain>,
    closed: Rc<Cell<bool>>,
}

impl Client {
    pub fn new<S: Stream + 'static>(stream: S) -> Self {
        let stream = Rc::new(stream);
        let waiting = Rc::new(RefCell::new(HashMap::new()));
        let closed = Rc::new(Cell::new(false));
        let (frames, outgoing) = rt::channel();
        rt::spawn(writer(Rc::clone(&stream), outgoing, Rc::clone(&closed)));
        rt::spawn(reader(
            Rc::clone(&stream),
            Rc::clone(&waiting),
            Rc::clone(&closed),
        ));
        let close = {
            let closed = Rc::clone(&closed);
            let shut = Cell::new(false);
            Box::new(move || {
                closed.set(true);
                if !shut.replace(true) {
                    let stream = Rc::clone(&stream);
                    rt::spawn(async move { drop(stream.shutdown().await) });
                }
            })
        };
        Self {
            close,
            next: Cell::new(0),
            waiting,
            frames,
            closed,
        }
    }

    pub async fn connect(path: &Path, server: u32) -> Result<Self, Error> {
        let mut tries = 1;
        let (stream, uid) = loop {
            match rt::UnixStream::connect(path).await {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && tries < CONNECT_TRIES => {
                    rt::sleep(CONNECT_PAUSE * tries).await;
                    tries += 1;
                }
                result => break result?,
            }
        };
        if uid != server {
            return Err(Error::Peer);
        }
        Ok(Self::new(stream))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.get()
    }

    pub fn close(&self) {
        (self.close)();
    }

    pub async fn call(&self, request: &Request) -> Result<Answer, Error> {
        let (_, mut answer) = self.send(request)?;
        answer.recv().await.ok_or(Error::Closed)
    }

    pub async fn call_within(&self, request: &Request, limit: Duration) -> Result<Answer, Error> {
        let (id, mut answer) = self.send(request)?;
        if let Ok(answer) = rt::timeout(limit, answer.recv()).await {
            answer.ok_or(Error::Closed)
        } else {
            self.waiting.borrow_mut().remove(&id);
            Err(Error::Timeout)
        }
    }

    fn send(&self, request: &Request) -> Result<(u32, Receiver<Answer>), Error> {
        if self.closed.get() {
            return Err(Error::Closed);
        }
        let id = self.next.get();
        self.next.set(id.wrapping_add(1));
        let (reply, answer) = rt::channel();
        self.waiting.borrow_mut().insert(id, reply);
        let mut out = Plain::with_capacity(REQUEST);
        request.encode(id, &mut out);
        if self.frames.send(out).is_err() {
            self.waiting.borrow_mut().remove(&id);
            return Err(Error::Closed);
        }
        Ok((id, answer))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if rt::in_runtime() {
            self.close();
        }
    }
}

async fn writer<S: Stream>(stream: Rc<S>, mut outgoing: Receiver<Plain>, closed: Rc<Cell<bool>>) {
    while let Some(first) = outgoing.recv().await {
        let mut batch = vec![first];
        while let Some(more) = outgoing.try_recv() {
            batch.push(more);
        }
        let mut out = Plain::with_capacity(batch.iter().map(|frame| frame.len()).sum());
        for frame in &batch {
            out.extend_from_slice(frame);
        }
        let (written, _) = stream.write_all(Buf::from_slice(&out)).await;
        if written.is_err() {
            closed.set(true);
            return;
        }
    }
}

async fn reader<S: Stream>(
    stream: Rc<S>,
    waiting: Rc<RefCell<HashMap<u32, Sender<Answer>>>>,
    closed: Rc<Cell<bool>>,
) {
    let mut frames = Frames::default();
    loop {
        let (read, mut buf) = stream.read(Buf::new(MAX_FRAME)).await;
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        frames.push(&buf[..n]);
        sys::mem::wipe(&mut buf);
        loop {
            match frames.pop() {
                Ok(Some((op, id, mut body))) => {
                    let answer = Answer::decode(op, &body).unwrap_or(Answer::Refused(Error::Bad));
                    sys::mem::wipe(&mut body);
                    if let Some(reply) = waiting.borrow_mut().remove(&id) {
                        let _ = reply.send(answer);
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    closed.set(true);
                    waiting.borrow_mut().clear();
                    return;
                }
            }
        }
    }
    closed.set(true);
    waiting.borrow_mut().clear();
}
