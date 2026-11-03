use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use crypto::Plain;
use rt::{Buf, Receiver, Sender};

use crate::Error;
use crate::proto::{Answer, Frames, MAX_FRAME, Request};
use crate::server::Stream;

const REQUEST: usize = 128;

pub struct Client {
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
        rt::spawn(reader(stream, Rc::clone(&waiting), Rc::clone(&closed)));
        Self {
            next: Cell::new(0),
            waiting,
            frames,
            closed,
        }
    }

    pub async fn connect(path: &Path, server: u32) -> Result<Self, Error> {
        let (stream, uid) = rt::UnixStream::connect(path).await?;
        if uid != server {
            return Err(Error::Peer);
        }
        Ok(Self::new(stream))
    }

    pub async fn call(&self, request: &Request) -> Result<Answer, Error> {
        if self.closed.get() {
            return Err(Error::Closed);
        }
        let id = self.next.get();
        self.next.set(id.wrapping_add(1));
        let (reply, mut answer) = rt::channel();
        self.waiting.borrow_mut().insert(id, reply);
        let mut out = Plain::with_capacity(REQUEST);
        request.encode(id, &mut out);
        if self.frames.send(out).is_err() {
            self.waiting.borrow_mut().remove(&id);
            return Err(Error::Closed);
        }
        answer.recv().await.ok_or(Error::Closed)
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
