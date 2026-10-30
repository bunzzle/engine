use std::cell::{Cell, RefCell};
use std::mem;
use std::rc::Rc;
use std::sync::{Mutex, PoisonError};

use crate::channel::{Receiver, Sender, channel};
use crate::executor::{JoinHandle, spawn, yield_now};
use crate::notify::Notify;

pub struct Mesh<T> {
    ends: Mutex<Vec<Option<Ends<T>>>>,
}

impl<T: Send> Mesh<T> {
    pub fn new(cores: u16) -> Self {
        let n = usize::from(cores);
        let mut senders: Vec<Vec<Sender<Vec<T>>>> = (0..n).map(|_| Vec::with_capacity(n)).collect();
        let mut receivers: Vec<Vec<Receiver<Vec<T>>>> =
            (0..n).map(|_| Vec::with_capacity(n)).collect();
        for from in &mut senders {
            for to in &mut receivers {
                let (sender, receiver) = channel();
                from.push(sender);
                to.push(receiver);
            }
        }
        let ends = senders
            .into_iter()
            .zip(receivers)
            .zip(0..cores)
            .map(|((senders, receivers), index)| {
                Some(Ends {
                    index,
                    senders,
                    receivers,
                })
            })
            .collect();
        Self {
            ends: Mutex::new(ends),
        }
    }

    pub fn take(&self, core: u16) -> Option<Ends<T>> {
        let mut ends = self.ends.lock().unwrap_or_else(PoisonError::into_inner);
        ends.get_mut(usize::from(core)).and_then(Option::take)
    }
}

pub struct Ends<T> {
    index: u16,
    senders: Vec<Sender<Vec<T>>>,
    receivers: Vec<Receiver<Vec<T>>>,
}

impl<T: Send + 'static> Ends<T> {
    pub fn index(&self) -> u16 {
        self.index
    }

    pub fn cores(&self) -> u16 {
        u16::try_from(self.senders.len()).expect("cores fit in u16")
    }

    pub fn start<H>(self, handler: H) -> (Peers<T>, JoinHandle<()>)
    where
        H: FnMut(u16, T) + 'static,
    {
        let inner = Rc::new(Inner {
            index: self.index,
            buffers: RefCell::new((0..self.senders.len()).map(|_| Vec::new()).collect()),
            senders: RefCell::new(Some(self.senders)),
            notify: Notify::default(),
            flushes: Cell::new(0),
        });
        spawn(flush(Rc::clone(&inner)));
        let handler = Rc::new(RefCell::new(handler));
        let tasks: Vec<_> = self
            .receivers
            .into_iter()
            .zip(0..)
            .map(|(receiver, from)| spawn(receive(receiver, from, Rc::clone(&handler))))
            .collect();
        let done = spawn(async move {
            for task in tasks {
                task.await;
            }
        });
        (Peers { inner }, done)
    }
}

async fn receive<T, H>(mut receiver: Receiver<Vec<T>>, from: u16, handler: Rc<RefCell<H>>)
where
    H: FnMut(u16, T),
{
    while let Some(batch) = receiver.recv().await {
        let mut handler = handler.borrow_mut();
        for message in batch {
            handler(from, message);
        }
    }
}

async fn flush<T: Send>(inner: Rc<Inner<T>>) {
    loop {
        inner.notify.wait().await;
        yield_now().await;
        if !inner.send_all() {
            return;
        }
    }
}

struct Inner<T> {
    index: u16,
    buffers: RefCell<Vec<Vec<T>>>,
    senders: RefCell<Option<Vec<Sender<Vec<T>>>>>,
    notify: Notify,
    flushes: Cell<u64>,
}

impl<T: Send> Inner<T> {
    fn send_all(&self) -> bool {
        let senders = self.senders.borrow();
        let Some(senders) = senders.as_ref() else {
            return false;
        };
        let mut buffers = self.buffers.borrow_mut();
        for (buffer, sender) in buffers.iter_mut().zip(senders) {
            if buffer.is_empty() {
                continue;
            }
            self.flushes.set(self.flushes.get() + 1);
            let _ = sender.send(mem::take(buffer));
        }
        true
    }
}

pub struct Peers<T> {
    inner: Rc<Inner<T>>,
}

impl<T> Clone for Peers<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<T: Send> Peers<T> {
    pub fn index(&self) -> u16 {
        self.inner.index
    }

    pub fn send(&self, to: u16, message: T) {
        let mut buffers = self.inner.buffers.borrow_mut();
        let buffer = &mut buffers[usize::from(to)];
        buffer.push(message);
        if buffer.len() == 1 {
            self.inner.notify.notify();
        }
    }

    pub fn flushes(&self) -> u64 {
        self.inner.flushes.get()
    }

    pub fn close(&self) {
        self.inner.send_all();
        self.inner.senders.borrow_mut().take();
        self.inner.notify.notify();
    }
}
