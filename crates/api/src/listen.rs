use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use intake::{End, Guard, Listener};
use rt::{Ends, TcpListener, spawn};
use sched::{Node, Transport};
use tls::Acceptor;

use crate::forward::{Forward, Forwarder};
use crate::server::{Config, Context, Port, Route, Stats, connection, serve};

pub struct Socket {
    pub socket: TcpListener,
    pub acceptor: Option<Rc<Acceptor>>,
    pub loopback: bool,
}

pub struct Api {
    listeners: Vec<Listener>,
    stats: Rc<Stats>,
    forward: Rc<Forwarder>,
    drain: std::time::Duration,
    context: Rc<dyn Any>,
}

impl Api {
    pub fn count(&self, route: Route, status: u16) -> u64 {
        self.stats
            .counts
            .borrow()
            .get(&(route, status))
            .copied()
            .unwrap_or(0)
    }

    pub fn sessions(&self) -> usize {
        self.listeners.iter().map(Listener::sessions).sum()
    }

    pub fn refused(&self) -> u64 {
        self.listeners.iter().map(Listener::refused).sum()
    }

    pub fn ended(&self, end: End) -> u64 {
        self.listeners.iter().map(|l| l.ended(end)).sum()
    }

    pub fn forwarded(&self) -> u64 {
        self.forward.forwarded()
    }

    pub fn served(&self) -> u64 {
        self.forward.served()
    }

    pub fn serving(&self) -> usize {
        self.forward.serving()
    }

    pub async fn close(self) {
        self.stats.closing.set(true);
        let closing: Vec<_> = self
            .listeners
            .into_iter()
            .map(|listener| spawn(listener.close()))
            .collect();
        for closed in closing {
            closed.await;
        }
        self.forward.close(self.drain).await;
        drop(self.context);
    }
}

pub fn start<T: Transport + 'static>(
    node: Node<T>,
    sockets: Vec<Socket>,
    config: Rc<Config>,
    guard: &Guard,
    ends: Ends<Forward>,
) -> Api {
    let stats = Rc::new(Stats::default());
    let drain = config.drain;
    let (forward, _) = Forwarder::start(ends);
    let context = Rc::new(Context {
        node,
        config,
        guard: guard.clone(),
        stats: Rc::clone(&stats),
        forward: Rc::clone(&forward),
        reading: RefCell::default(),
        searching: RefCell::default(),
        looking: RefCell::default(),
    });
    let owner = Rc::downgrade(&context);
    forward.serve_with(Box::new(move |inbound, open| {
        let owner = owner.upgrade();
        spawn(async move {
            if let Some(owner) = owner {
                serve(owner, inbound, open).await;
            }
        })
    }));
    let listeners = sockets
        .into_iter()
        .map(|socket| {
            let port = Rc::new(Port {
                acceptor: socket.acceptor,
                loopback: socket.loopback,
            });
            let context = Rc::clone(&context);
            Listener::start(socket.socket, guard.clone(), drain, move |io, ip, count| {
                connection(Rc::clone(&context), Rc::clone(&port), io, ip, count)
            })
        })
        .collect();
    Api {
        listeners,
        stats,
        forward,
        drain,
        context,
    }
}
