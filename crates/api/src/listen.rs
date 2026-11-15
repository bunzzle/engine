use std::rc::Rc;

use intake::{End, Guard, Listener};
use rt::TcpListener;
use sched::{Node, Transport};
use tls::Acceptor;

use crate::server::{Config, Context, Route, Stats, connection};

pub struct Api {
    listener: Listener,
    stats: Rc<Stats>,
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
        self.listener.sessions()
    }

    pub fn refused(&self) -> u64 {
        self.listener.refused()
    }

    pub fn ended(&self, end: End) -> u64 {
        self.listener.ended(end)
    }

    pub async fn close(self) {
        self.stats.closing.set(true);
        self.listener.close().await;
    }
}

pub fn listen<T: Transport + 'static>(
    node: Node<T>,
    socket: TcpListener,
    acceptor: Option<Rc<Acceptor>>,
    config: Rc<Config>,
    guard: Guard,
    loopback: bool,
) -> Api {
    let stats = Rc::new(Stats::default());
    let drain = config.drain;
    let context = Rc::new(Context {
        node,
        acceptor,
        config,
        guard: guard.clone(),
        loopback,
        stats: Rc::clone(&stats),
    });
    let listener = Listener::start(socket, guard, drain, move |io, ip, count| {
        connection(Rc::clone(&context), io, ip, count)
    });
    Api { listener, stats }
}
