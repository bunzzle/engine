use std::cell::Cell;
use std::future::poll_fn;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;

use rt::{JoinHandle, Notify, TcpListener, spawn, timeout};
use sched::{Node, Transport};
use tls::Acceptor;

use crate::conn::Conn;
use crate::session::{Config, End, serve};

const ENDS: usize = 5;

#[derive(Default)]
struct Shared {
    stop: Notify,
    idle: Notify,
    sessions: Cell<usize>,
    refused: Cell<u64>,
    ends: [Cell<u64>; ENDS],
}

pub struct Listener {
    shared: Rc<Shared>,
    task: JoinHandle<()>,
}

impl Listener {
    pub fn sessions(&self) -> usize {
        self.shared.sessions.get()
    }

    pub fn refused(&self) -> u64 {
        self.shared.refused.get()
    }

    pub fn ended(&self, end: End) -> u64 {
        self.shared.ends[index(end)].get()
    }

    pub async fn close(self) {
        self.shared.stop.notify();
        self.task.await;
        while self.shared.sessions.get() > 0 {
            self.shared.idle.wait().await;
        }
    }
}

pub fn listen<T: Transport + 'static>(
    node: Node<T>,
    socket: TcpListener,
    acceptor: Rc<Acceptor>,
    config: Rc<Config>,
    implicit: bool,
) -> Listener {
    let shared = Rc::new(Shared::default());
    let state = Rc::clone(&shared);
    let task = spawn(async move {
        let mut count = 0usize;
        loop {
            let Some(accepted) = accept_or_stop(&socket, &state.stop).await else {
                return;
            };
            let Ok((io, _)) = accepted else {
                continue;
            };
            if state.sessions.get() >= config.connections {
                state.refused.set(state.refused.get() + 1);
                continue;
            }
            count = count.wrapping_add(1);
            state.sessions.set(state.sessions.get() + 1);
            let (node, acceptor, config, state) = (
                node.clone(),
                Rc::clone(&acceptor),
                Rc::clone(&config),
                Rc::clone(&state),
            );
            spawn(async move {
                let end = session(&node, &acceptor, io, &config, implicit, count).await;
                let slot = &state.ends[index(end)];
                slot.set(slot.get() + 1);
                state.sessions.set(state.sessions.get() - 1);
                if state.sessions.get() == 0 {
                    state.idle.notify();
                }
            });
        }
    });
    Listener { shared, task }
}

async fn accept_or_stop(
    socket: &TcpListener,
    stop: &Notify,
) -> Option<std::io::Result<(rt::TcpStream, std::net::SocketAddr)>> {
    let mut accept = pin!(socket.accept());
    let mut stopped = pin!(stop.wait());
    poll_fn(|cx| {
        if stopped.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        accept.as_mut().poll(cx).map(Some)
    })
    .await
}

async fn session<T: Transport + 'static>(
    node: &Node<T>,
    acceptor: &Acceptor,
    io: rt::TcpStream,
    config: &Config,
    implicit: bool,
    count: usize,
) -> End {
    let conn = if implicit {
        match timeout(config.handshake, acceptor.accept(io)).await {
            Ok(Ok(stream)) => Conn::tls(stream),
            _ => return End::Tls,
        }
    } else {
        Conn::plain(io)
    };
    serve(node, acceptor, conn, config, count).await
}

fn index(end: End) -> usize {
    match end {
        End::Done => 0,
        End::Dropped => 1,
        End::Timeout => 2,
        End::Io => 3,
        End::Tls => 4,
    }
}
