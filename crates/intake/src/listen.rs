use std::cell::Cell;
use std::future::poll_fn;
use std::net::IpAddr;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;

use rt::{Buf, JoinHandle, Notify, TcpListener, TcpStream, spawn, timeout};
use sched::{Node, Transport};
use smtp::{Reply, reply};
use tls::Acceptor;

use crate::conn::Conn;
use crate::guard::{Guard, Refused};
use crate::session::{Config, End, serve};

const ENDS: usize = 6;
const CONNECTIONS: Reply = Reply::new(421, "4.7.0", "Too many connections");
const BUSY: Reply = Reply::new(421, "4.3.2", "System busy");

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
    guard: Guard,
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
            let Ok((io, peer)) = accepted else {
                continue;
            };
            let Some(admitted) = guard.admit() else {
                state.refused.set(state.refused.get() + 1);
                continue;
            };
            count = count.wrapping_add(1);
            state.sessions.set(state.sessions.get() + 1);
            let (node, acceptor, config, guard, state) = (
                node.clone(),
                Rc::clone(&acceptor),
                Rc::clone(&config),
                guard.clone(),
                Rc::clone(&state),
            );
            spawn(async move {
                let ip = peer.ip();
                let end = session(&node, &acceptor, io, &config, &guard, ip, implicit, count).await;
                drop(admitted);
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
) -> Option<std::io::Result<(TcpStream, std::net::SocketAddr)>> {
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

#[allow(clippy::too_many_arguments)]
async fn session<T: Transport + 'static>(
    node: &Node<T>,
    acceptor: &Acceptor,
    io: TcpStream,
    config: &Config,
    guard: &Guard,
    ip: IpAddr,
    implicit: bool,
    count: usize,
) -> End {
    let net = match guard.open(ip).await {
        Ok(net) => net,
        Err(refused) => {
            if !implicit {
                let reply = match refused {
                    Refused::Full => CONNECTIONS,
                    Refused::Banned => reply::AUTH_FAILURES,
                    Refused::Unanswered => BUSY,
                };
                let mut line = Vec::new();
                reply.write(&mut line);
                let _ = timeout(config.handshake, io.write_all(Buf::from_slice(&line))).await;
                let _ = io.shutdown().await;
            }
            return End::Refused;
        }
    };
    let conn = if implicit {
        match timeout(config.handshake, acceptor.accept(io)).await {
            Ok(Ok(stream)) => Conn::tls(stream),
            _ => return End::Tls,
        }
    } else {
        Conn::plain(io)
    };
    serve(node, acceptor, conn, config, guard, (ip, net), count).await
}

fn index(end: End) -> usize {
    match end {
        End::Done => 0,
        End::Dropped => 1,
        End::Timeout => 2,
        End::Io => 3,
        End::Tls => 4,
        End::Refused => 5,
    }
}
