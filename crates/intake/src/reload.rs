use std::cell::Cell;
use std::future::poll_fn;
use std::io;
use std::path::PathBuf;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;

use rt::{JoinHandle, Notify, Signal, Signals, spawn};
use tls::Certs;

#[derive(Default)]
struct Shared {
    stop: Notify,
    stopping: Notify,
    requested: Cell<Option<Signal>>,
    reloaded: Cell<u64>,
    failed: Cell<u64>,
}

pub struct Watch {
    shared: Rc<Shared>,
    task: JoinHandle<()>,
}

impl Watch {
    pub fn reloaded(&self) -> u64 {
        self.shared.reloaded.get()
    }

    pub fn failed(&self) -> u64 {
        self.shared.failed.get()
    }

    pub async fn stop_requested(&self) -> Signal {
        loop {
            if let Some(signal) = self.shared.requested.get() {
                return signal;
            }
            self.shared.stopping.wait().await;
        }
    }

    pub async fn close(self) {
        self.shared.stop.notify();
        self.task.await;
    }
}

pub fn watch(signals: Signals, certs: Arc<Certs>, chain: PathBuf, key: PathBuf) -> Watch {
    let shared = Rc::new(Shared::default());
    let state = Rc::clone(&shared);
    let task = spawn(async move {
        loop {
            let Some(received) = recv_or_stop(&signals, &state.stop).await else {
                return;
            };
            match received {
                Ok(Signal::Hangup) => {
                    let counter = match certs.reload(&chain, &key).await {
                        Ok(()) => &state.reloaded,
                        Err(_) => &state.failed,
                    };
                    counter.set(counter.get() + 1);
                }
                Ok(signal) => {
                    if state.requested.get().is_none() {
                        state.requested.set(Some(signal));
                    }
                    state.stopping.notify();
                }
                Err(_) => return,
            }
        }
    });
    Watch { shared, task }
}

async fn recv_or_stop(signals: &Signals, stop: &Notify) -> Option<io::Result<Signal>> {
    let mut recv = pin!(signals.recv());
    let mut stopped = pin!(stop.wait());
    poll_fn(|cx| {
        if stopped.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        recv.as_mut().poll(cx).map(Some)
    })
    .await
}
