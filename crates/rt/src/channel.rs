use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};

struct State<T> {
    items: VecDeque<T>,
    waker: Option<Waker>,
    senders: usize,
    receiver_alive: bool,
}

struct Chan<T> {
    state: Mutex<State<T>>,
}

impl<T> Chan<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub fn channel<T: Send>() -> (Sender<T>, Receiver<T>) {
    let chan = Arc::new(Chan {
        state: Mutex::new(State {
            items: VecDeque::new(),
            waker: None,
            senders: 1,
            receiver_alive: true,
        }),
    });
    (
        Sender {
            chan: Arc::clone(&chan),
        },
        Receiver { chan },
    )
}

pub struct Sender<T> {
    chan: Arc<Chan<T>>,
}

impl<T> Sender<T> {
    pub fn send(&self, value: T) -> Result<(), T> {
        let waker = {
            let mut state = self.chan.lock();
            if !state.receiver_alive {
                return Err(value);
            }
            state.items.push_back(value);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.chan.lock().senders += 1;
        Self {
            chan: Arc::clone(&self.chan),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let waker = {
            let mut state = self.chan.lock();
            state.senders -= 1;
            if state.senders == 0 {
                state.waker.take()
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

pub struct Receiver<T> {
    chan: Arc<Chan<T>>,
}

impl<T> Receiver<T> {
    pub fn try_recv(&mut self) -> Option<T> {
        self.chan.lock().items.pop_front()
    }

    pub async fn recv(&mut self) -> Option<T> {
        poll_fn(|cx| {
            let mut state = self.chan.lock();
            if let Some(value) = state.items.pop_front() {
                return Poll::Ready(Some(value));
            }
            if state.senders == 0 {
                return Poll::Ready(None);
            }
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut state = self.chan.lock();
        state.receiver_alive = false;
        state.items.clear();
    }
}
