use std::cell::Cell;
use std::future::poll_fn;
use std::task::{Poll, Waker};

#[derive(Default)]
pub struct Notify {
    set: Cell<bool>,
    waker: Cell<Option<Waker>>,
}

impl Notify {
    pub fn notify(&self) {
        self.set.set(true);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    pub async fn wait(&self) {
        poll_fn(|cx| {
            if self.set.replace(false) {
                return Poll::Ready(());
            }
            self.waker.set(Some(cx.waker().clone()));
            Poll::Pending
        })
        .await;
    }
}
