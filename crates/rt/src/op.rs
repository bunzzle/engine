use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::driver::{Completion, Driver, Op, OpId};

pub(crate) struct OpFuture {
    driver: Rc<dyn Driver>,
    op: Option<Op>,
    id: Option<OpId>,
}

impl OpFuture {
    pub(crate) fn with_driver(driver: Rc<dyn Driver>, op: Op) -> Self {
        Self {
            driver,
            op: Some(op),
            id: None,
        }
    }
}

impl Future for OpFuture {
    type Output = Completion;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Completion> {
        if let Some(op) = self.op.take() {
            let id = self.driver.submit(op, cx.waker());
            self.id = Some(id);
        }
        let Some(id) = self.id else {
            return Poll::Pending;
        };
        match self.driver.poll(id, cx.waker()) {
            Some(completion) => {
                self.id = None;
                Poll::Ready(completion)
            }
            None => Poll::Pending,
        }
    }
}

impl Drop for OpFuture {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.driver.cancel(id);
        }
    }
}

pub(crate) fn mismatch() -> io::Error {
    io::Error::other("driver returned a completion of the wrong kind")
}
