use std::error::Error;
use std::fmt;
use std::future::Future;
use std::ops::Add;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::executor;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self {
        let nanos = u64::try_from(rhs.as_nanos()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(nanos))
    }
}

pub fn now() -> Instant {
    executor::current().now()
}

pub fn wall_ms() -> u64 {
    executor::current().wall_ms()
}

pub fn sleep(duration: Duration) -> Sleep {
    sleep_until(now() + duration)
}

pub fn sleep_until(deadline: Instant) -> Sleep {
    Sleep {
        deadline,
        key: None,
    }
}

pub struct Sleep {
    deadline: Instant,
    key: Option<u64>,
}

impl Sleep {
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let inner = executor::current();
        if inner.now() >= self.deadline {
            if let Some(key) = self.key.take() {
                inner.cancel_timer(key);
            }
            return Poll::Ready(());
        }
        let key = inner.register_timer(self.deadline, self.key, cx.waker());
        self.key = Some(key);
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(key) = self.key.take()
            && let Some(inner) = executor::try_current()
        {
            inner.cancel_timer(key);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl Error for Elapsed {}

pub fn timeout<F: Future>(duration: Duration, future: F) -> Timeout<F> {
    Timeout {
        future: Box::pin(future),
        sleep: sleep(duration),
    }
}

pub struct Timeout<F> {
    future: Pin<Box<F>>,
    sleep: Sleep,
}

impl<F: Future> Future for Timeout<F> {
    type Output = Result<F::Output, Elapsed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(value) = self.future.as_mut().poll(cx) {
            return Poll::Ready(Ok(value));
        }
        match Pin::new(&mut self.sleep).poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed)),
            Poll::Pending => Poll::Pending,
        }
    }
}
