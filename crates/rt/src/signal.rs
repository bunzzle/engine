use std::cell::Cell;
use std::io;
use std::rc::Rc;

use crate::driver::{Completion, Driver, Handle, Op};
use crate::executor;
use crate::op::{OpFuture, mismatch};

pub use sys::signal::Signal;

pub struct Signals {
    driver: Rc<dyn Driver>,
    handle: Handle,
    held: Cell<u32>,
}

impl Signals {
    pub async fn listen(signals: &[Signal]) -> io::Result<Self> {
        let driver = executor::driver();
        let op = Op::ListenSignals {
            mask: Signal::mask(signals),
        };
        match OpFuture::with_driver(Rc::clone(&driver), op).await {
            Completion::Handle(result) => result.map(|handle| Self {
                driver,
                handle,
                held: Cell::new(0),
            }),
            _ => Err(mismatch()),
        }
    }

    pub async fn recv(&self) -> io::Result<Signal> {
        if self.held.get() == 0 {
            let op = Op::RecvSignals {
                handle: self.handle,
            };
            match OpFuture::with_driver(Rc::clone(&self.driver), op).await {
                Completion::Signals(result) => self.held.set(result?),
                _ => return Err(mismatch()),
            }
        }
        let held = self.held.get();
        let signal = Signal::first(held).ok_or_else(mismatch)?;
        self.held.set(held & !signal.bit());
        Ok(signal)
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        self.driver.release(self.handle);
    }
}
