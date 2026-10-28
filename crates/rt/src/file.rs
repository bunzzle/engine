use std::io;
use std::path::Path;
use std::rc::Rc;

use crate::buf::Buf;
use crate::driver::{Completion, Driver, Handle, Op, OpenOptions, Stat};
use crate::executor;
use crate::op::{OpFuture, mismatch};

pub async fn sync_dir(path: impl AsRef<Path>) -> io::Result<()> {
    let op = Op::SyncDir {
        path: path.as_ref().to_path_buf(),
    };
    match OpFuture::with_driver(executor::driver(), op).await {
        Completion::Unit(result) => result,
        _ => Err(mismatch()),
    }
}

pub struct File {
    driver: Rc<dyn Driver>,
    handle: Option<Handle>,
}

impl File {
    pub async fn open(path: impl AsRef<Path>, options: &OpenOptions) -> io::Result<Self> {
        let driver = executor::driver();
        let op = Op::Open {
            path: path.as_ref().to_path_buf(),
            options: options.clone(),
        };
        match OpFuture::with_driver(Rc::clone(&driver), op).await {
            Completion::Handle(result) => result.map(|handle| Self {
                driver,
                handle: Some(handle),
            }),
            _ => Err(mismatch()),
        }
    }

    fn handle(&self) -> Handle {
        self.handle.expect("file is open")
    }

    fn op(&self, op: Op) -> OpFuture {
        OpFuture::with_driver(Rc::clone(&self.driver), op)
    }

    pub async fn read_at(&self, buf: Buf, offset: u64) -> (io::Result<usize>, Buf) {
        let op = Op::ReadAt {
            handle: self.handle(),
            offset,
            buf,
        };
        match self.op(op).await {
            Completion::Bytes(result, buf) => (result, buf),
            _ => (Err(mismatch()), Buf::new(0)),
        }
    }

    pub async fn write_at(&self, buf: Buf, offset: u64) -> (io::Result<usize>, Buf) {
        let op = Op::WriteAt {
            handle: self.handle(),
            offset,
            buf,
        };
        match self.op(op).await {
            Completion::Bytes(result, buf) => (result, buf),
            _ => (Err(mismatch()), Buf::new(0)),
        }
    }

    pub async fn write_all_at(&self, buf: Buf, offset: u64) -> (io::Result<()>, Buf) {
        let total = buf.len();
        let (result, buf) = self.write_at(buf, offset).await;
        let mut done = match result {
            Ok(n) => n,
            Err(e) => return (Err(e), buf),
        };
        while done < total {
            let mut rest = Buf::aligned(total - done, buf.align());
            rest.extend_from_slice(&buf[done..]);
            let (result, _) = self.write_at(rest, offset + done as u64).await;
            match result {
                Ok(0) => return (Err(io::ErrorKind::WriteZero.into()), buf),
                Ok(n) => done += n,
                Err(e) => return (Err(e), buf),
            }
        }
        (Ok(()), buf)
    }

    pub async fn sync_data(&self) -> io::Result<()> {
        match self
            .op(Op::SyncData {
                handle: self.handle(),
            })
            .await
        {
            Completion::Unit(result) => result,
            _ => Err(mismatch()),
        }
    }

    pub async fn allocate(&self, len: u64) -> io::Result<()> {
        let op = Op::Allocate {
            handle: self.handle(),
            len,
        };
        match self.op(op).await {
            Completion::Unit(result) => result,
            _ => Err(mismatch()),
        }
    }

    pub async fn stat(&self) -> io::Result<Stat> {
        match self
            .op(Op::Stat {
                handle: self.handle(),
            })
            .await
        {
            Completion::Stat(result) => result,
            _ => Err(mismatch()),
        }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.driver.release(handle);
        }
    }
}
