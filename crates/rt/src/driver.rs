use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::task::Waker;

use crate::buf::Buf;
use crate::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId(pub u64);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub create_new: bool,
    pub truncate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub len: u64,
    pub sector_size: u32,
}

#[derive(Debug)]
pub enum Op {
    Open {
        path: PathBuf,
        options: OpenOptions,
    },
    ReadAt {
        handle: Handle,
        offset: u64,
        buf: Buf,
    },
    WriteAt {
        handle: Handle,
        offset: u64,
        buf: Buf,
    },
    SyncData {
        handle: Handle,
    },
    SyncDir {
        path: PathBuf,
    },
    Allocate {
        handle: Handle,
        len: u64,
    },
    Stat {
        handle: Handle,
    },
    Listen {
        addr: SocketAddr,
        backlog: u32,
    },
    Accept {
        handle: Handle,
    },
    Connect {
        addr: SocketAddr,
    },
    Recv {
        handle: Handle,
        buf: Buf,
    },
    Send {
        handle: Handle,
        buf: Buf,
    },
    Shutdown {
        handle: Handle,
    },
    BindUdp {
        addr: SocketAddr,
    },
    SendTo {
        handle: Handle,
        buf: Buf,
        addr: SocketAddr,
    },
    RecvFrom {
        handle: Handle,
        buf: Buf,
    },
    LocalAddr {
        handle: Handle,
    },
}

#[derive(Debug)]
pub enum Completion {
    Handle(io::Result<Handle>),
    Unit(io::Result<()>),
    Bytes(io::Result<usize>, Buf),
    Stat(io::Result<Stat>),
    Accepted(io::Result<(Handle, SocketAddr)>),
    From(io::Result<(usize, SocketAddr)>, Buf),
    Addr(io::Result<SocketAddr>),
}

pub trait Unpark: Send + Sync {
    fn unpark(&self);
}

pub trait Driver {
    fn now(&self) -> Instant;
    fn wall_ms(&self) -> u64;
    fn submit(&self, op: Op, waker: &Waker) -> OpId;
    fn poll(&self, id: OpId, waker: &Waker) -> Option<Completion>;
    fn cancel(&self, id: OpId);
    fn release(&self, handle: Handle);
    fn park(&self, deadline: Option<Instant>);
    fn unparker(&self) -> Arc<dyn Unpark>;
}
