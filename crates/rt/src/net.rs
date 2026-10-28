use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

use crate::buf::Buf;
use crate::driver::{Completion, Driver, Handle, Op};
use crate::executor;
use crate::op::{OpFuture, mismatch};

struct Socket {
    driver: Rc<dyn Driver>,
    handle: Handle,
}

impl Socket {
    async fn create(op: Op) -> io::Result<Self> {
        let driver = executor::driver();
        match OpFuture::with_driver(Rc::clone(&driver), op).await {
            Completion::Handle(result) => result.map(|handle| Self { driver, handle }),
            _ => Err(mismatch()),
        }
    }

    fn op(&self, op: Op) -> OpFuture {
        OpFuture::with_driver(Rc::clone(&self.driver), op)
    }

    async fn bytes(&self, op: Op) -> (io::Result<usize>, Buf) {
        match self.op(op).await {
            Completion::Bytes(result, buf) => (result, buf),
            _ => (Err(mismatch()), Buf::new(0)),
        }
    }

    async fn unit(&self, op: Op) -> io::Result<()> {
        match self.op(op).await {
            Completion::Unit(result) => result,
            _ => Err(mismatch()),
        }
    }

    async fn local_addr(&self) -> io::Result<SocketAddr> {
        match self
            .op(Op::LocalAddr {
                handle: self.handle,
            })
            .await
        {
            Completion::Addr(result) => result,
            _ => Err(mismatch()),
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.driver.release(self.handle);
    }
}

pub struct TcpListener {
    socket: Socket,
}

impl TcpListener {
    pub async fn bind(addr: SocketAddr, backlog: u32) -> io::Result<Self> {
        let socket = Socket::create(Op::Listen { addr, backlog }).await?;
        Ok(Self { socket })
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let op = Op::Accept {
            handle: self.socket.handle,
        };
        match self.socket.op(op).await {
            Completion::Accepted(result) => result.map(|(handle, peer)| {
                let socket = Socket {
                    driver: Rc::clone(&self.socket.driver),
                    handle,
                };
                (TcpStream { socket }, peer)
            }),
            _ => Err(mismatch()),
        }
    }

    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr().await
    }
}

pub struct TcpStream {
    socket: Socket,
}

impl TcpStream {
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::create(Op::Connect { addr }).await?;
        Ok(Self { socket })
    }

    pub async fn read(&self, buf: Buf) -> (io::Result<usize>, Buf) {
        let op = Op::Recv {
            handle: self.socket.handle,
            buf,
        };
        self.socket.bytes(op).await
    }

    pub async fn write(&self, buf: Buf) -> (io::Result<usize>, Buf) {
        let op = Op::Send {
            handle: self.socket.handle,
            buf,
        };
        self.socket.bytes(op).await
    }

    pub async fn write_all(&self, buf: Buf) -> (io::Result<()>, Buf) {
        let total = buf.len();
        let (result, buf) = self.write(buf).await;
        let mut done = match result {
            Ok(n) => n,
            Err(e) => return (Err(e), buf),
        };
        while done < total {
            let rest = Buf::from_slice(&buf[done..]);
            let (result, _) = self.write(rest).await;
            match result {
                Ok(0) => return (Err(io::ErrorKind::WriteZero.into()), buf),
                Ok(n) => done += n,
                Err(e) => return (Err(e), buf),
            }
        }
        (Ok(()), buf)
    }

    pub async fn shutdown(&self) -> io::Result<()> {
        self.socket
            .unit(Op::Shutdown {
                handle: self.socket.handle,
            })
            .await
    }

    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr().await
    }
}

pub struct UdpSocket {
    socket: Socket,
}

impl UdpSocket {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::create(Op::BindUdp { addr }).await?;
        Ok(Self { socket })
    }

    pub async fn send_to(&self, buf: Buf, addr: SocketAddr) -> (io::Result<usize>, Buf) {
        let op = Op::SendTo {
            handle: self.socket.handle,
            buf,
            addr,
        };
        self.socket.bytes(op).await
    }

    pub async fn recv_from(&self, buf: Buf) -> (io::Result<(usize, SocketAddr)>, Buf) {
        let op = Op::RecvFrom {
            handle: self.socket.handle,
            buf,
        };
        match self.socket.op(op).await {
            Completion::From(result, buf) => (result, buf),
            _ => (Err(mismatch()), Buf::new(0)),
        }
    }

    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr().await
    }
}
