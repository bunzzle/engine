use std::io;
use std::mem;

use rt::{Buf, TcpStream};
use tls::{Acceptor, Stream};

const READ: usize = 64 * 1024;

pub enum Conn {
    Plain { io: TcpStream, rx: Buf },
    Tls(Box<Stream>),
}

impl Conn {
    pub fn plain(io: TcpStream) -> Self {
        Self::Plain {
            io,
            rx: Buf::new(READ),
        }
    }

    pub fn tls(stream: Stream) -> Self {
        Self::Tls(Box::new(stream))
    }

    pub fn secure(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    pub async fn read(&mut self, out: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Self::Plain { io, rx } => {
                rx.clear();
                let (read, buf) = io.read(mem::replace(rx, Buf::new(0))).await;
                *rx = buf;
                let n = read?;
                out.extend_from_slice(&rx[..n]);
                Ok(n)
            }
            Self::Tls(stream) => {
                let start = out.len();
                out.resize(start + READ, 0);
                let read = stream.read(&mut out[start..]).await;
                out.truncate(start + *read.as_ref().unwrap_or(&0));
                read
            }
        }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain { io, .. } => io.write_all(Buf::from_slice(data)).await.0,
            Self::Tls(stream) => stream.write_all(data).await,
        }
    }

    pub(crate) async fn upgrade(self, acceptor: &Acceptor) -> io::Result<Self> {
        match self {
            Self::Plain { io, .. } => Ok(Self::tls(acceptor.accept(io).await?)),
            Self::Tls(_) => Err(io::ErrorKind::InvalidInput.into()),
        }
    }

    pub async fn shutdown(&mut self) {
        let _ = match self {
            Self::Plain { io, .. } => io.shutdown().await,
            Self::Tls(stream) => stream.shutdown().await,
        };
    }
}
