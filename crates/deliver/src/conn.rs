use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rt::{Buf, Instant, TcpStream, now, timeout};
use smtp::client::{QUIT, Response, Responses};
use tls::{Connector, Stream, Verify};

const READ: usize = 4096;
const QUIT_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lost {
    Timeout,
    Closed,
    Reply,
    Tls,
    Store,
}

impl Lost {
    pub(crate) fn text(self) -> &'static [u8] {
        match self {
            Self::Timeout => b"451 4.4.2 Timed out",
            Self::Closed => b"451 4.4.2 Connection lost",
            Self::Reply => b"451 4.5.0 Malformed reply",
            Self::Tls => b"451 4.7.5 TLS negotiation failed",
            Self::Store => b"451 4.3.0 Stored message cannot be read",
        }
    }
}

pub(crate) fn left(end: Instant, limit: Duration) -> Duration {
    end.saturating_duration_since(now()).min(limit)
}

enum Io {
    Plain(TcpStream),
    Tls(Box<Stream>),
}

pub(crate) struct Conn {
    io: Io,
    responses: Responses,
    end: Instant,
}

impl Conn {
    pub(crate) async fn open(
        from: IpAddr,
        to: SocketAddr,
        end: Instant,
        limit: Duration,
    ) -> Result<Self, Lost> {
        match timeout(left(end, limit), TcpStream::connect_from(from, to)).await {
            Ok(Ok(io)) => Ok(Self {
                io: Io::Plain(io),
                responses: Responses::default(),
                end,
            }),
            Ok(Err(_)) => Err(Lost::Closed),
            Err(_) => Err(Lost::Timeout),
        }
    }

    pub(crate) async fn response(&mut self, limit: Duration) -> Result<Response, Lost> {
        let (io, responses) = (&mut self.io, &mut self.responses);
        let read = async move {
            loop {
                if let Some(next) = responses.poll() {
                    return next.map_err(|_| Lost::Reply);
                }
                fill(io, responses).await?;
            }
        };
        timeout(left(self.end, limit), read)
            .await
            .unwrap_or(Err(Lost::Timeout))
    }

    pub(crate) async fn write(&mut self, bytes: &[u8], limit: Duration) -> Result<(), Lost> {
        let io = &mut self.io;
        let write = async move {
            match io {
                Io::Plain(stream) => stream.write_all(Buf::from_slice(bytes)).await.0,
                Io::Tls(stream) => stream.write_all(bytes).await,
            }
        };
        match timeout(left(self.end, limit), write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Lost::Closed),
            Err(_) => Err(Lost::Timeout),
        }
    }

    pub(crate) async fn starttls(
        self,
        connector: &Connector,
        name: &str,
        limit: Duration,
    ) -> Result<Self, Lost> {
        if self.responses.pending() {
            return Err(Lost::Reply);
        }
        let Io::Plain(io) = self.io else {
            return Err(Lost::Tls);
        };
        match timeout(
            left(self.end, limit),
            connector.connect(io, name, Verify::Any),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(Self {
                io: Io::Tls(Box::new(stream)),
                responses: Responses::default(),
                end: self.end,
            }),
            Ok(Err(_)) => Err(Lost::Tls),
            Err(_) => Err(Lost::Timeout),
        }
    }

    pub(crate) async fn quit(mut self) {
        if self.write(QUIT, QUIT_WAIT).await.is_ok() {
            let _ = self.response(QUIT_WAIT).await;
        }
        let _ = match &mut self.io {
            Io::Plain(stream) => stream.shutdown().await,
            Io::Tls(stream) => stream.shutdown().await,
        };
    }
}

async fn fill(io: &mut Io, responses: &mut Responses) -> Result<(), Lost> {
    let n = match io {
        Io::Plain(stream) => {
            let (read, buf) = stream.read(Buf::new(READ)).await;
            let n = read.map_err(|_| Lost::Closed)?;
            responses.input(&buf);
            n
        }
        Io::Tls(stream) => {
            let mut buf = [0; READ];
            let n = stream.read(&mut buf).await.map_err(|_| Lost::Closed)?;
            responses.input(&buf[..n]);
            n
        }
    };
    if n == 0 {
        return Err(Lost::Closed);
    }
    Ok(())
}
