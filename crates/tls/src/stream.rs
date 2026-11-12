use std::io::{self, Read, Write};
use std::mem;
use std::sync::Arc;

use rt::{Buf, TcpStream};
use rustls::crypto::CryptoProvider;
use rustls::server::ServerSessionMemoryCache;
use rustls::version::{TLS12, TLS13};
use rustls::{Connection, ServerConfig, ServerConnection};

use crate::{Certs, Clock, Error};

const CHUNK: usize = 17 * 1024;
const SESSIONS: usize = 4096;

pub struct Acceptor {
    config: Arc<ServerConfig>,
}

impl Acceptor {
    pub fn new(provider: Arc<CryptoProvider>, certs: Arc<Certs>) -> Result<Self, Error> {
        let mut config = ServerConfig::builder_with_details(provider, Arc::new(Clock))
            .with_protocol_versions(&[&TLS13, &TLS12])?
            .with_no_client_auth()
            .with_cert_resolver(certs);
        config.require_ems = true;
        config.session_storage = ServerSessionMemoryCache::new(SESSIONS);
        config.send_tls13_tickets = 1;
        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.config
    }

    pub async fn accept(&self, io: TcpStream) -> io::Result<Stream> {
        let conn = ServerConnection::new(Arc::clone(&self.config)).map_err(invalid)?;
        let mut stream = Stream::new(io, conn.into());
        stream.handshake().await?;
        Ok(stream)
    }
}

pub struct Stream {
    io: TcpStream,
    conn: Connection,
    rx: Buf,
    start: usize,
    tx: Buf,
    eof: bool,
}

impl Stream {
    pub fn new(io: TcpStream, conn: Connection) -> Self {
        Self {
            io,
            conn,
            rx: Buf::new(CHUNK),
            start: 0,
            tx: Buf::new(CHUNK),
            eof: false,
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn server_name(&self) -> Option<&str> {
        match &self.conn {
            Connection::Server(conn) => conn.server_name(),
            Connection::Client(_) => None,
        }
    }

    pub async fn handshake(&mut self) -> io::Result<()> {
        while self.conn.is_handshaking() {
            self.step().await?;
        }
        self.flush().await
    }

    pub async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.conn.reader().read(out) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.step().await?,
                done => return done,
            }
        }
    }

    pub async fn write_all(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n = self.conn.writer().write(data)?;
            data = &data[n..];
            self.flush().await?;
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.flush().await?;
        self.io.shutdown().await
    }

    fn check(&self) -> io::Result<()> {
        if self.rx.capacity() == 0 || self.tx.capacity() == 0 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }

    async fn step(&mut self) -> io::Result<()> {
        self.flush().await?;
        self.check()?;
        if self.start == self.rx.len() {
            if self.eof {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.rx.clear();
            self.start = 0;
            let (read, rx) = self.io.read(mem::replace(&mut self.rx, Buf::new(0))).await;
            self.rx = rx;
            if read? == 0 {
                self.eof = true;
                self.conn.read_tls(&mut io::empty())?;
                self.process().await?;
                if self.conn.is_handshaking() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                return Ok(());
            }
        }
        while self.start < self.rx.len() && self.conn.wants_read() {
            let n = self.conn.read_tls(&mut &self.rx[self.start..])?;
            self.start += n;
            self.process().await?;
            if n == 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        self.flush().await
    }

    async fn process(&mut self) -> io::Result<()> {
        match self.conn.process_new_packets() {
            Ok(_) => Ok(()),
            Err(e) => {
                let _ = self.flush().await;
                Err(invalid(e))
            }
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            self.check()?;
            self.tx.clear();
            self.conn.write_tls(&mut Out(&mut self.tx))?;
            let (written, tx) = self
                .io
                .write_all(mem::replace(&mut self.tx, Buf::new(0)))
                .await;
            self.tx = tx;
            written?;
        }
        Ok(())
    }
}

struct Out<'a>(&'a mut Buf);

impl Write for Out<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        Ok(self.0.extend_from_slice(data))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid(e: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
