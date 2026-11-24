use std::io;
use std::path::Path;
use std::time::Duration;

use rt::{Buf, UnixStream, timeout};

use crate::proto::{Frames, Reply, Request};

const READ: usize = 4096;

pub async fn call(
    socket: &Path,
    server: u32,
    request: &Request,
    wait: Duration,
) -> io::Result<Reply> {
    timeout(wait, exchange(socket, server, request))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

async fn exchange(socket: &Path, server: u32, request: &Request) -> io::Result<Reply> {
    let (stream, uid) = UnixStream::connect(socket).await?;
    if uid != server {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is served by uid {uid}", socket.display()),
        ));
    }
    let (written, _) = stream.write_all(Buf::from_slice(&request.encode())).await;
    written?;
    let mut frames = Frames::default();
    loop {
        match frames.pop() {
            Ok(Some(body)) => {
                return Reply::decode(&body)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
            }
            Ok(None) => {}
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        }
        let (read, buf) = stream.read(Buf::new(READ)).await;
        match read? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => frames.push(&buf[..n]),
        }
    }
}
