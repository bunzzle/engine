use std::io;
use std::mem::{offset_of, size_of};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::check;

enum Raw {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl Raw {
    fn new(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => Self::V4(libc::sockaddr_in {
                #[cfg(target_vendor = "apple")]
                sin_len: u8::try_from(size_of::<libc::sockaddr_in>()).expect("fits"),
                sin_family: libc::sa_family_t::try_from(libc::AF_INET).expect("fits"),
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            }),
            SocketAddr::V6(a) => Self::V6(libc::sockaddr_in6 {
                #[cfg(target_vendor = "apple")]
                sin6_len: u8::try_from(size_of::<libc::sockaddr_in6>()).expect("fits"),
                sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).expect("fits"),
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            }),
        }
    }

    fn domain(&self) -> libc::c_int {
        match self {
            Self::V4(_) => libc::AF_INET,
            Self::V6(_) => libc::AF_INET6,
        }
    }

    fn as_ptr(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::V4(a) => (
                std::ptr::from_ref(a).cast(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in>()).expect("fits"),
            ),
            Self::V6(a) => (
                std::ptr::from_ref(a).cast(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_in6>()).expect("fits"),
            ),
        }
    }
}

#[allow(unsafe_code)]
fn stream_socket(domain: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain system call with constant arguments.
    let fd = check(unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) })?;
    // SAFETY: `socket` returned a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: the descriptor is owned by `fd` and stays open for the call.
    check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
    Ok(fd)
}

#[allow(unsafe_code)]
pub fn listen(addr: SocketAddr, backlog: u32, shared: bool) -> io::Result<TcpListener> {
    let raw = Raw::new(&addr);
    let fd = stream_socket(raw.domain())?;
    let on: libc::c_int = 1;
    let len = libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("fits");
    // SAFETY: the descriptor is open, and `on` lives for the call with the given length.
    check(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            std::ptr::from_ref(&on).cast(),
            len,
        )
    })?;
    if shared {
        // SAFETY: the descriptor is open, and `on` lives for the call with the given length.
        check(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                std::ptr::from_ref(&on).cast(),
                len,
            )
        })?;
    }
    let (ptr, len) = raw.as_ptr();
    // SAFETY: `ptr` points to a socket address of `len` bytes owned by `raw`.
    check(unsafe { libc::bind(fd.as_raw_fd(), ptr, len) })?;
    let backlog = libc::c_int::try_from(backlog).unwrap_or(libc::c_int::MAX);
    // SAFETY: the descriptor is open and bound.
    check(unsafe { libc::listen(fd.as_raw_fd(), backlog) })?;
    let listener = TcpListener::from(fd);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[allow(unsafe_code)]
pub fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let raw = Raw::new(&addr);
    let stream = TcpStream::from(stream_socket(raw.domain())?);
    stream.set_nonblocking(true)?;
    let (ptr, len) = raw.as_ptr();
    // SAFETY: `ptr` points to a socket address of `len` bytes owned by `raw`.
    match check(unsafe { libc::connect(stream.as_raw_fd(), ptr, len) }) {
        Ok(_) => Ok(stream),
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => Ok(stream),
        Err(e) => Err(e),
    }
}

pub fn transient(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::ECONNABORTED
                | libc::EINTR
                | libc::EAGAIN
        )
    )
}

#[cfg(target_vendor = "apple")]
const UNIX_PATH: usize = 104;
#[cfg(not(target_vendor = "apple"))]
const UNIX_PATH: usize = 108;

fn unix_addr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= UNIX_PATH || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unusable socket path",
        ));
    }
    let len = offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    let mut addr = libc::sockaddr_un {
        #[cfg(target_vendor = "apple")]
        sun_len: u8::try_from(len).expect("fits"),
        sun_family: libc::sa_family_t::try_from(libc::AF_UNIX).expect("fits"),
        sun_path: [0; UNIX_PATH],
    };
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = libc::c_char::from_ne_bytes([*byte]);
    }
    Ok((addr, libc::socklen_t::try_from(len).expect("fits")))
}

#[allow(unsafe_code)]
pub fn unix_connect(path: &Path) -> io::Result<UnixStream> {
    let (addr, len) = unix_addr(path)?;
    let stream = UnixStream::from(stream_socket(libc::AF_UNIX)?);
    stream.set_nonblocking(true)?;
    // SAFETY: `addr` is a socket address of `len` bytes that lives for the call.
    match check(unsafe { libc::connect(stream.as_raw_fd(), std::ptr::from_ref(&addr).cast(), len) })
    {
        Ok(_) => Ok(stream),
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => Ok(stream),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let size = libc::socklen_t::try_from(size_of::<libc::ucred>()).expect("fits");
    let mut len = size;
    // SAFETY: the descriptor stays open for the call, and `cred` is writable for `len` bytes.
    check(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast(),
            &raw mut len,
        )
    })?;
    if len != size {
        return Err(io::Error::other("short peer credentials"));
    }
    Ok(cred.uid)
}

#[cfg(not(target_os = "linux"))]
#[allow(unsafe_code)]
pub fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the descriptor stays open for the call, and both outputs are writable.
    check(unsafe { libc::getpeereid(fd.as_raw_fd(), &raw mut uid, &raw mut gid) })?;
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use super::{peer_uid, unix_addr, unix_connect};
    use crate::process::euid;

    #[test]
    fn refuses_unusable_paths() {
        assert!(unix_addr(Path::new("")).is_err());
        assert!(unix_addr(Path::new(&"a".repeat(super::UNIX_PATH))).is_err());
        assert!(unix_addr(Path::new("/tmp/a\0b")).is_err());
        assert!(unix_addr(Path::new(&"a".repeat(super::UNIX_PATH - 1))).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn both_ends_see_the_peer_uid() {
        let dir = std::env::temp_dir().join(format!("sys-net-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("s");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");
        let client = unix_connect(&path).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        assert_eq!(peer_uid(server.as_fd()).expect("server side"), euid());
        assert_eq!(peer_uid(client.as_fd()).expect("client side"), euid());
        drop(listener);
        std::fs::remove_dir_all(&dir).expect("clean");
    }

    #[test]
    fn only_resource_errors_are_transient() {
        let error = |code| std::io::Error::from_raw_os_error(code);
        assert!(super::transient(&error(libc::EMFILE)));
        assert!(super::transient(&error(libc::ECONNABORTED)));
        assert!(!super::transient(&error(libc::EBADF)));
        assert!(!super::transient(&error(libc::EINVAL)));
        assert!(!super::transient(&std::io::Error::other("x")));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn missing_socket_is_an_error() {
        assert!(unix_connect(Path::new("/nonexistent/bunzzle.sock")).is_err());
    }
}
