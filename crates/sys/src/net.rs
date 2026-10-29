use std::io;
use std::mem::size_of;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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
pub fn listen(addr: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
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
