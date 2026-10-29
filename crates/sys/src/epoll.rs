use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::check;

const WAKE: u64 = 0;
const EMPTY: libc::epoll_event = libc::epoll_event { events: 0, u64: 0 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub token: usize,
    pub wake: bool,
}

pub struct Epoll {
    fd: OwnedFd,
    wake: EventFd,
}

impl Epoll {
    #[allow(unsafe_code)]
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain system call with a flag argument.
        let fd = check(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })?;
        // SAFETY: `epoll_create1` returned a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let epoll = Self {
            fd,
            wake: EventFd::new()?,
        };
        epoll.add(epoll.wake.as_fd(), libc::EPOLLIN | libc::EPOLLET, WAKE)?;
        Ok(epoll)
    }

    pub fn watch(&self, fd: BorrowedFd<'_>, token: usize) -> io::Result<()> {
        let events = libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLRDHUP | libc::EPOLLET;
        self.add(fd, events, token as u64)
    }

    pub fn wake(&self) -> io::Result<()> {
        self.wake.notify()
    }

    #[allow(unsafe_code)]
    pub fn wait(&self, out: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        let mut events = [EMPTY; 64];
        let millis = timeout.map_or(-1, |t| {
            let ms = t.as_nanos().div_ceil(1_000_000);
            libc::c_int::try_from(ms).unwrap_or(libc::c_int::MAX)
        });
        let capacity = libc::c_int::try_from(events.len()).expect("fits");
        // SAFETY: `events` is writable for `capacity` entries.
        let result =
            unsafe { libc::epoll_wait(self.fd.as_raw_fd(), events.as_mut_ptr(), capacity, millis) };
        let count = match check(result) {
            Ok(count) => usize::try_from(count).expect("count is not negative"),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => 0,
            Err(e) => return Err(e),
        };
        for event in &events[..count] {
            let token = event.u64;
            if token == WAKE {
                self.wake.drain();
            }
            out.push(Event {
                token: usize::try_from(token).unwrap_or(usize::MAX),
                wake: token == WAKE,
            });
        }
        Ok(())
    }

    #[allow(unsafe_code, clippy::cast_sign_loss)]
    fn add(&self, fd: BorrowedFd<'_>, events: libc::c_int, token: u64) -> io::Result<()> {
        let mut event = libc::epoll_event {
            events: events as u32,
            u64: token,
        };
        // SAFETY: both descriptors are open for the call and `event` is a valid event.
        check(unsafe {
            libc::epoll_ctl(
                self.fd.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                fd.as_raw_fd(),
                &raw mut event,
            )
        })
        .map(drop)
    }
}

pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    #[allow(unsafe_code)]
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain system call with value and flag arguments.
        let fd = check(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })?;
        // SAFETY: `eventfd` returned a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd })
    }

    #[allow(unsafe_code)]
    pub fn notify(&self) -> io::Result<()> {
        // SAFETY: the descriptor is owned by `self` and stays open for the call.
        match check(unsafe { libc::eventfd_write(self.fd.as_raw_fd(), 1) }) {
            Err(e) if e.kind() != io::ErrorKind::WouldBlock => Err(e),
            _ => Ok(()),
        }
    }

    #[allow(unsafe_code)]
    pub fn drain(&self) {
        let mut value: libc::eventfd_t = 0;
        // SAFETY: the descriptor is owned by `self` and `value` is writable.
        let _ = unsafe { libc::eventfd_read(self.fd.as_raw_fd(), &raw mut value) };
    }
}

impl AsFd for EventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
