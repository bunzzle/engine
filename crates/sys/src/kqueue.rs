use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr;
use std::time::Duration;

use crate::check;

const WAKE: usize = 0;
const EMPTY: libc::kevent = libc::kevent {
    ident: 0,
    filter: 0,
    flags: 0,
    fflags: 0,
    data: 0,
    udata: ptr::null_mut(),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub token: usize,
    pub wake: bool,
}

pub struct Kqueue {
    fd: OwnedFd,
}

impl Kqueue {
    #[allow(unsafe_code)]
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain system call without arguments.
        let fd = check(unsafe { libc::kqueue() })?;
        // SAFETY: `kqueue` returned a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: the descriptor is owned by `fd` and stays open for the call.
        check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
        let kqueue = Self { fd };
        kqueue.change(&[change(
            WAKE,
            libc::EVFILT_USER,
            libc::EV_ADD | libc::EV_CLEAR,
            0,
        )])?;
        Ok(kqueue)
    }

    pub fn watch(&self, fd: BorrowedFd<'_>, token: usize) -> io::Result<()> {
        let ident = usize::try_from(fd.as_raw_fd()).map_err(|_| io::Error::other("bad fd"))?;
        let flags = libc::EV_ADD | libc::EV_CLEAR;
        let mut read = change(ident, libc::EVFILT_READ, flags, 0);
        let mut write = change(ident, libc::EVFILT_WRITE, flags, 0);
        read.udata = ptr::without_provenance_mut(token);
        write.udata = ptr::without_provenance_mut(token);
        self.change(&[read, write])
    }

    pub fn wake(&self) -> io::Result<()> {
        self.change(&[change(WAKE, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER)])
    }

    #[allow(unsafe_code)]
    pub fn wait(&self, out: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        let mut events = [EMPTY; 64];
        let spec = timeout.map(|t| libc::timespec {
            tv_sec: libc::time_t::try_from(t.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_nsec: libc::c_long::from(t.subsec_nanos()),
        });
        let spec_ptr = spec.as_ref().map_or(ptr::null(), ptr::from_ref);
        let capacity = libc::c_int::try_from(events.len()).expect("fits");
        // SAFETY: `events` is writable for `capacity` entries and `spec_ptr` is null or points to `spec`.
        let result = unsafe {
            libc::kevent(
                self.fd.as_raw_fd(),
                ptr::null(),
                0,
                events.as_mut_ptr(),
                capacity,
                spec_ptr,
            )
        };
        let count = match check(result) {
            Ok(count) => usize::try_from(count).expect("count is not negative"),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => 0,
            Err(e) => return Err(e),
        };
        out.extend(events[..count].iter().map(|e| Event {
            token: e.udata.addr(),
            wake: e.filter == libc::EVFILT_USER,
        }));
        Ok(())
    }

    #[allow(unsafe_code)]
    fn change(&self, changes: &[libc::kevent]) -> io::Result<()> {
        let count = libc::c_int::try_from(changes.len()).expect("fits");
        // SAFETY: `changes` is readable for `count` entries; no events are returned.
        check(unsafe {
            libc::kevent(
                self.fd.as_raw_fd(),
                changes.as_ptr(),
                count,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        })
        .map(drop)
    }
}

fn change(ident: usize, filter: i16, flags: u16, note: u32) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags,
        fflags: note,
        ..EMPTY
    }
}
