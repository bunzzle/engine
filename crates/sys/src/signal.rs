use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::{mem, ptr};

use crate::check;

static PIPE: OnceLock<Pipe> = OnceLock::new();
static WRITE: AtomicI32 = AtomicI32::new(-1);
static PENDING: AtomicU32 = AtomicU32::new(0);
static TAKEN: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Signal {
    Hangup,
    Interrupt,
    Terminate,
}

impl Signal {
    pub const ALL: [Self; 3] = [Self::Hangup, Self::Interrupt, Self::Terminate];

    pub const fn bit(self) -> u32 {
        1 << self as u32
    }

    pub fn mask(signals: &[Self]) -> u32 {
        signals.iter().fold(0, |mask, signal| mask | signal.bit())
    }

    pub fn first(mask: u32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|signal| mask & signal.bit() != 0)
    }

    fn number(self) -> libc::c_int {
        match self {
            Self::Hangup => libc::SIGHUP,
            Self::Interrupt => libc::SIGINT,
            Self::Terminate => libc::SIGTERM,
        }
    }

    fn from_number(number: libc::c_int) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|signal| signal.number() == number)
    }
}

struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
}

impl Pipe {
    #[allow(unsafe_code)]
    fn new() -> io::Result<Self> {
        let mut fds: [libc::c_int; 2] = [-1; 2];
        open_pipe(&mut fds)?;
        // SAFETY: `pipe` returned a new read descriptor that nothing else owns.
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: `pipe` returned a new write descriptor that nothing else owns.
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        #[cfg(target_os = "macos")]
        for fd in [&read, &write] {
            // SAFETY: the descriptor is owned by this pipe and stays open for the call.
            check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
            // SAFETY: the descriptor is owned by this pipe and stays open for the call.
            check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
        }
        Ok(Self { read, write })
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn open_pipe(fds: &mut [libc::c_int; 2]) -> io::Result<()> {
    // SAFETY: `fds` is writable for the two descriptors `pipe2` returns.
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }).map(drop)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn open_pipe(fds: &mut [libc::c_int; 2]) -> io::Result<()> {
    // SAFETY: `fds` is writable for the two descriptors `pipe` returns.
    check(unsafe { libc::pipe(fds.as_mut_ptr()) }).map(drop)
}

pub struct Signals {
    read: BorrowedFd<'static>,
    mask: u32,
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl Signals {
    pub fn listen(signals: &[Signal]) -> io::Result<Self> {
        let mask = Signal::mask(signals);
        if mask == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no signals to listen for",
            ));
        }
        if TAKEN.swap(true, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "signals already have a listener",
            ));
        }
        let started = start(mask);
        if started.is_err() {
            TAKEN.store(false, Ordering::Release);
        }
        started
    }

    pub fn mask(&self) -> u32 {
        self.mask
    }

    pub fn take(&self) -> u32 {
        drain(self.read);
        let bits = PENDING.fetch_and(!self.mask, Ordering::AcqRel) & self.mask;
        drain(self.read);
        bits
    }

    pub fn restore(&self, bits: u32) {
        PENDING.fetch_or(bits & self.mask, Ordering::AcqRel);
        notify();
    }
}

impl AsFd for Signals {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.read
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        for (number, action) in self.previous.drain(..).rev() {
            let _ = set(number, &action);
        }
        TAKEN.store(false, Ordering::Release);
    }
}

pub fn raise(signal: Signal) -> io::Result<()> {
    send(signal.number())
}

fn start(mask: u32) -> io::Result<Signals> {
    if PIPE.get().is_none() {
        let _ = PIPE.set(Pipe::new()?);
    }
    let pipe = PIPE.get().ok_or_else(|| io::Error::other("signal pipe"))?;
    WRITE.store(pipe.write.as_raw_fd(), Ordering::Release);
    drain(pipe.read.as_fd());
    PENDING.fetch_and(!mask, Ordering::AcqRel);
    let mut signals = Signals {
        read: pipe.read.as_fd(),
        mask,
        previous: Vec::new(),
    };
    for signal in Signal::ALL {
        if mask & signal.bit() != 0 {
            let previous = handle_with(signal.number())?;
            signals.previous.push((signal.number(), previous));
        }
    }
    Ok(signals)
}

#[allow(unsafe_code)]
fn drain(fd: BorrowedFd<'_>) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: `buf` is writable for its length and the descriptor stays open for the call.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            continue;
        }
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return;
    }
}

#[allow(unsafe_code)]
fn notify() {
    let fd = WRITE.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }
    let byte = 1u8;
    // SAFETY: `write` is async-signal-safe, `byte` is readable for one byte and the write end is never closed.
    let _ = unsafe { libc::write(fd, ptr::from_ref(&byte).cast(), 1) };
}

#[allow(unsafe_code)]
extern "C" fn on_signal(number: libc::c_int) {
    let slot = errno();
    // SAFETY: `errno` points to the calling thread's error slot.
    let saved = unsafe { *slot };
    if let Some(signal) = Signal::from_number(number) {
        PENDING.fetch_or(signal.bit(), Ordering::AcqRel);
    }
    notify();
    // SAFETY: `errno` points to the calling thread's error slot.
    unsafe { *slot = saved };
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn errno() -> *mut libc::c_int {
    // SAFETY: returns the calling thread's error slot and has no preconditions.
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn errno() -> *mut libc::c_int {
    // SAFETY: returns the calling thread's error slot and has no preconditions.
    unsafe { libc::__error() }
}

#[allow(unsafe_code)]
fn handle_with(number: libc::c_int) -> io::Result<libc::sigaction> {
    // SAFETY: an all-zero `sigaction` is a valid value of a plain C struct.
    let mut action: libc::sigaction = unsafe { mem::zeroed() };
    action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: `sa_mask` is a writable signal set inside `action`.
    check(unsafe { libc::sigemptyset(&raw mut action.sa_mask) })?;
    // SAFETY: an all-zero `sigaction` is a valid value of a plain C struct.
    let mut previous: libc::sigaction = unsafe { mem::zeroed() };
    // SAFETY: both actions are valid and live for the call.
    check(unsafe { libc::sigaction(number, &raw const action, &raw mut previous) })?;
    Ok(previous)
}

#[allow(unsafe_code)]
fn set(number: libc::c_int, action: &libc::sigaction) -> io::Result<()> {
    // SAFETY: `action` is a valid action that lives for the call; the old one is not read back.
    check(unsafe { libc::sigaction(number, action, ptr::null_mut()) }).map(drop)
}

#[allow(unsafe_code)]
fn send(number: libc::c_int) -> io::Result<()> {
    // SAFETY: `getpid` takes no arguments and cannot fail.
    let pid = unsafe { libc::getpid() };
    // SAFETY: plain system call with a process id and a signal number.
    check(unsafe { libc::kill(pid, number) }).map(drop)
}
