pub mod buf;
pub mod crc32c;
#[cfg(target_os = "linux")]
pub mod epoll;
pub mod fs;
#[cfg(target_os = "macos")]
pub mod kqueue;
pub mod net;
#[cfg(target_os = "linux")]
pub mod uring;

#[cfg(target_os = "linux")]
pub use epoll::{Epoll as Poller, Event};
#[cfg(target_os = "macos")]
pub use kqueue::{Event, Kqueue as Poller};

use std::io;

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
