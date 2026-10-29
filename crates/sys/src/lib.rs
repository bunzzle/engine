pub mod crc32c;
pub mod fs;
#[cfg(target_os = "macos")]
pub mod kqueue;
pub mod net;

use std::io;

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
