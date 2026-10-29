use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;

use crate::check;

#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
pub fn full_sync(file: &File) -> io::Result<()> {
    // SAFETY: the descriptor is owned by `file` and stays open for the call.
    check(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) }).map(drop)
}

#[cfg(not(target_vendor = "apple"))]
#[allow(unsafe_code)]
pub fn full_sync(file: &File) -> io::Result<()> {
    // SAFETY: the descriptor is owned by `file` and stays open for the call.
    check(unsafe { libc::fdatasync(file.as_raw_fd()) }).map(drop)
}

#[allow(unsafe_code, clippy::useless_conversion)]
pub fn block_size(file: &File) -> io::Result<u32> {
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the descriptor is owned by `file`, and `stat` points to writable memory of the right type.
    check(unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) })?;
    // SAFETY: `fstatfs` returned success, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    u32::try_from(stat.f_bsize).map_err(|_| io::Error::other("block size out of range"))
}
