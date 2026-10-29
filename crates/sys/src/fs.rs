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

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn allocate(file: &File, len: u64) -> io::Result<()> {
    if file.metadata()?.len() >= len {
        return Ok(());
    }
    let size = libc::off_t::try_from(len).map_err(|_| io::Error::other("length out of range"))?;
    // SAFETY: the descriptor is owned by `file` and stays open for the call.
    match check(unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, size) }) {
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => file.set_len(len),
        result => result.map(drop),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn allocate(file: &File, len: u64) -> io::Result<()> {
    if file.metadata()?.len() < len {
        file.set_len(len)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn sector_size(file: &File) -> io::Result<u32> {
    use std::os::unix::fs::FileTypeExt;

    if file.metadata()?.file_type().is_block_device() {
        let logical = block_ioctl(file, libc::BLKSSZGET)?;
        let physical = block_ioctl(file, libc::BLKPBSZGET)?;
        return Ok(logical.max(physical));
    }
    Ok(block_size(file)?.max(direct_align(file)?))
}

#[cfg(not(target_os = "linux"))]
pub fn sector_size(file: &File) -> io::Result<u32> {
    block_size(file)
}

#[allow(unsafe_code, clippy::useless_conversion)]
fn block_size(file: &File) -> io::Result<u32> {
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the descriptor is owned by `file`, and `stat` points to writable memory of the right type.
    check(unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) })?;
    // SAFETY: `fstatfs` returned success, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    u32::try_from(stat.f_bsize).map_err(|_| io::Error::other("block size out of range"))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn block_ioctl(file: &File, request: libc::Ioctl) -> io::Result<u32> {
    let mut value: libc::c_uint = 0;
    // SAFETY: both requests write one unsigned int to `value`; the descriptor stays open.
    check(unsafe { libc::ioctl(file.as_raw_fd(), request, &raw mut value) })?;
    Ok(value)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn direct_align(file: &File) -> io::Result<u32> {
    let mut stat = MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: an empty path with `AT_EMPTY_PATH` targets the descriptor, and `stat` is writable.
    let result = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_DIOALIGN,
            stat.as_mut_ptr(),
        )
    };
    match check(result) {
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => return Ok(0),
        result => result?,
    };
    // SAFETY: `statx` returned success and `stat` started zeroed, so every field is initialized.
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & libc::STATX_DIOALIGN == 0 {
        return Ok(0);
    }
    Ok(stat.stx_dio_offset_align)
}
