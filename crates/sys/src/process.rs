use std::io;

use crate::check;

#[allow(unsafe_code)]
pub fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[allow(unsafe_code)]
pub fn private_umask() {
    // SAFETY: `umask` only swaps the process file mode mask and cannot fail.
    unsafe { libc::umask(0o077) };
}

#[allow(unsafe_code)]
pub fn no_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid `rlimit` that lives for the call.
    check(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) })?;
    #[cfg(target_os = "linux")]
    // SAFETY: `PR_SET_DUMPABLE` takes one integer argument; the rest are ignored.
    check(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    Ok(())
}

#[allow(unsafe_code)]
pub fn lock_memory() -> io::Result<()> {
    // SAFETY: plain system call with constant flags.
    check(unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) }).map(drop)
}

#[cfg(test)]
mod tests {
    #[test]
    fn core_dumps_turn_off() {
        super::no_core_dumps().expect("core dumps off");
    }
}
