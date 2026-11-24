use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

const STICKY: u32 = 0o1000;

pub fn socket_path(socket: &Path, uid: u32) -> Result<PathBuf, String> {
    let (Some(parent), Some(name)) = (socket.parent(), socket.file_name()) else {
        return Err(format!("{} is not a socket path", socket.display()));
    };
    if !socket.is_absolute() {
        return Err(format!("{} must be an absolute path", socket.display()));
    }
    let real = fs::canonicalize(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    for (depth, dir) in real.ancestors().enumerate() {
        let meta = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if meta.uid() != uid && meta.uid() != 0 {
            return Err(format!("{} belongs to another user", dir.display()));
        }
        let shared = meta.mode() & 0o022 != 0;
        if shared && (depth == 0 || meta.mode() & STICKY == 0) {
            return Err(format!(
                "{} must not be writable by group or others",
                dir.display()
            ));
        }
    }
    Ok(real.join(name))
}

pub fn clear_socket(socket: &Path) -> Result<(), String> {
    let meta = match fs::symlink_metadata(socket) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", socket.display())),
    };
    if !meta.file_type().is_socket() {
        return Err(format!("{} exists and is not a socket", socket.display()));
    }
    match sys::net::unix_connect(socket) {
        Ok(_) => Err(format!("a process already listens on {}", socket.display())),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            Err(format!("a process already listens on {}", socket.display()))
        }
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            fs::remove_file(socket).map_err(|e| format!("{}: {e}", socket.display()))
        }
        Err(e) => Err(format!("{}: {e}", socket.display())),
    }
}
