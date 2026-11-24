use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    Config(String),
    Io(io::Error),
    Random,
    Keys(keys::Error),
    Store(store::Error),
    Start(sched::Error),
    Tls(tls::Error),
    Bind(SocketAddr, io::Error),
    BindUnix(PathBuf, io::Error),
    Core(u16, String),
    Deadline,
    Stopped,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "{message}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Random => write!(f, "no random bytes"),
            Self::Keys(e) => write!(f, "keys: {e}"),
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Start(e) => write!(f, "{e}"),
            Self::Tls(e) => write!(f, "tls: {e}"),
            Self::Bind(address, e) => write!(f, "listen on {address}: {e}"),
            Self::BindUnix(path, e) => write!(f, "listen on {}: {e}", path.display()),
            Self::Core(core, message) => write!(f, "core {core}: {message}"),
            Self::Deadline => write!(f, "boot deadline passed"),
            Self::Stopped => write!(f, "stopped by another core"),
        }
    }
}

impl std::error::Error for Error {}
