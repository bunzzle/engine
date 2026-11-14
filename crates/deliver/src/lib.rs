mod classify;
mod conn;
mod dane;
mod deliver;
mod https;
mod mx;
mod pool;
mod settings;
mod sts;

pub use classify::{answer, kind};
pub use deliver::{Deliver, Message, Outcome};
pub use mx::Dns;
pub use pool::{Remote, limits};
pub use settings::{EightBit, Settings, Timeouts};
