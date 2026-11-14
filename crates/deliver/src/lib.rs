mod classify;
mod conn;
mod deliver;
mod mx;
mod pool;
mod settings;

pub use classify::{answer, kind};
pub use deliver::{Deliver, Message, Outcome};
pub use mx::Dns;
pub use pool::{Remote, limits};
pub use settings::{EightBit, Settings, Timeouts};
