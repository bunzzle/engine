mod classify;
mod conn;
mod deliver;
mod mx;
mod settings;

pub use classify::{answer, kind};
pub use deliver::{Deliver, Message, Outcome};
pub use mx::Dns;
pub use settings::{EightBit, Settings, Timeouts};
