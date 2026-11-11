pub mod base64;
mod canon;
mod error;
mod header;
mod sign;
mod tags;
mod verify;

pub use canon::BodyHash;
pub use error::Error;
pub use header::{Field, parse};
pub use sign::{SIGNED, Template, digest, header_list, signed, unsigned};
pub use verify::{Check, check};
