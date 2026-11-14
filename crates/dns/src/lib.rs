mod error;
mod name;
mod resolver;
pub mod wire;

pub use error::Error;
pub use name::Name;
pub use resolver::{Found, Lookup, Resolver, Settings};
pub use wire::{Record, Type};
