mod bodies;
mod error;
mod intake;
mod items;
mod limits;

pub use bodies::{KIND_BODY_CHUNK, Written, decode_chunk};
pub use error::Error;
pub use intake::{Body, Head, Intake, Message, MessageId, Slice};
pub use items::{
    BODY_ITEM, HEAD_CLEAR, HeadClear, SLICE_BASE, STATE_BASE, slice_item, slice_parts,
};
pub use limits::{Limits, SLICE};
