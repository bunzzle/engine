mod bodies;
mod error;
mod intake;
mod items;
mod limits;
mod recipients;

pub use bodies::{KIND_BODY_CHUNK, Written, decode_chunk};
pub use error::Error;
pub use intake::{Body, Head, Message, MessageId, Slice, Spool};
pub use items::{
    BODY_ITEM, HEAD_CLEAR, HeadClear, SLICE_BASE, STATE_BASE, STATE_CLEAR, Stamp, StateClear,
    slice_item, slice_parts, state_item,
};
pub use limits::{Limits, SLICE};
pub use recipients::{Done, Outcome, Recipient, Reply, Report, Status};
