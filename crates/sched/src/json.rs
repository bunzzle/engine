use std::fmt::Write as _;

use crypto::Ids;
use http::{json_string, rfc3339};

use crate::events::Kind;
use crate::reader::Read;

pub fn event_json(read: &Read, ids: &Ids, out: &mut String) {
    let event = &read.event;
    out.push_str("{\"id\":\"ev_");
    for byte in read.id {
        let _ = write!(out, "{byte:02x}");
    }
    out.push_str("\",\"type\":");
    json_string(kind_name(event.kind), out);
    out.push_str(",\"time\":");
    json_string(&rfc3339(event.time), out);
    out.push_str(",\"message_id\":");
    json_string(&ids.encode(&event.message.bytes()), out);
    let _ = write!(out, ",\"recipient\":{}", event.recipient);
    if let Some(body) = &read.body {
        out.push_str(",\"address\":");
        json_string(&String::from_utf8_lossy(&body.address), out);
        if !body.reply.is_empty() {
            out.push_str(",\"reply\":");
            json_string(&String::from_utf8_lossy(&body.reply), out);
        }
        let _ = write!(out, ",\"attempts\":{}", body.attempts);
    }
    if event.lost > 0 {
        let _ = write!(out, ",\"lost\":{}", event.lost);
    }
    out.push('}');
}

pub fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Delivered => "delivered",
        Kind::Deferred => "deferred",
        Kind::Failed => "failed",
        Kind::Expired => "expired",
        Kind::Canceled => "canceled",
        Kind::Suppressed => "suppressed",
        Kind::Bounced => "bounced",
        Kind::Complained => "complained",
    }
}
