use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Write as _;

use crypto::Ids;
use http::{Request, Response, rfc3339};
use sched::{EVENTS_LIMIT, EventKind, EventPage, EventRead, ReadError, Transport};

use crate::handler::ok;
use crate::json;
use crate::problem::Problem;
use crate::server::{Context, Stop};

const LIMIT: usize = 100;

pub(crate) async fn read<T: Transport + 'static>(
    context: &Context<T>,
    tenant: u32,
    request: &Request,
    id: &str,
) -> Result<Response, Stop> {
    let (after, limit) = query(request.query.as_deref())?;
    let Some(_held) = Held::take(&context.reading, tenant) else {
        return Err(Problem::rate_limited().into());
    };
    let node = &context.node;
    let ids = node.ids().ok_or_else(Problem::unavailable)?;
    let ids = Ids::new(&ids).map_err(|_| Problem::unavailable())?;
    let page = node.events(tenant, after, limit).await.map_err(problem)?;
    Ok(ok(id, body(&page, &ids)))
}

struct Held<'a> {
    reading: &'a RefCell<BTreeSet<u32>>,
    tenant: u32,
}

impl<'a> Held<'a> {
    fn take(reading: &'a RefCell<BTreeSet<u32>>, tenant: u32) -> Option<Self> {
        if !reading.borrow_mut().insert(tenant) {
            return None;
        }
        Some(Self { reading, tenant })
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.reading.borrow_mut().remove(&self.tenant);
    }
}

fn query(query: Option<&str>) -> Result<(Option<&str>, usize), Problem> {
    let mut after = None;
    let mut limit = None;
    let pairs = query.filter(|q| !q.is_empty()).map(|q| q.split('&'));
    for pair in pairs.into_iter().flatten() {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| Problem::bad_request("query not accepted"))?;
        let slot = match name {
            "after" => &mut after,
            "limit" => &mut limit,
            _ => {
                return Err(Problem::bad_request(
                    "only `after` and `limit` are accepted",
                ));
            }
        };
        if slot.replace(value).is_some() {
            return Err(Problem::bad_request(format!("`{name}` given twice")));
        }
    }
    let limit = match limit {
        None => LIMIT,
        Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            text.parse().map_err(|_| bad_limit())?
        }
        Some(_) => return Err(bad_limit()),
    };
    Ok((after, limit))
}

fn bad_limit() -> Problem {
    Problem::bad_request(format!("`limit` must be 1 to {EVENTS_LIMIT}"))
}

fn problem(error: ReadError) -> Problem {
    match error {
        ReadError::Tenant => Problem::suspended(),
        ReadError::Limit => bad_limit(),
        ReadError::Cursor => Problem::bad_cursor(),
        ReadError::Stale | ReadError::Unavailable | ReadError::Failed => Problem::unavailable(),
    }
}

fn body(page: &EventPage, ids: &Ids) -> String {
    let mut out = String::from("{\"events\":[");
    for (n, read) in page.events.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        event(read, ids, &mut out);
    }
    out.push_str("],\"next\":");
    json::string(&page.next, &mut out);
    let _ = write!(out, ",\"more\":{}}}", page.more);
    out
}

fn event(read: &EventRead, ids: &Ids, out: &mut String) {
    let event = &read.event;
    out.push_str("{\"type\":");
    json::string(kind(event.kind), out);
    out.push_str(",\"time\":");
    json::string(&rfc3339(event.time), out);
    out.push_str(",\"message_id\":");
    json::string(&ids.encode(&event.message.bytes()), out);
    let _ = write!(out, ",\"recipient\":{}", event.recipient);
    if let Some(body) = &read.body {
        out.push_str(",\"address\":");
        json::string(&String::from_utf8_lossy(&body.address), out);
        if !body.reply.is_empty() {
            out.push_str(",\"reply\":");
            json::string(&String::from_utf8_lossy(&body.reply), out);
        }
        let _ = write!(out, ",\"attempts\":{}", body.attempts);
    }
    if event.lost > 0 {
        let _ = write!(out, ",\"lost\":{}", event.lost);
    }
    out.push('}');
}

fn kind(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Delivered => "delivered",
        EventKind::Deferred => "deferred",
        EventKind::Failed => "failed",
        EventKind::Expired => "expired",
        EventKind::Canceled => "canceled",
        EventKind::Suppressed => "suppressed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_read_per_tenant_at_a_time() {
        let reading = RefCell::default();
        let first = Held::take(&reading, 1).expect("first");
        assert!(Held::take(&reading, 1).is_none());
        let other = Held::take(&reading, 2).expect("other tenant");
        drop(first);
        assert!(Held::take(&reading, 1).is_some());
        drop(other);
        assert!(reading.borrow().is_empty());
    }

    #[test]
    fn reads_only_after_and_limit_once() {
        assert_eq!(query(None).expect("none"), (None, LIMIT));
        assert_eq!(query(Some("")).expect("empty"), (None, LIMIT));
        assert_eq!(
            query(Some("limit=7&after=ab")).expect("both"),
            (Some("ab"), 7)
        );
        assert_eq!(query(Some("limit=0")).expect("zero"), (None, 0));
        for bad in [
            "limit=1&limit=2",
            "after=a&after=a",
            "other=1",
            "limit",
            "limit=1&",
            "&limit=1",
            "limit=+5",
            "limit=-1",
            "limit=",
            "limit=99999999999999999999999",
        ] {
            assert!(query(Some(bad)).is_err(), "{bad}");
        }
    }
}
