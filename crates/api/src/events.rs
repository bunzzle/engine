use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Write as _;

use crypto::Ids;
use http::{Request, Response};
use rt::timeout;
use sched::{EVENTS_LIMIT, EventPage, ReadError, Transport, event_json};

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
    let wait = context.guard.limits().ask;
    let page = timeout(wait, node.events(tenant, after, limit))
        .await
        .map_err(|_| Problem::unavailable())?
        .map_err(problem)?;
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
        ReadError::Stale => Problem::cursor_expired(),
        ReadError::Unavailable | ReadError::Failed => Problem::unavailable(),
    }
}

fn body(page: &EventPage, ids: &Ids) -> String {
    let mut out = String::from("{\"events\":[");
    for (n, read) in page.events.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        event_json(read, ids, &mut out);
    }
    out.push_str("],\"next\":");
    json::string(&page.next, &mut out);
    let _ = write!(out, ",\"more\":{}}}", page.more);
    out
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
    fn read_errors_keep_their_status() {
        let cases = [
            (ReadError::Tenant, 403, "tenant_suspended"),
            (ReadError::Limit, 400, "bad_request"),
            (ReadError::Cursor, 400, "bad_cursor"),
            (ReadError::Stale, 410, "cursor_expired"),
            (ReadError::Unavailable, 503, "unavailable"),
            (ReadError::Failed, 503, "unavailable"),
        ];
        for (error, status, code) in cases {
            let problem = problem(error);
            assert_eq!((problem.status.code(), problem.code), (status, code));
        }
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
