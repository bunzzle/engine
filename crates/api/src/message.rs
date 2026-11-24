use std::fmt::Write as _;

use control::Grant;
use crypto::Ids;
use http::{Request, Response, rfc3339};
use rt::timeout;
use sched::{MESSAGE_LIMIT, MessagePage, Transport};
use spool::{MessageId, Status};

use crate::events::{Held, problem};
use crate::handler::ok;
use crate::json;
use crate::problem::Problem;
use crate::server::{Context, Stop};

pub(crate) const PREFIX: &str = "/v1/messages/";

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Asked {
    pub(crate) id: MessageId,
    after: Option<u32>,
    limit: usize,
}

impl Asked {
    pub(crate) fn parse(ids: &Ids, request: &Request) -> Result<Self, Problem> {
        let text = request.path.strip_prefix(PREFIX).unwrap_or_default();
        let bytes = ids.decode(text.as_bytes()).ok_or_else(Problem::not_found)?;
        let (after, limit) = query(request.query.as_deref())?;
        Ok(Self {
            id: MessageId::from_bytes(bytes),
            after,
            limit,
        })
    }
}

pub(crate) fn ids<T: Transport + 'static>(context: &Context<T>) -> Result<Ids, Problem> {
    let ids = context.node.ids().ok_or_else(Problem::unavailable)?;
    Ids::new(&ids).map_err(|_| Problem::unavailable())
}

pub(crate) async fn read<T: Transport + 'static>(
    context: &Context<T>,
    grant: Grant,
    request: &Request,
    id: &str,
) -> Result<Response, Stop> {
    let ids = ids(context)?;
    let asked = Asked::parse(&ids, request)?;
    let Some(_held) = Held::take(&context.looking, grant.tenant) else {
        return Err(Problem::rate_limited().into());
    };
    let wait = context.guard.limits().ask;
    let found = timeout(
        wait,
        context.node.message(
            grant.tenant,
            grant.generation,
            asked.id,
            asked.after,
            asked.limit,
        ),
    )
    .await
    .map_err(|_| Problem::unavailable())?
    .map_err(problem)?;
    let page = found.ok_or_else(Problem::not_found)?;
    let message = ids.encode(&asked.id.bytes());
    Ok(ok(id, body(&message, &page)))
}

fn query(query: Option<&str>) -> Result<(Option<u32>, usize), Problem> {
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
    let after = after
        .map(|text| {
            number(text)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| Problem::bad_request("`after` must be a recipient index"))
        })
        .transpose()?;
    let limit = match limit {
        None => MESSAGE_LIMIT,
        Some(text) => number(text)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| (1..=MESSAGE_LIMIT).contains(n))
            .ok_or_else(|| Problem::bad_request(format!("`limit` must be 1 to {MESSAGE_LIMIT}")))?,
    };
    Ok((after, limit))
}

fn number(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn state(status: Status) -> &'static str {
    match status {
        Status::Ready => "queued",
        Status::Deferred => "deferred",
        Status::Delivered => "delivered",
        Status::Failed => "failed",
    }
}

fn body(message: &str, page: &MessagePage) -> String {
    let mut out = String::from("{\"id\":");
    json::string(message, &mut out);
    let done = if page.done { "done" } else { "queued" };
    let _ = write!(out, ",\"state\":\"{done}\",\"recipients\":[");
    for (n, recipient) in page.recipients.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"index\":{},\"address\":", recipient.index);
        json::string(&recipient.address, &mut out);
        let _ = write!(
            out,
            ",\"state\":\"{}\",\"attempts\":{}",
            state(recipient.status),
            recipient.attempts
        );
        if !recipient.status.is_final() {
            out.push_str(",\"next_attempt\":");
            json::string(&rfc3339(recipient.due), &mut out);
        }
        out.push('}');
    }
    let _ = write!(out, "],\"more\":{}}}", page.more);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sched::MessageRecipient;

    #[test]
    fn reads_after_and_limit_once() {
        assert_eq!(query(None).expect("none"), (None, MESSAGE_LIMIT));
        assert_eq!(query(Some("")).expect("empty"), (None, MESSAGE_LIMIT));
        assert_eq!(query(Some("after=0&limit=7")).expect("both"), (Some(0), 7));
        assert_eq!(
            query(Some("after=4294967295")).expect("max"),
            (Some(u32::MAX), MESSAGE_LIMIT)
        );
        for bad in [
            "limit=0",
            "limit=101",
            "limit=+5",
            "limit=",
            "after=",
            "after=-1",
            "after=4294967296",
            "after=99999999999",
            "after=1&after=2",
            "other=1",
            "after",
            "after=1&",
        ] {
            assert!(query(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_the_message_id_from_the_path() {
        let ids = Ids::new(&crypto::Secret::new([7; 16])).expect("ids");
        let id = MessageId {
            node: 2,
            shard: 5,
            key: 1 << 40 | 9,
        };
        let mut request = Request {
            path: format!("{PREFIX}{}", ids.encode(&id.bytes())),
            method: "GET".into(),
            query: Some("limit=2".into()),
            headers: http::Headers::default(),
            body: http::Framing::None,
            expect: false,
            close: false,
        };
        let asked = Asked::parse(&ids, &request).expect("asked");
        assert_eq!((asked.id, asked.after, asked.limit), (id, None, 2));
        for path in [PREFIX.to_owned(), format!("{PREFIX}nope"), "/v1/x".into()] {
            request.path = path;
            let problem = Asked::parse(&ids, &request).expect_err("bad id");
            assert_eq!(problem.code, "not_found");
        }
    }

    #[test]
    fn writes_the_page() {
        let recipient = |index, status| MessageRecipient {
            index,
            address: format!("r{index}@example.com"),
            status,
            attempts: 2,
            due: 1000,
        };
        let page = MessagePage {
            done: false,
            recipients: vec![
                recipient(0, Status::Deferred),
                recipient(1, Status::Delivered),
            ],
            more: true,
        };
        assert_eq!(
            body("m\"1", &page),
            "{\"id\":\"m\\\"1\",\"state\":\"queued\",\"recipients\":[\
             {\"index\":0,\"address\":\"r0@example.com\",\"state\":\"deferred\",\"attempts\":2,\
             \"next_attempt\":\"1970-01-01T00:00:01.000Z\"},\
             {\"index\":1,\"address\":\"r1@example.com\",\"state\":\"delivered\",\"attempts\":2}],\
             \"more\":true}"
        );
        let finished = MessagePage {
            done: true,
            recipients: Vec::new(),
            more: false,
        };
        assert_eq!(
            body("m", &finished),
            "{\"id\":\"m\",\"state\":\"done\",\"recipients\":[],\"more\":false}"
        );
    }
}
