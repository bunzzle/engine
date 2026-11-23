use crypto::Ids;
use http::{Request, Response, parse_rfc3339};
use rt::timeout;
use sched::{
    EventKind, SEARCH_DAYS, SEARCH_LIMIT, SearchField, SearchQuery, Transport, event_kind_name,
};

use crate::events::{Held, body, problem};
use crate::handler::ok;
use crate::problem::Problem;
use crate::server::{Context, Stop};

const LIMIT: usize = 25;
const DAY: u64 = 86_400_000;
const VALUE: usize = 1024;
const NAMES: [&str; 8] = [
    "recipient",
    "domain",
    "message",
    "type",
    "from",
    "to",
    "limit",
    "after",
];
const KINDS: [EventKind; 6] = [
    EventKind::Delivered,
    EventKind::Deferred,
    EventKind::Failed,
    EventKind::Expired,
    EventKind::Canceled,
    EventKind::Suppressed,
];

pub(crate) async fn read<T: Transport + 'static>(
    context: &Context<T>,
    tenant: u32,
    request: &Request,
    id: &str,
) -> Result<Response, Stop> {
    let asked = Asked::parse(request.query.as_deref())?;
    let node = &context.node;
    let ids = node.ids().ok_or_else(Problem::unavailable)?;
    let ids = Ids::new(&ids).map_err(|_| Problem::unavailable())?;
    let now = node.sched().clock().now();
    let query = asked.query(&ids, now)?;
    let Some(_held) = Held::take(&context.searching, tenant) else {
        return Err(Problem::rate_limited().into());
    };
    let wait = context.guard.limits().ask;
    let page = timeout(
        wait,
        node.search(tenant, &query, asked.after.as_deref(), asked.limit),
    )
    .await
    .map_err(|_| Problem::unavailable())?
    .map_err(problem)?;
    Ok(ok(id, body(&page, &ids)))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Asked {
    field: Option<(SearchField, Vec<u8>)>,
    kinds: Vec<EventKind>,
    from: Option<u64>,
    to: Option<u64>,
    limit: usize,
    after: Option<String>,
}

impl Asked {
    fn parse(query: Option<&str>) -> Result<Self, Problem> {
        let mut asked = Self {
            limit: LIMIT,
            ..Self::default()
        };
        let mut seen = Vec::new();
        let pairs = query.filter(|q| !q.is_empty()).map(|q| q.split('&'));
        for pair in pairs.into_iter().flatten() {
            let (name, raw) = pair
                .split_once('=')
                .ok_or_else(|| Problem::bad_request("query not accepted"))?;
            if !NAMES.contains(&name) {
                return Err(Problem::bad_request(
                    "only `recipient`, `domain`, `message`, `type`, `from`, `to`, `limit` \
                     and `after` are accepted",
                ));
            }
            if seen.contains(&name) {
                return Err(Problem::bad_request(format!("`{name}` given twice")));
            }
            seen.push(name);
            if name == "after" {
                asked.after = Some(raw.to_owned());
                continue;
            }
            let value = unescape(raw)
                .ok_or_else(|| Problem::bad_request(format!("`{name}` is not a valid value")))?;
            match name {
                "recipient" => asked.pick(SearchField::Recipient, value)?,
                "domain" => asked.pick(SearchField::Domain, value)?,
                "message" => asked.pick(SearchField::Message, value)?,
                "type" => asked.kinds = kinds(&value)?,
                "from" => asked.from = Some(time("from", &value)?),
                "to" => asked.to = Some(time("to", &value)?),
                "limit" => asked.limit = limit(&value)?,
                _ => unreachable!("names checked above"),
            }
        }
        if asked.field.is_none() {
            return Err(Problem::bad_request(
                "one of `recipient`, `domain` or `message` is required",
            ));
        }
        Ok(asked)
    }

    fn pick(&mut self, field: SearchField, value: Vec<u8>) -> Result<(), Problem> {
        if self.field.is_some() {
            return Err(Problem::bad_request(
                "give only one of `recipient`, `domain` or `message`",
            ));
        }
        self.field = Some((field, value));
        Ok(())
    }

    fn query(&self, ids: &Ids, now: u64) -> Result<SearchQuery, Problem> {
        let (field, value) = self.field.as_ref().expect("checked in parse");
        let raw = match field {
            SearchField::Message => ids
                .decode(value)
                .ok_or_else(|| Problem::bad_request("`message` is not a message id"))?
                .to_vec(),
            _ => value.clone(),
        };
        let resumed = self.after.is_some();
        let (from, to) = match (self.from, self.to) {
            (Some(from), Some(to)) => (from, to),
            (Some(from), None) if resumed => (from, from.saturating_add(1)),
            (None, Some(to)) if resumed => (to.saturating_sub(1), to),
            (from, to) => {
                let to = to.unwrap_or(now.saturating_add(1));
                (from.unwrap_or(to.saturating_sub(DAY)), to)
            }
        };
        if from >= to {
            return Err(Problem::bad_request("`from` must be before `to`"));
        }
        if (to - 1) / DAY - from / DAY >= SEARCH_DAYS {
            return Err(Problem::bad_request(format!(
                "`from` to `to` may span at most {SEARCH_DAYS} UTC days"
            )));
        }
        let built = SearchQuery::new(*field, &raw, &self.kinds, from, to).ok_or_else(|| {
            Problem::bad_request(format!("`{}` is not a valid value", name(*field)))
        })?;
        Ok(built.fixed(self.from.is_some(), self.to.is_some()))
    }
}

fn name(field: SearchField) -> &'static str {
    match field {
        SearchField::Recipient => "recipient",
        SearchField::Domain => "domain",
        SearchField::Message => "message",
    }
}

fn unescape(raw: &str) -> Option<Vec<u8>> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let pair = bytes.get(at + 1..at + 3)?;
            let text = std::str::from_utf8(pair).ok()?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(text, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
        if out.len() > VALUE {
            return None;
        }
    }
    Some(out)
}

fn kinds(value: &[u8]) -> Result<Vec<EventKind>, Problem> {
    let mut out = Vec::new();
    for part in value.split(|&b| b == b',') {
        let kind = KINDS
            .into_iter()
            .find(|k| event_kind_name(*k).as_bytes() == part)
            .ok_or_else(|| {
                Problem::bad_request(
                    "`type` takes delivered, deferred, failed, expired, canceled or suppressed",
                )
            })?;
        if !out.contains(&kind) {
            out.push(kind);
        }
    }
    Ok(out)
}

fn time(name: &str, value: &[u8]) -> Result<u64, Problem> {
    parse_rfc3339(value).ok_or_else(|| {
        Problem::bad_request(format!(
            "`{name}` must be an RFC 3339 UTC time like 2026-01-02T03:04:05Z"
        ))
    })
}

fn limit(value: &[u8]) -> Result<usize, Problem> {
    let bad = || Problem::bad_request(format!("`limit` must be 1 to {SEARCH_LIMIT}"));
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) || value.len() > 4 {
        return Err(bad());
    }
    let limit = std::str::from_utf8(value)
        .ok()
        .and_then(|t| t.parse().ok())
        .ok_or_else(bad)?;
    if limit == 0 || limit > SEARCH_LIMIT {
        return Err(bad());
    }
    Ok(limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Ids {
        Ids::new(&crypto::Secret::new([7; 16])).expect("ids")
    }

    fn parsed(query: &str) -> Asked {
        Asked::parse(Some(query)).expect(query)
    }

    #[test]
    fn reads_each_parameter_once() {
        let asked = parsed(
            "recipient=Ann%2Bnews@Example.com&type=failed,delivered,failed\
             &from=2026-11-20T00:00:00Z&to=2026-11-21T00:00:00.5Z&limit=100&after=ab",
        );
        assert_eq!(
            asked,
            Asked {
                field: Some((SearchField::Recipient, b"Ann+news@Example.com".to_vec())),
                kinds: vec![EventKind::Failed, EventKind::Delivered],
                from: Some(1_795_132_800_000),
                to: Some(1_795_219_200_500),
                limit: 100,
                after: Some("ab".into()),
            }
        );
        assert_eq!(parsed("domain=example.com").limit, LIMIT);
        assert_eq!(
            parsed("recipient=a+b@example.com").field,
            Some((SearchField::Recipient, b"a+b@example.com".to_vec()))
        );
        for bad in [
            "",
            "type=failed",
            "recipient=a@b.c&domain=b.c",
            "recipient=a@b.c&recipient=a@b.c",
            "recipient=a@b.c&limit=0",
            "recipient=a@b.c&limit=101",
            "recipient=a@b.c&limit=+5",
            "recipient=a@b.c&limit=",
            "recipient=a@b.c&limit=99999999999999999999",
            "recipient=a@b.c&type=",
            "recipient=a@b.c&type=sent",
            "recipient=a@b.c&type=failed,",
            "recipient=a@b.c&from=yesterday",
            "recipient=a@b.c&to=2026-11-20",
            "recipient=a%2",
            "recipient=a%zz",
            "recipient=a@b.c&other=1",
            "recipient",
            "recipient=a@b.c&",
        ] {
            let problem = Asked::parse(Some(bad)).expect_err(bad);
            assert_eq!(problem.code, "bad_request", "{bad}");
        }
        let long = format!("recipient={}", "a".repeat(VALUE + 1));
        assert!(Asked::parse(Some(&long)).is_err());
        let cursor = "ab".repeat(1400);
        let long = parsed(&format!("domain=b.c&after={cursor}"));
        assert_eq!(long.after.as_deref(), Some(cursor.as_str()));
        let unknown = Asked::parse(Some("x=%zz")).expect_err("unknown");
        assert!(unknown.message.contains("only"), "{}", unknown.message);
    }

    #[test]
    fn resolves_the_time_range() {
        let ids = ids();
        let now = 10 * DAY + 5;
        let range = |text: &str| {
            parsed(text)
                .query(&ids, now)
                .map(|q| (q.field(), q.value().to_vec()))
        };
        assert!(range("domain=Example.COM").is_ok());
        let both = parsed("domain=b.c&from=1970-01-03T00:00:00Z&to=1970-01-11T00:00:00Z");
        assert!(both.query(&ids, now).is_ok());
        for bad in [
            "domain=b.c&from=1970-01-02T00:00:00Z",
            "domain=b.c&from=1970-01-05T00:00:00Z&to=1970-01-05T00:00:00Z",
            "domain=b.c&from=1970-01-12T00:00:00Z",
            "message=nope",
            "domain=@",
        ] {
            let problem = parsed(bad).query(&ids, now).expect_err(bad);
            assert_eq!(problem.code, "bad_request", "{bad}");
        }
        let week = "domain=b.c&from=1970-01-04T00:00:00Z";
        assert!(parsed(week).query(&ids, now).is_ok());
        let later = now + 2 * DAY;
        assert!(parsed(week).query(&ids, later).is_err());
        let resumed = parsed(&format!("{week}&after=ab")).query(&ids, later);
        assert!(resumed.is_ok());
        let until = "domain=b.c&to=1970-01-04T00:00:00Z&after=ab";
        assert!(parsed(until).query(&ids, later).is_ok());
        let id = ids.encode(&[3; 16]);
        let (field, value) = range(&format!("message={id}")).expect("message");
        assert_eq!((field, value), (SearchField::Message, vec![3; 16]));
    }
}
