use std::fmt::Write as _;

use control::{ALL_EVENTS, Hook, HookState};
use crypto::Ids;
use http::{Request, Response, Status};
use sched::{HookChange, Transport};

use crate::handler::{Handler, Source, ok};
use crate::json::{self, Value};
use crate::problem::Problem;
use crate::server::Stop;

const MAX_BODY: u64 = 8 * 1024;
const TAG: [u8; 2] = *b"wh";
const EVENTS: [&str; 6] = [
    "delivered",
    "deferred",
    "failed",
    "expired",
    "canceled",
    "suppressed",
];

enum Path<'a> {
    All,
    One(&'a str),
    Rotate(&'a str),
    Secret(&'a str),
}

fn path(path: &str) -> Option<Path<'_>> {
    let rest = path.strip_prefix("/v1/webhooks")?;
    if rest.is_empty() {
        return Some(Path::All);
    }
    let rest = rest.strip_prefix('/')?;
    match rest.split_once('/') {
        None if !rest.is_empty() => Some(Path::One(rest)),
        Some((id, "rotate")) if !id.is_empty() => Some(Path::Rotate(id)),
        Some((id, "secret")) if !id.is_empty() => Some(Path::Secret(id)),
        _ => None,
    }
}

pub(crate) async fn handle<T: Transport + 'static, S: Source>(
    handler: &mut Handler<'_, T, S>,
    request: &Request,
    id: &str,
) -> Result<Response, Stop> {
    let ids = handler
        .context
        .node
        .ids()
        .ok_or_else(Problem::unavailable)?;
    let ids = Ids::new(&ids).map_err(|_| Problem::unavailable())?;
    let tenant = handler.grant.tenant;
    let node = &handler.context.node;
    let method = request.method.as_str();
    match path(&request.path).ok_or_else(Problem::not_found)? {
        Path::All => match method {
            "GET" => {
                let mut out = String::from("{\"webhooks\":[");
                for (n, hook) in node.hooks(tenant).iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    write(hook, &ids, None, &mut out);
                }
                out.push_str("]}");
                Ok(ok(id, out))
            }
            "POST" => {
                let body = handler.body(request).await?;
                let (url, events) = create(&body)?;
                let hook = node
                    .hook_new(tenant, &url, events)
                    .await
                    .map_err(|error| refusal(&error))?;
                let secret = secret(handler, &hook, hook.version).await.ok();
                let mut out = String::new();
                write(&hook, &ids, secret.as_deref(), &mut out);
                Ok(created(id, out))
            }
            _ => Err(Problem::method("GET, POST").into()),
        },
        Path::One(text) => {
            let body = match method {
                "PATCH" => Some(handler.body(request).await?),
                _ => None,
            };
            let hook = known(handler, &ids, text)?;
            match method {
                "GET" => Ok(ok(id, written(&hook, &ids, None))),
                "PATCH" => {
                    let change = change(body.as_deref().unwrap_or_default())?;
                    let hook = node
                        .hook_change(tenant, hook.id, change)
                        .await
                        .map_err(|error| refusal(&error))?;
                    Ok(ok(id, written(&hook, &ids, None)))
                }
                "DELETE" => {
                    node.hook_remove(tenant, hook.id)
                        .await
                        .map_err(|error| refusal(&error))?;
                    let mut out = String::from("{\"id\":");
                    json::string(&public(&ids, tenant, hook.id), &mut out);
                    out.push_str(",\"deleted\":true}");
                    Ok(ok(id, out))
                }
                _ => Err(Problem::method("GET, PATCH, DELETE").into()),
            }
        }
        Path::Rotate(text) => {
            let hook = known(handler, &ids, text)?;
            if method != "POST" {
                return Err(Problem::method("POST").into());
            }
            let hook = node
                .hook_rotate(tenant, hook.id)
                .await
                .map_err(|error| refusal(&error))?;
            let secret = secret(handler, &hook, hook.version).await?;
            Ok(ok(id, written(&hook, &ids, Some(&secret))))
        }
        Path::Secret(text) => {
            let hook = known(handler, &ids, text)?;
            if method != "GET" {
                return Err(Problem::method("GET").into());
            }
            let secret = secret(handler, &hook, hook.version).await?;
            let mut out = String::from("{\"id\":");
            json::string(&public(&ids, tenant, hook.id), &mut out);
            out.push_str(",\"secret\":");
            json::string(&secret, &mut out);
            let _ = write!(out, ",\"version\":{}}}", hook.version);
            Ok(ok(id, out))
        }
    }
}

impl<T: Transport + 'static, S: Source> Handler<'_, T, S> {
    async fn body(&mut self, request: &Request) -> Result<Vec<u8>, Stop> {
        let json = request
            .headers
            .get("content-type")
            .is_some_and(|value| crate::handler::media(value) == "application/json");
        if !json {
            return Err(Problem::media_type().into());
        }
        self.source.start(request, MAX_BODY)?;
        let mut body = Vec::new();
        while let Some(bytes) = self.source.next().await? {
            body.extend_from_slice(&bytes);
        }
        Ok(body)
    }
}

async fn secret<T: Transport + 'static, S: Source>(
    handler: &Handler<'_, T, S>,
    hook: &Hook,
    version: u8,
) -> Result<String, Stop> {
    let secret = handler
        .context
        .node
        .hook_secret(hook.tenant, hook.id, version)
        .await
        .map_err(|error| refusal(&error))?;
    Ok(format!("whsec_{}", dkim::base64::encode(secret.expose())))
}

fn known<T: Transport + 'static, S: Source>(
    handler: &Handler<'_, T, S>,
    ids: &Ids,
    text: &str,
) -> Result<Hook, Problem> {
    let tenant = handler.grant.tenant;
    let id = private(ids, tenant, text).ok_or_else(Problem::not_found)?;
    handler
        .context
        .node
        .hook(tenant, id)
        .map_err(|_| Problem::not_found())
}

pub(crate) fn public(ids: &Ids, tenant: u32, id: u32) -> String {
    let mut block = [0; 16];
    block[0..4].copy_from_slice(&tenant.to_le_bytes());
    block[6..8].copy_from_slice(&TAG);
    block[8..12].copy_from_slice(&id.to_le_bytes());
    format!("wh_{}", ids.encode(&block))
}

pub(crate) fn private(ids: &Ids, tenant: u32, text: &str) -> Option<u32> {
    let block = ids.decode(text.strip_prefix("wh_")?.as_bytes())?;
    let word = |at: usize| u32::from_le_bytes(block[at..at + 4].try_into().expect("4 bytes"));
    let fits = word(0) == tenant && block[4..6] == [0, 0] && block[6..8] == TAG && word(12) == 0;
    fits.then(|| word(8))
}

fn written(hook: &Hook, ids: &Ids, secret: Option<&str>) -> String {
    let mut out = String::new();
    write(hook, ids, secret, &mut out);
    out
}

fn write(hook: &Hook, ids: &Ids, secret: Option<&str>, out: &mut String) {
    out.push_str("{\"id\":");
    json::string(&public(ids, hook.tenant, hook.id), out);
    out.push_str(",\"url\":");
    json::string(&hook.url, out);
    out.push_str(",\"events\":[");
    let mut first = true;
    for (bit, name) in EVENTS.iter().enumerate() {
        if hook.events & (1 << bit) != 0 {
            if !first {
                out.push(',');
            }
            first = false;
            json::string(name, out);
        }
    }
    out.push_str("],\"state\":");
    json::string(state(hook.state), out);
    let _ = write!(out, ",\"version\":{}", hook.version);
    if let Some(secret) = secret {
        out.push_str(",\"secret\":");
        json::string(secret, out);
    }
    out.push('}');
}

fn state(state: HookState) -> &'static str {
    match state {
        HookState::Active => "active",
        HookState::Paused => "paused",
        HookState::Failing => "failing",
        HookState::Gone => "gone",
    }
}

fn object(body: &[u8], allowed: &[&str]) -> Result<Value, Problem> {
    let value = json::parse(body, json::Limits::default())
        .map_err(|_| Problem::bad_request("body is not valid JSON"))?;
    let fields = value
        .as_object()
        .ok_or_else(|| Problem::bad_request("body must be a JSON object"))?;
    if let Some((name, _)) = fields
        .iter()
        .find(|(name, _)| !allowed.contains(&name.as_str()))
    {
        return Err(Problem::bad_request(format!("`{name}` is not accepted")));
    }
    Ok(value)
}

fn url(value: &Value) -> Result<String, Problem> {
    let url = value
        .as_str()
        .ok_or_else(|| Problem::bad_request("`url` must be a string"))?;
    if !control::hook_url_ok(url) {
        return Err(Problem::bad_request(
            "`url` must be an https URL with a DNS host",
        ));
    }
    Ok(url.to_owned())
}

fn events(value: &Value) -> Result<u8, Problem> {
    let bad = || Problem::bad_request("`events` must be a non-empty list of event types");
    let mut mask = 0;
    for name in value.as_array().ok_or_else(bad)? {
        let name = name.as_str().ok_or_else(bad)?;
        let bit = EVENTS.iter().position(|e| *e == name).ok_or_else(bad)?;
        mask |= 1 << bit;
    }
    if mask == 0 {
        return Err(bad());
    }
    Ok(mask)
}

fn create(body: &[u8]) -> Result<(String, u8), Problem> {
    let value = object(body, &["url", "events"])?;
    let url = url(value
        .get("url")
        .ok_or_else(|| Problem::bad_request("`url` is required"))?)?;
    let events = value
        .get("events")
        .map(events)
        .transpose()?
        .unwrap_or(ALL_EVENTS);
    Ok((url, events))
}

fn change(body: &[u8]) -> Result<HookChange, Problem> {
    let value = object(body, &["url", "events", "enabled"])?;
    let enabled = value
        .get("enabled")
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| Problem::bad_request("`enabled` must be true or false"))
        })
        .transpose()?;
    Ok(HookChange {
        url: value.get("url").map(url).transpose()?.map(Into::into),
        events: value.get("events").map(events).transpose()?,
        enabled,
    })
}

fn created(id: &str, body: String) -> Response {
    Response::new(Status::CREATED)
        .header("Request-Id", id)
        .and_then(|r| r.body("application/json", body.into_bytes()))
        .unwrap_or_else(|_| Response::new(Status::INTERNAL))
}

fn refusal(error: &sched::Error) -> Problem {
    match error {
        sched::Error::Control(control::Error::Invalid("url")) => {
            Problem::bad_request("`url` must be an https URL with a DNS host")
        }
        sched::Error::Control(control::Error::Invalid("events")) => {
            Problem::bad_request("`events` must be a non-empty list of event types")
        }
        sched::Error::Control(control::Error::Refused) => Problem::not_found(),
        sched::Error::Control(control::Error::Full) => Problem::new(
            Status::UNPROCESSABLE,
            "webhook_limit",
            "endpoint or secret limit reached",
        ),
        _ => Problem::unavailable(),
    }
}
