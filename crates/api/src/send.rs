use dkim::base64;

use crate::json::{self, Value};
use crate::mime::{self, Attachment, Mailbox, Message};
use crate::problem::Problem;

const FIELDS: [&str; 12] = [
    "from",
    "to",
    "cc",
    "bcc",
    "reply_to",
    "subject",
    "text",
    "html",
    "headers",
    "attachments",
    "envelope_from",
    "require_tls",
];
const ATTACHMENT: [&str; 4] = ["filename", "content_type", "data", "content_id"];

#[derive(Debug)]
pub struct Send {
    pub message: Message,
    pub sender: String,
    pub recipients: Vec<String>,
    pub require_tls: bool,
}

pub fn parse(body: &[u8], recipients: usize, message: u64) -> Result<Send, Problem> {
    let value = json::parse(body, json::Limits::default())
        .map_err(|_| Problem::bad_request("body is not valid JSON"))?;
    let fields = value
        .as_object()
        .ok_or_else(|| Problem::bad_request("body must be an object"))?;
    known(fields, &FIELDS, "")?;
    let from = value
        .get("from")
        .ok_or_else(|| Problem::bad_request("`from` is required"))?;
    let from = mailbox(from, "from")?;
    let to = list(value.get("to"), "to")?;
    let cc = list(value.get("cc"), "cc")?;
    let bcc = list(value.get("bcc"), "bcc")?;
    let reply_to = list(value.get("reply_to"), "reply_to")?;
    let subject = optional_str(&value, "subject")?.unwrap_or_default();
    let text = optional_str(&value, "text")?;
    let html = optional_str(&value, "html")?;
    if text.is_none() && html.is_none() {
        return Err(Problem::bad_message("`text` or `html` is required"));
    }
    let headers = headers(value.get("headers"))?;
    let attachments = attachments(value.get("attachments"), message)?;
    let sender = match value.get("envelope_from") {
        None => from.address.clone(),
        Some(v) => address(v, "envelope_from")?,
    };
    let require_tls = match value.get("require_tls") {
        None => false,
        Some(v) => v
            .as_bool()
            .ok_or_else(|| Problem::bad_request("`require_tls` must be a boolean"))?,
    };
    let mut all: Vec<String> = Vec::new();
    for mailbox in to.iter().chain(&cc).chain(&bcc) {
        if !all.iter().any(|a| a.eq_ignore_ascii_case(&mailbox.address)) {
            all.push(mailbox.address.clone());
        }
    }
    if all.is_empty() {
        return Err(Problem::no_recipients());
    }
    if all.len() > recipients {
        return Err(Problem::too_many_recipients());
    }
    Ok(Send {
        message: Message {
            from: Some(from),
            to,
            cc,
            reply_to,
            subject,
            text,
            html,
            headers,
            attachments,
        },
        sender,
        recipients: all,
        require_tls,
    })
}

fn known(fields: &[(String, Value)], allowed: &[&str], within: &str) -> Result<(), Problem> {
    match fields.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
        Some((key, _)) => Err(Problem::bad_request(format!(
            "unknown field `{within}{key}`"
        ))),
        None => Ok(()),
    }
}

fn optional_str(value: &Value, key: &str) -> Result<Option<String>, Problem> {
    match value.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| Problem::bad_request(format!("`{key}` must be a string"))),
    }
}

fn address(value: &Value, field: &str) -> Result<String, Problem> {
    let text = value
        .as_str()
        .ok_or_else(|| Problem::bad_request(format!("`{field}` must be an address")))?;
    if !mime::address_ok(text) {
        return Err(Problem::bad_address(field));
    }
    Ok(text.to_owned())
}

fn mailbox(value: &Value, field: &str) -> Result<Mailbox, Problem> {
    if value.as_str().is_some() {
        return Ok(Mailbox {
            address: address(value, field)?,
            name: None,
        });
    }
    let fields = value
        .as_object()
        .ok_or_else(|| Problem::bad_request(format!("`{field}` must be an address")))?;
    known(fields, &["address", "name"], &format!("{field}."))?;
    let address = value
        .get("address")
        .ok_or_else(|| Problem::bad_request(format!("`{field}.address` is required")))?;
    let name = match value.get("name") {
        None => None,
        Some(name) => Some(
            name.as_str()
                .ok_or_else(|| Problem::bad_request(format!("`{field}.name` must be a string")))?
                .to_owned(),
        ),
    };
    Ok(Mailbox {
        address: self::address(address, field)?,
        name,
    })
}

fn list(value: Option<&Value>, field: &str) -> Result<Vec<Mailbox>, Problem> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|item| mailbox(item, field)).collect(),
        Some(item) => Ok(vec![mailbox(item, field)?]),
    }
}

fn headers(value: Option<&Value>) -> Result<Vec<(String, String)>, Problem> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let fields = value
        .as_object()
        .ok_or_else(|| Problem::bad_request("`headers` must be an object"))?;
    let mut out = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        let value = value
            .as_str()
            .ok_or_else(|| Problem::bad_request("`headers` values must be strings"))?;
        if mime::denied(name) {
            return Err(Problem::bad_header());
        }
        out.push((name.clone(), value.to_owned()));
    }
    Ok(out)
}

fn attachments(value: Option<&Value>, limit: u64) -> Result<Vec<Attachment>, Problem> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| Problem::bad_request("`attachments` must be a list"))?;
    let mut total = 0u64;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let fields = item
            .as_object()
            .ok_or_else(|| Problem::bad_request("`attachments` items must be objects"))?;
        known(fields, &ATTACHMENT, "attachments.")?;
        let text = |key: &str| -> Result<String, Problem> {
            item.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Problem::bad_request(format!("`attachments.{key}` is required")))
        };
        let filename = text("filename")?;
        let content_type = text("content_type")?;
        let data = text("data")?;
        let content_id = match item.get("content_id") {
            None => None,
            Some(_) => Some(text("content_id")?),
        };
        total += data.len() as u64 / 4 * 3;
        if total > limit {
            return Err(Problem::too_large());
        }
        out.push(Attachment {
            filename,
            content_type,
            data: decode(data.as_bytes())?,
            content_id,
        });
    }
    Ok(out)
}

fn decode(text: &[u8]) -> Result<Vec<u8>, Problem> {
    let strict = text.len().is_multiple_of(4)
        && text
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    strict
        .then(|| base64::decode(text))
        .flatten()
        .ok_or_else(|| Problem::bad_message("`attachments.data` is not valid base64"))
}
