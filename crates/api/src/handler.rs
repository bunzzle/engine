use control::Grant;
use http::{Request, Response, Status};
use intake::{Envelope, Failure, Fault, Origin, Required, Submission, data_hold, message_limit};
use sched::{Draft, Node, Refusal, Transport, domain_of};
use smtp::{Decoder, Fault as LineFault};

use crate::json;
use crate::mime;
use crate::problem::Problem;
use crate::send;
use crate::server::{Context, Route, Stop};

const SLACK: u64 = 64 * 1024;

pub(crate) trait Source {
    fn start(&mut self, request: &Request, max: u64) -> Result<(), Stop>;
    async fn next(&mut self) -> Result<Option<Vec<u8>>, Stop>;
    fn secure(&self) -> bool;
}

pub(crate) struct Handler<'a, T, S> {
    pub(crate) context: &'a Context<T>,
    pub(crate) source: &'a mut S,
    pub(crate) grant: Grant,
    pub(crate) shard: u16,
}

impl<T: Transport + 'static, S: Source> Handler<'_, T, S> {
    pub(crate) async fn run(
        &mut self,
        route: Route,
        request: &Request,
        id: &str,
    ) -> Result<Response, Stop> {
        let message = match route {
            Route::Messages => self.send(request).await?,
            Route::Raw => self.raw(request).await?,
            Route::Health | Route::Other => return Err(Problem::not_found().into()),
        };
        Ok(accepted(id, &message))
    }

    async fn send(&mut self, request: &Request) -> Result<String, Stop> {
        let json = request
            .headers
            .get("content-type")
            .is_some_and(|value| media(value) == "application/json");
        if !json {
            return Err(Problem::media_type().into());
        }
        let node = &self.context.node;
        let limit = message_limit(node);
        let max = self
            .context
            .config
            .max_body
            .unwrap_or(limit / 3 * 4 + SLACK);
        let spool = node.spool();
        let hold = max + 2 * limit + 2 * chunk(node);
        let hold = usize::try_from(hold).unwrap_or(usize::MAX);
        let Some(_hold) = self.context.guard.reserve(hold) else {
            return Err(Problem::unavailable().close().into());
        };
        self.source.start(request, max)?;
        let mut body = Vec::new();
        while let Some(bytes) = self.source.next().await? {
            body.extend_from_slice(&bytes);
        }
        let recipients = spool.limits().recipients as usize;
        let send = send::parse(&body, recipients, limit)?;
        drop(body);
        self.submit(send, limit).await
    }

    async fn submit(&mut self, send: send::Send, limit: u64) -> Result<String, Stop> {
        let node = &self.context.node;
        let mut draft = self.draft(&send.sender, &send.recipients).await?;
        let mut submission = self.open(&mut draft).await?;
        let boundary = format!("=_{}", submission.id());
        let built = mime::build(&send.message, &boundary).map_err(mime_fault)?;
        if built.len() as u64 > limit {
            return Err(Problem::too_large().into());
        }
        submission
            .push(node, self.grant, &built)
            .await
            .map_err(failure)?;
        drop(built);
        let envelope = (send.sender, send.recipients, send.require_tls);
        self.seal(submission, draft, envelope).await
    }

    async fn raw(&mut self, request: &Request) -> Result<String, Stop> {
        let rfc822 = request
            .headers
            .get("content-type")
            .is_some_and(|value| media(value) == "message/rfc822");
        if !rfc822 {
            return Err(Problem::media_type().into());
        }
        let node = &self.context.node;
        let limit = message_limit(node);
        let recipients = node.spool().limits().recipients as usize;
        let raw = send::envelope(&request.headers, recipients)?;
        let mut draft = self.draft(&raw.sender, &raw.recipients).await?;
        let Some(_hold) = self.context.guard.reserve(data_hold(node)) else {
            return Err(Problem::unavailable().close().into());
        };
        let mut submission = self.open(&mut draft).await?;
        self.source.start(request, limit)?;
        let mut lines = Decoder::chunks(limit);
        let mut out = Vec::new();
        while let Some(bytes) = self.source.next().await? {
            lines.feed(&bytes, &mut out);
            line_fault(&lines)?;
            submission
                .push(&self.context.node, self.grant, &out)
                .await
                .map_err(failure)?;
            out.clear();
        }
        lines.finish(&mut out);
        line_fault(&lines)?;
        submission
            .push(&self.context.node, self.grant, &out)
            .await
            .map_err(failure)?;
        let envelope = (raw.sender, raw.recipients, raw.require_tls);
        self.seal(submission, draft, envelope).await
    }

    async fn draft(&mut self, sender: &str, recipients: &[String]) -> Result<Draft, Stop> {
        let node = &self.context.node;
        let grant = self.grant;
        let domain = domain_of(sender).ok_or_else(|| Problem::bad_address("envelope_from"))?;
        if node.table().sender(grant.tenant, &domain).is_none() {
            return Err(Problem::sender().into());
        }
        let mut draft = node
            .draft(grant.tenant, Some(grant.pool))
            .map_err(refusal)?;
        if draft.generation() != grant.generation {
            return Err(Problem::suspended().into());
        }
        let addresses: Vec<&str> = recipients.iter().map(String::as_str).collect();
        let results = node.recipients(&mut draft, &addresses).await;
        let mut refused = Vec::new();
        for (address, result) in addresses.iter().zip(results) {
            match result {
                Ok(_) => {}
                Err(Refusal::Address) => refused.push(((*address).to_owned(), "bad_address")),
                Err(Refusal::Suppressed) => refused.push(((*address).to_owned(), "suppressed")),
                Err(other) => return Err(refusal(other).into()),
            }
        }
        if !refused.is_empty() {
            return Err(Problem::refused(refused).into());
        }
        Ok(draft)
    }

    async fn open(&mut self, draft: &mut Draft) -> Result<Submission, Stop> {
        let node = &self.context.node;
        Ok(Submission::open(node, draft, self.shard)
            .await
            .map_err(failure)?)
    }

    async fn seal(
        &mut self,
        submission: Submission,
        draft: Draft,
        (sender, recipients, require_tls): (String, Vec<String>, bool),
    ) -> Result<String, Stop> {
        let with = if self.source.secure() {
            "HTTPS"
        } else {
            "HTTP"
        };
        let origin = Origin {
            node: &self.context.config.name,
            with,
            lifetime: self.context.config.lifetime,
        };
        let envelope = Envelope {
            sender,
            required: Required {
                requiretls: require_tls,
                ..Required::default()
            },
            ..Envelope::default()
        };
        let node = &self.context.node;
        Ok(submission
            .finish(node, self.grant, &origin, draft, envelope, &recipients)
            .await
            .map_err(failure)?)
    }
}

pub(crate) fn chunk<T: Transport + 'static>(node: &Node<T>) -> u64 {
    let spool = node.spool();
    spool.stream_chunk().max(spool.limits().inline) as u64
}

fn accepted(request: &str, message: &str) -> Response {
    let mut out = String::from("{\"id\":");
    json::string(message, &mut out);
    out.push('}');
    ok(request, out)
}

pub(crate) fn ok(request: &str, body: String) -> Response {
    Response::new(Status::OK)
        .header("Request-Id", request)
        .and_then(|r| r.body("application/json", body.into_bytes()))
        .unwrap_or_else(|_| Response::new(Status::INTERNAL))
}

fn line_fault(lines: &Decoder) -> Result<(), Problem> {
    match lines.fault() {
        None => Ok(()),
        Some(LineFault::Size) => Err(Problem::too_large()),
        Some(LineFault::Cr(_)) => Err(Problem::bad_message("bare CR in the message")),
        Some(LineFault::Nul(_)) => Err(Problem::bad_message("NUL in the message")),
        Some(LineFault::Long(_)) => Err(Problem::bad_message("line longer than 998 octets")),
    }
}

fn media(value: &[u8]) -> String {
    let end = value.iter().position(|&b| b == b';').unwrap_or(value.len());
    String::from_utf8_lossy(value[..end].trim_ascii()).to_ascii_lowercase()
}

pub(crate) fn refusal(refusal: Refusal) -> Problem {
    match refusal {
        Refusal::Tenant => Problem::suspended(),
        Refusal::Pool => Problem::pool(),
        Refusal::Recipients => Problem::too_many_recipients(),
        Refusal::Address => Problem::bad_address("to"),
        Refusal::Suppressed => Problem::refused(Vec::new()),
        Refusal::Busy => Problem::rate_limited(),
        Refusal::Conflict
        | Refusal::Message
        | Refusal::Keys
        | Refusal::Signer
        | Refusal::Failed => Problem::unavailable(),
    }
}

fn failure(failure: Failure) -> Problem {
    match failure {
        Failure::Header(Fault::TooLarge) | Failure::TooBig => Problem::too_large(),
        Failure::Header(Fault::Signer) | Failure::Temporary => Problem::unavailable(),
        Failure::Header(_) => Problem::bad_header(),
        Failure::FromDomain | Failure::NoKey => Problem::sender(),
        Failure::Refused(r) => refusal(r),
    }
}

fn mime_fault(fault: mime::Fault) -> Problem {
    match fault {
        mime::Fault::Address => Problem::bad_address("from"),
        mime::Fault::Header => Problem::bad_header(),
        mime::Fault::ContentType => Problem::bad_message("`attachments.content_type` not accepted"),
        mime::Fault::ContentId => Problem::bad_message("`attachments.content_id` not accepted"),
        mime::Fault::Filename => Problem::bad_message("`attachments.filename` not accepted"),
        mime::Fault::Body => Problem::bad_message("message body not accepted"),
    }
}
