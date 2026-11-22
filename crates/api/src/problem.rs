use http::{Response, Status};

use crate::json;

const RETRY: &str = "5";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub status: Status,
    pub code: &'static str,
    pub message: String,
    pub refused: Vec<(String, &'static str)>,
    pub allow: &'static str,
    pub close: bool,
}

impl Problem {
    pub fn new(status: Status, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            refused: Vec::new(),
            allow: "",
            close: false,
        }
    }

    #[must_use]
    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    pub fn framing(status: Status) -> Self {
        let code = match status.code() {
            411 => "length_required",
            413 => "too_large",
            414 => "uri_too_long",
            431 => "headers_too_large",
            501 => "not_implemented",
            505 => "version_not_supported",
            408 => "timeout",
            _ => "bad_request",
        };
        Self::new(status, code, status.reason()).close()
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(Status::BAD_REQUEST, "bad_request", message)
    }

    pub fn bad_address(field: &str) -> Self {
        Self::new(
            Status::BAD_REQUEST,
            "bad_address",
            format!("`{field}` is not a valid address"),
        )
    }

    pub fn bad_header() -> Self {
        Self::new(Status::BAD_REQUEST, "bad_header", "header not accepted")
    }

    pub fn bad_message(message: impl Into<String>) -> Self {
        Self::new(Status::BAD_REQUEST, "bad_message", message)
    }

    pub fn bad_cursor() -> Self {
        Self::new(
            Status::BAD_REQUEST,
            "bad_cursor",
            "`after` is not a valid cursor",
        )
    }

    pub fn cursor_expired() -> Self {
        Self::new(
            Status::GONE,
            "cursor_expired",
            "cursor expired, read again without `after`",
        )
    }

    pub fn unauthorized() -> Self {
        Self::new(Status::UNAUTHORIZED, "unauthorized", "unauthorized")
    }

    pub fn scope() -> Self {
        Self::new(
            Status::FORBIDDEN,
            "scope_not_allowed",
            "key scope not allowed",
        )
    }

    pub fn sender() -> Self {
        Self::new(
            Status::FORBIDDEN,
            "sender_not_allowed",
            "sender domain not verified",
        )
    }

    pub fn suspended() -> Self {
        Self::new(Status::FORBIDDEN, "tenant_suspended", "account not active")
    }

    pub fn pool() -> Self {
        Self::new(Status::FORBIDDEN, "pool_not_allowed", "pool not allowed")
    }

    pub fn not_found() -> Self {
        Self::new(Status::NOT_FOUND, "not_found", "not found")
    }

    pub fn method(allow: &'static str) -> Self {
        Self {
            allow,
            ..Self::new(
                Status::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "method not allowed",
            )
        }
    }

    pub fn media_type() -> Self {
        Self::new(
            Status::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "unsupported media type",
        )
    }

    pub fn too_large() -> Self {
        Self::new(Status::TOO_LARGE, "too_large", "message too large")
    }

    pub fn no_recipients() -> Self {
        Self::new(Status::UNPROCESSABLE, "no_recipients", "no recipients")
    }

    pub fn too_many_recipients() -> Self {
        Self::new(
            Status::UNPROCESSABLE,
            "too_many_recipients",
            "too many recipients",
        )
    }

    pub fn idempotency_conflict() -> Self {
        Self::new(
            Status::UNPROCESSABLE,
            "idempotency_conflict",
            "key used with another request",
        )
    }

    pub fn refused(refused: Vec<(String, &'static str)>) -> Self {
        Self {
            refused,
            ..Self::new(
                Status::UNPROCESSABLE,
                "recipients_refused",
                "recipients refused",
            )
        }
    }

    pub fn rate_limited() -> Self {
        Self::new(
            Status::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests",
        )
    }

    pub fn unavailable() -> Self {
        Self::new(Status::UNAVAILABLE, "unavailable", "try again later")
    }

    pub fn response(&self, request: &str) -> Response {
        let mut body = String::from("{\"error\":{\"code\":");
        json::string(self.code, &mut body);
        body.push_str(",\"message\":");
        json::string(&self.message, &mut body);
        body.push_str(",\"request\":");
        json::string(request, &mut body);
        if !self.refused.is_empty() {
            body.push_str(",\"refused\":[");
            for (n, (address, code)) in self.refused.iter().enumerate() {
                if n > 0 {
                    body.push(',');
                }
                body.push_str("{\"address\":");
                json::string(address, &mut body);
                body.push_str(",\"code\":");
                json::string(code, &mut body);
                body.push('}');
            }
            body.push(']');
        }
        body.push_str("}}");
        let mut response = Response::new(self.status)
            .header("Request-Id", request)
            .and_then(|r| r.body("application/json", body.into_bytes()))
            .unwrap_or_else(|_| Response::new(Status::INTERNAL));
        match self.status.code() {
            401 => response = with(response, "WWW-Authenticate", "Bearer"),
            405 => response = with(response, "Allow", self.allow),
            429 | 503 => response = with(response, "Retry-After", RETRY),
            _ => {}
        }
        if self.close {
            response = response.close();
        }
        response
    }
}

fn with(response: Response, name: &'static str, value: &str) -> Response {
    let fallback = response.clone();
    response.header(name, value).unwrap_or(fallback)
}
