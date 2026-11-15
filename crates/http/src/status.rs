#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status(u16);

impl Status {
    pub const CONTINUE: Self = Self(100);
    pub const OK: Self = Self(200);
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const REQUEST_TIMEOUT: Self = Self(408);
    pub const LENGTH_REQUIRED: Self = Self(411);
    pub const TOO_LARGE: Self = Self(413);
    pub const URI_TOO_LONG: Self = Self(414);
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    pub const EXPECTATION_FAILED: Self = Self(417);
    pub const UNPROCESSABLE: Self = Self(422);
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    pub const HEADERS_TOO_LARGE: Self = Self(431);
    pub const INTERNAL: Self = Self(500);
    pub const NOT_IMPLEMENTED: Self = Self(501);
    pub const UNAVAILABLE: Self = Self(503);
    pub const VERSION: Self = Self(505);

    pub const fn code(self) -> u16 {
        self.0
    }

    pub const fn reason(self) -> &'static str {
        match self.0 {
            100 => "Continue",
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            411 => "Length Required",
            413 => "Content Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            417 => "Expectation Failed",
            422 => "Unprocessable Content",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            501 => "Not Implemented",
            503 => "Service Unavailable",
            505 => "HTTP Version Not Supported",
            _ => "Internal Server Error",
        }
    }
}
