use std::borrow::Cow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    code: u16,
    status: &'static str,
    text: Cow<'static, str>,
}

impl Reply {
    pub const fn new(code: u16, status: &'static str, text: &'static str) -> Self {
        Self {
            code,
            status,
            text: Cow::Borrowed(text),
        }
    }

    pub fn owned(code: u16, status: &'static str, text: String) -> Self {
        Self {
            code,
            status,
            text: Cow::Owned(text),
        }
    }

    pub fn code(&self) -> u16 {
        self.code
    }

    pub fn status(&self) -> &'static str {
        self.status
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn failure(&self) -> bool {
        self.code >= 400
    }

    pub(crate) fn overshoot(&self) -> bool {
        self.code == 452 && self.status == "4.5.3"
    }

    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.code.to_string().as_bytes());
        out.push(b' ');
        if !self.status.is_empty() {
            out.extend_from_slice(self.status.as_bytes());
            out.push(b' ');
        }
        out.extend(
            self.text
                .bytes()
                .map(|b| if (32..=126).contains(&b) { b } else { b' ' }),
        );
        out.extend_from_slice(b"\r\n");
    }
}

pub const OK: Reply = Reply::new(250, "2.0.0", "OK");
pub const SENDER_OK: Reply = Reply::new(250, "2.1.0", "Sender OK");
pub const RECIPIENT_OK: Reply = Reply::new(250, "2.1.5", "Recipient OK");
pub const AUTH_OK: Reply = Reply::new(235, "2.7.0", "Authentication succeeded");
pub const DATA_GO: Reply = Reply::new(354, "", "End data with <CR><LF>.<CR><LF>");
pub const TLS_GO: Reply = Reply::new(220, "2.0.0", "Ready to start TLS");
pub const BYE: Reply = Reply::new(221, "2.0.0", "Bye");
pub const HELP: Reply = Reply::new(214, "2.0.0", "No help available");
pub const VRFY: Reply = Reply::new(252, "2.5.0", "Cannot VRFY user");
pub const UNRECOGNIZED: Reply = Reply::new(500, "5.5.2", "Command unrecognized");
pub const LINE_TOO_LONG: Reply = Reply::new(500, "5.5.2", "Line too long");
pub const SYNTAX: Reply = Reply::new(501, "5.5.4", "Syntax error in parameters");
pub const NOT_IMPLEMENTED: Reply = Reply::new(502, "5.5.1", "Command not implemented");
pub const SEQUENCE: Reply = Reply::new(503, "5.5.1", "Bad sequence of commands");
pub const MECHANISM: Reply = Reply::new(504, "5.5.4", "Unrecognized authentication mechanism");
pub const PARAMETER: Reply = Reply::new(555, "5.5.4", "Parameter not recognized");
pub const TLS_FIRST: Reply = Reply::new(530, "5.7.0", "Must issue a STARTTLS command first");
pub const AUTH_FIRST: Reply = Reply::new(530, "5.7.0", "Authentication required");
pub const AUTH_SYNTAX: Reply = Reply::new(501, "5.5.2", "Cannot decode response");
pub const AUTH_CANCELLED: Reply = Reply::new(501, "5.7.0", "Authentication cancelled");
pub const AUTH_FAILED: Reply = Reply::new(535, "5.7.8", "Authentication credentials invalid");
pub const AUTH_TEMPORARY: Reply = Reply::new(454, "4.7.0", "Temporary authentication failure");
pub const NULL_SENDER: Reply = Reply::new(550, "5.7.1", "Null sender not allowed");
pub const SENDER_SYNTAX: Reply = Reply::new(553, "5.1.7", "Bad sender address syntax");
pub const RECIPIENT_SYNTAX: Reply = Reply::new(553, "5.1.3", "Bad recipient address syntax");
pub const UTF8: Reply = Reply::new(553, "5.6.7", "Non-ASCII addresses not supported");
pub const TOO_BIG: Reply = Reply::new(552, "5.3.4", "Message size exceeds limit");
pub const TOO_MANY_RECIPIENTS: Reply = Reply::new(452, "4.5.3", "Too many recipients");
pub const NO_RECIPIENTS: Reply = Reply::new(554, "5.5.1", "No valid recipients");
pub const TEMPORARY: Reply = Reply::new(451, "4.3.0", "Temporary failure");
pub const SYNC: Reply = Reply::new(554, "5.5.0", "Protocol synchronization error");
pub const ERRORS: Reply = Reply::new(421, "4.7.0", "Too many errors");
pub const AUTH_FAILURES: Reply = Reply::new(421, "4.7.0", "Too many authentication failures");
pub const OVERSHOOT: Reply = Reply::new(421, "4.5.3", "Too many recipients");
pub const DISCARD: Reply = Reply::new(421, "4.3.4", "Message too big");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_one_line_and_blanks_control_bytes() {
        let mut out = Vec::new();
        Reply::owned(250, "2.0.0", "id\r\nMAIL\0".into()).write(&mut out);
        assert_eq!(out, b"250 2.0.0 id  MAIL \r\n");
        assert!(TOO_MANY_RECIPIENTS.overshoot());
        assert!(!TEMPORARY.overshoot());
    }
}
