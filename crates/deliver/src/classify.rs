use sched::{Answer, Kind};
use smtp::client::Response;

const GREYLIST: [&str; 6] = [
    "greylist",
    "graylist",
    "grey-list",
    "gray-list",
    "grey list",
    "gray list",
];
const THROTTLE: [&str; 6] = [
    "rate limit",
    "ratelimit",
    "throttl",
    "too many connections",
    "too many messages",
    "too many concurrent",
];

const GONE: [&str; 9] = [
    "user unknown",
    "unknown user",
    "no such user",
    "no such mailbox",
    "mailbox not found",
    "recipient unknown",
    "unknown recipient",
    "user does not exist",
    "mailbox does not exist",
];

const NOT_RECIPIENT: [&str; 2] = ["sender", "verif"];

pub fn gone(response: &Response) -> bool {
    if !matches!(response.code, 550 | 551 | 553) {
        return false;
    }
    match response.status {
        Some((5, subject, detail)) => matches!((subject, detail), (1, 1 | 6 | 10) | (2, 1)),
        Some(_) => false,
        None => {
            let text = response.lines.join(" ").to_ascii_lowercase();
            let quoted = response
                .lines
                .iter()
                .any(|l| l.trim_start().to_ascii_lowercase().starts_with("response:"));
            let sender = NOT_RECIPIENT.iter().any(|w| text.contains(w));
            !quoted && !sender && GONE.iter().any(|w| text.contains(w))
        }
    }
}

pub fn answer(response: &Response) -> Answer {
    match response.code {
        200..=399 => Answer::Delivered,
        400..=499 => Answer::Deferred(kind(response)),
        _ => Answer::Failed,
    }
}

pub fn kind(response: &Response) -> Kind {
    let text = response.lines.join(" ").to_ascii_lowercase();
    let status = response
        .status
        .map(|(_, subject, detail)| (subject, detail));
    let has = |words: &[&str]| words.iter().any(|w| text.contains(w));
    if has(&GREYLIST) || (response.code == 450 && status == Some((7, 1))) {
        Kind::Greylisted
    } else if response.code == 421 || status == Some((7, 28)) || has(&THROTTLE) {
        Kind::Throttled
    } else if status == Some((2, 2)) || (response.code == 452 && status.is_none()) {
        Kind::MailboxFull
    } else {
        Kind::Temporary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(code: u16, status: Option<(u8, u16, u16)>, text: &str) -> Response {
        Response {
            code,
            status,
            lines: vec![text.to_owned()],
        }
    }

    #[test]
    fn classifies_replies() {
        let cases = [
            (response(250, None, "ok"), Answer::Delivered),
            (
                response(550, Some((5, 1, 1)), "no such user"),
                Answer::Failed,
            ),
            (
                response(451, Some((4, 7, 1)), "Greylisted, try again"),
                Answer::Deferred(Kind::Greylisted),
            ),
            (
                response(450, Some((4, 7, 1)), "come back later"),
                Answer::Deferred(Kind::Greylisted),
            ),
            (
                response(421, None, "closing"),
                Answer::Deferred(Kind::Throttled),
            ),
            (
                response(451, Some((4, 7, 28)), "unusual rate"),
                Answer::Deferred(Kind::Throttled),
            ),
            (
                response(451, Some((4, 7, 0)), "Rate limit exceeded"),
                Answer::Deferred(Kind::Throttled),
            ),
            (
                response(452, Some((4, 2, 2)), "mailbox full"),
                Answer::Deferred(Kind::MailboxFull),
            ),
            (
                response(452, None, "insufficient storage"),
                Answer::Deferred(Kind::MailboxFull),
            ),
            (
                response(452, Some((4, 5, 3)), "too many recipients"),
                Answer::Deferred(Kind::Temporary),
            ),
            (
                response(451, Some((4, 3, 0)), "local error"),
                Answer::Deferred(Kind::Temporary),
            ),
        ];
        for (response, want) in cases {
            assert_eq!(answer(&response), want, "{}", response.text());
        }
    }

    #[test]
    fn only_mailbox_level_failures_are_gone() {
        let cases = [
            (response(550, Some((5, 1, 1)), "no such user"), true),
            (response(550, Some((5, 1, 10)), "null MX"), true),
            (response(551, Some((5, 1, 6)), "moved"), true),
            (response(550, Some((5, 2, 1)), "account disabled"), true),
            (response(550, None, "User unknown"), true),
            (response(553, None, "mailbox does not exist"), true),
            (response(550, Some((5, 7, 1)), "user unknown"), false),
            (response(554, Some((5, 1, 1)), "no such user"), false),
            (response(550, Some((5, 2, 2)), "mailbox full"), false),
            (response(550, Some((4, 1, 1)), "no such user"), false),
            (response(550, None, "blocked"), false),
            (response(550, None, "sender domain does not exist"), false),
            (response(450, Some((4, 1, 1)), "user unknown"), false),
            (
                Response {
                    code: 550,
                    status: None,
                    lines: vec![
                        "Verification failed for <noreply@example.com>".to_owned(),
                        "No Such User Here".to_owned(),
                        "Sender verify failed".to_owned(),
                    ],
                },
                false,
            ),
            (
                Response {
                    code: 550,
                    status: None,
                    lines: vec![
                        "Callout check failed".to_owned(),
                        "Response: 550 5.1.1 <a@example.com> User unknown".to_owned(),
                    ],
                },
                false,
            ),
        ];
        for (response, want) in cases {
            assert_eq!(gone(&response), want, "{}", response.text());
        }
    }
}
