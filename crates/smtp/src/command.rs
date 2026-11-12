use crate::reply::{self, Reply};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command<'a> {
    Ehlo,
    Helo,
    Starttls,
    Auth {
        mechanism: &'a [u8],
        initial: Option<&'a [u8]>,
    },
    Mail(&'a [u8]),
    Rcpt(&'a [u8]),
    Data,
    Bdat {
        size: u64,
        last: bool,
    },
    BadBdat,
    Rset,
    Noop,
    Quit,
    Vrfy,
    Expn,
    Help,
}

pub(crate) fn parse(line: &[u8]) -> Result<Command<'_>, Reply> {
    if line.iter().any(|&b| b < 32 || b == 127) {
        return Err(reply::UNRECOGNIZED);
    }
    let (verb, args) = match line.iter().position(|&b| b == b' ') {
        Some(space) => (&line[..space], Some(&line[space + 1..])),
        None => (line, None),
    };
    let upper = verb.to_ascii_uppercase();
    let command = match upper.as_slice() {
        b"EHLO" => Command::Ehlo,
        b"HELO" => Command::Helo,
        b"STARTTLS" => Command::Starttls,
        b"AUTH" => return auth(args),
        b"MAIL" => return Ok(Command::Mail(prefixed(args, b"FROM:")?)),
        b"RCPT" => return Ok(Command::Rcpt(prefixed(args, b"TO:")?)),
        b"DATA" => Command::Data,
        b"BDAT" => return Ok(bdat(args)),
        b"RSET" => Command::Rset,
        b"NOOP" => return Ok(Command::Noop),
        b"QUIT" => Command::Quit,
        b"VRFY" => return Ok(Command::Vrfy),
        b"EXPN" => return Ok(Command::Expn),
        b"HELP" => return Ok(Command::Help),
        _ => return Err(reply::UNRECOGNIZED),
    };
    let wants_args = matches!(command, Command::Ehlo | Command::Helo);
    let has_args = args.is_some_and(|a| !a.trim_ascii().is_empty());
    if wants_args == has_args {
        Ok(command)
    } else {
        Err(reply::SYNTAX)
    }
}

fn auth(args: Option<&[u8]>) -> Result<Command<'_>, Reply> {
    let mut parts = args.unwrap_or_default().split(|&b| b == b' ');
    let mechanism = parts.next().filter(|m| !m.is_empty());
    let initial = parts.next();
    match (mechanism, initial, parts.next()) {
        (Some(mechanism), initial, None) if initial.is_none_or(|i| !i.is_empty()) => {
            Ok(Command::Auth { mechanism, initial })
        }
        _ => Err(reply::SYNTAX),
    }
}

fn prefixed<'a>(args: Option<&'a [u8]>, prefix: &[u8]) -> Result<&'a [u8], Reply> {
    match args {
        Some(args)
            if args.len() >= prefix.len() && args[..prefix.len()].eq_ignore_ascii_case(prefix) =>
        {
            Ok(args[prefix.len()..].trim_ascii_start())
        }
        _ => Err(reply::SYNTAX),
    }
}

fn bdat(args: Option<&[u8]>) -> Command<'_> {
    let mut parts = args.unwrap_or_default().split(|&b| b == b' ');
    let size = parts
        .next()
        .filter(|s| !s.is_empty() && s.len() <= 20 && s.iter().all(u8::is_ascii_digit))
        .and_then(|s| std::str::from_utf8(s).ok()?.parse().ok());
    let last = match parts.next() {
        None => Some(false),
        Some(word) if word.eq_ignore_ascii_case(b"LAST") => Some(true),
        Some(_) => None,
    };
    match (size, last, parts.next()) {
        (Some(size), Some(last), None) => Command::Bdat { size, last },
        _ => Command::BadBdat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands() {
        let cases: [(&[u8], Command<'_>); 12] = [
            (b"ehlo client.example", Command::Ehlo),
            (b"HELO x", Command::Helo),
            (b"StartTLS", Command::Starttls),
            (
                b"AUTH PLAIN AGEAYg==",
                Command::Auth {
                    mechanism: b"PLAIN",
                    initial: Some(b"AGEAYg=="),
                },
            ),
            (
                b"auth login",
                Command::Auth {
                    mechanism: b"login",
                    initial: None,
                },
            ),
            (
                b"MAIL FROM:<a@b.c> SIZE=1",
                Command::Mail(b"<a@b.c> SIZE=1"),
            ),
            (b"mail from: <a@b.c>", Command::Mail(b"<a@b.c>")),
            (b"RCPT TO:<a@b.c>", Command::Rcpt(b"<a@b.c>")),
            (
                b"BDAT 10 last",
                Command::Bdat {
                    size: 10,
                    last: true,
                },
            ),
            (
                b"BDAT 0",
                Command::Bdat {
                    size: 0,
                    last: false,
                },
            ),
            (b"NOOP anything", Command::Noop),
            (b"QUIT", Command::Quit),
        ];
        for (line, want) in cases {
            assert_eq!(parse(line), Ok(want), "{}", String::from_utf8_lossy(line));
        }
    }

    #[test]
    fn refuses_bad_commands() {
        let cases: [(&[u8], Reply); 10] = [
            (b"EHLO", reply::SYNTAX),
            (b"EHLO ", reply::SYNTAX),
            (b"DATA x", reply::SYNTAX),
            (b"QUIT now", reply::SYNTAX),
            (b"MAIL <a@b.c>", reply::SYNTAX),
            (b"RCPT FROM:<a@b.c>", reply::SYNTAX),
            (b"AUTH", reply::SYNTAX),
            (b"AUTH PLAIN a b", reply::SYNTAX),
            (b"XYZZY", reply::UNRECOGNIZED),
            (b"NOOP \x00", reply::UNRECOGNIZED),
        ];
        for (line, want) in cases {
            assert_eq!(parse(line), Err(want), "{}", String::from_utf8_lossy(line));
        }
        for line in [
            &b"BDAT"[..],
            b"BDAT x",
            b"BDAT 1 MORE",
            b"BDAT 1 LAST x",
            b"BDAT 99999999999999999999",
        ] {
            assert_eq!(parse(line), Ok(Command::BadBdat));
        }
    }
}
