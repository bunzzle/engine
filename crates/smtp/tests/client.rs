use smtp::client::{
    Answer, Capabilities, DATA, Dots, Fault, Mail, Rcpt, Refused, Response, Responses, Ret, Step,
    Transaction, ehlo,
};

fn responses(text: &[u8]) -> Vec<Result<Response, Fault>> {
    let mut parser = Responses::default();
    parser.input(text);
    let mut out = Vec::new();
    while let Some(next) = parser.poll() {
        let failed = next.is_err();
        out.push(next);
        if failed {
            break;
        }
    }
    out
}

fn one(text: &str) -> Response {
    let mut parser = Responses::default();
    parser.input(text.as_bytes());
    if !text.ends_with('\n') {
        parser.input(b"\r\n");
    }
    parser.poll().expect("complete").expect("valid")
}

fn caps(pipelining: bool) -> Capabilities {
    Capabilities {
        size: Some(0),
        pipelining,
        eight_bit: true,
        dsn: true,
        ..Capabilities::default()
    }
}

fn mail() -> Mail {
    Mail {
        sender: "bounce@example.net".into(),
        size: 1234,
        ..Mail::default()
    }
}

fn rcpts(n: usize) -> Vec<Rcpt> {
    (0..n)
        .map(|i| Rcpt {
            address: format!("user{i}@example.com"),
            ..Rcpt::default()
        })
        .collect()
}

fn run(caps: &Capabilities, n: usize, replies: &[&str]) -> (Vec<String>, Vec<Step>, Transaction) {
    let mut transaction = Transaction::new(caps, &mail(), &rcpts(n)).expect("transaction");
    let mut sent = vec![String::from_utf8(transaction.start()).expect("ascii")];
    let mut steps = Vec::new();
    for reply in replies {
        let step = transaction.reply(&one(reply));
        if let Step::Send(bytes) = &step {
            sent.push(String::from_utf8(bytes.clone()).expect("ascii"));
        }
        steps.push(step);
    }
    (sent, steps, transaction)
}

fn codes(transaction: &Transaction) -> Vec<String> {
    transaction
        .answers()
        .iter()
        .map(|a| match a {
            Some(Answer::Accepted) => "ok".to_owned(),
            Some(Answer::Refused(r)) => format!("refused {}", r.code),
            Some(Answer::Again(r)) => format!("again {}", r.code),
            None => "none".to_owned(),
        })
        .collect()
}

#[test]
fn replies_parse_across_lines_and_chunks() {
    let mut parser = Responses::default();
    parser.input(b"250-mx.example.com Hello\r\n250-PIPEL");
    assert_eq!(parser.poll(), None);
    parser.input(b"INING\r\n250 2.0.0 SIZE 1000\r\n550 5.1.1 No such user\r\n");
    let ehlo = parser.poll().expect("ehlo").expect("valid");
    assert_eq!(ehlo.code, 250);
    assert_eq!(ehlo.lines.len(), 3);
    let refused = parser.poll().expect("refused").expect("valid");
    assert_eq!(refused.status, Some((5, 1, 1)));
    assert_eq!(refused.lines, ["No such user"]);
    assert_eq!(refused.text(), "550 5.1.1 No such user");
    assert!(!parser.pending());
    let bare = one("354\n");
    assert_eq!((bare.code, bare.status), (354, None));
    assert_eq!(one("250 4.0.0 wrong class").status, None);
}

#[test]
fn bad_or_huge_replies_fault() {
    assert_eq!(responses(b"250-a\r\n251 b\r\n"), [Err(Fault::Syntax)]);
    assert_eq!(responses(b"abc\r\n"), [Err(Fault::Syntax)]);
    assert_eq!(responses(b"650 nope\r\n"), [Err(Fault::Syntax)]);
    assert_eq!(responses(b"250xok\r\n"), [Err(Fault::Syntax)]);
    let long = [b"250 ".as_slice(), &[b'a'; 5000]].concat();
    assert_eq!(responses(&long), [Err(Fault::TooLong)]);
    let many = "250-x\r\n".repeat(150);
    assert_eq!(responses(many.as_bytes()), [Err(Fault::TooLong)]);
    let mut parser = Responses::default();
    parser.input(b"250-a\r\n251 b\r\n250 ok\r\n");
    assert_eq!(parser.poll(), Some(Err(Fault::Syntax)));
    assert_eq!(parser.poll(), Some(Err(Fault::Syntax)));
}

#[test]
fn capabilities_come_from_ehlo_lines() {
    let reply = one(
        "250-mx.example.com greets you\r\n250-SIZE 35882577\r\n250-8BITMIME\r\n250-PIPELINING\r\n\
         250-starttls\r\n250-DSN\r\n250-SMTPUTF8\r\n250-CHUNKING\r\n250 ENHANCEDSTATUSCODES\r\n",
    );
    let caps = Capabilities::parse(&reply);
    assert_eq!(caps.size, Some(35_882_577));
    assert!(caps.pipelining && caps.eight_bit && caps.starttls && caps.dsn);
    assert!(caps.smtputf8 && caps.chunking && caps.enhanced && !caps.requiretls);
    let only = one("250-PIPELINING\r\n250 SIZE\r\n");
    assert!(!Capabilities::parse(&only).pipelining);
    assert_eq!(Capabilities::parse(&only).size, Some(0));
}

#[test]
fn commands_carry_parameters_only_when_offered() {
    let mut full = mail();
    full.eight_bit = true;
    full.ret = Some(Ret::Headers);
    full.envid = b"id+1 x".to_vec();
    let rcpt = Rcpt {
        address: "a@example.com".into(),
        notify: Some("FAILURE,DELAY".into()),
        orcpt: b"a@example.com".to_vec(),
    };
    let mut transaction =
        Transaction::new(&caps(true), &full, std::slice::from_ref(&rcpt)).expect("t");
    let sent = String::from_utf8(transaction.start()).expect("ascii");
    assert_eq!(
        sent,
        "MAIL FROM:<bounce@example.net> SIZE=1234 BODY=8BITMIME RET=HDRS ENVID=id+2B1+20x\r\n\
         RCPT TO:<a@example.com> NOTIFY=FAILURE,DELAY ORCPT=rfc822;a@example.com\r\nDATA\r\n"
    );
    let bare = Capabilities::default();
    let mut transaction = Transaction::new(&bare, &full, &[rcpt]).expect("t");
    let sent = String::from_utf8(transaction.start()).expect("ascii");
    assert_eq!(sent, "MAIL FROM:<bounce@example.net>\r\n");
}

#[test]
fn unsafe_values_and_missing_extensions_are_refused() {
    let mut injected = mail();
    injected.sender = "a@b>\r\nRCPT TO:<x@y".into();
    assert!(matches!(
        Transaction::new(&caps(true), &injected, &rcpts(1)),
        Err(Refused::Unsafe)
    ));
    let bad = vec![Rcpt {
        address: "a b@example.com".into(),
        ..Rcpt::default()
    }];
    assert!(matches!(
        Transaction::new(&caps(true), &mail(), &bad),
        Err(Refused::Unsafe)
    ));
    let mut utf8 = mail();
    utf8.smtputf8 = true;
    assert!(matches!(
        Transaction::new(&caps(true), &utf8, &rcpts(1)),
        Err(Refused::Smtputf8)
    ));
    let mut tls = mail();
    tls.requiretls = true;
    assert!(matches!(
        Transaction::new(&caps(true), &tls, &rcpts(1)),
        Err(Refused::RequireTls)
    ));
    assert_eq!(
        ehlo("mx.example.net").expect("ehlo"),
        b"EHLO mx.example.net\r\n"
    );
    assert_eq!(ehlo("mx\r\nQUIT"), Err(Refused::Unsafe));
    let mut null = mail();
    null.sender = String::new();
    let mut t = Transaction::new(&caps(false), &null, &rcpts(1)).expect("null sender");
    assert_eq!(t.start(), b"MAIL FROM:<> SIZE=1234\r\n");
}

#[test]
fn pipelined_transaction_answers_each_recipient() {
    let (sent, steps, t) = run(
        &caps(true),
        3,
        &[
            "250 ok",
            "250 ok",
            "550 5.1.1 unknown",
            "452 4.5.3 too many",
            "354 go",
            "250 queued",
        ],
    );
    assert_eq!(sent.len(), 1);
    assert!(sent[0].ends_with("DATA\r\n"));
    assert_eq!(steps[..4], [Step::Wait, Step::Wait, Step::Wait, Step::Wait]);
    assert_eq!(steps[4], Step::Body);
    assert_eq!(steps[5], Step::Done);
    assert_eq!(codes(&t), ["ok", "refused 550", "again 452"]);
    assert!(t.again());
    assert!(t.reusable());
}

#[test]
fn a_refused_mail_answers_everyone_and_skips_the_rest() {
    let (_, steps, t) = run(
        &caps(true),
        2,
        &[
            "451 4.3.0 later",
            "503 5.5.1 no",
            "503 5.5.1 no",
            "554 5.5.1 no",
        ],
    );
    assert_eq!(steps, [Step::Wait, Step::Wait, Step::Wait, Step::Done]);
    assert_eq!(codes(&t), ["refused 451", "refused 451"]);
    assert_eq!(t.mail_refused().map(|r| r.code), Some(451));
    assert!(t.reusable());
    let (sent, steps, t) = run(&caps(true), 1, &["550 no", "250 ok", "354 go", "554 no"]);
    assert_eq!(
        steps,
        [
            Step::Wait,
            Step::Wait,
            Step::Send(b".\r\n".to_vec()),
            Step::Done
        ]
    );
    assert_eq!(sent.last().map(String::as_str), Some(".\r\n"));
    assert_eq!(codes(&t), ["refused 550"]);
    assert!(t.reusable());
}

#[test]
fn no_body_goes_out_when_no_recipient_or_data_fails() {
    let (_, steps, t) = run(&caps(true), 2, &["250 ok", "550 a", "550 b", "354 go"]);
    assert_eq!(steps.last(), Some(&Step::Send(b".\r\n".to_vec())));
    assert!(!t.reusable());
    assert_eq!(codes(&t), ["refused 550", "refused 550"]);
    let (_, steps, t) = run(
        &caps(true),
        2,
        &["250 ok", "250 ok", "550 b", "451 4.3.0 busy"],
    );
    assert_eq!(steps.last(), Some(&Step::Done));
    assert_eq!(codes(&t), ["refused 451", "refused 550"]);
    let (_, _, t) = run(
        &caps(true),
        1,
        &["250 ok", "250 ok", "354 go", "552 5.3.4 too big"],
    );
    assert_eq!(codes(&t), ["refused 552"]);
}

#[test]
fn without_pipelining_one_command_per_round_trip() {
    let (sent, steps, t) = run(
        &caps(false),
        2,
        &["250 ok", "250 ok", "550 no", "354 go", "250 queued"],
    );
    assert_eq!(
        sent,
        [
            "MAIL FROM:<bounce@example.net> SIZE=1234\r\n",
            "RCPT TO:<user0@example.com>\r\n",
            "RCPT TO:<user1@example.com>\r\n",
            String::from_utf8(DATA.to_vec()).expect("ascii").as_str(),
        ]
    );
    assert_eq!(steps[3], Step::Body);
    assert_eq!(codes(&t), ["ok", "refused 550"]);
    let (sent, steps, _) = run(&caps(false), 1, &["250 ok", "550 no"]);
    assert_eq!(sent.len(), 2);
    assert_eq!(steps.last(), Some(&Step::Done));
    let (_, _, t) = run(&caps(false), 1, &["452 4.2.2 full"]);
    assert_eq!(codes(&t), ["refused 452"]);
    let (_, _, t) = run(
        &caps(false),
        2,
        &["250 ok", "250 ok", "452 4.2.2 full", "354 go", "250 ok"],
    );
    assert_eq!(codes(&t), ["ok", "refused 452"]);
}

#[test]
fn dots_are_stuffed_and_line_ends_normalised() {
    let encode = |chunks: &[&[u8]]| {
        let mut dots = Dots::default();
        let mut out = Vec::new();
        for chunk in chunks {
            dots.encode(chunk, &mut out);
        }
        dots.finish(&mut out);
        String::from_utf8(out).expect("ascii")
    };
    assert_eq!(encode(&[b"a\r\n.b\r\n"]), "a\r\n..b\r\n.\r\n");
    assert_eq!(encode(&[b".\r\n"]), "..\r\n.\r\n");
    assert_eq!(encode(&[b"a\r", b"\n.", b"\r\n"]), "a\r\n..\r\n.\r\n");
    assert_eq!(encode(&[b"no end"]), "no end\r\n.\r\n");
    assert_eq!(encode(&[b""]), ".\r\n");
    assert_eq!(encode(&[b"x\n.\r\ny"]), "x\r\n..\r\ny\r\n.\r\n");
    assert_eq!(encode(&[b"x\r.\ry\r"]), "x\r\n..\r\ny\r\n.\r\n");
    assert_eq!(encode(&[b"a.b\r\n"]), "a.b\r\n.\r\n");
}
