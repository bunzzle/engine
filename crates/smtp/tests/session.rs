mod common;

use common::{Client, LIMIT, PLAIN};
use smtp::{Reply, reply};

fn lines(text: &str) -> Vec<&str> {
    text.split_terminator("\r\n").collect()
}

#[test]
fn a_submission_session_from_starttls_to_quit() {
    let mut client = Client::new(false);
    assert_eq!(client.text(), "220 mx.example.org ESMTP\r\n");
    assert_eq!(
        lines(&client.send(b"EHLO client.example\r\n")),
        [
            "250-mx.example.org",
            "250-PIPELINING",
            "250-ENHANCEDSTATUSCODES",
            "250 STARTTLS"
        ]
    );
    assert_eq!(
        client.send(b"AUTH PLAIN AHVzZXIAYnpfZ29vZA==\r\n"),
        "530 5.7.0 Must issue a STARTTLS command first\r\n"
    );
    assert_eq!(
        client.send(b"MAIL FROM:<a@example.org>\r\n"),
        "530 5.7.0 Must issue a STARTTLS command first\r\n"
    );
    assert_eq!(
        client.send(b"STARTTLS\r\n"),
        "220 2.0.0 Ready to start TLS\r\n"
    );
    assert!(client.server.tls());
    assert_eq!(
        client.send(b"MAIL FROM:<a@example.org>\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    assert_eq!(
        lines(&client.send(b"EHLO client.example\r\n")),
        [
            "250-mx.example.org",
            "250-PIPELINING",
            "250-ENHANCEDSTATUSCODES",
            "250-8BITMIME",
            "250-CHUNKING",
            "250-SIZE 65536",
            "250 AUTH PLAIN LOGIN"
        ]
    );
    assert_eq!(
        client.send(b"MAIL FROM:<a@example.org>\r\n"),
        "530 5.7.0 Authentication required\r\n"
    );
    assert_eq!(
        client.send(format!("AUTH PLAIN {PLAIN}\r\n").as_bytes()),
        "235 2.7.0 Authentication succeeded\r\n"
    );
    assert_eq!(
        lines(&client.send(
            b"MAIL FROM:<a@example.org> BODY=8BITMIME SIZE=100\r\nRCPT TO:<b@example.net>\r\nRCPT TO:<c@example.net>\r\nDATA\r\n"
        )),
        [
            "250 2.1.0 Sender OK",
            "250 2.1.5 Recipient OK",
            "250 2.1.5 Recipient OK",
            "354 End data with <CR><LF>.<CR><LF>"
        ]
    );
    assert_eq!(
        client.send(b"Subject: hi\r\n\r\n..dot\r\nbody\r\n.\r\nQUIT\r\n"),
        "250 2.0.0 id1\r\n221 2.0.0 Bye\r\n"
    );
    assert_eq!(
        client.messages,
        [b"Subject: hi\r\n\r\n.dot\r\nbody\r\n".to_vec()]
    );
    assert_eq!(
        client.log,
        [
            "starttls",
            "auth",
            "mail a@example.org Some(100) Some(EightBit)",
            "rcpt b@example.net c@example.net",
            "data",
            "end 0",
            "close"
        ]
    );
    assert!(client.server.closed());
}

#[test]
fn pipelined_recipients_go_out_as_one_group_and_replies_keep_their_order() {
    let mut client = Client::ready();
    let text = client.send(
        b"MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.net>\r\nRCPT TO:<broken\r\nRCPT TO:<bad@example.net>\r\nRCPT TO:<c@example.net> NOTIFY=NEVER\r\nRCPT TO:<d@example.net>\r\nNOOP\r\n",
    );
    assert_eq!(
        lines(&text),
        [
            "250 2.1.0 Sender OK",
            "250 2.1.5 Recipient OK",
            "553 5.1.3 Bad recipient address syntax",
            "550 5.7.1 Recipient refused",
            "555 5.5.4 Parameter not recognized",
            "250 2.1.5 Recipient OK",
            "250 2.0.0 OK"
        ]
    );
    assert_eq!(
        client.log[1],
        "rcpt b@example.net bad@example.net d@example.net"
    );
}

#[test]
fn starttls_with_buffered_bytes_closes_without_tls() {
    let mut client = Client::new(false);
    client.send(b"EHLO client.example\r\n");
    let text = client.send(b"STARTTLS\r\nMAIL FROM:<a@example.org>\r\n");
    assert_eq!(text, "554 5.5.0 Protocol synchronization error\r\n");
    assert_eq!(client.log, ["close"]);
    assert!(!client.server.tls());
}

#[test]
fn bytes_before_the_greeting_or_after_ehlo_close_the_session() {
    let mut server = smtp::Server::new(smtp::Config {
        name: "mx.example.org".into(),
        message: LIMIT,
        implicit: true,
    });
    server.input(b"EHLO x\r\n");
    assert!(matches!(server.poll(), Some(smtp::Event::Close)));
    assert_eq!(
        server.output(),
        b"554 5.5.0 Protocol synchronization error\r\n"
    );

    let mut client = Client::new(true);
    client.clear();
    let text = client.send(b"EHLO client.example\r\nMAIL FROM:<a@example.org>\r\n");
    assert_eq!(text, "554 5.5.0 Protocol synchronization error\r\n");
    assert!(client.server.closed());
}

#[test]
fn bytes_pipelined_after_data_close_the_session() {
    let mut client = Client::ready();
    let text = client
        .send(b"MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.net>\r\nDATA\r\nSubject: x\r\n");
    assert!(text.ends_with("554 5.5.0 Protocol synchronization error\r\n"));
    assert_eq!(client.log.last().map(String::as_str), Some("close"));
    assert_eq!(client.messages, Vec::<Vec<u8>>::new());
}

#[test]
fn bytes_before_the_data_answer_close_the_session() {
    let mut client = Client::ready();
    transaction(&mut client);
    client.server.input(b"DATA\r\n");
    assert!(matches!(client.server.poll(), Some(smtp::Event::Data)));
    client.server.input(b"Subject: early\r\n");
    client.server.data(Ok(()));
    assert!(matches!(client.server.poll(), Some(smtp::Event::Close)));
    assert_eq!(
        client.server.output(),
        b"554 5.5.0 Protocol synchronization error\r\n"
    );
}

fn transaction(client: &mut Client) {
    let text = client.send(b"MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.net>\r\n");
    assert_eq!(text, "250 2.1.0 Sender OK\r\n250 2.1.5 Recipient OK\r\n");
}

fn data(client: &mut Client, body: &[u8]) -> String {
    transaction(client);
    assert_eq!(
        client.send(b"DATA\r\n"),
        "354 End data with <CR><LF>.<CR><LF>\r\n"
    );
    client.send(body)
}

#[test]
fn smuggled_terminators_stay_inside_the_message() {
    let mut client = Client::ready();
    let text = data(
        &mut client,
        b"a\r\n\n.\nMAIL FROM:<x@example.org>\r\n.\nb\r\n\n.\r\nc\r\n.\r\n",
    );
    assert_eq!(text, "250 2.0.0 id1\r\n");
    assert_eq!(
        client.messages,
        [b"a\r\n\r\n.\r\nMAIL FROM:<x@example.org>\r\n.\r\nb\r\n\r\n.\r\nc\r\n".to_vec()]
    );
    assert_eq!(client.log.last().map(String::as_str), Some("end 4"));
}

#[test]
fn a_bare_cr_refuses_the_message_and_the_session_goes_on() {
    let mut client = Client::ready();
    let text = data(
        &mut client,
        b"a\r\n\r.\r\nMAIL FROM:<x@example.org>\r\n.\r\n",
    );
    assert_eq!(text, "554 5.6.0 Bare CR in line 2\r\n");
    assert_eq!(client.messages, Vec::<Vec<u8>>::new());
    assert!(client.log.contains(&"reset".into()));
    let text = data(&mut client, b"ok\r\n.\r\n");
    assert_eq!(text, "250 2.0.0 id1\r\n");
}

#[test]
fn a_long_line_or_a_big_message_is_read_to_the_end_and_refused() {
    let mut client = Client::ready();
    let mut body = vec![b'x'; 999];
    body.extend_from_slice(b"\r\n.\r\n");
    assert_eq!(
        data(&mut client, &body),
        "554 5.6.0 Line 1 longer than 998 octets\r\n"
    );
    let mut body = b"x\r\n".repeat(usize::try_from(LIMIT).expect("fits") / 3 + 1);
    body.extend_from_slice(b".\r\n");
    assert_eq!(
        data(&mut client, &body),
        "552 5.3.4 Message size exceeds limit\r\n"
    );
    assert_eq!(client.messages, Vec::<Vec<u8>>::new());
    assert!(!client.server.closed());
}

#[test]
fn discarding_after_a_refusal_is_bounded() {
    let mut client = Client::ready();
    client.refuse_after = Some(10);
    let text = data(&mut client, b"Subject: a long header\r\n");
    assert_eq!(text, "");
    let text = client.send(b"more\r\n.\r\n");
    assert_eq!(text, "552 5.3.4 Header too big\r\n");
    assert_eq!(client.messages, Vec::<Vec<u8>>::new());

    let text = data(&mut client, b"Subject: a long header\r\n");
    assert_eq!(text, "");
    let chunk = vec![b'y'; 1000];
    let mut text = String::new();
    for _ in 0..=LIMIT / 1000 {
        text.push_str(&client.send(&chunk));
    }
    assert_eq!(text, "421 4.3.4 Message too big\r\n");
    assert!(client.server.closed());
}

#[test]
fn chunks_keep_dots_join_split_line_ends_and_end_with_last() {
    let mut client = Client::ready();
    transaction(&mut client);
    let text = client.send(b"BDAT 6\r\na\r\n.\r\rBDAT 8\r\n\nb\r\n.\r\n\nBDAT 1 LAST\r\nc");
    assert_eq!(
        text,
        "554 5.6.0 Bare CR in line 2\r\n503 5.5.1 Bad sequence of commands\r\n503 5.5.1 Bad sequence of commands\r\n"
    );
    assert_eq!(
        client.send(b"MAIL FROM:<a@example.org>\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    assert_eq!(client.send(b"RSET\r\n"), "250 2.0.0 OK\r\n");
    transaction(&mut client);
    let text = client.send(b"BDAT 5\r\na\r\n.\rBDAT 8\r\n\nb\r\n.\r\n\nBDAT 1 LAST\r\nc");
    assert_eq!(text, "250 2.0.0 OK\r\n250 2.0.0 OK\r\n250 2.0.0 id1\r\n");
    assert_eq!(client.messages, [b"a\r\n.\r\nb\r\n.\r\n\r\nc\r\n".to_vec()]);
    assert_eq!(client.log.last().map(String::as_str), Some("end 1"));
}

#[test]
fn chunk_rules() {
    let mut client = Client::ready();
    assert_eq!(
        client.send(b"BDAT 3\r\nabc"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    transaction(&mut client);
    assert_eq!(client.send(b"BDAT 0 LAST\r\n"), "250 2.0.0 id1\r\n");
    assert_eq!(client.messages, [Vec::<u8>::new()]);
    transaction(&mut client);
    assert_eq!(client.send(b"BDAT 2\r\nab"), "250 2.0.0 OK\r\n");
    assert_eq!(
        client.send(b"DATA\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    assert_eq!(
        client.send(b"RCPT TO:<c@example.net>\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    assert_eq!(client.send(b"BDAT 1 LAST\r\nc"), "250 2.0.0 id2\r\n");
    assert_eq!(client.messages[1], b"abc\r\n");
    let text = client.send(format!("BDAT {}\r\n", LIMIT + 1).as_bytes());
    assert_eq!(text, "552 5.3.4 Message size exceeds limit\r\n");
    assert!(client.server.closed());

    let mut client = Client::ready();
    assert_eq!(
        client.send(b"BDAT x\r\n"),
        "501 5.5.4 Syntax error in parameters\r\n"
    );
    assert!(client.server.closed());
}

#[test]
fn authentication_exchanges_and_failures() {
    let mut client = Client::new(true);
    client.send(b"EHLO client.example\r\n");
    client.clear();
    assert_eq!(client.send(b"AUTH LOGIN\r\n"), "334 VXNlcm5hbWU6\r\n");
    assert_eq!(client.send(b"dXNlcg==\r\n"), "334 UGFzc3dvcmQ6\r\n");
    assert_eq!(
        client.send(b"YnpfZ29vZA==\r\n"),
        "235 2.7.0 Authentication succeeded\r\n"
    );
    assert!(client.server.authenticated());
    assert_eq!(
        client.send(b"AUTH PLAIN\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );

    let mut client = Client::new(true);
    client.send(b"EHLO client.example\r\n");
    client.clear();
    assert_eq!(client.send(b"AUTH PLAIN\r\n"), "334 \r\n");
    assert_eq!(
        client.send(b"*\r\n"),
        "501 5.7.0 Authentication cancelled\r\n"
    );
    assert_eq!(
        client.send(b"AUTH CRAM-MD5\r\n"),
        "504 5.5.4 Unrecognized authentication mechanism\r\n"
    );
    assert_eq!(
        client.send(b"AUTH PLAIN !!!\r\n"),
        "501 5.5.2 Cannot decode response\r\n"
    );
    assert_eq!(
        client.send(b"AUTH PLAIN b3RoZXIAdXNlcgBiel9nb29k\r\n"),
        "535 5.7.8 Authentication credentials invalid\r\n"
    );
    assert_eq!(
        client.send(b"AUTH PLAIN AHVzZXIAYnpfYmFk\r\n"),
        "535 5.7.8 Authentication credentials invalid\r\n"
    );
    assert_eq!(
        client.send(b"AUTH LOGIN dXNlcg==\r\nAHVzZXIAYnpfYmFk\r\n"),
        "334 UGFzc3dvcmQ6\r\n535 5.7.8 Authentication credentials invalid\r\n421 4.7.0 Too many authentication failures\r\n"
    );
    assert!(client.server.closed());
    assert!(!client.log.iter().any(|l| l.contains("bz_")));
}

#[test]
fn temporary_auth_failures_do_not_count_toward_the_close() {
    let mut client = Client::new(true);
    client.send(b"EHLO client.example\r\n");
    for _ in 0..5 {
        client
            .server
            .input(format!("AUTH PLAIN {PLAIN}\r\n").as_bytes());
        assert!(matches!(client.server.poll(), Some(smtp::Event::Auth(_))));
        client.server.auth(Err(reply::AUTH_TEMPORARY));
    }
    assert!(!client.server.closed());
}

#[test]
fn mail_parameters_and_senders() {
    let mut client = Client::ready();
    let cases: [(&[u8], &str); 9] = [
        (b"MAIL FROM:<>\r\n", "550 5.7.1 Null sender not allowed"),
        (
            b"MAIL FROM:<\xc3\xbc@example.org>\r\n",
            "553 5.6.7 Non-ASCII addresses not supported",
        ),
        (
            b"MAIL FROM:<a@@example.org>\r\n",
            "553 5.1.7 Bad sender address syntax",
        ),
        (
            b"MAIL FROM:<a@example.org> SIZE=65537\r\n",
            "552 5.3.4 Message size exceeds limit",
        ),
        (
            b"MAIL FROM:<a@example.org> SIZE=x\r\n",
            "501 5.5.4 Syntax error in parameters",
        ),
        (
            b"MAIL FROM:<a@example.org> BODY=BINARYMIME\r\n",
            "555 5.5.4 Parameter not recognized",
        ),
        (
            b"MAIL FROM:<a@example.org> SMTPUTF8\r\n",
            "555 5.5.4 Parameter not recognized",
        ),
        (
            b"MAIL FROM:<deny@example.org>\r\n",
            "550 5.7.1 Sender not allowed",
        ),
        (
            b"RCPT TO:<b@example.net>\r\n",
            "503 5.5.1 Bad sequence of commands",
        ),
    ];
    for (line, want) in cases {
        assert_eq!(client.send(line), format!("{want}\r\n"));
    }
    transaction(&mut client);
    assert_eq!(
        client.send(b"MAIL FROM:<a@example.org>\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    assert_eq!(
        client.send(b"DATA\r\n"),
        "354 End data with <CR><LF>.<CR><LF>\r\n"
    );
}

#[test]
fn ehlo_and_rset_drop_the_transaction() {
    let mut client = Client::ready();
    transaction(&mut client);
    client.send(b"EHLO again.example\r\n");
    assert_eq!(client.log.last().map(String::as_str), Some("reset"));
    assert_eq!(
        client.send(b"DATA\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    transaction(&mut client);
    assert_eq!(client.send(b"RSET\r\n"), "250 2.0.0 OK\r\n");
    assert_eq!(client.log.last().map(String::as_str), Some("reset"));
    client.send(b"MAIL FROM:<a@example.org>\r\nRCPT TO:<bad@example.net>\r\n");
    assert_eq!(
        client.send(b"DATA\r\n"),
        "554 5.5.1 No valid recipients\r\n"
    );
}

#[test]
fn twenty_errors_close_the_session_but_overshoot_does_not_count() {
    let mut client = Client::ready();
    transaction(&mut client);
    let mut text = String::new();
    for _ in 0..30 {
        text.push_str(&client.send(b"RCPT TO:<full@example.net>\r\n"));
    }
    assert!(!client.server.closed());
    assert_eq!(text.matches("452 4.5.3").count(), 30);
    let mut text = String::new();
    for _ in 0..19 {
        text.push_str(&client.send(b"XYZZY\r\n"));
    }
    assert!(!client.server.closed());
    text.push_str(&client.send(b"XYZZY\r\n"));
    assert!(text.ends_with("500 5.5.2 Command unrecognized\r\n421 4.7.0 Too many errors\r\n"));
    assert!(client.server.closed());
}

#[test]
fn a_thousand_overshoot_recipients_close_the_session() {
    let mut client = Client::ready();
    transaction(&mut client);
    let text = client.send(&b"RCPT TO:<full@example.net>\r\n".repeat(1000));
    assert!(text.ends_with("452 4.5.3 Too many recipients\r\n421 4.5.3 Too many recipients\r\n"));
    assert!(client.server.closed());
}

#[test]
fn long_command_lines_are_refused_and_skipped() {
    let mut client = Client::ready();
    let mut line = b"NOOP ".to_vec();
    line.extend(vec![b'x'; 3000]);
    line.extend_from_slice(b"\r\nNOOP\r\n");
    assert_eq!(
        client.send(&line),
        "500 5.5.2 Line too long\r\n250 2.0.0 OK\r\n"
    );
    let mut line = b"NOOP ".to_vec();
    line.extend(vec![b'x'; 20_000]);
    assert_eq!(client.send(&line), "");
    assert_eq!(
        client.send(b"x\r\nNOOP\r\n"),
        "500 5.5.2 Line too long\r\n250 2.0.0 OK\r\n"
    );
}

#[test]
fn other_commands() {
    let mut client = Client::ready();
    assert_eq!(client.send(b"VRFY a\r\n"), "252 2.5.0 Cannot VRFY user\r\n");
    assert_eq!(
        client.send(b"EXPN a\r\n"),
        "502 5.5.1 Command not implemented\r\n"
    );
    assert_eq!(client.send(b"HELP\r\n"), "214 2.0.0 No help available\r\n");
    assert_eq!(
        client.send(b"STARTTLS\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    assert_eq!(
        client.send(b"HELO plain.example\n"),
        "250 mx.example.org\r\n"
    );
    assert_eq!(
        client.send(b"AUTH PLAIN\r\n"),
        "503 5.5.1 Bad sequence of commands\r\n"
    );
    let driver = Reply::new(451, "4.3.2", "Busy");
    transaction(&mut client);
    client.server.input(b"DATA\r\n");
    assert!(matches!(client.server.poll(), Some(smtp::Event::Data)));
    client.server.data(Err(driver));
    assert!(matches!(client.server.poll(), Some(smtp::Event::Reset)));
    assert_eq!(client.server.output(), b"451 4.3.2 Busy\r\n");
}
