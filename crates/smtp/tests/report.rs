use smtp::report::{Bounce, Report, parse};

fn dsn_crlf() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"From: MAILER-DAEMON@mx.example.net\r\n");
    m.extend_from_slice(b"To: sender@example.com\r\n");
    m.extend_from_slice(b"Subject: Delivery Status Notification (Failure)\r\n");
    m.extend_from_slice(
        b"Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"mx-42\"\r\n",
    );
    m.extend_from_slice(b"\r\n");
    m.extend_from_slice(b"--mx-42\r\n");
    m.extend_from_slice(b"Content-Type: text/plain; charset=us-ascii\r\n");
    m.extend_from_slice(b"\r\n");
    m.extend_from_slice(b"This is a delivery status notification.\r\n");
    m.extend_from_slice(b"--mx-42\r\n");
    m.extend_from_slice(b"Content-Type: message/delivery-status\r\n");
    m.extend_from_slice(b"\r\n");
    m.extend_from_slice(b"Reporting-MTA: dns; mx.example.net\r\n");
    m.extend_from_slice(b"Arrival-Date: Tue, 24 Nov 2026 10:00:00 +0300\r\n");
    m.extend_from_slice(b"\r\n");
    m.extend_from_slice(b"Final-Recipient: rfc822; <gone@example.org>\r\n");
    m.extend_from_slice(b"Original-Recipient: rfc822; gone@example.org\r\n");
    m.extend_from_slice(b"Action: failed\r\n");
    m.extend_from_slice(b"Status: 5.1.1\r\n");
    m.extend_from_slice(b"Diagnostic-Code: smtp; 550 5.1.1 user unknown\r\n");
    m.extend_from_slice(b"--mx-42--\r\n");
    m
}

fn wrap(body: &[u8], part_head: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"Content-Type: multipart/report; boundary=\"b1\"\n\n");
    m.extend_from_slice(
        format!("--b1\nContent-Type: text/plain\n\nnotice\n--b1\n{part_head}\n\n").as_bytes(),
    );
    m.extend_from_slice(body);
    m.extend_from_slice(b"\n--b1--\n");
    m
}

fn bounce(
    status: (u8, u16, u16),
    original: Option<&str>,
    recipient: Option<&str>,
    diag: &str,
) -> Bounce {
    Bounce {
        status,
        original: original.map(str::to_string),
        recipient: recipient.map(str::to_string),
        diagnostic: diag.to_string(),
    }
}

#[test]
fn dsn_with_crlf() {
    assert_eq!(
        parse(&dsn_crlf()),
        Report::Bounces(vec![bounce(
            (5, 1, 1),
            Some("gone@example.org"),
            Some("gone@example.org"),
            "550 5.1.1 user unknown",
        )])
    );
}

#[test]
fn dsn_with_lf() {
    let body: &[u8] = b"Reporting-MTA: dns; mx.example.net\n\nFinal-Recipient: rfc822; bob@x.io\nAction: failed\nStatus: 5.2.2\nDiagnostic-Code: smtp; 552 mailbox full\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/delivery-status")),
        Report::Bounces(vec![bounce(
            (5, 2, 2),
            None,
            Some("bob@x.io"),
            "552 mailbox full",
        )])
    );
}

#[test]
fn delivery_status_as_second_and_third_part() {
    let body: &[u8] = b"Reporting-MTA: dns; mx\n\nFinal-Recipient: rfc822; a@x.io\nAction: failed\nStatus: 5.0.0\n";
    let mut second = Vec::new();
    second.extend_from_slice(b"Content-Type: multipart/report; boundary=q\n\n");
    second.extend_from_slice(b"--q\nContent-Type: text/plain\n\nhi\n--q\n");
    second.extend_from_slice(b"Content-Type: message/delivery-status\n\n");
    second.extend_from_slice(body);
    second.extend_from_slice(b"\n--q\nContent-Type: text/rfc822-headers\n\nSubject: x\n\n--q--\n");
    assert!(matches!(parse(&second), Report::Bounces(_)));

    let mut third = Vec::new();
    third.extend_from_slice(b"Content-Type: multipart/report; boundary=q\n\n");
    third.extend_from_slice(b"--q\nContent-Type: text/plain\n\nhi\n--q\n");
    third.extend_from_slice(b"Content-Type: text/rfc822-headers\n\nSubject: x\n--q\n");
    third.extend_from_slice(b"Content-Type: message/delivery-status\n\n");
    third.extend_from_slice(body);
    third.extend_from_slice(b"\n--q--\n");
    assert!(matches!(parse(&third), Report::Bounces(_)));
}

#[test]
fn per_message_block_is_not_a_recipient() {
    let body: &[u8] = b"Reporting-MTA: dns; mx\nAction: failed\nStatus: 5.9.9\n\nFinal-Recipient: rfc822; a@x.io\nAction: failed\nStatus: 5.1.1\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/delivery-status")),
        Report::Bounces(vec![bounce((5, 1, 1), None, Some("a@x.io"), "")])
    );
}

#[test]
fn delayed_and_transient_are_ignored() {
    let body: &[u8] = b"Reporting-MTA: dns; mx\n\nFinal-Recipient: rfc822; a@x.io\nAction: delayed\nStatus: 4.4.1\n\nFinal-Recipient: rfc822; b@x.io\nAction: failed\nStatus: 4.2.2\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/delivery-status")),
        Report::Unknown
    );
}

#[test]
fn two_failed_recipients() {
    let body: &[u8] = b"Reporting-MTA: dns; mx\n\nFinal-Recipient: rfc822; a@x.io\nAction: failed\nStatus: 5.1.1\nDiagnostic-Code: smtp; 550 no such user\n\nFinal-Recipient: rfc822; b@x.io\nAction: failed\nStatus: 5.7.1 (policy rejection)\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/delivery-status")),
        Report::Bounces(vec![
            bounce((5, 1, 1), None, Some("a@x.io"), "550 no such user"),
            bounce((5, 7, 1), None, Some("b@x.io"), ""),
        ])
    );
}

#[test]
fn folded_diagnostic_code() {
    let body: &[u8] = b"Reporting-MTA: dns; mx\n\nFinal-Recipient: rfc822; a@x.io\nAction: failed\nStatus: 5.1.1\nDiagnostic-Code: smtp; 550 very long\n diagnostic text\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/delivery-status")),
        Report::Bounces(vec![bounce(
            (5, 1, 1),
            None,
            Some("a@x.io"),
            "550 very long diagnostic text",
        )])
    );
}

#[test]
fn uppercase_address_type() {
    let body: &[u8] = b"Reporting-MTA: dns; mx\n\nFinal-Recipient: RFC822; <a@x.io>\nOriginal-Recipient: RfC822; b@x.io\nAction: FAILED\nStatus: 5.1.1\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/delivery-status")),
        Report::Bounces(vec![bounce((5, 1, 1), Some("b@x.io"), Some("a@x.io"), "",)])
    );
}

#[test]
fn base64_status_part() {
    let body: &[u8] = b"Reporting-MTA: dns; mx\n\nFinal-Recipient: rfc822; a@x.io\nAction: failed\nStatus: 5.1.1\n";
    let encoded = dkim::base64::encode(body);
    assert_eq!(
        parse(&wrap(
            encoded.as_bytes(),
            "Content-Type: message/delivery-status\nContent-Transfer-Encoding: base64"
        )),
        Report::Bounces(vec![bounce((5, 1, 1), None, Some("a@x.io"), "")])
    );
}

#[test]
fn quoted_printable_status_part() {
    let body: &[u8] = b"Reporting-MTA: dns; mx\n\nFinal-Recipient: rfc822; a@x.io\nAction: failed\nStatus: =\n5.1.1\nDiagnostic-Code: smtp; 550=20gone\n";
    assert_eq!(
        parse(&wrap(
            body,
            "Content-Type: message/delivery-status\nContent-Transfer-Encoding: quoted-printable"
        )),
        Report::Bounces(vec![bounce((5, 1, 1), None, Some("a@x.io"), "550 gone",)])
    );
}

#[test]
fn global_delivery_status_utf8() {
    let body: &str = "Reporting-MTA: dns; mx\n\nFinal-Recipient: UTF-8; h\u{00e5}mza@x.io\nAction: failed\nStatus: 5.1.1\n";
    let mut m = Vec::new();
    m.extend_from_slice(b"Content-Type: multipart/report; boundary=g\n\n");
    m.extend_from_slice(
        b"--g\nContent-Type: message/global-delivery-status\nContent-Transfer-Encoding: 8bit\n\n",
    );
    m.extend_from_slice(body.as_bytes());
    m.extend_from_slice(b"\n--g--\n");
    assert_eq!(
        parse(&m),
        Report::Bounces(vec![
            bounce((5, 1, 1), None, Some("h\u{00e5}mza@x.io"), "",)
        ])
    );
}

#[test]
fn arf_abuse_with_recipient() {
    let body: &[u8] = b"Feedback-Type: abuse\nOriginal-Rcpt-To: <user@x.io>\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/feedback-report")),
        Report::Complaint {
            recipient: Some("user@x.io".to_string()),
        }
    );
}

#[test]
fn arf_abuse_without_recipient() {
    let body: &[u8] = b"Feedback-Type: abuse\nSource-IP: 192.0.2.1\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/feedback-report")),
        Report::Complaint { recipient: None }
    );
}

#[test]
fn arf_not_spam_is_unknown() {
    let body: &[u8] = b"Feedback-Type: not-spam\nOriginal-Rcpt-To: user@x.io\n";
    assert_eq!(
        parse(&wrap(body, "Content-Type: message/feedback-report")),
        Report::Unknown
    );
}

#[test]
fn plain_text_mail_is_unknown() {
    let m: &[u8] = b"From: a@x.io\nTo: b@y.io\nContent-Type: text/plain\n\nhello\n";
    assert_eq!(parse(m), Report::Unknown);
}

#[test]
fn missing_boundary_is_unknown() {
    let m: &[u8] = b"Content-Type: multipart/report; report-type=delivery-status\n\nbody\n";
    assert_eq!(parse(m), Report::Unknown);
}

#[test]
fn over_limit_blocks_are_ignored() {
    let mut body = Vec::new();
    body.extend_from_slice(b"Reporting-MTA: dns; mx\n");
    for i in 0..1001 {
        body.extend_from_slice(
            format!(
                "\nFinal-Recipient: rfc822; u{i}@x.io\nAction: failed\nStatus: 5.1.{}\n",
                i % 1000
            )
            .as_bytes(),
        );
    }
    let Report::Bounces(bounces) = parse(&wrap(&body, "Content-Type: message/delivery-status"))
    else {
        panic!("expected bounces");
    };
    assert_eq!(bounces.len(), 1000);
}

#[test]
fn no_prefix_panics() {
    let samples: Vec<Vec<u8>> = vec![
        dsn_crlf(),
        wrap(b"Reporting-MTA: dns; mx\n\nFinal-Recipient: rfc822; a@x.io\nAction: failed\nStatus: 5.1.1\n", "Content-Type: message/delivery-status"),
        wrap(b"Feedback-Type: abuse\nOriginal-Rcpt-To: user@x.io\n", "Content-Type: message/feedback-report"),
        b"Content-Type: multipart/report\n\n".to_vec(),
        Vec::new(),
    ];
    for sample in samples {
        for len in 0..sample.len() {
            let _ = parse(&sample[..len]);
        }
    }
}

fn expected() -> Report {
    Report::Bounces(vec![bounce(
        (5, 1, 1),
        Some("gone@example.org"),
        Some("gone@example.org"),
        "550 5.1.1 user unknown",
    )])
}

#[test]
fn long_folded_header_is_skipped() {
    let mut m = b"X-Long: ".to_vec();
    for _ in 0..200 {
        m.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz\r\n\t");
    }
    m.extend_from_slice(b"end\r\n");
    m.extend_from_slice(&dsn_crlf());
    assert_eq!(parse(&m), expected());
}

#[test]
fn over_cap_field_is_skipped() {
    let mut m = b"X-Huge: ".to_vec();
    m.extend(std::iter::repeat_n(b'a', 70_000));
    m.extend_from_slice(b"\r\n");
    m.extend_from_slice(&dsn_crlf());
    assert_eq!(parse(&m), expected());
}

#[test]
fn boundary_with_trailing_space() {
    let text = String::from_utf8(dsn_crlf()).expect("ascii");
    let padded = text
        .replace("--mx-42\r\n", "--mx-42 \t\r\n")
        .replace("--mx-42--\r\n", "--mx-42-- \r\n");
    assert_eq!(parse(padded.as_bytes()), expected());
}
