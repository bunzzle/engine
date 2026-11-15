use http::{Event, Limits, Response, Server, Status};

use crate::common::{LIMIT, Seen, request, run, run_with};

fn fault(input: &str) -> (Status, bool, usize) {
    let run = run(&[input.as_bytes()]);
    let Some(Seen::Fault(status)) = run.seen.first() else {
        panic!("no fault for {input:?}: {:?}", run.seen);
    };
    (*status, run.closed, run.seen.len())
}

fn refused(input: &str, status: Status) {
    let (got, closed, seen) = fault(input);
    assert_eq!(got, status, "{input:?}");
    assert!(closed, "{input:?} left open");
    assert_eq!(seen, 1, "{input:?} parsed after a fault");
}

fn accepted(input: &str, expected: &[Seen]) {
    let run = run(&[input.as_bytes()]);
    assert_eq!(run.seen, expected, "{input:?}");
}

#[test]
fn reads_simple_requests() {
    accepted(
        "GET /a?b=c HTTP/1.1\r\nHost: x\r\n\r\n",
        &[request("GET", "/a?b=c", b"")],
    );
    accepted(
        "POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
        &[request("POST", "/m", b"hello")],
    );
    accepted(
        "POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        &[request("POST", "/m", b"")],
    );
}

#[test]
fn reads_chunked_bodies() {
    accepted(
        "POST /m HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;a=b\r\n world\r\n0\r\nX-T: y\r\n\r\n",
        &[request("POST", "/m", b"hello world")],
    );
    accepted(
        "POST /m HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: Chunked\r\n\r\nA \r\n0123456789\r\n0\r\n\r\n",
        &[request("POST", "/m", b"0123456789")],
    );
}

#[test]
fn keeps_connections_and_reads_pipelined_requests() {
    let input = "GET /1 HTTP/1.1\r\nHost: x\r\n\r\nPOST /2 HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nokGET /3 HTTP/1.1\r\nHost: x\r\n\r\n";
    let run = run(&[input.as_bytes()]);
    assert_eq!(
        run.seen,
        [
            request("GET", "/1", b""),
            request("POST", "/2", b"ok"),
            request("GET", "/3", b"")
        ]
    );
    assert!(!run.closed);
}

#[test]
fn refuses_smuggling_framing() {
    let cases = [
        (
            "Content-Length: 5\r\nTransfer-Encoding: chunked",
            Status::BAD_REQUEST,
        ),
        (
            "Transfer-Encoding: chunked\r\nContent-Length: 5",
            Status::BAD_REQUEST,
        ),
        (
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
            Status::BAD_REQUEST,
        ),
        (
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
            Status::BAD_REQUEST,
        ),
        ("Transfer-Encoding : chunked", Status::BAD_REQUEST),
        ("Transfer-Encoding: xchunked", Status::NOT_IMPLEMENTED),
        (
            "Transfer-Encoding: chunked, identity",
            Status::NOT_IMPLEMENTED,
        ),
        ("Transfer-Encoding: gzip", Status::NOT_IMPLEMENTED),
        ("Transfer-Encoding:\r\n chunked", Status::BAD_REQUEST),
        (
            "Content-Length: 5\r\nContent-Length: 6",
            Status::BAD_REQUEST,
        ),
        ("Content-Length: 5, 5", Status::BAD_REQUEST),
        ("Content-Length: +5", Status::BAD_REQUEST),
        ("Content-Length: -1", Status::BAD_REQUEST),
        ("Content-Length: 5 5", Status::BAD_REQUEST),
        ("Content-Length: 0x5", Status::BAD_REQUEST),
        ("Content-Length:", Status::BAD_REQUEST),
        ("Content-Length: 12345678901234567890", Status::BAD_REQUEST),
    ];
    for (field, status) in cases {
        refused(
            &format!(
                "POST /m HTTP/1.1\r\nHost: x\r\n{field}\r\n\r\nhello\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
            ),
            status,
        );
    }
}

#[test]
fn accepts_identical_lengths() {
    accepted(
        "POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\nok",
        &[request("POST", "/m", b"ok")],
    );
    accepted(
        "POST /m HTTP/1.1\r\nHost: x\r\nContent-Length:\t002 \r\n\r\nok",
        &[request("POST", "/m", b"ok")],
    );
}

#[test]
fn requires_a_length_for_bodies() {
    refused(
        "POST /m HTTP/1.1\r\nHost: x\r\n\r\n",
        Status::LENGTH_REQUIRED,
    );
    refused(
        "PUT /m HTTP/1.1\r\nHost: x\r\n\r\n",
        Status::LENGTH_REQUIRED,
    );
    accepted(
        "DELETE /m HTTP/1.1\r\nHost: x\r\n\r\n",
        &[request("DELETE", "/m", b"")],
    );
}

#[test]
fn refuses_bad_lines() {
    let cases = [
        ("GET /a HTTP/1.0\r\nHost: x\r\n\r\n", Status::VERSION),
        ("GET /a HTTP/2.0\r\nHost: x\r\n\r\n", Status::VERSION),
        ("GET /a HTTP/1.1x\r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("GET /a http/1.1\r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("GET  /a HTTP/1.1\r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("GET /a HTTP/1.1 \r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("GET /a\r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("G(T /a HTTP/1.1\r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        (
            "GET /a\x01 HTTP/1.1\r\nHost: x\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        ("GET /a#f HTTP/1.1\r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("GET * HTTP/1.1\r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("GET x:80 HTTP/1.1\r\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("GET /a HTTP/1.1\nHost: x\r\n\r\n", Status::BAD_REQUEST),
        ("GET /a HTTP/1.1\r\nHost: x\n\r\n", Status::BAD_REQUEST),
        ("GET /a HTTP/1.1\r\nHost: x\r\n\n", Status::BAD_REQUEST),
        (
            "GET /a HTTP/1.1\r\nHost: x\rY: z\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        (
            "GET /a HTTP/1.1\r\nHost: x\r\nA: b\x00c\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        (
            "GET /a HTTP/1.1\r\nHost: x\r\nA: b\r\n c\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        (
            "GET /a HTTP/1.1\r\nHost: x\r\nA : b\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        (
            "GET /a HTTP/1.1\r\nHost: x\r\n: b\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        (
            "GET /a HTTP/1.1\r\nHost: x\r\nA(: b\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        (
            "GET /a HTTP/1.1\r\nHost: x\r\nnocolon\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        ("GET /a HTTP/1.1\r\n\r\n", Status::BAD_REQUEST),
        (
            "GET /a HTTP/1.1\r\nHost: x\r\nHost: x\r\n\r\n",
            Status::BAD_REQUEST,
        ),
        ("GET /a HTTP/1.1\r\nHost:\r\n\r\n", Status::BAD_REQUEST),
        ("GET /a HTTP/1.1\r\nHost: a@b\r\n\r\n", Status::BAD_REQUEST),
        (
            "GET /a HTTP/1.1\r\nHost: x\r\nExpect: 200-ok\r\n\r\n",
            Status::EXPECTATION_FAILED,
        ),
    ];
    for (input, status) in cases {
        refused(input, status);
    }
}

#[test]
fn takes_absolute_form_for_the_same_host() {
    accepted(
        "GET http://API.example/v1?a HTTP/1.1\r\nHost: api.example\r\n\r\n",
        &[request("GET", "/v1?a", b"")],
    );
    accepted(
        "GET https://api.example HTTP/1.1\r\nHost: api.example\r\n\r\n",
        &[request("GET", "/", b"")],
    );
    refused(
        "GET http://other.example/v1 HTTP/1.1\r\nHost: api.example\r\n\r\n",
        Status::BAD_REQUEST,
    );
    refused(
        "GET ftp://api.example/v1 HTTP/1.1\r\nHost: api.example\r\n\r\n",
        Status::BAD_REQUEST,
    );
}

#[test]
fn skips_a_few_leading_empty_lines() {
    accepted(
        "\r\n\r\nGET /a HTTP/1.1\r\nHost: x\r\n\r\n",
        &[request("GET", "/a", b"")],
    );
    refused(
        &format!("{}GET /a HTTP/1.1\r\nHost: x\r\n\r\n", "\r\n".repeat(9)),
        Status::BAD_REQUEST,
    );
}

#[test]
fn caps_lines_heads_and_fields() {
    let limits = Limits::default();
    let long = "a".repeat(limits.line);
    refused(
        &format!("GET /{long} HTTP/1.1\r\nHost: x\r\n\r\n"),
        Status::URI_TOO_LONG,
    );
    let (status, closed, _) = fault(&format!("GET /{long}"));
    assert_eq!((status, closed), (Status::URI_TOO_LONG, true));
    let fits = "a".repeat(limits.line - "GET / HTTP/1.1".len());
    accepted(
        &format!("GET /{fits} HTTP/1.1\r\nHost: x\r\n\r\n"),
        &[request("GET", &format!("/{fits}"), b"")],
    );
    let big = format!("A: {}\r\n", "b".repeat(1000)).repeat(17);
    refused(
        &format!("GET /a HTTP/1.1\r\nHost: x\r\n{big}\r\n"),
        Status::HEADERS_TOO_LARGE,
    );
    let (status, _, _) = fault(&format!("GET /a HTTP/1.1\r\nHost: x\r\n{big}"));
    assert_eq!(status, Status::HEADERS_TOO_LARGE);
    let fields = "A: b\r\n".repeat(limits.fields);
    refused(
        &format!("GET /a HTTP/1.1\r\nHost: x\r\n{fields}\r\n"),
        Status::HEADERS_TOO_LARGE,
    );
    let fields = "A: b\r\n".repeat(limits.fields - 1);
    accepted(
        &format!("GET /a HTTP/1.1\r\nHost: x\r\n{fields}\r\n"),
        &[request("GET", "/a", b"")],
    );
}

#[test]
fn refuses_bad_chunks() {
    let head = "POST /m HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
    let cases = [
        ("10000000000000000\r\n", Status::BAD_REQUEST),
        ("g\r\n", Status::BAD_REQUEST),
        ("\r\n", Status::BAD_REQUEST),
        (";a\r\n", Status::BAD_REQUEST),
        ("5\nhello\r\n0\r\n\r\n", Status::BAD_REQUEST),
        ("5\r\nhelloX\r\n0\r\n\r\n", Status::BAD_REQUEST),
        ("5\r\nhello\n0\r\n\r\n", Status::BAD_REQUEST),
        ("0\r\n\n", Status::BAD_REQUEST),
        ("0\r\n bad: x\r\n\r\n", Status::BAD_REQUEST),
        ("0\r\nno colon\r\n\r\n", Status::BAD_REQUEST),
        ("1;a\x00\r\nx\r\n0\r\n\r\n", Status::BAD_REQUEST),
        ("100001\r\n", Status::TOO_LARGE),
        ("ffffffffffffffff\r\n", Status::TOO_LARGE),
    ];
    for (body, status) in cases {
        refused(&format!("{head}{body}"), status);
    }
    let extension = format!("1;{}\r\nx\r\n0\r\n\r\n", "e".repeat(256));
    refused(&format!("{head}{extension}"), Status::BAD_REQUEST);
    let extension = format!("1;{}\r\nx\r\n0\r\n\r\n", "e".repeat(254));
    accepted(
        &format!("{head}{extension}"),
        &[request("POST", "/m", b"x")],
    );
    let trailer = format!("0\r\nA: {}\r\n\r\n", "b".repeat(4096));
    refused(&format!("{head}{trailer}"), Status::BAD_REQUEST);
}

#[test]
fn refuses_bodies_over_the_limit() {
    refused(
        &format!(
            "POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            LIMIT + 1
        ),
        Status::TOO_LARGE,
    );
    let chunk = "8000\r\n".to_owned() + &"a".repeat(0x8000) + "\r\n";
    let body = chunk.repeat(32) + "1\r\na\r\n0\r\n\r\n";
    refused(
        &format!("POST /m HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n{body}"),
        Status::TOO_LARGE,
    );
    let body = chunk.repeat(32) + "0\r\n\r\n";
    let run =
        run(&[
            format!("POST /m HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n{body}")
                .as_bytes(),
        ]);
    assert!(matches!(&run.seen[..], [Seen::Request { body, .. }] if body.len() as u64 == LIMIT));
}

#[test]
fn closes_after_an_early_response() {
    let input = b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut server = Server::new(Limits::default());
    server.input(input);
    assert!(matches!(server.event(), Some(Event::Request(_))));
    server.respond(&Response::new(Status::UNAUTHORIZED), 0);
    assert!(server.closed());
    assert!(server.event().is_none());
    let output = String::from_utf8(server.output()).expect("ascii");
    assert!(output.contains("Connection: close\r\n"));

    let mut server = Server::new(Limits::default());
    server.input(b"POST /m HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert!(matches!(server.event(), Some(Event::Request(_))));
    server.respond(&Response::new(Status::FORBIDDEN), 0);
    assert!(server.closed());

    let mut server = Server::new(Limits::default());
    server.input(b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nab");
    assert!(matches!(server.event(), Some(Event::Request(_))));
    server.accept_body(LIMIT).expect("accepted");
    assert_eq!(server.event(), Some(Event::Body(b"ab".to_vec())));
    server.respond(&Response::new(Status::UNPROCESSABLE), 0);
    assert!(server.closed());

    let mut server = Server::new(Limits::default());
    server.input(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(matches!(server.event(), Some(Event::Request(_))));
    server.respond(&Response::new(Status::NOT_FOUND), 0);
    assert!(!server.closed());
    assert!(matches!(server.event(), Some(Event::Request(r)) if r.path == "/b"));
}

#[test]
fn sends_continue_only_when_the_body_is_wanted() {
    let head = b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nExpect: 100-Continue\r\n\r\n";
    let mut server = Server::new(Limits::default());
    server.input(head);
    assert!(matches!(server.event(), Some(Event::Request(r)) if r.expect));
    assert_eq!(server.output(), b"");
    server.accept_body(LIMIT).expect("accepted");
    assert_eq!(server.output(), b"HTTP/1.1 100 Continue\r\n\r\n");
    server.input(b"ok");
    assert_eq!(server.event(), Some(Event::Body(b"ok".to_vec())));
    assert_eq!(server.event(), Some(Event::End));

    let mut server = Server::new(Limits::default());
    server.input(head);
    assert!(matches!(server.event(), Some(Event::Request(_))));
    server.respond(&Response::new(Status::UNAUTHORIZED), 0);
    let output = server.output();
    assert!(output.starts_with(b"HTTP/1.1 401 "));
    assert!(server.closed());

    let mut server = Server::new(Limits::default());
    server
        .input(b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n");
    assert!(matches!(server.event(), Some(Event::Request(_))));
    server.accept_body(LIMIT).expect("accepted");
    assert_eq!(server.output(), b"");
}

#[test]
fn closes_when_asked_or_at_the_request_cap() {
    let run = run(&[b"GET /a HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, Close\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"]);
    assert_eq!(run.seen, [request("GET", "/a", b"")]);
    assert!(run.closed);

    let limits = Limits {
        requests: 2,
        ..Limits::default()
    };
    let one = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n".repeat(3);
    let run = run_with(limits, &[one.as_bytes()]);
    assert_eq!(run.seen.len(), 2);
    assert!(run.closed);
    let text = String::from_utf8(run.output).expect("ascii");
    assert_eq!(text.matches("Connection: close").count(), 1);
}

#[test]
fn reports_phases() {
    let mut server = Server::new(Limits::default());
    assert_eq!(server.phase(), http::Phase::Head);
    server.input(b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n");
    assert!(matches!(server.event(), Some(Event::Request(_))));
    assert_eq!(server.phase(), http::Phase::Handler);
    assert!(!server.wants_input());
    server.accept_body(LIMIT).expect("accepted");
    assert_eq!(server.phase(), http::Phase::Body);
    assert!(server.wants_input());
    server.input(b"x");
    assert!(matches!(server.event(), Some(Event::Body(_))));
    assert_eq!(server.event(), Some(Event::End));
    assert_eq!(server.phase(), http::Phase::Handler);
    server.respond(&Response::new(Status::OK), 0);
    assert_eq!(server.phase(), http::Phase::Idle);
    server.input(b"G");
    assert!(server.event().is_none());
    assert_eq!(server.phase(), http::Phase::Head);
}

#[test]
fn answers_head_requests_without_a_body() {
    let mut server = Server::new(Limits::default());
    server.input(b"HEAD /a HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(matches!(server.event(), Some(Event::Request(_))));
    let response = Response::new(Status::OK)
        .body("text/plain", b"hello".to_vec())
        .expect("valid");
    server.respond(&response, 0);
    let output = String::from_utf8(server.output()).expect("ascii");
    assert!(output.contains("Content-Length: 5\r\n"));
    assert!(output.ends_with("\r\n\r\n"));
}
