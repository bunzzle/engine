use http::{Event, Invalid, Limits, Response, Server, Status, imf};

#[test]
fn refuses_unsafe_headers() {
    let base = || Response::new(Status::OK);
    assert_eq!(base().header("X-A", "a\r\nB: c").err(), Some(Invalid));
    assert_eq!(base().header("X-A", "a\nb").err(), Some(Invalid));
    assert_eq!(base().header("X-A", "a\0").err(), Some(Invalid));
    assert_eq!(base().header("X-A", "caf\u{e9}").err(), Some(Invalid));
    assert_eq!(base().header("X A", "a").err(), Some(Invalid));
    assert_eq!(base().header("", "a").err(), Some(Invalid));
    assert_eq!(base().header("Content-Length", "1").err(), Some(Invalid));
    assert_eq!(
        base().header("connection", "keep-alive").err(),
        Some(Invalid)
    );
    assert_eq!(
        base().header("Transfer-Encoding", "chunked").err(),
        Some(Invalid)
    );
    assert_eq!(base().header("Date", "x").err(), Some(Invalid));
    assert!(base().header("Retry-After", "1").is_ok());
}

#[test]
fn writes_the_response_head() {
    let mut server = Server::new(Limits::default());
    server.input(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(matches!(server.event(), Some(Event::Request(_))));
    let response = Response::new(Status::TOO_MANY_REQUESTS)
        .header("Retry-After", "2")
        .and_then(|r| r.body("application/json", b"{}".to_vec()))
        .expect("valid");
    server.respond(&response, 784_111_777_000);
    assert_eq!(
        String::from_utf8(server.output()).expect("ascii"),
        "HTTP/1.1 429 Too Many Requests\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\nContent-Length: 2\r\nCache-Control: no-store\r\nRetry-After: 2\r\nContent-Type: application/json\r\n\r\n{}"
    );
    assert!(!server.closed());
    assert_eq!(imf(0), "Thu, 01 Jan 1970 00:00:00 GMT");
}

#[test]
fn close_on_the_response_closes_the_connection() {
    let mut server = Server::new(Limits::default());
    server.input(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(matches!(server.event(), Some(Event::Request(_))));
    server.respond(&Response::new(Status::UNAVAILABLE).close(), 0);
    assert!(server.closed());
    assert!(server.event().is_none());
    assert!(
        String::from_utf8(server.output())
            .expect("ascii")
            .contains("Connection: close\r\n")
    );
}

#[test]
fn a_timeout_mid_head_closes() {
    let mut server = Server::new(Limits::default());
    server.input(b"GET /a HTTP/1.1\r\nHo");
    assert!(server.event().is_none());
    server.respond(&Response::new(Status::REQUEST_TIMEOUT), 0);
    assert!(server.closed());
}
