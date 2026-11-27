use crate::common::{Client, PLAIN};

fn lines(text: &str) -> Vec<&str> {
    text.split_terminator("\r\n").collect()
}

#[test]
fn mx_offers_size_and_8bitmime_without_tls_and_never_auth() {
    let mut client = Client::mx(false);
    assert_eq!(
        lines(&client.send(b"EHLO relay.example\r\n")),
        [
            "250-mx.example.org",
            "250-PIPELINING",
            "250-ENHANCEDSTATUSCODES",
            "250-8BITMIME",
            "250-CHUNKING",
            "250-SIZE 65536",
            "250 STARTTLS"
        ]
    );
    assert_eq!(
        client.send(format!("AUTH PLAIN {PLAIN}\r\n").as_bytes()),
        "502 5.5.1 Command not implemented\r\n"
    );
    assert_eq!(
        client.send(b"STARTTLS\r\n"),
        "220 2.0.0 Ready to start TLS\r\n"
    );
    assert_eq!(
        lines(&client.send(b"EHLO relay.example\r\n")),
        [
            "250-mx.example.org",
            "250-PIPELINING",
            "250-ENHANCEDSTATUSCODES",
            "250-8BITMIME",
            "250-CHUNKING",
            "250 SIZE 65536"
        ]
    );
    assert!(!client.server.authenticated());
}

#[test]
fn mx_takes_a_null_sender_in_the_clear_and_one_recipient() {
    let mut client = Client::mx(false);
    client.send(b"EHLO relay.example\r\n");
    client.clear();
    assert_eq!(
        lines(&client.send(
            b"MAIL FROM:<> BODY=8BITMIME\r\nRCPT TO:<b1@example.org>\r\nRCPT TO:<b2@example.org>\r\nDATA\r\n"
        )),
        [
            "250 2.1.0 Sender OK",
            "250 2.1.5 Recipient OK",
            "452 4.5.3 Too many recipients",
            "354 End data with <CR><LF>.<CR><LF>"
        ]
    );
    assert_eq!(
        client.log,
        ["mail  None Some(EightBit)", "rcpt b1@example.org", "data"]
    );
    assert_eq!(
        client.send(b"Subject: x\r\n\r\nbody\r\n.\r\n"),
        "250 2.0.0 id1\r\n"
    );
    client.clear();
    assert_eq!(
        lines(&client.send(b"MAIL FROM:<mailer@example.net>\r\nRCPT TO:<b3@example.org>\r\n")),
        ["250 2.1.0 Sender OK", "250 2.1.5 Recipient OK"]
    );
    assert_eq!(
        client.send(b"RCPT TO:<b4@example.org>\r\n"),
        "452 4.5.3 Too many recipients\r\n"
    );
}

#[test]
fn mx_takes_a_recipient_after_a_refused_one() {
    let mut client = Client::mx(true);
    client.send(b"EHLO relay.example\r\n");
    client.clear();
    assert_eq!(
        lines(
            &client
                .send(b"MAIL FROM:<>\r\nRCPT TO:<bad@example.org>\r\nRCPT TO:<b1@example.org>\r\n")
        ),
        [
            "250 2.1.0 Sender OK",
            "550 5.7.1 Recipient refused",
            "452 4.5.3 Too many recipients"
        ]
    );
    assert_eq!(
        lines(&client.send(b"RCPT TO:<b1@example.org>\r\nRCPT TO:<b2@example.org>\r\n")),
        ["250 2.1.5 Recipient OK", "452 4.5.3 Too many recipients"]
    );
    assert_eq!(
        client.log,
        [
            "mail  None None",
            "rcpt bad@example.org",
            "rcpt b1@example.org"
        ]
    );
}

#[test]
fn submission_still_refuses_a_null_sender() {
    let mut client = Client::ready();
    assert_eq!(
        client.send(b"MAIL FROM:<>\r\n"),
        "550 5.7.1 Null sender not allowed\r\n"
    );
}
