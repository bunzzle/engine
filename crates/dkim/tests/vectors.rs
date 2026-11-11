use std::fmt::Write;

use aws_lc_rs::digest::{Digest, SHA256};
use aws_lc_rs::signature::{
    ED25519, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256,
    UnparsedPublicKey,
};
use crypto::{DkimAlg, DkimKey, Plain};
use dkim::{
    BodyHash, Check, Error, SIGNED, Template, base64, check, digest, header_list, parse, signed,
    unsigned,
};

const RFC_ED25519: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n d=football.example.com; i=@football.example.com;\r\n q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n subject : date : message-id : from : subject : date;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r\n";
const RFC_RSA: &str = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n d=football.example.com; i=@football.example.com;\r\n q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n date : message-id : from : subject : date;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r\n";
const RFC_HEADERS: &str = "From: Joe SixPack <joe@football.example.com>\r\nTo: Suzie Q <suzie@shopping.example.net>\r\nSubject: Is dinner ready?\r\nDate: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\nMessage-ID: <20030712040037.46341.5F8J@football.example.com>\r\n";
const RFC_BODY: &[u8] = b"Hi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n\r\n";
const RFC_ED25519_PUBLIC: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const RFC_RSA_PUBLIC: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB";
const RFC_ED25519_SECRET: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const HEADERS: &str = "From: Ada <ada@news.example.org>\r\nTo: bob@example.net,\r\n carol@example.net\r\nSubject:  Weekly\t notes \r\nDate: Tue, 10 Nov 2026 09:00:00 +0000\r\nMessage-ID: <x1@news.example.org>\r\nX-Other: kept\r\n";
const BODY: &[u8] = b"Hello  there \r\n\r\nline two\r\n\r\n\r\n";

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("small")
    }
}

fn body_hash(body: &[u8]) -> [u8; 32] {
    let mut hash = BodyHash::new();
    hash.update(body);
    hash.finish()
}

fn fixed_ed25519() -> DkimKey {
    let mut pkcs8 = ED25519_PKCS8_PREFIX.to_vec();
    pkcs8.extend(base64::decode(RFC_ED25519_SECRET.as_bytes()).expect("secret"));
    DkimKey::from_pkcs8(DkimAlg::Ed25519Sha256, Plain::new(pkcs8)).expect("pkcs8")
}

fn template(alg: DkimAlg) -> Template<'static> {
    Template {
        alg,
        domain: "news.example.org",
        selector: "s2026",
        time: 1_794_000_000,
        expiry: 1_794_604_800,
    }
}

fn sign(key: &DkimKey, headers: &str, body: &[u8]) -> Vec<u8> {
    let fields = parse(headers.as_bytes()).expect("parse");
    let field = unsigned(&template(key.alg()), &fields, &body_hash(body)).expect("unsigned");
    let mut stored = field.clone();
    stored.extend_from_slice(headers.as_bytes());
    let digest = digest(&parse(&stored).expect("stored"), 0).expect("digest");
    let mut out = signed(&field, &key.sign(&digest).expect("sign")).expect("signed");
    out.extend_from_slice(headers.as_bytes());
    out
}

fn verify(section: &[u8], at: usize, body: &[u8], public: &[u8]) -> Result<Check, Error> {
    let fields = parse(section)?;
    let check = check(&fields, at, &body_hash(body))?;
    let valid = match check.alg {
        DkimAlg::Ed25519Sha256 => UnparsedPublicKey::new(&ED25519, public)
            .verify(&check.digest, &check.signature)
            .is_ok(),
        DkimAlg::RsaSha256 => {
            let digest = Digest::import_less_safe(&check.digest, &SHA256).expect("digest");
            let legacy =
                UnparsedPublicKey::new(&RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, public);
            let current = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public);
            if public.len() < 200 {
                legacy.verify_digest(&digest, &check.signature).is_ok()
            } else {
                current.verify_digest(&digest, &check.signature).is_ok()
            }
        }
    };
    valid.then_some(check).ok_or(Error::BodyHash)
}

fn rfc_section() -> String {
    format!("{RFC_ED25519}{RFC_RSA}{RFC_HEADERS}")
}

#[test]
fn rfc8463_signatures_verify() {
    let section = rfc_section();
    let ed25519 = base64::decode(RFC_ED25519_PUBLIC.as_bytes()).expect("public");
    let rsa = base64::decode(RFC_RSA_PUBLIC.as_bytes()).expect("public");
    let check = verify(section.as_bytes(), 0, RFC_BODY, &ed25519).expect("ed25519");
    assert_eq!(check.domain, "football.example.com");
    assert_eq!(check.selector, "brisbane");
    assert_eq!(check.time, Some(1_528_637_909));
    verify(section.as_bytes(), 1, RFC_BODY, &rsa).expect("rsa");
    assert_eq!(fixed_ed25519().public().expect("public"), ed25519);
}

#[test]
fn rfc8463_ed25519_signature_is_reproduced_exactly() {
    let section = rfc_section();
    let fields = parse(section.as_bytes()).expect("parse");
    let check = check(&fields, 0, &body_hash(RFC_BODY)).expect("check");
    let signature = fixed_ed25519().sign(&check.digest).expect("sign");
    assert_eq!(signature, check.signature);
}

#[test]
fn rfc8463_breaks_when_a_signed_field_changes() {
    let section = rfc_section().replace("Is dinner ready?", "Is dinner ready!");
    let public = base64::decode(RFC_ED25519_PUBLIC.as_bytes()).expect("public");
    assert!(verify(section.as_bytes(), 0, RFC_BODY, &public).is_err());
    let body = b"Hi.\r\n\r\nWe lost the game.  Are you hungry now?\r\n";
    assert_eq!(
        verify(rfc_section().as_bytes(), 0, body, &public),
        Err(Error::BodyHash)
    );
}

#[test]
fn own_fields_are_frozen() {
    let fields = parse(HEADERS.as_bytes()).expect("parse");
    let field =
        unsigned(&template(DkimAlg::Ed25519Sha256), &fields, &body_hash(BODY)).expect("unsigned");
    assert_eq!(
        String::from_utf8(field.clone()).expect("ascii"),
        "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=news.example.org;\r\n s=s2026; t=1794000000; x=1794604800; h=from:from:to:to:cc:subject:subject:\r\n date:date:message-id:message-id:reply-to:sender:in-reply-to:references:\r\n mime-version:content-type:content-transfer-encoding:list-unsubscribe:\r\n list-unsubscribe-post:list-id:feedback-id;\r\n bh=Krfr4fEXuvkvZYRj05fUGTwbWqL9NgfH6AluDBRGGMM=; b=\r\n"
    );
    let mut stored = field.clone();
    stored.extend_from_slice(HEADERS.as_bytes());
    let digest = digest(&parse(&stored).expect("stored"), 0).expect("digest");
    let full = signed(&field, &fixed_ed25519().sign(&digest).expect("sign")).expect("signed");
    assert_eq!(
        String::from_utf8(full).expect("ascii"),
        "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=news.example.org;\r\n s=s2026; t=1794000000; x=1794604800; h=from:from:to:to:cc:subject:subject:\r\n date:date:message-id:message-id:reply-to:sender:in-reply-to:references:\r\n mime-version:content-type:content-transfer-encoding:list-unsubscribe:\r\n list-unsubscribe-post:list-id:feedback-id;\r\n bh=Krfr4fEXuvkvZYRj05fUGTwbWqL9NgfH6AluDBRGGMM=; b=LCIzLjIZbDzdEtUdNGjpNtJOjD\r\n X+i6bPV8zmxPtK4cVWof1wxt7hyqol6ILrtStO5INfPtnwq7aJtIFt0uqzCw==\r\n"
    );
}

#[test]
fn own_signatures_verify_and_stay_within_the_line_width() {
    let ed25519 = fixed_ed25519();
    let rsa = DkimKey::generate(DkimAlg::RsaSha256).expect("rsa");
    for key in [&ed25519, &rsa] {
        let section = sign(key, HEADERS, BODY);
        verify(&section, 0, BODY, &key.public().expect("public")).expect("verify");
        let field = parse(&section).expect("parse")[0].raw();
        for line in field.split(|&b| b == b'\n') {
            assert!(line.len() <= 79, "{}", String::from_utf8_lossy(line));
        }
    }
}

#[test]
fn over_signing_blocks_added_fields() {
    let key = fixed_ed25519();
    let public = key.public().expect("public");
    let section = sign(&key, HEADERS, BODY);
    let field_end = parse(&section).expect("parse")[0].raw().len();
    for added in [
        "From: Mallory <m@evil.example>\r\n",
        "Reply-To: m@evil.example\r\n",
        "Cc: m@evil.example\r\n",
        "List-Unsubscribe: <https://evil.example/u>\r\n",
    ] {
        for at in [field_end, section.len()] {
            let mut tampered = section.clone();
            tampered.splice(at..at, added.bytes());
            assert!(
                verify(&tampered, 0, BODY, &public).is_err(),
                "{added} at {at}"
            );
        }
    }
    let mut traced = b"Received: by mx.example.net; Tue, 10 Nov 2026 09:00:01 +0000\r\n".to_vec();
    traced.extend_from_slice(&section);
    verify(&traced, 1, BODY, &public).expect("unsigned field added");
}

#[test]
fn relaxed_survives_whitespace_and_folding_changes() {
    let key = fixed_ed25519();
    let public = key.public().expect("public");
    let section = sign(&key, HEADERS, BODY);
    let refolded = String::from_utf8(section)
        .expect("ascii")
        .replace("Subject:  Weekly\t notes ", "subject: Weekly\r\n   notes")
        .into_bytes();
    let body = b"Hello \t there\r\n\r\nline two   \r\n";
    verify(&refolded, 0, body, &public).expect("relaxed");
}

#[test]
fn random_messages_round_trip_with_streamed_bodies() {
    let key = fixed_ed25519();
    let public = key.public().expect("public");
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let words = ["a", "b c", "  ", "\t", "x\r\n", "\r\n", "  y  \r\n", "z"];
    for _ in 0..200 {
        let mut body = Vec::new();
        for _ in 0..rng.below(60) {
            body.extend_from_slice(words[rng.below(words.len())].as_bytes());
        }
        let mut streamed = BodyHash::new();
        let mut at = 0;
        while at < body.len() {
            let n = (1 + rng.below(7)).min(body.len() - at);
            streamed.update(&body[at..at + n]);
            at += n;
        }
        assert_eq!(streamed.finish(), body_hash(&body));
        let mut headers = String::new();
        for _ in 0..rng.below(4) {
            write!(headers, "To: r{}@example.net\r\n", rng.below(100)).expect("write");
        }
        headers.push_str("From: a@news.example.org\r\n");
        if rng.below(2) == 0 {
            headers.push_str("Subject: x\r\n  y\r\n");
        }
        let section = sign(&key, &headers, &body);
        verify(&section, 0, &body, &public).expect("verify");
    }
}

#[test]
fn header_list_counts_each_instance_plus_one() {
    let fields = parse(b"To: a\r\nTo: b\r\nFrom: c\r\n").expect("parse");
    let list = header_list(&fields);
    assert_eq!(list.len(), SIGNED.len() + 3);
    assert_eq!(list.iter().filter(|name| **name == "to").count(), 3);
    assert_eq!(list.iter().filter(|name| **name == "from").count(), 2);
    assert_eq!(list.iter().filter(|name| **name == "cc").count(), 1);
}

#[test]
fn removed_b_value_ignores_its_whitespace() {
    let a = "DKIM-Signature: v=1; c=relaxed/relaxed; h=from; b=abc ; d=x\r\nFrom: a\r\n";
    let b = "DKIM-Signature: v=1; c=relaxed/relaxed; h=from; b=\r\n  QUJD\r\n ; d=x\r\nFrom: a\r\n";
    let one = digest(&parse(a.as_bytes()).expect("a"), 0).expect("a");
    let two = digest(&parse(b.as_bytes()).expect("b"), 0).expect("b");
    assert_eq!(one, two);
    let c = "DKIM-Signature: v=1; c=relaxed/relaxed; h=from; b=; d=x\r\nFrom: a\r\n";
    assert_eq!(digest(&parse(c.as_bytes()).expect("c"), 0).expect("c"), one);
}

#[test]
fn template_and_field_errors() {
    let fields = parse(HEADERS.as_bytes()).expect("parse");
    let body = body_hash(BODY);
    let mut bad = template(DkimAlg::RsaSha256);
    bad.domain = "News.example.org";
    assert_eq!(unsigned(&bad, &fields, &body), Err(Error::Domain));
    bad = template(DkimAlg::RsaSha256);
    bad.selector = "-s";
    assert_eq!(unsigned(&bad, &fields, &body), Err(Error::Selector));
    bad = template(DkimAlg::RsaSha256);
    bad.expiry = bad.time;
    assert_eq!(unsigned(&bad, &fields, &body), Err(Error::Expiry));
    assert_eq!(
        signed(b"DKIM-Signature: v=1; b=x\r\n", b"s"),
        Err(Error::Unsigned)
    );
    assert_eq!(
        signed(b"DKIM-Signature: v=1;b=\r\n", b"s"),
        Err(Error::Unsigned)
    );
    let field = unsigned(&template(DkimAlg::RsaSha256), &fields, &body).expect("unsigned");
    assert_eq!(signed(&field, b""), Err(Error::Unsigned));
}

#[test]
fn check_refuses_what_we_do_not_accept() {
    let body = body_hash(RFC_BODY);
    let cases = [
        (
            "c=relaxed/relaxed;",
            "c=simple/simple;",
            Error::Canonicalization,
        ),
        ("a=ed25519-sha256;", "a=rsa-sha1;", Error::Algorithm),
        ("v=1;", "v=2;", Error::Version),
        ("t=1528637909;", "t=1528637909; l=10;", Error::Length),
        (
            "t=1528637909;",
            "t=1528637909; x=1528637909;",
            Error::Expiry,
        ),
        (
            "h=from : to :\r\n subject : date : message-id : from : subject : date;",
            "h=to : subject;",
            Error::From,
        ),
        (
            "bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;",
            "bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv9=;",
            Error::Base64,
        ),
    ];
    for (from, to, error) in cases {
        let section = format!("{}{RFC_HEADERS}", RFC_ED25519.replace(from, to));
        let fields = parse(section.as_bytes()).expect("parse");
        assert_eq!(check(&fields, 0, &body), Err(error), "{to}");
    }
    let fields = parse(RFC_HEADERS.as_bytes()).expect("parse");
    assert_eq!(check(&fields, 9, &body), Err(Error::Missing("field")));
}
