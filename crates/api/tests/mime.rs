use api::mime::{Attachment, Fault, Mailbox, Message, build};
use dkim::base64;

use crate::common::{Rng, cases};

const BOUNDARY: &str = "=_b0undary7";

#[derive(Debug, PartialEq, Eq)]
struct Leaf {
    content_type: String,
    disposition: Option<String>,
    id: Option<String>,
    data: Vec<u8>,
}

fn mailbox(address: &str) -> Mailbox {
    Mailbox {
        address: address.to_owned(),
        name: None,
    }
}

fn simple() -> Message {
    Message {
        from: Some(mailbox("a@example.com")),
        to: vec![mailbox("b@example.org")],
        subject: "Hello".to_owned(),
        text: Some("Hi there".to_owned()),
        ..Message::default()
    }
}

fn unfold(section: &str) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in section.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            fields.last_mut().expect("field").1.push_str(line);
        } else if let Some((name, value)) = line.split_once(':') {
            fields.push((name.to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    fields
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn decode_words(value: &str) -> String {
    let mut out = String::new();
    let mut pending = Vec::new();
    for word in value.split_whitespace() {
        if let Some(inner) = word
            .strip_prefix("=?utf-8?B?")
            .and_then(|w| w.strip_suffix("?="))
        {
            pending.extend(base64::decode(inner.as_bytes()).expect("base64 word"));
        } else {
            if !pending.is_empty() {
                out.push_str(&String::from_utf8(std::mem::take(&mut pending)).expect("utf-8"));
            }
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(word);
        }
    }
    out.push_str(&String::from_utf8(pending).expect("utf-8"));
    out
}

fn quoted_printable(body: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let lines: Vec<&str> = body.split("\r\n").collect();
    for (i, line) in lines.iter().enumerate() {
        let bytes = line.as_bytes();
        let mut j = 0;
        let soft = line.ends_with('=');
        let end = if soft { bytes.len() - 1 } else { bytes.len() };
        while j < end {
            if bytes[j] == b'=' {
                let hex = std::str::from_utf8(&bytes[j + 1..j + 3]).expect("hex");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                j += 3;
            } else {
                out.push(bytes[j]);
                j += 1;
            }
        }
        if !soft && i + 1 < lines.len() {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

fn leaves(part: &str, out: &mut Vec<Leaf>) {
    let (section, body) = part.split_once("\r\n\r\n").expect("header end");
    let fields = unfold(section);
    let content_type = field(&fields, "content-type").expect("content type");
    if let Some(rest) = content_type.strip_prefix("multipart/") {
        let boundary = rest
            .split("boundary=\"")
            .nth(1)
            .and_then(|b| b.split('"').next())
            .expect("boundary");
        let open = format!("--{boundary}\r\n");
        let close = format!("--{boundary}--\r\n");
        let inner = body.strip_suffix(&close).expect("close delimiter");
        for piece in inner.split(&open).skip(1) {
            let piece = piece.strip_suffix("\r\n").unwrap_or(piece);
            leaves(&format!("{piece}\r\n"), out);
        }
        return;
    }
    let data = match field(&fields, "content-transfer-encoding") {
        Some("7bit") => body
            .strip_suffix("\r\n")
            .unwrap_or(body)
            .as_bytes()
            .to_vec(),
        Some("quoted-printable") => quoted_printable(body.strip_suffix("\r\n").unwrap_or(body)),
        Some("base64") => base64::decode(body.as_bytes()).expect("base64"),
        other => panic!("encoding {other:?}"),
    };
    out.push(Leaf {
        content_type: content_type.to_owned(),
        disposition: field(&fields, "content-disposition").map(str::to_owned),
        id: field(&fields, "content-id").map(str::to_owned),
        data,
    });
}

fn read(bytes: &[u8]) -> (Vec<(String, String)>, Vec<Leaf>) {
    let text = std::str::from_utf8(bytes).expect("ascii");
    assert!(bytes.is_ascii(), "8-bit output");
    for line in text.split_inclusive('\n') {
        assert!(line.ends_with("\r\n"), "bare LF in {line:?}");
        assert!(
            !line[..line.len() - 2].contains('\r'),
            "bare CR in {line:?}"
        );
        assert!(line.len() - 2 <= 998, "line of {}", line.len() - 2);
    }
    assert!(text.ends_with("\r\n"));
    let (section, _) = text.split_once("\r\n\r\n").expect("header end");
    let mut found = Vec::new();
    leaves(text, &mut found);
    (unfold(section), found)
}

fn crlf(text: &str) -> Vec<u8> {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
        .into_bytes()
}

#[test]
fn builds_a_plain_message() {
    let bytes = build(&simple(), BOUNDARY).expect("built");
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("ascii"),
        "From: a@example.com\r\nTo: b@example.org\r\nSubject: Hello\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nHi there\r\n"
    );
    let (_, leaves) = read(&bytes);
    assert_eq!(leaves.len(), 1);
}

#[test]
fn nests_alternative_related_and_mixed() {
    let message = Message {
        html: Some("<p>Hi <img src=\"cid:logo@x\"></p>".to_owned()),
        attachments: vec![
            Attachment {
                filename: "report.pdf".to_owned(),
                content_type: "application/pdf".to_owned(),
                data: vec![0, 1, 2, 255],
                content_id: None,
            },
            Attachment {
                filename: "logo.png".to_owned(),
                content_type: "image/png".to_owned(),
                data: vec![9; 200],
                content_id: Some("<logo@x>".to_owned()),
            },
        ],
        ..simple()
    };
    let bytes = build(&message, BOUNDARY).expect("built");
    let (fields, leaves) = read(&bytes);
    assert!(
        field(&fields, "content-type")
            .expect("type")
            .starts_with("multipart/mixed")
    );
    let text = String::from_utf8(bytes.clone()).expect("ascii");
    assert!(text.contains("multipart/related"));
    assert!(text.contains("multipart/alternative"));
    let kinds: Vec<&str> = leaves.iter().map(|l| l.content_type.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "text/plain; charset=utf-8",
            "text/html; charset=utf-8",
            "image/png",
            "application/pdf"
        ]
    );
    assert_eq!(leaves[0].data, b"Hi there");
    assert_eq!(leaves[2].data, vec![9; 200]);
    assert_eq!(leaves[2].id.as_deref(), Some("<logo@x>"));
    assert_eq!(
        leaves[2].disposition.as_deref(),
        Some("inline; filename=\"logo.png\"")
    );
    assert_eq!(leaves[3].data, [0, 1, 2, 255]);
    assert_eq!(
        leaves[3].disposition.as_deref(),
        Some("attachment; filename=\"report.pdf\"")
    );
}

#[test]
fn encodes_subjects_and_names() {
    let long = "word ".repeat(40);
    for subject in [
        "Grüße aus Antalya 😀",
        long.trim(),
        "has =?utf-8?B?x?= inside",
        &"ü".repeat(300),
    ] {
        let message = Message {
            subject: subject.to_owned(),
            to: vec![
                Mailbox {
                    address: "c@example.org".to_owned(),
                    name: Some("Çağrı \"the\" Öztürk".to_owned()),
                },
                Mailbox {
                    address: "d@example.org".to_owned(),
                    name: Some("Plain \"Quoted\" \\ Name".to_owned()),
                },
            ],
            ..simple()
        };
        let bytes = build(&message, BOUNDARY).expect("built");
        let (fields, _) = read(&bytes);
        assert_eq!(
            decode_words(field(&fields, "subject").expect("subject")),
            subject
        );
        let to = field(&fields, "to").expect("to");
        assert!(to.contains("<c@example.org>"), "{to}");
        assert!(
            to.contains("\"Plain \\\"Quoted\\\" \\\\ Name\" <d@example.org>"),
            "{to}"
        );
        let encoded = to.split(" <c@example.org>").next().expect("name");
        assert_eq!(decode_words(encoded), "Çağrı \"the\" Öztürk");
    }
}

#[test]
fn folds_long_recipient_lists() {
    let message = Message {
        to: (0..300)
            .map(|i| mailbox(&format!("user{i}@example.org")))
            .collect(),
        cc: vec![mailbox(&format!(
            "{}@{}.example",
            "l".repeat(64),
            "d".repeat(63)
        ))],
        ..simple()
    };
    let bytes = build(&message, BOUNDARY).expect("built");
    let (fields, _) = read(&bytes);
    let to: Vec<&str> = field(&fields, "to").expect("to").split(", ").collect();
    assert_eq!(to.len(), 300);
    assert_eq!(to[299], "user299@example.org");
    let text = String::from_utf8(bytes).expect("ascii");
    assert!(text.lines().all(|l| l.len() <= 78 || l.contains("lllll")));
}

#[test]
fn uses_quoted_printable_when_needed() {
    let texts = [
        "a".repeat(2000),
        "café\nnaïve".to_owned(),
        "trailing space \ntab\t\nend".to_owned(),
        "equals = and =_b0undary7 inside".to_owned(),
        "\r\n.\r\nFrom x\n\n".to_owned(),
        "😀".repeat(100),
    ];
    for text in texts {
        let message = Message {
            text: Some(text.clone()),
            ..simple()
        };
        let bytes = build(&message, BOUNDARY).expect("built");
        let (_, leaves) = read(&bytes);
        let expected = crlf(&text);
        let expected = expected.strip_suffix(b"\r\n").unwrap_or(&expected);
        assert_eq!(leaves[0].data, expected, "{text:?}");
    }
}

#[test]
fn encodes_non_ascii_filenames() {
    let message = Message {
        attachments: vec![Attachment {
            filename: "rapor şubat 2026.pdf".to_owned(),
            content_type: "application/pdf".to_owned(),
            data: b"x".to_vec(),
            content_id: None,
        }],
        ..simple()
    };
    let bytes = build(&message, BOUNDARY).expect("built");
    let (_, leaves) = read(&bytes);
    assert_eq!(
        leaves[1].disposition.as_deref(),
        Some("attachment; filename*=utf-8''rapor%20%C5%9Fubat%202026.pdf")
    );
}

#[test]
fn refuses_bad_input() {
    let with = |f: fn(&mut Message)| {
        let mut message = simple();
        f(&mut message);
        build(&message, BOUNDARY).err()
    };
    assert_eq!(with(|m| m.from = None), Some(Fault::Address));
    for address in [
        "a", "a@", "@b", "a b@c", "a@b c", "a@-b", "a..b@c", "a@b..c", "<a@b>", "a@b\r\n", "ü@b",
        "a@ü",
    ] {
        let mut message = simple();
        message.to = vec![mailbox(address)];
        assert_eq!(
            build(&message, BOUNDARY).err(),
            Some(Fault::Address),
            "{address}"
        );
    }
    assert_eq!(
        with(|m| m.to[0].name = Some("x\r\nBcc: e@f".to_owned())),
        Some(Fault::Header)
    );
    assert_eq!(
        with(|m| m.subject = "x\r\nBcc: e@f".to_owned()),
        Some(Fault::Header)
    );
    assert_eq!(with(|m| m.subject = "x\0".to_owned()), Some(Fault::Header));
    for name in [
        "From",
        "bcc",
        "Content-Type",
        "content-transfer-encoding",
        "ARC-Seal",
        "DKIM-Signature",
        "Message-ID",
        "X A",
        "",
        "X:Y",
    ] {
        let mut message = simple();
        message.headers = vec![(name.to_owned(), "v".to_owned())];
        assert_eq!(
            build(&message, BOUNDARY).err(),
            Some(Fault::Header),
            "{name}"
        );
    }
    for value in ["a\r\nB: c", "a\nb", "ü", "a\0"] {
        let mut message = simple();
        message.headers = vec![("X-A".to_owned(), value.to_owned())];
        assert_eq!(
            build(&message, BOUNDARY).err(),
            Some(Fault::Header),
            "{value:?}"
        );
    }
    let mut message = simple();
    message.headers = vec![("X-A".to_owned(), "v".repeat(995))];
    assert_eq!(build(&message, BOUNDARY).err(), Some(Fault::Header));
    message.headers = vec![("X-Tag".to_owned(), "v1".to_owned())];
    assert!(build(&message, BOUNDARY).is_ok());
    assert_eq!(with(|m| m.text = None), Some(Fault::Body));
}

#[test]
fn refuses_bad_attachments_and_boundaries() {
    let file = |content_type: &str, filename: &str, id: Option<&str>| {
        let mut message = simple();
        message.attachments = vec![Attachment {
            filename: filename.to_owned(),
            content_type: content_type.to_owned(),
            data: Vec::new(),
            content_id: id.map(str::to_owned),
        }];
        build(&message, BOUNDARY).err()
    };
    for content_type in [
        "text",
        "text/",
        "/plain",
        "text/plain; charset=x",
        "a/b\r\nX: y",
        "a b/c",
    ] {
        assert_eq!(
            file(content_type, "a.txt", None),
            Some(Fault::ContentType),
            "{content_type:?}"
        );
    }
    for filename in ["", "a/b", "a\\b", "a\r\nb", "a\0", &"n".repeat(256)] {
        assert_eq!(
            file("text/plain", filename, None),
            Some(Fault::Filename),
            "{filename:?}"
        );
    }
    for id in ["noat", "<a@b", "a b@c", "<a@b>\r\nX: y", "@b"] {
        assert_eq!(
            file("image/png", "a.png", Some(id)),
            Some(Fault::ContentId),
            "{id:?}"
        );
    }
    assert!(file("image/png", "a.png", Some("a@b")).is_none());
    for boundary in [
        "short",
        "=_has space",
        "no_prefix_long",
        &format!("=_{}", "a".repeat(60)),
    ] {
        assert_eq!(
            build(&simple(), boundary).err(),
            Some(Fault::Body),
            "{boundary}"
        );
    }
}

fn random_text(rng: &mut Rng) -> String {
    let pieces = [
        "a",
        " ",
        "\n",
        "\r\n",
        "\r",
        "=",
        "=_b0undary7",
        "ü",
        "😀",
        "\t",
        ".",
        "--",
    ];
    let mut text = String::new();
    for _ in 0..rng.below(200) {
        if rng.below(30) == 0 {
            text.push_str(&"x".repeat(rng.below(1500)));
        } else {
            text.push_str(pieces[rng.below(pieces.len())]);
        }
    }
    text
}

#[test]
fn random_messages_read_back() {
    for mut rng in cases(400) {
        let attachments = (0..rng.below(4))
            .map(|i| Attachment {
                filename: format!("f{i}.bin"),
                content_type: "application/octet-stream".to_owned(),
                data: (0..rng.below(300))
                    .map(|_| u8::try_from(rng.below(256)).expect("byte"))
                    .collect(),
                content_id: (rng.below(2) == 0).then(|| format!("c{i}@x")),
            })
            .collect::<Vec<_>>();
        let text = (rng.below(3) > 0).then(|| random_text(&mut rng));
        let html = (text.is_none() || rng.below(2) == 0).then(|| random_text(&mut rng));
        let message = Message {
            subject: random_text(&mut rng).replace(['\r', '\n', '\t'], " "),
            text: text.clone(),
            html: html.clone(),
            attachments: attachments.clone(),
            ..simple()
        };
        let bytes = build(&message, BOUNDARY).expect("built");
        let (fields, leaves) = read(&bytes);
        let subject = field(&fields, "subject").map_or(String::new(), decode_words);
        let words: Vec<&str> = message.subject.split_whitespace().collect();
        assert_eq!(subject.split_whitespace().collect::<Vec<_>>(), words);
        let mut texts = leaves
            .iter()
            .filter(|l| l.content_type.starts_with("text/"));
        for original in [&text, &html].into_iter().flatten() {
            let expected = crlf(original);
            let expected = expected.strip_suffix(b"\r\n").unwrap_or(&expected);
            assert_eq!(texts.next().expect("text").data, expected);
        }
        let files: Vec<&Leaf> = leaves
            .iter()
            .filter(|l| !l.content_type.starts_with("text/"))
            .collect();
        assert_eq!(files.len(), attachments.len());
        for attachment in &attachments {
            assert!(files.iter().any(|f| f.data == attachment.data
                && f.id.as_deref().map(|i| i.trim_matches(['<', '>']))
                    == attachment.content_id.as_deref()));
        }
    }
}
