use crypto::DkimAlg;
use dkim::Template;

use crate::date::rfc5322;
use crate::header::{Checked, Fault};
use crate::mailbox::label_ok;

const WIDTH: usize = 78;
const DAY: u64 = 86_400;
const SIGNATURE_FLOOR: u64 = 7 * DAY;

pub struct Signer<'a> {
    pub key: u32,
    pub alg: DkimAlg,
    pub domain: &'a str,
    pub selector: &'a str,
}

pub struct Stamp<'a> {
    pub node: &'a str,
    pub id: &'a str,
    pub now: u64,
    pub lifetime: u64,
}

pub fn node_name(name: &str) -> bool {
    name.len() <= 255 && name.as_bytes().split(|&b| b == b'.').all(label_ok)
}

pub fn assemble(
    section: &[u8],
    checked: &Checked,
    stamp: &Stamp,
    signers: &[Signer],
    body: &[u8; 32],
) -> Result<Vec<u8>, Fault> {
    let date = rfc5322(stamp.now);
    let mut client = section.to_vec();
    if !checked.date {
        client.extend_from_slice(format!("Date: {date}\r\n").as_bytes());
    }
    if !checked.message_id {
        let id = format!("Message-ID: <{}@{}>\r\n", stamp.id, checked.from);
        client.extend_from_slice(id.as_bytes());
    }
    let fields = dkim::parse(&client).map_err(|_| Fault::Malformed)?;
    let time = stamp.now / 1000;
    let expiry = time + (stamp.lifetime / 1000 + DAY).max(SIGNATURE_FLOOR);
    let mut out = fold(&format!(
        "Received: by {} with ESMTPSA id {};",
        stamp.node, stamp.id
    ));
    out.extend_from_slice(format!(" {date}\r\n").as_bytes());
    for signer in signers {
        let template = Template {
            alg: signer.alg,
            domain: signer.domain,
            selector: signer.selector,
            time,
            expiry,
        };
        let field = dkim::unsigned(&template, &fields, body).map_err(|_| Fault::Signer)?;
        out.extend_from_slice(&field);
    }
    out.extend_from_slice(&client);
    Ok(out)
}

fn fold(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 8);
    let mut line = 0;
    for (n, word) in text.split(' ').enumerate() {
        if n > 0 {
            if line + 1 + word.len() > WIDTH {
                out.extend_from_slice(b"\r\n");
                line = 0;
            }
            out.push(b' ');
            line += 1;
        }
        out.extend_from_slice(word.as_bytes());
        line += word.len();
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use dkim::{BodyHash, Field};

    use super::*;
    use crate::header::check;

    const NOW: u64 = 1_794_478_400_123;

    fn body_hash(body: &[u8]) -> [u8; 32] {
        let mut hash = BodyHash::new();
        hash.update(body);
        hash.finish()
    }

    fn stamp() -> Stamp<'static> {
        Stamp {
            node: "mx1.example.net",
            id: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            now: NOW,
            lifetime: 10 * DAY * 1000,
        }
    }

    fn signers() -> [Signer<'static>; 2] {
        [
            Signer {
                key: 3,
                alg: DkimAlg::RsaSha256,
                domain: "example.org",
                selector: "r1",
            },
            Signer {
                key: 4,
                alg: DkimAlg::Ed25519Sha256,
                domain: "example.org",
                selector: "e1",
            },
        ]
    }

    fn built(section: &str) -> Vec<u8> {
        let checked = check(section.as_bytes()).expect("check");
        assemble(
            section.as_bytes(),
            &checked,
            &stamp(),
            &signers(),
            &body_hash(b"hi\r\n"),
        )
        .expect("assemble")
    }

    fn names(fields: &[Field<'_>]) -> Vec<String> {
        fields
            .iter()
            .map(|f| String::from_utf8_lossy(f.name()).to_ascii_lowercase())
            .collect()
    }

    #[test]
    fn adds_fields_in_order() {
        let out = built("From: Ann <a@mail.example.org>\r\nSubject: hi\r\n");
        let fields = dkim::parse(&out).expect("parse");
        assert_eq!(
            names(&fields),
            [
                "received",
                "dkim-signature",
                "dkim-signature",
                "from",
                "subject",
                "date",
                "message-id"
            ]
        );
        let text = String::from_utf8(out.clone()).expect("ascii");
        assert!(text.starts_with(
            "Received: by mx1.example.net with ESMTPSA id ABCDEFGHIJKLMNOPQRSTUVWXYZ;\r\n Thu, 12 Nov 2026 10:13:20 +0000\r\n"
        ));
        assert!(text.ends_with(
            "Date: Thu, 12 Nov 2026 10:13:20 +0000\r\nMessage-ID: <ABCDEFGHIJKLMNOPQRSTUVWXYZ@mail.example.org>\r\n"
        ));
        assert!(
            out.split(|&b| b == b'\n')
                .all(|line| line.len() <= WIDTH + 1)
        );
    }

    #[test]
    fn keeps_the_client_date_and_message_id() {
        let section = "Date: x\r\nMessage-ID: <m@a>\r\nFrom: a@example.org\r\n";
        let out = built(section);
        assert!(out.ends_with(section.as_bytes()));
        let fields = dkim::parse(&out).expect("parse");
        assert_eq!(fields.iter().filter(|f| f.is("date")).count(), 1);
    }

    #[test]
    fn signature_fields_verify_and_cover_added_fields() {
        let out = built("From: a@example.org\r\nSubject: hi\r\n");
        let fields = dkim::parse(&out).expect("parse");
        for (at, alg) in [(1, DkimAlg::RsaSha256), (2, DkimAlg::Ed25519Sha256)] {
            let raw = fields[at].raw();
            let text = String::from_utf8_lossy(raw).replace("\r\n", "");
            let tight: String = text.split_whitespace().collect();
            assert!(text.contains(" d=example.org;"), "{text}");
            assert!(text.contains(&format!(" t={};", NOW / 1000)), "{text}");
            assert!(
                text.contains(&format!(" x={};", NOW / 1000 + 11 * DAY)),
                "{text}"
            );
            assert!(
                tight.contains("date:date:") && tight.contains("message-id:message-id:"),
                "{tight}"
            );
            dkim::digest(&fields, at).expect("digest");
            let signed = dkim::signed(raw, &[7; 64]).expect("signed");
            let section = [
                &out[..fields[at].raw().as_ptr() as usize - out.as_ptr() as usize],
                &signed,
            ]
            .concat();
            let fields = dkim::parse(&section).expect("parse");
            let found = dkim::check(&fields, at, &body_hash(b"hi\r\n")).expect("check");
            assert_eq!(found.alg, alg);
        }
    }

    #[test]
    fn short_lifetimes_keep_seven_days() {
        let section = "From: a@example.org\r\n";
        let checked = check(section.as_bytes()).expect("check");
        let short = Stamp {
            lifetime: 3_600_000,
            ..stamp()
        };
        let out = assemble(
            section.as_bytes(),
            &checked,
            &short,
            &signers()[..1],
            &[0; 32],
        )
        .expect("assemble");
        let text = String::from_utf8(out).expect("ascii").replace("\r\n", "");
        assert!(
            text.contains(&format!(" x={};", NOW / 1000 + 7 * DAY)),
            "{text}"
        );
    }

    #[test]
    fn checks_node_names() {
        assert!(node_name("mx1.example.net"));
        assert!(node_name("localhost"));
        for bad in ["", "a..b", "-a.b", "a b", "a.b.", "\u{e9}.b"] {
            assert!(!node_name(bad), "{bad}");
        }
    }
}
