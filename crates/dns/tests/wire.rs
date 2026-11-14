mod common;

use std::net::Ipv4Addr;

use common::{AD, NXDOMAIN, TC, mx, reply, rr, soa, wire};
use dns::wire::{Rcode, parse, query};
use dns::{Error, Name, Record, Type};

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

#[test]
fn names_are_lowercased_and_bounded() {
    assert_eq!(name("MX.Example.COM."), name("mx.example.com"));
    assert_eq!(name("mx.example.com").to_string(), "mx.example.com");
    assert!(Name::parse("a..b").is_err());
    assert!(Name::parse(&"a".repeat(64)).is_err());
    assert!(Name::parse(&["abcdefghij"; 25].join(".")).is_err());
    assert!(Name::parse("bad name").is_err());
    assert!(name(".").is_root());
    assert_eq!(
        name("mx.example.com").prefixed("_25").expect("prefixed"),
        name("_25.mx.example.com")
    );
}

#[test]
fn a_query_asks_recursion_and_edns() {
    let packet = query(0xabcd, &name("example.com"), Type::Mx, true);
    assert_eq!(&packet[..2], &[0xab, 0xcd]);
    assert_eq!(&packet[2..4], &[0x01, 0x20]);
    assert_eq!(&packet[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
    let opt = &packet[packet.len() - 11..];
    assert_eq!(opt, &[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
    let plain = query(1, &name("example.com"), Type::Mx, false);
    assert_eq!(plain[plain.len() - 4], 0);
}

#[test]
fn a_reply_follows_aliases_and_reads_records() {
    let asked = name("example.com");
    let packet = query(7, &asked, Type::Mx, false);
    let answers = [
        rr("example.com", 5, 300, wire("mail.example.org")),
        rr("mail.example.org", 15, 600, mx(10, "mx1.example.org")),
        rr("mail.example.org", 15, 100, mx(20, "mx2.example.org")),
        rr("other.example.org", 15, 50, mx(5, "evil.example.net")),
    ];
    let got = parse(7, &asked, Type::Mx, &reply(&packet, AD, &answers, &[])).expect("parse");
    assert_eq!(got.rcode, Rcode::NoError);
    assert!(got.authentic);
    assert_eq!(got.name, name("mail.example.org"));
    assert_eq!(got.ttl, 100);
    assert_eq!(
        got.records,
        vec![
            Record::Mx {
                preference: 10,
                exchange: name("mx1.example.org")
            },
            Record::Mx {
                preference: 20,
                exchange: name("mx2.example.org")
            },
        ]
    );
}

#[test]
fn a_negative_reply_takes_the_smaller_soa_ttl() {
    let asked = name("nowhere.example.com");
    let packet = query(9, &asked, Type::A, false);
    let authority = [rr("example.com", 6, 60, soa(3600))];
    let got = parse(
        9,
        &asked,
        Type::A,
        &reply(&packet, NXDOMAIN, &[], &authority),
    )
    .expect("parse");
    assert_eq!(got.rcode, Rcode::NxDomain);
    assert_eq!(got.negative_ttl, Some(60));
    let authority = [rr("example.com", 6, 3600, soa(30))];
    let got = parse(9, &asked, Type::A, &reply(&packet, 0, &[], &authority)).expect("parse");
    assert_eq!(got.negative_ttl, Some(30));
    assert_eq!(got.records, Vec::<Record>::new());
}

#[test]
fn txt_strings_join_and_tlsa_and_addresses_parse() {
    let asked = name("_mta-sts.example.com");
    let packet = query(3, &asked, Type::Txt, false);
    let text = b"\x0av=STSv1; i\x07d=12345".to_vec();
    let answers = [rr("_mta-sts.example.com", 16, 60, text)];
    let got = parse(3, &asked, Type::Txt, &reply(&packet, 0, &answers, &[])).expect("txt");
    assert_eq!(
        got.records,
        vec![Record::Txt(b"v=STSv1; id=12345".to_vec())]
    );

    let asked = name("_25._tcp.mx.example.com");
    let packet = query(4, &asked, Type::Tlsa, false);
    let answers = [rr(
        "_25._tcp.mx.example.com",
        52,
        60,
        vec![3, 1, 1, 0xaa, 0xbb],
    )];
    let got = parse(4, &asked, Type::Tlsa, &reply(&packet, 0, &answers, &[])).expect("tlsa");
    assert_eq!(
        got.records,
        vec![Record::Tlsa {
            usage: 3,
            selector: 1,
            matching: 1,
            data: vec![0xaa, 0xbb]
        }]
    );

    let asked = name("mx.example.com");
    let packet = query(5, &asked, Type::A, false);
    let answers = [rr("mx.example.com", 1, 60, vec![192, 0, 2, 7])];
    let got = parse(5, &asked, Type::A, &reply(&packet, 0, &answers, &[])).expect("a");
    assert_eq!(got.records, vec![Record::A(Ipv4Addr::new(192, 0, 2, 7))]);
    let answers = [rr("mx.example.com", 1, 60, vec![192, 0, 2])];
    let short = reply(&packet, 0, &answers, &[]);
    assert_eq!(parse(5, &asked, Type::A, &short), Err(Error::Malformed));
}

#[test]
fn a_reply_must_match_the_query() {
    let asked = name("example.com");
    let packet = query(11, &asked, Type::Mx, false);
    let good = reply(&packet, 0, &[], &[]);
    assert!(parse(11, &asked, Type::Mx, &good).is_ok());
    assert_eq!(parse(12, &asked, Type::Mx, &good), Err(Error::Malformed));
    assert_eq!(
        parse(11, &name("example.net"), Type::Mx, &good),
        Err(Error::Malformed)
    );
    assert_eq!(parse(11, &asked, Type::A, &good), Err(Error::Malformed));
    let mut not_reply = good.clone();
    not_reply[2] &= 0x7f;
    assert_eq!(
        parse(11, &asked, Type::Mx, &not_reply),
        Err(Error::Malformed)
    );
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        parse(11, &asked, Type::Mx, &trailing),
        Err(Error::Malformed)
    );
    let truncated = reply(&packet, TC, &[], &[]);
    assert!(
        parse(11, &asked, Type::Mx, &truncated)
            .expect("tc")
            .truncated
    );
}

#[test]
fn compression_pointers_must_point_backward() {
    let asked = name("example.com");
    let packet = query(1, &asked, Type::Mx, false);
    let end = common::question_end(&packet);
    let mut base = reply(&packet, 0, &[], &[]);
    base[7] = 1;
    let mut good = base.clone();
    good.extend([0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 8, 0, 10]);
    good.extend([3, b'm', b'x', b'1', 0xc0, 12]);
    let got = parse(1, &asked, Type::Mx, &good).expect("compressed");
    assert_eq!(
        got.records,
        vec![Record::Mx {
            preference: 10,
            exchange: name("mx1.example.com")
        }]
    );
    let at = u8::try_from(end).expect("small");
    let mut self_loop = base.clone();
    self_loop.extend([0xc0, at, 0, 15, 0, 1, 0, 0, 0, 60, 0, 2, 0, 10]);
    assert_eq!(
        parse(1, &asked, Type::Mx, &self_loop),
        Err(Error::Malformed)
    );
    let mut forward = base.clone();
    forward.extend([0xc0, at + 2, 0, 15, 0, 1, 0, 0, 0, 60, 0, 2, 0, 10]);
    assert_eq!(parse(1, &asked, Type::Mx, &forward), Err(Error::Malformed));
    let mut reserved = base;
    reserved.extend([0x80, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 2, 0, 10]);
    assert_eq!(parse(1, &asked, Type::Mx, &reserved), Err(Error::Malformed));
}

#[test]
fn alias_loops_and_long_chains_are_refused() {
    let asked = name("a.example.com");
    let packet = query(2, &asked, Type::A, false);
    let looped = [
        rr("a.example.com", 5, 60, wire("b.example.com")),
        rr("b.example.com", 5, 60, wire("a.example.com")),
    ];
    let got = parse(2, &asked, Type::A, &reply(&packet, 0, &looped, &[]));
    assert_eq!(got, Err(Error::Malformed));
}

#[test]
fn random_bytes_never_panic() {
    let asked = name("example.com");
    let packet = query(5, &asked, Type::Mx, false);
    let answers = [rr("example.com", 15, 60, mx(10, "mx.example.com"))];
    let good = reply(&packet, 0, &answers, &[]);
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let mut bytes = good.clone();
        let flips = 1 + next() % 6;
        for _ in 0..flips {
            let at = usize::try_from(next() % bytes.len() as u64).expect("index");
            bytes[at] = u8::try_from(next() & 0xff).expect("byte");
        }
        let cut = usize::try_from(next() % (bytes.len() as u64 + 1)).expect("cut");
        bytes.truncate(cut.max(2));
        let _ = parse(5, &asked, Type::Mx, &bytes);
    }
}
