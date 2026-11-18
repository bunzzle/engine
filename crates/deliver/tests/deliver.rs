mod common;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

use common::{Script, Seen, Zone, policy, serve, serve_policy};
use control::Leases;
use deliver::{
    Applied, Applies, Deliver, Detail, EightBit, Message, Outcome, Remote, ResultType, Settings,
    Taken, limits,
};
use dns::{Found, Name, Record, Type};
use rt::sim::{Config, SimDriver};
use rt::{Mesh, Runtime, now, sleep, spawn};
use sched::{
    Answer, Body, Destination, Done, Envelope, Kind, Recipient, Records as Saving, Required,
    Restore, Saved, Transport,
};
use tls::{Connector, simulated};

const EGRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const EGRESS2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const MX1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
const MX2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
const WEB: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
const ROOTS: &[u8] = include_bytes!("data/ca.pem");
const LEAF: &str = "b144595e51e3ade2a723db0ddb2b560ba510fd1da2d9246d45b4618481d8bb01";
const ROOT: &str = "86ee2f95596152cea98375f669a6e13a72a7de0671efcc61dcde8b5d501e8bc1";
const ENFORCE: &str = "version: STSv1\nmode: enforce\nmx: mx2.example.com\nmax_age: 86400\n";
const HEADER: &[u8] = b"Received: from a\r\nSubject: hi\r\n";
const TEMPORARY: Answer = Answer::Deferred(Kind::Temporary);

type Records = &'static [(u8, u8, u8, &'static str)];

fn run<T: 'static>(future: impl Future<Output = T> + 'static) -> T {
    let driver = Rc::new(SimDriver::new(7, Config::default()));
    Runtime::new(driver).block_on(future)
}

fn mx(records: &[(u16, &str)]) -> Found {
    Found::Records(
        records
            .iter()
            .map(|(preference, name)| Record::Mx {
                preference: *preference,
                exchange: Name::parse(name).expect("name"),
            })
            .collect(),
    )
}

fn a(ips: &[IpAddr]) -> Found {
    Found::Records(
        ips.iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => Record::A(*v4),
                IpAddr::V6(v6) => Record::Aaaa(*v6),
            })
            .collect(),
    )
}

fn zone() -> Zone {
    let zone = Zone::default();
    zone.set(
        "example.com",
        Type::Mx,
        mx(&[(20, "mx2.example.com"), (10, "mx1.example.com")]),
    );
    zone.set("mx1.example.com", Type::A, a(&[MX1]));
    zone.set("mx2.example.com", Type::A, a(&[MX2]));
    zone
}

fn deliverer(zone: Zone, settings: Settings) -> Deliver<Zone> {
    limited(zone, settings, None)
}

fn limited(zone: Zone, settings: Settings, leases: Option<Leases<Remote>>) -> Deliver<Zone> {
    let connector = Connector::new(simulated(2), None).expect("connector");
    Deliver::new(zone, connector, settings, leases, 9).expect("deliver")
}

fn verifying(zone: Zone, settings: Settings) -> Deliver<Zone> {
    let connector = Connector::new(simulated(2), Some(ROOTS)).expect("connector");
    Deliver::new(zone, connector, settings, None, 9).expect("deliver")
}

fn signed(only: bool) -> Zone {
    let zone = zone();
    if only {
        zone.set("example.com", Type::Mx, mx(&[(10, "mx1.example.com")]));
    }
    zone.sign("example.com", Type::Mx);
    zone.sign("mx1.example.com", Type::A);
    zone.sign("mx2.example.com", Type::A);
    zone
}

fn tlsa(zone: &Zone, host: &str, records: &[(u8, u8, u8, &str)]) {
    let name = format!("_25._tcp.{host}");
    let records = records
        .iter()
        .map(|(usage, selector, matching, data)| Record::Tlsa {
            usage: *usage,
            selector: *selector,
            matching: *matching,
            data: (0..data.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&data[i..i + 2], 16).expect("hex"))
                .collect(),
        })
        .collect();
    zone.set(&name, Type::Tlsa, Found::Records(records));
    zone.sign(&name, Type::Tlsa);
}

fn sts(zone: &Zone, id: &str) {
    zone.set(
        "_mta-sts.example.com",
        Type::Txt,
        Found::Records(vec![Record::Txt(format!("v=STSv1; id={id}").into_bytes())]),
    );
    zone.set("mta-sts.example.com", Type::A, a(&[WEB]));
}

fn strict() -> Settings {
    let mut settings = settings();
    settings.mta_sts = true;
    settings
}

fn mailed(seen: &Rc<RefCell<Seen>>) -> bool {
    commands(seen).iter().any(|c| c.starts_with("MAIL"))
}

fn settings() -> Settings {
    Settings::new("out.sender.example")
}

fn envelope() -> Envelope {
    Envelope {
        sender: "bounce@sender.example".into(),
        ..Envelope::default()
    }
}

fn destination(domain: &str) -> Destination {
    Destination {
        domain: domain.into(),
        pool: 1,
        egress: vec![(EGRESS, 1)],
    }
}

async fn send(
    deliver: &Deliver<Zone>,
    envelope: &Envelope,
    destination: &Destination,
    addresses: &[&str],
    body: &[u8],
) -> Vec<Outcome> {
    let recipients: Vec<(u32, Recipient)> = (1..)
        .step_by(2)
        .zip(addresses)
        .map(|(index, address)| {
            let recipient = Recipient {
                address: (*address).to_owned(),
                ..Recipient::default()
            };
            (index, recipient)
        })
        .collect();
    let mut body = Body::Inline(body.to_vec());
    let message = Message {
        envelope,
        recipients: &recipients,
        header: HEADER,
        body: &mut body,
        size: 100,
    };
    deliver.deliver(destination, message).await
}

async fn simple(deliver: &Deliver<Zone>, domain: &str) -> Vec<Outcome> {
    send(
        deliver,
        &envelope(),
        &destination(domain),
        &["a@example.com"],
        b"hello\r\n",
    )
    .await
}

fn answers(outcomes: &[Outcome]) -> Vec<Answer> {
    outcomes.iter().map(|o| o.answer).collect()
}

fn reply(outcome: &Outcome) -> String {
    String::from_utf8_lossy(&outcome.reply).into_owned()
}

fn commands(seen: &Rc<RefCell<Seen>>) -> Vec<String> {
    seen.borrow().commands.clone()
}

#[test]
fn delivers_with_pipelining() {
    let (outcomes, seen) = run(async {
        let seen = serve(
            MX1,
            Script::new(&["PIPELINING", "8BITMIME", "SIZE 1000000"]),
        );
        let deliver = deliverer(zone(), settings());
        let outcomes = send(
            &deliver,
            &envelope(),
            &destination("example.com"),
            &["a@example.com", "b@example.com"],
            b".dot\r\nline\r\n",
        )
        .await;
        (outcomes, seen)
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered, Answer::Delivered]);
    assert_eq!(
        outcomes.iter().map(|o| o.recipient).collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(reply(&outcomes[0]), "250 2.0.0 queued");
    assert_eq!(
        commands(&seen),
        [
            "EHLO out.sender.example",
            "MAIL FROM:<bounce@sender.example> SIZE=100",
            "RCPT TO:<a@example.com>",
            "RCPT TO:<b@example.com>",
            "DATA",
        ]
    );
    assert_eq!(
        seen.borrow().bodies,
        [b"Received: from a\r\nSubject: hi\r\n\r\n..dot\r\nline\r\n".to_vec()]
    );
}

#[test]
fn starts_tls_when_offered() {
    let (outcomes, seen) = run(async {
        let seen = serve(MX1, Script::new(&["STARTTLS", "PIPELINING"]));
        let deliver = deliverer(zone(), settings());
        (simple(&deliver, "example.com").await, seen)
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered]);
    assert!(seen.borrow().tls);
    assert_eq!(
        commands(&seen)[..3],
        [
            "EHLO out.sender.example",
            "STARTTLS",
            "EHLO out.sender.example"
        ]
    );
}

#[test]
fn refuses_bytes_sent_ahead_of_tls() {
    let (outcomes, seen) = run(async {
        let mut script = Script::new(&["STARTTLS"]);
        script.inject = true;
        let seen = serve(MX1, script);
        let deliver = deliverer(zone(), settings());
        (simple(&deliver, "example.com").await, seen)
    });
    assert_eq!(answers(&outcomes), [TEMPORARY]);
    assert!(!seen.borrow().tls);
    assert_eq!(commands(&seen), ["EHLO out.sender.example", "STARTTLS"]);
}

#[test]
fn answers_each_recipient() {
    let (outcomes, seen) = run(async {
        let mut script = Script::new(&["ENHANCEDSTATUSCODES"]);
        script.rcpt = Rc::new(|address| {
            match address.split('@').next().unwrap_or_default() {
                "gone" => "550 5.1.1 no such user",
                "grey" => "450 4.7.1 greylisted, try later",
                "full" => "452 4.2.2 mailbox full",
                "slow" => "451 4.3.0 local error",
                _ => "250 2.1.5 ok",
            }
            .to_owned()
        });
        let seen = serve(MX1, script);
        let deliver = deliverer(zone(), settings());
        let outcomes = send(
            &deliver,
            &envelope(),
            &destination("example.com"),
            &[
                "ok@example.com",
                "gone@example.com",
                "grey@example.com",
                "full@example.com",
                "slow@example.com",
            ],
            b"hello\r\n",
        )
        .await;
        (outcomes, seen)
    });
    assert_eq!(
        answers(&outcomes),
        [
            Answer::Delivered,
            Answer::Failed,
            Answer::Deferred(Kind::Greylisted),
            Answer::Deferred(Kind::MailboxFull),
            TEMPORARY,
        ]
    );
    assert_eq!(reply(&outcomes[1]), "550 5.1.1 no such user");
    assert_eq!(seen.borrow().bodies.len(), 1);
}

#[test]
fn recipients_over_the_limit_come_later() {
    let outcomes = run(async {
        let mut script = Script::new(&["PIPELINING", "ENHANCEDSTATUSCODES"]);
        let count = Cell::new(0);
        script.rcpt = Rc::new(move |_| {
            count.set(count.get() + 1);
            if count.get() > 2 {
                "452 4.5.3 too many recipients".to_owned()
            } else {
                "250 2.1.5 ok".to_owned()
            }
        });
        serve(MX1, script);
        let deliver = deliverer(zone(), settings());
        send(
            &deliver,
            &envelope(),
            &destination("example.com"),
            &["a@example.com", "b@example.com", "c@example.com"],
            b"hello\r\n",
        )
        .await
    });
    assert_eq!(
        answers(&outcomes),
        [Answer::Delivered, Answer::Delivered, Answer::Later(0)]
    );
}

#[test]
fn too_many_with_nothing_sent_defers() {
    let outcomes = run(async {
        let mut script = Script::new(&["PIPELINING", "ENHANCEDSTATUSCODES"]);
        script.rcpt = Rc::new(|_| "452 4.5.3 too many recipients".to_owned());
        serve(MX1, script);
        let deliver = deliverer(zone(), settings());
        simple(&deliver, "example.com").await
    });
    assert_eq!(answers(&outcomes), [TEMPORARY]);
}

#[test]
fn transaction_replies_answer_everyone() {
    let cases = [
        (
            "550 5.7.1 sender blocked",
            "250 2.0.0 queued",
            Answer::Failed,
        ),
        ("250 2.1.0 ok", "554 5.7.1 spam", Answer::Failed),
        ("250 2.1.0 ok", "451 4.3.0 try later", TEMPORARY),
    ];
    for (mail, done, want) in cases {
        let outcomes = run(async move {
            let mut script = Script::new(&["PIPELINING", "ENHANCEDSTATUSCODES"]);
            script.mail = mail;
            script.done = done;
            serve(MX1, script);
            let deliver = deliverer(zone(), settings());
            send(
                &deliver,
                &envelope(),
                &destination("example.com"),
                &["a@example.com", "b@example.com"],
                b"hello\r\n",
            )
            .await
        });
        assert_eq!(answers(&outcomes), [want, want], "{mail} / {done}");
    }
}

#[test]
fn tries_hosts_in_preference_order() {
    let (outcomes, first, second) = run(async {
        let first = serve(MX1, Script::new(&[]));
        let second = serve(MX2, Script::new(&[]));
        let deliver = deliverer(zone(), settings());
        (simple(&deliver, "example.com").await, first, second)
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered]);
    assert_eq!(first.borrow().connections, 1);
    assert_eq!(second.borrow().connections, 0);
}

#[test]
fn falls_back_to_the_next_host() {
    let banners = ["", "421 4.3.2 busy", "554 5.7.1 go away"];
    for banner in banners {
        let (outcomes, second) = run(async move {
            if !banner.is_empty() {
                let mut script = Script::new(&[]);
                script.banner = banner;
                serve(MX1, script);
            }
            let second = serve(MX2, Script::new(&[]));
            let deliver = deliverer(zone(), settings());
            (simple(&deliver, "example.com").await, second)
        });
        assert_eq!(answers(&outcomes), [Answer::Delivered], "{banner}");
        assert_eq!(second.borrow().connections, 1, "{banner}");
    }
}

#[test]
fn no_reachable_host_defers() {
    let outcomes = run(async {
        let mut script = Script::new(&[]);
        script.banner = "421 4.3.2 busy";
        serve(MX2, script);
        let deliver = deliverer(zone(), settings());
        simple(&deliver, "example.com").await
    });
    assert_eq!(answers(&outcomes), [TEMPORARY]);
    assert_eq!(reply(&outcomes[0]), "421 4.3.2 busy");
}

type Case = (
    &'static str,
    Option<Found>,
    Option<Option<Found>>,
    Answer,
    &'static str,
);

fn record(zone: &Zone, name: &str, kind: Type, found: Option<Found>) {
    match found {
        Some(found) => zone.set(name, kind, found),
        None => zone.fail(name, kind),
    }
}

#[test]
fn answers_from_dns() {
    let cases: [Case; 7] = [
        (
            "missing.test",
            Some(Found::NxDomain),
            None,
            Answer::Failed,
            "550 5.1.2",
        ),
        (
            "null.test",
            Some(mx(&[(0, ".")])),
            None,
            Answer::Failed,
            "556 5.1.10",
        ),
        ("broken.test", None, None, TEMPORARY, "451 4.4.3 MX"),
        (
            "implicit.test",
            Some(Found::NoData),
            Some(Some(a(&[MX1]))),
            Answer::Delivered,
            "250",
        ),
        (
            "mixed.test",
            Some(mx(&[(0, "."), (10, "mx.mixed.test")])),
            Some(Some(a(&[MX1]))),
            Answer::Delivered,
            "250",
        ),
        (
            "nohost.test",
            Some(mx(&[(10, "mx.nohost.test")])),
            Some(Some(Found::NoData)),
            TEMPORARY,
            "451 4.4.4",
        ),
        (
            "hostfail.test",
            Some(mx(&[(10, "mx.hostfail.test")])),
            Some(None),
            TEMPORARY,
            "451 4.4.3 Mail",
        ),
    ];
    for (domain, records, host, want, text) in cases {
        let outcomes = run(async move {
            serve(MX1, Script::new(&[]));
            let zone = Zone::default();
            record(&zone, domain, Type::Mx, records);
            if let Some(host) = host {
                let name = if domain == "implicit.test" {
                    domain.to_owned()
                } else {
                    format!("mx.{domain}")
                };
                record(&zone, &name, Type::A, host);
            }
            let deliver = deliverer(zone, settings());
            simple(&deliver, domain).await
        });
        assert_eq!(answers(&outcomes), [want], "{domain}");
        assert!(
            reply(&outcomes[0]).starts_with(text),
            "{domain}: {}",
            reply(&outcomes[0])
        );
    }
}

#[test]
fn skips_literal_and_local_addresses() {
    let outcomes = run(async {
        let zone = Zone::default();
        zone.set(
            "example.com",
            Type::Mx,
            mx(&[(10, "192.0.2.1"), (20, "mx.example.com")]),
        );
        zone.set(
            "mx.example.com",
            Type::A,
            a(&[IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        );
        let asked = Rc::clone(&zone.asked);
        let deliver = deliverer(zone, settings());
        let outcomes = simple(&deliver, "example.com").await;
        assert_eq!(asked.borrow().len(), 2);
        outcomes
    });
    assert_eq!(answers(&outcomes), [TEMPORARY]);
    assert!(reply(&outcomes[0]).starts_with("451 4.4.4"));
}

#[test]
fn checks_what_the_message_needs() {
    let utf8 = Envelope {
        required: Required {
            smtputf8: true,
            requiretls: false,
        },
        ..envelope()
    };
    let tls = Envelope {
        required: Required {
            smtputf8: false,
            requiretls: true,
        },
        ..envelope()
    };
    let eight = Envelope {
        eight_bit: true,
        ..envelope()
    };
    let mut strict = settings();
    strict.eight_bit = EightBit::Fail;
    let cases = [
        (utf8, settings(), "8BITMIME", Answer::Failed, "553 5.6.7"),
        (tls, settings(), "8BITMIME", Answer::Failed, "550 5.7.30"),
        (
            eight.clone(),
            strict,
            "PIPELINING",
            Answer::Failed,
            "554 5.6.3",
        ),
        (eight, settings(), "PIPELINING", Answer::Delivered, "250"),
        (
            envelope(),
            settings(),
            "SIZE 50",
            Answer::Failed,
            "552 5.3.4",
        ),
    ];
    for (envelope, settings, extension, want, text) in cases {
        let (outcomes, seen) = run(async move {
            let seen = serve(MX1, Script::new(&[extension]));
            let deliver = deliverer(zone(), settings);
            let outcomes = send(
                &deliver,
                &envelope,
                &destination("example.com"),
                &["a@example.com"],
                b"hello\r\n",
            )
            .await;
            (outcomes, seen)
        });
        assert_eq!(answers(&outcomes), [want], "{text}");
        assert!(reply(&outcomes[0]).starts_with(text), "{text}");
        let commands = commands(&seen);
        assert!(!commands.iter().any(|c| c.contains("BODY=")), "{text}");
        if want == Answer::Failed {
            assert!(!commands.iter().any(|c| c.starts_with("MAIL")), "{text}");
        }
    }
}

#[test]
fn falls_back_to_helo() {
    let (outcomes, seen) = run(async {
        let mut script = Script::new(&[]);
        script.ehlo = "502 5.5.1 not here".to_owned();
        let seen = serve(MX1, script);
        let deliver = deliverer(zone(), settings());
        (simple(&deliver, "example.com").await, seen)
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered]);
    assert_eq!(
        commands(&seen)[..3],
        [
            "EHLO out.sender.example",
            "HELO out.sender.example",
            "MAIL FROM:<bounce@sender.example>"
        ]
    );
}

#[test]
fn deadline_bounds_the_attempt() {
    let (outcomes, elapsed, seen) = run(async {
        let mut script = Script::new(&["PIPELINING"]);
        script.done = "";
        let seen = serve(MX1, script);
        let mut settings = settings();
        settings.deadline = Duration::from_secs(20);
        let deliver = deliverer(zone(), settings);
        let start = now();
        let outcomes = simple(&deliver, "example.com").await;
        (outcomes, now().saturating_duration_since(start), seen)
    });
    assert_eq!(answers(&outcomes), [TEMPORARY]);
    assert_eq!(reply(&outcomes[0]), "451 4.4.2 Timed out");
    assert!(elapsed >= Duration::from_secs(20), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(21), "{elapsed:?}");
    assert_eq!(seen.borrow().bodies.len(), 1);
}

#[test]
fn no_egress_defers_without_lookups() {
    let (outcomes, asked) = run(async {
        let zone = zone();
        let asked = Rc::clone(&zone.asked);
        let deliver = deliverer(zone, settings());
        let mut destination = destination("example.com");
        destination.egress.clear();
        let outcomes = send(
            &deliver,
            &envelope(),
            &destination,
            &["a@example.com"],
            b"hello\r\n",
        )
        .await;
        (outcomes, asked)
    });
    assert_eq!(answers(&outcomes), [TEMPORARY]);
    assert!(asked.borrow().is_empty());
}

#[test]
fn reuses_an_idle_connection() {
    let (seen, pooled) = run(async {
        let seen = serve(MX1, Script::new(&["PIPELINING"]));
        let deliver = deliverer(zone(), settings());
        for _ in 0..2 {
            let outcomes = simple(&deliver, "example.com").await;
            assert_eq!(answers(&outcomes), [Answer::Delivered]);
        }
        assert_eq!(deliver.pooled(), 1);
        sleep(Duration::from_secs(6)).await;
        (seen, deliver.pooled())
    });
    assert_eq!(pooled, 0);
    assert_eq!(seen.borrow().connections, 1);
    let commands = commands(&seen);
    assert_eq!(commands.iter().filter(|c| *c == "RSET").count(), 1);
    assert_eq!(commands.last().map(String::as_str), Some("QUIT"));
}

#[test]
fn retires_a_connection_after_its_transactions() {
    let seen = run(async {
        let seen = serve(MX1, Script::new(&[]));
        let mut settings = settings();
        settings.reuse = 2;
        let deliver = deliverer(zone(), settings);
        for _ in 0..3 {
            let outcomes = simple(&deliver, "example.com").await;
            assert_eq!(answers(&outcomes), [Answer::Delivered]);
        }
        seen
    });
    assert_eq!(seen.borrow().connections, 2);
}

#[test]
fn skips_a_dead_host_for_a_while() {
    let (skipped, later, second) = run(async {
        let second = serve(MX2, Script::new(&[]));
        let mut settings = settings();
        settings.pooled = 0;
        let deliver = deliverer(zone(), settings);
        let outcomes = simple(&deliver, "example.com").await;
        assert_eq!(answers(&outcomes), [Answer::Delivered]);
        assert_eq!(deliver.dead_hosts(), 1);
        let first = serve(MX1, Script::new(&[]));
        let outcomes = simple(&deliver, "example.com").await;
        assert_eq!(answers(&outcomes), [Answer::Delivered]);
        let skipped = first.borrow().connections;
        sleep(Duration::from_secs(61)).await;
        let outcomes = simple(&deliver, "example.com").await;
        assert_eq!(answers(&outcomes), [Answer::Delivered]);
        let later = first.borrow().connections;
        (skipped, later, second.borrow().connections)
    });
    assert_eq!((skipped, later, second), (0, 1, 2));
}

#[test]
fn waits_for_a_free_connection() {
    let (busy, waited, freed) = run(async {
        let script = Script::new(&["PIPELINING"]);
        script.stalls.set(1);
        serve(MX1, script);
        let mesh = Mesh::new(1);
        let (leases, _done) = limits(mesh.take(0).expect("ends"), 1, [7; 16]);
        let mut settings = settings();
        settings.deadline = Duration::from_secs(20);
        settings.wait = Duration::from_secs(1);
        let deliver = Rc::new(limited(zone(), settings, Some(leases)));
        let stuck = Rc::clone(&deliver);
        let first = spawn(async move { simple(&stuck, "example.com").await });
        sleep(Duration::from_millis(100)).await;
        let start = now();
        let busy = simple(&deliver, "example.com").await;
        let waited = now().saturating_duration_since(start);
        assert_eq!(answers(&first.await), [TEMPORARY]);
        let freed = simple(&deliver, "example.com").await;
        (busy, waited, freed)
    });
    assert_eq!(answers(&busy), [Answer::Later(1000)]);
    assert_eq!(reply(&busy[0]), "451 4.4.5 Connection limit reached");
    assert!(waited >= Duration::from_secs(1), "{waited:?}");
    assert!(waited < Duration::from_secs(2), "{waited:?}");
    assert_eq!(answers(&freed), [Answer::Delivered]);
}

#[test]
fn keeps_the_egress_of_a_pooled_connection() {
    let seen = run(async {
        let seen = serve(MX1, Script::new(&[]));
        let deliver = deliverer(zone(), settings());
        let mut destination = destination("example.com");
        destination.egress.push((EGRESS2, 1));
        for _ in 0..3 {
            let outcomes = send(
                &deliver,
                &envelope(),
                &destination,
                &["a@example.com"],
                b"hello\r\n",
            )
            .await;
            assert_eq!(answers(&outcomes), [Answer::Delivered]);
        }
        seen
    });
    assert_eq!(seen.borrow().connections, 1);
}

#[test]
fn closes_after_421() {
    let seen = run(async {
        let mut script = Script::new(&[]);
        script.rcpt = Rc::new(|address| {
            if address.starts_with("busy@") {
                "421 4.7.0 too busy".to_owned()
            } else {
                "250 2.1.5 ok".to_owned()
            }
        });
        let seen = serve(MX1, script);
        let deliver = deliverer(zone(), settings());
        let outcomes = send(
            &deliver,
            &envelope(),
            &destination("example.com"),
            &["busy@example.com"],
            b"hello\r\n",
        )
        .await;
        assert_eq!(answers(&outcomes), [Answer::Deferred(Kind::Throttled)]);
        let outcomes = send(
            &deliver,
            &envelope(),
            &destination("example.com"),
            &["busy@example.com", "ok@example.com"],
            b"hello\r\n",
        )
        .await;
        assert_eq!(
            answers(&outcomes),
            [Answer::Deferred(Kind::Throttled), Answer::Delivered]
        );
        assert_eq!(deliver.pooled(), 0);
        seen
    });
    assert_eq!(seen.borrow().connections, 2);
}

#[test]
fn dane_checks_the_server_certificate() {
    let cases: [(Records, Answer); 5] = [
        (&[(3, 1, 1, LEAF)], Answer::Delivered),
        (&[(2, 0, 1, ROOT)], Answer::Delivered),
        (&[(3, 1, 1, ROOT), (3, 1, 1, LEAF)], Answer::Delivered),
        (&[(3, 1, 1, ROOT)], TEMPORARY),
        (&[(2, 0, 1, LEAF)], TEMPORARY),
    ];
    for (records, want) in cases {
        let (outcomes, seen) = run(async move {
            let seen = serve(MX1, Script::new(&["STARTTLS"]));
            let zone = signed(true);
            tlsa(&zone, "mx1.example.com", records);
            let deliver = deliverer(zone, settings());
            (simple(&deliver, "example.com").await, seen)
        });
        assert_eq!(answers(&outcomes), [want], "{records:?}");
        assert_eq!(mailed(&seen), want == Answer::Delivered, "{records:?}");
        if want == TEMPORARY {
            assert_eq!(reply(&outcomes[0]), "451 4.7.5 TLS negotiation failed");
        }
    }
}

#[test]
fn dane_never_falls_back_to_plaintext() {
    let cases: [(Records, &[&str], Answer); 4] = [
        (&[(3, 1, 1, LEAF)], &[], TEMPORARY),
        (&[(1, 1, 1, LEAF)], &[], TEMPORARY),
        (&[(1, 1, 1, ROOT)], &["STARTTLS"], Answer::Delivered),
        (&[(3, 9, 1, ROOT)], &["STARTTLS"], Answer::Delivered),
    ];
    for (records, extensions, want) in cases {
        let (outcomes, seen) = run(async move {
            let seen = serve(MX1, Script::new(extensions));
            let zone = signed(true);
            tlsa(&zone, "mx1.example.com", records);
            let deliver = deliverer(zone, settings());
            (simple(&deliver, "example.com").await, seen)
        });
        assert_eq!(answers(&outcomes), [want], "{records:?}");
        assert_eq!(seen.borrow().tls, want == Answer::Delivered, "{records:?}");
        if want == TEMPORARY {
            assert!(!mailed(&seen));
            assert!(reply(&outcomes[0]).starts_with("451 4.7.4"));
        }
    }
}

#[test]
fn dane_needs_signed_answers() {
    for (mx, host, records) in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        let (outcomes, asked) = run(async move {
            drop(serve(MX1, Script::new(&["STARTTLS"])));
            let zone = zone();
            zone.set("example.com", Type::Mx, mx_one());
            if mx {
                zone.sign("example.com", Type::Mx);
            }
            if host {
                zone.sign("mx1.example.com", Type::A);
            }
            tlsa(&zone, "mx1.example.com", &[(3, 1, 1, ROOT)]);
            if !records {
                zone.unsign("_25._tcp.mx1.example.com", Type::Tlsa);
            }
            let asked = Rc::clone(&zone.asked);
            let deliver = deliverer(zone, settings());
            (simple(&deliver, "example.com").await, asked)
        });
        assert_eq!(answers(&outcomes), [Answer::Delivered]);
        let tlsa = asked.borrow().iter().any(|(_, kind)| *kind == Type::Tlsa);
        assert_eq!(tlsa, !records);
    }
}

fn mx_one() -> Found {
    mx(&[(10, "mx1.example.com")])
}

#[test]
fn tlsa_failure_tries_the_next_host() {
    let (outcomes, first, second) = run(async {
        let first = serve(MX1, Script::new(&["STARTTLS"]));
        let second = serve(MX2, Script::new(&["STARTTLS"]));
        let zone = signed(false);
        zone.fail("_25._tcp.mx1.example.com", Type::Tlsa);
        let deliver = deliverer(zone, settings());
        (simple(&deliver, "example.com").await, first, second)
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered]);
    assert_eq!(first.borrow().connections, 0);
    assert_eq!(second.borrow().connections, 1);
}

#[test]
fn dane_follows_a_signed_alias() {
    let (outcomes, asked) = run(async {
        drop(serve(MX1, Script::new(&["STARTTLS"])));
        let zone = signed(true);
        zone.alias("mx1.example.com", "mx.hosting.example");
        tlsa(&zone, "mx.hosting.example", &[(2, 0, 1, ROOT)]);
        tlsa(&zone, "mx1.example.com", &[(3, 1, 1, ROOT)]);
        let asked = Rc::clone(&zone.asked);
        let deliver = deliverer(zone, settings());
        (simple(&deliver, "example.com").await, asked)
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered]);
    let tlsa: Vec<String> = asked
        .borrow()
        .iter()
        .filter(|(_, kind)| *kind == Type::Tlsa)
        .map(|(name, _)| name.clone())
        .collect();
    assert_eq!(tlsa, ["_25._tcp.mx.hosting.example"]);
}

#[test]
fn pooled_connections_keep_their_tls_level() {
    let (outcomes, seen) = run(async {
        let seen = serve(MX1, Script::new(&["STARTTLS"]));
        let zone = signed(true);
        let deliver = deliverer(zone.clone(), settings());
        let first = simple(&deliver, "example.com").await;
        assert_eq!(answers(&first), [Answer::Delivered]);
        assert_eq!(deliver.pooled(), 1);
        tlsa(&zone, "mx1.example.com", &[(3, 1, 1, ROOT)]);
        (simple(&deliver, "example.com").await, seen)
    });
    assert_eq!(answers(&outcomes), [TEMPORARY]);
    assert_eq!(seen.borrow().connections, 2);
}

#[test]
fn mta_sts_enforce_limits_hosts() {
    let (outcomes, first, second, requests, policies) = run(async {
        let first = serve(MX1, Script::new(&["STARTTLS"]));
        let second = serve(MX2, Script::new(&["STARTTLS"]));
        let requests = serve_policy(WEB, Rc::new(RefCell::new(policy(ENFORCE))));
        let zone = zone();
        sts(&zone, "1");
        let deliver = verifying(zone, strict());
        let mut outcomes = simple(&deliver, "example.com").await;
        outcomes.extend(simple(&deliver, "example.com").await);
        (outcomes, first, second, requests, deliver.policies())
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered, Answer::Delivered]);
    assert_eq!(first.borrow().connections, 0);
    assert!(second.borrow().tls);
    assert_eq!(policies, 1);
    let requests = requests.borrow();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .starts_with("GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mta-sts.example.com\r\n")
    );
}

#[test]
fn mta_sts_enforce_needs_verified_tls() {
    let cases = [
        ("mx2.example.com", &[][..], "451 4.7.4"),
        ("mx3.example.com", &["STARTTLS"][..], "451 4.7.5"),
    ];
    for (host, extensions, text) in cases {
        let (outcomes, seen) = run(async move {
            let seen = serve(MX2, Script::new(extensions));
            let text = format!("version: STSv1\nmode: enforce\nmx: {host}\nmax_age: 86400\n");
            drop(serve_policy(WEB, Rc::new(RefCell::new(policy(&text)))));
            let zone = zone();
            zone.set("example.com", Type::Mx, mx(&[(10, host)]));
            zone.set("mx3.example.com", Type::A, a(&[MX2]));
            sts(&zone, "1");
            let deliver = verifying(zone, strict());
            (simple(&deliver, "example.com").await, seen)
        });
        assert_eq!(answers(&outcomes), [TEMPORARY], "{host}");
        assert!(reply(&outcomes[0]).starts_with(text), "{host}");
        assert!(!mailed(&seen), "{host}");
    }
}

#[test]
fn mta_sts_without_enforce_does_not_block() {
    let testing = "version: STSv1\nmode: testing\nmx: mx2.example.com\nmax_age: 86400\n";
    let wrong = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{ENFORCE}",
        ENFORCE.len()
    );
    let cases = [
        (Some(policy(testing)), true),
        (Some(wrong), true),
        (None, true),
        (Some(policy(ENFORCE)), false),
    ];
    for (served, first) in cases {
        let (outcomes, seen) = run(async move {
            let seen = serve(MX1, Script::new(&[]));
            drop(serve(MX2, Script::new(&["STARTTLS"])));
            if let Some(served) = served {
                drop(serve_policy(WEB, Rc::new(RefCell::new(served))));
            }
            let zone = zone();
            sts(&zone, "1");
            let deliver = verifying(zone, strict());
            (simple(&deliver, "example.com").await, seen)
        });
        assert_eq!(answers(&outcomes), [Answer::Delivered]);
        assert_eq!(seen.borrow().connections == 1, first);
    }
}

#[test]
fn cached_policy_outlives_a_failed_fetch() {
    let (outcomes, first, requests) = run(async {
        let first = serve(MX1, Script::new(&["STARTTLS"]));
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        let response = Rc::new(RefCell::new(policy(ENFORCE)));
        let requests = serve_policy(WEB, Rc::clone(&response));
        let zone = zone();
        sts(&zone, "1");
        let deliver = verifying(zone.clone(), strict());
        let mut outcomes = simple(&deliver, "example.com").await;
        *response.borrow_mut() = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned();
        sts(&zone, "2");
        outcomes.extend(simple(&deliver, "example.com").await);
        zone.fail("_mta-sts.example.com", Type::Txt);
        outcomes.extend(simple(&deliver, "example.com").await);
        (outcomes, first, requests)
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered; 3]);
    assert_eq!(first.borrow().connections, 0);
    assert_eq!(requests.borrow().len(), 2);
}

#[derive(Default)]
struct Memory {
    rows: RefCell<BTreeMap<(u16, u32), Vec<u8>>>,
}

impl Saving for Memory {
    fn home(&self) -> u16 {
        1
    }

    fn put(&self, shard: u16, id: u32, data: Vec<u8>) -> Done<'_> {
        self.rows.borrow_mut().insert((shard, id), data);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&self, shard: u16, id: u32) -> Done<'_> {
        self.rows.borrow_mut().remove(&(shard, id));
        Box::pin(std::future::ready(Ok(())))
    }
}

fn restore(memory: &Rc<Memory>) -> Restore {
    let saved = memory
        .rows
        .borrow()
        .iter()
        .map(|(&(shard, id), data)| Saved {
            shard,
            id,
            data: data.clone(),
        })
        .collect();
    Restore {
        saved,
        unread: 0,
        dropped: 0,
        records: Rc::clone(memory) as Rc<dyn Saving>,
    }
}

#[test]
fn saved_policy_is_enforced_after_a_restart_without_its_server() {
    let (outcomes, first, requests, stats) = run(async {
        let first = serve(MX1, Script::new(&["STARTTLS"]));
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        let requests = serve_policy(WEB, Rc::new(RefCell::new(policy(ENFORCE))));
        let zone = zone();
        sts(&zone, "1");
        let memory = Rc::new(Memory::default());
        let deliver = verifying(zone.clone(), strict());
        deliver.restore(restore(&memory)).await;
        let mut outcomes = simple(&deliver, "example.com").await;
        drop(deliver);
        sleep(Duration::from_millis(1)).await;
        assert_eq!(memory.rows.borrow().len(), 1);
        sts(&zone, "2");
        zone.fail("mta-sts.example.com", Type::A);
        let again = verifying(zone, strict());
        again.restore(restore(&memory)).await;
        outcomes.extend(simple(&again, "example.com").await);
        (outcomes, first, requests, again.policy_stats())
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered; 2]);
    assert_eq!(first.borrow().connections, 0);
    assert_eq!(requests.borrow().len(), 1);
    assert_eq!(stats.loaded, 1);
}

fn policy_for(mx: &str, max_age: u64) -> String {
    policy(&format!(
        "version: STSv1\nmode: enforce\n{mx}max_age: {max_age}\n"
    ))
}

async fn both<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (pin!(a), pin!(b));
    let (mut x, mut y) = (None, None);
    poll_fn(|cx| {
        if x.is_none()
            && let Poll::Ready(out) = a.as_mut().poll(cx)
        {
            x = Some(out);
        }
        if y.is_none()
            && let Poll::Ready(out) = b.as_mut().poll(cx)
        {
            y = Some(out);
        }
        if x.is_some() && y.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    (x.expect("first"), y.expect("second"))
}

async fn ticks(deliver: &Deliver<Zone>, every: Duration, count: u32) {
    for _ in 0..count {
        deliver.tick().await;
        sleep(every).await;
    }
}

#[test]
fn concurrent_deliveries_share_one_policy_fetch() {
    let (outcomes, first, requests) = run(async {
        let first = serve(MX1, Script::new(&["STARTTLS"]));
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        let requests = serve_policy(WEB, Rc::new(RefCell::new(policy(ENFORCE))));
        let zone = zone();
        sts(&zone, "1");
        let deliver = verifying(zone, strict());
        let (mut a, b) = both(
            simple(&deliver, "example.com"),
            simple(&deliver, "example.com"),
        )
        .await;
        a.extend(b);
        (a, first, requests)
    });
    assert_eq!(answers(&outcomes), [Answer::Delivered; 2]);
    assert_eq!(first.borrow().connections, 0);
    assert_eq!(requests.borrow().len(), 1);
}

#[test]
fn daily_refresh_fetches_a_changed_policy_without_mail() {
    let (fetched, after) = run(async {
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        let response = Rc::new(RefCell::new(policy_for("mx: mx2.example.com\n", 604_800)));
        let requests = serve_policy(WEB, Rc::clone(&response));
        let zone = zone();
        sts(&zone, "1");
        let deliver = verifying(zone.clone(), strict());
        simple(&deliver, "example.com").await;
        ticks(&deliver, Duration::from_mins(1), 5).await;
        assert_eq!(requests.borrow().len(), 1);
        *response.borrow_mut() = policy_for("mx: mx2.example.com\nmx: mx1.example.com\n", 604_800);
        sts(&zone, "2");
        sleep(Duration::from_hours(24)).await;
        ticks(&deliver, Duration::from_mins(1), 200).await;
        let fetched = requests.borrow().len();
        simple(&deliver, "example.com").await;
        let after = requests.borrow().len();
        (fetched, after)
    });
    assert_eq!(fetched, 2);
    assert_eq!(after, 2);
}

#[test]
fn refresh_extends_a_policy_close_to_expiry() {
    let fetched = run(async {
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        let response = Rc::new(RefCell::new(policy_for("mx: mx2.example.com\n", 345_600)));
        let requests = serve_policy(WEB, response);
        let zone = zone();
        sts(&zone, "1");
        let deliver = verifying(zone, strict());
        simple(&deliver, "example.com").await;
        let mut fetched = Vec::new();
        for _ in 0..4 {
            ticks(&deliver, Duration::from_mins(10), 144).await;
            fetched.push(requests.borrow().len());
        }
        fetched
    });
    assert_eq!(fetched, [1, 1, 1, 2]);
}

#[test]
fn policies_unused_for_half_a_year_are_dropped() {
    let (before, after) = run(async {
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        let year = policy_for("mx: mx2.example.com\n", 31_557_600);
        drop(serve_policy(WEB, Rc::new(RefCell::new(year))));
        let zone = zone();
        sts(&zone, "1");
        let deliver = verifying(zone, strict());
        simple(&deliver, "example.com").await;
        deliver.tick().await;
        sleep(Duration::from_hours(24 * 179)).await;
        deliver.tick().await;
        let before = deliver.policies();
        sleep(Duration::from_hours(24 * 2)).await;
        deliver.tick().await;
        (before, deliver.policies())
    });
    assert_eq!((before, after), (1, 0));
}

#[test]
fn refreshes_do_not_keep_an_unused_policy() {
    let (refreshed, left) = run(async {
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        let week = policy_for("mx: mx2.example.com\n", 604_800);
        let requests = serve_policy(WEB, Rc::new(RefCell::new(week)));
        let zone = zone();
        sts(&zone, "1");
        let deliver = verifying(zone, strict());
        simple(&deliver, "example.com").await;
        ticks(&deliver, Duration::from_hours(1), 24 * 181).await;
        let refreshed = requests.borrow().len();
        (refreshed, deliver.policies())
    });
    assert!(refreshed > 1, "{refreshed}");
    assert_eq!(left, 0);
}

fn one(taken: &[Taken]) -> (&str, &Applies) {
    assert_eq!(taken.len(), 1, "{taken:?}");
    assert_eq!(taken[0].policies.len(), 1, "{taken:?}");
    (&taken[0].domain, &taken[0].policies[0])
}

fn detail(result: ResultType, mx: &str, receiving: Option<IpAddr>) -> Detail {
    Detail {
        result,
        sending: EGRESS,
        mx: (!mx.is_empty()).then(|| mx.to_owned()),
        receiving,
        count: 1,
        reason: None,
    }
}

#[test]
fn sessions_count_successes_per_policy_domain() {
    let taken = run(async {
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        drop(serve_policy(WEB, Rc::new(RefCell::new(policy(ENFORCE)))));
        let zone = zone();
        sts(&zone, "1");
        let deliver = verifying(zone, strict());
        simple(&deliver, "example.com").await;
        simple(&deliver, "example.com").await;
        deliver.take_results()
    });
    let (domain, applies) = one(&taken);
    assert_eq!(domain, "example.com");
    let lines = ENFORCE.lines().map(ToString::to_string).collect();
    let mx = vec!["mx2.example.com".to_owned()];
    assert_eq!(applies.policy, Applied::Sts { lines, mx });
    assert_eq!((applies.success, applies.failure), (1, 0));
}

#[test]
fn sessions_without_starttls_are_failures() {
    let (taken, again) = run(async {
        drop(serve(MX1, Script::new(&[])));
        let deliver = deliverer(zone(), settings());
        simple(&deliver, "example.com").await;
        (deliver.take_results(), deliver.take_results())
    });
    let (domain, applies) = one(&taken);
    assert_eq!(domain, "example.com");
    assert_eq!(applies.policy, Applied::None);
    assert_eq!((applies.success, applies.failure), (0, 1));
    let want = detail(
        ResultType::StarttlsNotSupported,
        "mx1.example.com",
        Some(MX1),
    );
    assert_eq!(applies.details, [want]);
    assert_eq!(again, []);
}

#[test]
fn certificate_and_policy_failures_are_named() {
    let (mismatch, fetch) = run(async {
        drop(serve(MX2, Script::new(&["STARTTLS"])));
        let text = "version: STSv1\nmode: enforce\nmx: mx3.example.com\nmax_age: 86400\n";
        drop(serve_policy(WEB, Rc::new(RefCell::new(policy(text)))));
        let zone = zone();
        zone.set("example.com", Type::Mx, mx(&[(10, "mx3.example.com")]));
        zone.set("mx3.example.com", Type::A, a(&[MX2]));
        sts(&zone, "1");
        let deliver = verifying(zone.clone(), strict());
        simple(&deliver, "example.com").await;
        let mismatch = deliver.take_results();
        let fresh = verifying(zone.clone(), strict());
        zone.fail("mta-sts.example.com", Type::A);
        simple(&fresh, "example.com").await;
        (mismatch, fresh.take_results())
    });
    let (_, applies) = one(&mismatch);
    let want = detail(
        ResultType::CertificateHostMismatch,
        "mx3.example.com",
        Some(MX2),
    );
    assert_eq!(applies.details, [want]);
    let failed = fetch
        .iter()
        .flat_map(|t| &t.policies)
        .find(|a| matches!(&a.policy, Applied::Sts { lines, .. } if lines.is_empty()))
        .expect("fetch failure");
    assert_eq!(
        failed.details,
        [detail(ResultType::StsPolicyFetchError, "", None)]
    );
}

#[test]
fn dane_sessions_report_to_the_mx_host() {
    let taken = run(async {
        drop(serve(MX1, Script::new(&["STARTTLS"])));
        let zone = signed(true);
        tlsa(&zone, "mx1.example.com", &[(3, 1, 1, LEAF)]);
        let deliver = deliverer(zone, settings());
        simple(&deliver, "example.com").await;
        deliver.take_results()
    });
    let (domain, applies) = one(&taken);
    assert_eq!(domain, "mx1.example.com");
    let records = vec![format!("3 1 1 {LEAF}")];
    assert_eq!(applies.policy, Applied::Tlsa { records });
    assert_eq!((applies.success, applies.failure), (1, 0));
}

#[test]
fn only_servfail_on_tlsa_counts_as_dnssec_invalid() {
    let mut found = Vec::new();
    for slow in [false, true] {
        let taken = run(async move {
            drop(serve(MX1, Script::new(&["STARTTLS"])));
            let zone = signed(true);
            tlsa(&zone, "mx1.example.com", &[(3, 1, 1, LEAF)]);
            let name = "_25._tcp.mx1.example.com";
            if slow {
                zone.time_out(name, Type::Tlsa);
            } else {
                zone.fail(name, Type::Tlsa);
            }
            let deliver = deliverer(zone, settings());
            simple(&deliver, "example.com").await;
            deliver.take_results()
        });
        found.push(taken);
    }
    let (domain, applies) = one(&found[0]);
    assert_eq!(domain, "mx1.example.com");
    let records = Vec::new();
    assert_eq!(applies.policy, Applied::Tlsa { records });
    let bogus = detail(ResultType::DnssecInvalid, "mx1.example.com", None);
    assert_eq!(applies.details, [bogus]);
    assert_eq!(found[1], []);
}

#[test]
fn testing_mode_observes_certificates_and_mx_names_without_blocking() {
    for reports in [true, false] {
        let (outcomes, taken) = run(async move {
            drop(serve(MX2, Script::new(&["STARTTLS"])));
            let text = "version: STSv1\nmode: testing\nmx: mx2.example.com\nmax_age: 86400\n";
            drop(serve_policy(WEB, Rc::new(RefCell::new(policy(text)))));
            let zone = zone();
            zone.set("example.com", Type::Mx, mx(&[(10, "mx3.example.com")]));
            zone.set("mx3.example.com", Type::A, a(&[MX2]));
            sts(&zone, "1");
            let mut settings = strict();
            settings.tlsrpt = reports;
            let deliver = verifying(zone, settings);
            (
                simple(&deliver, "example.com").await,
                deliver.take_results(),
            )
        });
        assert_eq!(answers(&outcomes), [Answer::Delivered], "{reports}");
        let (domain, applies) = one(&taken);
        assert_eq!(domain, "example.com");
        assert!(matches!(applies.policy, Applied::Sts { .. }));
        if reports {
            assert_eq!((applies.success, applies.failure), (0, 2));
            let mismatch = detail(ResultType::ValidationFailure, "mx3.example.com", None);
            let cert = detail(
                ResultType::CertificateHostMismatch,
                "mx3.example.com",
                Some(MX2),
            );
            assert_eq!(applies.details, [cert, mismatch]);
        } else {
            assert_eq!((applies.success, applies.failure), (1, 0));
        }
    }
}

#[test]
fn requiretls_needs_verified_tls() {
    let tls = Envelope {
        required: Required {
            smtputf8: false,
            requiretls: true,
        },
        ..envelope()
    };
    let cases: [(bool, Records, &[&str], Answer, bool); 4] = [
        (
            true,
            &[(3, 1, 1, LEAF)],
            &["STARTTLS", "REQUIRETLS"],
            Answer::Delivered,
            true,
        ),
        (
            true,
            &[(3, 1, 1, LEAF)],
            &["STARTTLS"],
            Answer::Failed,
            true,
        ),
        (
            true,
            &[],
            &["STARTTLS", "REQUIRETLS"],
            Answer::Failed,
            false,
        ),
        (
            false,
            &[],
            &["STARTTLS", "REQUIRETLS"],
            Answer::Delivered,
            true,
        ),
    ];
    for (dane, records, extensions, want, connects) in cases {
        let tls = tls.clone();
        let (outcomes, seen) = run(async move {
            let seen = serve(MX2, Script::new(extensions));
            drop(serve_policy(WEB, Rc::new(RefCell::new(policy(ENFORCE)))));
            let zone = if dane { signed(false) } else { zone() };
            zone.set("example.com", Type::Mx, mx(&[(10, "mx2.example.com")]));
            if !records.is_empty() {
                tlsa(&zone, "mx2.example.com", records);
            }
            let settings = if dane { settings() } else { strict() };
            if !dane {
                sts(&zone, "1");
            }
            let deliver = verifying(zone, settings);
            let outcomes = send(
                &deliver,
                &tls,
                &destination("example.com"),
                &["a@example.com"],
                b"hello\r\n",
            )
            .await;
            (outcomes, seen)
        });
        assert_eq!(answers(&outcomes), [want], "{records:?} {extensions:?}");
        assert_eq!(seen.borrow().connections > 0, connects, "{extensions:?}");
        if want == Answer::Failed {
            assert!(reply(&outcomes[0]).starts_with("550 5.7.30"));
            assert!(!mailed(&seen));
        } else {
            assert!(
                commands(&seen)
                    .iter()
                    .any(|c| c.starts_with("MAIL") && c.ends_with(" REQUIRETLS"))
            );
        }
    }
}

#[test]
fn requiretls_defers_when_the_host_is_down() {
    let tls = Envelope {
        required: Required {
            smtputf8: false,
            requiretls: true,
        },
        ..envelope()
    };
    let outcomes = run(async move {
        let zone = signed(false);
        tlsa(&zone, "mx1.example.com", &[(3, 1, 1, LEAF)]);
        let deliver = deliverer(zone, settings());
        send(
            &deliver,
            &tls,
            &destination("example.com"),
            &["a@example.com"],
            b"hello\r\n",
        )
        .await
    });
    assert_eq!(answers(&outcomes), [TEMPORARY]);
}
