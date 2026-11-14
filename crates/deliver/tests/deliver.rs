mod common;

use std::cell::{Cell, RefCell};
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::Duration;

use common::{Script, Seen, Zone, serve};
use deliver::{Deliver, EightBit, Message, Outcome, Settings};
use dns::{Found, Name, Record, Type};
use rt::sim::{Config, SimDriver};
use rt::{Runtime, now};
use sched::{Answer, Body, Destination, Envelope, Kind, Recipient, Required};
use tls::{Connector, simulated};

const EGRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const MX1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
const MX2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
const HEADER: &[u8] = b"Received: from a\r\nSubject: hi\r\n";
const TEMPORARY: Answer = Answer::Deferred(Kind::Temporary);

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
    let connector = Connector::new(simulated(2), None).expect("connector");
    Deliver::new(zone, connector, settings, 9).expect("deliver")
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
            "QUIT",
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
