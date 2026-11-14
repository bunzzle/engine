mod common;

use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use common::{AD, NXDOMAIN, SERVFAIL, TC, mx, reply, rr, soa};
use crypto::Secret;
use dns::{Error, Found, Name, Record, Resolver, Settings, Type};
use rt::sim::{Config, SimDriver, check};
use rt::{Buf, Runtime, TcpListener, UdpSocket, sleep, spawn};

const ONE: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)), 53);
const TWO: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 54)), 53);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Answer,
    ServFail,
    Truncate,
    Spoof,
    Silent,
    Authentic,
    Missing,
}

fn run<T: 'static>(seed: u64, future: impl Future<Output = T> + 'static) -> T {
    let driver = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(driver).block_on(future)
}

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn answer(query: &[u8], flags: u16) -> Vec<u8> {
    let answers = [
        rr("example.com", 15, 300, mx(10, "mx1.example.com")),
        rr("example.com", 15, 300, mx(20, "mx2.example.com")),
    ];
    reply(query, flags, &answers, &[])
}

fn serve(at: SocketAddr, mode: Mode, asked: Rc<Cell<u32>>) {
    drop(spawn(async move {
        let socket = UdpSocket::bind(at).await.expect("bind");
        loop {
            let (got, buf) = socket.recv_from(Buf::new(512)).await;
            let (_, from) = got.expect("recv");
            asked.set(asked.get() + 1);
            let query = buf.to_vec();
            let packet = match mode {
                Mode::Answer => answer(&query, 0),
                Mode::Authentic => answer(&query, AD),
                Mode::ServFail => reply(&query, SERVFAIL, &[], &[]),
                Mode::Truncate => reply(&query, TC, &[], &[]),
                Mode::Missing => {
                    let authority = [rr("example.com", 6, 600, soa(120))];
                    reply(&query, NXDOMAIN, &[], &authority)
                }
                Mode::Silent => continue,
                Mode::Spoof => {
                    let mut wrong = answer(&query, 0);
                    wrong[1] ^= 1;
                    let spoofer = UdpSocket::bind(SocketAddr::from((at.ip(), 5353)))
                        .await
                        .expect("spoofer");
                    let (sent, _) = spoofer.send_to(Buf::from_slice(&wrong), from).await;
                    sent.expect("spoof");
                    let fake = reply(&query, NXDOMAIN, &[], &[]);
                    let (sent, _) = spoofer.send_to(Buf::from_slice(&fake), from).await;
                    sent.expect("spoof");
                    drop(spoofer);
                    let mut bad_id = reply(&query, NXDOMAIN, &[], &[]);
                    bad_id[0] ^= 0xff;
                    let (sent, _) = socket.send_to(Buf::from_slice(&bad_id), from).await;
                    sent.expect("bad id");
                    sleep(Duration::from_millis(5)).await;
                    answer(&query, 0)
                }
            };
            let (sent, _) = socket.send_to(Buf::from_slice(&packet), from).await;
            sent.expect("send");
        }
    }));
}

fn serve_tcp(at: SocketAddr, asked: Rc<Cell<u32>>) {
    drop(spawn(async move {
        let listener = TcpListener::bind(at, 16).await.expect("bind tcp");
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            asked.set(asked.get() + 1);
            let mut data = Vec::new();
            while data.len() < 2
                || data.len() < 2 + usize::from(u16::from_be_bytes([data[0], data[1]]))
            {
                let (read, buf) = stream.read(Buf::new(512)).await;
                if read.expect("read") == 0 {
                    break;
                }
                data.extend_from_slice(&buf);
            }
            let packet = answer(&data[2..], 0);
            let mut framed = u16::try_from(packet.len())
                .expect("small")
                .to_be_bytes()
                .to_vec();
            framed.extend(packet);
            for chunk in framed.chunks(7) {
                let (written, _) = stream.write_all(Buf::from_slice(chunk)).await;
                written.expect("write");
            }
        }
    }));
}

fn resolver(servers: Vec<SocketAddr>, dnssec: bool) -> Resolver {
    let mut settings = Settings::new(servers);
    settings.dnssec = dnssec;
    settings.timeout = Duration::from_secs(2);
    Resolver::new(settings, &Secret::new([7; 32]))
}

fn exchanges(found: &Found) -> Vec<String> {
    match found {
        Found::Records(records) => records
            .iter()
            .map(|r| match r {
                Record::Mx { exchange, .. } => exchange.to_string(),
                other => format!("{other:?}"),
            })
            .collect(),
        other => vec![format!("{other:?}")],
    }
}

#[test]
fn an_answer_is_cached_until_its_ttl() {
    check(0..10, |seed| {
        let asked = Rc::new(Cell::new(0));
        let seen = Rc::clone(&asked);
        let (first, cached, sent) = run(seed, async move {
            serve(ONE, Mode::Answer, Rc::clone(&seen));
            let dns = resolver(vec![ONE], false);
            let first = dns
                .lookup(&name("Example.COM"), Type::Mx)
                .await
                .expect("mx");
            let again = dns
                .lookup(&name("example.com"), Type::Mx)
                .await
                .expect("mx");
            assert!(Rc::ptr_eq(&first, &again));
            sleep(Duration::from_secs(301)).await;
            dns.lookup(&name("example.com"), Type::Mx)
                .await
                .expect("mx");
            (exchanges(&first.found), dns.cached(), dns.sent())
        });
        assert_eq!(first, ["mx1.example.com", "mx2.example.com"]);
        assert_eq!(cached, 1);
        assert_eq!(sent, 2);
        assert_eq!(asked.get(), 2);
    });
}

#[test]
fn concurrent_lookups_share_one_query() {
    let asked = Rc::new(Cell::new(0));
    let seen = Rc::clone(&asked);
    let all = run(1, async move {
        serve(ONE, Mode::Answer, seen);
        let dns = resolver(vec![ONE], false);
        let tasks: Vec<_> = (0..5)
            .map(|_| {
                let dns = dns.clone();
                spawn(async move { dns.lookup(&name("example.com"), Type::Mx).await })
            })
            .collect();
        let mut all = Vec::new();
        for task in tasks {
            all.push(exchanges(&task.await.expect("mx").found));
        }
        all
    });
    assert_eq!(all.len(), 5);
    assert_eq!(asked.get(), 1);
}

#[test]
fn spoofed_and_mismatched_packets_are_ignored() {
    check(0..10, |seed| {
        let found = run(seed, async {
            serve(ONE, Mode::Spoof, Rc::new(Cell::new(0)));
            let dns = resolver(vec![ONE], false);
            let lookup = dns.lookup(&name("example.com"), Type::Mx).await;
            exchanges(&lookup.expect("mx").found)
        });
        assert_eq!(found, ["mx1.example.com", "mx2.example.com"]);
    });
}

#[test]
fn a_truncated_answer_is_asked_again_over_tcp() {
    let tcp = Rc::new(Cell::new(0));
    let seen = Rc::clone(&tcp);
    let found = run(2, async move {
        serve(ONE, Mode::Truncate, Rc::new(Cell::new(0)));
        serve_tcp(ONE, seen);
        let dns = resolver(vec![ONE], false);
        exchanges(
            &dns.lookup(&name("example.com"), Type::Mx)
                .await
                .expect("mx")
                .found,
        )
    });
    assert_eq!(found, ["mx1.example.com", "mx2.example.com"]);
    assert_eq!(tcp.get(), 1);
}

#[test]
fn a_failing_server_moves_to_the_next() {
    let (ok, failed, silent) = run(3, async {
        serve(ONE, Mode::ServFail, Rc::new(Cell::new(0)));
        serve(TWO, Mode::Answer, Rc::new(Cell::new(0)));
        let dns = resolver(vec![ONE, TWO], false);
        let ok = dns
            .lookup(&name("example.com"), Type::Mx)
            .await
            .map(|l| l.found.clone());
        let only_bad = resolver(vec![ONE], false);
        let failed = only_bad
            .lookup(&name("example.com"), Type::Mx)
            .await
            .map(drop);
        let nobody = resolver(vec![TWO], false);
        drop(nobody);
        let quiet = SocketAddr::from(([10, 0, 0, 55], 53));
        serve(quiet, Mode::Silent, Rc::new(Cell::new(0)));
        let silent = resolver(vec![quiet], false)
            .lookup(&name("example.com"), Type::Mx)
            .await
            .map(drop);
        (ok, failed, silent)
    });
    assert!(matches!(ok, Ok(Found::Records(_))));
    assert_eq!(failed, Err(Error::ServFail));
    assert_eq!(silent, Err(Error::Timeout));
}

#[test]
fn a_missing_name_is_cached_for_the_negative_ttl() {
    let asked = Rc::new(Cell::new(0));
    let seen = Rc::clone(&asked);
    let (found, cached) = run(4, async move {
        serve(ONE, Mode::Missing, seen);
        let dns = resolver(vec![ONE], false);
        let found = dns
            .lookup(&name("example.com"), Type::Mx)
            .await
            .expect("nx");
        sleep(Duration::from_secs(119)).await;
        dns.lookup(&name("example.com"), Type::Mx)
            .await
            .expect("nx");
        sleep(Duration::from_secs(2)).await;
        dns.lookup(&name("example.com"), Type::Mx)
            .await
            .expect("nx");
        (found.found.clone(), dns.cached())
    });
    assert_eq!(found, Found::NxDomain);
    assert_eq!(cached, 1);
    assert_eq!(asked.get(), 2);
}

#[test]
fn the_ad_bit_counts_only_when_trusted() {
    let (trusted, untrusted) = run(5, async {
        serve(ONE, Mode::Authentic, Rc::new(Cell::new(0)));
        let trusted = resolver(vec![ONE], true)
            .lookup(&name("example.com"), Type::Mx)
            .await
            .expect("mx")
            .secure;
        let untrusted = resolver(vec![ONE], false)
            .lookup(&name("example.com"), Type::Mx)
            .await
            .expect("mx")
            .secure;
        (trusted, untrusted)
    });
    assert!(trusted);
    assert!(!untrusted);
}
