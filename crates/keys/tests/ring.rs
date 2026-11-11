use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use crypto::{BatchKey, DkimAlg, Plain, Secret, Wrap, seal_batch};
use keys::proto::{Answer, Frames, Request};
use keys::{
    Audit, BatchSettings, Batches, Client, Connect, Error, Fault, Ring, RingSettings, Server,
    Settings, Vault,
};
use rt::sim::{Config, SimDriver};
use rt::{Buf, Runtime, TcpListener, TcpStream, sleep, spawn};

const DAY: u32 = 20_833;

fn at(host: u8) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(10, 0, 0, host), 7000))
}

fn quiet() -> Config {
    let mut config = Config::default();
    config.faults.crash_keep = 0;
    config
}

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

async fn serve(dir: &str, host: u8) -> Rc<Server> {
    let vault = Vault::init(Path::new(dir), DAY).await.expect("init");
    let audit = Audit::open(Path::new(dir)).await.expect("audit");
    let server = Rc::new(Server::start(vault, audit, Settings::default()));
    let listener = TcpListener::bind(at(host), 16).await.expect("bind");
    let accepting = Rc::clone(&server);
    spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accepting.serve(stream);
        }
    });
    server
}

async fn create(host: u8, tenant: u32) {
    let client = Client::new(TcpStream::connect(at(host)).await.expect("connect"));
    let create = Request::Create {
        tenant,
        generation: 1,
        retention: 30,
    };
    assert!(matches!(
        client.call(&create).await.expect("create"),
        Answer::Keys { .. }
    ));
    client.close();
}

async fn naming(host: u8) -> Secret<16> {
    let client = Client::new(TcpStream::connect(at(host)).await.expect("connect"));
    let answer = client
        .call(&Request::Hello { node: 1 })
        .await
        .expect("hello");
    client.close();
    match answer {
        Answer::Hello { naming, .. } => naming,
        _ => panic!("expected hello"),
    }
}

fn hosts(order: &[u8]) -> (Connect, Rc<Cell<usize>>) {
    let order: Rc<[u8]> = order.into();
    let tries = Rc::new(Cell::new(0));
    let counted = Rc::clone(&tries);
    let connect: Connect = Rc::new(move || {
        let n = counted.get();
        counted.set(n + 1);
        let host = order[n.min(order.len() - 1)];
        Box::pin(async move { Ok(Client::new(TcpStream::connect(at(host)).await?)) })
    });
    (connect, tries)
}

fn settings() -> RingSettings {
    RingSettings {
        deadline: Duration::from_secs(1),
        ..RingSettings::new(1)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fake {
    Silent,
    Closes,
}

async fn fake(host: u8, naming: Secret<16>, mode: Fake) -> Rc<Cell<u32>> {
    let listener = TcpListener::bind(at(host), 4).await.expect("bind");
    let naming = Rc::new(naming);
    let closed = Rc::new(Cell::new(0));
    let counted = Rc::clone(&closed);
    spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let naming = Rc::clone(&naming);
            let closed = Rc::clone(&counted);
            spawn(async move {
                let mut frames = Frames::default();
                let mut greeted = false;
                loop {
                    let (read, buf) = stream.read(Buf::new(4096)).await;
                    let Ok(n @ 1..) = read else {
                        closed.set(closed.get() + 1);
                        return;
                    };
                    frames.push(&buf[..n]);
                    while let Ok(Some((op, id, body))) = frames.pop() {
                        let answer = match Request::decode(op, &body) {
                            Ok(Request::Hello { .. }) if !greeted => {
                                greeted = true;
                                Answer::Hello {
                                    day: DAY,
                                    naming: Secret::new(*naming.expose()),
                                }
                            }
                            Ok(Request::Open { .. }) if mode == Fake::Closes => Answer::Keys {
                                day: DAY,
                                oldest: DAY,
                                version: 1,
                                data: Secret::new([5; 32]),
                                hash: Secret::new([6; 16]),
                                today: [7; 32],
                                tomorrow: [8; 32],
                            },
                            _ => continue,
                        };
                        let mut out = Plain::with_capacity(256);
                        answer.encode(id, &mut out);
                        let (written, _) = stream.write_all(Buf::from_slice(&out)).await;
                        written.expect("write");
                        if matches!(answer, Answer::Keys { .. }) {
                            drop(stream.shutdown().await);
                        }
                    }
                }
            });
        }
    });
    closed
}

#[test]
fn tenant_keys_open_once_on_first_use_and_stay_cached() {
    let driver = Rc::new(SimDriver::new(1, quiet()));
    run(&driver, async {
        let _server = serve("/a", 1).await;
        create(1, 4).await;
        let (connect, tries) = hosts(&[1]);
        let ring = Ring::new(connect, settings());
        assert_eq!(ring.naming(), None);
        assert!(ring.get(4, 1).is_none());
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let ring = ring.clone();
            tasks.push(spawn(async move { ring.open(4, 1).await }));
        }
        let mut opened = Vec::new();
        for task in tasks {
            opened.push(task.await.expect("open"));
        }
        let label = [&4u32.to_le_bytes()[..], &1u32.to_le_bytes()].concat();
        let sealed = opened[0].keys.seal(&label, b"mail").expect("seal");
        for working in &opened {
            assert_eq!(working.keys.open(&label, &sealed).expect("open"), b"mail");
            assert_eq!((working.day, working.oldest), (DAY, DAY));
        }
        assert_eq!(ring.stats().opens, 1);
        assert_eq!(tries.get(), 1);
        assert_eq!(ring.day(), DAY);
        assert_eq!(Some(*naming(1).await.expose()), ring.naming());
        let cached = ring.get(4, 1).expect("cached");
        assert_eq!(cached.keys.open(&label, &sealed).expect("open"), b"mail");
        assert_eq!(ring.open(9, 1).await.err(), Some(Fault::Unknown));
        assert_eq!(ring.open(4, 2).await.err(), Some(Fault::Unknown));
        assert_eq!(ring.stats().unknown, 2);
    });
}

#[test]
fn create_sets_retention_adopts_a_retry_and_refuses_another_generation() {
    let driver = Rc::new(SimDriver::new(8, quiet()));
    run(&driver, {
        let driver = Rc::clone(&driver);
        async move {
            let _server = serve("/a", 1).await;
            let ring = Ring::new(hosts(&[1]).0, settings());
            assert_eq!(ring.create(4, 1, 30).await, Ok(()));
            let first = ring.get(4, 1).expect("cached");
            assert_eq!(ring.stats().opens, 0);
            assert_eq!(ring.create(4, 1, 60).await, Ok(()));
            let again = ring.open(4, 1).await.expect("open");
            let label = [&4u32.to_le_bytes()[..], &1u32.to_le_bytes()].concat();
            let sealed = first.keys.seal(&label, b"mail").expect("seal");
            assert_eq!(again.keys.open(&label, &sealed).expect("open"), b"mail");
            assert_eq!(ring.create(4, 2, 30).await, Err(Fault::Conflict));
            sleep(Duration::from_secs(1)).await;
            let disk = driver.disk();
            let audit = disk
                .contents(&Path::new("/a").join("audit"))
                .expect("audit");
            let text = String::from_utf8(audit.to_vec()).expect("text");
            assert_eq!(text.matches(" retention 4 1 ").count(), 2, "{text}");
        }
    });
}

#[test]
fn unwrap_answers_once_per_batch_and_maps_refusals() {
    let driver = Rc::new(SimDriver::new(9, quiet()));
    run(&driver, async {
        let _server = serve("/a", 1).await;
        let ring = Ring::new(hosts(&[1]).0, settings());
        ring.create(4, 1, 30).await.expect("create");
        let working = ring.open(4, 1).await.expect("open");
        let mut batches = Batches::new(BatchSettings::default());
        let batch = batches.seal(&working, 2, 77, rt::now()).expect("seal");
        let wrap = Wrap::decode(&batch.wrap).expect("wrap");
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let ring = ring.clone();
            let wrap = wrap.clone();
            tasks.push(spawn(async move { ring.unwrap(4, 1, 2, 77, &wrap).await }));
        }
        let message = [7; 16];
        let aad = crypto::aad(4, 1, &message, 0, 1);
        let sealed = batch.key.record(&message, 0, 1).seal_one(&aad, b"mail");
        for task in tasks {
            let key = BatchKey::new(&task.await.expect("unwrap"));
            let opened = key.record(&message, 0, 1).open_one(&aad, &sealed);
            assert_eq!(opened.expect("open"), b"mail");
        }
        assert_eq!(ring.stats().unwraps, 1);
        let ninety = batches.seal(&working, 3, 90, rt::now()).expect("seal");
        let ninety = Wrap::decode(&ninety.wrap).expect("wrap");
        let mut tampered = ninety.clone();
        tampered.enc[0] ^= 1;
        let joined = {
            let ring = ring.clone();
            let wrap = ninety.clone();
            spawn(async move { ring.unwrap(4, 1, 3, 90, &wrap).await })
        };
        while ring.stats().unwraps < 2 {
            rt::yield_now().await;
        }
        let other = {
            let ring = ring.clone();
            let wrap = ninety.clone();
            spawn(async move { ring.unwrap(5, 1, 3, 90, &wrap).await })
        };
        assert_eq!(
            ring.unwrap(4, 1, 3, 90, &tampered).await.err(),
            Some(Fault::Bad)
        );
        assert!(joined.await.is_ok());
        assert_eq!(other.await.err(), Some(Fault::Unknown));
        assert_eq!(
            ring.unwrap(4, 2, 2, 77, &wrap).await.err(),
            Some(Fault::Bad)
        );
        assert_eq!(
            ring.unwrap(4, 1, 3, 77, &wrap).await.err(),
            Some(Fault::Bad)
        );
        assert_eq!(ring.stats().unwraps, 3);
        assert_eq!(
            ring.unwrap(4, 1, 2, 78, &wrap).await.err(),
            Some(Fault::Bad)
        );
        assert_eq!(
            ring.unwrap(9, 1, 2, 77, &wrap).await.err(),
            Some(Fault::Unknown)
        );
        let old =
            seal_batch(&working.today, 4, 1, DAY - 5, 2, 80, &Secret::new([3; 32])).expect("wrap");
        assert_eq!(
            ring.unwrap(4, 1, 2, 80, &old).await.err(),
            Some(Fault::Gone)
        );
        assert_eq!(ring.stats().gone, 1);
    });
}

#[test]
fn keys_down_is_unavailable_and_retries_back_off() {
    let driver = Rc::new(SimDriver::new(2, quiet()));
    run(&driver, async {
        let (connect, tries) = hosts(&[9]);
        let ring = Ring::new(connect, settings());
        assert_eq!(ring.open(4, 1).await.err(), Some(Fault::Unavailable));
        assert_eq!(ring.open(4, 1).await.err(), Some(Fault::Unavailable));
        assert_eq!(tries.get(), 1);
        sleep(Duration::from_millis(150)).await;
        assert_eq!(ring.open(4, 1).await.err(), Some(Fault::Unavailable));
        assert_eq!(tries.get(), 2);
        sleep(Duration::from_millis(150)).await;
        assert_eq!(ring.open(4, 1).await.err(), Some(Fault::Unavailable));
        assert_eq!(tries.get(), 2);
        assert!(!ring.failed());
    });
}

#[test]
fn a_stuck_connection_times_out_and_the_ring_reconnects() {
    let driver = Rc::new(SimDriver::new(3, quiet()));
    run(&driver, async {
        let _server = serve("/a", 1).await;
        create(1, 4).await;
        let closed = fake(2, naming(1).await, Fake::Silent).await;
        let (connect, tries) = hosts(&[2, 1]);
        let ring = Ring::new(connect, settings());
        let begin = rt::now();
        assert_eq!(ring.open(4, 1).await.err(), Some(Fault::Unavailable));
        assert!(rt::now().saturating_duration_since(begin) >= Duration::from_secs(1));
        assert_eq!(ring.stats().drops, 1);
        sleep(Duration::from_millis(200)).await;
        assert_eq!(closed.get(), 1);
        let working = ring.open(4, 1).await.expect("open after reconnect");
        assert_eq!(working.day, DAY);
        assert_eq!(tries.get(), 2);
        assert_eq!(ring.stats().connects, 2);
    });
}

#[test]
fn a_changed_naming_key_fails_the_ring_for_good() {
    let driver = Rc::new(SimDriver::new(4, quiet()));
    run(&driver, async {
        let _first = serve("/a", 1).await;
        let _second = serve("/b", 3).await;
        fake(2, naming(1).await, Fake::Closes).await;
        let (connect, _) = hosts(&[2, 3]);
        let ring = Ring::new(connect, settings());
        assert!(ring.open(4, 1).await.is_ok());
        sleep(Duration::from_millis(200)).await;
        assert!(ring.get(4, 1).is_some());
        assert_eq!(ring.open(4, 2).await.err(), Some(Fault::Failed));
        assert!(ring.failed());
        assert!(ring.get(4, 1).is_none());
        assert_eq!(ring.open(4, 1).await.err(), Some(Fault::Failed));
        sleep(Duration::from_secs(10)).await;
        assert_eq!(ring.open(4, 1).await.err(), Some(Fault::Failed));
        assert_eq!(ring.hello().await.err(), Some(Error::Failed));
        assert!(ring.stats().refused >= 3);
        assert_eq!(ring.stats().failed, 1);
    });
}

#[test]
fn a_slow_vault_write_keeps_the_connection() {
    let driver = Rc::new(SimDriver::new(6, quiet()));
    run(&driver, async {
        let _server = serve("/a", 1).await;
        create(1, 4).await;
        let (connect, tries) = hosts(&[1]);
        let ring = Ring::new(
            connect,
            RingSettings {
                slow: Duration::from_millis(300),
                ..settings()
            },
        );
        assert!(ring.open(4, 1).await.is_ok());
        let slow = Request::Create {
            tenant: 5,
            generation: 1,
            retention: 30,
        };
        assert_eq!(ring.call(&slow).await.err(), Some(Error::Timeout));
        assert_eq!(ring.stats().slow, 1);
        assert_eq!(ring.stats().drops, 0);
        let patient = Ring::new(hosts(&[1]).0, settings());
        let created = patient.call(&slow).await.expect("create");
        assert!(matches!(created, Answer::Keys { .. }));
        assert!(ring.open(5, 1).await.is_ok());
        assert_eq!(tries.get(), 1);
    });
}

#[test]
fn a_dropped_client_closes_its_connection() {
    let driver = Rc::new(SimDriver::new(7, quiet()));
    run(&driver, async {
        let closed = fake(2, Secret::new([1; 16]), Fake::Silent).await;
        let client = Client::new(TcpStream::connect(at(2)).await.expect("connect"));
        assert!(matches!(
            client.call(&Request::Hello { node: 1 }).await,
            Ok(Answer::Hello { .. })
        ));
        drop(client);
        sleep(Duration::from_millis(200)).await;
        assert_eq!(closed.get(), 1);
    });
}

#[test]
fn a_cancelled_open_leaves_the_ring_usable() {
    let driver = Rc::new(SimDriver::new(5, quiet()));
    run(&driver, async {
        let _server = serve("/a", 1).await;
        create(1, 4).await;
        let silent = TcpListener::bind(at(2), 4).await.expect("bind");
        let _held = spawn(async move {
            let mut kept = Vec::new();
            while let Ok((stream, _)) = silent.accept().await {
                kept.push(stream);
            }
        });
        let (connect, _) = hosts(&[2, 1]);
        let ring = Ring::new(connect, settings());
        let cut = rt::timeout(Duration::from_millis(100), ring.hello()).await;
        assert!(cut.is_err());
        sleep(Duration::from_millis(10)).await;
        ring.hello().await.expect("hello");
        assert!(ring.open(4, 1).await.is_ok());
    });
}

const DAY_MS: i64 = 86_400_000;

#[test]
fn sealing_steps_one_day_and_refetches_keys_more_than_a_day_old() {
    let driver = Rc::new(SimDriver::new(12, quiet()));
    let jumps = Rc::clone(&driver);
    run(&driver, async move {
        let _server = serve("/a", 1).await;
        create(1, 4).await;
        create(1, 5).await;
        let (connect, _) = hosts(&[1]);
        let ring = Ring::new(connect, settings());
        let opened = ring.open(4, 1).await.expect("open");
        let today = ring.sealing(4, 1).await.expect("sealing");
        assert_eq!((today.day, today.today), (DAY, opened.today));
        let stale = ring.open(5, 1).await.expect("open");
        assert_eq!(ring.stats().refreshes, 0);

        jumps.jump_wall_clock(DAY_MS);
        let next = ring.sealing(4, 1).await.expect("sealing");
        assert_eq!((next.day, next.today), (DAY + 1, opened.tomorrow));
        assert_eq!(ring.stats().behind, 1);
        assert_eq!(ring.stats().refreshes, 1);
        ring.sealing(4, 1).await.expect("sealing");
        assert_eq!(ring.stats().refreshes, 1);

        sleep(Duration::from_millis(50)).await;
        jumps.jump_wall_clock(2 * DAY_MS);
        let opens = ring.stats().opens;
        let fetched = ring.sealing(5, 1).await.expect("sealing");
        assert_eq!(ring.stats().opens, opens + 1);
        let cached = ring.get(5, 1).expect("cached");
        assert!(cached.day >= stale.day);
        assert_eq!(cached.seen, stale.seen + 3);
        assert_eq!((fetched.day, fetched.today), (cached.day, cached.today));
    });
}

#[test]
fn settled_is_sent_only_when_it_moves_forward() {
    let driver = Rc::new(SimDriver::new(13, quiet()));
    run(&driver, async {
        let _server = serve("/a", 1).await;
        let (connect, _) = hosts(&[1]);
        let ring = Ring::new(connect, settings());
        ring.hello().await.expect("hello");
        ring.settled(DAY - 2);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(ring.stats().settled, DAY - 2);
        let calls = ring.stats().unavailable;
        ring.settled(DAY - 5);
        ring.settled(DAY - 2);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(ring.stats().settled, DAY - 2);
        ring.settled(DAY - 1);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(ring.stats().settled, DAY - 1);
        assert_eq!(ring.stats().unavailable, calls);
    });
}

#[test]
fn dkim_keys_are_made_loaded_and_sign_through_the_ring() {
    let driver = Rc::new(SimDriver::new(5, quiet()));
    run(&driver, async {
        let _server = serve("/a", 1).await;
        create(1, 4).await;
        let (connect, _) = hosts(&[1]);
        let ring = Ring::new(connect, settings());
        let ed = DkimAlg::Ed25519Sha256;
        let (public, blob) = ring.dkim_new(4, 1, 1, ed).await.expect("new");
        let digest = [6; 32];
        let signed = ring.sign(4, 1, 1, ed, digest).await.expect("sign");
        UnparsedPublicKey::new(&ED25519, &public)
            .verify(&digest, &signed)
            .expect("verify");
        assert_eq!(ring.sign(4, 1, 2, ed, digest).await, Err(Fault::Unknown));
        assert_eq!(ring.load(4, 1, 2, ed, &blob).await, Err(Fault::Bad));
        assert_eq!(ring.load(4, 1, 1, ed, &blob).await, Ok(()));
        let (_, other) = ring.dkim_new(4, 1, 3, ed).await.expect("new");
        assert_eq!(ring.load(4, 1, 1, ed, &other).await, Err(Fault::Conflict));
        assert_eq!(ring.dkim_new(9, 1, 1, ed).await, Err(Fault::Unknown));
        let stats = ring.stats();
        assert_eq!((stats.dkim_new, stats.loads, stats.signs), (3, 3, 2));
    });
}

#[test]
fn calls_made_while_connecting_wait_for_that_connection() {
    let driver = Rc::new(SimDriver::new(6, quiet()));
    run(&driver, async {
        let _server = serve("/a", 1).await;
        for tenant in 4..10 {
            create(1, tenant).await;
        }
        let (connect, tries) = hosts(&[1]);
        let ring = Ring::new(connect, settings());
        let tasks: Vec<_> = (4..10)
            .map(|tenant| {
                let ring = ring.clone();
                spawn(async move { ring.open(tenant, 1).await })
            })
            .collect();
        for task in tasks {
            assert!(task.await.is_ok());
        }
        assert_eq!(tries.get(), 1);
        assert_eq!(ring.stats().connects, 1);
        assert_eq!(ring.stats().unavailable, 0);
    });
}
