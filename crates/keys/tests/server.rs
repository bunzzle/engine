use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use crypto::{Plain, Secret, seal_batch};
use keys::proto::{Answer, Frames, Request};
use keys::{Audit, Client, Error, Rate, Server, Settings, Vault};
use rt::sim::{Config, SimDriver};
use rt::{Buf, Runtime, TcpListener, TcpStream, UnixListener, sleep, spawn};

const DIR: &str = "/keys";
const DAY: u32 = 20_833;

fn addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 7000))
}

fn quiet() -> Config {
    let mut config = Config::default();
    config.faults.crash_keep = 0;
    config
}

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

async fn start(settings: Settings) -> Rc<Server> {
    let vault = Vault::init(Path::new(DIR), DAY).await.expect("init");
    let audit = Audit::open(Path::new(DIR)).await.expect("audit");
    let server = Rc::new(Server::start(vault, audit, settings));
    let listener = TcpListener::bind(addr(), 16).await.expect("bind");
    let accepting = Rc::clone(&server);
    spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accepting.serve(stream);
        }
    });
    server
}

async fn client() -> Client {
    Client::new(TcpStream::connect(addr()).await.expect("connect"))
}

fn keys(answer: Answer) -> (u32, [u8; 32], [u8; 32]) {
    match answer {
        Answer::Keys {
            day, data, today, ..
        } => (day, *data.expose(), today),
        _ => panic!("expected keys"),
    }
}

fn refused(answer: &Answer) -> Error {
    match answer {
        Answer::Refused(error) => *error,
        _ => panic!("expected a refusal"),
    }
}

async fn day(client: &Client) -> u32 {
    match client
        .call(&Request::Hello { node: 1 })
        .await
        .expect("hello")
    {
        Answer::Hello { day, .. } => day,
        _ => panic!("expected hello"),
    }
}

#[test]
fn calls_answer_keys_unwraps_and_refusals() {
    let driver = Rc::new(SimDriver::new(1, quiet()));
    run(&driver, async {
        let _server = start(Settings::default()).await;
        let client = client().await;
        assert_eq!(day(&client).await, DAY);
        let create = Request::Create {
            tenant: 1,
            generation: 1,
            retention: 30,
        };
        let created = client.call(&create).await.expect("create");
        assert!(matches!(created, Answer::Keys { oldest: DAY, .. }));
        let (day, data, today) = keys(created);
        assert_eq!(day, DAY);
        let open = Request::Open {
            tenant: 1,
            generation: 1,
        };
        assert_eq!(keys(client.call(&open).await.expect("open")).1, data);
        assert_eq!(keys(client.call(&create).await.expect("again")).1, data);
        let batch = Secret::new([9; 32]);
        let wrap = seal_batch(&today, 1, 1, DAY, 0, 7, &batch).expect("wrap");
        let unwrap = Request::Unwrap {
            tenant: 1,
            batch: 7,
            wrap,
        };
        match client.call(&unwrap).await.expect("unwrap") {
            Answer::Key(key) => assert!(key == batch),
            _ => panic!("expected a key"),
        }
        let other = Request::Create {
            tenant: 1,
            generation: 2,
            retention: 30,
        };
        assert_eq!(
            refused(&client.call(&other).await.expect("other")),
            Error::Generation
        );
        let delete = Request::Delete {
            tenant: 1,
            generation: 1,
        };
        assert!(matches!(
            client.call(&delete).await.expect("delete"),
            Answer::Done
        ));
        assert_eq!(
            refused(&client.call(&open).await.expect("open")),
            Error::Unknown
        );
        assert_eq!(
            refused(&client.call(&unwrap).await.expect("unwrap")),
            Error::Unknown
        );
        sleep(Duration::from_secs(1)).await;
    });
    let audit = driver.disk();
    let text = String::from_utf8(
        audit
            .contents(&Path::new(DIR).join("audit"))
            .expect("audit")
            .to_vec(),
    )
    .expect("text");
    assert!(text.contains(&format!(" unwrap 1 1 {DAY} 1\n")), "{text}");
    assert!(text.contains(" delete 1 1 "), "{text}");
}

#[test]
fn creates_are_paced_into_few_writes_and_answered_after_them() {
    let driver = Rc::new(SimDriver::new(2, quiet()));
    let ops = run(&driver, {
        let driver = Rc::clone(&driver);
        async move {
            let _server = start(Settings::default()).await;
            let client = Rc::new(client().await);
            let before = driver.disk_ops();
            let mut tasks = Vec::new();
            for tenant in 1..=50 {
                let client = Rc::clone(&client);
                tasks.push(spawn(async move {
                    let create = Request::Create {
                        tenant,
                        generation: 1,
                        retention: 30,
                    };
                    keys(client.call(&create).await.expect("create")).1
                }));
            }
            let mut data = Vec::new();
            for task in tasks {
                data.push(task.await);
            }
            data.sort_unstable();
            data.dedup();
            assert_eq!(data.len(), 50);
            driver.disk_ops() - before
        }
    });
    assert!(ops < 40, "{ops} disk operations for 50 creates");
}

#[test]
fn slot_writes_are_at_least_a_pace_apart() {
    let driver = Rc::new(SimDriver::new(8, quiet()));
    run(&driver, async {
        let _server = start(Settings::default()).await;
        let client = client().await;
        let begin = rt::now();
        for tenant in 1..=5 {
            let create = Request::Create {
                tenant,
                generation: 1,
                retention: 30,
            };
            keys(client.call(&create).await.expect("create"));
        }
        let spent = rt::now().saturating_duration_since(begin);
        assert!(spent >= Duration::from_secs(4), "{spent:?}");
    });
}

#[test]
fn unwraps_stop_at_the_tenant_limit() {
    let driver = Rc::new(SimDriver::new(3, quiet()));
    run(&driver, async {
        let settings = Settings {
            tenant: Rate {
                per_second: 1,
                burst: 3,
            },
            ..Settings::default()
        };
        let server = start(settings).await;
        let client = client().await;
        let create = Request::Create {
            tenant: 1,
            generation: 1,
            retention: 30,
        };
        let (_, _, today) = keys(client.call(&create).await.expect("create"));
        let wrap = seal_batch(&today, 1, 1, DAY, 0, 7, &Secret::new([9; 32])).expect("wrap");
        let unwrap = Request::Unwrap {
            tenant: 1,
            batch: 7,
            wrap,
        };
        let mut keys = 0;
        let mut busy = 0;
        for _ in 0..5 {
            match client.call(&unwrap).await.expect("unwrap") {
                Answer::Key(_) => keys += 1,
                Answer::Refused(Error::Busy) => busy += 1,
                _ => panic!("unexpected answer"),
            }
        }
        assert_eq!((keys, busy), (3, 2));
        assert_eq!(server.stats().busy, 2);
    });
}

#[test]
fn the_day_moves_once_per_day_and_never_jumps() {
    let driver = Rc::new(SimDriver::new(4, quiet()));
    run(&driver, {
        let driver = Rc::clone(&driver);
        async move {
            let settings = Settings {
                tick: Duration::from_secs(60),
                ..Settings::default()
            };
            let server = start(settings).await;
            let client = client().await;
            sleep(Duration::from_hours(17)).await;
            assert_eq!(day(&client).await, DAY + 1);
            driver.jump_wall_clock(3 * 86_400_000);
            sleep(Duration::from_mins(5)).await;
            assert_eq!(day(&client).await, DAY + 1);
            assert_eq!(server.stats().ahead, 1);
            driver.jump_wall_clock(-6 * 86_400_000);
            sleep(Duration::from_mins(5)).await;
            assert_eq!(day(&client).await, DAY + 1);
            assert_eq!(server.stats().behind, 1);
            assert_eq!(server.stats().days, 1);
        }
    });
}

#[test]
fn shreds_wait_for_settled_days_or_the_deadline() {
    let driver = Rc::new(SimDriver::new(5, quiet()));
    run(&driver, async {
        let settings = Settings {
            tick: Duration::from_secs(60),
            force_after: Duration::from_hours(10),
            ..Settings::default()
        };
        let server = start(settings).await;
        let client = client().await;
        let mut wraps = Vec::new();
        for tenant in [1, 2] {
            let create = Request::Create {
                tenant,
                generation: 1,
                retention: 1,
            };
            let (_, _, today) = keys(client.call(&create).await.expect("create"));
            let wrap =
                seal_batch(&today, tenant, 1, DAY, 0, 7, &Secret::new([9; 32])).expect("wrap");
            wraps.push(Request::Unwrap {
                tenant,
                batch: 7,
                wrap,
            });
        }
        sleep(Duration::from_hours(17)).await;
        sleep(Duration::from_mins(23 * 60 + 30)).await;
        assert_eq!(day(&client).await, DAY + 2);
        assert!(matches!(
            client.call(&wraps[0]).await.expect("unwrap"),
            Answer::Key(_)
        ));
        let settled = Request::Settled { day: DAY };
        assert!(matches!(
            client.call(&settled).await.expect("settled"),
            Answer::Done
        ));
        assert_eq!(
            refused(&client.call(&wraps[0]).await.expect("unwrap")),
            Error::Gone
        );
        assert_eq!(
            refused(&client.call(&wraps[1]).await.expect("unwrap")),
            Error::Gone
        );
        assert_eq!(server.stats().forced, 0);
    });
    let driver = Rc::new(SimDriver::new(6, quiet()));
    run(&driver, async {
        let settings = Settings {
            tick: Duration::from_secs(60),
            force_after: Duration::from_hours(1),
            ..Settings::default()
        };
        let server = start(settings).await;
        let client = client().await;
        let create = Request::Create {
            tenant: 1,
            generation: 1,
            retention: 1,
        };
        let (_, _, today) = keys(client.call(&create).await.expect("create"));
        let wrap = seal_batch(&today, 1, 1, DAY, 0, 7, &Secret::new([9; 32])).expect("wrap");
        let unwrap = Request::Unwrap {
            tenant: 1,
            batch: 7,
            wrap,
        };
        sleep(Duration::from_hours(17)).await;
        sleep(Duration::from_mins(23 * 60 + 30)).await;
        assert!(matches!(
            client.call(&unwrap).await.expect("unwrap"),
            Answer::Key(_)
        ));
        sleep(Duration::from_hours(1)).await;
        assert_eq!(
            refused(&client.call(&unwrap).await.expect("unwrap")),
            Error::Gone
        );
        assert_eq!(server.stats().forced, 1);
    });
}

#[test]
fn a_waiting_create_does_not_hold_back_answers_behind_it() {
    let driver = Rc::new(SimDriver::new(9, quiet()));
    run(&driver, async {
        let _server = start(Settings::default()).await;
        let client = Rc::new(client().await);
        let first = Request::Create {
            tenant: 1,
            generation: 1,
            retention: 30,
        };
        keys(client.call(&first).await.expect("create"));
        let creating = spawn({
            let client = Rc::clone(&client);
            async move {
                let second = Request::Create {
                    tenant: 2,
                    generation: 1,
                    retention: 30,
                };
                keys(client.call(&second).await.expect("create"));
                rt::now()
            }
        });
        sleep(Duration::from_millis(10)).await;
        let open = Request::Open {
            tenant: 1,
            generation: 1,
        };
        keys(client.call(&open).await.expect("open"));
        let opened = rt::now();
        let created = creating.await;
        assert!(
            created.saturating_duration_since(opened) >= Duration::from_millis(500),
            "{opened:?} {created:?}"
        );
    });
}

#[test]
fn more_requests_than_in_flight_slots_are_all_answered_in_order() {
    let driver = Rc::new(SimDriver::new(10, quiet()));
    run(&driver, async {
        let _server = start(Settings::default()).await;
        let stream = TcpStream::connect(addr()).await.expect("connect");
        let mut out = Plain::with_capacity(64 * 1024);
        for id in 0..3_000 {
            Request::Hello { node: 1 }.encode(id, &mut out);
        }
        let (written, _) = stream.write_all(Buf::from_slice(&out)).await;
        written.expect("write");
        let mut frames = Frames::default();
        let mut ids = Vec::new();
        while ids.len() < 3_000 {
            let (read, buf) = stream.read(Buf::new(4096)).await;
            let n = read.expect("read");
            assert!(n > 0, "closed after {} answers", ids.len());
            frames.push(&buf[..n]);
            while let Some((op, id, body)) = frames.pop().expect("frame") {
                assert!(matches!(
                    Answer::decode(op, &body).expect("answer"),
                    Answer::Hello { day: DAY, .. }
                ));
                ids.push(id);
            }
        }
        assert!(ids.iter().copied().eq(0..3_000));
    });
}

#[test]
fn a_call_past_its_deadline_times_out_and_the_client_stays_open() {
    let driver = Rc::new(SimDriver::new(11, quiet()));
    run(&driver, async {
        let silent = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 7000));
        let listener = TcpListener::bind(silent, 4).await.expect("bind");
        let held = spawn(async move { listener.accept().await.expect("accept") });
        let client = Client::new(TcpStream::connect(silent).await.expect("connect"));
        let _stream = held.await;
        let begin = rt::now();
        let answer = client
            .call_within(&Request::Hello { node: 1 }, Duration::from_secs(2))
            .await;
        assert_eq!(answer.err(), Some(Error::Timeout));
        assert!(rt::now().saturating_duration_since(begin) >= Duration::from_secs(2));
        assert!(!client.is_closed());
    });
}

#[test]
fn a_malformed_request_is_refused_and_the_connection_stays() {
    let driver = Rc::new(SimDriver::new(7, quiet()));
    run(&driver, async {
        let _server = start(Settings::default()).await;
        let stream = TcpStream::connect(addr()).await.expect("connect");
        let mut out = Plain::with_capacity(64);
        out.extend_from_slice(&5u32.to_le_bytes());
        out.push(99);
        out.extend_from_slice(&3u32.to_le_bytes());
        Request::Settled { day: 1 }.encode(4, &mut out);
        let (written, _) = stream.write_all(Buf::from_slice(&out)).await;
        written.expect("write");
        let mut frames = Frames::default();
        let mut answers = Vec::new();
        while answers.len() < 2 {
            let (read, buf) = stream.read(Buf::new(4096)).await;
            let n = read.expect("read");
            assert!(n > 0, "closed");
            frames.push(&buf[..n]);
            while let Some((op, id, body)) = frames.pop().expect("frame") {
                answers.push((id, Answer::decode(op, &body).expect("answer")));
            }
        }
        assert!(matches!(answers[0], (3, Answer::Refused(Error::Bad))));
        assert!(matches!(answers[1], (4, Answer::Done)));
    });
}

#[test]
fn the_unix_socket_serves_only_the_engine_user() {
    const KEYS: u32 = 70;
    const ENGINE: u32 = 80;
    let driver = Rc::new(SimDriver::new(9, quiet()));
    let control = Rc::clone(&driver);
    run(&driver, async move {
        let socket = Path::new("/run/keys.sock");
        control.set_uid(KEYS);
        let vault = Vault::init(Path::new(DIR), DAY).await.expect("init");
        let audit = Audit::open(Path::new(DIR)).await.expect("audit");
        let server = Server::start(vault, audit, Settings::default());
        server.listen(UnixListener::bind(socket).await.expect("bind"), ENGINE);

        control.set_uid(ENGINE);
        let engine = Client::connect(socket, KEYS).await.expect("connect");
        assert_eq!(day(&engine).await, DAY);
        assert_eq!(
            Client::connect(socket, ENGINE).await.err(),
            Some(Error::Peer)
        );

        control.set_uid(90);
        let stranger = Client::connect(socket, KEYS).await.expect("connect");
        let refused = stranger.call(&Request::Hello { node: 1 }).await;
        assert_eq!(refused.err(), Some(Error::Closed));
        assert_eq!(server.stats().refused, 1);
        assert_eq!(day(&engine).await, DAY);
        sleep(Duration::from_secs(1)).await;
    });
    let text = String::from_utf8(
        driver
            .disk()
            .contents(&Path::new(DIR).join("audit"))
            .expect("audit")
            .to_vec(),
    )
    .expect("text");
    assert!(text.contains(&format!(" refused 90 0 {DAY} 1\n")), "{text}");
}
