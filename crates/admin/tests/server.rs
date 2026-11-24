use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use admin::{Code, Handler, Reply, Request, call, serve};
use rt::sim::{Config, SimDriver};
use rt::{Buf, Runtime, UnixListener, UnixStream, sleep, yield_now};

const ENGINE: u32 = 80;
const ROOT: u32 = 0;
const SOCKET: &str = "/run/admin.sock";

struct Status(Cell<u32>);

impl Handler for Status {
    async fn handle(&self, request: Request) -> Reply {
        match request {
            Request::Status => {
                yield_now().await;
                self.0.set(self.0.get() + 1);
                Reply::new(Code::Ok, format!("calls {}", self.0.get()))
            }
        }
    }
}

async fn started(control: &SimDriver) -> admin::Admin {
    control.set_uid(ENGINE);
    let listener = UnixListener::bind(Path::new(SOCKET)).await.expect("bind");
    serve(listener, vec![ENGINE, ROOT], Rc::new(Status(Cell::new(0))))
}

async fn closed(stream: &UnixStream) -> bool {
    let (read, _) = stream.read(Buf::new(64)).await;
    matches!(read, Ok(0) | Err(_))
}

#[test]
fn status_answers_the_engine_user_and_root_only() {
    let driver = Rc::new(SimDriver::new(3, Config::default()));
    let control = Rc::clone(&driver);
    Runtime::new(driver).block_on(async move {
        let admin = started(&control).await;
        let socket = Path::new(SOCKET);
        for (n, uid) in [(1, ENGINE), (2, ROOT)] {
            control.set_uid(uid);
            let reply = call(socket, ENGINE, &Request::Status).await.expect("call");
            assert_eq!(reply, Reply::new(Code::Ok, format!("calls {n}")));
        }
        control.set_uid(90);
        let (stranger, _) = UnixStream::connect(socket).await.expect("connect");
        assert!(closed(&stranger).await);
        assert!(call(socket, 90, &Request::Status).await.is_err());
        sleep(Duration::from_millis(10)).await;
        let stats = admin.stats();
        assert_eq!((stats.accepted, stats.refused, stats.requests), (2, 2, 2));
        admin.close().await;
    });
}

#[test]
fn bad_frames_are_refused_or_closed() {
    let driver = Rc::new(SimDriver::new(4, Config::default()));
    let control = Rc::clone(&driver);
    Runtime::new(driver).block_on(async move {
        let admin = started(&control).await;
        let (stream, _) = UnixStream::connect(Path::new(SOCKET))
            .await
            .expect("connect");
        let (written, _) = stream.write_all(Buf::from_slice(&[0, 0, 0, 2, 9, 1])).await;
        written.expect("write");
        let mut frames = admin::Frames::default();
        let body = loop {
            if let Some(body) = frames.pop().expect("frame") {
                break body;
            }
            let (read, buf) = stream.read(Buf::new(64)).await;
            frames.push(&buf[..read.expect("read")]);
        };
        let reply = Reply::decode(&body).expect("reply");
        assert_eq!(reply.code, Code::Refused);
        assert_eq!(reply.text, "unknown protocol version");
        let (written, _) = stream.write_all(Buf::from_slice(&[0, 0, 0, 0])).await;
        written.expect("write");
        assert!(closed(&stream).await);
        sleep(Duration::from_millis(10)).await;
        assert_eq!(admin.stats().malformed, 2);
        assert_eq!(admin.sessions(), 0);
        admin.close().await;
    });
}

#[test]
fn sessions_are_capped_and_end_on_close() {
    let driver = Rc::new(SimDriver::new(5, Config::default()));
    let control = Rc::clone(&driver);
    Runtime::new(driver).block_on(async move {
        let admin = started(&control).await;
        let socket = Path::new(SOCKET);
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(UnixStream::connect(socket).await.expect("connect").0);
        }
        sleep(Duration::from_millis(10)).await;
        assert_eq!(admin.sessions(), 4);
        let (fifth, _) = UnixStream::connect(socket).await.expect("connect");
        assert!(closed(&fifth).await);
        assert_eq!(admin.stats().full, 1);
        admin.close().await;
        for stream in &held {
            assert!(closed(stream).await);
        }
    });
}

#[test]
fn idle_sessions_end() {
    let driver = Rc::new(SimDriver::new(6, Config::default()));
    let control = Rc::clone(&driver);
    Runtime::new(driver).block_on(async move {
        let admin = started(&control).await;
        let (stream, _) = UnixStream::connect(Path::new(SOCKET))
            .await
            .expect("connect");
        sleep(Duration::from_secs(61)).await;
        assert!(closed(&stream).await);
        assert_eq!(admin.sessions(), 0);
        admin.close().await;
    });
}
