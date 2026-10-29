#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;
use std::{fs, io, process, thread};

use rt::{
    Buf, File, Native, OpenOptions, Runtime, TcpListener, TcpStream, UdpSocket, channel, now,
    sleep, spawn, sync_dir, timeout,
};

fn run<T: 'static>(future: impl Future<Output = T> + 'static) -> T {
    let driver = Rc::new(Native::new().expect("native driver"));
    Runtime::new(driver).block_on(future)
}

fn drivers() -> Vec<(&'static str, Native)> {
    vec![
        ("auto", Native::new().expect("native driver")),
        ("plain", Native::plain().expect("plain driver")),
    ]
}

fn options() -> OpenOptions {
    OpenOptions {
        read: true,
        write: true,
        create: true,
        ..OpenOptions::default()
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rt-native-{}-{name}", process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn local() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[test]
fn files_write_sync_and_read_back() {
    for (name, driver) in drivers() {
        let dir = scratch(&format!("files-{name}"));
        let path = dir.join("data");
        let target = path.clone();
        Runtime::new(Rc::new(driver)).block_on(async move {
            let file = File::open(&target, &options()).await.expect("open");
            file.allocate(1 << 20).await.expect("allocate");
            let (written, _) = file
                .write_all_at(Buf::from_slice(b"durable bytes"), 4096)
                .await;
            written.expect("write");
            file.sync_data().await.expect("sync");
            sync_dir(target.parent().expect("parent"))
                .await
                .expect("sync dir");
            let stat = file.stat().await.expect("stat");
            assert_eq!(stat.len, 1 << 20);
            assert!(stat.sector_size.is_power_of_two());
            let (read, buf) = file.read_at(Buf::new(13), 4096).await;
            assert_eq!(read.expect("read"), 13);
            assert_eq!(&buf[..], b"durable bytes");
        });
        assert_eq!(
            &fs::read(&path).expect("std read")[4096..4109],
            b"durable bytes"
        );
        fs::remove_dir_all(dir).expect("clean up");
    }
}

#[test]
fn more_writes_than_the_ring_holds_all_complete() {
    for (name, driver) in drivers() {
        let dir = scratch(&format!("many-{name}"));
        let path = dir.join("data");
        let target = path.clone();
        Runtime::new(Rc::new(driver)).block_on(async move {
            let file = Rc::new(File::open(&target, &options()).await.expect("open"));
            let tasks: Vec<_> = (0..1000u16)
                .map(|i| {
                    let file = Rc::clone(&file);
                    spawn(async move {
                        let (written, _) = file
                            .write_all_at(Buf::from_slice(&i.to_le_bytes()), u64::from(i) * 2)
                            .await;
                        written.expect("write");
                    })
                })
                .collect();
            for task in tasks {
                task.await;
            }
            file.sync_data().await.expect("sync");
        });
        let data = fs::read(&path).expect("std read");
        for i in 0..1000u16 {
            let at = usize::from(i) * 2;
            assert_eq!(&data[at..at + 2], &i.to_le_bytes());
        }
        fs::remove_dir_all(dir).expect("clean up");
    }
}

#[test]
fn a_dropped_file_operation_leaves_the_driver_usable() {
    for (name, driver) in drivers() {
        let dir = scratch(&format!("dropped-{name}"));
        let target = dir.join("data");
        Runtime::new(Rc::new(driver)).block_on(async move {
            let file = File::open(&target, &options()).await.expect("open");
            let write = file.write_all_at(Buf::from_slice(&vec![7u8; 1 << 16]), 0);
            let _ = timeout(Duration::ZERO, write).await;
            let (written, _) = file.write_all_at(Buf::from_slice(b"after"), 1 << 17).await;
            written.expect("write");
            let (read, buf) = file.read_at(Buf::new(5), 1 << 17).await;
            assert_eq!(read.expect("read"), 5);
            assert_eq!(&buf[..], b"after");
        });
        fs::remove_dir_all(dir).expect("clean up");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn ci_runs_files_on_the_ring() {
    let native = Native::new().expect("native driver");
    if std::env::var_os("CI").is_some() {
        assert!(native.uses_ring());
    }
    assert!(!Native::plain().expect("plain driver").uses_ring());
}

#[test]
fn tcp_echo() {
    run(async {
        let listener = TcpListener::bind(local(), 16).await.expect("bind");
        let addr = listener.local_addr().await.expect("addr");
        let server = spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut total = Vec::new();
            loop {
                let (read, buf) = stream.read(Buf::new(7)).await;
                if read.expect("read") == 0 {
                    break;
                }
                total.extend_from_slice(&buf);
            }
            let (written, _) = stream.write_all(Buf::from_slice(&total)).await;
            written.expect("echo");
            stream.shutdown().await.expect("shutdown");
        });
        let client = TcpStream::connect(addr).await.expect("connect");
        let message = vec![42u8; 300_000];
        let (written, _) = client.write_all(Buf::from_slice(&message)).await;
        written.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut echoed = Vec::new();
        loop {
            let (read, buf) = client.read(Buf::new(65536)).await;
            if read.expect("read") == 0 {
                break;
            }
            echoed.extend_from_slice(&buf);
        }
        server.await;
        assert_eq!(echoed, message);
    });
}

#[test]
fn a_refused_connect_reports_an_error() {
    run(async {
        let listener = TcpListener::bind(local(), 1).await.expect("bind");
        let addr = listener.local_addr().await.expect("addr");
        drop(listener);
        let refused = TcpStream::connect(addr).await;
        let kind = refused.err().map(|e| e.kind());
        assert_eq!(kind, Some(io::ErrorKind::ConnectionRefused));
    });
}

#[test]
fn udp_round_trip() {
    run(async {
        let a = UdpSocket::bind(local()).await.expect("bind a");
        let b = UdpSocket::bind(local()).await.expect("bind b");
        let to = b.local_addr().await.expect("addr b");
        let from = a.local_addr().await.expect("addr a");
        let task = spawn(async move { b.recv_from(Buf::new(64)).await });
        let (sent, _) = a.send_to(Buf::from_slice(b"ping"), to).await;
        assert_eq!(sent.expect("send"), 4);
        let (received, buf) = task.await;
        assert_eq!(received.expect("recv"), (4, from));
        assert_eq!(&buf[..], b"ping");
    });
}

#[test]
fn timers_wait_at_least_their_duration() {
    run(async {
        let start = now();
        sleep(Duration::from_millis(30)).await;
        assert!(now().saturating_duration_since(start) >= Duration::from_millis(30));
    });
}

#[test]
fn another_thread_wakes_the_runtime() {
    let (sender, mut receiver) = channel();
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        sender.send(7u32).expect("send");
    });
    let value = run(async move { receiver.recv().await });
    worker.join().expect("join");
    assert_eq!(value, Some(7));
}
