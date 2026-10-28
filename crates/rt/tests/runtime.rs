mod common;

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use common::MemDriver;
use rt::{
    Buf, Elapsed, File, OpenOptions, Runtime, TcpListener, channel, now, sleep, spawn, timeout,
    wall_ms, yield_now,
};

fn runtime() -> (Runtime, Rc<MemDriver>) {
    let driver = Rc::new(MemDriver::default());
    (Runtime::new(driver.clone()), driver)
}

fn create() -> OpenOptions {
    OpenOptions {
        read: true,
        write: true,
        create: true,
        ..OpenOptions::default()
    }
}

#[test]
fn aligned_buffers_start_on_their_alignment() {
    for align in [1, 512, 4096] {
        let buf = Buf::aligned(8192, align);
        assert_eq!(buf.as_ptr().addr() % align, 0);
        assert_eq!(buf.capacity(), 8192);
        assert!(buf.is_empty());
    }
}

#[test]
fn buffers_fill_up_to_capacity() {
    let mut buf = Buf::new(4);
    assert_eq!(buf.extend_from_slice(b"abcdef"), 4);
    assert_eq!(&buf[..], b"abcd");
    assert_eq!(buf.remaining(), 0);
    buf.set_len(2);
    assert_eq!(&buf[..], b"ab");
    buf.clear();
    assert!(buf.is_empty());
}

#[test]
fn block_on_returns_the_value() {
    let (rt, _) = runtime();
    assert_eq!(rt.block_on(async { 7 }), 7);
}

#[test]
fn tasks_run_in_a_deterministic_order() {
    let (rt, _) = runtime();
    let log = Rc::new(RefCell::new(Vec::new()));
    let out = log.clone();
    rt.block_on(async move {
        let mut handles = Vec::new();
        for name in ["a", "b"] {
            let log = out.clone();
            handles.push(spawn(async move {
                for step in 0..3 {
                    log.borrow_mut().push(format!("{name}{step}"));
                    yield_now().await;
                }
            }));
        }
        for handle in handles {
            handle.await;
        }
    });
    assert_eq!(*log.borrow(), ["a0", "b0", "a1", "b1", "a2", "b2"]);
}

#[test]
fn join_handles_return_task_output() {
    let (rt, _) = runtime();
    let sum = rt.block_on(async {
        let a = spawn(async { 2 });
        let b = spawn(async { 3 });
        a.await + b.await
    });
    assert_eq!(sum, 5);
}

#[test]
fn sleep_advances_the_driver_clock() {
    let (rt, _) = runtime();
    let elapsed = rt.block_on(async {
        let start = now();
        sleep(Duration::from_secs(5)).await;
        now().saturating_duration_since(start)
    });
    assert_eq!(elapsed, Duration::from_secs(5));
}

#[test]
fn timers_fire_in_deadline_order() {
    let (rt, _) = runtime();
    let log = Rc::new(RefCell::new(Vec::new()));
    let out = log.clone();
    rt.block_on(async move {
        let mut handles = Vec::new();
        for (name, secs) in [("late", 3), ("early", 1), ("middle", 2)] {
            let log = out.clone();
            handles.push(spawn(async move {
                sleep(Duration::from_secs(secs)).await;
                log.borrow_mut().push(name);
            }));
        }
        for handle in handles {
            handle.await;
        }
    });
    assert_eq!(*log.borrow(), ["early", "middle", "late"]);
}

#[test]
fn timeout_reports_elapsed_or_value() {
    let (rt, _) = runtime();
    rt.block_on(async {
        let late = timeout(Duration::from_secs(1), sleep(Duration::from_secs(5))).await;
        assert_eq!(late, Err(Elapsed));
        let early = timeout(Duration::from_secs(5), async {
            sleep(Duration::from_secs(1)).await;
            9
        })
        .await;
        assert_eq!(early, Ok(9));
    });
}

#[test]
fn wall_clock_comes_from_the_driver() {
    let (rt, _) = runtime();
    let (before, after) = rt.block_on(async {
        let before = wall_ms();
        sleep(Duration::from_secs(2)).await;
        (before, wall_ms())
    });
    assert_eq!(after - before, 2_000);
}

#[test]
fn files_round_trip_through_the_driver() {
    let (rt, driver) = runtime();
    rt.block_on(async {
        let file = File::open("/data", &create()).await.expect("open");
        file.allocate(16).await.expect("allocate");
        let (written, _) = file.write_all_at(Buf::from_slice(b"hello"), 4).await;
        written.expect("write");
        file.sync_data().await.expect("sync");
        let (read, buf) = file.read_at(Buf::new(5), 4).await;
        assert_eq!(read.expect("read"), 5);
        assert_eq!(&buf[..], b"hello");
        let stat = file.stat().await.expect("stat");
        assert_eq!(stat.len, 16);
        assert_eq!(stat.sector_size, 4096);
    });
    assert_eq!(driver.released(), 1);
}

#[test]
fn opening_a_missing_file_without_create_fails() {
    let (rt, _) = runtime();
    let result = rt.block_on(async { File::open("/missing", &OpenOptions::default()).await });
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::NotFound)
    );
}

#[test]
fn dropping_a_pending_operation_cancels_it() {
    let (rt, driver) = runtime();
    rt.block_on(async {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 2525));
        let listener = TcpListener::bind(addr, 16).await.expect("bind");
        assert_eq!(listener.local_addr().await.expect("addr"), addr);
        let accept = timeout(Duration::from_secs(1), listener.accept()).await;
        assert!(accept.is_err());
    });
    assert_eq!(driver.cancelled(), 1);
    assert_eq!(driver.pending(), 0);
    assert_eq!(driver.released(), 1);
}

#[test]
fn channels_wake_the_loop_from_another_thread() {
    let (rt, _) = runtime();
    let (tx, mut rx) = channel::<u32>();
    let sender = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        tx.send(42).expect("send");
    });
    let got = rt.block_on(async move { rx.recv().await });
    sender.join().expect("join");
    assert_eq!(got, Some(42));
}

#[test]
fn channels_close_when_every_sender_is_gone() {
    let (rt, _) = runtime();
    let (tx, mut rx) = channel::<u32>();
    let extra = tx.clone();
    tx.send(1).expect("send");
    drop(tx);
    drop(extra);
    let got = rt.block_on(async move { (rx.recv().await, rx.recv().await) });
    assert_eq!(got, (Some(1), None));
}

#[test]
fn sending_to_a_dropped_receiver_returns_the_value() {
    let (tx, rx) = channel::<u32>();
    drop(rx);
    assert_eq!(tx.send(5), Err(5));
}
