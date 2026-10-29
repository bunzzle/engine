use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Disk, Faults, SimDriver, check};
use rt::{
    Buf, File, OpenOptions, Runtime, TcpListener, TcpStream, UdpSocket, now, sleep, spawn,
    sync_dir, timeout, wall_ms,
};

const MILLION: u32 = 1_000_000;

fn create() -> OpenOptions {
    OpenOptions {
        read: true,
        write: true,
        create: true,
        ..OpenOptions::default()
    }
}

fn existing() -> OpenOptions {
    OpenOptions {
        read: true,
        write: true,
        ..OpenOptions::default()
    }
}

fn faults(edit: impl FnOnce(&mut Faults)) -> Config {
    let mut config = Config::default();
    edit(&mut config.faults);
    config
}

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

async fn write_file(path: &'static str, data: &'static [u8], sync: bool) {
    let file = File::open(path, &create()).await.expect("open");
    let (written, _) = file.write_all_at(Buf::from_slice(data), 0).await;
    written.expect("write");
    if sync {
        file.sync_data().await.expect("sync");
    }
    sync_dir("/").await.expect("sync dir");
}

fn trace(seed: u64) -> Vec<(u64, u32)> {
    let driver = Rc::new(SimDriver::new(seed, Config::default()));
    let log = Rc::new(RefCell::new(Vec::new()));
    let out = log.clone();
    run(&driver, async move {
        let mut tasks = Vec::new();
        for task in 0..4u32 {
            let log = out.clone();
            tasks.push(spawn(async move {
                let path = format!("/f{task}");
                let file = File::open(&path, &create()).await.expect("open");
                for step in 0..3u64 {
                    let (written, _) = file.write_at(Buf::from_slice(b"x"), step).await;
                    written.expect("write");
                    file.sync_data().await.expect("sync");
                    log.borrow_mut().push((now().as_nanos(), task));
                }
            }));
        }
        for task in tasks {
            task.await;
        }
    });
    log.take()
}

#[test]
fn same_seed_gives_the_same_run() {
    check(0..20, |seed| assert_eq!(trace(seed), trace(seed)));
}

#[test]
fn different_seeds_give_different_runs() {
    assert_ne!(trace(1), trace(2));
}

#[test]
fn synced_data_survives_a_crash() {
    check(0..20, |seed| {
        let driver = Rc::new(SimDriver::new(seed, faults(|f| f.crash_keep = 0)));
        run(&driver, write_file("/data", b"durable", true));
        let disk = driver.crash();
        assert_eq!(disk.contents(Path::new("/data")), Some(&b"durable"[..]));
    });
}

#[test]
fn unsynced_data_is_lost_when_the_crash_keeps_nothing() {
    let driver = Rc::new(SimDriver::new(3, faults(|f| f.crash_keep = 0)));
    run(&driver, write_file("/data", b"volatile", false));
    let disk = driver.crash();
    assert_eq!(disk.contents(Path::new("/data")), Some(&b""[..]));
}

#[test]
fn unsynced_data_survives_when_the_crash_keeps_everything() {
    let driver = Rc::new(SimDriver::new(3, faults(|f| f.crash_keep = MILLION)));
    run(&driver, write_file("/data", b"kept", false));
    let disk = driver.crash();
    assert_eq!(disk.contents(Path::new("/data")), Some(&b"kept"[..]));
}

#[test]
fn disk_operations_stop_after_the_halt_point() {
    let writes = |halt_after| {
        let config = Config {
            halt_after,
            ..faults(|f| f.crash_keep = MILLION)
        };
        let driver = Rc::new(SimDriver::new(5, config));
        let done = Rc::new(RefCell::new(0u64));
        let out = done.clone();
        run(&driver, async move {
            spawn(async move {
                let file = File::open("/data", &create()).await.expect("open");
                for step in 0..5u64 {
                    let (written, _) = file.write_at(Buf::from_slice(b"y"), step).await;
                    written.expect("write");
                    *out.borrow_mut() += 1;
                }
            });
            sleep(Duration::from_secs(1)).await;
        });
        (
            driver.disk_ops(),
            driver.is_halted(),
            done.take(),
            driver.crash(),
        )
    };
    let (ops, halted, done, _) = writes(None);
    assert_eq!((ops, halted, done), (5, false, 5));
    let (ops, halted, done, disk) = writes(Some(3));
    assert_eq!((ops, halted), (3, true));
    assert!(done <= 3);
    assert_eq!(disk.contents(Path::new("/data")), None);
}

#[test]
fn new_files_need_a_directory_sync_to_survive() {
    let driver = Rc::new(SimDriver::new(4, Config::default()));
    run(&driver, async {
        let file = File::open("/dir/new", &create()).await.expect("open");
        file.sync_data().await.expect("sync");
    });
    assert!(!driver.crash().exists(Path::new("/dir/new")));
    run(&driver, async { sync_dir("/dir").await.expect("sync dir") });
    assert!(driver.crash().exists(Path::new("/dir/new")));
}

#[test]
fn torn_writes_keep_a_prefix_of_whole_units() {
    check(0..20, |seed| {
        let config = faults(|f| f.torn_write = MILLION);
        let driver = Rc::new(SimDriver::new(seed, config.clone()));
        run(&driver, async {
            let file = File::open("/data", &create()).await.expect("open");
            let (written, _) = file.write_all_at(Buf::from_slice(&[1; 4096]), 0).await;
            written.expect("write");
            file.sync_data().await.expect("sync");
            sync_dir("/").await.expect("sync dir");
            let (written, _) = file.write_all_at(Buf::from_slice(&[2; 4096]), 0).await;
            written.expect("write");
        });
        let disk = driver.crash();
        let data = disk.contents(Path::new("/data")).expect("file");
        let cut = data.iter().position(|b| *b == 1).expect("old data remains");
        assert!(cut > 0 && cut < 4096 && cut % 512 == 0, "cut at {cut}");
        assert!(data[..cut].iter().all(|b| *b == 2));
        assert!(data[cut..].iter().all(|b| *b == 1));
    });
}

#[test]
fn failed_sync_reports_an_error() {
    let driver = Rc::new(SimDriver::new(5, faults(|f| f.sync_error = MILLION)));
    let result = run(&driver, async {
        let file = File::open("/data", &create()).await.expect("open");
        let (written, _) = file.write_at(Buf::from_slice(b"x"), 0).await;
        written.expect("write");
        file.sync_data().await
    });
    assert!(result.is_err());
}

#[test]
fn lost_writes_report_success_but_never_land() {
    let driver = Rc::new(SimDriver::new(
        6,
        faults(|f| {
            f.lost_write = MILLION;
            f.crash_keep = 0;
        }),
    ));
    run(&driver, write_file("/data", b"gone", true));
    let disk = driver.crash();
    assert_eq!(disk.contents(Path::new("/data")), Some(&[0u8; 4][..]));
}

#[test]
fn misdirected_writes_land_in_another_sector() {
    let driver = Rc::new(SimDriver::new(
        7,
        faults(|f| {
            f.misdirected_write = MILLION;
            f.crash_keep = 0;
        }),
    ));
    run(&driver, async {
        let file = File::open("/data", &create()).await.expect("open");
        let (written, _) = file.write_all_at(Buf::from_slice(&[0; 8192]), 0).await;
        written.expect("write");
        file.sync_data().await.expect("sync");
        sync_dir("/").await.expect("sync dir");
        let (written, _) = file.write_all_at(Buf::from_slice(&[9; 4096]), 0).await;
        written.expect("write");
        file.sync_data().await.expect("sync");
    });
    let disk = driver.crash();
    let data = disk.contents(Path::new("/data")).expect("file");
    assert!(data[..4096].iter().all(|b| *b == 0));
    assert!(data[4096..].iter().all(|b| *b == 9));
}

#[test]
fn read_corruption_flips_a_bit() {
    let driver = Rc::new(SimDriver::new(8, faults(|f| f.read_corruption = MILLION)));
    let read = run(&driver, async {
        let file = File::open("/data", &create()).await.expect("open");
        let (written, _) = file.write_all_at(Buf::from_slice(&[0; 64]), 0).await;
        written.expect("write");
        let (read, buf) = file.read_at(Buf::new(64), 0).await;
        read.expect("read");
        buf.to_vec()
    });
    let flipped: u32 = read.iter().map(|b| b.count_ones()).sum();
    assert_eq!(flipped, 1);
}

#[test]
fn a_restarted_driver_reads_the_crashed_disk() {
    let first = Rc::new(SimDriver::new(9, faults(|f| f.crash_keep = 0)));
    run(&first, write_file("/data", b"before", true));
    let disk: Disk = first.crash();
    let second = Rc::new(SimDriver::with_disk(10, Config::default(), disk));
    let data = run(&second, async {
        let file = File::open("/data", &existing()).await.expect("open");
        let (read, buf) = file.read_at(Buf::new(16), 0).await;
        read.expect("read");
        buf.to_vec()
    });
    assert_eq!(data, b"before");
}

#[test]
fn sector_size_is_reported_by_stat() {
    let config = Config {
        sector_size: 512,
        ..Config::default()
    };
    let driver = Rc::new(SimDriver::new(11, config));
    let stat = run(&driver, async {
        let file = File::open("/data", &create()).await.expect("open");
        file.allocate(1 << 20).await.expect("allocate");
        file.stat().await.expect("stat")
    });
    assert_eq!(stat.sector_size, 512);
    assert_eq!(stat.len, 1 << 20);
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), port))
}

#[test]
fn tcp_echo_between_tasks() {
    check(0..20, |seed| {
        let driver = Rc::new(SimDriver::new(seed, Config::default()));
        let reply = run(&driver, async {
            let listener = TcpListener::bind(addr(25), 16).await.expect("bind");
            let server = spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let (read, buf) = stream.read(Buf::new(64)).await;
                read.expect("read");
                let (written, _) = stream.write_all(buf).await;
                written.expect("write");
            });
            let client = TcpStream::connect(addr(25)).await.expect("connect");
            let (written, _) = client.write_all(Buf::from_slice(b"EHLO")).await;
            written.expect("write");
            let (read, buf) = client.read(Buf::new(64)).await;
            read.expect("read");
            server.await;
            buf.to_vec()
        });
        assert_eq!(reply, b"EHLO");
    });
}

#[test]
fn closed_streams_read_end_of_file() {
    let driver = Rc::new(SimDriver::new(12, Config::default()));
    let n = run(&driver, async {
        let listener = TcpListener::bind(addr(25), 16).await.expect("bind");
        let server = spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            drop(stream);
        });
        let client = TcpStream::connect(addr(25)).await.expect("connect");
        server.await;
        let (read, _) = client.read(Buf::new(8)).await;
        read.expect("read")
    });
    assert_eq!(n, 0);
}

#[test]
fn connecting_without_a_listener_is_refused() {
    let driver = Rc::new(SimDriver::new(13, Config::default()));
    let result = run(&driver, async {
        TcpStream::connect(addr(25)).await.map(|_| ())
    });
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::ConnectionRefused)
    );
}

#[test]
fn unreachable_hosts_time_out() {
    let driver = Rc::new(SimDriver::new(14, Config::default()));
    driver.set_reachable(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), false);
    let result = run(&driver, async {
        let _listener = TcpListener::bind(addr(25), 16).await.expect("bind");
        timeout(Duration::from_secs(30), TcpStream::connect(addr(25))).await
    });
    assert!(result.is_err());
}

#[test]
fn connection_resets_fail_sends() {
    let driver = Rc::new(SimDriver::new(15, faults(|f| f.connection_reset = MILLION)));
    let result = run(&driver, async {
        let listener = TcpListener::bind(addr(25), 16).await.expect("bind");
        let _server = spawn(async move { listener.accept().await.map(|_| ()) });
        let client = TcpStream::connect(addr(25)).await.expect("connect");
        let (written, _) = client.write(Buf::from_slice(b"x")).await;
        written
    });
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::ConnectionReset)
    );
}

#[test]
fn udp_datagrams_arrive_or_are_dropped() {
    let driver = Rc::new(SimDriver::new(16, Config::default()));
    let (n, from) = run(&driver, async {
        let a = UdpSocket::bind(addr(53)).await.expect("bind");
        let b = UdpSocket::bind(addr(5353)).await.expect("bind");
        let (sent, _) = b.send_to(Buf::from_slice(b"query"), addr(53)).await;
        sent.expect("send");
        let (received, _) = a.recv_from(Buf::new(512)).await;
        received.expect("recv")
    });
    assert_eq!((n, from), (5, addr(5353)));

    let lossy = Rc::new(SimDriver::new(17, faults(|f| f.packet_loss = MILLION)));
    let lost = run(&lossy, async {
        let a = UdpSocket::bind(addr(53)).await.expect("bind");
        let b = UdpSocket::bind(addr(5353)).await.expect("bind");
        let (sent, _) = b.send_to(Buf::from_slice(b"query"), addr(53)).await;
        sent.expect("send");
        timeout(Duration::from_secs(5), a.recv_from(Buf::new(512))).await
    });
    assert!(lost.is_err());
}

#[test]
fn time_only_moves_when_the_loop_waits() {
    let driver = Rc::new(SimDriver::new(18, Config::default()));
    let (start, busy, slept) = run(&driver, async {
        let start = now();
        let mut x = 0u64;
        for i in 0..100_000 {
            x = x.wrapping_add(i);
        }
        assert!(x > 0);
        let busy = now();
        sleep(Duration::from_secs(60)).await;
        (start, busy, now())
    });
    assert_eq!(start, busy);
    assert_eq!(
        slept.saturating_duration_since(start),
        Duration::from_secs(60)
    );
}

#[test]
fn the_wall_clock_can_jump() {
    let driver = Rc::new(SimDriver::new(19, Config::default()));
    let before = run(&driver, async { wall_ms() });
    driver.jump_wall_clock(-3_600_000);
    let back = run(&driver, async { wall_ms() });
    driver.jump_wall_clock(7_200_000);
    let ahead = run(&driver, async { wall_ms() });
    assert_eq!(before - back, 3_600_000);
    assert_eq!(ahead - before, 3_600_000);
}

#[test]
#[should_panic(expected = "simulation stalled")]
fn a_stalled_simulation_panics() {
    let driver = Rc::new(SimDriver::new(20, Config::default()));
    run(&driver, async {
        let listener = TcpListener::bind(addr(25), 16).await.expect("bind");
        listener.accept().await.map(|_| ())
    })
    .ok();
}

#[test]
#[should_panic(expected = "bad seed")]
fn failing_seeds_are_reported() {
    check(0..5, |seed| assert!(seed % 5 != 2, "bad seed"));
}
