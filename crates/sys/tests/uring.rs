#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use sys::buf::Buf;
use sys::uring::{Done, Request, Ring};

fn scratch(name: &str) -> (PathBuf, Rc<File>) {
    let path = std::env::temp_dir().join(format!("sys-uring-{}-{name}", process::id()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("open");
    (path, Rc::new(file))
}

fn ring() -> Option<Ring> {
    match Ring::new(8) {
        Ok(ring) => Some(ring),
        Err(e) if std::env::var_os("CI").is_none() => {
            eprintln!("io_uring unavailable: {e}");
            None
        }
        Err(e) => panic!("io_uring unavailable in CI: {e}"),
    }
}

fn wait(ring: &mut Ring, count: usize) -> Vec<Done> {
    let mut out = Vec::new();
    while out.len() < count {
        ring.submit(&mut out);
        ring.complete(&mut out);
        thread::sleep(Duration::from_millis(1));
    }
    out
}

#[test]
fn writes_sync_and_reads_complete() {
    let Some(mut ring) = ring() else { return };
    let (path, file) = scratch("round-trip");
    let data = Buf::from_slice(b"ring bytes");
    let write = Request::Write {
        file: Rc::clone(&file),
        offset: 512,
        buf: data,
    };
    assert!(ring.push(1, write).is_ok());
    let done = wait(&mut ring, 1);
    assert_eq!(done[0].id, 1);
    assert_eq!(done[0].result.as_ref().ok(), Some(&10));
    assert!(
        ring.push(
            2,
            Request::SyncData {
                file: Rc::clone(&file)
            }
        )
        .is_ok()
    );
    let done = wait(&mut ring, 1);
    assert_eq!(done[0].id, 2);
    assert!(done[0].result.is_ok());
    assert!(done[0].buf.is_none());
    let read = Request::Read {
        file: Rc::clone(&file),
        offset: 512,
        buf: Buf::new(10),
    };
    assert!(ring.push(3, read).is_ok());
    let done = wait(&mut ring, 1);
    assert_eq!(done[0].result.as_ref().ok(), Some(&10));
    assert_eq!(done[0].buf.as_deref(), Some(&b"ring bytes"[..]));
    assert!(ring.idle());
    fs::remove_file(path).expect("clean up");
}

#[test]
fn a_full_ring_hands_the_request_back() {
    let Some(mut ring) = ring() else { return };
    let (path, file) = scratch("full");
    let mut accepted = 0u64;
    loop {
        let request = Request::SyncData {
            file: Rc::clone(&file),
        };
        if ring.push(accepted, request).is_err() {
            break;
        }
        accepted += 1;
    }
    assert!(accepted >= 8);
    let done = wait(&mut ring, usize::try_from(accepted).expect("fits"));
    assert!(done.iter().all(|d| d.result.is_ok()));
    assert!(ring.idle());
    fs::remove_file(path).expect("clean up");
}

#[test]
fn errors_come_back_per_request() {
    let Some(mut ring) = ring() else { return };
    let (path, file) = scratch("errors");
    drop(file);
    let read_only = Rc::new(File::open(&path).expect("open read only"));
    let write = Request::Write {
        file: read_only,
        offset: 0,
        buf: Buf::from_slice(b"x"),
    };
    assert!(ring.push(9, write).is_ok());
    let done = wait(&mut ring, 1);
    let kind = done[0].result.as_ref().err().map(io::Error::raw_os_error);
    assert_eq!(kind, Some(Some(libc::EBADF)));
    assert_eq!(done[0].buf.as_deref(), Some(&b"x"[..]));
    fs::remove_file(path).expect("clean up");
}

#[test]
fn dropping_the_ring_finishes_writes_in_flight() {
    let Some(mut ring) = ring() else { return };
    let (path, file) = scratch("drop");
    for i in 0..8u8 {
        let write = Request::Write {
            file: Rc::clone(&file),
            offset: u64::from(i) * 4096,
            buf: Buf::from_slice(&[i; 4096]),
        };
        assert!(ring.push(u64::from(i), write).is_ok());
    }
    let mut out = Vec::new();
    ring.submit(&mut out);
    drop(ring);
    drop(file);
    let data = fs::read(&path).expect("read");
    assert_eq!(data.len(), 8 * 4096);
    for (i, chunk) in data.chunks(4096).enumerate() {
        assert!(chunk.iter().all(|&b| usize::from(b) == i));
    }
    fs::remove_file(path).expect("clean up");
}
