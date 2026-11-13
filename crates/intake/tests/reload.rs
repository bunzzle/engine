use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use intake::{Watch, watch};
use rt::sim::{Config, SimDriver, check};
use rt::{Buf, File, OpenOptions, Runtime, Signal, Signals, sleep};
use tls::Certs;
use tls::rustls::pki_types::CertificateDer;
use tls::rustls::pki_types::pem::PemObject;

const A: &[u8] = include_bytes!("data/a.pem");
const B: &[u8] = include_bytes!("data/b.pem");
const KEY_A: &str = "302e020100300506032b65700422042098cded488e5305ce6644e0188d522eac4a19a7722043c25e621026562f2dda6d";
const KEY_B: &str = "302e020100300506032b6570042204202da3be782d1298201aa29a0351162606dd1c71e074692703192e346cb2115026";
const CHAIN: &str = "/chain.pem";
const KEY: &str = "/key.pem";

fn pem(hex: &str) -> Vec<u8> {
    let der: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let label = "PRIVATE KEY";
    let body = dkim::base64::encode(&der);
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n").into_bytes()
}

fn der(chain: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(chain).expect("pem").to_vec()
}

async fn write_file(path: &str, data: &[u8]) {
    let options = OpenOptions {
        write: true,
        create: true,
        truncate: true,
        ..OpenOptions::default()
    };
    let file = File::open(path, &options).await.expect("open");
    let (written, _) = file.write_all_at(Buf::from_slice(data), 0).await;
    written.expect("write");
    file.sync_data().await.expect("sync");
}

async fn settle(watch: &Watch, reloaded: u64, failed: u64) {
    for _ in 0..1_000 {
        if watch.reloaded() == reloaded && watch.failed() == failed {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "reloaded {} failed {}, wanted {reloaded} and {failed}",
        watch.reloaded(),
        watch.failed()
    );
}

#[test]
fn hangup_reloads_certificates_and_keeps_the_old_pair_on_failure() {
    check(0..20, |seed| {
        let driver = Rc::new(SimDriver::new(seed, Config::default()));
        let control = Rc::clone(&driver);
        Runtime::new(driver).block_on(async move {
            write_file(CHAIN, A).await;
            write_file(KEY, &pem(KEY_A)).await;
            let certs = Arc::new(
                Certs::read(Path::new(CHAIN), Path::new(KEY))
                    .await
                    .expect("read"),
            );
            let signals = Signals::listen(&[Signal::Hangup, Signal::Terminate])
                .await
                .expect("listen");
            let watch = watch(
                signals,
                Arc::clone(&certs),
                PathBuf::from(CHAIN),
                PathBuf::from(KEY),
            );
            write_file(CHAIN, B).await;
            control.raise(Signal::Hangup);
            settle(&watch, 0, 1).await;
            assert_eq!(certs.current().cert[0].to_vec(), der(A));
            write_file(KEY, &pem(KEY_B)).await;
            control.raise(Signal::Hangup);
            settle(&watch, 1, 1).await;
            assert_eq!(certs.current().cert[0].to_vec(), der(B));
            control.raise(Signal::Terminate);
            assert_eq!(
                watch.stop_requested().await.expect("signal"),
                Signal::Terminate
            );
            control.raise(Signal::Hangup);
            settle(&watch, 2, 1).await;
            watch.close().await;
        });
    });
}

#[test]
fn a_failed_signal_receive_requests_a_stop_with_the_error() {
    check(0..20, |seed| {
        let driver = Rc::new(SimDriver::new(seed, Config::default()));
        let control = Rc::clone(&driver);
        Runtime::new(driver).block_on(async move {
            write_file(CHAIN, A).await;
            write_file(KEY, &pem(KEY_A)).await;
            let certs = Arc::new(
                Certs::read(Path::new(CHAIN), Path::new(KEY))
                    .await
                    .expect("read"),
            );
            let signals = Signals::listen(&[Signal::Hangup, Signal::Terminate])
                .await
                .expect("listen");
            let watch = watch(signals, certs, PathBuf::from(CHAIN), PathBuf::from(KEY));
            control.fail_signals();
            assert!(watch.stop_requested().await.is_err());
            watch.close().await;
        });
    });
}
