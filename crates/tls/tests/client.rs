use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;

use aws_lc_rs::digest::{SHA256, SHA512, digest};
use rt::sim::{Config, SimDriver};
use rt::{Runtime, TcpListener, TcpStream, spawn};
use tls::rustls::HandshakeKind;
use tls::rustls::pki_types::CertificateDer;
use tls::rustls::pki_types::pem::PemObject;
use tls::rustls::server::ParsedCertificate;
use tls::{Acceptor, Certs, Connector, Tlsa, Verify, simulated};

const CA: &[u8] = include_bytes!("data/ca.pem");
const A: &[u8] = include_bytes!("data/a.pem");
const KEY_A: &str = "302e020100300506032b65700422042098cded488e5305ce6644e0188d522eac4a19a7722043c25e621026562f2dda6d";

fn addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 25))
}

fn key() -> Vec<u8> {
    let der: Vec<u8> = (0..KEY_A.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&KEY_A[i..i + 2], 16).expect("hex"))
        .collect();
    let label = "PRIVATE KEY";
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        dkim::base64::encode(&der)
    )
    .into_bytes()
}

fn der(pem: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem).expect("cert")
}

fn spki(pem: &[u8]) -> Vec<u8> {
    let cert = der(pem);
    let parsed = ParsedCertificate::try_from(&cert).expect("parse");
    parsed.subject_public_key_info().as_ref().to_vec()
}

fn tlsa(usage: u8, selector: u8, matching: u8, data: &[u8]) -> Tlsa {
    Tlsa {
        usage,
        selector,
        matching,
        data: data.to_vec(),
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().to_vec()
}

fn dane(names: &[&str], records: Vec<Tlsa>) -> Verify {
    Verify::Dane {
        names: names.iter().map(|n| (*n).to_owned()).collect(),
        records,
    }
}

fn serve(chain: &[u8]) {
    let provider = simulated(1);
    let certs = Arc::new(Certs::new(chain, &key()).expect("certs"));
    let acceptor = Rc::new(Acceptor::new(provider, certs).expect("acceptor"));
    drop(spawn(async move {
        let listener = TcpListener::bind(addr(), 16).await.expect("bind");
        while let Ok((io, _)) = listener.accept().await {
            let acceptor = Rc::clone(&acceptor);
            drop(spawn(async move {
                if let Ok(mut stream) = acceptor.accept(io).await {
                    let mut buf = [0; 64];
                    if let Ok(n) = stream.read(&mut buf).await {
                        let _ = stream.write_all(&buf[..n]).await;
                    }
                }
            }));
        }
    }));
}

fn outcomes(
    chain: Vec<u8>,
    roots: Option<&'static [u8]>,
    cases: Vec<(&'static str, Verify)>,
) -> Vec<io::Result<HandshakeKind>> {
    let driver = Rc::new(SimDriver::new(7, Config::default()));
    Runtime::new(driver).block_on(async move {
        serve(&chain);
        let connector = Connector::new(simulated(2), roots).expect("connector");
        let mut results = Vec::new();
        for (name, verify) in cases {
            let result = async {
                let io = TcpStream::connect(addr()).await?;
                let mut stream = connector.connect(io, name, verify).await?;
                let kind = stream.connection().handshake_kind().expect("done");
                stream.write_all(b"x").await?;
                let mut back = [0; 1];
                stream.read(&mut back).await?;
                Ok(kind)
            }
            .await;
            results.push(result);
        }
        results
    })
}

fn kinds(results: &[io::Result<HandshakeKind>]) -> Vec<String> {
    results
        .iter()
        .map(|r| match r {
            Ok(kind) => format!("{kind:?}"),
            Err(e) => format!("{:?}", e.kind()),
        })
        .collect()
}

#[test]
fn opportunistic_accepts_any_certificate() {
    let results = outcomes(A.to_vec(), None, vec![("mx.other.test", Verify::Any)]);
    assert_eq!(kinds(&results), ["Full"]);
}

#[test]
fn webpki_checks_roots_and_name() {
    let results = outcomes(
        A.to_vec(),
        Some(CA),
        vec![
            ("mail.test", Verify::WebPki),
            ("other.test", Verify::WebPki),
        ],
    );
    assert_eq!(kinds(&results), ["Full", "InvalidData"]);
    let results = outcomes(A.to_vec(), None, vec![("mail.test", Verify::WebPki)]);
    assert_eq!(kinds(&results), ["InvalidInput"]);
}

#[test]
fn dane_ee_matches_the_server_key_or_certificate() {
    let cert = der(A);
    let key = spki(A);
    let results = outcomes(
        A.to_vec(),
        None,
        vec![
            (
                "mx.test",
                dane(&["mx.test"], vec![tlsa(3, 1, 1, &sha256(&key))]),
            ),
            (
                "mx.test",
                dane(&["mx.test"], vec![tlsa(3, 0, 0, cert.as_ref())]),
            ),
            (
                "mx.test",
                dane(
                    &["mx.test"],
                    vec![tlsa(3, 1, 2, digest(&SHA512, &key).as_ref())],
                ),
            ),
            ("mx.test", dane(&["mx.test"], vec![tlsa(3, 1, 1, &[0; 32])])),
            (
                "mx.test",
                dane(
                    &["mx.test"],
                    vec![tlsa(3, 1, 1, &[1; 32]), tlsa(3, 1, 1, &sha256(&key))],
                ),
            ),
        ],
    );
    assert_eq!(
        kinds(&results),
        ["Full", "Full", "Full", "InvalidData", "Full"]
    );
}

#[test]
fn dane_ta_needs_the_anchor_in_the_chain_and_a_matching_name() {
    let anchor = sha256(der(CA).as_ref());
    let with_ca = [A, CA].concat();
    let results = outcomes(
        with_ca.clone(),
        None,
        vec![
            (
                "mail.test",
                dane(&["mail.test"], vec![tlsa(2, 0, 1, &anchor)]),
            ),
            (
                "mail.test",
                dane(&["other.test"], vec![tlsa(2, 0, 1, &anchor)]),
            ),
            (
                "mail.test",
                dane(
                    &["other.test", "mail.test"],
                    vec![tlsa(2, 1, 1, &sha256(&spki(CA)))],
                ),
            ),
        ],
    );
    assert_eq!(kinds(&results), ["Full", "InvalidData", "Full"]);
    let results = outcomes(
        A.to_vec(),
        None,
        vec![(
            "mail.test",
            dane(&["mail.test"], vec![tlsa(2, 0, 1, &anchor)]),
        )],
    );
    assert_eq!(kinds(&results), ["InvalidData"]);
}

#[test]
fn dane_without_usable_records_is_refused_before_connecting() {
    let results = outcomes(
        A.to_vec(),
        None,
        vec![(
            "mx.test",
            dane(
                &["mx.test"],
                vec![tlsa(1, 1, 1, &[0; 32]), tlsa(3, 2, 1, &[0; 32])],
            ),
        )],
    );
    assert_eq!(kinds(&results), ["InvalidInput"]);
}

#[test]
fn unverified_sessions_never_resume_a_verified_connection() {
    let key = spki(A);
    let results = outcomes(
        A.to_vec(),
        Some(CA),
        vec![
            ("mail.test", Verify::Any),
            ("mail.test", Verify::Any),
            ("mail.test", Verify::WebPki),
            (
                "mail.test",
                dane(&["mail.test"], vec![tlsa(3, 1, 1, &sha256(&key))]),
            ),
            ("mail.test", Verify::WebPki),
        ],
    );
    assert_eq!(
        kinds(&results),
        ["Full", "Resumed", "Full", "Full", "Resumed"]
    );
}
