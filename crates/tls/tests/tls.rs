use std::cell::RefCell;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use rt::sim::{Config, Faults, Rng, SimDriver, check};
use rt::{Buf, File, OpenOptions, Runtime, TcpListener, TcpStream, spawn};
use tls::rustls::client::Resumption;
use tls::rustls::crypto::CryptoProvider;
use tls::rustls::pki_types::pem::PemObject;
use tls::rustls::pki_types::{CertificateDer, ServerName};
use tls::rustls::version::{TLS12, TLS13};
use tls::rustls::{
    ClientConfig, ClientConnection, HandshakeKind, NamedGroup, ProtocolVersion, RootCertStore,
};
use tls::{Acceptor, Certs, Clock, Error, Stream, provider, simulated};

const CA: &[u8] = include_bytes!("data/ca.pem");
const A: &[u8] = include_bytes!("data/a.pem");
const B: &[u8] = include_bytes!("data/b.pem");
const P256: &[u8] = include_bytes!("data/p256.pem");
const KEY_A: &str = "302e020100300506032b65700422042098cded488e5305ce6644e0188d522eac4a19a7722043c25e621026562f2dda6d";
const KEY_B: &str = "302e020100300506032b6570042204202da3be782d1298201aa29a0351162606dd1c71e074692703192e346cb2115026";
const KEY_P256: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420df68a79dca3e02bdab5dd73c56179dfcdc75ea34041825b2e53e2e4a499458e1a14403420004b325c3c51e804dc0260c23d07e9e19d46d8a432a2ff6cab5988d98ac9decc1396a2fd052a668543a054d2d833d2d0e87eec97e7c3e7b014c2b513d6151d74dbd";

fn addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 587))
}

fn pem(hex: &str) -> Vec<u8> {
    let der: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let body = dkim::base64::encode(&der);
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("ascii"));
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out.into_bytes()
}

fn quiet() -> Config {
    let mut config = Config::default();
    config.faults.crash_keep = 0;
    config
}

fn run<T: 'static>(seed: u64, config: Config, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(Rc::new(SimDriver::new(seed, config))).block_on(future)
}

fn client_config(provider: Arc<CryptoProvider>, tls12: bool) -> Arc<ClientConfig> {
    resuming(provider, tls12, false)
}

fn resuming(provider: Arc<CryptoProvider>, tls12: bool, resume: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA).expect("ca"))
        .expect("root");
    let versions: &[_] = if tls12 { &[&TLS12] } else { &[&TLS13] };
    let mut config = ClientConfig::builder_with_details(provider, Arc::new(Clock))
        .with_protocol_versions(versions)
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !resume {
        config.resumption = Resumption::disabled();
    }
    Arc::new(config)
}

async fn connect(config: &Arc<ClientConfig>) -> io::Result<Stream> {
    let io = TcpStream::connect(addr()).await?;
    let name = ServerName::try_from("mail.test").expect("name");
    let conn = ClientConnection::new(Arc::clone(config), name).map_err(io::Error::other)?;
    let mut stream = Stream::new(io, conn.into());
    stream.handshake().await?;
    Ok(stream)
}

type Outcomes = Rc<RefCell<Vec<io::Result<usize>>>>;

async fn serve(acceptor: Acceptor) -> Outcomes {
    let outcomes: Outcomes = Rc::default();
    let listener = TcpListener::bind(addr(), 16).await.expect("bind");
    let acceptor = Rc::new(acceptor);
    let seen = Rc::clone(&outcomes);
    spawn(async move {
        while let Ok((io, _)) = listener.accept().await {
            let acceptor = Rc::clone(&acceptor);
            let seen = Rc::clone(&seen);
            spawn(async move {
                let outcome = echo(&acceptor, io).await;
                seen.borrow_mut().push(outcome);
            });
        }
    });
    outcomes
}

async fn echo(acceptor: &Acceptor, io: TcpStream) -> io::Result<usize> {
    let mut stream = acceptor.accept(io).await?;
    let mut total = 0;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            stream.shutdown().await?;
            return Ok(total);
        }
        total += n;
        stream.write_all(&buf[..n]).await?;
    }
}

fn payload(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    (0..len).map(|_| rng.next_u64().to_le_bytes()[0]).collect()
}

async fn round_trip(stream: &mut Stream, data: &[u8]) -> io::Result<Vec<u8>> {
    let mut back = Vec::with_capacity(data.len());
    let mut buf = vec![0u8; 3000];
    let mut sent = 0;
    for chunk in data.chunks(7001) {
        stream.write_all(chunk).await?;
        sent += chunk.len();
        while back.len() < sent {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            back.extend_from_slice(&buf[..n]);
        }
    }
    Ok(back)
}

fn session(seed: u64, tls12: bool) -> (Vec<u8>, ProtocolVersion) {
    run(seed, quiet(), async move {
        let provider = simulated(seed);
        let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
        let outcomes = serve(Acceptor::new(Arc::clone(&provider), certs).expect("acceptor")).await;
        let config = client_config(provider, tls12);
        let mut stream = connect(&config).await.expect("handshake");
        let data = payload(seed, 50_000);
        let back = round_trip(&mut stream, &data).await.expect("echo");
        assert_eq!(back, data);
        let mut exported = vec![0u8; 32];
        let rustls::Connection::Client(conn) = stream.connection() else {
            panic!("client");
        };
        let version = conn.protocol_version().expect("version");
        conn.export_keying_material(&mut exported[..], b"test", None)
            .expect("export");
        stream.shutdown().await.expect("shutdown");
        let mut buf = [0u8; 16];
        assert_eq!(stream.read(&mut buf).await.expect("close notify"), 0);
        rt::sleep(Duration::from_millis(50)).await;
        let outcomes = outcomes.borrow();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(*outcomes[0].as_ref().expect("server"), data.len());
        (exported, version)
    })
}

#[test]
fn echoes_over_tls13() {
    check(0..40, |seed| {
        let (exported, version) = session(seed, false);
        assert_eq!(version, ProtocolVersion::TLSv1_3);
        assert_eq!(session(seed, false).0, exported);
    });
}

#[test]
fn echoes_over_tls12_with_extended_master_secret() {
    check(0..20, |seed| {
        let (exported, version) = session(seed, true);
        assert_eq!(version, ProtocolVersion::TLSv1_2);
        assert_eq!(session(seed, true).0, exported);
    });
}

#[test]
fn seeds_give_different_keys() {
    assert_ne!(session(1, false).0, session(2, false).0);
}

#[test]
fn real_provider_with_ecdsa_key() {
    run(7, quiet(), async {
        let provider = provider();
        let certs = Arc::new(Certs::new(P256, &pem(KEY_P256)).expect("certs"));
        serve(Acceptor::new(Arc::clone(&provider), certs).expect("acceptor")).await;
        let mut stream = connect(&client_config(provider, false))
            .await
            .expect("handshake");
        let data = payload(7, 20_000);
        assert_eq!(round_trip(&mut stream, &data).await.expect("echo"), data);
        let rustls::Connection::Client(conn) = stream.connection() else {
            panic!("client");
        };
        assert_eq!(
            conn.negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name),
            Some(NamedGroup::X25519MLKEM768)
        );
    });
}

fn leaf(stream: &Stream) -> Vec<u8> {
    stream.connection().peer_certificates().expect("peer")[0].to_vec()
}

#[test]
fn replaced_certificate_serves_new_connections() {
    run(3, quiet(), async {
        let provider = simulated(3);
        let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
        serve(Acceptor::new(Arc::clone(&provider), Arc::clone(&certs)).expect("acceptor")).await;
        let config = client_config(provider, false);
        let mut first = connect(&config).await.expect("first");
        assert_eq!(
            leaf(&first),
            CertificateDer::from_pem_slice(A).expect("a").to_vec()
        );
        certs.replace(B, &pem(KEY_B)).expect("replace");
        let second = connect(&config).await.expect("second");
        assert_eq!(
            leaf(&second),
            CertificateDer::from_pem_slice(B).expect("b").to_vec()
        );
        assert_eq!(
            round_trip(&mut first, b"still here").await.expect("echo"),
            b"still here"
        );
        assert!(certs.replace(A, &pem(KEY_B)).is_err());
        let third = connect(&config).await.expect("third");
        assert_eq!(
            leaf(&third),
            CertificateDer::from_pem_slice(B).expect("b").to_vec()
        );
    });
}

#[test]
fn pipelined_records_are_all_read() {
    check(0..20, |seed| {
        run(seed, quiet(), async move {
            let provider = simulated(seed);
            let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
            serve(Acceptor::new(Arc::clone(&provider), certs).expect("acceptor")).await;
            let mut stream = connect(&client_config(provider, false))
                .await
                .expect("handshake");
            let data = payload(seed, 30_000);
            for chunk in data.chunks(37) {
                stream.write_all(chunk).await.expect("write");
            }
            let mut back = Vec::new();
            let mut buf = vec![0u8; 5000];
            while back.len() < data.len() {
                let n = stream.read(&mut buf).await.expect("read");
                assert_ne!(n, 0);
                back.extend_from_slice(&buf[..n]);
            }
            assert_eq!(back, data);
        });
    });
}

#[test]
fn resumes_sessions() {
    for tls12 in [false, true] {
        run(8, quiet(), async move {
            let provider = simulated(8);
            let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
            serve(Acceptor::new(Arc::clone(&provider), certs).expect("acceptor")).await;
            let config = resuming(provider, tls12, true);
            let mut first = connect(&config).await.expect("first");
            assert_eq!(round_trip(&mut first, b"one").await.expect("echo"), b"one");
            let mut second = connect(&config).await.expect("second");
            assert_eq!(round_trip(&mut second, b"two").await.expect("echo"), b"two");
            assert_eq!(
                first.connection().handshake_kind(),
                Some(HandshakeKind::Full)
            );
            assert_eq!(
                second.connection().handshake_kind(),
                Some(HandshakeKind::Resumed)
            );
        });
    }
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

#[test]
fn reads_and_reloads_files() {
    run(4, quiet(), async {
        write_file("/chain.pem", A).await;
        write_file("/key.pem", &pem(KEY_A)).await;
        let certs = Certs::read(Path::new("/chain.pem"), Path::new("/key.pem"))
            .await
            .expect("read");
        write_file("/chain.pem", B).await;
        assert!(matches!(
            certs
                .reload(Path::new("/chain.pem"), Path::new("/key.pem"))
                .await,
            Err(Error::Tls(_))
        ));
        assert_eq!(
            certs.current().cert[0].to_vec(),
            CertificateDer::from_pem_slice(A).expect("a").to_vec()
        );
        write_file("/key.pem", &pem(KEY_B)).await;
        certs
            .reload(Path::new("/chain.pem"), Path::new("/key.pem"))
            .await
            .expect("reload");
        assert_eq!(
            certs.current().cert[0].to_vec(),
            CertificateDer::from_pem_slice(B).expect("b").to_vec()
        );
        assert!(matches!(
            Certs::read(Path::new("/missing.pem"), Path::new("/key.pem")).await,
            Err(Error::Io(_))
        ));
    });
}

#[test]
fn refuses_bad_material() {
    assert!(matches!(Certs::new(A, &pem(KEY_B)), Err(Error::Tls(_))));
    assert!(matches!(
        Certs::new(b"", &pem(KEY_A)),
        Err(Error::NoCertificate)
    ));
    assert!(matches!(Certs::new(A, A), Err(Error::NoKey)));
    assert!(matches!(Certs::new(A, b""), Err(Error::NoKey)));
    let mut broken = pem(KEY_A);
    broken[40] = b'*';
    assert!(Certs::new(A, &broken).is_err());
}

fn failure(outcome: &io::Result<usize>) -> Option<io::ErrorKind> {
    outcome.as_ref().err().map(io::Error::kind)
}

async fn raw(bytes: &[u8], close: bool) -> Vec<u8> {
    let io = TcpStream::connect(addr()).await.expect("connect");
    let (written, _) = io.write_all(Buf::from_slice(bytes)).await;
    written.expect("write");
    if close {
        io.shutdown().await.expect("shutdown");
    }
    let mut got = Vec::new();
    loop {
        let (read, buf) = io.read(Buf::new(4096)).await;
        match read {
            Ok(0) | Err(_) => return got,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
}

#[test]
fn plaintext_and_early_close_fail_the_handshake() {
    run(5, quiet(), async {
        let provider = simulated(5);
        let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
        let outcomes = serve(Acceptor::new(provider, certs).expect("acceptor")).await;
        let alert = raw(b"EHLO client.test\r\n", false).await;
        assert_eq!(alert.first(), Some(&0x15));
        raw(&[0x16, 0x03, 0x01, 0x00, 0x40, 0x01], true).await;
        raw(b"", true).await;
        rt::sleep(Duration::from_millis(50)).await;
        let outcomes = outcomes.borrow();
        assert_eq!(outcomes.len(), 3);
        assert_eq!(failure(&outcomes[0]), Some(io::ErrorKind::InvalidData));
        assert_eq!(failure(&outcomes[1]), Some(io::ErrorKind::UnexpectedEof));
        assert_eq!(failure(&outcomes[2]), Some(io::ErrorKind::UnexpectedEof));
    });
}

#[test]
fn close_without_notify_is_a_truncation() {
    run(6, quiet(), async {
        let provider = simulated(6);
        let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
        let outcomes = serve(Acceptor::new(Arc::clone(&provider), certs).expect("acceptor")).await;
        let config = client_config(provider, false);
        let mut stream = connect(&config).await.expect("handshake");
        assert_eq!(
            round_trip(&mut stream, b"hello").await.expect("echo"),
            b"hello"
        );
        drop(stream);
        rt::sleep(Duration::from_millis(50)).await;
        let outcomes = outcomes.borrow();
        assert_eq!(failure(&outcomes[0]), Some(io::ErrorKind::UnexpectedEof));
    });
}

#[test]
fn faulty_network_never_corrupts() {
    check(0..60, |seed| {
        let mut config = quiet();
        config.faults = Faults {
            packet_loss: 20_000,
            connection_reset: 20_000,
            ..Faults::default()
        };
        config.faults.crash_keep = 0;
        run(seed, config, async move {
            let provider = simulated(seed);
            let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
            let outcomes =
                serve(Acceptor::new(Arc::clone(&provider), certs).expect("acceptor")).await;
            let config = client_config(provider, false);
            let data = payload(seed, 30_000);
            if let Ok(mut stream) = connect(&config).await
                && let Ok(back) = round_trip(&mut stream, &data).await
            {
                assert_eq!(back, data);
            }
            rt::sleep(Duration::from_secs(1)).await;
            for total in outcomes.borrow().iter().flatten() {
                assert!(*total <= data.len());
            }
        });
    });
}

#[test]
fn a_cancelled_read_breaks_the_stream() {
    run(9, quiet(), async {
        let provider = simulated(9);
        let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
        serve(Acceptor::new(Arc::clone(&provider), certs).expect("acceptor")).await;
        let mut stream = connect(&client_config(provider, false))
            .await
            .expect("handshake");
        let mut buf = [0u8; 64];
        let waited = rt::timeout(Duration::from_millis(10), stream.read(&mut buf)).await;
        assert!(waited.is_err());
        let kind = |result: io::Result<()>| result.err().map(|e| e.kind());
        assert_eq!(
            stream.read(&mut buf).await.err().map(|e| e.kind()),
            Some(io::ErrorKind::BrokenPipe)
        );
        assert_eq!(
            kind(stream.write_all(b"x").await),
            Some(io::ErrorKind::BrokenPipe)
        );
        assert_eq!(
            kind(stream.shutdown().await),
            Some(io::ErrorKind::BrokenPipe)
        );
    });
}

async fn dribble(seed: u64, config: Arc<ClientConfig>) -> Stream {
    let io = TcpStream::connect(addr()).await.expect("connect");
    let name = ServerName::try_from("mail.test").expect("name");
    let mut conn = ClientConnection::new(config, name).expect("client");
    let mut rng = Rng::new(seed);
    loop {
        while conn.wants_write() {
            let mut out = Vec::new();
            conn.write_tls(&mut out).expect("tls");
            let mut rest = &out[..];
            while !rest.is_empty() {
                let take = rest.len().min(1 + rng.index(64));
                let (written, _) = io.write_all(Buf::from_slice(&rest[..take])).await;
                written.expect("write");
                rest = &rest[take..];
                rt::sleep(Duration::from_millis(1)).await;
            }
        }
        if !conn.is_handshaking() {
            return Stream::new(io, conn.into());
        }
        let (read, buf) = io.read(Buf::new(4096)).await;
        let n = read.expect("read");
        assert_ne!(n, 0);
        conn.read_tls(&mut &buf[..n]).expect("read tls");
        conn.process_new_packets().expect("process");
    }
}

#[test]
fn split_hybrid_handshake() {
    check(0..20, |seed| {
        run(seed, quiet(), async move {
            let provider = provider();
            let certs = Arc::new(Certs::new(P256, &pem(KEY_P256)).expect("certs"));
            let outcomes =
                serve(Acceptor::new(Arc::clone(&provider), certs).expect("acceptor")).await;
            let mut stream = dribble(seed, client_config(provider, false)).await;
            assert_eq!(
                stream
                    .connection()
                    .negotiated_key_exchange_group()
                    .map(rustls::crypto::SupportedKxGroup::name),
                Some(NamedGroup::X25519MLKEM768)
            );
            let data = payload(seed, 10_000);
            assert_eq!(round_trip(&mut stream, &data).await.expect("echo"), data);
            stream.shutdown().await.expect("shutdown");
            rt::sleep(Duration::from_millis(50)).await;
            assert_eq!(*outcomes.borrow()[0].as_ref().expect("server"), data.len());
        });
    });
}

#[test]
fn server_sees_the_requested_name() {
    run(10, quiet(), async {
        let provider = simulated(10);
        let certs = Arc::new(Certs::new(A, &pem(KEY_A)).expect("certs"));
        let acceptor = Acceptor::new(Arc::clone(&provider), certs).expect("acceptor");
        let listener = TcpListener::bind(addr(), 4).await.expect("bind");
        let seen = Rc::new(RefCell::new(None));
        let record = Rc::clone(&seen);
        spawn(async move {
            let (io, _) = listener.accept().await.expect("accept");
            let stream = acceptor.accept(io).await.expect("server");
            *record.borrow_mut() = stream.server_name().map(str::to_owned);
        });
        let stream = connect(&client_config(provider, false))
            .await
            .expect("handshake");
        assert_eq!(stream.server_name(), None);
        rt::sleep(Duration::from_millis(50)).await;
        assert_eq!(seen.borrow().as_deref(), Some("mail.test"));
    });
}
