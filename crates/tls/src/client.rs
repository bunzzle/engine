use std::io;
use std::sync::Arc;

use aws_lc_rs::digest::{SHA256, SHA512, digest};
use rt::TcpStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientSessionMemoryCache, Resumption, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::version::{TLS12, TLS13};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore,
    SignatureScheme,
};

use crate::{Clock, Error, Stream};

const SESSIONS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlsa {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub data: Vec<u8>,
}

impl Tlsa {
    pub fn usable(&self) -> bool {
        matches!(self.usage, 2 | 3) && self.selector <= 1 && self.matching <= 2
    }
}

pub enum Verify {
    Any,
    WebPki,
    Dane {
        names: Vec<String>,
        records: Vec<Tlsa>,
    },
}

pub struct Connector {
    provider: Arc<CryptoProvider>,
    any: Arc<ClientConfig>,
    webpki: Option<Arc<ClientConfig>>,
}

impl Connector {
    pub fn new(provider: Arc<CryptoProvider>, roots: Option<&[u8]>) -> Result<Self, Error> {
        let any = Arc::new(Any(Arc::clone(&provider)));
        let mut config = builder(&provider)?
            .dangerous()
            .with_custom_certificate_verifier(any)
            .with_no_client_auth();
        config.resumption = Resumption::store(Arc::new(ClientSessionMemoryCache::new(SESSIONS)));
        let webpki = match roots {
            Some(pem) => {
                let mut store = RootCertStore::empty();
                for cert in CertificateDer::pem_slice_iter(pem) {
                    store.add(cert.map_err(|_| Error::Pem)?)?;
                }
                if store.is_empty() {
                    return Err(Error::NoCertificate);
                }
                let verifier = WebPkiServerVerifier::builder_with_provider(
                    Arc::new(store),
                    Arc::clone(&provider),
                )
                .build()
                .map_err(|_| Error::NoCertificate)?;
                let mut config = builder(&provider)?
                    .with_webpki_verifier(verifier)
                    .with_no_client_auth();
                config.resumption =
                    Resumption::store(Arc::new(ClientSessionMemoryCache::new(SESSIONS)));
                Some(Arc::new(config))
            }
            None => None,
        };
        Ok(Self {
            provider,
            any: Arc::new(config),
            webpki,
        })
    }

    pub async fn connect(&self, io: TcpStream, name: &str, verify: Verify) -> io::Result<Stream> {
        let config = match verify {
            Verify::Any => Arc::clone(&self.any),
            Verify::WebPki => Arc::clone(
                self.webpki
                    .as_ref()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no roots"))?,
            ),
            Verify::Dane { names, records } => {
                let dane = Dane::new(Arc::clone(&self.provider), names, records)?;
                let mut config = builder(&self.provider)
                    .map_err(io::Error::other)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(dane))
                    .with_no_client_auth();
                config.resumption = Resumption::disabled();
                Arc::new(config)
            }
        };
        let name = ServerName::try_from(name.to_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let conn = ClientConnection::new(config, name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut stream = Stream::new(io, conn.into());
        stream.handshake().await?;
        Ok(stream)
    }
}

fn builder(
    provider: &Arc<CryptoProvider>,
) -> Result<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>, Error> {
    Ok(
        ClientConfig::builder_with_details(Arc::clone(provider), Arc::new(Clock))
            .with_protocol_versions(&[&TLS13, &TLS12])?,
    )
}

fn signature12(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    verify_tls12_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

fn signature13(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    verify_tls13_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

#[derive(Debug)]
struct Any(Arc<CryptoProvider>);

impl ServerCertVerifier for Any {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        signature12(&self.0, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        signature13(&self.0, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct Dane {
    provider: Arc<CryptoProvider>,
    names: Vec<ServerName<'static>>,
    records: Vec<Tlsa>,
}

impl Dane {
    fn new(
        provider: Arc<CryptoProvider>,
        names: Vec<String>,
        records: Vec<Tlsa>,
    ) -> io::Result<Self> {
        let records: Vec<Tlsa> = records.into_iter().filter(Tlsa::usable).collect();
        if records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no usable TLSA",
            ));
        }
        let names = names
            .into_iter()
            .map(|name| {
                ServerName::try_from(name)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            provider,
            names,
            records,
        })
    }

    fn trusted_by(
        &self,
        anchor: &CertificateDer<'_>,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> bool {
        let mut store = RootCertStore::empty();
        if store.add(anchor.clone().into_owned()).is_err() {
            return false;
        }
        let Ok(verifier) = WebPkiServerVerifier::builder_with_provider(
            Arc::new(store),
            Arc::clone(&self.provider),
        )
        .build() else {
            return false;
        };
        self.names.iter().any(|name| {
            verifier
                .verify_server_cert(end, chain, name, &[], now)
                .is_ok()
        })
    }
}

fn matches(record: &Tlsa, cert: &CertificateDer<'_>) -> bool {
    let selected = match record.selector {
        0 => cert.as_ref().to_vec(),
        1 => match ParsedCertificate::try_from(cert) {
            Ok(parsed) => parsed.subject_public_key_info().as_ref().to_vec(),
            Err(_) => return false,
        },
        _ => return false,
    };
    match record.matching {
        0 => selected == record.data,
        1 => digest(&SHA256, &selected).as_ref() == record.data.as_slice(),
        2 => digest(&SHA512, &selected).as_ref() == record.data.as_slice(),
        _ => false,
    }
}

impl ServerCertVerifier for Dane {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        for record in &self.records {
            let trusted = match record.usage {
                3 => matches(record, end),
                2 => chain
                    .iter()
                    .filter(|cert| matches(record, cert))
                    .any(|anchor| self.trusted_by(anchor, end, chain, now)),
                _ => false,
            };
            if trusted {
                return Ok(ServerCertVerified::assertion());
            }
        }
        Err(CertificateError::ApplicationVerificationFailure.into())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        signature12(&self.provider, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        signature13(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
