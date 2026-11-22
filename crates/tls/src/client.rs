use std::io;
use std::sync::{Arc, Mutex, PoisonError};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Expired,
    NameMismatch,
    Untrusted,
    Unverified,
    Lost,
}

pub fn refusal(error: &io::Error) -> Refusal {
    let Some(rejected) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return Refusal::Lost;
    };
    refused(rejected)
}

fn refused(rejected: &rustls::Error) -> Refusal {
    let rustls::Error::InvalidCertificate(cert) = rejected else {
        return Refusal::Unverified;
    };
    match cert {
        CertificateError::Expired
        | CertificateError::ExpiredContext { .. }
        | CertificateError::NotValidYet
        | CertificateError::NotValidYetContext { .. } => Refusal::Expired,
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            Refusal::NameMismatch
        }
        CertificateError::UnknownIssuer
        | CertificateError::BadSignature
        | CertificateError::Revoked => Refusal::Untrusted,
        _ => Refusal::Unverified,
    }
}

#[derive(Debug, Default)]
pub struct Observed(Mutex<Option<Result<(), Refusal>>>);

impl Observed {
    pub fn verdict(&self) -> Option<Result<(), Refusal>> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, verdict: Result<(), Refusal>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(verdict);
    }
}

pub enum Verify {
    Any,
    WebPki,
    Observe(Arc<Observed>),
    Dane {
        names: Vec<String>,
        records: Vec<Tlsa>,
    },
}

pub struct Connector {
    provider: Arc<CryptoProvider>,
    any: Arc<ClientConfig>,
    webpki: Option<Arc<ClientConfig>>,
    verifier: Option<Arc<WebPkiServerVerifier>>,
}

impl Connector {
    pub fn new(provider: Arc<CryptoProvider>, roots: Option<&[u8]>) -> Result<Self, Error> {
        let any = Arc::new(Any(Arc::clone(&provider)));
        let mut config = builder(&provider)?
            .dangerous()
            .with_custom_certificate_verifier(any)
            .with_no_client_auth();
        config.resumption = Resumption::store(Arc::new(ClientSessionMemoryCache::new(SESSIONS)));
        let mut kept = None;
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
                kept = Some(Arc::clone(&verifier));
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
            verifier: kept,
        })
    }

    pub fn webpki(&self) -> bool {
        self.webpki.is_some()
    }

    pub async fn connect(&self, io: TcpStream, name: &str, verify: Verify) -> io::Result<Stream> {
        let config = match verify {
            Verify::Any => Arc::clone(&self.any),
            Verify::WebPki => Arc::clone(
                self.webpki
                    .as_ref()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no roots"))?,
            ),
            Verify::Observe(observed) => {
                let inner = self
                    .verifier
                    .as_ref()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no roots"))?;
                let observe = Observe {
                    inner: Arc::clone(inner),
                    provider: Arc::clone(&self.provider),
                    observed,
                };
                let mut config = builder(&self.provider)
                    .map_err(io::Error::other)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(observe))
                    .with_no_client_auth();
                config.resumption = Resumption::disabled();
                Arc::new(config)
            }
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
struct Observe {
    inner: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    observed: Arc<Observed>,
}

impl ServerCertVerifier for Observe {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verdict = self
            .inner
            .verify_server_cert(end, chain, name, ocsp, now)
            .map(drop)
            .map_err(|rejected| refused(&rejected));
        self.observed.set(verdict);
        Ok(ServerCertVerified::assertion())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webpki_reports_loaded_roots() {
        let provider = crate::simulated(1);
        let without = Connector::new(Arc::clone(&provider), None).expect("connector");
        assert!(!without.webpki());
        let roots: &[u8] = include_bytes!("../tests/data/ca.pem");
        let with = Connector::new(provider, Some(roots)).expect("connector");
        assert!(with.webpki());
    }
}
