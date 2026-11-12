use std::io;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use rt::{Buf, File, OpenOptions};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

const MAX_FILE: u64 = 1 << 20;

#[derive(Debug)]
pub struct Certs {
    current: RwLock<Arc<CertifiedKey>>,
}

impl Certs {
    pub fn new(chain: &[u8], key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            current: RwLock::new(Arc::new(certified(chain, key)?)),
        })
    }

    pub async fn read(chain: &Path, key: &Path) -> Result<Self, Error> {
        let chain = read_file(chain).await?;
        let key = read_file(key).await?;
        Self::new(&chain, &key)
    }

    pub fn replace(&self, chain: &[u8], key: &[u8]) -> Result<(), Error> {
        let next = Arc::new(certified(chain, key)?);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = next;
        Ok(())
    }

    pub async fn reload(&self, chain: &Path, key: &Path) -> Result<(), Error> {
        let chain = read_file(chain).await?;
        let key = read_file(key).await?;
        self.replace(&chain, &key)
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

fn certified(chain: &[u8], key: &[u8]) -> Result<CertifiedKey, Error> {
    let chain = CertificateDer::pem_slice_iter(chain)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Pem)?;
    if chain.is_empty() {
        return Err(Error::NoCertificate);
    }
    let mut der = match PrivateKeyDer::from_pem_slice(key) {
        Ok(der) => der,
        Err(pem::Error::NoItemsFound) => return Err(Error::NoKey),
        Err(_) => return Err(Error::Pem),
    };
    let signing = any_supported_type(&der);
    der.zeroize();
    let certified = CertifiedKey::new(chain, signing?);
    certified.keys_match()?;
    Ok(certified)
}

async fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, Error> {
    let options = OpenOptions {
        read: true,
        ..OpenOptions::default()
    };
    let file = File::open(path, &options).await?;
    let len = file.stat().await?.len;
    if len > MAX_FILE {
        return Err(Error::TooLarge);
    }
    let len = usize::try_from(len).map_err(|_| Error::TooLarge)?;
    let mut data = Zeroizing::new(Vec::with_capacity(len));
    let mut buf = Buf::new(len.max(1));
    while data.len() < len {
        buf.clear();
        let offset = data.len() as u64;
        let (read, back) = file.read_at(buf, offset).await;
        buf = back;
        let read = match read {
            Ok(0) => Err(io::ErrorKind::UnexpectedEof.into()),
            other => other,
        };
        match read {
            Ok(read) => data.extend_from_slice(&buf[..read]),
            Err(e) => {
                buf.full_mut().zeroize();
                return Err(Error::Io(e));
            }
        }
    }
    buf.full_mut().zeroize();
    Ok(data)
}
