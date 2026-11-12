use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::agreement::{self, PrivateKey, PublicKey, UnparsedPublicKey, X25519};
use rt::sim::Rng;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;
use rustls::{Error, NamedGroup, PeerMisbehaved};

thread_local! {
    static SEEDED: RefCell<Option<Rng>> = const { RefCell::new(None) };
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(default_provider())
}

pub fn simulated(seed: u64) -> Arc<CryptoProvider> {
    SEEDED.with(|rng| *rng.borrow_mut() = Some(Rng::new(seed)));
    Arc::new(CryptoProvider {
        kx_groups: vec![&SeededX25519],
        secure_random: &SeededRandom,
        ..default_provider()
    })
}

#[derive(Debug)]
pub struct Clock;

impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        rt::in_runtime().then(|| UnixTime::since_unix_epoch(Duration::from_millis(rt::wall_ms())))
    }
}

fn seeded_fill(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
    SEEDED.with(|rng| {
        let mut rng = rng.borrow_mut();
        let rng = rng.as_mut().ok_or(GetRandomFailed)?;
        for chunk in buf.chunks_mut(8) {
            let bytes = rng.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    })
}

#[derive(Debug)]
struct SeededRandom;

impl SecureRandom for SeededRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        seeded_fill(buf)
    }
}

#[derive(Debug)]
struct SeededX25519;

impl SupportedKxGroup for SeededX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut seed = [0u8; 32];
        seeded_fill(&mut seed)?;
        let private = PrivateKey::from_private_key(&X25519, &seed).map_err(|_| GetRandomFailed)?;
        let public = private.compute_public_key().map_err(|_| GetRandomFailed)?;
        Ok(Box::new(Exchange { private, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct Exchange {
    private: PrivateKey,
    public: PublicKey,
}

impl ActiveKeyExchange for Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if peer.len() != 32 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        agreement::agree(
            &self.private,
            UnparsedPublicKey::new(&X25519, peer),
            Error::from(PeerMisbehaved::InvalidKeyShare),
            |secret| Ok(SharedSecret::from(secret)),
        )
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_ref()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
