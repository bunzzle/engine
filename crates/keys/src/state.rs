use std::collections::BTreeMap;

use crypto::{Plain, Secret};

use crate::Error;

const FORMAT: u8 = 1;
const FIXED: usize = 1 + 4 + 16 + 4;
const ENTRY: usize = 4 + 4 + 2 + 4 + 32 + 32;

pub struct Entry {
    pub generation: u32,
    pub retention: u16,
    pub oldest: u32,
    pub key: Secret<32>,
    pub ratchet: Secret<32>,
}

pub struct State {
    pub day: u32,
    pub naming: Secret<16>,
    pub tenants: BTreeMap<u32, Entry>,
}

impl State {
    pub fn encode(&self) -> Plain {
        let mut out = Plain::with_capacity(FIXED + ENTRY * self.tenants.len());
        out.push(FORMAT);
        out.extend_from_slice(&self.day.to_le_bytes());
        out.extend_from_slice(self.naming.expose());
        let count = u32::try_from(self.tenants.len()).expect("tenant count fits in u32");
        out.extend_from_slice(&count.to_le_bytes());
        for (tenant, entry) in &self.tenants {
            out.extend_from_slice(&tenant.to_le_bytes());
            out.extend_from_slice(&entry.generation.to_le_bytes());
            out.extend_from_slice(&entry.retention.to_le_bytes());
            out.extend_from_slice(&entry.oldest.to_le_bytes());
            out.extend_from_slice(entry.key.expose());
            out.extend_from_slice(entry.ratchet.expose());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < FIXED || bytes[0] != FORMAT {
            return Err(Error::Corrupt("state format"));
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        let count = u32_at(21) as usize;
        if bytes.len() != FIXED + ENTRY * count {
            return Err(Error::Corrupt("state length"));
        }
        let mut tenants = BTreeMap::new();
        let mut last = None;
        for i in 0..count {
            let at = FIXED + ENTRY * i;
            let tenant = u32_at(at);
            if last.is_some_and(|last| tenant <= last) {
                return Err(Error::Corrupt("state order"));
            }
            last = Some(tenant);
            let entry = Entry {
                generation: u32_at(at + 4),
                retention: u16::from_le_bytes(bytes[at + 8..at + 10].try_into().expect("2 bytes")),
                oldest: u32_at(at + 10),
                key: Secret::from_slice(&bytes[at + 14..at + 46])?,
                ratchet: Secret::from_slice(&bytes[at + 46..at + 78])?,
            };
            tenants.insert(tenant, entry);
        }
        Ok(Self {
            day: u32_at(1),
            naming: Secret::from_slice(&bytes[5..21])?,
            tenants,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crypto::Secret;

    use super::{Entry, State};
    use crate::Error;

    fn state() -> State {
        let mut tenants = BTreeMap::new();
        for tenant in [3, 1, 9] {
            tenants.insert(
                tenant,
                Entry {
                    generation: tenant + 1,
                    retention: 30,
                    oldest: 100 + tenant,
                    key: Secret::new([u8::try_from(tenant).expect("small"); 32]),
                    ratchet: Secret::new([7; 32]),
                },
            );
        }
        State {
            day: 120,
            naming: Secret::new([5; 16]),
            tenants,
        }
    }

    #[test]
    fn round_trip() {
        let bytes = state().encode();
        let back = State::decode(&bytes).expect("decodes");
        assert_eq!(back.day, 120);
        assert!(back.naming == Secret::new([5; 16]));
        assert_eq!(back.tenants.keys().copied().collect::<Vec<_>>(), [1, 3, 9]);
        let entry = &back.tenants[&9];
        assert_eq!(
            (entry.generation, entry.retention, entry.oldest),
            (10, 30, 109)
        );
        assert!(entry.key == Secret::new([9; 32]));
        assert_eq!(back.encode()[..], bytes[..]);
    }

    #[test]
    fn bad_bytes_are_refused() {
        let bytes = state().encode();
        assert_eq!(
            State::decode(&bytes[..bytes.len() - 1]).err(),
            Some(Error::Corrupt("state length"))
        );
        let mut bad = bytes.to_vec();
        bad[0] = 2;
        assert_eq!(
            State::decode(&bad).err(),
            Some(Error::Corrupt("state format"))
        );
        let mut swapped = bytes.to_vec();
        swapped[25..29].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            State::decode(&swapped).err(),
            Some(Error::Corrupt("state order"))
        );
    }
}
