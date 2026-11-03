use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::{Error, Secret};

pub const TAG: usize = 16;

pub struct ChunkKey(LessSafeKey);

impl ChunkKey {
    pub fn new(key: &Secret<32>) -> Self {
        Self(LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, key.expose()).expect("32-byte key"),
        ))
    }

    pub(crate) fn seal(&self, index: u32, last: bool, aad: &[u8], data: &mut Vec<u8>) {
        let tag = self
            .0
            .seal_in_place_separate_tag(nonce(index, last), Aad::from(aad), data)
            .expect("chunk within the cipher limit");
        data.extend_from_slice(tag.as_ref());
    }

    pub fn open<'a>(
        &self,
        index: u32,
        last: bool,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        if data.len() < TAG {
            return Err(Error::Format("chunk"));
        }
        let len = data.len() - TAG;
        if self
            .0
            .open_in_place(nonce(index, last), Aad::from(aad), data)
            .is_err()
        {
            sys::mem::wipe(data);
            return Err(Error::Open);
        }
        Ok(&mut data[..len])
    }

    pub fn seal_one(self, aad: &[u8], clear: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(clear.len() + TAG);
        data.extend_from_slice(clear);
        self.seal(0, true, aad, &mut data);
        data
    }

    pub fn open_one(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
        let mut data = sealed.to_vec();
        let len = self.open(0, true, aad, &mut data)?.len();
        data.truncate(len);
        Ok(data)
    }
}

fn nonce(index: u32, last: bool) -> Nonce {
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    bytes[11] = u8::from(last);
    Nonce::assume_unique_for_key(bytes)
}

pub struct Sealer {
    key: ChunkKey,
    aad: Vec<u8>,
    next: u32,
}

impl Sealer {
    pub fn new(key: ChunkKey, aad: &[u8]) -> Self {
        Self {
            key,
            aad: aad.to_vec(),
            next: 0,
        }
    }

    pub fn seal(&mut self, data: &mut Vec<u8>) -> Result<(), Error> {
        let index = self.next;
        let next = index.checked_add(1).ok_or(Error::Order)?;
        self.key.seal(index, false, &self.aad, data);
        self.next = next;
        Ok(())
    }

    pub fn seal_last(self, data: &mut Vec<u8>) {
        self.key.seal(self.next, true, &self.aad, data);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Reading,
    Done,
    Failed,
}

pub struct Opener {
    key: ChunkKey,
    aad: Vec<u8>,
    next: u32,
    state: State,
}

impl Opener {
    pub fn new(key: ChunkKey, aad: &[u8]) -> Self {
        Self {
            key,
            aad: aad.to_vec(),
            next: 0,
            state: State::Reading,
        }
    }

    pub fn open<'a>(&mut self, last: bool, data: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        if self.state != State::Reading {
            self.state = State::Failed;
            return Err(Error::Order);
        }
        let index = self.next;
        let next = if last {
            Some(index)
        } else {
            index.checked_add(1)
        };
        let Some(next) = next else {
            self.state = State::Failed;
            return Err(Error::Order);
        };
        match self.key.open(index, last, &self.aad, data) {
            Ok(clear) => {
                self.next = next;
                if last {
                    self.state = State::Done;
                }
                Ok(clear)
            }
            Err(error) => {
                self.state = State::Failed;
                Err(error)
            }
        }
    }

    pub fn finish(&self) -> Result<(), Error> {
        if self.state == State::Done {
            Ok(())
        } else {
            Err(Error::Order)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ChunkKey, Opener, Sealer, TAG};
    use crate::{Error, Secret};

    fn key() -> ChunkKey {
        ChunkKey::new(&Secret::new([7; 32]))
    }

    fn sealed(chunks: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut sealer = Sealer::new(key(), b"aad");
        let (last, rest) = chunks.split_last().expect("one chunk");
        let mut out: Vec<Vec<u8>> = rest
            .iter()
            .map(|chunk| {
                let mut data = chunk.to_vec();
                sealer.seal(&mut data).expect("seals");
                data
            })
            .collect();
        let mut data = last.to_vec();
        sealer.seal_last(&mut data);
        out.push(data);
        out
    }

    fn open_all(chunks: &mut [Vec<u8>]) -> Result<Vec<u8>, Error> {
        let mut opener = Opener::new(key(), b"aad");
        let count = chunks.len();
        let mut out = Vec::new();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            out.extend_from_slice(opener.open(i + 1 == count, chunk)?);
        }
        opener.finish()?;
        Ok(out)
    }

    #[test]
    fn round_trip() {
        let mut chunks = sealed(&[b"one ", b"two ", b"three"]);
        assert!(chunks.iter().all(|c| c.len() > TAG));
        assert_eq!(open_all(&mut chunks).expect("opens"), b"one two three");
    }

    #[test]
    fn truncation_is_caught() {
        let mut chunks = sealed(&[b"one ", b"two ", b"three"]);
        chunks.pop();
        assert_eq!(open_all(&mut chunks), Err(Error::Open));
    }

    #[test]
    fn extra_chunk_after_last_is_refused() {
        let mut chunks = sealed(&[b"one ", b"two"]);
        let mut extra = sealed(&[b"x", b"y", b"z"]).remove(2);
        let mut opener = Opener::new(key(), b"aad");
        opener.open(false, &mut chunks[0]).expect("first");
        opener.open(true, &mut chunks[1]).expect("last");
        assert_eq!(opener.open(true, &mut extra), Err(Error::Order));
    }

    #[test]
    fn reorder_and_wrong_aad_are_caught() {
        let mut chunks = sealed(&[b"one ", b"two ", b"three"]);
        chunks.swap(0, 1);
        assert_eq!(open_all(&mut chunks), Err(Error::Open));
        let mut chunk = sealed(&[b"only"]).remove(0);
        assert_eq!(
            key().open(0, true, b"other", &mut chunk).err(),
            Some(Error::Open)
        );
    }

    #[test]
    fn failed_open_wipes_the_buffer() {
        let mut chunk = sealed(&[b"secret text"]).remove(0);
        let last = chunk.len() - 1;
        chunk[last] ^= 1;
        assert!(key().open(0, true, b"aad", &mut chunk).is_err());
        assert!(chunk.iter().all(|&b| b == 0));
    }

    #[test]
    fn opener_is_poisoned_after_a_bad_chunk() {
        let mut chunks = sealed(&[b"one ", b"two ", b"three"]);
        let mut opener = Opener::new(key(), b"aad");
        let mut bad = chunks[0].clone();
        bad[0] ^= 1;
        assert_eq!(opener.open(false, &mut bad).err(), Some(Error::Open));
        assert_eq!(opener.open(false, &mut chunks[0]).err(), Some(Error::Order));
        assert_eq!(opener.open(true, &mut chunks[2]).err(), Some(Error::Order));
        assert_eq!(opener.finish(), Err(Error::Order));
    }

    #[test]
    fn known_answer() {
        let sealed = sealed(&[b"ab", b"c"]);
        let hex: Vec<String> = sealed.iter().map(|c| crate::seal::tests::hex(c)).collect();
        assert_eq!(
            hex,
            [
                "00ba9a6e189eadc352814a6e3a1a9a8ffd9d",
                "3230e41eca8ddd28a4c19cdaf4b1c3770c"
            ]
        );
    }

    #[test]
    fn unfinished_stream_is_refused() {
        let mut chunks = sealed(&[b"one ", b"two"]);
        let mut opener = Opener::new(key(), b"aad");
        opener.open(false, &mut chunks[0]).expect("first");
        assert_eq!(opener.finish(), Err(Error::Order));
    }

    #[test]
    fn short_chunk_is_refused() {
        let mut short = [0u8; TAG - 1];
        assert_eq!(
            key().open(0, true, b"", &mut short).err(),
            Some(Error::Format("chunk"))
        );
    }

    #[test]
    fn one_shot_round_trip() {
        let sealed = key().seal_one(b"aad", b"hello");
        assert_eq!(key().open_one(b"aad", &sealed).expect("opens"), b"hello");
    }
}
