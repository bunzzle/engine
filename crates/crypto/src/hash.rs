use aws_lc_rs::digest::{Context, SHA256, digest};

pub struct Sha256(Context);

impl Sha256 {
    pub fn new() -> Self {
        Self(Context::new(&SHA256))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(self) -> [u8; 32] {
        self.0.finish().as_ref().try_into().expect("32 bytes")
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    digest(&SHA256, data).as_ref().try_into().expect("32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::tests::hex;

    #[test]
    fn streaming_matches_one_shot_and_the_known_answer() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut hash = Sha256::new();
        hash.update(b"a");
        hash.update(b"");
        hash.update(b"bc");
        assert_eq!(hash.finish(), sha256(b"abc"));
    }
}
