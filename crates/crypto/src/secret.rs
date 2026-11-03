use crate::Error;

pub struct Plain(Vec<u8>);

impl Plain {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        assert!(
            self.0.len() + bytes.len() <= self.0.capacity(),
            "plain buffer would grow"
        );
        self.0.extend_from_slice(bytes);
    }

    pub fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }
}

impl std::ops::Deref for Plain {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for Plain {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for Plain {
    fn drop(&mut self) {
        let len = self.0.capacity();
        self.0.resize(len, 0);
        sys::mem::wipe(&mut self.0);
    }
}

pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Result<Self, Error> {
        let mut secret = Self([0; N]);
        aws_lc_rs::rand::fill(&mut secret.0).map_err(|_| Error::Random)?;
        Ok(secret)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut secret = Self([0; N]);
        if bytes.len() != N {
            return Err(Error::Key);
        }
        secret.0.copy_from_slice(bytes);
        Ok(secret)
    }

    #[must_use]
    pub fn copy(&self) -> Self {
        let mut out = Self([0; N]);
        out.0.copy_from_slice(&self.0);
        out
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        sys::mem::wipe(&mut self.0);
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        aws_lc_rs::constant_time::verify_slices_are_equal(&self.0, &other.0).is_ok()
    }
}

impl<const N: usize> Eq for Secret<N> {}
