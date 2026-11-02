use crate::Error;

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

    pub(crate) fn copy(&self) -> Self {
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
