use std::fmt;

use crate::Error;

pub const MAX_WIRE: usize = 255;
const MAX_LABEL: usize = 63;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(Box<[u8]>);

impl Name {
    pub fn root() -> Self {
        Self(Box::new([0]))
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() {
            return Ok(Self::root());
        }
        let mut wire = Vec::with_capacity(text.len() + 2);
        for label in text.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty()
                || bytes.len() > MAX_LABEL
                || !bytes.iter().all(|b| b.is_ascii_graphic() && *b != b'\\')
            {
                return Err(Error::Name);
            }
            wire.push(u8::try_from(bytes.len()).map_err(|_| Error::Name)?);
            wire.extend(bytes.iter().map(u8::to_ascii_lowercase));
        }
        wire.push(0);
        if wire.len() > MAX_WIRE {
            return Err(Error::Name);
        }
        Ok(Self(wire.into_boxed_slice()))
    }

    pub(crate) fn from_wire(wire: Vec<u8>) -> Self {
        Self(wire.into_boxed_slice())
    }

    pub fn wire(&self) -> &[u8] {
        &self.0
    }

    pub fn labels(&self) -> impl Iterator<Item = &[u8]> {
        let mut at = 0;
        std::iter::from_fn(move || {
            let len = usize::from(*self.0.get(at)?);
            if len == 0 {
                return None;
            }
            let label = self.0.get(at + 1..at + 1 + len)?;
            at += 1 + len;
            Some(label)
        })
    }

    pub fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    pub fn prefixed(&self, label: &str) -> Result<Self, Error> {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_LABEL
            || !bytes
                .iter()
                .all(|b| b.is_ascii_graphic() && *b != b'.' && *b != b'\\')
            || self.0.len() + 1 + bytes.len() > MAX_WIRE
        {
            return Err(Error::Name);
        }
        let mut wire = Vec::with_capacity(self.0.len() + 1 + bytes.len());
        wire.push(u8::try_from(bytes.len()).map_err(|_| Error::Name)?);
        wire.extend(bytes.iter().map(u8::to_ascii_lowercase));
        wire.extend_from_slice(&self.0);
        Ok(Self(wire.into_boxed_slice()))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return write!(f, ".");
        }
        for (i, label) in self.labels().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            for &b in label {
                if b.is_ascii_graphic() && b != b'.' && b != b'\\' {
                    write!(f, "{}", char::from(b))?;
                } else {
                    write!(f, "\\{b:03}")?;
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}
