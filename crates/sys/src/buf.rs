use std::fmt;
use std::ops::{Deref, DerefMut};

pub struct Buf {
    raw: Vec<u8>,
    start: usize,
    capacity: usize,
    len: usize,
    align: usize,
}

impl Buf {
    pub fn new(capacity: usize) -> Self {
        Self::aligned(capacity, 1)
    }

    pub fn aligned(capacity: usize, align: usize) -> Self {
        assert!(align.is_power_of_two(), "alignment must be a power of two");
        let raw = vec![0u8; capacity + align - 1];
        let addr = raw.as_ptr().addr();
        let start = addr.next_multiple_of(align) - addr;
        Self {
            raw,
            start,
            capacity,
            len: 0,
            align,
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut buf = Self::new(data.len());
        buf.extend_from_slice(data);
        buf
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn align(&self) -> usize {
        self.align
    }

    pub fn remaining(&self) -> usize {
        self.capacity - self.len
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn set_len(&mut self, len: usize) {
        assert!(len <= self.capacity, "length exceeds capacity");
        self.len = len;
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.remaining());
        let at = self.start + self.len;
        self.raw[at..at + n].copy_from_slice(&data[..n]);
        self.len += n;
        n
    }

    pub fn spare_mut(&mut self) -> &mut [u8] {
        let from = self.start + self.len;
        &mut self.raw[from..self.start + self.capacity]
    }

    pub fn full_mut(&mut self) -> &mut [u8] {
        &mut self.raw[self.start..self.start + self.capacity]
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.raw[self.start..].as_ptr()
    }
}

impl Deref for Buf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.raw[self.start..self.start + self.len]
    }
}

impl DerefMut for Buf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.raw[self.start..self.start + self.len]
    }
}

impl fmt::Debug for Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buf")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("align", &self.align)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::Buf;

    #[test]
    fn aligned_buffers_start_on_the_boundary() {
        for align in [1, 8, 512, 4096] {
            let buf = Buf::aligned(100, align);
            assert_eq!(buf.as_ptr().addr() % align, 0);
            assert_eq!(buf.capacity(), 100);
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn writes_stop_at_capacity() {
        let mut buf = Buf::aligned(4, 64);
        assert_eq!(buf.extend_from_slice(b"abcdef"), 4);
        assert_eq!(&buf[..], b"abcd");
        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.spare_mut(), []);
    }

    #[test]
    fn the_spare_area_follows_the_data() {
        let mut buf = Buf::new(8);
        buf.extend_from_slice(b"ab");
        buf.spare_mut()[..3].copy_from_slice(b"cde");
        buf.set_len(5);
        assert_eq!(&buf[..], b"abcde");
        buf.clear();
        assert_eq!(buf.full_mut().len(), 8);
    }

    #[test]
    #[should_panic(expected = "length exceeds capacity")]
    fn a_length_past_capacity_panics() {
        Buf::new(2).set_len(3);
    }
}
