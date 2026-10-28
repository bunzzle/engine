#[derive(Clone, Copy, Debug)]
pub struct Fields<'a> {
    bytes: &'a [u8],
}

impl<'a> Fields<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn u8(&self, at: usize) -> u8 {
        self.bytes[at]
    }

    pub fn u16(&self, at: usize) -> u16 {
        u16::from_le_bytes(self.array(at))
    }

    pub fn u32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.array(at))
    }

    pub fn u64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.array(at))
    }

    pub fn bytes(&self, at: usize, len: usize) -> &'a [u8] {
        &self.bytes[at..at + len]
    }

    fn array<const N: usize>(&self, at: usize) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[at..at + N]);
        out
    }
}

#[derive(Debug)]
pub struct FieldsMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> FieldsMut<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    pub fn put_u8(&mut self, at: usize, value: u8) {
        self.bytes[at] = value;
    }

    pub fn put_u16(&mut self, at: usize, value: u16) {
        self.put_bytes(at, &value.to_le_bytes());
    }

    pub fn put_u32(&mut self, at: usize, value: u32) {
        self.put_bytes(at, &value.to_le_bytes());
    }

    pub fn put_u64(&mut self, at: usize, value: u64) {
        self.put_bytes(at, &value.to_le_bytes());
    }

    pub fn put_bytes(&mut self, at: usize, value: &[u8]) {
        self.bytes[at..at + value.len()].copy_from_slice(value);
    }
}
