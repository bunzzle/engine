use store::{Fields, FieldsMut};

pub const BODY_ITEM: u32 = 1;
pub const SLICE_BASE: u32 = 2;
pub const STATE_BASE: u32 = 1 << 16;
pub const HEAD_CLEAR: usize = 48;

pub fn slice_item(slice: u32) -> u32 {
    SLICE_BASE + slice
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeadClear {
    pub batch_key: u64,
    pub recipients: u32,
    pub body_size: u64,
    pub accepted: u64,
    pub not_before: u64,
    pub priority: u8,
}

impl HeadClear {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; HEAD_CLEAR];
        let mut fields = FieldsMut::new(&mut out);
        fields.put_u64(0, self.batch_key);
        fields.put_u32(8, self.recipients);
        fields.put_u64(16, self.body_size);
        fields.put_u64(24, self.accepted);
        fields.put_u64(32, self.not_before);
        fields.put_u8(40, self.priority);
        out
    }

    pub fn decode(clear: &[u8]) -> Option<Self> {
        if clear.len() != HEAD_CLEAR {
            return None;
        }
        let fields = Fields::new(clear);
        let reserved = fields.u32(12) != 0 || fields.bytes(41, 7).iter().any(|&b| b != 0);
        (!reserved).then(|| Self {
            batch_key: fields.u64(0),
            recipients: fields.u32(8),
            body_size: fields.u64(16),
            accepted: fields.u64(24),
            not_before: fields.u64(32),
            priority: fields.u8(40),
        })
    }
}

pub(crate) fn encode_slice(queues: &[u32], sealed: &[u8]) -> Vec<u8> {
    let start = 4 + 4 * queues.len();
    let mut out = vec![0; start + sealed.len()];
    let mut fields = FieldsMut::new(&mut out);
    fields.put_u32(
        0,
        u32::try_from(queues.len()).expect("slice count fits in u32"),
    );
    for (n, &queue) in queues.iter().enumerate() {
        fields.put_u32(4 + 4 * n, queue);
    }
    out[start..].copy_from_slice(sealed);
    out
}

pub fn slice_parts(payload: &[u8]) -> Option<(Vec<u32>, &[u8])> {
    let count = usize::try_from(Fields::new(payload.get(..4)?).u32(0)).ok()?;
    let start = count.checked_mul(4)?.checked_add(4)?;
    let fields = Fields::new(payload.get(..start)?);
    let queues = (0..count).map(|n| fields.u32(4 + 4 * n)).collect();
    Some((queues, &payload[start..]))
}
