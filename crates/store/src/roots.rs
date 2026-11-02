use index::BLOCK;

use crate::layout::{Fields, FieldsMut};
use crate::run::{ROOT_SIZE, Root, decode_roots, encode_roots};

pub const INDEX_ROOT_SIZE: usize = 56;

const PART_FORMAT: u32 = 1;
const HEAD: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexRoot {
    pub kind: u8,
    pub partition: u32,
    pub run: u32,
    pub segment: u32,
    pub region: u32,
    pub epoch: u64,
    pub offset: u64,
    pub length: u32,
    pub checksum: u32,
    pub covered: u64,
}

impl IndexRoot {
    pub fn partition_key(&self) -> (u8, u32) {
        (self.kind, self.partition)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Roots {
    pub state: Vec<Root>,
    pub index: Vec<IndexRoot>,
}

pub fn encode_part(state: &[Root], index: &[IndexRoot]) -> Vec<u8> {
    let mut out = vec![0u8; HEAD];
    let mut fields = FieldsMut::new(&mut out);
    fields.put_u32(0, PART_FORMAT);
    fields.put_u32(
        4,
        u32::try_from(state.len()).expect("state roots fit in u32"),
    );
    fields.put_u32(
        8,
        u32::try_from(index.len()).expect("index roots fit in u32"),
    );
    out.extend_from_slice(&encode_roots(state));
    let at = out.len();
    out.resize(at + index.len() * INDEX_ROOT_SIZE, 0);
    for (root, bytes) in index
        .iter()
        .zip(out[at..].as_chunks_mut::<INDEX_ROOT_SIZE>().0)
    {
        let mut fields = FieldsMut::new(bytes);
        fields.put_u32(0, root.region);
        fields.put_u8(4, root.kind);
        fields.put_u32(8, root.partition);
        fields.put_u32(12, root.run);
        fields.put_u32(16, root.segment);
        fields.put_u32(20, root.length);
        fields.put_u64(24, root.epoch);
        fields.put_u64(32, root.offset);
        fields.put_u64(40, root.covered);
        fields.put_u32(48, root.checksum);
    }
    out
}

pub fn decode_part(bytes: &[u8]) -> Option<Roots> {
    let fields = Fields::new(bytes.get(..HEAD)?);
    if fields.u32(0) != PART_FORMAT || fields.u32(12) != 0 {
        return None;
    }
    let state = usize::try_from(fields.u32(4))
        .ok()?
        .checked_mul(ROOT_SIZE)?;
    let index = usize::try_from(fields.u32(8))
        .ok()?
        .checked_mul(INDEX_ROOT_SIZE)?;
    if HEAD.checked_add(state)?.checked_add(index)? != bytes.len() {
        return None;
    }
    let (state, index) = bytes[HEAD..].split_at(state);
    Some(Roots {
        state: decode_roots(state)?,
        index: decode_index_roots(index)?,
    })
}

fn decode_index_roots(bytes: &[u8]) -> Option<Vec<IndexRoot>> {
    let mut roots: Vec<IndexRoot> = Vec::with_capacity(bytes.len() / INDEX_ROOT_SIZE);
    for chunk in bytes.as_chunks::<INDEX_ROOT_SIZE>().0 {
        let fields = Fields::new(chunk);
        if fields.bytes(5, 3) != [0; 3] || fields.u32(52) != 0 {
            return None;
        }
        let root = IndexRoot {
            kind: fields.u8(4),
            partition: fields.u32(8),
            run: fields.u32(12),
            segment: fields.u32(16),
            region: fields.u32(0),
            epoch: fields.u64(24),
            offset: fields.u64(32),
            length: fields.u32(20),
            checksum: fields.u32(48),
            covered: fields.u64(40),
        };
        let length = root.length as usize;
        if length < 2 * BLOCK || !length.is_multiple_of(BLOCK) {
            return None;
        }
        if !follows(roots.last(), &root) {
            return None;
        }
        roots.push(root);
    }
    Some(roots)
}

fn follows(previous: Option<&IndexRoot>, root: &IndexRoot) -> bool {
    let starts_partition = root.run == 0 && root.segment == 0;
    let Some(previous) = previous else {
        return starts_partition;
    };
    if previous.partition_key() != root.partition_key() {
        return previous.partition_key() < root.partition_key() && starts_partition;
    }
    if root.run == previous.run {
        root.segment == previous.segment + 1 && root.covered == previous.covered
    } else {
        root.run == previous.run + 1 && root.segment == 0 && root.covered > previous.covered
    }
}

#[cfg(test)]
mod tests {
    use super::{INDEX_ROOT_SIZE, IndexRoot, Roots, decode_part, encode_part};
    use crate::run::Root;

    fn index(kind: u8, partition: u32, run: u32, segment: u32, covered: u64) -> IndexRoot {
        IndexRoot {
            kind,
            partition,
            run,
            segment,
            region: 7,
            epoch: 3,
            offset: u64::from(segment) * 8192,
            length: 8192,
            checksum: 0xFEED,
            covered,
        }
    }

    fn state() -> Vec<Root> {
        vec![Root {
            region: 2,
            base: true,
            epoch: 9,
            offset: 0,
            length: 4096,
            checksum: 0xABCD,
            covered: 4,
        }]
    }

    fn valid() -> Vec<IndexRoot> {
        vec![
            index(1, 0, 0, 0, 5),
            index(1, 0, 0, 1, 5),
            index(1, 0, 1, 0, 9),
            index(2, 20_000, 0, 0, 9),
            index(2, 20_001, 0, 0, 3),
        ]
    }

    #[test]
    fn a_part_round_trips_with_both_root_lists() {
        let roots = Roots {
            state: state(),
            index: valid(),
        };
        let bytes = encode_part(&roots.state, &roots.index);
        assert_eq!(decode_part(&bytes), Some(roots));
        assert_eq!(decode_part(&encode_part(&[], &[])), Some(Roots::default()));
    }

    #[test]
    fn index_roots_must_form_ordered_runs_of_segments() {
        let refused = [
            vec![index(1, 0, 0, 1, 5)],
            vec![index(1, 0, 1, 0, 5)],
            vec![index(1, 0, 0, 0, 5), index(1, 0, 0, 2, 5)],
            vec![index(1, 0, 0, 0, 5), index(1, 0, 0, 1, 6)],
            vec![index(1, 0, 0, 0, 5), index(1, 0, 1, 0, 5)],
            vec![index(1, 0, 0, 0, 5), index(1, 0, 2, 0, 9)],
            vec![index(1, 0, 0, 0, 5), index(1, 0, 1, 1, 9)],
            vec![index(2, 0, 0, 0, 5), index(1, 0, 0, 0, 5)],
            vec![index(1, 4, 0, 0, 5), index(1, 3, 0, 0, 5)],
            vec![index(1, 4, 0, 0, 5), index(1, 4, 0, 0, 5)],
            vec![index(1, 4, 0, 0, 5), index(1, 5, 1, 0, 9)],
        ];
        for roots in refused {
            assert_eq!(decode_part(&encode_part(&[], &roots)), None, "{roots:?}");
        }
    }

    #[test]
    fn damaged_parts_are_refused() {
        let bytes = encode_part(&state(), &valid());
        let first = bytes.len() - 5 * INDEX_ROOT_SIZE;
        let mut format = bytes.clone();
        format[0] = 2;
        assert_eq!(decode_part(&format), None);
        let mut reserved = bytes.clone();
        reserved[12] = 1;
        assert_eq!(decode_part(&reserved), None);
        let mut count = bytes.clone();
        count[8] = 4;
        assert_eq!(decode_part(&count), None);
        let mut padding = bytes.clone();
        padding[first + 5] = 1;
        assert_eq!(decode_part(&padding), None);
        let mut tail = bytes.clone();
        tail[first + 52] = 1;
        assert_eq!(decode_part(&tail), None);
        let mut short = bytes.clone();
        short[first + 20..first + 24].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(decode_part(&short), None);
        let mut unaligned = bytes.clone();
        unaligned[first + 20..first + 24].copy_from_slice(&9000u32.to_le_bytes());
        assert_eq!(decode_part(&unaligned), None);
        assert_eq!(decode_part(&bytes[..bytes.len() - 1]), None);
        for cut in 0..bytes.len() {
            let _ = decode_part(&bytes[..cut]);
        }
    }
}
