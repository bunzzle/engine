use std::collections::BTreeMap;

use rt::Buf;

use crate::committer::Location;
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::layout::{Fields, FieldsMut};
use crate::record::{self, FLAG_MORE, Header, Record, record_size};
use crate::shard::{Delivery, Item};
use sys::crc32c::checksum;

pub const KIND_RUN: u8 = 3;
pub const MAX_DELTAS: usize = 8;
pub const ROOT_SIZE: usize = 40;

const RUN_FORMAT: u32 = 1;
const HEAD: usize = 24;
const ENTRY: usize = 56;
const FLAG_BASE: u8 = 1;
const OP_PUT: u8 = 1;
const OP_TOMBSTONE: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    pub region: u32,
    pub base: bool,
    pub epoch: u64,
    pub offset: u64,
    pub length: u32,
    pub checksum: u32,
    pub covered: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Run {
    pub shard: u16,
    pub base: bool,
    pub covered: u64,
    pub changes: BTreeMap<u64, Option<Item>>,
}

pub fn encode_roots(roots: &[Root]) -> Vec<u8> {
    let mut out = vec![0u8; roots.len() * ROOT_SIZE];
    for (root, bytes) in roots.iter().zip(out.as_chunks_mut::<ROOT_SIZE>().0) {
        let mut fields = FieldsMut::new(bytes);
        fields.put_u32(0, root.region);
        fields.put_u8(4, if root.base { FLAG_BASE } else { 0 });
        fields.put_u64(8, root.epoch);
        fields.put_u64(16, root.offset);
        fields.put_u32(24, root.length);
        fields.put_u32(28, root.checksum);
        fields.put_u64(32, root.covered);
    }
    out
}

pub fn decode_roots(bytes: &[u8]) -> Option<Vec<Root>> {
    if !bytes.len().is_multiple_of(ROOT_SIZE) || bytes.len() > (MAX_DELTAS + 1) * ROOT_SIZE {
        return None;
    }
    let mut roots = Vec::with_capacity(bytes.len() / ROOT_SIZE);
    for chunk in bytes.as_chunks::<ROOT_SIZE>().0 {
        let fields = Fields::new(chunk);
        let flags = fields.u8(4);
        if flags & !FLAG_BASE != 0 || fields.bytes(5, 3) != [0; 3] || fields.u32(24) == 0 {
            return None;
        }
        roots.push(Root {
            region: fields.u32(0),
            base: flags == FLAG_BASE,
            epoch: fields.u64(8),
            offset: fields.u64(16),
            length: fields.u32(24),
            checksum: fields.u32(28),
            covered: fields.u64(32),
        });
    }
    let ordered = roots.iter().skip(1).all(|r| !r.base)
        && roots.windows(2).all(|w| w[0].covered < w[1].covered)
        && roots.iter().filter(|r| !r.base).count() <= MAX_DELTAS;
    ordered.then_some(roots)
}

pub(crate) fn run_size(entries: usize) -> usize {
    HEAD + entries * ENTRY
}

pub(crate) fn encode<'a>(
    shard: u16,
    base: bool,
    covered: u64,
    len: usize,
    changes: impl Iterator<Item = (u64, Option<&'a Item>)>,
) -> Vec<u8> {
    let mut out = vec![0u8; run_size(len)];
    let mut fields = FieldsMut::new(&mut out);
    fields.put_u32(0, RUN_FORMAT);
    fields.put_u16(4, shard);
    fields.put_u8(6, if base { FLAG_BASE } else { 0 });
    fields.put_u32(8, u32::try_from(len).expect("entry count fits in u32"));
    fields.put_u64(16, covered);
    let mut at = HEAD;
    let mut written = 0;
    for (key, item) in changes {
        fields.put_u64(at, key);
        match item {
            Some(item) => {
                fields.put_u32(at + 8, item.tenant);
                fields.put_u8(at + 12, OP_PUT);
                fields.put_u8(at + 13, item.delivery.status);
                fields.put_u16(at + 14, item.delivery.attempts);
                fields.put_u64(at + 16, item.delivery.due);
                fields.put_u32(at + 24, item.location.region);
                fields.put_u32(at + 28, item.location.size);
                fields.put_u64(at + 32, item.location.epoch);
                fields.put_u64(at + 40, item.location.offset);
                fields.put_u64(at + 48, item.location.sequence);
            }
            None => fields.put_u8(at + 12, OP_TOMBSTONE),
        }
        at += ENTRY;
        written += 1;
    }
    assert_eq!(written, len, "run entry count mismatch");
    out
}

pub(crate) fn decode(blob: &[u8]) -> Option<Run> {
    let fields = Fields::new(blob.get(..HEAD)?);
    let flags = fields.u8(6);
    let len = fields.u32(8) as usize;
    if fields.u32(0) != RUN_FORMAT
        || flags & !FLAG_BASE != 0
        || fields.u8(7) != 0
        || fields.u32(12) != 0
        || len.checked_mul(ENTRY)?.checked_add(HEAD)? != blob.len()
    {
        return None;
    }
    let base = flags == FLAG_BASE;
    let fields = Fields::new(blob);
    let mut changes = BTreeMap::new();
    let mut last = None;
    for index in 0..len {
        let at = HEAD + index * ENTRY;
        let key = fields.u64(at);
        if last.is_some_and(|last| last >= key) {
            return None;
        }
        last = Some(key);
        let item = match fields.u8(at + 12) {
            OP_PUT => Some(Item {
                tenant: fields.u32(at + 8),
                delivery: Delivery {
                    status: fields.u8(at + 13),
                    attempts: fields.u16(at + 14),
                    due: fields.u64(at + 16),
                },
                location: Location {
                    region: fields.u32(at + 24),
                    epoch: fields.u64(at + 32),
                    offset: fields.u64(at + 40),
                    sequence: fields.u64(at + 48),
                    size: fields.u32(at + 28),
                },
            }),
            OP_TOMBSTONE
                if !base
                    && fields.bytes(at + 8, 4) == [0; 4]
                    && fields.bytes(at + 13, ENTRY - 13).iter().all(|&b| b == 0) =>
            {
                None
            }
            _ => return None,
        };
        changes.insert(key, item);
    }
    Some(Run {
        shard: fields.u16(4),
        base,
        covered: fields.u64(16),
        changes,
    })
}

pub(crate) fn disk_size(blob: &[u8], sector: usize) -> usize {
    record::chunks(blob)
        .map(|(_, chunk)| record_size(chunk.len()))
        .sum::<usize>()
        .next_multiple_of(sector)
}

pub(crate) async fn write(
    data: &CoreFile,
    region: u32,
    epoch: u64,
    offset: u64,
    blob: &[u8],
) -> Result<Root, Error> {
    let head = Fields::new(&blob[..HEAD]);
    let shard = head.u16(4);
    let base = head.u8(6) == FLAG_BASE;
    let covered = head.u64(16);
    let sector = data.sector_size() as usize;
    let length = disk_size(blob, sector);
    let mut buf = Buf::aligned(length, sector);
    buf.set_len(length);
    let mut at = 0;
    for (flags, chunk) in record::chunks(blob) {
        let header = Header {
            kind: KIND_RUN,
            flags,
            shard,
            tenant: 0,
            epoch,
            sequence: covered,
        };
        at += record::encode(&header, chunk, &mut buf[at..]);
    }
    buf[at..].fill(0);
    let (result, _) = data
        .file()
        .write_all_at(buf, data.region_offset(region) + offset)
        .await;
    result?;
    Ok(Root {
        region,
        base,
        epoch,
        offset,
        length: u32::try_from(length).expect("run fits in a region"),
        checksum: checksum(blob),
        covered,
    })
}

pub async fn read_run(data: &CoreFile, root: &Root, shard: u16) -> Result<Run, Error> {
    let damaged = Error::Damaged {
        region: root.region,
        offset: root.offset,
    };
    let sector = data.sector_size() as usize;
    let length = root.length as usize;
    let (result, buf) = data
        .file()
        .read_at(
            Buf::aligned(length, sector),
            data.region_offset(root.region) + root.offset,
        )
        .await;
    if result? != length {
        return Err(damaged);
    }
    let mut blob = Vec::new();
    let mut at = 0;
    loop {
        let Ok(found) = Record::decode(&buf[at..]) else {
            return Err(damaged);
        };
        if found.kind() != KIND_RUN
            || found.shard() != shard
            || found.epoch() != root.epoch
            || found.sequence() != root.covered
        {
            return Err(damaged);
        }
        blob.extend_from_slice(found.payload());
        at += record_size(found.payload().len());
        if found.flags() & FLAG_MORE == 0 {
            break;
        }
    }
    match decode(&blob) {
        Some(run)
            if checksum(&blob) == root.checksum
                && run.shard == shard
                && run.base == root.base
                && run.covered == root.covered =>
        {
            Ok(run)
        }
        _ => Err(damaged),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{ENTRY, HEAD, MAX_DELTAS, Root, decode, decode_roots, encode, encode_roots};
    use crate::committer::Location;
    use crate::shard::{Delivery, Item};

    fn item(key: u64) -> Item {
        Item {
            tenant: 3,
            delivery: Delivery {
                status: 2,
                attempts: 5,
                due: 900 + key,
            },
            location: Location {
                region: 4,
                epoch: 6,
                offset: key * 128,
                sequence: 70 + key,
                size: 128,
            },
        }
    }

    fn root(base: bool, covered: u64) -> Root {
        Root {
            region: 2,
            base,
            epoch: 9,
            offset: 4096 * covered,
            length: 4096,
            checksum: 0xABCD,
            covered,
        }
    }

    #[test]
    fn a_run_round_trips_with_tombstones() {
        let changes = BTreeMap::from([(1, Some(item(1))), (4, None), (9, Some(item(9)))]);
        let blob = encode(
            2,
            false,
            41,
            changes.len(),
            changes.iter().map(|(&k, v)| (k, v.as_ref())),
        );
        let run = decode(&blob).expect("decode");
        assert_eq!((run.shard, run.base, run.covered), (2, false, 41));
        assert_eq!(run.changes, changes);
    }

    #[test]
    fn damaged_runs_are_rejected() {
        let changes = BTreeMap::from([(1, Some(item(1))), (4, None)]);
        let blob = encode(
            0,
            false,
            8,
            2,
            changes.iter().map(|(&k, v)| (k, v.as_ref())),
        );
        let mut base = blob.clone();
        base[6] = 1;
        assert_eq!(decode(&base), None, "a base holds no tombstones");
        let mut unsorted = blob.clone();
        unsorted[HEAD + ENTRY..HEAD + ENTRY + 8].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(decode(&unsorted), None);
        let mut tombstone = blob.clone();
        tombstone[HEAD + ENTRY + 20] = 1;
        assert_eq!(decode(&tombstone), None);
        let mut op = blob.clone();
        op[HEAD + 12] = 7;
        assert_eq!(decode(&op), None);
        assert_eq!(decode(&blob[..blob.len() - 1]), None);
        for cut in 0..blob.len() {
            let _ = decode(&blob[..cut]);
        }
    }

    #[test]
    fn roots_round_trip_in_order_only() {
        let roots = vec![root(true, 3), root(false, 5), root(false, 8)];
        assert_eq!(decode_roots(&encode_roots(&roots)), Some(roots));
        assert_eq!(decode_roots(&[]), Some(Vec::new()));
        let late_base = vec![root(false, 3), root(true, 5)];
        assert_eq!(decode_roots(&encode_roots(&late_base)), None);
        let unordered = vec![root(true, 5), root(false, 5)];
        assert_eq!(decode_roots(&encode_roots(&unordered)), None);
        let many: Vec<Root> = (0..=MAX_DELTAS as u64).map(|c| root(false, c)).collect();
        assert_eq!(decode_roots(&encode_roots(&many)), None);
        let mut flags = encode_roots(&[root(true, 1)]);
        flags[4] = 2;
        assert_eq!(decode_roots(&flags), None);
        assert_eq!(decode_roots(&[0; 39]), None);
    }
}
