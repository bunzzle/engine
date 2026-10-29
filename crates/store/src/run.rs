use std::collections::BTreeMap;

use rt::Buf;

use crate::committer::Location;
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::layout::{Fields, FieldsMut};
use crate::record::{self, FLAG_MORE, Header, Record, record_size};
use crate::shard::{BODY_SIZE, Delivery, Item, Key, decode_bodies, encode_body};
use sys::crc32c::checksum;

pub const KIND_RUN: u8 = 3;
pub const MAX_DELTAS: usize = 8;
pub const ROOT_SIZE: usize = 40;

const RUN_FORMAT: u32 = 3;
const HEAD: usize = 24;
const ENTRY: usize = 72;
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
    pub changes: BTreeMap<Key, Option<Item>>,
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

pub(crate) fn entry_size(item: Option<&Item>) -> usize {
    ENTRY
        + item.map_or(0, |item| {
            item.clear.len().next_multiple_of(8) + item.bodies.len() * BODY_SIZE
        })
}

pub(crate) fn encode<'a>(
    shard: u16,
    base: bool,
    covered: u64,
    changes: impl Iterator<Item = (Key, Option<&'a Item>)>,
) -> Vec<u8> {
    let mut out = vec![0u8; HEAD];
    let mut len: u32 = 0;
    for (key, item) in changes {
        let at = out.len();
        out.resize(at + entry_size(item), 0);
        let mut fields = FieldsMut::new(&mut out[at..]);
        fields.put_u64(0, key.message);
        fields.put_u32(8, key.item);
        match item {
            Some(item) => {
                fields.put_u32(12, item.tenant);
                fields.put_u8(16, OP_PUT);
                fields.put_u8(17, item.delivery.status);
                fields.put_u16(18, item.delivery.attempts);
                fields.put_u32(
                    20,
                    u32::try_from(item.clear.len()).expect("clear part fits in u32"),
                );
                fields.put_u64(24, item.delivery.due);
                fields.put_u32(32, item.location.region);
                fields.put_u32(36, item.location.size);
                fields.put_u64(40, item.location.epoch);
                fields.put_u64(48, item.location.offset);
                fields.put_u64(56, item.location.sequence);
                fields.put_u32(
                    64,
                    u32::try_from(item.bodies.len()).expect("bodies fit in u32"),
                );
                let clear = at + ENTRY;
                out[clear..clear + item.clear.len()].copy_from_slice(&item.clear);
                let bodies = clear + item.clear.len().next_multiple_of(8);
                for (body, bytes) in item.bodies.iter().zip(out[bodies..].chunks_mut(BODY_SIZE)) {
                    encode_body(body, bytes);
                }
            }
            None => fields.put_u8(16, OP_TOMBSTONE),
        }
        len += 1;
    }
    let mut fields = FieldsMut::new(&mut out);
    fields.put_u32(0, RUN_FORMAT);
    fields.put_u16(4, shard);
    fields.put_u8(6, if base { FLAG_BASE } else { 0 });
    fields.put_u32(8, len);
    fields.put_u64(16, covered);
    out
}

pub(crate) fn decode(blob: &[u8]) -> Option<Run> {
    let fields = Fields::new(blob.get(..HEAD)?);
    let flags = fields.u8(6);
    let len = fields.u32(8);
    if fields.u32(0) != RUN_FORMAT
        || flags & !FLAG_BASE != 0
        || fields.u8(7) != 0
        || fields.u32(12) != 0
    {
        return None;
    }
    let base = flags == FLAG_BASE;
    let mut changes = BTreeMap::new();
    let mut last = None;
    let mut at = HEAD;
    for _ in 0..len {
        let entry = Fields::new(blob.get(at..at.checked_add(ENTRY)?)?);
        let key = Key::new(entry.u64(0), entry.u32(8));
        if last.is_some_and(|last| last >= key) {
            return None;
        }
        last = Some(key);
        let item = match entry.u8(16) {
            OP_PUT if entry.u32(68) == 0 => {
                let clear = usize::try_from(entry.u32(20)).ok()?;
                let padded = clear.checked_next_multiple_of(8)?;
                let bodies = usize::try_from(entry.u32(64))
                    .ok()?
                    .checked_mul(BODY_SIZE)?;
                let size = padded.checked_add(bodies)?;
                let tail = blob.get(at + ENTRY..at.checked_add(ENTRY)?.checked_add(size)?)?;
                if tail[clear..padded].iter().any(|&b| b != 0) {
                    return None;
                }
                at += size;
                Some(Item {
                    tenant: entry.u32(12),
                    delivery: Delivery {
                        status: entry.u8(17),
                        attempts: entry.u16(18),
                        due: entry.u64(24),
                    },
                    location: Location {
                        region: entry.u32(32),
                        epoch: entry.u64(40),
                        offset: entry.u64(48),
                        sequence: entry.u64(56),
                        size: entry.u32(36),
                    },
                    clear: tail[..clear].into(),
                    bodies: decode_bodies(&tail[padded..])?.into(),
                })
            }
            OP_TOMBSTONE
                if !base
                    && entry.bytes(12, 4) == [0; 4]
                    && entry.bytes(17, ENTRY - 17).iter().all(|&b| b == 0) =>
            {
                None
            }
            _ => return None,
        };
        at += ENTRY;
        changes.insert(key, item);
    }
    (at == blob.len()).then_some(Run {
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
    use crate::journal::Range;
    use crate::shard::{BODY_SIZE, Delivery, Item, Key};

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
            clear: vec![0xC0 | u8::try_from(key).expect("small key"); 3].into(),
            bodies: (key..key + key / 4)
                .map(|n| Range {
                    region: 5,
                    epoch: 2,
                    offset: n * 4096,
                    length: 4096,
                    checksum: 0xC0DE,
                })
                .collect(),
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

    fn changes() -> BTreeMap<Key, Option<Item>> {
        BTreeMap::from([
            (Key::new(1, 0), Some(item(1))),
            (Key::new(1, 7), None),
            (Key::new(4, 0), None),
            (Key::new(9, 2), Some(item(9))),
        ])
    }

    fn blob(base: bool) -> Vec<u8> {
        let changes = changes();
        encode(2, base, 41, changes.iter().map(|(&k, v)| (k, v.as_ref())))
    }

    #[test]
    fn a_run_round_trips_with_tombstones_clear_parts_and_bodies() {
        let run = decode(&blob(false)).expect("decode");
        assert_eq!((run.shard, run.base, run.covered), (2, false, 41));
        assert_eq!(run.changes, changes());
        assert_eq!(blob(false).len(), HEAD + 4 * ENTRY + 2 * 8 + 2 * BODY_SIZE);
    }

    #[test]
    fn damaged_runs_are_rejected() {
        let blob = blob(false);
        let second = HEAD + ENTRY + 8;
        let mut base = blob.clone();
        base[6] = 1;
        assert_eq!(decode(&base), None, "a base holds no tombstones");
        let mut unsorted = blob.clone();
        unsorted[second + 8..second + 12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode(&unsorted), None);
        let mut tombstone = blob.clone();
        tombstone[second + 24] = 1;
        assert_eq!(decode(&tombstone), None);
        let mut op = blob.clone();
        op[HEAD + 16] = 7;
        assert_eq!(decode(&op), None);
        let mut padding = blob.clone();
        padding[HEAD + ENTRY + 3] = 1;
        assert_eq!(decode(&padding), None);
        let mut clear = blob.clone();
        clear[HEAD + 20..HEAD + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&clear), None);
        let last = blob.len() - 2 * BODY_SIZE;
        let mut body = blob.clone();
        body[last + 28] = 1;
        assert_eq!(decode(&body), None, "body reserved bytes");
        let mut empty = blob.clone();
        empty[last + 4..last + 8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode(&empty), None, "empty body range");
        let mut reserved = blob.clone();
        reserved[HEAD + 68] = 1;
        assert_eq!(decode(&reserved), None);
        let mut bodies = blob.clone();
        bodies[last - 8 - ENTRY + 64] = 3;
        assert_eq!(decode(&bodies), None, "body count past the end");
        let mut count = blob.clone();
        count[8] = 3;
        assert_eq!(decode(&count), None);
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
