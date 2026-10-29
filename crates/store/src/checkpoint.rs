use std::collections::BTreeMap;

use rt::Buf;

use crate::data_file::DataFile;
use crate::error::Error;
use crate::journal::Position;
use crate::layout::{Fields, FieldsMut};
use crate::record::{self, FLAG_MORE, Header, Record, SYSTEM_SHARD, record_size};
use crate::recovery::State;
use crate::superblock::CheckpointCopy;
use crate::usage::{Count, Usage};
use sys::crc32c::checksum;

pub const KIND_CHECKPOINT: u8 = 2;

const BLOB_FORMAT: u32 = 2;
const HEAD: usize = 48;
const PART_HEAD: usize = 24;
const TENANT: usize = 16;

pub const PART_TAG_OTHER: u16 = 0x8000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub tag: u16,
    pub replay_sequence: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub position: Position,
    pub record_sequence: u64,
    pub used: Vec<bool>,
    pub epochs: Vec<u64>,
    pub usage: Usage,
    pub release: Vec<u32>,
    pub parts: Vec<Part>,
}

pub struct Loaded {
    pub position: Position,
    pub state: State,
    pub parts: Vec<Part>,
}

fn padded(len: usize) -> usize {
    len.next_multiple_of(8)
}

fn write_bitmap(fields: &mut FieldsMut, at: usize, set: &[bool]) -> usize {
    let mut bits = vec![0u8; padded(set.len().div_ceil(8))];
    for (index, _) in set.iter().enumerate().filter(|(_, on)| **on) {
        bits[index / 8] |= 1 << (index % 8);
    }
    fields.put_bytes(at, &bits);
    bits.len()
}

fn read_bitmap(blob: &[u8], at: usize, count: usize) -> Vec<bool> {
    (0..count)
        .map(|i| blob[at + i / 8] & (1 << (i % 8)) != 0)
        .collect()
}

pub(crate) fn encode(snapshot: &Snapshot) -> Vec<u8> {
    let count = snapshot.epochs.len();
    assert_eq!(snapshot.used.len(), count, "region table mismatch");
    assert_eq!(snapshot.usage.counts().len(), count, "usage table mismatch");
    let bitmap = padded(count.div_ceil(8));
    let release = padded(snapshot.release.len() * 4);
    let tenants = snapshot.usage.tenants();
    let parts: usize = snapshot
        .parts
        .iter()
        .map(|p| PART_HEAD + padded(p.bytes.len()))
        .sum();
    let mut out = vec![
        0u8;
        HEAD + count * 8
            + padded(count * 4)
            + count * 8
            + 2 * bitmap
            + release
            + tenants.len() * TENANT
            + parts
    ];
    let mut fields = FieldsMut::new(&mut out);
    fields.put_u32(0, BLOB_FORMAT);
    fields.put_u32(4, u32::try_from(count).expect("region count fits in u32"));
    fields.put_u64(8, snapshot.record_sequence);
    fields.put_u64(16, snapshot.position.sequence);
    fields.put_u64(24, snapshot.position.offset);
    fields.put_u32(32, snapshot.position.previous);
    fields.put_u32(
        36,
        u32::try_from(snapshot.release.len()).expect("release list fits in u32"),
    );
    fields.put_u32(
        40,
        u32::try_from(snapshot.parts.len()).expect("part count fits in u32"),
    );
    fields.put_u32(
        44,
        u32::try_from(tenants.len()).expect("tenant count fits in u32"),
    );
    let mut at = HEAD;
    for epoch in &snapshot.epochs {
        fields.put_u64(at, *epoch);
        at += 8;
    }
    for (index, count) in snapshot.usage.counts().iter().enumerate() {
        fields.put_u32(at + index * 4, count.extents);
    }
    at += padded(count * 4);
    for count in snapshot.usage.counts() {
        fields.put_u64(at, count.bytes);
        at += 8;
    }
    at += write_bitmap(&mut fields, at, &snapshot.used);
    at += write_bitmap(&mut fields, at, snapshot.usage.quarantined());
    for (index, region) in snapshot.release.iter().enumerate() {
        fields.put_u32(at + index * 4, *region);
    }
    at += release;
    for (tenant, bytes) in tenants {
        fields.put_u32(at, *tenant);
        fields.put_u64(at + 8, *bytes);
        at += TENANT;
    }
    for part in &snapshot.parts {
        fields.put_u16(at, part.tag);
        fields.put_u64(at + 8, part.replay_sequence);
        fields.put_u64(at + 16, part.bytes.len() as u64);
        fields.put_bytes(at + PART_HEAD, &part.bytes);
        at += PART_HEAD + padded(part.bytes.len());
    }
    out
}

pub(crate) fn decode(blob: &[u8], region_count: u32) -> Option<Snapshot> {
    if blob.len() < HEAD {
        return None;
    }
    let fields = Fields::new(blob);
    let count = fields.u32(4);
    if fields.u32(0) != BLOB_FORMAT || count != region_count {
        return None;
    }
    let count = count as usize;
    let releases = fields.u32(36) as usize;
    let part_count = fields.u32(40) as usize;
    let tenant_count = fields.u32(44) as usize;
    let bitmap = padded(count.div_ceil(8));
    let mut at = HEAD;
    let fixed = (at + count * 8 + padded(count * 4) + count * 8 + 2 * bitmap)
        .checked_add(padded(releases.checked_mul(4)?))?
        .checked_add(tenant_count.checked_mul(TENANT)?)?;
    if blob.len() < fixed {
        return None;
    }
    let epochs = (0..count).map(|i| fields.u64(at + i * 8)).collect();
    at += count * 8;
    let extents: Vec<u32> = (0..count).map(|i| fields.u32(at + i * 4)).collect();
    at += padded(count * 4);
    let counts = (0..count)
        .map(|i| Count {
            extents: extents[i],
            bytes: fields.u64(at + i * 8),
        })
        .collect();
    at += count * 8;
    let used = read_bitmap(blob, at, count);
    at += bitmap;
    let quarantined = read_bitmap(blob, at, count);
    at += bitmap;
    let release = (0..releases).map(|i| fields.u32(at + i * 4)).collect();
    at += padded(releases * 4);
    let mut tenants = BTreeMap::new();
    for _ in 0..tenant_count {
        if fields.u32(at + 4) != 0 || tenants.insert(fields.u32(at), fields.u64(at + 8)).is_some() {
            return None;
        }
        at += TENANT;
    }
    let mut parts = Vec::with_capacity(part_count.min(blob.len() / PART_HEAD));
    for _ in 0..part_count {
        if blob.len() < at + PART_HEAD || fields.u16(at + 2) != 0 || fields.u32(at + 4) != 0 {
            return None;
        }
        let len = usize::try_from(fields.u64(at + 16)).ok()?;
        let end = at.checked_add(PART_HEAD)?.checked_add(padded(len))?;
        if blob.len() < end {
            return None;
        }
        parts.push(Part {
            tag: fields.u16(at),
            replay_sequence: fields.u64(at + 8),
            bytes: blob[at + PART_HEAD..at + PART_HEAD + len].to_vec(),
        });
        at = end;
    }
    if at != blob.len() {
        return None;
    }
    Some(Snapshot {
        position: Position {
            sequence: fields.u64(16),
            offset: fields.u64(24),
            previous: fields.u32(32),
        },
        record_sequence: fields.u64(8),
        used,
        epochs,
        usage: Usage::from_parts(counts, quarantined, tenants),
        release,
        parts,
    })
}

pub(crate) async fn write_copy(
    data: &DataFile,
    region: u32,
    epoch: u64,
    sequence: u64,
    blob: &[u8],
) -> Result<CheckpointCopy, Error> {
    let sector = data.sector_size() as usize;
    let size: usize = record::chunks(blob)
        .map(|(_, chunk)| record_size(chunk.len()))
        .sum();
    let length = size.next_multiple_of(sector);
    if length as u64 > data.superblock().region_size() {
        return Err(Error::CheckpointTooLarge);
    }
    let mut buf = Buf::aligned(length, sector);
    buf.set_len(length);
    let mut at = 0;
    for (flags, chunk) in record::chunks(blob) {
        let header = Header {
            kind: KIND_CHECKPOINT,
            flags,
            shard: SYSTEM_SHARD,
            tenant: 0,
            epoch,
            sequence,
        };
        at += record::encode(&header, chunk, &mut buf[at..]);
    }
    buf[at..].fill(0);
    let (result, _) = data
        .file()
        .write_all_at(buf, data.region_offset(region))
        .await;
    result?;
    Ok(CheckpointCopy {
        region,
        epoch,
        length: length as u64,
        checksum: checksum(blob),
    })
}

async fn read_copy(data: &DataFile, copy: CheckpointCopy) -> Option<Vec<u8>> {
    let sector = data.sector_size() as usize;
    let length = usize::try_from(copy.length).ok()?;
    let (result, buf) = data
        .file()
        .read_at(
            Buf::aligned(length, sector),
            data.region_offset(copy.region),
        )
        .await;
    if result.ok()? != length {
        return None;
    }
    let mut blob = Vec::new();
    let mut at = 0;
    let mut sequence = None;
    loop {
        let found = Record::decode(&buf[at..]).ok()?;
        if found.kind() != KIND_CHECKPOINT
            || found.epoch() != copy.epoch
            || *sequence.get_or_insert(found.sequence()) != found.sequence()
        {
            return None;
        }
        blob.extend_from_slice(found.payload());
        at += record_size(found.payload().len());
        if found.flags() & FLAG_MORE == 0 {
            break;
        }
    }
    (checksum(&blob) == copy.checksum).then_some(blob)
}

pub async fn load(data: &DataFile, reserve: u32) -> Result<Loaded, Error> {
    let superblock = data.superblock();
    let count = superblock.region_count();
    let mut state = State::new(count, reserve);
    let Some(checkpoint) = superblock.checkpoint() else {
        return Ok(Loaded {
            position: Position::START,
            state,
            parts: Vec::new(),
        });
    };
    let mut snapshot = None;
    for copy in checkpoint.copies {
        let Some(blob) = read_copy(data, copy).await else {
            continue;
        };
        let Some(found) = decode(&blob, count) else {
            continue;
        };
        if consistent(
            &found,
            &checkpoint.copies,
            checkpoint.position,
            data.superblock().shards(),
        ) {
            snapshot = Some(found);
            break;
        }
    }
    let snapshot = snapshot.ok_or(Error::CheckpointLost)?;
    let mut released = vec![false; snapshot.used.len()];
    for &region in &snapshot.release {
        released[region as usize] = true;
    }
    for (region, used) in snapshot.used.iter().enumerate() {
        if *used && !released[region] {
            state
                .regions
                .mark_used(u32::try_from(region).expect("region count fits in u32"));
        }
    }
    state.epochs = snapshot.epochs;
    state.usage = snapshot.usage;
    state.record_sequence = snapshot.record_sequence;
    state.checkpoint = checkpoint.copies.iter().map(|c| c.region).collect();
    Ok(Loaded {
        position: snapshot.position,
        state,
        parts: snapshot.parts,
    })
}

fn consistent(
    snapshot: &Snapshot,
    copies: &[CheckpointCopy; 2],
    position: Position,
    shards: u32,
) -> bool {
    let count = snapshot.used.len();
    let usage = &snapshot.usage;
    let mut released = vec![false; count];
    let mut unique = true;
    for &region in &snapshot.release {
        if let Some(slot) = released.get_mut(region as usize) {
            unique &= !*slot;
            *slot = true;
        }
    }
    let region_bytes = usage
        .counts()
        .iter()
        .try_fold(0u64, |a, c| a.checked_add(c.bytes));
    let tenant_bytes = usage
        .tenants()
        .values()
        .try_fold(0u64, |a, b| a.checked_add(*b));
    unique
        && region_bytes.is_some()
        && region_bytes == tenant_bytes
        && usage.tenants().values().all(|b| *b > 0)
        && (0..count).all(|r| {
            snapshot.used[r] && !released[r]
                || usage.counts()[r] == Count::default() && !usage.quarantined()[r]
        })
        && snapshot.position == position
        && copies.iter().all(|c| {
            snapshot.used[c.region as usize] && snapshot.epochs[c.region as usize] == c.epoch
        })
        && snapshot.release.iter().all(|&region| {
            (region as usize) < count
                && snapshot.used[region as usize]
                && copies.iter().all(|c| c.region != region)
        })
        && snapshot
            .parts
            .iter()
            .all(|p| p.replay_sequence == position.sequence)
        && parts_valid(&snapshot.parts, shards)
}

fn parts_valid(parts: &[Part], shards: u32) -> bool {
    let mut tags: Vec<u16> = parts.iter().map(|p| p.tag).collect();
    tags.sort_unstable();
    tags.windows(2).all(|w| w[0] != w[1])
        && tags
            .iter()
            .all(|&tag| tag >= PART_TAG_OTHER || u32::from(tag) < shards)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{PART_TAG_OTHER, Part, Snapshot, decode, encode, parts_valid};
    use crate::journal::Position;
    use crate::usage::{Count, Usage};

    fn snapshot() -> Snapshot {
        Snapshot {
            position: Position {
                offset: 8192,
                sequence: 42,
                previous: 7,
            },
            record_sequence: 99,
            used: (0..11).map(|i| i % 3 == 0).collect(),
            epochs: (0..11).map(|i| i * 2).collect(),
            usage: Usage::from_parts(
                (0..11)
                    .map(|i| Count {
                        extents: i,
                        bytes: u64::from(i) * 100,
                    })
                    .collect(),
                (0..11).map(|i| i == 6).collect(),
                BTreeMap::from([(3, 2000), (8, 3500)]),
            ),
            release: vec![3, 9],
            parts: vec![
                Part {
                    tag: 1,
                    replay_sequence: 42,
                    bytes: vec![5; 13],
                },
                Part {
                    tag: 2,
                    replay_sequence: 42,
                    bytes: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn a_snapshot_round_trips() {
        let original = snapshot();
        let blob = encode(&original);
        assert_eq!(decode(&blob, 11), Some(original));
    }

    #[test]
    fn a_wrong_size_or_region_count_is_rejected() {
        let blob = encode(&snapshot());
        assert_eq!(decode(&blob, 12), None);
        assert_eq!(decode(&blob[..blob.len() - 8], 11), None);
        let mut longer = blob.clone();
        longer.extend_from_slice(&[0; 8]);
        assert_eq!(decode(&longer, 11), None);
        for cut in 0..blob.len() {
            let _ = decode(&blob[..cut], 11);
        }
    }

    fn part(tag: u16) -> Part {
        Part {
            tag,
            replay_sequence: 1,
            bytes: Vec::new(),
        }
    }

    #[test]
    fn part_tags_are_unique_shards_or_other() {
        assert!(parts_valid(&[part(0), part(3), part(PART_TAG_OTHER)], 4));
        assert!(!parts_valid(&[part(4)], 4));
        assert!(!parts_valid(&[part(2), part(2)], 4));
        assert!(parts_valid(&[part(u16::MAX)], 4));
    }
}
