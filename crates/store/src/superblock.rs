use crate::error::Error;
use crate::journal::Position;
use crate::layout::{Fields, FieldsMut};
use sys::crc32c::checksum;

pub const FORMAT: u16 = 1;
pub const COPIES: usize = 4;
pub const SLOT_SIZE: u64 = 64 * 1024;
pub const ZONE_SIZE: u64 = SLOT_SIZE * COPIES as u64;
pub const MAX_SHARDS: u32 = 0x8000;
pub const MIN_SECTOR_SIZE: u32 = 4096;
pub const MAX_SECTOR_SIZE: u32 = 64 * 1024;

pub(crate) const HEADER_SIZE: usize = 4096;
const QUORUM: usize = 2;
const MAGIC: [u8; 8] = *b"bunzzle\0";
const CHECKED: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub position: Position,
    pub copies: [CheckpointCopy; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointCopy {
    pub region: u32,
    pub epoch: u64,
    pub length: u64,
    pub checksum: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub(crate) format: u16,
    pub(crate) oldest_format: u16,
    pub(crate) sector_size: u32,
    pub(crate) sequence: u64,
    pub(crate) parent: u32,
    pub(crate) shards: u32,
    pub(crate) file_id: u64,
    pub(crate) file_size: u64,
    pub(crate) regions_offset: u64,
    pub(crate) journal_size: u64,
    pub(crate) region_size: u64,
    pub(crate) region_count: u32,
    pub(crate) checkpoint: Option<Checkpoint>,
}

impl Superblock {
    pub fn format(&self) -> u16 {
        self.format
    }

    pub fn oldest_format(&self) -> u16 {
        self.oldest_format
    }

    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn shards(&self) -> u32 {
        self.shards
    }

    pub fn file_id(&self) -> u64 {
        self.file_id
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    pub fn regions_offset(&self) -> u64 {
        self.regions_offset
    }

    pub fn journal_size(&self) -> u64 {
        self.journal_size
    }

    pub fn journal_offsets(&self) -> [u64; 2] {
        [
            ZONE_SIZE,
            self.regions_offset + u64::from(self.region_count) * self.region_size,
        ]
    }

    pub fn region_size(&self) -> u64 {
        self.region_size
    }

    pub fn region_offset(&self, region: u32) -> u64 {
        assert!(region < self.region_count, "region {region} out of range");
        self.regions_offset + u64::from(region) * self.region_size
    }

    pub fn region_count(&self) -> u32 {
        self.region_count
    }

    pub fn checkpoint(&self) -> Option<Checkpoint> {
        self.checkpoint
    }

    pub(crate) fn encode(&self, copy: u16, out: &mut [u8]) -> u32 {
        let out = &mut out[..HEADER_SIZE];
        out.fill(0);
        let mut fields = FieldsMut::new(out);
        fields.put_u16(4, copy);
        fields.put_bytes(6, &MAGIC);
        fields.put_u16(14, self.format);
        fields.put_u16(16, self.oldest_format);
        fields.put_u32(20, self.sector_size);
        fields.put_u64(24, self.sequence);
        fields.put_u32(32, self.parent);
        fields.put_u32(36, self.shards);
        fields.put_u64(40, self.file_id);
        fields.put_u64(48, self.file_size);
        fields.put_u64(56, self.regions_offset);
        fields.put_u64(112, self.journal_size);
        fields.put_u64(64, self.region_size);
        fields.put_u32(72, self.region_count);
        if let Some(checkpoint) = self.checkpoint {
            fields.put_u64(80, checkpoint.position.sequence);
            fields.put_u64(88, checkpoint.position.offset);
            fields.put_u32(96, checkpoint.position.previous);
            for (copy, at) in checkpoint.copies.iter().zip([120, 144]) {
                fields.put_u32(at, copy.region);
                fields.put_u32(at + 4, copy.checksum);
                fields.put_u64(at + 8, copy.epoch);
                fields.put_u64(at + 16, copy.length);
            }
        }
        let sum = checksum(&out[CHECKED..]);
        FieldsMut::new(out).put_u32(0, sum);
        sum
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Stored> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        let bytes = &bytes[..HEADER_SIZE];
        let fields = Fields::new(bytes);
        let sum = fields.u32(0);
        if sum != checksum(&bytes[CHECKED..]) || fields.bytes(6, 8) != MAGIC {
            return None;
        }
        let copy = |at: usize| CheckpointCopy {
            region: fields.u32(at),
            checksum: fields.u32(at + 4),
            epoch: fields.u64(at + 8),
            length: fields.u64(at + 16),
        };
        let checkpoint = (fields.u64(136) > 0).then(|| Checkpoint {
            position: Position {
                sequence: fields.u64(80),
                offset: fields.u64(88),
                previous: fields.u32(96),
            },
            copies: [copy(120), copy(144)],
        });
        Some(Stored {
            superblock: Self {
                format: fields.u16(14),
                oldest_format: fields.u16(16),
                sector_size: fields.u32(20),
                sequence: fields.u64(24),
                parent: fields.u32(32),
                shards: fields.u32(36),
                file_id: fields.u64(40),
                file_size: fields.u64(48),
                regions_offset: fields.u64(56),
                journal_size: fields.u64(112),
                region_size: fields.u64(64),
                region_count: fields.u32(72),
                checkpoint,
            },
            copy: fields.u16(4),
            checksum: sum,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !self.sector_size.is_power_of_two()
            || !(MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE).contains(&self.sector_size)
        {
            return Err(Error::Invalid("sector size"));
        }
        if self.region_size == 0 || !self.region_size.is_multiple_of(SLOT_SIZE) {
            return Err(Error::Invalid("region size"));
        }
        if self.journal_size == 0 || !self.journal_size.is_multiple_of(SLOT_SIZE) {
            return Err(Error::Invalid("journal size"));
        }
        if self.region_count == 0
            || self.shards == 0
            || self.shards > MAX_SHARDS
            || self.regions_offset != ZONE_SIZE + self.journal_size
        {
            return Err(Error::Invalid("layout"));
        }
        let size = u64::from(self.region_count)
            .checked_mul(self.region_size)
            .and_then(|regions| regions.checked_add(self.regions_offset))
            .and_then(|end| end.checked_add(self.journal_size));
        if size != Some(self.file_size) {
            return Err(Error::Invalid("file size"));
        }
        if self.oldest_format > self.format {
            return Err(Error::Invalid("oldest format"));
        }
        if let Some(checkpoint) = self.checkpoint {
            let [first, second] = checkpoint.copies;
            let valid = checkpoint.position.sequence > 0
                && checkpoint.position.offset < self.journal_size
                && checkpoint
                    .position
                    .offset
                    .is_multiple_of(u64::from(self.sector_size))
                && first.region != second.region
                && checkpoint.copies.iter().all(|c| {
                    c.region < self.region_count
                        && c.epoch > 0
                        && c.length > 0
                        && c.length <= self.region_size
                        && c.length.is_multiple_of(u64::from(self.sector_size))
                });
            if !valid {
                return Err(Error::Invalid("checkpoint"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Stored {
    pub superblock: Superblock,
    pub copy: u16,
    pub checksum: u32,
}

#[derive(Debug)]
pub(crate) struct Selected {
    pub superblock: Superblock,
    pub checksum: u32,
    pub stale: Vec<usize>,
}

struct Group {
    superblock: Superblock,
    checksum: u32,
    count: usize,
}

pub(crate) fn select(copies: &[Option<Stored>; COPIES]) -> Result<Selected, Error> {
    let mut groups: Vec<Group> = Vec::new();
    for (slot, copy) in copies.iter().enumerate() {
        let Some(copy) = copy else { continue };
        if usize::from(copy.copy) != slot {
            continue;
        }
        match groups
            .iter_mut()
            .find(|g| g.checksum == copy.checksum && g.superblock == copy.superblock)
        {
            Some(group) => group.count += 1,
            None => groups.push(Group {
                superblock: copy.superblock,
                checksum: copy.checksum,
                count: 1,
            }),
        }
    }
    if groups.is_empty() {
        return Err(Error::NotFormatted);
    }
    let best = groups
        .iter()
        .filter(|g| g.count >= QUORUM)
        .max_by_key(|g| g.superblock.sequence)
        .ok_or(Error::QuorumLost)?;
    let newest = best.superblock;
    for group in &groups {
        let other = group.superblock;
        if other.file_id != newest.file_id {
            return Err(Error::ForeignCopy);
        }
        if group.checksum == best.checksum && other == newest {
            continue;
        }
        if other.sequence == newest.sequence {
            return Err(Error::Fork);
        }
        if other.sequence > newest.sequence + 1 {
            return Err(Error::SequenceSkipped);
        }
        if other.sequence + 1 == newest.sequence && newest.parent != group.checksum {
            return Err(Error::ParentNotConnected);
        }
    }
    let stale = copies
        .iter()
        .enumerate()
        .filter(|(slot, copy)| {
            !copy.is_some_and(|c| c.checksum == best.checksum && usize::from(c.copy) == *slot)
        })
        .map(|(slot, _)| slot)
        .collect();
    Ok(Selected {
        superblock: newest,
        checksum: best.checksum,
        stale,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        COPIES, Checkpoint, CheckpointCopy, FORMAT, HEADER_SIZE, Position, Stored, Superblock,
        ZONE_SIZE, select,
    };
    use crate::error::Error;

    fn superblock(sequence: u64) -> Superblock {
        Superblock {
            format: FORMAT,
            oldest_format: FORMAT,
            sector_size: 4096,
            sequence,
            parent: 0,
            shards: 4,
            file_id: 7,
            file_size: ZONE_SIZE + 4 * 65536,
            regions_offset: ZONE_SIZE + 65536,
            journal_size: 65536,
            region_size: 65536,
            region_count: 2,
            checkpoint: None,
        }
    }

    fn copy(superblock: &Superblock, slot: usize) -> Option<Stored> {
        let mut bytes = vec![0u8; HEADER_SIZE];
        superblock.encode(u16::try_from(slot).expect("slot"), &mut bytes);
        Superblock::decode(&bytes)
    }

    fn chain() -> (Superblock, Superblock) {
        let first = superblock(1);
        let mut bytes = vec![0u8; HEADER_SIZE];
        let mut second = superblock(2);
        second.parent = first.encode(0, &mut bytes);
        (first, second)
    }

    fn slots(layout: [Option<&Superblock>; COPIES]) -> [Option<Stored>; COPIES] {
        let mut out = [None; COPIES];
        for (slot, superblock) in layout.iter().enumerate() {
            out[slot] = superblock.and_then(|s| copy(s, slot));
        }
        out
    }

    #[test]
    fn encode_and_decode_round_trip() {
        let mut original = superblock(9);
        original.checkpoint = Some(Checkpoint {
            position: Position {
                sequence: 3,
                offset: 4096,
                previous: 5,
            },
            copies: [
                CheckpointCopy {
                    region: 1,
                    epoch: 2,
                    length: 8192,
                    checksum: 11,
                },
                CheckpointCopy {
                    region: 4,
                    epoch: 6,
                    length: 4096,
                    checksum: 12,
                },
            ],
        });
        let decoded = copy(&original, 2).expect("decodes");
        assert_eq!(decoded.superblock, original);
        assert_eq!(decoded.copy, 2);
        assert_eq!(
            copy(&original, 0).expect("decodes").checksum,
            decoded.checksum
        );
    }

    #[test]
    fn a_flipped_bit_fails_the_checksum() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        superblock(1).encode(0, &mut bytes);
        bytes[200] ^= 1;
        assert!(Superblock::decode(&bytes).is_none());
    }

    #[test]
    fn the_newest_quorum_wins() {
        let (first, second) = chain();
        let picked =
            select(&slots([Some(&second), Some(&second), Some(&first), None])).expect("selects");
        assert_eq!(picked.superblock.sequence, 2);
        assert_eq!(picked.stale, vec![2, 3]);
    }

    #[test]
    fn a_single_newer_copy_is_an_unfinished_update() {
        let (first, second) = chain();
        let picked = select(&slots([
            Some(&second),
            Some(&first),
            Some(&first),
            Some(&first),
        ]))
        .expect("selects");
        assert_eq!(picked.superblock.sequence, 1);
        assert_eq!(picked.stale, vec![0]);
    }

    #[test]
    fn a_misplaced_copy_does_not_count() {
        let (_, second) = chain();
        let mut layout = slots([Some(&second), None, None, None]);
        layout[1] = copy(&second, 0);
        assert!(matches!(select(&layout), Err(Error::QuorumLost)));
    }

    #[test]
    fn errors_are_typed() {
        let (first, second) = chain();
        assert!(matches!(select(&[None; COPIES]), Err(Error::NotFormatted)));
        assert!(matches!(
            select(&slots([Some(&first), None, None, None])),
            Err(Error::QuorumLost)
        ));

        let mut forked = second;
        forked.shards = 8;
        assert!(matches!(
            select(&slots([
                Some(&second),
                Some(&second),
                Some(&forked),
                Some(&forked)
            ])),
            Err(Error::Fork)
        ));

        let mut orphan = second;
        orphan.parent = 99;
        assert!(matches!(
            select(&slots([
                Some(&orphan),
                Some(&orphan),
                Some(&first),
                Some(&first)
            ])),
            Err(Error::ParentNotConnected)
        ));

        let mut foreign = first;
        foreign.file_id = 8;
        assert!(matches!(
            select(&slots([Some(&first), Some(&first), Some(&foreign), None])),
            Err(Error::ForeignCopy)
        ));

        let skipped = superblock(4);
        assert!(matches!(
            select(&slots([
                Some(&skipped),
                Some(&first),
                Some(&first),
                Some(&first)
            ])),
            Err(Error::SequenceSkipped)
        ));
    }
}
