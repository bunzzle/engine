use std::cmp::Ordering;

use sys::crc32c::checksum;

use crate::bloom::Bloom;
use crate::entry::{self, BLOCK, Entry, Found, KEY, Key, Reference, Shape};
use crate::error::Error;

const MAGIC: u32 = 0x5844_4e49;
const FORMAT: u32 = 1;
const CRC: usize = BLOCK - 4;
const BLOCK_LEN: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub offset: u64,
    pub length: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Footer {
    pub shape: Shape,
    pub blocks: u32,
    pub pages: u32,
    pub entries: u64,
    pub covered: u64,
    pub first: Key,
    pub last: Key,
    fences: u32,
    filter: u32,
    meta: u32,
}

impl Footer {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BLOCK || !sealed(bytes) {
            return Err(Error::Corrupt("footer"));
        }
        if u32_at(bytes, 0) != MAGIC || u32_at(bytes, 4) != FORMAT {
            return Err(Error::Corrupt("footer format"));
        }
        let footer = Self {
            shape: Shape {
                value: u16::from_le_bytes(bytes[8..10].try_into().expect("2 bytes")),
            },
            blocks: u32_at(bytes, 12),
            pages: u32_at(bytes, 16),
            entries: u64_at(bytes, 20),
            fences: u32_at(bytes, 28),
            filter: u32_at(bytes, 32),
            meta: u32_at(bytes, 36),
            covered: u64_at(bytes, 40),
            first: bytes[48..48 + KEY].try_into().expect("key"),
            last: bytes[68..68 + KEY].try_into().expect("key"),
        };
        let fences = u64::from(footer.blocks) * KEY as u64;
        let most = u64::from(footer.blocks) * footer.shape.per_block() as u64;
        if footer.shape.per_block() == 0
            || u64::from(footer.fences) != fences
            || footer.filter == 0
            || footer.entries == 0
            || footer.entries > most
            || footer.first > footer.last
        {
            return Err(Error::Corrupt("footer fields"));
        }
        Ok(footer)
    }

    pub fn meta(&self) -> Range {
        Range {
            offset: (u64::from(self.blocks) + u64::from(self.pages)) * BLOCK as u64,
            length: self.fences + self.filter,
        }
    }

    pub fn length(&self) -> u64 {
        self.meta().offset
            + u64::from(self.fences + self.filter).next_multiple_of(BLOCK as u64)
            + BLOCK as u64
    }
}

pub fn footer_range(length: u64) -> Option<Range> {
    (length >= 2 * BLOCK as u64 && length.is_multiple_of(BLOCK as u64)).then(|| Range {
        offset: length - BLOCK as u64,
        length: BLOCK_LEN,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    footer: Footer,
    fences: Vec<Key>,
    bloom: Bloom,
}

impl Segment {
    pub fn load(footer: Footer, meta: &[u8]) -> Result<Self, Error> {
        let fences = footer.fences as usize;
        if meta.len() != fences + footer.filter as usize || checksum(meta) != footer.meta {
            return Err(Error::Corrupt("segment meta"));
        }
        let keys: Vec<Key> = meta[..fences].as_chunks::<KEY>().0.to_vec();
        let ordered = keys.windows(2).all(|w| w[0] < w[1]);
        if !ordered || keys.first() != Some(&footer.first) {
            return Err(Error::Corrupt("segment fences"));
        }
        let bloom =
            Bloom::from_bytes(meta[fences..].to_vec()).ok_or(Error::Corrupt("segment filter"))?;
        Ok(Self {
            footer,
            fences: keys,
            bloom,
        })
    }

    pub fn footer(&self) -> &Footer {
        &self.footer
    }

    pub fn first(&self) -> &Key {
        &self.footer.first
    }

    pub fn last(&self) -> &Key {
        &self.footer.last
    }

    pub fn blocks(&self) -> u32 {
        self.footer.blocks
    }

    pub fn pinned(&self) -> usize {
        self.fences.len() * KEY + self.bloom.bytes().len()
    }

    pub fn probe(&self, key: &Key) -> Option<u32> {
        if key < &self.footer.first || key > &self.footer.last || !self.bloom.may(key) {
            return None;
        }
        Some(self.block_of(key))
    }

    pub fn block_of(&self, key: &Key) -> u32 {
        let block = self.fences.partition_point(|f| f <= key).saturating_sub(1);
        u32::try_from(block).expect("blocks fit u32")
    }

    pub fn block(&self, block: u32) -> Range {
        Range {
            offset: u64::from(block) * BLOCK as u64,
            length: BLOCK_LEN,
        }
    }

    pub fn page(&self, payload: Reference) -> Result<Range, Error> {
        let offset = u64::from(payload.offset);
        let page = offset - offset % BLOCK as u64;
        let fits = offset % BLOCK as u64 + u64::from(payload.length) <= CRC as u64;
        if payload.length == 0 || page >= u64::from(self.footer.pages) * BLOCK as u64 || !fits {
            return Err(Error::Corrupt("payload reference"));
        }
        Ok(Range {
            offset: u64::from(self.footer.blocks) * BLOCK as u64 + page,
            length: BLOCK_LEN,
        })
    }
}

pub fn entries(shape: Shape, block: &[u8]) -> Result<Vec<Found>, Error> {
    let count = block_count(shape, block)?;
    let found = (0..count)
        .map(|i| entry::decode(shape, &block[2 + i * shape.entry()..]))
        .collect::<Result<Vec<_>, _>>()?;
    if !found.windows(2).all(|w| w[0].key < w[1].key) {
        return Err(Error::Corrupt("block order"));
    }
    Ok(found)
}

pub fn find(shape: Shape, block: &[u8], key: &Key) -> Result<Option<Found>, Error> {
    let count = block_count(shape, block)?;
    let size = shape.entry();
    let (mut low, mut high) = (0, count);
    while low < high {
        let mid = low + (high - low) / 2;
        let at = 2 + mid * size;
        match block[at..at + KEY].cmp(key) {
            Ordering::Less => low = mid + 1,
            Ordering::Greater => high = mid,
            Ordering::Equal => return entry::decode(shape, &block[at..]).map(Some),
        }
    }
    Ok(None)
}

pub fn payload(page: &[u8], payload: Reference) -> Result<Vec<u8>, Error> {
    if page.len() != BLOCK || !sealed(page) {
        return Err(Error::Corrupt("payload page"));
    }
    let start = payload.offset as usize % BLOCK;
    let end = start + usize::from(payload.length);
    if end > CRC {
        return Err(Error::Corrupt("payload reference"));
    }
    Ok(page[start..end].to_vec())
}

fn block_count(shape: Shape, block: &[u8]) -> Result<usize, Error> {
    if block.len() != BLOCK || !sealed(block) {
        return Err(Error::Corrupt("block"));
    }
    let count = usize::from(u16::from_le_bytes(block[..2].try_into().expect("2 bytes")));
    if count == 0 || count > shape.per_block() {
        return Err(Error::Corrupt("block count"));
    }
    Ok(count)
}

pub struct Built {
    pub bytes: Vec<u8>,
    pub first: Key,
    pub last: Key,
    pub entries: u64,
}

pub struct Writer {
    shape: Shape,
    covered: u64,
    blocks: Vec<u8>,
    block: Vec<u8>,
    count: usize,
    pages: Vec<u8>,
    page: Vec<u8>,
    fences: Vec<Key>,
    keys: Vec<Key>,
    last: Option<Key>,
}

impl Writer {
    pub fn new(shape: Shape, covered: u64) -> Self {
        assert!(shape.per_block() > 0, "entry larger than a block");
        Self {
            shape,
            covered,
            blocks: Vec::new(),
            block: fresh(),
            count: 0,
            pages: Vec::new(),
            page: Vec::new(),
            fences: Vec::new(),
            keys: Vec::new(),
            last: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn length_with(&self, entry: &Entry) -> u64 {
        let keys = self.keys.len() + 1;
        let full = self.count == self.shape.per_block();
        let blocks = self.blocks.len() / BLOCK + 1 + usize::from(full);
        let page_full = self.page.len() + entry.payload.len() > entry::MAX_PAYLOAD;
        let pages = self.pages.len() / BLOCK
            + usize::from(!self.page.is_empty() || !entry.payload.is_empty())
            + usize::from(page_full && !entry.payload.is_empty());
        let meta = blocks * KEY + Bloom::new(keys).bytes().len();
        ((blocks + pages) * BLOCK + meta.next_multiple_of(BLOCK) + BLOCK) as u64
    }

    pub fn push(&mut self, entry: &Entry) -> Result<(), Error> {
        self.shape.check(entry)?;
        if self.last.is_some_and(|last| last >= entry.key) {
            return Err(Error::Order);
        }
        if self.count == self.shape.per_block() {
            self.end_block();
        }
        if self.count == 0 {
            self.fences.push(entry.key);
        }
        let reference = self.add_payload(&entry.payload);
        let size = self.shape.entry();
        let at = 2 + self.count * size;
        entry::encode(self.shape, entry, reference, &mut self.block[at..at + size]);
        self.count += 1;
        self.keys.push(entry.key);
        self.last = Some(entry.key);
        Ok(())
    }

    pub fn finish(mut self) -> Option<Built> {
        let (first, last) = (*self.keys.first()?, self.last?);
        self.end_block();
        if !self.page.is_empty() {
            self.end_page();
        }
        let blocks = u32::try_from(self.blocks.len() / BLOCK).expect("blocks fit u32");
        let pages = u32::try_from(self.pages.len() / BLOCK).expect("pages fit u32");
        let mut bloom = Bloom::new(self.keys.len());
        for key in &self.keys {
            bloom.add(key);
        }
        let mut meta: Vec<u8> = self.fences.iter().flatten().copied().collect();
        let fences = u32::try_from(meta.len()).expect("fences fit u32");
        meta.extend_from_slice(bloom.bytes());
        let filter = u32::try_from(bloom.bytes().len()).expect("filter fits u32");
        let meta_crc = checksum(&meta);
        let mut bytes = self.blocks;
        bytes.extend_from_slice(&self.pages);
        bytes.extend_from_slice(&meta);
        bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
        let mut footer = vec![0; BLOCK];
        footer[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        footer[4..8].copy_from_slice(&FORMAT.to_le_bytes());
        footer[8..10].copy_from_slice(&self.shape.value.to_le_bytes());
        footer[12..16].copy_from_slice(&blocks.to_le_bytes());
        footer[16..20].copy_from_slice(&pages.to_le_bytes());
        let entries = self.keys.len() as u64;
        footer[20..28].copy_from_slice(&entries.to_le_bytes());
        footer[28..32].copy_from_slice(&fences.to_le_bytes());
        footer[32..36].copy_from_slice(&filter.to_le_bytes());
        footer[36..40].copy_from_slice(&meta_crc.to_le_bytes());
        footer[40..48].copy_from_slice(&self.covered.to_le_bytes());
        footer[48..48 + KEY].copy_from_slice(&first);
        footer[68..68 + KEY].copy_from_slice(&last);
        seal(&mut footer);
        bytes.extend_from_slice(&footer);
        Some(Built {
            bytes,
            first,
            last,
            entries,
        })
    }

    fn add_payload(&mut self, payload: &[u8]) -> Reference {
        if payload.is_empty() {
            return Reference {
                offset: 0,
                length: 0,
            };
        }
        if self.page.len() + payload.len() > entry::MAX_PAYLOAD {
            self.end_page();
        }
        let offset = self.pages.len() + self.page.len();
        self.page.extend_from_slice(payload);
        Reference {
            offset: u32::try_from(offset).expect("segment below 4 GiB"),
            length: u16::try_from(payload.len()).expect("payload fits u16"),
        }
    }

    fn end_block(&mut self) {
        if self.count == 0 {
            return;
        }
        let count = u16::try_from(self.count).expect("count fits u16");
        self.block[..2].copy_from_slice(&count.to_le_bytes());
        seal(&mut self.block);
        self.blocks.extend_from_slice(&self.block);
        self.block = fresh();
        self.count = 0;
    }

    fn end_page(&mut self) {
        let mut page = std::mem::take(&mut self.page);
        page.resize(BLOCK, 0);
        seal(&mut page);
        self.pages.extend_from_slice(&page);
    }
}

fn fresh() -> Vec<u8> {
    vec![0; BLOCK]
}

fn seal(bytes: &mut [u8]) {
    let crc = checksum(&bytes[..CRC]);
    bytes[CRC..].copy_from_slice(&crc.to_le_bytes());
}

fn sealed(bytes: &[u8]) -> bool {
    checksum(&bytes[..CRC]) == u32_at(bytes, CRC)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
}
