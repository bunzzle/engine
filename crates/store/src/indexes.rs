use std::collections::BTreeMap;
use std::sync::Arc;

use index::{
    BLOCK, Cursor, Entry, Footer, Key, Memtable, Merge, Merged, Op, Range, Run, Segment, Shape,
    Source, find, footer_range,
};
use rt::Buf;

use crate::committer::Write;
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::layout::{Fields, FieldsMut};
use crate::roots::IndexRoot;
use sys::crc32c::checksum;

pub const KIND_INDEX: u8 = 5;

const HEAD: usize = 36;
const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;
const SEQUENCED: u32 = 1;
const TAIL: u32 = 2;
const HEAD_STAMP: std::ops::Range<usize> = 4..12;
const TAIL_STAMP: std::ops::Range<usize> = 12..20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexStamp {
    Off,
    Head,
    Tail,
}

impl IndexStamp {
    fn flags(self) -> u32 {
        match self {
            Self::Off => 0,
            Self::Head => SEQUENCED,
            Self::Tail => TAIL,
        }
    }

    fn from_flags(flags: u32) -> Option<Self> {
        match flags {
            0 => Some(Self::Off),
            SEQUENCED => Some(Self::Head),
            TAIL => Some(Self::Tail),
            _ => None,
        }
    }

    fn bytes(self) -> Option<std::ops::Range<usize>> {
        match self {
            Self::Off => None,
            Self::Head => Some(HEAD_STAMP),
            Self::Tail => Some(TAIL_STAMP),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexRecord {
    pub kind: u8,
    pub partition: u32,
    pub stamp: IndexStamp,
    pub entry: Entry,
}

impl IndexRecord {
    pub fn encode(&self) -> Vec<u8> {
        let entry = &self.entry;
        let mut out = vec![0u8; HEAD + entry.value.len() + entry.payload.len()];
        let mut fields = FieldsMut::new(&mut out);
        fields.put_u8(0, self.kind);
        fields.put_u8(
            1,
            match entry.op {
                Op::Put => OP_PUT,
                Op::Delete => OP_DELETE,
            },
        );
        fields.put_u16(
            2,
            u16::try_from(entry.value.len()).expect("index value fits in u16"),
        );
        fields.put_u32(4, self.partition);
        fields.put_u32(
            8,
            u32::try_from(entry.payload.len()).expect("index payload fits in u32"),
        );
        fields.put_u32(12, self.stamp.flags());
        fields.put_bytes(16, &entry.key);
        fields.put_bytes(HEAD, &entry.value);
        fields.put_bytes(HEAD + entry.value.len(), &entry.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let fields = Fields::new(bytes.get(..HEAD)?);
        let op = match fields.u8(1) {
            OP_PUT => Op::Put,
            OP_DELETE => Op::Delete,
            _ => return None,
        };
        let value = usize::from(fields.u16(2));
        let payload = usize::try_from(fields.u32(8)).ok()?;
        let stamp = IndexStamp::from_flags(fields.u32(12))?;
        if HEAD.checked_add(value)?.checked_add(payload)? != bytes.len() {
            return None;
        }
        let entry = Entry {
            key: fields.bytes(16, index::KEY).try_into().ok()?,
            op,
            value: bytes[HEAD..HEAD + value].to_vec(),
            payload: bytes[HEAD + value..].to_vec(),
        };
        Shape {
            value: fields.u16(2),
        }
        .check(&entry)
        .ok()?;
        Some(Self {
            kind: fields.u8(0),
            partition: fields.u32(4),
            stamp,
            entry,
        })
    }

    pub fn unstamped(&self) -> bool {
        self.stamp
            .bytes()
            .is_none_or(|at| self.entry.key[at].iter().all(|&b| b == 0))
    }

    #[must_use]
    pub fn stamped(mut self, sequence: u64) -> Self {
        match self.stamp {
            IndexStamp::Off => {}
            IndexStamp::Head => self.entry.key[HEAD_STAMP].copy_from_slice(&sequence.to_be_bytes()),
            IndexStamp::Tail => {
                self.entry.key[TAIL_STAMP].copy_from_slice(&(u64::MAX - sequence).to_be_bytes());
            }
        }
        self
    }

    pub fn write(&self, shard: u16) -> Write {
        Write {
            kind: KIND_INDEX,
            counted: false,
            shard,
            tenant: index::tenant(&self.entry.key),
            payload: self.encode(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Place {
    pub(crate) region: u32,
    pub(crate) epoch: u64,
    pub(crate) offset: u64,
    pub(crate) length: u32,
    pub(crate) checksum: u32,
}

#[derive(Clone)]
pub(crate) struct Stored {
    pub(crate) run: Arc<Run>,
    pub(crate) places: Arc<[Place]>,
}

impl Stored {
    pub(crate) fn bytes(&self) -> u64 {
        self.places.iter().map(|p| u64::from(p.length)).sum()
    }

    pub(crate) fn same(&self, other: &Stored) -> bool {
        Arc::ptr_eq(&self.run, &other.run)
    }
}

pub(crate) struct Swap {
    pub(crate) inputs: Vec<Stored>,
    pub(crate) output: Option<Stored>,
    pub(crate) regions: Vec<u32>,
}

pub(crate) struct Flushed {
    pub(crate) replaces: bool,
    pub(crate) output: Option<Stored>,
}

#[derive(Default)]
pub(crate) struct Partition {
    pub(crate) live: Option<Memtable>,
    pub(crate) frozen: Vec<Entry>,
    pub(crate) runs: Vec<Stored>,
    pub(crate) flushed: Option<Flushed>,
    pub(crate) merged: Vec<Swap>,
    pub(crate) cut_merges: Vec<Swap>,
    pub(crate) merging: bool,
    pub(crate) closed: Closed,
    pub(crate) dropped: Dropped,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Closed {
    #[default]
    Open,
    Whole,
    Tiered,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Dropped {
    #[default]
    Kept,
    Asked,
    InCut,
}

impl Partition {
    pub(crate) fn covered(&self) -> u64 {
        self.runs.last().map_or(0, |s| s.run.covered())
    }

    pub(crate) fn shape(&self) -> Option<Shape> {
        self.live
            .as_ref()
            .map(Memtable::shape)
            .or_else(|| self.runs.first().map(|s| s.run.shape()))
    }

    pub(crate) fn apply(&mut self, entry: Entry) -> Result<(), Error> {
        let shape = self.shape().unwrap_or(Shape {
            value: u16::try_from(entry.value.len()).map_err(|_| Error::Invalid("index shape"))?,
        });
        self.live
            .get_or_insert_with(|| Memtable::new(shape))
            .put(entry)
            .map_err(|_| Error::Invalid("index shape"))
    }

    pub(crate) fn freeze(&mut self) {
        assert!(self.frozen.is_empty(), "index frozen twice");
        self.frozen = self.live.as_mut().map(Memtable::take).unwrap_or_default();
        self.cut_merges = std::mem::take(&mut self.merged);
        if self.dropped == Dropped::Asked {
            self.dropped = Dropped::InCut;
        }
    }

    pub(crate) fn merged_runs(&self) -> Vec<Stored> {
        let mut runs = self.runs.clone();
        for swap in &self.cut_merges {
            let Some(at) = runs.iter().position(|r| r.same(&swap.inputs[0])) else {
                continue;
            };
            let end = at + swap.inputs.len();
            let contiguous = runs
                .get(at..end)
                .is_some_and(|found| found.iter().zip(&swap.inputs).all(|(a, b)| a.same(b)));
            if contiguous {
                runs.splice(at..end, swap.output.iter().cloned());
            }
        }
        runs
    }

    pub(crate) fn view(&self) -> Vec<Stored> {
        if self.dropped == Dropped::InCut {
            return Vec::new();
        }
        let mut runs = self.merged_runs();
        if let Some(flushed) = &self.flushed {
            if flushed.replaces {
                runs.pop();
            }
            runs.extend(flushed.output.iter().cloned());
        }
        runs
    }

    pub(crate) fn published(&mut self, unhold: &mut Vec<u32>) {
        self.runs = self.view();
        self.frozen.clear();
        self.flushed = None;
        for swap in std::mem::take(&mut self.cut_merges) {
            unhold.extend(swap.regions);
            self.merging = false;
        }
    }

    pub(crate) fn abandoned(&mut self) {
        self.flushed = None;
        if self.dropped == Dropped::InCut {
            self.dropped = Dropped::Asked;
        }
        let mut merged = std::mem::take(&mut self.cut_merges);
        merged.append(&mut self.merged);
        self.merged = merged;
        let frozen = std::mem::take(&mut self.frozen);
        if let Some(live) = self.live.as_mut() {
            live.restore(frozen);
        }
    }

    pub(crate) fn roots(&self, (kind, partition): (u8, u32), pending: bool) -> Vec<IndexRoot> {
        let runs = if pending {
            self.view()
        } else {
            self.runs.clone()
        };
        let mut roots = Vec::new();
        for (run, stored) in runs.iter().enumerate() {
            for (segment, place) in stored.places.iter().enumerate() {
                roots.push(IndexRoot {
                    kind,
                    partition,
                    run: u32::try_from(run).expect("runs fit in u32"),
                    segment: u32::try_from(segment).expect("segments fit in u32"),
                    region: place.region,
                    epoch: place.epoch,
                    offset: place.offset,
                    length: place.length,
                    checksum: place.checksum,
                    covered: stored.run.covered(),
                });
            }
        }
        roots
    }

    pub(crate) async fn lookup(
        &self,
        data: &CoreFile,
        key: &Key,
        payload: bool,
    ) -> Result<Option<Entry>, Error> {
        let newer = self.live.as_ref().and_then(|live| live.get(key));
        let frozen = self
            .frozen
            .binary_search_by(|e| e.key.cmp(key))
            .ok()
            .map(|at| &self.frozen[at]);
        if let Some(entry) = newer.or(frozen) {
            return Ok(Some(Entry {
                key: entry.key,
                op: entry.op,
                value: entry.value.clone(),
                payload: if payload {
                    entry.payload.clone()
                } else {
                    Vec::new()
                },
            }));
        }
        for stored in self.view().iter().rev() {
            let Some((segment, range)) = stored.run.probe(key) else {
                continue;
            };
            let place = &stored.places[segment];
            let block = read(data, place, range).await?;
            let Some(found) =
                find(stored.run.shape(), &block, key).map_err(|_| damaged(place, range))?
            else {
                continue;
            };
            let mut bytes = Vec::new();
            if payload && found.payload.length > 0 {
                let page = stored.run.segments()[segment]
                    .page(found.payload)
                    .map_err(|_| damaged(place, range))?;
                let block = read(data, place, page).await?;
                bytes = index::payload(&block, found.payload).map_err(|_| damaged(place, page))?;
            }
            return Ok(Some(Entry {
                key: found.key,
                op: found.op,
                value: found.value,
                payload: bytes,
            }));
        }
        Ok(None)
    }

    pub(crate) async fn range(
        &self,
        data: &CoreFile,
        from: Key,
        to: Key,
        limit: usize,
    ) -> Result<Vec<Entry>, Error> {
        let live: Vec<Entry> = self
            .live
            .as_ref()
            .map(|l| l.range(from).take_while(|e| e.key < to).cloned().collect())
            .unwrap_or_default();
        let start = self.frozen.partition_point(|e| e.key < from);
        let frozen: Vec<Entry> = self.frozen[start..]
            .iter()
            .take_while(|e| e.key < to)
            .cloned()
            .collect();
        let mut sources = vec![
            Source::Entries(live.into_iter()),
            Source::Entries(frozen.into_iter()),
        ];
        let view = self.view();
        let runs: Vec<&Stored> = view.iter().rev().collect();
        sources.extend(runs.iter().map(|s| Source::Run(Cursor::seek(&s.run, from))));
        let mut merge = Merge::new(sources, false);
        let mut out = Vec::new();
        while out.len() < limit {
            match merge.step().map_err(|_| Error::Invalid("index order"))? {
                Merged::Entry(entry) if entry.key < to => out.push(entry),
                Merged::Entry(_) | Merged::Done => break,
                Merged::Need(source, segment, range) => {
                    let place = &runs[source - 2].places[segment];
                    let bytes = read(data, place, range).await?;
                    merge
                        .feed(source, bytes)
                        .map_err(|_| damaged(place, range))?;
                }
            }
        }
        Ok(out)
    }

    pub(crate) async fn scan(&self, data: &CoreFile) -> Result<Vec<Entry>, Error> {
        let live: Vec<Entry> = self
            .live
            .as_ref()
            .map(|l| l.entries().cloned().collect())
            .unwrap_or_default();
        let mut sources = vec![
            Source::Entries(live.into_iter()),
            Source::Entries(self.frozen.clone().into_iter()),
        ];
        let runs: Vec<&Stored> = self.runs.iter().rev().collect();
        sources.extend(runs.iter().map(|s| Source::Run(Cursor::new(&s.run))));
        let mut merge = Merge::new(sources, false);
        let mut out = Vec::new();
        loop {
            match merge.step().map_err(|_| Error::Invalid("index order"))? {
                Merged::Entry(entry) => out.push(entry),
                Merged::Need(source, segment, range) => {
                    let place = &runs[source - 2].places[segment];
                    let bytes = read(data, place, range).await?;
                    merge
                        .feed(source, bytes)
                        .map_err(|_| damaged(place, range))?;
                }
                Merged::Done => return Ok(out),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub entries: usize,
    pub blocks: usize,
}

pub const MAX_PART_ENTRIES: usize = 4096;
pub const MAX_PART_BLOCKS: usize = 1024;

impl Budget {
    pub(crate) fn clamped(self) -> Self {
        Self {
            entries: self.entries.clamp(1, MAX_PART_ENTRIES),
            blocks: self.blocks.min(MAX_PART_BLOCKS),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tails {
    pub entries: Vec<(u16, usize, Entry)>,
    pub blocks: usize,
    pub more: bool,
}

pub(crate) struct TailPart<'a> {
    pub(crate) shard: u16,
    pub(crate) part: usize,
    pub(crate) partition: &'a Partition,
    pub(crate) keys: std::ops::Range<Key>,
}

struct Stream<'a> {
    shard: u16,
    part: usize,
    to: Key,
    runs: &'a [Stored],
    merge: Merge<'a>,
    head: Option<Entry>,
    done: bool,
    cut: bool,
}

pub(crate) fn after(mut key: Key) -> Key {
    for byte in key.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return key;
        }
    }
    [0xff; index::KEY]
}

fn tail(key: &Key) -> u64 {
    u64::from_be_bytes(key[TAIL_STAMP].try_into().expect("8 bytes"))
}

impl<'a> Stream<'a> {
    fn open(p: &TailPart<'_>, view: &'a [Stored], budget: Budget) -> Self {
        let (from, mut to) = (p.keys.start, p.keys.end);
        let mut live: Vec<Entry> = p
            .partition
            .live
            .as_ref()
            .map(|l| {
                l.range(from)
                    .take_while(|e| e.key < to)
                    .take(budget.entries + 1)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let start = p.partition.frozen.partition_point(|e| e.key < from);
        let mut frozen: Vec<Entry> = p.partition.frozen[start..]
            .iter()
            .take_while(|e| e.key < to)
            .take(budget.entries + 1)
            .cloned()
            .collect();
        let mut cut = false;
        for taken in [&mut live, &mut frozen] {
            if taken.len() > budget.entries
                && let Some(over) = taken.pop()
            {
                to = to.min(over.key);
                cut = true;
            }
        }
        let mut sources = vec![
            Source::Entries(live.into_iter()),
            Source::Entries(frozen.into_iter()),
        ];
        sources.extend(
            view.iter()
                .rev()
                .map(|s| Source::Run(Cursor::seek(&s.run, from))),
        );
        Self {
            shard: p.shard,
            part: p.part,
            to,
            runs: view,
            merge: Merge::new(sources, false),
            head: None,
            done: from >= to,
            cut,
        }
    }

    async fn fill(
        &mut self,
        data: &CoreFile,
        out: &mut Tails,
        budget: Budget,
    ) -> Result<bool, Error> {
        while self.head.is_none() && !self.done {
            if out.blocks >= budget.blocks && !out.entries.is_empty() {
                return Ok(false);
            }
            match self
                .merge
                .step()
                .map_err(|_| Error::Invalid("index order"))?
            {
                Merged::Entry(entry) if entry.key < self.to => self.head = Some(entry),
                Merged::Entry(_) | Merged::Done => {
                    self.done = true;
                    if self.cut {
                        return Ok(false);
                    }
                }
                Merged::Need(source, segment, range) => {
                    let stored = &self.runs[self.runs.len() - 1 - (source - 2)];
                    let place = &stored.places[segment];
                    let bytes = read(data, place, range).await?;
                    out.blocks += 1;
                    self.merge
                        .feed(source, bytes)
                        .map_err(|_| damaged(place, range))?;
                }
            }
        }
        Ok(true)
    }
}

pub(crate) async fn scan_tails(
    data: &CoreFile,
    parts: Vec<TailPart<'_>>,
    budget: Budget,
) -> Result<Tails, Error> {
    let views: Vec<(TailPart<'_>, Vec<Stored>)> = parts
        .into_iter()
        .map(|p| {
            let view = p.partition.view();
            (p, view)
        })
        .collect();
    let mut streams: Vec<Stream<'_>> = views
        .iter()
        .map(|(p, view)| Stream::open(p, view, budget))
        .collect();
    let mut out = Tails::default();
    loop {
        for stream in &mut streams {
            if !stream.fill(data, &mut out, budget).await? {
                out.more = true;
                return Ok(out);
            }
        }
        let next = streams
            .iter()
            .enumerate()
            .filter_map(|(at, s)| {
                s.head
                    .as_ref()
                    .map(|e| ((tail(&e.key), s.shard, s.part), at))
            })
            .min();
        let Some(((_, shard, part), at)) = next else {
            return Ok(out);
        };
        if out.entries.len() >= budget.entries {
            out.more = true;
            return Ok(out);
        }
        let entry = streams[at].head.take().expect("head");
        out.entries.push((shard, part, entry));
    }
}

pub(crate) fn damaged(place: &Place, range: Range) -> Error {
    Error::Damaged {
        region: place.region,
        offset: place.offset + range.offset,
    }
}

pub(crate) async fn read(data: &CoreFile, place: &Place, range: Range) -> Result<Vec<u8>, Error> {
    let sector = u64::from(data.sector_size());
    let start = place.offset + range.offset;
    let end = start + u64::from(range.length);
    if end > place.offset + u64::from(place.length) {
        return Err(damaged(place, range));
    }
    let from = start - start % sector;
    let length = usize::try_from(end.next_multiple_of(sector) - from).expect("read fits in usize");
    let (result, buf) = data
        .file()
        .read_at(
            Buf::aligned(length, data.sector_size() as usize),
            data.region_offset(place.region) + from,
        )
        .await;
    if result? != length {
        return Err(damaged(place, range));
    }
    let at = usize::try_from(start - from).expect("offset fits in usize");
    Ok(buf[at..at + range.length as usize].to_vec())
}

pub(crate) fn footer_checksum(bytes: &[u8]) -> u32 {
    checksum(&bytes[bytes.len() - BLOCK..])
}

pub(crate) async fn load(
    data: &CoreFile,
    roots: &[IndexRoot],
) -> Result<BTreeMap<(u8, u32), Partition>, Error> {
    let mut partitions: BTreeMap<(u8, u32), Partition> = BTreeMap::new();
    let mut at = 0;
    while at < roots.len() {
        let first = &roots[at];
        let end = at
            + roots[at..]
                .iter()
                .take_while(|r| r.partition_key() == first.partition_key() && r.run == first.run)
                .count();
        let mut segments = Vec::with_capacity(end - at);
        let mut places = Vec::with_capacity(end - at);
        for root in &roots[at..end] {
            let place = Place {
                region: root.region,
                epoch: root.epoch,
                offset: root.offset,
                length: root.length,
                checksum: root.checksum,
            };
            segments.push(load_segment(data, &place, root.covered).await?);
            places.push(place);
        }
        let run = Run::new(segments).map_err(|_| damaged(&places[0], whole(&places[0])))?;
        let partition = partitions.entry(first.partition_key()).or_default();
        if partition
            .runs
            .first()
            .is_some_and(|s| s.run.shape() != run.shape())
        {
            return Err(damaged(&places[0], whole(&places[0])));
        }
        partition.runs.push(Stored {
            run: Arc::new(run),
            places: places.into(),
        });
        at = end;
    }
    Ok(partitions)
}

fn whole(place: &Place) -> Range {
    Range {
        offset: 0,
        length: place.length,
    }
}

async fn load_segment(data: &CoreFile, place: &Place, covered: u64) -> Result<Segment, Error> {
    let range = footer_range(u64::from(place.length)).ok_or(damaged(place, whole(place)))?;
    let bytes = read(data, place, range).await?;
    if checksum(&bytes) != place.checksum {
        return Err(damaged(place, range));
    }
    let footer = Footer::decode(&bytes).map_err(|_| damaged(place, range))?;
    if footer.length() != u64::from(place.length) || footer.covered != covered {
        return Err(damaged(place, range));
    }
    let meta = footer.meta();
    let bytes = read(data, place, meta).await?;
    Segment::load(footer, &bytes).map_err(|_| damaged(place, meta))
}

pub(crate) async fn write_segment(
    data: &CoreFile,
    region: u32,
    epoch: u64,
    offset: u64,
    bytes: &[u8],
) -> Result<Place, Error> {
    let sector = data.sector_size() as usize;
    let length = bytes.len().next_multiple_of(sector);
    let mut buf = Buf::aligned(length, sector);
    buf.extend_from_slice(bytes);
    buf.set_len(length);
    buf[bytes.len()..].fill(0);
    let (result, _) = data
        .file()
        .write_all_at(buf, data.region_offset(region) + offset)
        .await;
    result?;
    Ok(Place {
        region,
        epoch,
        offset,
        length: u32::try_from(bytes.len()).expect("segment fits in a region"),
        checksum: footer_checksum(bytes),
    })
}
