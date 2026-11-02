use std::collections::BTreeMap;

use index::{
    BLOCK, Cursor, Entry, Footer, Key, Memtable, Merge, Merged, Op, Range, Run, Segment, Shape,
    Source, Writer, find, footer_range,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexRecord {
    pub kind: u8,
    pub partition: u32,
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
        if fields.u32(12) != 0 || HEAD.checked_add(value)?.checked_add(payload)? != bytes.len() {
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
            entry,
        })
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

pub(crate) struct Stored {
    pub(crate) run: Run,
    pub(crate) places: Vec<Place>,
}

#[derive(Default)]
pub(crate) struct Partition {
    pub(crate) live: Option<Memtable>,
    pub(crate) frozen: Vec<Entry>,
    pub(crate) runs: Vec<Stored>,
    pub(crate) flushed: Option<Stored>,
}

impl Partition {
    pub(crate) fn covered(&self) -> u64 {
        self.runs.last().map_or(0, |s| s.run.covered())
    }

    fn shape(&self) -> Option<Shape> {
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
    }

    pub(crate) fn published(&mut self) {
        self.frozen.clear();
        if let Some(stored) = self.flushed.take() {
            self.runs.push(stored);
        }
    }

    pub(crate) fn abandoned(&mut self) {
        self.flushed = None;
        let frozen = std::mem::take(&mut self.frozen);
        if let Some(live) = self.live.as_mut() {
            live.restore(frozen);
        }
    }

    pub(crate) fn roots(&self, (kind, partition): (u8, u32), pending: bool) -> Vec<IndexRoot> {
        let mut roots = Vec::new();
        let flushed = self.flushed.iter().filter(|_| pending);
        for (run, stored) in self.runs.iter().chain(flushed).enumerate() {
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
    ) -> Result<Option<(Op, Vec<u8>)>, Error> {
        let newer = self.live.as_ref().and_then(|live| live.get(key));
        let frozen = self
            .frozen
            .binary_search_by(|e| e.key.cmp(key))
            .ok()
            .map(|at| &self.frozen[at]);
        if let Some(entry) = newer.or(frozen) {
            return Ok(Some((entry.op, entry.value.clone())));
        }
        for stored in self.runs.iter().rev() {
            let Some((segment, range)) = stored.run.probe(key) else {
                continue;
            };
            let place = &stored.places[segment];
            let block = read(data, place, range).await?;
            if let Some(found) =
                find(stored.run.shape(), &block, key).map_err(|_| damaged(place, range))?
            {
                return Ok(Some((found.op, found.value)));
            }
        }
        Ok(None)
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

fn damaged(place: &Place, range: Range) -> Error {
    Error::Damaged {
        region: place.region,
        offset: place.offset + range.offset,
    }
}

async fn read(data: &CoreFile, place: &Place, range: Range) -> Result<Vec<u8>, Error> {
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

pub(crate) fn segments(
    shape: Shape,
    covered: u64,
    entries: &[Entry],
    region_size: u64,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut writer = Writer::new(shape, covered);
    for entry in entries {
        if !writer.is_empty() && writer.length_with(entry) > region_size {
            let full = std::mem::replace(&mut writer, Writer::new(shape, covered));
            out.extend(full.finish().map(|b| b.bytes));
        }
        writer
            .push(entry)
            .expect("memtable entries are sorted and checked");
    }
    out.extend(writer.finish().map(|b| b.bytes));
    out
}

pub(crate) fn built(bytes: &[u8]) -> Segment {
    let footer = Footer::decode(&bytes[bytes.len() - BLOCK..]).expect("built footer");
    let meta = footer.meta();
    let at = usize::try_from(meta.offset).expect("meta fits in usize");
    Segment::load(footer, &bytes[at..at + meta.length as usize]).expect("built segment")
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
        partition.runs.push(Stored { run, places });
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
