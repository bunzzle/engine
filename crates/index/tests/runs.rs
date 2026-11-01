use std::collections::BTreeMap;

use index::{
    BLOCK, Cursor, Entry, Error, Footer, Key, Memtable, Merge, Merged, OVERHEAD, Op, Range, Run,
    Segment, Shape, Source, Step, Writer, find, footer_range, key, payload, siphash128,
};

const SHAPE: Shape = Shape { value: 12 };

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn key(&mut self) -> Key {
        let mut hash = [0; 16];
        hash[..8].copy_from_slice(&self.next().to_le_bytes());
        hash[8..].copy_from_slice(&self.next().to_le_bytes());
        key(u32::try_from(self.next() % 5).expect("small") + 1, hash)
    }

    fn entry(&mut self, key: Key) -> Entry {
        let value = self.next().to_le_bytes().repeat(2)[..12].to_vec();
        let length = match self.next() % 4 {
            0 => 0,
            1 => usize::try_from(self.next() % 64).expect("small"),
            2 => usize::try_from(self.next() % 400).expect("small"),
            _ => usize::try_from(self.next() % 4000).expect("small"),
        };
        Entry::put(key, value, vec![key[5]; length])
    }
}

fn slice(bytes: &[u8], range: Range) -> Vec<u8> {
    let start = usize::try_from(range.offset).expect("fits");
    bytes[start..start + range.length as usize].to_vec()
}

fn open(bytes: &[u8]) -> Result<Segment, Error> {
    let range = footer_range(bytes.len() as u64).ok_or(Error::Corrupt("length"))?;
    let footer = Footer::decode(&slice(bytes, range))?;
    if footer.length() != bytes.len() as u64 {
        return Err(Error::Corrupt("length"));
    }
    let meta = slice(bytes, footer.meta());
    Segment::load(footer, &meta)
}

fn write(entries: &[Entry], limit: u64, covered: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut writer = Writer::new(SHAPE, covered);
    let mut predicted = 0;
    for entry in entries {
        if !writer.is_empty() && writer.length_with(entry) > limit {
            let built = std::mem::replace(&mut writer, Writer::new(SHAPE, covered))
                .finish()
                .expect("not empty");
            assert_eq!(built.bytes.len() as u64, predicted, "length prediction");
            out.push(built.bytes);
        }
        predicted = writer.length_with(entry);
        writer.push(entry).expect("push");
    }
    if let Some(built) = writer.finish() {
        assert_eq!(built.bytes.len() as u64, predicted, "length prediction");
        out.push(built.bytes);
    }
    out
}

fn sorted(rng: &mut Rng, count: usize) -> Vec<Entry> {
    let mut map = BTreeMap::new();
    while map.len() < count {
        let key = rng.key();
        map.insert(key, rng.entry(key));
    }
    map.into_values().collect()
}

fn load(bytes: &[Vec<u8>]) -> Run {
    Run::new(bytes.iter().map(|b| open(b).expect("open")).collect()).expect("run")
}

fn get(run: &Run, bytes: &[Vec<u8>], key: &Key) -> Option<Entry> {
    let (segment, range) = run.probe(key)?;
    let found = find(run.shape(), &slice(&bytes[segment], range), key).expect("find")?;
    let payload = if found.payload.length == 0 {
        Vec::new()
    } else {
        let page = run.segments()[segment].page(found.payload).expect("page");
        payload(&slice(&bytes[segment], page), found.payload).expect("payload")
    };
    Some(Entry {
        key: found.key,
        op: found.op,
        value: found.value,
        payload,
    })
}

fn scan(mut cursor: Cursor<'_>, bytes: &[Vec<u8>]) -> Vec<Entry> {
    let mut out = Vec::new();
    loop {
        match cursor.step().expect("step") {
            Step::Entry(entry) => out.push(entry),
            Step::Need(segment, range) => cursor.feed(slice(&bytes[segment], range)).expect("feed"),
            Step::Done => return out,
        }
    }
}

#[test]
fn siphash128_matches_the_reference_vectors() {
    let key: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).expect("small"));
    let vectors = [
        (0, "a3817f04ba25a8e66df67214c7550293"),
        (1, "da87c1d86b99af44347659119b22fc45"),
        (7, "a1f1ebbed8dbc153c0b84aa61ff08239"),
        (8, "3b62a9ba6258f5610f83e264f31497b4"),
        (15, "5493e99933b0a8117e08ec0f97cfc3d9"),
        (16, "6ee2a4ca67b054bbfd3315bf85230577"),
        (63, "5150d1772f50834a503e069a973fbd7c"),
    ];
    for (length, expected) in vectors {
        let message: Vec<u8> = (0..length).collect();
        let hex = siphash128(&key, &message)
            .iter()
            .fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                write!(s, "{b:02x}").expect("string");
                s
            });
        assert_eq!(hex, expected, "length {length}");
    }
}

#[test]
fn every_written_entry_is_found_across_segments() {
    let mut rng = Rng(7);
    let entries = sorted(&mut rng, 20_000);
    let bytes = write(&entries, 256 * 1024, 41);
    assert!(bytes.len() > 4, "split into segments");
    for b in &bytes {
        assert!(b.len() as u64 <= 256 * 1024);
    }
    let run = load(&bytes);
    assert_eq!(run.entries(), 20_000);
    assert_eq!(run.covered(), 41);
    for entry in &entries {
        assert_eq!(get(&run, &bytes, &entry.key).as_ref(), Some(entry));
    }
    let mut probed = 0;
    for _ in 0..20_000 {
        let key = rng.key();
        if let Some((segment, range)) = run.probe(&key) {
            probed += 1;
            assert_eq!(find(SHAPE, &slice(&bytes[segment], range), &key), Ok(None));
        }
    }
    assert!(probed < 400, "false positives {probed}");
}

#[test]
fn cursors_scan_and_seek_in_order() {
    let mut rng = Rng(11);
    let entries = sorted(&mut rng, 5_000);
    let bytes = write(&entries, 128 * 1024, 3);
    let run = load(&bytes);
    assert_eq!(scan(Cursor::new(&run), &bytes), entries);
    for at in [0, 1, 99, 2_500, 4_999] {
        let from = entries[at].key;
        assert_eq!(scan(Cursor::seek(&run, from), &bytes), entries[at..]);
    }
    let mut after = entries[4_999].key;
    after[19] = after[19].wrapping_add(1);
    if after > entries[4_999].key {
        assert_eq!(scan(Cursor::seek(&run, after), &bytes), []);
    }
}

#[test]
fn merges_keep_the_newest_and_drop_deletes_on_request() {
    let mut rng = Rng(19);
    let keys: Vec<Key> = (0..3_000).map(|_| rng.key()).collect();
    let mut model = BTreeMap::new();
    let mut levels = Vec::new();
    for level in 0..3u64 {
        let mut map = BTreeMap::new();
        for _ in 0..1_500 {
            let key = keys[usize::try_from(rng.next() % 3_000).expect("small")];
            let entry = if rng.next().is_multiple_of(5) {
                Entry::delete(key, SHAPE)
            } else {
                rng.entry(key)
            };
            map.insert(key, entry.clone());
            model.insert(key, entry);
        }
        let entries: Vec<Entry> = map.into_values().collect();
        levels.push(write(&entries, 64 * 1024, level + 1));
    }
    let runs: Vec<Run> = levels.iter().map(|b| load(b)).collect();
    let mut newest = Memtable::new(SHAPE);
    for _ in 0..300 {
        let key = keys[usize::try_from(rng.next() % 3_000).expect("small")];
        let entry = rng.entry(key);
        newest.put(entry.clone()).expect("put");
        model.insert(key, entry);
    }
    for drop_deletes in [false, true] {
        let mut sources = vec![Source::Entries(
            newest.entries().cloned().collect::<Vec<_>>().into_iter(),
        )];
        sources.extend(runs.iter().rev().map(|r| Source::Run(Cursor::new(r))));
        let mut merge = Merge::new(sources, drop_deletes);
        let mut out = Vec::new();
        loop {
            match merge.step().expect("step") {
                Merged::Entry(entry) => out.push(entry),
                Merged::Need(source, segment, range) => {
                    let level = &levels[runs.len() - source];
                    merge
                        .feed(source, slice(&level[segment], range))
                        .expect("feed");
                }
                Merged::Done => break,
            }
        }
        let expected: Vec<Entry> = model
            .values()
            .filter(|e| !(drop_deletes && e.op == Op::Delete))
            .cloned()
            .collect();
        assert_eq!(out, expected, "drop deletes {drop_deletes}");
    }
}

#[test]
fn damaged_bytes_are_refused() {
    let mut rng = Rng(23);
    let entries = sorted(&mut rng, 2_000);
    let bytes = write(&entries, u64::MAX, 1).remove(0);
    let segment = open(&bytes).expect("open");
    let range = segment.block(3);
    let mut block = slice(&bytes, range);
    block[100] ^= 1;
    assert!(find(SHAPE, &block, &entries[0].key).is_err());
    let length = bytes.len();
    let meta = usize::try_from(segment.footer().meta().offset).expect("fits");
    for at in [length - BLOCK + 50, meta + 10, meta + 200, 5_000] {
        let mut damaged = bytes.clone();
        damaged[at] ^= 0x40;
        if at == 5_000 {
            let segment = open(&damaged).expect("meta intact");
            let block = slice(&damaged, segment.block(1));
            assert!(find(SHAPE, &block, &entries[0].key).is_err());
        } else {
            assert!(open(&damaged).is_err(), "byte {at}");
        }
    }
}

#[test]
fn writer_refuses_bad_input() {
    let mut rng = Rng(29);
    let entries = sorted(&mut rng, 3);
    let mut writer = Writer::new(SHAPE, 0);
    writer.push(&entries[1]).expect("push");
    assert_eq!(writer.push(&entries[0]), Err(Error::Order));
    assert_eq!(writer.push(&entries[1]), Err(Error::Order));
    let mut wrong = entries[2].clone();
    wrong.value.pop();
    assert_eq!(writer.push(&wrong), Err(Error::Shape));
    let mut big = entries[2].clone();
    big.payload = vec![0; index::MAX_PAYLOAD + 1];
    assert_eq!(writer.push(&big), Err(Error::TooLarge));
    assert!(Writer::new(SHAPE, 0).finish().is_none());
}

#[test]
fn memtable_counts_bytes_and_restores_under_newer() {
    let mut rng = Rng(31);
    let entries = sorted(&mut rng, 4);
    let mut table = Memtable::new(SHAPE);
    for entry in &entries[..3] {
        table.put(entry.clone()).expect("put");
    }
    let size = |e: &Entry| SHAPE.entry() + e.payload.len() + OVERHEAD;
    assert_eq!(table.bytes(), entries[..3].iter().map(size).sum::<usize>());
    let frozen = table.take();
    assert_eq!(frozen, entries[..3]);
    assert!(table.is_empty());
    assert_eq!(table.bytes(), 0);
    let newer = Entry::delete(entries[1].key, SHAPE);
    table.put(newer.clone()).expect("put");
    table.put(entries[3].clone()).expect("put");
    table.restore(frozen);
    assert_eq!(table.len(), 4);
    assert_eq!(table.get(&entries[1].key), Some(&newer));
    assert_eq!(table.get(&entries[0].key), Some(&entries[0]));
    let expected: usize = [&entries[0], &newer, &entries[2], &entries[3]]
        .into_iter()
        .map(size)
        .sum();
    assert_eq!(table.bytes(), expected);
}

#[test]
fn resealed_footers_with_bad_fields_are_refused() {
    let mut rng = Rng(37);
    let entries = sorted(&mut rng, 500);
    let bytes = write(&entries, u64::MAX, 1).remove(0);
    let range = footer_range(bytes.len() as u64).expect("range");
    let footer = slice(&bytes, range);
    assert!(Footer::decode(&footer).is_ok());
    let edits: [(usize, u64); 4] = [(20, 0), (20, 1 << 40), (28, 7), (32, 0)];
    for (at, value) in edits {
        let mut forged = footer.clone();
        let width = if at == 20 { 8 } else { 4 };
        forged[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
        let crc = sys::crc32c::checksum(&forged[..BLOCK - 4]);
        forged[BLOCK - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(Footer::decode(&forged).is_err(), "field at {at}");
    }
}
