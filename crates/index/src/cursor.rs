use crate::entry::{Entry, Found, Key, Op};
use crate::error::Error;
use crate::run::Run;
use crate::segment::{self, Range};

#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Entry(Entry),
    Need(usize, Range),
    Done,
}

#[derive(Clone, Copy)]
enum Waiting {
    Nothing,
    Block,
    Page(u64),
}

pub struct Cursor<'a> {
    run: &'a Run,
    segment: usize,
    block: u32,
    entries: Vec<Found>,
    at: usize,
    page: Option<(u64, Vec<u8>)>,
    waiting: Waiting,
    from: Option<Key>,
}

impl<'a> Cursor<'a> {
    pub fn new(run: &'a Run) -> Self {
        Self {
            run,
            segment: 0,
            block: 0,
            entries: Vec::new(),
            at: 0,
            page: None,
            waiting: Waiting::Nothing,
            from: None,
        }
    }

    pub fn seek(run: &'a Run, from: Key) -> Self {
        let segment = run.segments().partition_point(|s| s.last() < &from);
        let block = run.segments().get(segment).map_or(0, |s| s.block_of(&from));
        Self {
            segment,
            block,
            from: Some(from),
            ..Self::new(run)
        }
    }

    pub fn step(&mut self) -> Result<Step, Error> {
        loop {
            if let Some(found) = self.entries.get(self.at) {
                if self.from.is_some_and(|from| found.key < from) {
                    self.at += 1;
                    continue;
                }
                let payload = if found.payload.length == 0 {
                    Vec::new()
                } else {
                    let range = self.run.segments()[self.segment].page(found.payload)?;
                    match &self.page {
                        Some((offset, page)) if *offset == range.offset => {
                            segment::payload(page, found.payload)?
                        }
                        _ => {
                            self.waiting = Waiting::Page(range.offset);
                            return Ok(Step::Need(self.segment, range));
                        }
                    }
                };
                let found = &self.entries[self.at];
                self.at += 1;
                return Ok(Step::Entry(Entry {
                    key: found.key,
                    op: found.op,
                    value: found.value.clone(),
                    payload,
                }));
            }
            let Some(segment) = self.run.segments().get(self.segment) else {
                return Ok(Step::Done);
            };
            if self.block >= segment.blocks() {
                self.segment += 1;
                self.block = 0;
                self.page = None;
                continue;
            }
            self.waiting = Waiting::Block;
            return Ok(Step::Need(self.segment, segment.block(self.block)));
        }
    }

    pub fn feed(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        match std::mem::replace(&mut self.waiting, Waiting::Nothing) {
            Waiting::Nothing => Err(Error::Corrupt("unexpected read")),
            Waiting::Block => {
                let segment = &self.run.segments()[self.segment];
                let entries = segment::entries(self.run.shape(), &bytes)?;
                let inside = entries
                    .first()
                    .zip(entries.last())
                    .is_some_and(|(a, b)| &a.key >= segment.first() && &b.key <= segment.last());
                if !inside {
                    return Err(Error::Corrupt("block outside its segment"));
                }
                self.entries = entries;
                self.at = 0;
                self.block += 1;
                Ok(())
            }
            Waiting::Page(offset) => {
                self.page = Some((offset, bytes));
                Ok(())
            }
        }
    }
}

pub enum Source<'a> {
    Run(Cursor<'a>),
    Entries(std::vec::IntoIter<Entry>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Merged {
    Entry(Entry),
    Need(usize, usize, Range),
    Done,
}

pub struct Merge<'a> {
    sources: Vec<Source<'a>>,
    heads: Vec<Option<Entry>>,
    done: Vec<bool>,
    drop_deletes: bool,
    last: Option<Key>,
}

impl<'a> Merge<'a> {
    pub fn new(newest_first: Vec<Source<'a>>, drop_deletes: bool) -> Self {
        let count = newest_first.len();
        Self {
            sources: newest_first,
            heads: vec![None; count],
            done: vec![false; count],
            drop_deletes,
            last: None,
        }
    }

    pub fn step(&mut self) -> Result<Merged, Error> {
        loop {
            for (i, source) in self.sources.iter_mut().enumerate() {
                if self.heads[i].is_some() || self.done[i] {
                    continue;
                }
                match source {
                    Source::Run(cursor) => match cursor.step()? {
                        Step::Entry(entry) => self.heads[i] = Some(entry),
                        Step::Need(segment, range) => return Ok(Merged::Need(i, segment, range)),
                        Step::Done => self.done[i] = true,
                    },
                    Source::Entries(entries) => match entries.next() {
                        Some(entry) => self.heads[i] = Some(entry),
                        None => self.done[i] = true,
                    },
                }
            }
            let Some(key) = self.heads.iter().flatten().map(|e| e.key).min() else {
                return Ok(Merged::Done);
            };
            if self.last.is_some_and(|last| last >= key) {
                return Err(Error::Order);
            }
            self.last = Some(key);
            let mut newest = None;
            for head in &mut self.heads {
                if head.as_ref().is_some_and(|e| e.key == key) {
                    let entry = head.take();
                    newest = newest.or(entry);
                }
            }
            let entry = newest.expect("a head holds the key");
            if entry.op == Op::Delete && self.drop_deletes {
                continue;
            }
            return Ok(Merged::Entry(entry));
        }
    }

    pub fn feed(&mut self, source: usize, bytes: Vec<u8>) -> Result<(), Error> {
        match &mut self.sources[source] {
            Source::Run(cursor) => cursor.feed(bytes),
            Source::Entries(_) => Err(Error::Corrupt("unexpected read")),
        }
    }
}
