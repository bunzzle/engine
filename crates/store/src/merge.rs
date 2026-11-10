use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use index::{BLOCK, Cursor, Entry, Footer, Merge, Merged, Run, Segment, Shape, Source, Writer};
use rt::{sleep, yield_now};

use crate::core_file::CoreFile;
use crate::error::Error;
use crate::indexes::{Place, Stored, damaged, read, write_segment};
use crate::regions::Claim;
use crate::session::Session;

pub const DELAY_RUNS: usize = 16;
pub const REFUSE_RUNS: usize = 24;

pub type Retain = Rc<dyn Fn(u8, &Entry, bool) -> bool>;

#[derive(Clone)]
pub struct Tiering {
    pub flush_size: u64,
    pub fan_in: usize,
    pub similar: u64,
    pub bytes_per_tick: u64,
    pub tick: Duration,
    pub retain: Retain,
}

impl Default for Tiering {
    fn default() -> Self {
        Self {
            flush_size: 64 * 1024 * 1024,
            fan_in: 4,
            similar: 2,
            bytes_per_tick: 4 * 1024 * 1024,
            tick: Duration::from_millis(10),
            retain: Rc::new(|_, _, _| true),
        }
    }
}

struct Append {
    region: u32,
    epoch: u64,
    offset: u64,
}

pub(crate) struct Placer {
    claim: Claim,
    current: Option<Append>,
    pub(crate) claimed: Vec<u32>,
}

impl Placer {
    pub(crate) fn new(claim: Claim) -> Self {
        Self {
            claim,
            current: None,
            claimed: Vec::new(),
        }
    }

    pub(crate) fn room(&self, region_size: u64) -> u64 {
        self.current
            .as_ref()
            .map_or(region_size, |a| region_size - a.offset)
    }

    pub(crate) async fn place(
        &mut self,
        session: &Session,
        data: &CoreFile,
        size: u64,
    ) -> Result<(u32, u64, u64), Error> {
        let region_size = data.superblock().region_size();
        if size > region_size {
            return Err(Error::CheckpointTooLarge);
        }
        if self.room(region_size) < size || self.current.is_none() {
            let (region, epoch) = session.claim(self.claim).await?;
            self.claimed.push(region);
            let old = self.current.replace(Append {
                region,
                epoch,
                offset: 0,
            });
            if let Some(old) = old
                && self.claim != Claim::Index
            {
                session.unhold(old.region)?;
            }
        }
        let append = self.current.as_mut().expect("append region claimed");
        let at = (append.region, append.epoch, append.offset);
        append.offset += size;
        Ok(at)
    }
}

pub(crate) struct Rate {
    bytes_per_tick: u64,
    tick: Duration,
    used: u64,
}

impl Rate {
    async fn spend(&mut self, bytes: u64) {
        self.used += bytes;
        if self.used >= self.bytes_per_tick {
            self.used = 0;
            sleep(self.tick).await;
        } else {
            yield_now().await;
        }
    }
}

pub(crate) struct Output<'a> {
    pub(crate) data: &'a CoreFile,
    pub(crate) session: &'a Session,
    pub(crate) placer: &'a mut Placer,
    pub(crate) rate: Option<&'a mut Rate>,
}

pub(crate) async fn write_run(
    out: Output<'_>,
    shape: Shape,
    covered: u64,
    entries: Vec<Entry>,
    runs: &[Stored],
    oldest: bool,
    keep: &dyn Fn(&Entry, bool) -> bool,
) -> Result<Option<Stored>, Error> {
    let Output {
        data,
        session,
        placer,
        mut rate,
    } = out;
    let region_size = data.superblock().region_size();
    let sector = u64::from(data.sector_size());
    let mut sources = vec![Source::Entries(entries.into_iter())];
    sources.extend(runs.iter().map(|s| Source::Run(Cursor::new(&s.run))));
    let mut merge = Merge::new(sources, oldest);
    let mut writer = Writer::new(shape, covered);
    let mut segments = Vec::new();
    let mut places = Vec::new();
    loop {
        match merge.step().map_err(|_| Error::Invalid("index order"))? {
            Merged::Entry(entry) => {
                if !keep(&entry, oldest) {
                    continue;
                }
                let room = placer.room(region_size);
                let length = writer.length_with(&entry).next_multiple_of(sector);
                if !writer.is_empty() && length > room {
                    let full = std::mem::replace(&mut writer, Writer::new(shape, covered));
                    let (segment, place) = finish(full, data, session, placer).await?;
                    segments.push(segment);
                    places.push(place);
                }
                writer
                    .push(&entry)
                    .map_err(|_| Error::Invalid("index entry"))?;
            }
            Merged::Need(source, segment, range) => {
                let place = &runs[source - 1].places[segment];
                let bytes = read(data, place, range).await?;
                merge
                    .feed(source, bytes)
                    .map_err(|_| damaged(place, range))?;
                if let Some(rate) = rate.as_deref_mut() {
                    rate.spend(u64::from(range.length)).await;
                }
            }
            Merged::Done => break,
        }
    }
    if !writer.is_empty() {
        let (segment, place) = finish(writer, data, session, placer).await?;
        segments.push(segment);
        places.push(place);
    }
    if segments.is_empty() {
        return Ok(None);
    }
    let run = Run::new(segments).map_err(|_| Error::Invalid("index run"))?;
    Ok(Some(Stored {
        run: Arc::new(run),
        places: places.into(),
    }))
}

async fn finish(
    writer: Writer,
    data: &CoreFile,
    session: &Session,
    placer: &mut Placer,
) -> Result<(Segment, Place), Error> {
    let bytes = writer.finish().expect("writer holds entries").bytes;
    let size = (bytes.len() as u64).next_multiple_of(u64::from(data.sector_size()));
    let (region, epoch, offset) = placer.place(session, data, size).await?;
    let place = write_segment(data, region, epoch, offset, &bytes).await?;
    let footer = Footer::decode(&bytes[bytes.len() - BLOCK..]).expect("built footer");
    let meta = footer.meta();
    let at = usize::try_from(meta.offset).expect("meta fits in usize");
    let segment = Segment::load(footer, &bytes[at..at + meta.length as usize]).expect("built");
    Ok((segment, place))
}

pub struct Job {
    pub(crate) shard: u16,
    pub(crate) partition: (u8, u32),
    pub(crate) inputs: Vec<Stored>,
    pub(crate) oldest: bool,
    pub(crate) whole: bool,
    pub(crate) regions: u32,
}

impl Job {
    pub fn shard(&self) -> u16 {
        self.shard
    }

    pub fn partition(&self) -> (u8, u32) {
        self.partition
    }

    pub fn runs(&self) -> usize {
        self.inputs.len()
    }

    pub fn regions(&self) -> u32 {
        self.regions
    }
}

pub struct Done {
    pub(crate) job: Job,
    pub(crate) result: Result<(Option<Stored>, Vec<u32>), Error>,
}

impl Done {
    pub fn job(&self) -> &Job {
        &self.job
    }

    pub fn error(&self) -> Option<&Error> {
        self.result.as_ref().err()
    }
}

pub(crate) fn window(sizes: &[u64], tiering: &Tiering) -> Option<std::ops::Range<usize>> {
    let fan_in = tiering.fan_in.max(2);
    (0..sizes.len().saturating_sub(fan_in - 1))
        .map(|at| at..at + fan_in)
        .filter(|range| {
            let found = &sizes[range.clone()];
            let low = found.iter().min().copied().unwrap_or(0).max(1);
            let high = found.iter().max().copied().unwrap_or(0);
            high <= low.saturating_mul(tiering.similar)
        })
        .min_by_key(|range| sizes[range.clone()].iter().sum::<u64>())
}

pub async fn merge(job: Job, data: CoreFile, session: Session, tiering: Tiering) -> Done {
    let result = run(&job, &data, &session, &tiering).await;
    Done { job, result }
}

async fn run(
    job: &Job,
    data: &CoreFile,
    session: &Session,
    tiering: &Tiering,
) -> Result<(Option<Stored>, Vec<u32>), Error> {
    session.reserve_index(job.regions).await?;
    let mut placer = Placer::new(Claim::Index);
    let mut rate = Rate {
        bytes_per_tick: tiering.bytes_per_tick.max(1),
        tick: tiering.tick,
        used: 0,
    };
    let newest_first: Vec<Stored> = job.inputs.iter().rev().cloned().collect();
    let shape = job.inputs[0].run.shape();
    let covered = newest_first[0].run.covered();
    let kind = job.partition.0;
    let retain = Rc::clone(&tiering.retain);
    let keep = move |entry: &Entry, oldest: bool| retain(kind, entry, oldest);
    let output = Output {
        data,
        session,
        placer: &mut placer,
        rate: Some(&mut rate),
    };
    let written = write_run(
        output,
        shape,
        covered,
        Vec::new(),
        &newest_first,
        job.oldest,
        &keep,
    )
    .await;
    let used = u32::try_from(placer.claimed.len()).expect("regions fit in u32");
    session.unreserve_index(job.regions.saturating_sub(used))?;
    match written {
        Ok(output) => Ok((output, placer.claimed)),
        Err(e) => {
            for &region in &placer.claimed {
                session.unhold(region)?;
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Tiering, window};

    #[test]
    fn windows_take_neighbouring_runs_of_similar_size() {
        let tiering = Tiering::default();
        assert_eq!(window(&[100, 10, 12, 10, 11], &tiering), Some(1..5));
        assert_eq!(window(&[10, 10, 10, 40, 10], &tiering), None);
        assert_eq!(
            window(&[30, 20, 20, 20, 20, 10, 10, 10, 10], &tiering),
            Some(5..9)
        );
        assert_eq!(window(&[10, 10, 10], &tiering), None);
    }
}
