use std::collections::BTreeMap;

use index::{Key, Op, Shape};

use crate::checkpoint::Part;
use crate::committer::Location;
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::indexes::{Closed, Dropped, Flushed, IndexRecord, Partition, Stored, Swap};
use crate::journal::Range;
use crate::merge::{Done, Job, Output, Placer, Tiering, window, write_run};
use crate::regions::Claim;
use crate::roots::{IndexRoot, encode_part};
use crate::run::{self, MAX_DELTAS, Root};
use crate::session::Session;
use crate::shard::{Delta, Index, ShardState};

struct Pending {
    sequence: u64,
    delta: Delta,
    roots: Vec<Root>,
}

struct Kept {
    state: ShardState,
    roots: Vec<Root>,
    pending: Option<Pending>,
    indexes: BTreeMap<(u8, u32), Partition>,
}

pub struct Keeper {
    shards: BTreeMap<u16, Kept>,
    append: Placer,
    flush: Placer,
    tiering: Tiering,
    unhold: Vec<u32>,
}

impl Default for Keeper {
    fn default() -> Self {
        Self {
            shards: BTreeMap::new(),
            append: Placer::new(Claim::State),
            flush: Placer::new(Claim::Flush),
            tiering: Tiering::default(),
            unhold: Vec::new(),
        }
    }
}

impl Keeper {
    pub fn insert(&mut self, shard: u16, state: ShardState, roots: Vec<Root>) {
        self.insert_indexed(shard, state, roots, BTreeMap::new());
    }

    pub(crate) fn insert_indexed(
        &mut self,
        shard: u16,
        state: ShardState,
        roots: Vec<Root>,
        indexes: BTreeMap<(u8, u32), Partition>,
    ) {
        let kept = Kept {
            state,
            roots,
            pending: None,
            indexes,
        };
        assert!(
            self.shards.insert(shard, kept).is_none(),
            "shard {shard} is already kept"
        );
    }

    pub fn state(&self, shard: u16) -> Option<&ShardState> {
        self.shards.get(&shard).map(|k| &k.state)
    }

    pub fn roots(&self, shard: u16) -> Option<&[Root]> {
        self.shards.get(&shard).map(|k| k.roots.as_slice())
    }

    pub fn index_roots(&self, shard: u16) -> Option<Vec<IndexRoot>> {
        let kept = self.shards.get(&shard)?;
        Some(index_roots(&kept.indexes, false))
    }

    pub fn partitions(&self, shard: u16) -> Vec<(u8, u32)> {
        self.shards
            .get(&shard)
            .map(|k| k.indexes.keys().copied().collect())
            .unwrap_or_default()
    }

    pub fn apply_index(&mut self, shard: u16, record: IndexRecord) -> Result<(), Error> {
        let kept = self.shards.get_mut(&shard).expect("shard is kept here");
        kept.indexes
            .entry((record.kind, record.partition))
            .or_default()
            .apply(record.entry)
    }

    pub async fn lookup(
        &self,
        data: &CoreFile,
        shard: u16,
        partition: (u8, u32),
        key: &Key,
    ) -> Result<Option<(Op, Vec<u8>)>, Error> {
        match self.partition(shard, partition) {
            Some(found) => found.lookup(data, key).await,
            None => Ok(None),
        }
    }

    pub async fn scan(
        &self,
        data: &CoreFile,
        shard: u16,
        partition: (u8, u32),
    ) -> Result<Vec<index::Entry>, Error> {
        match self.partition(shard, partition) {
            Some(found) => found.scan(data).await,
            None => Ok(Vec::new()),
        }
    }

    pub async fn range(
        &self,
        data: &CoreFile,
        shard: u16,
        partition: (u8, u32),
        keys: std::ops::Range<Key>,
        limit: usize,
    ) -> Result<Vec<index::Entry>, Error> {
        match self.partition(shard, partition) {
            Some(found) => found.range(data, keys.start, keys.end, limit).await,
            None => Ok(Vec::new()),
        }
    }

    pub fn index_shape(&self, shard: u16, partition: (u8, u32)) -> Option<Shape> {
        self.partition(shard, partition)?.shape()
    }

    fn partition(&self, shard: u16, partition: (u8, u32)) -> Option<&Partition> {
        self.shards.get(&shard)?.indexes.get(&partition)
    }

    fn partition_mut(&mut self, shard: u16, partition: (u8, u32)) -> Option<&mut Partition> {
        self.shards.get_mut(&shard)?.indexes.get_mut(&partition)
    }

    pub fn tiering(&self) -> &Tiering {
        &self.tiering
    }

    pub fn set_tiering(&mut self, tiering: Tiering) {
        self.tiering = tiering;
    }

    pub fn runs(&self, shard: u16, partition: (u8, u32)) -> usize {
        self.partition(shard, partition).map_or(0, |p| p.runs.len())
    }

    pub fn most_runs(&self) -> usize {
        self.shards
            .values()
            .flat_map(|k| k.indexes.values())
            .map(|p| p.runs.len())
            .max()
            .unwrap_or(0)
    }

    pub fn close_partition(&mut self, shard: u16, partition: (u8, u32)) {
        if let Some(found) = self.partition_mut(shard, partition)
            && found.closed == Closed::Open
        {
            found.closed = Closed::Whole;
        }
    }

    pub fn drop_partition(&mut self, shard: u16, partition: (u8, u32)) {
        if let Some(found) = self.partition_mut(shard, partition)
            && found.dropped == Dropped::Kept
        {
            found.dropped = Dropped::Asked;
        }
    }

    pub fn plan(&mut self, data: &CoreFile) -> Option<Job> {
        let region_size = data.superblock().region_size();
        let tiering = &self.tiering;
        for (&shard, kept) in &mut self.shards {
            for (&key, partition) in &mut kept.indexes {
                if partition.merging
                    || partition.dropped != Dropped::Kept
                    || partition.runs.len() < 2
                {
                    continue;
                }
                let closed = partition.closed != Closed::Open;
                let whole = partition.closed == Closed::Whole;
                let range = if whole {
                    0..partition.runs.len()
                } else {
                    let open = partition.runs.len() - usize::from(!closed);
                    let sizes: Vec<u64> =
                        partition.runs[..open].iter().map(Stored::bytes).collect();
                    match window(&sizes, tiering) {
                        Some(range) => range,
                        None => continue,
                    }
                };
                let inputs = partition.runs[range.clone()].to_vec();
                let bytes: u64 = inputs.iter().map(Stored::bytes).sum();
                partition.merging = true;
                return Some(Job {
                    shard,
                    partition: key,
                    inputs,
                    oldest: range.start == 0,
                    whole,
                    regions: u32::try_from(bytes.div_ceil(region_size) + 1)
                        .expect("regions fit in u32"),
                });
            }
        }
        None
    }

    pub fn cancel(&mut self, job: &Job) {
        if let Some(partition) = self.partition_mut(job.shard, job.partition) {
            partition.merging = false;
        }
    }

    pub fn merged(&mut self, done: Done) -> Result<(), Error> {
        let Done { job, result } = done;
        let Some(partition) = self.partition_mut(job.shard, job.partition) else {
            if let Ok((_, regions)) = result {
                self.unhold.extend(regions);
            }
            return Ok(());
        };
        match result {
            Ok((output, regions)) => {
                partition.merged.push(Swap {
                    inputs: job.inputs,
                    output,
                    regions,
                });
                Ok(())
            }
            Err(e) => {
                partition.merging = false;
                if job.whole && matches!(e, Error::Full) {
                    partition.closed = Closed::Tiered;
                }
                Err(e)
            }
        }
    }

    pub fn apply(
        &mut self,
        shard: u16,
        index: &Index,
        clear: &[u8],
        bodies: &[Range],
        location: Location,
        commit: u64,
    ) {
        let kept = self.shards.get_mut(&shard).expect("shard is kept here");
        kept.state.apply(index, clear, bodies, location, commit);
    }

    pub async fn cut(
        &mut self,
        session: &Session,
        data: &CoreFile,
        sequence: u64,
    ) -> Result<(), Error> {
        let covered = sequence - 1;
        for region in std::mem::take(&mut self.unhold) {
            session.unhold(region)?;
        }
        for kept in self.shards.values_mut() {
            assert!(
                kept.pending.is_none(),
                "cut {sequence} before the last one settled"
            );
            kept.pending = Some(Pending {
                sequence,
                delta: kept.state.freeze(covered),
                roots: kept.roots.clone(),
            });
            for partition in kept.indexes.values_mut() {
                partition.freeze();
            }
        }
        let mut parts = Vec::with_capacity(self.shards.len());
        let shards: Vec<u16> = self.shards.keys().copied().collect();
        for shard in shards {
            let flushed = self.flush(shard, data, session, covered).await;
            let roots = match flushed {
                Ok(()) => self.next_roots(shard, data, session, covered).await,
                Err(e) => Err(e),
            };
            let roots = match roots {
                Ok(roots) => roots,
                Err(e) => {
                    self.abandoned(sequence);
                    session.fail(sequence)?;
                    return Err(e);
                }
            };
            let index = index_roots(&self.shards[&shard].indexes, true);
            parts.push(Part {
                tag: shard,
                replay_sequence: sequence,
                bytes: encode_part(&roots, &index),
            });
            let kept = self.shards.get_mut(&shard).expect("shard is kept here");
            kept.pending.as_mut().expect("pending cut").roots = roots;
        }
        session.parts(sequence, parts)
    }

    async fn next_roots(
        &mut self,
        shard: u16,
        data: &CoreFile,
        session: &Session,
        covered: u64,
    ) -> Result<Vec<Root>, Error> {
        let kept = &self.shards[&shard];
        let pending = kept.pending.as_ref().expect("pending cut");
        let changes = &pending.delta.changes;
        if changes.is_empty() {
            return Ok(kept.roots.clone());
        }
        let deltas = kept.roots.iter().filter(|r| !r.base);
        let count = deltas.clone().count();
        let delta_bytes: u64 = deltas.map(|r| u64::from(r.length)).sum::<u64>()
            + changes
                .values()
                .map(|item| run::entry_size(item.as_ref()) as u64)
                .sum::<u64>();
        let rebase = match kept.roots.first() {
            Some(base) if base.base => count >= MAX_DELTAS || delta_bytes > u64::from(base.length),
            _ => true,
        };
        let blob = if rebase {
            let entries = kept.state.entries();
            run::encode(
                shard,
                true,
                covered,
                entries.iter().map(|(&k, v)| (k, Some(v))),
            )
        } else {
            run::encode(
                shard,
                false,
                covered,
                changes.iter().map(|(&k, v)| (k, v.as_ref())),
            )
        };
        let mut roots = if rebase {
            Vec::new()
        } else {
            kept.roots.clone()
        };
        roots.push(self.write(data, session, &blob).await?);
        Ok(roots)
    }

    async fn write(
        &mut self,
        data: &CoreFile,
        session: &Session,
        blob: &[u8],
    ) -> Result<Root, Error> {
        let size = run::disk_size(blob, data.sector_size() as usize) as u64;
        let (region, epoch, offset) = self.append.place(session, data, size).await?;
        run::write(data, region, epoch, offset, blob).await
    }

    async fn flush(
        &mut self,
        shard: u16,
        data: &CoreFile,
        session: &Session,
        covered: u64,
    ) -> Result<(), Error> {
        let Self {
            shards,
            flush,
            tiering,
            ..
        } = self;
        let kept = shards.get_mut(&shard).expect("shard is kept here");
        for (&(kind, _), partition) in &mut kept.indexes {
            if partition.frozen.is_empty() || partition.dropped == Dropped::InCut {
                continue;
            }
            let shape = partition.shape().expect("frozen entries have a shape");
            let runs = partition.merged_runs();
            let replaces = runs.last().is_some_and(|n| n.bytes() < tiering.flush_size)
                && !(partition.closed != Closed::Open && partition.merging);
            let inputs: Vec<_> = runs
                .last()
                .filter(|_| replaces)
                .cloned()
                .into_iter()
                .collect();
            let oldest = runs.len() <= inputs.len();
            let retain = &tiering.retain;
            let keep = |entry: &index::Entry, oldest: bool| retain(kind, entry, oldest);
            let out = Output {
                data,
                session,
                placer: flush,
                rate: None,
            };
            let entries = partition.frozen.clone();
            let output = write_run(out, shape, covered, entries, &inputs, oldest, &keep).await?;
            partition.flushed = Some(Flushed { replaces, output });
        }
        Ok(())
    }

    pub fn published(&mut self, sequence: u64) {
        for kept in self.shards.values_mut() {
            if let Some(pending) = kept.pending.take_if(|p| p.sequence == sequence) {
                kept.roots = pending.roots;
                let unhold = &mut self.unhold;
                kept.indexes.retain(|_, partition| {
                    if partition.dropped == Dropped::InCut {
                        let swaps = partition.cut_merges.iter().chain(&partition.merged);
                        unhold.extend(swaps.flat_map(|s| s.regions.iter().copied()));
                        return false;
                    }
                    partition.published(unhold);
                    true
                });
            }
        }
    }
    pub fn abandoned(&mut self, sequence: u64) {
        for kept in self.shards.values_mut() {
            if let Some(pending) = kept.pending.take_if(|p| p.sequence == sequence) {
                kept.state.restore(pending.delta);
                for partition in kept.indexes.values_mut() {
                    partition.abandoned();
                }
            }
        }
    }
}

fn index_roots(indexes: &BTreeMap<(u8, u32), Partition>, pending: bool) -> Vec<IndexRoot> {
    indexes
        .iter()
        .flat_map(|(&key, p)| p.roots(key, pending))
        .collect()
}
