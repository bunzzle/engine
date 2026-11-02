use std::collections::BTreeMap;

use index::{Key, Op};

use crate::checkpoint::Part;
use crate::committer::Location;
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::indexes::{self, IndexRecord, Partition, Stored};
use crate::journal::Range;
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

struct Append {
    region: u32,
    epoch: u64,
    offset: u64,
}

#[derive(Default)]
pub struct Keeper {
    shards: BTreeMap<u16, Kept>,
    append: Option<Append>,
    flush: Option<Append>,
}

async fn place(
    cursor: &mut Option<Append>,
    claim: Claim,
    session: &Session,
    data: &CoreFile,
    size: u64,
) -> Result<(u32, u64, u64), Error> {
    if size > data.superblock().region_size() {
        return Err(Error::CheckpointTooLarge);
    }
    let fits = cursor
        .as_ref()
        .is_some_and(|a| a.offset + size <= data.superblock().region_size());
    if !fits {
        let (region, epoch) = session.claim(claim).await?;
        if let Some(old) = cursor.replace(Append {
            region,
            epoch,
            offset: 0,
        }) {
            session.unhold(old.region)?;
        }
    }
    let append = cursor.as_mut().expect("append region claimed");
    let at = (append.region, append.epoch, append.offset);
    append.offset += size;
    Ok(at)
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

    fn partition(&self, shard: u16, partition: (u8, u32)) -> Option<&Partition> {
        self.shards.get(&shard)?.indexes.get(&partition)
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
        let (region, epoch, offset) =
            place(&mut self.append, Claim::State, session, data, size).await?;
        run::write(data, region, epoch, offset, blob).await
    }

    async fn flush(
        &mut self,
        shard: u16,
        data: &CoreFile,
        session: &Session,
        covered: u64,
    ) -> Result<(), Error> {
        let region_size = data.superblock().region_size();
        let sector = u64::from(data.sector_size());
        let keys: Vec<(u8, u32)> = self.shards[&shard].indexes.keys().copied().collect();
        for key in keys {
            let partition = &self.shards[&shard].indexes[&key];
            let Some(shape) = partition.live.as_ref().map(index::Memtable::shape) else {
                continue;
            };
            if partition.frozen.is_empty() {
                continue;
            }
            let built = indexes::segments(shape, covered, &partition.frozen, region_size);
            let mut segments = Vec::with_capacity(built.len());
            let mut places = Vec::with_capacity(built.len());
            for bytes in built {
                let size = (bytes.len() as u64).next_multiple_of(sector);
                let (region, epoch, offset) =
                    place(&mut self.flush, Claim::Flush, session, data, size).await?;
                places.push(indexes::write_segment(data, region, epoch, offset, &bytes).await?);
                segments.push(indexes::built(&bytes));
            }
            let run = index::Run::new(segments).expect("flushed segments form a run");
            let kept = self.shards.get_mut(&shard).expect("shard is kept here");
            let partition = kept.indexes.get_mut(&key).expect("partition is kept");
            partition.flushed = Some(Stored { run, places });
        }
        Ok(())
    }

    pub fn published(&mut self, sequence: u64) {
        for kept in self.shards.values_mut() {
            if let Some(pending) = kept.pending.take_if(|p| p.sequence == sequence) {
                kept.roots = pending.roots;
                for partition in kept.indexes.values_mut() {
                    partition.published();
                }
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
