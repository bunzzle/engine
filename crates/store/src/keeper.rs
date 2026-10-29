use std::collections::BTreeMap;

use crate::checkpoint::Part;
use crate::committer::Location;
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::run::{self, MAX_DELTAS, Root, encode_roots, run_size};
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
}

impl Keeper {
    pub fn insert(&mut self, shard: u16, state: ShardState, roots: Vec<Root>) {
        let kept = Kept {
            state,
            roots,
            pending: None,
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

    pub fn apply(&mut self, shard: u16, index: &Index, location: Location, commit: u64) {
        let kept = self.shards.get_mut(&shard).expect("shard is kept here");
        kept.state.apply(index, location, commit);
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
        }
        let mut parts = Vec::with_capacity(self.shards.len());
        let shards: Vec<u16> = self.shards.keys().copied().collect();
        for shard in shards {
            let roots = match self.next_roots(shard, data, session, covered).await {
                Ok(roots) => roots,
                Err(e) => {
                    self.abandoned(sequence);
                    session.fail(sequence)?;
                    return Err(e);
                }
            };
            parts.push(Part {
                tag: shard,
                replay_sequence: sequence,
                bytes: encode_roots(&roots),
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
        let delta_bytes: u64 =
            deltas.map(|r| u64::from(r.length)).sum::<u64>() + run_size(changes.len()) as u64;
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
                entries.len(),
                entries.iter().map(|(&k, v)| (k, Some(v))),
            )
        } else {
            run::encode(
                shard,
                false,
                covered,
                changes.len(),
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
        let region_size = data.superblock().region_size();
        let size = run::disk_size(blob, data.sector_size() as usize) as u64;
        if size > region_size {
            return Err(Error::CheckpointTooLarge);
        }
        let fits = self
            .append
            .as_ref()
            .is_some_and(|a| a.offset + size <= region_size);
        if !fits {
            let (region, epoch) = session.claim_state().await?;
            self.append = Some(Append {
                region,
                epoch,
                offset: 0,
            });
        }
        let append = self.append.as_mut().expect("append region claimed");
        let root = run::write(data, append.region, append.epoch, append.offset, blob).await?;
        append.offset += size;
        Ok(root)
    }

    pub fn published(&mut self, sequence: u64) {
        for kept in self.shards.values_mut() {
            if let Some(pending) = kept.pending.take_if(|p| p.sequence == sequence) {
                kept.roots = pending.roots;
            }
        }
    }

    pub fn abandoned(&mut self, sequence: u64) {
        for kept in self.shards.values_mut() {
            if let Some(pending) = kept.pending.take_if(|p| p.sequence == sequence) {
                kept.state.restore(pending.delta);
            }
        }
    }
}
