use super::{Committer, Location, Submission};
use crate::regions::{CHECKPOINT_RESERVE, COMPACTION_RESERVE, Claim};
use crate::session::{Event, Owned};
use crate::usage::Usage;

const MAX_LIVE_SHARE: f64 = 0.75;
const LOW_SHARE: u32 = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompactionStats {
    pub victims: u64,
    pub emptied: u64,
    pub dropped: u64,
    pub moved: u64,
    pub debt: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Space {
    pub free: u32,
    pub reserved: u32,
    pub releasable: u32,
    pub quarantined: u32,
    pub low: bool,
}

struct Victim {
    region: u32,
    epoch: u64,
    waiting: Vec<usize>,
}

#[derive(Default)]
pub(super) struct Compaction {
    candidates: Vec<(u32, u64)>,
    victim: Option<Victim>,
    sealed_at: Vec<u64>,
    stats: CompactionStats,
}

impl Compaction {
    pub(super) fn new(count: u32) -> Self {
        Self {
            sealed_at: vec![0; count as usize],
            ..Self::default()
        }
    }
}

impl Committer {
    pub fn compaction(&self) -> CompactionStats {
        self.compaction.stats
    }

    pub fn space(&self) -> Space {
        let count = self.regions.count();
        Space {
            free: self.regions.free(),
            reserved: self.regions.reserved(),
            releasable: u32::try_from((0..count).filter(|&r| self.releasable(r)).count())
                .expect("region count fits in u32"),
            quarantined: u32::try_from(self.usage.quarantined().iter().filter(|&&q| q).count())
                .expect("region count fits in u32"),
            low: self.low_space(),
        }
    }

    fn low_space(&self) -> bool {
        let held = COMPACTION_RESERVE
            + self.regions.reserved()
            + CHECKPOINT_RESERVE
            + self.regions.state_reserve();
        let margin = (self.regions.count() / LOW_SHARE).max(2);
        self.regions.free() < self.regions.reserve() + held + margin
    }

    fn releasable(&self, region: u32) -> bool {
        self.regions.is_used(region)
            && !self.open[region as usize]
            && self.usage.is_empty(region)
            && !self.usage.is_quarantined(region)
            && !self.checkpoint.contains(&region)
            && !self.is_state(region)
            && !self.pins.is_pinned(region)
    }

    pub(super) fn space_needs_checkpoint(&self) -> bool {
        self.low_space() && (0..self.regions.count()).any(|r| self.releasable(r))
    }

    pub(super) fn account(&mut self, submission: &Submission, locations: &[Location]) {
        let records = submission
            .records
            .iter()
            .zip(locations)
            .filter(|(w, _)| w.counted)
            .map(|(_, l)| u64::from(l.size));
        let bodies = submission.bodies.iter().map(|b| u64::from(b.range.length));
        let bytes: u64 = records.chain(bodies).sum();
        let stats = &mut self.compaction.stats;
        if submission.claim == Claim::Internal {
            stats.moved += bytes;
        } else {
            stats.debt += bytes;
        }
    }

    pub(super) fn sealed(&mut self, region: u32) {
        self.open[region as usize] = false;
        self.compaction.sealed_at[region as usize] = self.journal.position().sequence;
    }

    pub(super) fn is_victim(&self, region: u32) -> bool {
        self.compaction
            .victim
            .as_ref()
            .is_some_and(|v| v.region == region)
    }

    pub(super) fn survey(
        &mut self,
        usage: &Usage,
        used: &[bool],
        epochs: &[u64],
        surveys: &[Vec<Owned>],
    ) {
        let mut owned = vec![(0u32, 0u64); used.len()];
        for entry in surveys.iter().flatten() {
            if let Some(slot) = owned.get_mut(entry.region as usize) {
                slot.0 += entry.extents;
                slot.1 += entry.bytes;
            }
        }
        self.compaction.candidates = (0u32..)
            .zip(owned)
            .filter(|&(region, (extents, bytes))| {
                let count = usage.count(region);
                used[region as usize]
                    && count.extents > 0
                    && count.extents == extents
                    && count.bytes == bytes
            })
            .map(|(region, _)| (region, epochs[region as usize]))
            .collect();
    }

    pub(super) fn start_victim(&mut self) {
        if self.compaction.victim.is_some() || self.failed {
            return;
        }
        let region_size = self.data.superblock().region_size();
        let now = self.journal.position().sequence;
        let mut best: Option<(f64, u32, u64)> = None;
        for &(region, epoch) in &self.compaction.candidates {
            if !self.compactable(region, epoch) {
                continue;
            }
            let bytes = self.usage.count(region).bytes;
            #[allow(clippy::cast_precision_loss)]
            let live = bytes as f64 / region_size as f64;
            if live > MAX_LIVE_SHARE {
                continue;
            }
            #[allow(clippy::cast_precision_loss)]
            let age = now.saturating_sub(self.compaction.sealed_at[region as usize]) as f64;
            let score = (1.0 - live) * (age + 1.0) / (1.0 + live);
            if best.is_none_or(|(s, ..)| score > s) {
                best = Some((score, region, bytes));
            }
        }
        let Some((_, region, bytes)) = best else {
            return;
        };
        if bytes > self.compaction.stats.debt && !self.low_space() {
            return;
        }
        let regions = u32::try_from(bytes.div_ceil(region_size) + 1).unwrap_or(u32::MAX);
        if self.regions.reserve_internal(regions).is_err() {
            return;
        }
        let epoch = self.epochs[region as usize];
        let waiting = (0..self.sessions.len())
            .filter(|&s| self.sessions[s].is_some())
            .collect();
        self.compaction.victim = Some(Victim {
            region,
            epoch,
            waiting,
        });
        self.compaction.stats.victims += 1;
        self.compaction.stats.debt = 0;
        self.broadcast(|| Event::Compact { region, epoch });
        self.settle_victim();
    }

    fn compactable(&self, region: u32, epoch: u64) -> bool {
        self.regions.is_used(region)
            && self.epochs[region as usize] == epoch
            && !self.open[region as usize]
            && !self.pins.is_pinned(region)
            && !self.usage.is_quarantined(region)
            && !self.checkpoint.contains(&region)
            && !self.is_state(region)
            && !self.releasing(region)
            && !self.carried.contains(&region)
            && !self.usage.is_empty(region)
    }

    pub(super) fn compacted(&mut self, session: usize, region: u32, epoch: u64) {
        if let Some(victim) = self.compaction.victim.as_mut()
            && victim.region == region
            && victim.epoch == epoch
        {
            victim.waiting.retain(|&s| s != session);
        }
        self.settle_victim();
    }

    pub(super) fn settle_victim(&mut self) {
        let sessions = &self.sessions;
        let Some(victim) = self.compaction.victim.as_mut() else {
            return;
        };
        victim
            .waiting
            .retain(|&s| sessions[s].as_ref().is_some_and(|tx| !tx.is_closed()));
        if !victim.waiting.is_empty() {
            return;
        }
        let region = victim.region;
        self.compaction.victim = None;
        let reserved = self.regions.reserved();
        self.regions.unreserve_internal(reserved);
        if self.usage.is_empty(region) {
            self.compaction.stats.emptied += 1;
        } else {
            self.compaction.stats.dropped += 1;
        }
    }
}
