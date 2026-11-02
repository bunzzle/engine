use index::BLOCK;

use super::Committer;
use crate::checkpoint::{Part, Snapshot};
use crate::error::Error;
use crate::regions::Claim;
use crate::roots::{IndexRoot, decode_part};
use crate::run::Root;

#[derive(Default)]
pub(super) struct Runs {
    pub(super) regions: Vec<u32>,
    pub(super) held: Vec<Vec<u32>>,
    pub(super) merging: Vec<u32>,
}

impl Committer {
    pub(super) fn is_state(&self, region: u32) -> bool {
        self.runs.regions.contains(&region)
    }

    pub(super) fn claim_run(&mut self, session: usize, claim: Claim) -> Result<(u32, u64), Error> {
        if !matches!(claim, Claim::State | Claim::Flush | Claim::Index) {
            return Err(Error::Invalid("claim"));
        }
        if claim == Claim::Index && self.runs.merging[session] == 0 {
            return Err(Error::Full);
        }
        let region = self.regions.acquire(claim)?;
        assert!(
            self.usage.is_empty(region),
            "free region {region} has live data"
        );
        if claim == Claim::Index {
            self.runs.merging[session] -= 1;
        }
        let epoch = &mut self.epochs[region as usize];
        *epoch += 1;
        self.runs.regions.push(region);
        self.runs.held[session].push(region);
        Ok((region, *epoch))
    }

    pub(super) fn unhold(&mut self, session: usize, region: u32) {
        if let Some(held) = self.runs.held.get_mut(session) {
            held.retain(|&r| r != region);
        }
    }

    pub(super) fn reserve_index(&mut self, session: usize, regions: u32) -> Result<(), Error> {
        self.regions.reserve_index(regions)?;
        self.runs.merging[session] += regions;
        Ok(())
    }

    pub(super) fn unreserve_index(&mut self, session: usize, regions: u32) {
        if let Some(merging) = self.runs.merging.get_mut(session) {
            let regions = regions.min(*merging);
            *merging -= regions;
            self.regions.unreserve_index(regions);
        }
    }

    pub(super) fn drop_session_runs(&mut self, session: usize) {
        self.runs.held[session].clear();
        let merging = std::mem::take(&mut self.runs.merging[session]);
        self.regions.unreserve_index(merging);
    }

    pub(super) fn referenced(&self, parts: &[Part]) -> Option<Vec<u32>> {
        let shards = self.data.superblock().shards();
        let mut regions = Vec::new();
        for part in parts.iter().filter(|p| u32::from(p.tag) < shards) {
            let roots = decode_part(&part.bytes)?;
            if !roots.state.iter().all(|r| self.root_valid(r))
                || !roots.index.iter().all(|r| self.index_root_valid(r))
            {
                return None;
            }
            let found = roots.state.iter().map(|r| r.region);
            for region in found.chain(roots.index.iter().map(|r| r.region)) {
                if !regions.contains(&region) {
                    regions.push(region);
                }
            }
        }
        Some(regions)
    }

    fn root_valid(&self, root: &Root) -> bool {
        self.extent_valid(root.region, root.epoch, root.offset, u64::from(root.length))
            && u64::from(root.length).is_multiple_of(u64::from(self.data.sector_size()))
    }

    fn index_root_valid(&self, root: &IndexRoot) -> bool {
        let sector = u64::from(self.data.sector_size());
        let length = u64::from(root.length);
        length.is_multiple_of(BLOCK as u64)
            && self.extent_valid(
                root.region,
                root.epoch,
                root.offset,
                length.next_multiple_of(sector),
            )
    }

    fn extent_valid(&self, region: u32, epoch: u64, offset: u64, length: u64) -> bool {
        let superblock = self.data.superblock();
        let sector = u64::from(superblock.sector_size());
        self.is_state(region)
            && self.epochs[region as usize] == epoch
            && offset.is_multiple_of(sector)
            && offset + length <= superblock.region_size()
    }

    pub(super) fn mark_state(&self, snapshot: &mut Snapshot, referenced: &[u32]) {
        for &region in &self.runs.regions {
            snapshot.used[region as usize] = referenced.contains(&region);
            snapshot.epochs[region as usize] = self.epochs[region as usize];
        }
    }

    pub(super) fn release_state(&mut self, referenced: &[u32]) {
        let held = &self.runs.held;
        let (kept, released) = self
            .runs
            .regions
            .iter()
            .partition(|r| referenced.contains(r) || held.iter().any(|h| h.contains(r)));
        self.runs.regions = kept;
        for region in released {
            self.regions.release(region);
        }
    }
}
