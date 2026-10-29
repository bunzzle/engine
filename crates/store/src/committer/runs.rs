use super::Committer;
use crate::checkpoint::{Part, Snapshot};
use crate::error::Error;
use crate::regions::Claim;
use crate::run::{Root, decode_roots};

#[derive(Default)]
pub(super) struct Runs {
    pub(super) regions: Vec<u32>,
    pub(super) appending: Vec<Option<u32>>,
}

impl Committer {
    pub(super) fn is_state(&self, region: u32) -> bool {
        self.runs.regions.contains(&region)
    }

    pub(super) fn claim_state(&mut self, session: usize) -> Result<(u32, u64), Error> {
        let region = self.regions.acquire(Claim::State)?;
        assert!(
            self.usage.is_empty(region),
            "free region {region} has live data"
        );
        let epoch = &mut self.epochs[region as usize];
        *epoch += 1;
        self.runs.regions.push(region);
        self.runs.appending[session] = Some(region);
        Ok((region, *epoch))
    }

    pub(super) fn referenced(&self, parts: &[Part]) -> Option<Vec<u32>> {
        let shards = self.data.superblock().shards();
        let mut regions = Vec::new();
        for part in parts.iter().filter(|p| u32::from(p.tag) < shards) {
            for root in decode_roots(&part.bytes)? {
                if !self.root_valid(&root) {
                    return None;
                }
                if !regions.contains(&root.region) {
                    regions.push(root.region);
                }
            }
        }
        Some(regions)
    }

    fn root_valid(&self, root: &Root) -> bool {
        let superblock = self.data.superblock();
        let sector = u64::from(superblock.sector_size());
        self.is_state(root.region)
            && self.epochs[root.region as usize] == root.epoch
            && root.offset.is_multiple_of(sector)
            && u64::from(root.length).is_multiple_of(sector)
            && root.offset + u64::from(root.length) <= superblock.region_size()
    }

    pub(super) fn mark_state(&self, snapshot: &mut Snapshot, referenced: &[u32]) {
        for &region in &self.runs.regions {
            snapshot.used[region as usize] = referenced.contains(&region);
            snapshot.epochs[region as usize] = self.epochs[region as usize];
        }
    }

    pub(super) fn release_state(&mut self, referenced: &[u32]) {
        let appending = &self.runs.appending;
        let (kept, released) = self
            .runs
            .regions
            .iter()
            .partition(|r| referenced.contains(r) || appending.contains(&Some(**r)));
        self.runs.regions = kept;
        for region in released {
            self.regions.release(region);
        }
    }
}
