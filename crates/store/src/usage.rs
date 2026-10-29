use std::collections::BTreeMap;

use crate::journal::{Dead, Live};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Count {
    pub extents: u32,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
    counts: Vec<Count>,
    quarantined: Vec<bool>,
    tenants: BTreeMap<u32, u64>,
    held: BTreeMap<u32, Count>,
    held_tenants: BTreeMap<u32, u64>,
}

impl Usage {
    pub fn new(count: u32) -> Self {
        Self {
            counts: vec![Count::default(); count as usize],
            quarantined: vec![false; count as usize],
            tenants: BTreeMap::new(),
            held: BTreeMap::new(),
            held_tenants: BTreeMap::new(),
        }
    }

    pub(crate) fn from_parts(
        counts: Vec<Count>,
        quarantined: Vec<bool>,
        tenants: BTreeMap<u32, u64>,
    ) -> Self {
        assert_eq!(counts.len(), quarantined.len(), "usage table mismatch");
        Self {
            counts,
            quarantined,
            tenants,
            held: BTreeMap::new(),
            held_tenants: BTreeMap::new(),
        }
    }

    pub fn count(&self, region: u32) -> Count {
        self.counts[region as usize]
    }

    pub fn counts(&self) -> &[Count] {
        &self.counts
    }

    pub fn is_empty(&self, region: u32) -> bool {
        self.counts[region as usize] == Count::default()
    }

    pub fn is_quarantined(&self, region: u32) -> bool {
        self.quarantined[region as usize]
    }

    pub fn quarantined(&self) -> &[bool] {
        &self.quarantined
    }

    pub fn quarantine(&mut self, region: u32) {
        self.quarantined[region as usize] = true;
    }

    pub fn tenant(&self, tenant: u32) -> u64 {
        self.tenants.get(&tenant).copied().unwrap_or(0)
    }

    pub fn tenants(&self) -> &BTreeMap<u32, u64> {
        &self.tenants
    }

    pub(crate) fn add(&mut self, live: &Live) -> Option<()> {
        let count = &self.counts[live.region as usize];
        let next = Count {
            extents: count.extents.checked_add(live.extents)?,
            bytes: count.bytes.checked_add(live.bytes)?,
        };
        let total = self.tenant(live.tenant).checked_add(live.bytes)?;
        self.counts[live.region as usize] = next;
        self.tenants.insert(live.tenant, total);
        Some(())
    }

    pub(crate) fn remove(&mut self, dead: &Dead) -> Option<()> {
        let count = &self.counts[dead.region as usize];
        let next = Count {
            extents: count.extents.checked_sub(1)?,
            bytes: count.bytes.checked_sub(u64::from(dead.length))?,
        };
        let total = self
            .tenant(dead.tenant)
            .checked_sub(u64::from(dead.length))?;
        self.counts[dead.region as usize] = next;
        if total == 0 {
            self.tenants.remove(&dead.tenant);
        } else {
            self.tenants.insert(dead.tenant, total);
        }
        Some(())
    }

    pub(crate) fn hold(&mut self, dead: &[Dead]) -> Result<(), u32> {
        let mut regions = BTreeMap::<u32, Count>::new();
        let mut tenants = BTreeMap::<u32, u64>::new();
        for d in dead {
            let length = u64::from(d.length);
            let region = regions
                .entry(d.region)
                .or_insert_with(|| self.held.get(&d.region).copied().unwrap_or_default());
            region.extents += 1;
            region.bytes += length;
            let count = self.counts[d.region as usize];
            let tenant = tenants
                .entry(d.tenant)
                .or_insert_with(|| self.held_tenants.get(&d.tenant).copied().unwrap_or(0));
            *tenant += length;
            if region.extents > count.extents
                || region.bytes > count.bytes
                || *tenant > self.tenant(d.tenant)
            {
                return Err(d.region);
            }
        }
        self.held.extend(regions);
        self.held_tenants.extend(tenants);
        Ok(())
    }

    pub(crate) fn unhold(&mut self, dead: &[Dead]) {
        for d in dead {
            let length = u64::from(d.length);
            let region = self.held.get_mut(&d.region).expect("held region");
            region.extents -= 1;
            region.bytes -= length;
            if *region == Count::default() {
                self.held.remove(&d.region);
            }
            let tenant = self.held_tenants.get_mut(&d.tenant).expect("held tenant");
            *tenant -= length;
            if *tenant == 0 {
                self.held_tenants.remove(&d.tenant);
            }
        }
    }

    pub(crate) fn settle(&mut self, live: &[Live], dead: &[Dead]) {
        for d in dead {
            self.remove(d).expect("held dead entry applies");
        }
        for l in live {
            self.add(l).expect("live entry fits");
        }
        self.held.clear();
        self.held_tenants.clear();
    }

    pub(crate) fn forget(&mut self) {
        self.held.clear();
        self.held_tenants.clear();
    }
}
