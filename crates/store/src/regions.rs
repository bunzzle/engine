use crate::error::Error;

pub const CHECKPOINT_RESERVE: u32 = 2;
pub const COMPACTION_RESERVE: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    Intake,
    Control,
    Internal,
    State,
    Checkpoint,
}

#[derive(Clone, Debug)]
pub struct Regions {
    used: Vec<bool>,
    free: u32,
    reserve: u32,
    state_reserve: u32,
    reserved: u32,
}

impl Regions {
    pub fn new(count: u32, reserve: u32) -> Self {
        assert!(
            reserve + COMPACTION_RESERVE + CHECKPOINT_RESERVE <= count,
            "reserve exceeds region count"
        );
        Self {
            used: vec![false; count as usize],
            free: count,
            reserve,
            state_reserve: 0,
            reserved: 0,
        }
    }

    pub fn count(&self) -> u32 {
        u32::try_from(self.used.len()).expect("region count fits in u32")
    }

    pub fn free(&self) -> u32 {
        self.free
    }

    pub fn reserve(&self) -> u32 {
        self.reserve
    }

    pub fn state_reserve(&self) -> u32 {
        self.state_reserve
    }

    pub fn add_state_reserve(&mut self) {
        assert!(
            self.reserve + COMPACTION_RESERVE + CHECKPOINT_RESERVE + self.state_reserve
                < self.count(),
            "reserve exceeds region count"
        );
        self.state_reserve += 1;
    }

    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    pub fn reserve_internal(&mut self, regions: u32) -> Result<(), Error> {
        let floor = CHECKPOINT_RESERVE + self.state_reserve;
        if self.free < self.reserved + regions + floor {
            return Err(Error::Full);
        }
        self.reserved += regions;
        Ok(())
    }

    pub fn unreserve_internal(&mut self, regions: u32) {
        self.reserved = self.reserved.saturating_sub(regions);
    }

    pub fn is_used(&self, region: u32) -> bool {
        self.used[region as usize]
    }

    pub fn acquire(&mut self, claim: Claim) -> Result<u32, Error> {
        if self.free == 0 {
            return Err(Error::Full);
        }
        let floor = CHECKPOINT_RESERVE + self.state_reserve;
        let held = COMPACTION_RESERVE + self.reserved + floor;
        let keep = match claim {
            Claim::Intake => self.reserve + held,
            Claim::Control => held,
            Claim::Internal => floor,
            Claim::State => CHECKPOINT_RESERVE,
            Claim::Checkpoint => 0,
        };
        if self.free <= keep {
            return Err(if claim == Claim::Intake {
                Error::Reserve
            } else {
                Error::Full
            });
        }
        let index = self
            .used
            .iter()
            .position(|used| !used)
            .expect("free count matches the bitmap");
        self.used[index] = true;
        self.free -= 1;
        if claim == Claim::Internal {
            self.reserved = self.reserved.saturating_sub(1);
        }
        Ok(u32::try_from(index).expect("region count fits in u32"))
    }

    pub fn mark_used(&mut self, region: u32) {
        let slot = &mut self.used[region as usize];
        assert!(!*slot, "region {region} is already used");
        *slot = true;
        self.free -= 1;
    }

    pub fn release(&mut self, region: u32) {
        let slot = &mut self.used[region as usize];
        assert!(*slot, "region {region} is not used");
        *slot = false;
        self.free += 1;
    }
}
