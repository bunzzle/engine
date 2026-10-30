use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Counter {
    boot: u32,
    next: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ids {
    shards: BTreeMap<u16, Counter>,
}

impl Ids {
    pub fn new(boot: u32, shards: &[u16]) -> Self {
        Self::starting_at(boot, shards, 1)
    }

    pub fn starting_at(boot: u32, shards: &[u16], next: u32) -> Self {
        let shards = shards
            .iter()
            .map(|&shard| (shard, Counter { boot, next }))
            .collect();
        Self { shards }
    }

    pub fn next(&mut self, shard: u16) -> Option<u64> {
        let counter = self.shards.get_mut(&shard)?;
        if counter.next == 0 {
            return None;
        }
        let key = message_key(counter.boot, counter.next);
        counter.next = counter.next.wrapping_add(1);
        Some(key)
    }

    pub fn boot(&self, shard: u16) -> Option<u32> {
        self.shards.get(&shard).map(|counter| counter.boot)
    }

    pub fn renew(&mut self, shard: u16, boot: u32) {
        let counter = self.shards.get_mut(&shard).expect("shard owned here");
        assert!(boot > counter.boot, "boot must move forwards");
        *counter = Counter { boot, next: 1 };
    }
}

pub fn message_key(boot: u32, counter: u32) -> u64 {
    u64::from(boot) << 32 | u64::from(counter)
}

pub fn split_key(key: u64) -> (u32, u32) {
    let boot = u32::try_from(key >> 32).expect("high half fits in u32");
    let counter = u32::try_from(key & u64::from(u32::MAX)).expect("low half fits in u32");
    (boot, counter)
}

pub const CONTROL_BOOT: u32 = u32::MAX;
pub const CONTROL_KINDS: u32 = 256;
pub const LAST_BOOT: u32 = CONTROL_BOOT - CONTROL_KINDS;

pub fn control_key(kind: u8, id: u32) -> u64 {
    message_key(CONTROL_BOOT - u32::from(kind), id)
}

pub fn is_control(key: u64) -> bool {
    split_key(key).0 > LAST_BOOT
}

pub fn next_boot(boot: u32) -> Option<u32> {
    boot.checked_add(1).filter(|&next| next <= LAST_BOOT)
}
