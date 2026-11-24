use std::sync::Arc;

use metrics::{Def, Kind, Slab};
use rt::{Instant, now, wall_ms};

const LATENCY: &[u64] = &[
    25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000,
    1_000_000, 5_000_000,
];

macro_rules! catalog {
    ($($id:ident: $kind:expr, $name:literal, $help:literal;)*) => {
        #[derive(Clone, Copy)]
        enum Id {
            $($id,)*
        }

        pub static METRICS: &[Def] = &[
            $(Def { name: $name, help: $help, kind: $kind },)*
        ];
    };
}

catalog! {
    CommitSeconds: Kind::Histogram(LATENCY), "store_commit_seconds", "Time to write and sync one commit batch";
    SyncSeconds: Kind::Histogram(LATENCY), "store_sync_seconds", "Time the data device took to sync";
    WriteStarted: Kind::Gauge, "store_write_started_seconds", "Unix time the commit write and sync in flight started, 0 when idle";
    Commits: Kind::Counter, "store_commits", "Commit batches made durable";
    Submissions: Kind::Counter, "store_submissions", "Submissions made durable";
    Refused: Kind::Counter, "store_refused", "Submissions answered with an error";
    BytesWritten: Kind::Counter, "store_bytes_written", "Bytes written to the data device by commits";
    Checkpoints: Kind::Counter, "store_checkpoints", "Checkpoints written";
    Failed: Kind::Gauge, "store_failed", "1 when the store stopped after a device fault";
    RegionsFree: Kind::Gauge, "store_regions_free", "Free regions";
    RegionsReserved: Kind::Gauge, "store_regions_reserved", "Regions reserved for internal work";
    RegionsQuarantined: Kind::Gauge, "store_regions_quarantined", "Regions quarantined after a fault";
    SpaceLow: Kind::Gauge, "store_space_low", "1 when free regions are near the reserve";
    JournalFreeBytes: Kind::Gauge, "store_journal_free_bytes", "Free journal bytes";
    JournalBytes: Kind::Gauge, "store_journal_bytes", "Journal size in bytes";
    CompactionVictims: Kind::Counter, "store_compaction_victims", "Regions chosen for compaction";
    CompactionMovedBytes: Kind::Counter, "store_compaction_moved_bytes", "Bytes moved by compaction";
}

pub fn slab() -> Arc<Slab> {
    Arc::new(Slab::new(METRICS).expect("store metrics catalog"))
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Tally {
    pub commits: u64,
    pub submissions: u64,
    pub refused: u64,
    pub bytes: u64,
    pub checkpoints: u64,
}

pub(crate) struct Snapshot {
    pub tally: Tally,
    pub failed: bool,
    pub free: u32,
    pub reserved: u32,
    pub quarantined: u32,
    pub low: bool,
    pub journal_free: u64,
    pub journal: u64,
    pub victims: u64,
    pub moved: u64,
}

#[derive(Default)]
pub(crate) struct Probe {
    slab: Option<Arc<Slab>>,
}

impl Probe {
    pub fn attach(&mut self, slab: Arc<Slab>) {
        let names = |defs: &[Def]| defs.iter().map(|d| d.name).collect::<Vec<_>>();
        assert_eq!(
            names(slab.defs()),
            names(METRICS),
            "store metrics slab built from another catalog"
        );
        self.slab = Some(slab);
    }

    pub fn start(&self) -> Option<Instant> {
        let slab = self.slab.as_ref()?;
        slab.set(Id::WriteStarted as usize, (wall_ms() / 1000).max(1));
        Some(now())
    }

    pub fn finish(&self, started: Option<Instant>, synced: Option<Instant>, ok: bool) {
        let (Some(slab), Some(started)) = (&self.slab, started) else {
            return;
        };
        slab.set(Id::WriteStarted as usize, 0);
        if !ok {
            slab.set(Id::Failed as usize, 1);
            return;
        }
        let end = now();
        slab.observe(
            Id::CommitSeconds as usize,
            micros(end.saturating_duration_since(started)),
        );
        if let Some(synced) = synced {
            slab.observe(
                Id::SyncSeconds as usize,
                micros(end.saturating_duration_since(synced)),
            );
        }
    }

    pub fn now(&self) -> Option<Instant> {
        self.slab.as_ref().map(|_| now())
    }

    pub fn publish(&self, snapshot: impl FnOnce() -> Snapshot) {
        let Some(slab) = &self.slab else {
            return;
        };
        let s = snapshot();
        let set = |id: Id, value: u64| slab.set(id as usize, value);
        set(Id::Commits, s.tally.commits);
        set(Id::Submissions, s.tally.submissions);
        set(Id::Refused, s.tally.refused);
        set(Id::BytesWritten, s.tally.bytes);
        set(Id::Checkpoints, s.tally.checkpoints);
        set(Id::Failed, u64::from(s.failed));
        set(Id::RegionsFree, u64::from(s.free));
        set(Id::RegionsReserved, u64::from(s.reserved));
        set(Id::RegionsQuarantined, u64::from(s.quarantined));
        set(Id::SpaceLow, u64::from(s.low));
        set(Id::JournalFreeBytes, s.journal_free);
        set(Id::JournalBytes, s.journal);
        set(Id::CompactionVictims, s.victims);
        set(Id::CompactionMovedBytes, s.moved);
        slab.publish(wall_ms());
    }
}

fn micros(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}
