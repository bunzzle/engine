use std::path::Path;
use std::sync::Arc;

use crate::checkpoint::{Part, load};
use crate::committer::{Client, Committer};
use crate::core_file::{CoreFile, Source};
use crate::data_file::DataFile;
use crate::error::Error;
use crate::ids::Ids;
use crate::journal::Entry;
use crate::keeper::Keeper;
use crate::recovery::recover;
use crate::regions::{CHECKPOINT_RESERVE, COMPACTION_RESERVE};
use crate::session::{Results, Session};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setup {
    pub cores: u16,
    pub credits: u32,
    pub reserve: u32,
}

pub struct Booted {
    pub committer: Committer,
    pub client: Client,
    pub starts: Vec<Start>,
}

pub struct Start {
    index: u16,
    boot: u32,
    shards: Vec<u16>,
    session: Session,
    results: Results,
    source: Source,
    parts: Arc<[Part]>,
    entries: Arc<[Entry]>,
}

pub struct Core {
    pub index: u16,
    pub shards: Vec<u16>,
    pub session: Session,
    pub results: Results,
    pub file: CoreFile,
    pub keeper: Keeper,
    pub ids: Ids,
}

pub async fn boot(path: impl AsRef<Path>, setup: Setup) -> Result<Booted, Error> {
    let mut data = DataFile::open(path).await?;
    let superblock = *data.superblock();
    let shards = superblock.shards();
    if setup.cores == 0 || u32::from(setup.cores) > shards {
        return Err(Error::Config(
            "core count must be between 1 and the shard count",
        ));
    }
    let kept = setup
        .reserve
        .checked_add(CHECKPOINT_RESERVE + COMPACTION_RESERVE + u32::from(setup.cores));
    if kept.is_none_or(|kept| kept >= superblock.region_count()) {
        return Err(Error::Config("reserves leave no region for intake"));
    }
    let loaded = load(&data, setup.reserve).await?;
    let recovered = recover(&data, loaded.position, loaded.state).await?;
    let boot = data.next_boot().await?;
    let (mut committer, client) = Committer::new(data, recovered.journal, recovered.state);
    let parts: Arc<[Part]> = loaded.parts.into();
    let entries: Arc<[Entry]> = recovered.entries.into();
    let source = committer.source();
    let starts = (0..setup.cores)
        .map(|index| {
            let (session, results) = committer.session(&client, setup.credits);
            Start {
                index,
                boot,
                shards: (0..shards)
                    .filter(|s| s % u32::from(setup.cores) == u32::from(index))
                    .map(|s| u16::try_from(s).expect("shard fits in u16"))
                    .collect(),
                session,
                results,
                source: source.clone(),
                parts: Arc::clone(&parts),
                entries: Arc::clone(&entries),
            }
        })
        .collect();
    Ok(Booted {
        committer,
        client,
        starts,
    })
}

impl Start {
    pub fn index(&self) -> u16 {
        self.index
    }

    pub async fn open(self) -> Result<Core, Error> {
        let file = self.source.open().await?;
        let keeper = Keeper::rebuild(&file, &self.parts, &self.entries, &self.shards).await?;
        Ok(Core {
            index: self.index,
            ids: Ids::new(self.boot, &self.shards),
            shards: self.shards,
            session: self.session,
            results: self.results,
            file,
            keeper,
        })
    }
}
