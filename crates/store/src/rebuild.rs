use std::collections::BTreeMap;

use rt::Buf;

use crate::checkpoint::Part;
use crate::committer::Location;
use crate::core_file::CoreFile;
use crate::error::Error;
use crate::journal::{Entry, Range};
use crate::keeper::Keeper;
use crate::record::Record;
use crate::run::{Root, decode_roots, read_run};
use crate::shard::{Index, KIND_STATE, ShardState};

struct Rebuilding {
    state: ShardState,
    roots: Vec<Root>,
    covered: u64,
}

impl Keeper {
    pub async fn rebuild(
        data: &CoreFile,
        parts: &[Part],
        entries: &[Entry],
        shards: &[u16],
    ) -> Result<Self, Error> {
        let mut rebuilding = BTreeMap::new();
        for &shard in shards {
            let roots = match parts.iter().find(|p| p.tag == shard) {
                Some(part) => decode_roots(&part.bytes).ok_or(Error::CheckpointLost)?,
                None => Vec::new(),
            };
            let mut state = ShardState::default();
            for root in &roots {
                state.load_run(read_run(data, root, shard).await?);
            }
            let covered = state.covered();
            rebuilding.insert(
                shard,
                Rebuilding {
                    state,
                    roots,
                    covered,
                },
            );
        }
        for entry in entries {
            let commit = &entry.commit;
            for range in &commit.ranges[..usize::from(commit.streams)] {
                replay(data, entry.sequence, range, &mut rebuilding).await?;
            }
        }
        let mut keeper = Self::default();
        for (shard, rebuilt) in rebuilding {
            keeper.insert(shard, rebuilt.state, rebuilt.roots);
        }
        Ok(keeper)
    }
}

async fn replay(
    data: &CoreFile,
    commit: u64,
    range: &Range,
    rebuilding: &mut BTreeMap<u16, Rebuilding>,
) -> Result<(), Error> {
    let bad = Error::BadCommit(commit);
    let length = range.length as usize;
    let (result, buf) = data
        .file()
        .read_at(
            Buf::aligned(length, data.sector_size() as usize),
            data.region_offset(range.region) + range.offset,
        )
        .await;
    if result? != length {
        return Err(bad);
    }
    let mut at = 0;
    while at < length {
        let Ok(record) = Record::decode(&buf[at..]) else {
            if buf[at..].iter().all(|&b| b == 0) {
                break;
            }
            return Err(bad);
        };
        let size = record.size();
        if record.kind() == KIND_STATE
            && let Some(shard) = rebuilding.get_mut(&record.shard())
            && commit > shard.covered
        {
            let parts = Index::parts(record.payload()).ok_or(Error::BadCommit(commit))?;
            let location = Location {
                region: range.region,
                epoch: range.epoch,
                offset: range.offset + at as u64,
                sequence: record.sequence(),
                size: u32::try_from(size).expect("record fits in u32"),
            };
            shard
                .state
                .apply(&parts.index, parts.clear, &parts.bodies, location, commit);
        }
        at += size;
    }
    Ok(())
}
