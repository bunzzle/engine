use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use rt::{Buf, File, OpenOptions};

use crate::{Error, MODE};

pub const ROTATE_AT: u64 = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    Create,
    Open,
    Unwrap,
    Busy,
    Retention,
    Delete,
    Day,
    Shred,
    Forced,
    Refused,
    DkimNew,
    Load,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Open => "open",
            Self::Unwrap => "unwrap",
            Self::Busy => "busy",
            Self::Retention => "retention",
            Self::Delete => "delete",
            Self::Day => "day",
            Self::Shred => "shred",
            Self::Forced => "forced",
            Self::Refused => "refused",
            Self::DkimNew => "dkim-new",
            Self::Load => "load",
        }
    }
}

pub struct Audit {
    dir: PathBuf,
    file: File,
    offset: u64,
    counts: BTreeMap<(Op, u32, u32, u32), u64>,
}

fn options() -> OpenOptions {
    OpenOptions {
        read: true,
        write: true,
        create: true,
        mode: Some(MODE),
        ..OpenOptions::default()
    }
}

impl Audit {
    pub async fn open(dir: &Path) -> Result<Self, Error> {
        let file = File::open(dir.join("audit"), &options()).await?;
        let offset = file.stat().await?.len;
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
            offset,
            counts: BTreeMap::new(),
        })
    }

    pub fn note(&mut self, op: Op, tenant: u32, generation: u32, day: u32) {
        *self
            .counts
            .entry((op, tenant, generation, day))
            .or_default() += 1;
    }

    pub async fn flush(&mut self, wall_ms: u64) -> Result<(), Error> {
        if self.counts.is_empty() {
            return Ok(());
        }
        let mut text = String::new();
        for ((op, tenant, generation, day), count) in std::mem::take(&mut self.counts) {
            let _ = writeln!(
                text,
                "{wall_ms} {} {tenant} {generation} {day} {count}",
                op.name()
            );
        }
        if self.offset >= ROTATE_AT {
            rt::rename(self.dir.join("audit"), self.dir.join("audit.1")).await?;
            self.file = File::open(self.dir.join("audit"), &options()).await?;
            rt::sync_dir(&self.dir).await?;
            self.offset = 0;
        }
        let (written, _) = self
            .file
            .write_all_at(Buf::from_slice(text.as_bytes()), self.offset)
            .await;
        written?;
        self.file.sync_data().await?;
        self.offset += text.len() as u64;
        Ok(())
    }
}
