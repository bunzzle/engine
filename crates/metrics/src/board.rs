use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
}

#[derive(Clone, Copy, Debug)]
pub struct Def {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    Name(&'static str),
    Help(&'static str),
    Duplicate(&'static str),
    Cores,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => write!(f, "invalid metric name `{name}`"),
            Self::Help(name) => write!(f, "invalid help text for `{name}`"),
            Self::Duplicate(name) => write!(f, "duplicate metric name `{name}`"),
            Self::Cores => f.write_str("a board needs at least one core"),
        }
    }
}

impl std::error::Error for Invalid {}

pub(crate) const UP: &str = "core_up";
pub(crate) const AGE: &str = "core_publish_age_seconds";

pub struct Slab {
    values: Box<[AtomicU64]>,
    stamp: AtomicU64,
}

impl Slab {
    fn new(len: usize) -> Self {
        Self {
            values: (0..len).map(|_| AtomicU64::new(0)).collect(),
            stamp: AtomicU64::new(0),
        }
    }

    pub fn set(&self, index: usize, value: u64) {
        if let Some(slot) = self.values.get(index) {
            slot.store(value, Ordering::Relaxed);
        }
    }

    pub fn publish(&self, now_ms: u64) {
        self.stamp
            .store(now_ms.saturating_add(1), Ordering::Release);
    }

    pub fn published(&self) -> Option<u64> {
        self.stamp.load(Ordering::Acquire).checked_sub(1)
    }

    pub fn get(&self, index: usize) -> Option<u64> {
        self.values.get(index).map(|v| v.load(Ordering::Relaxed))
    }
}

pub struct Board {
    pub(crate) prefix: &'static str,
    pub(crate) defs: &'static [Def],
    pub(crate) slabs: Box<[Slab]>,
}

impl Board {
    pub fn new(prefix: &'static str, defs: &'static [Def], cores: u16) -> Result<Self, Invalid> {
        if cores == 0 {
            return Err(Invalid::Cores);
        }
        if !valid_name(prefix) {
            return Err(Invalid::Name(prefix));
        }
        let mut seen: HashSet<String> = [UP, AGE].map(String::from).into();
        for def in defs {
            if !valid_name(def.name) || (def.kind == Kind::Counter && def.name.ends_with("_total"))
            {
                return Err(Invalid::Name(def.name));
            }
            if def.help.is_empty() || def.help.contains(['\\', '\n']) {
                return Err(Invalid::Help(def.name));
            }
            let fresh = seen.insert(def.name.to_owned())
                && (def.kind == Kind::Gauge || seen.insert(format!("{}_total", def.name)));
            if !fresh {
                return Err(Invalid::Duplicate(def.name));
            }
        }
        let slabs = (0..cores).map(|_| Slab::new(defs.len())).collect();
        Ok(Self {
            prefix,
            defs,
            slabs,
        })
    }

    pub fn defs(&self) -> &'static [Def] {
        self.defs
    }

    pub fn cores(&self) -> usize {
        self.slabs.len()
    }

    pub fn slab(&self, core: u16) -> Option<&Slab> {
        self.slabs.get(usize::from(core))
    }
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
