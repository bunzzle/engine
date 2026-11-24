use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
    Histogram(&'static [u64]),
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
    Bounds(&'static str),
    Cores,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => write!(f, "invalid metric name `{name}`"),
            Self::Help(name) => write!(f, "invalid help text for `{name}`"),
            Self::Duplicate(name) => write!(f, "duplicate metric name `{name}`"),
            Self::Bounds(name) => write!(f, "invalid histogram bounds for `{name}`"),
            Self::Cores => f.write_str("a board needs at least one core"),
        }
    }
}

impl std::error::Error for Invalid {}

pub(crate) const UP: &str = "core_up";
pub(crate) const AGE: &str = "core_publish_age_seconds";

pub(crate) struct Histogram {
    pub buckets: Vec<u64>,
    pub sum: u64,
}

pub struct Slab {
    defs: &'static [Def],
    offsets: Box<[usize]>,
    values: Box<[AtomicU64]>,
    stamp: AtomicU64,
}

impl Slab {
    pub fn new(defs: &'static [Def]) -> Result<Self, Invalid> {
        check(defs, &mut builtins())?;
        Ok(Self::build(defs))
    }

    fn build(defs: &'static [Def]) -> Self {
        let mut offsets = Vec::with_capacity(defs.len());
        let mut len = 0;
        for def in defs {
            offsets.push(len);
            len += slots(def.kind);
        }
        Self {
            defs,
            offsets: offsets.into(),
            values: (0..len).map(|_| AtomicU64::new(0)).collect(),
            stamp: AtomicU64::new(0),
        }
    }

    pub fn defs(&self) -> &'static [Def] {
        self.defs
    }

    pub fn set(&self, index: usize, value: u64) {
        if let Some(slot) = self.scalar(index) {
            slot.store(value, Ordering::Relaxed);
        }
    }

    pub fn get(&self, index: usize) -> Option<u64> {
        self.scalar(index).map(|v| v.load(Ordering::Relaxed))
    }

    pub fn observe(&self, index: usize, micros: u64) {
        let Some((offset, bounds)) = self.histogram_at(index) else {
            return;
        };
        let bucket = bounds.partition_point(|bound| *bound < micros);
        self.values[offset + bucket].fetch_add(1, Ordering::Relaxed);
        self.values[offset + bounds.len() + 1].fetch_add(micros, Ordering::Relaxed);
    }

    pub fn publish(&self, now_ms: u64) {
        self.stamp
            .store(now_ms.saturating_add(1), Ordering::Release);
    }

    pub fn published(&self) -> Option<u64> {
        self.stamp.load(Ordering::Acquire).checked_sub(1)
    }

    pub(crate) fn histogram(&self, index: usize) -> Option<Histogram> {
        let (offset, bounds) = self.histogram_at(index)?;
        let buckets = self.values[offset..=offset + bounds.len()]
            .iter()
            .map(|v| v.load(Ordering::Relaxed))
            .collect();
        let sum = self.values[offset + bounds.len() + 1].load(Ordering::Relaxed);
        Some(Histogram { buckets, sum })
    }

    fn scalar(&self, index: usize) -> Option<&AtomicU64> {
        let def = self.defs.get(index)?;
        if matches!(def.kind, Kind::Histogram(_)) {
            return None;
        }
        self.values.get(self.offsets[index])
    }

    fn histogram_at(&self, index: usize) -> Option<(usize, &'static [u64])> {
        match self.defs.get(index)?.kind {
            Kind::Histogram(bounds) => Some((self.offsets[index], bounds)),
            _ => None,
        }
    }
}

pub struct Board {
    pub(crate) prefix: &'static str,
    pub(crate) defs: &'static [Def],
    pub(crate) slabs: Box<[Slab]>,
    pub(crate) node: Option<Arc<Slab>>,
}

impl Board {
    pub fn new(prefix: &'static str, defs: &'static [Def], cores: u16) -> Result<Self, Invalid> {
        if cores == 0 {
            return Err(Invalid::Cores);
        }
        if !valid_name(prefix) {
            return Err(Invalid::Name(prefix));
        }
        check(defs, &mut builtins())?;
        let slabs = (0..cores).map(|_| Slab::build(defs)).collect();
        Ok(Self {
            prefix,
            defs,
            slabs,
            node: None,
        })
    }

    pub fn with_node(mut self, node: Arc<Slab>) -> Result<Self, Invalid> {
        let mut seen = builtins();
        check(self.defs, &mut seen)?;
        check(node.defs, &mut seen)?;
        self.node = Some(node);
        Ok(self)
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

    pub fn node(&self) -> Option<&Arc<Slab>> {
        self.node.as_ref()
    }
}

fn slots(kind: Kind) -> usize {
    match kind {
        Kind::Counter | Kind::Gauge => 1,
        Kind::Histogram(bounds) => bounds.len() + 2,
    }
}

fn builtins() -> HashSet<String> {
    [UP, AGE].map(String::from).into()
}

fn check(defs: &'static [Def], seen: &mut HashSet<String>) -> Result<(), Invalid> {
    for def in defs {
        let suffixes: &[&str] = match def.kind {
            Kind::Counter => &["_total"],
            Kind::Gauge => &[],
            Kind::Histogram(bounds) => {
                if bounds.is_empty() || !bounds.is_sorted_by(|a, b| a < b) {
                    return Err(Invalid::Bounds(def.name));
                }
                if !def.name.ends_with("_seconds") {
                    return Err(Invalid::Name(def.name));
                }
                &["_bucket", "_sum", "_count"]
            }
        };
        if !valid_name(def.name) || (def.kind == Kind::Counter && def.name.ends_with("_total")) {
            return Err(Invalid::Name(def.name));
        }
        if def.help.is_empty() || def.help.contains(['\\', '\n']) {
            return Err(Invalid::Help(def.name));
        }
        let fresh = seen.insert(def.name.to_owned())
            && suffixes
                .iter()
                .all(|suffix| seen.insert(format!("{}{suffix}", def.name)));
        if !fresh {
            return Err(Invalid::Duplicate(def.name));
        }
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
