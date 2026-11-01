use crate::entry::{Key, Shape};
use crate::error::Error;
use crate::segment::{Range, Segment};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    shape: Shape,
    covered: u64,
    segments: Vec<Segment>,
}

impl Run {
    pub fn new(segments: Vec<Segment>) -> Result<Self, Error> {
        let first = segments.first().ok_or(Error::Corrupt("empty run"))?;
        let (shape, covered) = (first.footer().shape, first.footer().covered);
        let same = segments
            .iter()
            .all(|s| s.footer().shape == shape && s.footer().covered == covered);
        let disjoint = segments.windows(2).all(|w| w[0].last() < w[1].first());
        if !same || !disjoint {
            return Err(Error::Corrupt("run segments"));
        }
        Ok(Self {
            shape,
            covered,
            segments,
        })
    }

    pub fn shape(&self) -> Shape {
        self.shape
    }

    pub fn covered(&self) -> u64 {
        self.covered
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn entries(&self) -> u64 {
        self.segments.iter().map(|s| s.footer().entries).sum()
    }

    pub fn pinned(&self) -> usize {
        self.segments.iter().map(Segment::pinned).sum()
    }

    pub fn probe(&self, key: &Key) -> Option<(usize, Range)> {
        let at = self.segments.partition_point(|s| s.last() < key);
        let segment = self.segments.get(at)?;
        segment.probe(key).map(|block| (at, segment.block(block)))
    }
}
