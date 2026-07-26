//! Lightweight version-vector helpers for multi-device vault sync.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Device id → logical counter.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionVector(pub BTreeMap<String, u64>);

impl VersionVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&mut self, device_id: &str) {
        let e = self.0.entry(device_id.to_string()).or_insert(0);
        *e = e.saturating_add(1);
    }

    /// True if `self` dominates `other` (every counter ≥ and at least one >).
    pub fn dominates(&self, other: &Self) -> bool {
        if self == other {
            return false;
        }
        for (dev, &c) in &other.0 {
            if self.0.get(dev).copied().unwrap_or(0) < c {
                return false;
            }
        }
        true
    }

    pub fn concurrent(&self, other: &Self) -> bool {
        !self.dominates(other) && !other.dominates(self) && self != other
    }

    pub fn merge_max(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for (dev, &c) in &other.0 {
            let e = out.0.entry(dev.clone()).or_insert(0);
            if c > *e {
                *e = c;
            }
        }
        out
    }
}

/// Last-write-wins tiebreak for concurrent encrypted revisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LwwKey {
    pub version_vector: VersionVector,
    pub device_id: String,
    pub content_hash: [u8; 32],
}

impl PartialOrd for LwwKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LwwKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Prefer dominating VV; else higher sum of counters; else device_id; else hash.
        if self.version_vector.dominates(&other.version_vector) {
            return std::cmp::Ordering::Greater;
        }
        if other.version_vector.dominates(&self.version_vector) {
            return std::cmp::Ordering::Less;
        }
        let sum = |vv: &VersionVector| vv.0.values().sum::<u64>();
        sum(&self.version_vector)
            .cmp(&sum(&other.version_vector))
            .then_with(|| self.device_id.cmp(&other.device_id))
            .then_with(|| self.content_hash.cmp(&other.content_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dominates_and_concurrent() {
        let mut a = VersionVector::new();
        a.increment("d1");
        let mut b = a.clone();
        b.increment("d1");
        assert!(b.dominates(&a));
        assert!(!a.dominates(&b));

        let mut c = VersionVector::new();
        c.increment("d2");
        assert!(a.concurrent(&c));
    }
}
