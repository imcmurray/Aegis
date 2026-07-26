//! Network-visible VaultSync types (ciphertext + cleartext causal metadata only).
//!
//! Signature canonicalization lives in [`crate::sync::revision_sign_bytes`] and
//! must stay aligned with the vault-sync contract.

use crate::crdt::VersionVector;
use serde::{Deserialize, Serialize};

/// Contract parameters — public verifying key of the vault owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSyncParams {
    /// Ed25519 verifying key bytes (32).
    #[serde(with = "serde_bytes")]
    pub owner_verifying_key: Vec<u8>,
    /// Magic / app id.
    pub app: String,
}

impl Default for VaultSyncParams {
    fn default() -> Self {
        Self {
            owner_verifying_key: Vec::new(),
            app: "AEGIS_VAULT_SYNC_V1".into(),
        }
    }
}

/// One encrypted vault revision written by a device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedRevision {
    pub version_vector: VersionVector,
    pub device_id: String,
    /// Ed25519 signature over canonical bytes of (vv, device_id, content_hash, ciphertext).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub content_hash: [u8; 32],
}

/// Contract state: multi-value register of concurrent encrypted revisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSyncState {
    pub revisions: Vec<EncryptedRevision>,
}

impl VaultSyncState {
    pub const MAX_REVISIONS: usize = 8;
    pub const MAX_CIPHERTEXT: usize = 8 * 1024 * 1024; // 8 MiB soft cap per revision

    /// Merge another state by version-vector MVR rules (cleartext only).
    pub fn merge(&mut self, other: &VaultSyncState) {
        for rev in &other.revisions {
            self.upsert(rev.clone());
        }
        self.prune();
    }

    pub fn upsert(&mut self, rev: EncryptedRevision) {
        // Drop if dominated by existing.
        if self
            .revisions
            .iter()
            .any(|e| e.version_vector.dominates(&rev.version_vector))
        {
            return;
        }
        // Remove any dominated by new.
        self.revisions
            .retain(|e| !rev.version_vector.dominates(&e.version_vector));
        // Avoid exact duplicates.
        if !self.revisions.iter().any(|e| {
            e.content_hash == rev.content_hash && e.device_id == rev.device_id
        }) {
            self.revisions.push(rev);
        }
        self.prune();
    }

    fn prune(&mut self) {
        if self.revisions.len() > Self::MAX_REVISIONS {
            // Keep highest LWW-ish by sum of VV counters.
            self.revisions.sort_by_key(|r| {
                std::cmp::Reverse(r.version_vector.0.values().sum::<u64>())
            });
            self.revisions.truncate(Self::MAX_REVISIONS);
        }
    }
}

pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn decode_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod empty_cbor {
    use super::*;
    #[test]
    fn empty_state_cbor_has_revisions_field() {
        let b = encode_cbor(&VaultSyncState::default()).unwrap();
        // ciborium: a1 69 "revisions" 80  — not bare empty map (a0)
        assert_eq!(hex::encode(&b), "a1697265766973696f6e7380");
        let s: VaultSyncState = decode_cbor(&b).unwrap();
        assert!(s.revisions.is_empty());
    }
}
