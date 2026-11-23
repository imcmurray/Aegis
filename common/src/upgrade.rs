//! Delegate upgrade snapshot (D20).
//!
//! Freenet keys a delegate's secret store by its code hash, so a new delegate
//! WASM starts with an empty store. `ExportForUpgrade` (old delegate) produces
//! a snapshot of the vault's already-encrypted-at-rest records and
//! `ImportUpgradeSnapshot` (new delegate) writes them in one atomic commit.
//! The snapshot never carries the root, a DEK or K_s.

use crate::crypto::{MasterEnvelopeV2, VaultBlobV2};
use crate::session_v2::{VaultSessionV2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2};
use crate::vault::{SecretStore, StoreOp, VaultError, SECRET_KEYS_V2};
use serde::{Deserialize, Serialize};

pub const UPGRADE_SNAPSHOT_VERSION: u32 = 1;
/// Maximum size in bytes of the encoded snapshot.
pub const MAX_UPGRADE_SNAPSHOT: usize = 8 * 1024 * 1024;

/// Error text for a snapshot that exceeds [`MAX_UPGRADE_SNAPSHOT`].
pub const ERR_TOO_LARGE: &str = "vault too large for upgrade snapshot";
/// Error text for any import validation failure.
pub const ERR_INVALID: &str = "invalid upgrade snapshot";
/// Prefix of the error text when the atomic commit fails.
pub const ERR_COMMIT_PREFIX: &str = "atomic commit failed: ";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeSnapshot {
    pub v: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    pub records: Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf)>,
}

fn locked() -> VaultError {
    VaultError::Msg("vault is locked".into())
}

/// Reads only SECRET_KEYS_V2 through `store` (the logical/committed view). No store writes.
pub fn export_upgrade_snapshot(
    store: &dyn SecretStore,
    session: &VaultSessionV2,
) -> Result<Vec<u8>, VaultError> {
    let env_bytes = store.get(SECRET_ENVELOPE_V2).ok_or_else(locked)?;
    let env = MasterEnvelopeV2::from_bytes(&env_bytes).map_err(|_| locked())?;
    let env_vid = env.vault_id_bytes().map_err(|_| locked())?;
    if env_vid != session.vault_id() || env.key_epoch != session.key_epoch() {
        return Err(locked());
    }

    let mut records = Vec::new();
    for key in SECRET_KEYS_V2 {
        if let Some(value) = store.get(key) {
            records.push((
                serde_bytes::ByteBuf::from(key.to_vec()),
                serde_bytes::ByteBuf::from(value),
            ));
        }
    }
    let snap = UpgradeSnapshot {
        v: UPGRADE_SNAPSHOT_VERSION,
        vault_id: session.vault_id().to_vec(),
        key_epoch: session.key_epoch(),
        records,
    };
    let mut out = Vec::new();
    ciborium::into_writer(&snap, &mut out)
        .map_err(|e| VaultError::Serde(e.to_string()))?;
    if out.len() > MAX_UPGRADE_SNAPSHOT {
        return Err(VaultError::Msg(ERR_TOO_LARGE.into()));
    }
    Ok(out)
}

fn invalid() -> VaultError {
    VaultError::Msg(ERR_INVALID.into())
}

/// Validate a snapshot fully; returns it only if every check passes.
fn validate(snapshot: &[u8]) -> Result<UpgradeSnapshot, VaultError> {
    if snapshot.len() > MAX_UPGRADE_SNAPSHOT {
        return Err(invalid());
    }
    let snap: UpgradeSnapshot = ciborium::from_reader(snapshot).map_err(|_| invalid())?;
    if snap.v != UPGRADE_SNAPSHOT_VERSION || snap.vault_id.len() != 16 {
        return Err(invalid());
    }
    let mut seen: Vec<&[u8]> = Vec::new();
    for (k, _) in &snap.records {
        let k = k.as_slice();
        if !SECRET_KEYS_V2.contains(&k) || seen.contains(&k) {
            return Err(invalid());
        }
        seen.push(k);
    }
    let find = |key: &[u8]| {
        snap.records
            .iter()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, v)| v.as_slice())
    };
    let env_bytes = find(SECRET_ENVELOPE_V2).ok_or_else(invalid)?;
    let vault_bytes = find(SECRET_VAULT_V2).ok_or_else(invalid)?;
    let env = MasterEnvelopeV2::from_bytes(env_bytes).map_err(|_| invalid())?;
    let env_vid = env.vault_id_bytes().map_err(|_| invalid())?;
    if env_vid.as_slice() != snap.vault_id.as_slice() || env.key_epoch != snap.key_epoch {
        return Err(invalid());
    }
    let blob = VaultBlobV2::from_bytes(vault_bytes).map_err(|_| invalid())?;
    if blob.key_epoch != snap.key_epoch || blob.vault_id != snap.vault_id {
        return Err(invalid());
    }
    Ok(snap)
}

/// Validates, then writes everything in ONE store.commit. Never calls set/remove. No session.
pub fn import_upgrade_snapshot(
    store: &mut dyn SecretStore,
    snapshot: &[u8],
) -> Result<(), VaultError> {
    let snap = validate(snapshot)?;
    let mut ops = Vec::new();
    for (k, v) in &snap.records {
        ops.push(StoreOp::put(k.to_vec(), v.to_vec()));
    }
    for key in SECRET_KEYS_V2 {
        if !snap.records.iter().any(|(k, _)| k.as_slice() == *key) {
            ops.push(StoreOp::delete(key.to_vec()));
        }
    }
    store
        .commit(&ops)
        .map_err(|e| VaultError::Msg(format!("{ERR_COMMIT_PREFIX}{e}")))
}
