//! Live v1 → v2 migration (Phase 5). Fresh RootSecret; keep vault_id. D14 commit.

use crate::crypto::envelope_v2::{
    open_audit_v2, open_vault_v2, seal_audit_v2, seal_vault_v2, unwrap_root_v2,
    wrap_existing_root_v2, wrap_existing_root_v2_legacy_passphrase,
};
use crate::crypto::hkdf_v2::derive_operational_keys;
use crate::crypto::passphrase::validate_v2_passphrase;
use crate::crypto::secret::RootSecret;
use crate::crypto::suite::KEY_EPOCH_INITIAL;
use crate::crypto::{
    derive_keys, normalize_recovery_key, open, unwrap_master, unwrap_master_with_aad,
    MasterEnvelope, SealedBlob, SecretKey,
};
use crate::recovery_v2::{wrap_recovery, SECRET_RECOVERY_V2};
use crate::session_v2::{
    VaultSessionV2, SECRET_AUDIT_V2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2,
};
use crate::types::{unix_now, AuditEvent, AuditKind, VaultDocument};
use crate::vault::{
    SecretStore, StoreOp, VaultError, RECOVERY_AAD, SECRET_AUDIT, SECRET_ENVELOPE,
    SECRET_RECOVERY, SECRET_SYNC_COUNTER, SECRET_SYNC_STATE, SECRET_VAULT, VAULT_INSTANCE_KEYS,
};

/// Decode v1 hex vault_id (32 ASCII chars) into the original 16 bytes.
pub fn decode_v1_vault_id(hex_id: &str) -> Result<[u8; 16], VaultError> {
    let trimmed = hex_id.trim();
    if trimmed.len() != 32 {
        return Err(VaultError::Msg("invalid vault_id".into()));
    }
    let bytes = hex::decode(trimmed).map_err(|_| VaultError::Msg("invalid vault_id".into()))?;
    bytes
        .try_into()
        .map_err(|_| VaultError::Msg("invalid vault_id".into()))
}

fn load_v1_audit(
    store: &dyn SecretStore,
    keys: &crate::crypto::DerivedKeys,
    vault_id: &str,
) -> Vec<AuditEvent> {
    let Some(bytes) = store.get(SECRET_AUDIT) else {
        return Vec::new();
    };
    let Ok(sealed) = SealedBlob::from_cbor(&bytes) else {
        return Vec::new();
    };
    let Ok(pt) = open(&keys.vault_dek, vault_id.as_bytes(), b"audit", &sealed) else {
        return Vec::new();
    };
    ciborium::from_reader(pt.as_slice()).unwrap_or_default()
}

fn refuse_if_not_migratable_v1(store: &dyn SecretStore) -> Result<(), VaultError> {
    if store.has(SECRET_ENVELOPE_V2) {
        return Err(VaultError::Msg("vault is already v2".into()));
    }
    if store.has(SECRET_SYNC_STATE) || store.has(SECRET_SYNC_COUNTER) {
        return Err(VaultError::VaultSyncMigrationDeferred);
    }
    Ok(())
}

fn decrypt_v1_document(
    store: &dyn SecretStore,
    master: &SecretKey,
    envelope: &MasterEnvelope,
) -> Result<(VaultDocument, Vec<AuditEvent>), VaultError> {
    let v1_keys = derive_keys(master)?;
    let vault_bytes = store
        .get(SECRET_VAULT)
        .ok_or_else(|| VaultError::Msg("vault blob not found".into()))?;
    let sealed = SealedBlob::from_cbor(&vault_bytes)?;
    let pt = open(
        &v1_keys.vault_dek,
        envelope.vault_id.as_bytes(),
        b"vault",
        &sealed,
    )?;
    let doc: VaultDocument =
        ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;
    if doc.meta.vault_id != envelope.vault_id {
        return Err(VaultError::Msg("vault_id mismatch".into()));
    }
    let audit = load_v1_audit(store, &v1_keys, &envelope.vault_id);
    Ok((doc, audit))
}

/// Candidate-first v2 construction. `enforce_d18` is true when wrapping under a
/// newly chosen passphrase (recovery migration). Passphrase-preserving live
/// migration keeps the historical wrap password without re-applying D18.
fn commit_v2_from_v1(
    store: &mut dyn SecretStore,
    master: &SecretKey,
    envelope: &MasterEnvelope,
    wrap_passphrase: &str,
    enforce_d18: bool,
) -> Result<(VaultSessionV2, String), VaultError> {
    let (mut doc, mut audit) = decrypt_v1_document(store, master, envelope)?;
    let vault_id = decode_v1_vault_id(&envelope.vault_id)?;
    let root = RootSecret::random();
    if root.as_bytes() == master.as_bytes() {
        return Err(VaultError::Msg("root collision".into()));
    }
    let kdf = crate::crypto::kdf::Argon2ParamsV2::generate_v2();
    let env_v2 = if enforce_d18 {
        wrap_existing_root_v2(wrap_passphrase, vault_id, KEY_EPOCH_INITIAL, &kdf, &root)?
    } else {
        wrap_existing_root_v2_legacy_passphrase(
            wrap_passphrase,
            vault_id,
            KEY_EPOCH_INITIAL,
            &kdf,
            &root,
        )?
    };
    let keys = derive_operational_keys(&root, &vault_id)?;
    doc.meta.vault_id = hex::encode(vault_id);
    doc.meta.format_version = 2;
    doc.meta.updated_at = unix_now();

    audit.push(AuditEvent {
        ts: unix_now(),
        kind: AuditKind::Unlock,
        entry_id: None,
        detail: "migrated v1 to v2".into(),
    });

    let mut vault_pt = Vec::new();
    ciborium::into_writer(&doc, &mut vault_pt).map_err(|e| VaultError::Serde(e.to_string()))?;
    let vault_blob = seal_vault_v2(&keys.vault_dek, vault_id, KEY_EPOCH_INITIAL, &vault_pt)?;
    let mut audit_pt = Vec::new();
    ciborium::into_writer(&audit, &mut audit_pt).map_err(|e| VaultError::Serde(e.to_string()))?;
    let audit_blob = seal_audit_v2(&keys.audit_dek, vault_id, KEY_EPOCH_INITIAL, &audit_pt)?;
    let (rec_wrap, rec_secret) = wrap_recovery(&root, vault_id, KEY_EPOCH_INITIAL)?;

    let opened_root = unwrap_root_v2(wrap_passphrase, &env_v2)?;
    if opened_root.as_bytes() != root.as_bytes() {
        return Err(VaultError::Msg("candidate reopen failed".into()));
    }
    let reopened = open_vault_v2(&keys.vault_dek, &vault_blob)?;
    let doc2: VaultDocument =
        ciborium::from_reader(reopened.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;
    if doc2.entries.len() != doc.entries.len() || doc2.meta.vault_id != hex::encode(vault_id) {
        return Err(VaultError::Msg("candidate reopen failed".into()));
    }
    let _ = open_audit_v2(&keys.audit_dek, &audit_blob)?;

    let mut ops: Vec<StoreOp> = vec![
        StoreOp::put(SECRET_ENVELOPE_V2, env_v2.to_bytes()?),
        StoreOp::put(SECRET_VAULT_V2, vault_blob.to_bytes()?),
        StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?),
        StoreOp::put(SECRET_RECOVERY_V2, rec_wrap.to_cbor()?),
    ];
    for k in VAULT_INSTANCE_KEYS {
        ops.push(StoreOp::delete(*k));
    }
    store
        .commit(&ops)
        .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;

    let session = VaultSessionV2::from_migrated(root, keys, vault_id, KEY_EPOCH_INITIAL, doc, audit);
    Ok((
        session,
        crate::recovery_v2::encode_recovery_secret(&rec_secret),
    ))
}

fn load_v1_envelope(store: &dyn SecretStore) -> Result<MasterEnvelope, VaultError> {
    let env_bytes = store
        .get(SECRET_ENVELOPE)
        .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
    MasterEnvelope::from_cbor(&env_bytes).map_err(Into::into)
}

fn recover_v1_master_from_passphrase(
    store: &dyn SecretStore,
    passphrase: &str,
) -> Result<(SecretKey, MasterEnvelope), VaultError> {
    let envelope = load_v1_envelope(store)?;
    let master = unwrap_master(passphrase, &envelope)?;
    Ok((master, envelope))
}

fn recover_v1_master_from_recovery(
    store: &dyn SecretStore,
    recovery_key: &str,
) -> Result<(SecretKey, MasterEnvelope), VaultError> {
    let rec_bytes = store
        .get(SECRET_RECOVERY)
        .ok_or_else(|| VaultError::Msg("no recovery key configured".into()))?;
    let rec_env = MasterEnvelope::from_cbor(&rec_bytes)?;
    let normalized = normalize_recovery_key(recovery_key);
    let master = unwrap_master_with_aad(&normalized, &rec_env, RECOVERY_AAD)?;
    let envelope = load_v1_envelope(store)?;
    if envelope.vault_id != rec_env.vault_id {
        return Err(VaultError::Msg("vault_id mismatch".into()));
    }
    Ok((master, envelope))
}

/// Shared post-auth migration: VaultSync preflight, then candidate + D14 commit.
fn migrate_recovered_v1(
    store: &mut dyn SecretStore,
    master: &SecretKey,
    envelope: &MasterEnvelope,
    wrap_passphrase: &str,
    enforce_d18: bool,
) -> Result<(VaultSessionV2, String), VaultError> {
    refuse_if_not_migratable_v1(store)?;
    commit_v2_from_v1(store, master, envelope, wrap_passphrase, enforce_d18)
}

/// Authenticate v1 with the live passphrase, then the common migration pipeline.
pub fn migrate_live_v1_to_v2(
    store: &mut dyn SecretStore,
    passphrase: &str,
) -> Result<(VaultSessionV2, String), VaultError> {
    let (master, envelope) = recover_v1_master_from_passphrase(store, passphrase)?;
    migrate_recovered_v1(store, &master, &envelope, passphrase, false)
}

/// Authenticate v1 with the recovery key. Wrap the new RootSecret under a
/// freshly chosen D18 passphrase (the old master passphrase is not required).
pub fn migrate_live_v1_to_v2_with_recovery(
    store: &mut dyn SecretStore,
    recovery_key: &str,
    new_v2_passphrase: &str,
) -> Result<(VaultSessionV2, String), VaultError> {
    let (master, envelope) = recover_v1_master_from_recovery(store, recovery_key)?;
    validate_v2_passphrase(new_v2_passphrase)?;
    migrate_recovered_v1(store, &master, &envelope, new_v2_passphrase, true)
}

/// Build a new v2 vault from a decrypted document (legacy backup restore). New vault_id.
pub fn restore_document_as_v2(
    store: &mut dyn SecretStore,
    doc_in: VaultDocument,
    audit_in: Vec<AuditEvent>,
    vault_passphrase: &str,
    replace: bool,
) -> Result<VaultSessionV2, VaultError> {
    crate::session_v2::install_new_v2_from_document(store, doc_in, audit_in, vault_passphrase, replace)
}

#[cfg(test)]
mod tests {
    use super::decode_v1_vault_id;

    #[test]
    fn decode_v1_vault_id_is_exact_16_bytes_not_ascii() {
        let raw = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let hex_id = hex::encode(raw);
        assert_eq!(hex_id.len(), 32);
        let got = decode_v1_vault_id(&hex_id).unwrap();
        assert_eq!(got, raw);
        assert_ne!(&got[..], hex_id.as_bytes());
    }

    #[test]
    fn decode_v1_vault_id_rejects_malformed() {
        assert!(decode_v1_vault_id("short").is_err());
        assert!(decode_v1_vault_id("gggggggggggggggggggggggggggggggg").is_err());
        assert!(decode_v1_vault_id(&"ab".repeat(16)).is_ok());
        assert!(decode_v1_vault_id(&"ab".repeat(15)).is_err());
    }
}
