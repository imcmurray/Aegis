//! Multi-device vault sync: build/verify encrypted revisions and merge remote state.

use crate::crdt::VersionVector;
use crate::crypto::{open, seal, DerivedKeys, EnvelopeKind, SecretKey};
use crate::sync_types::{EncryptedRevision, VaultSyncState};
use crate::types::{unix_now, VaultDocument};
use crate::vault::{SecretStore, VaultError, SECRET_SYNC_STATE};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Opaque transport for VaultSyncState (file for dev, secret store, Freenet contract later).
pub trait SyncTransport {
    fn load(&self) -> Result<VaultSyncState, String>;
    fn save(&mut self, state: &VaultSyncState) -> Result<(), String>;
}

/// File-backed sync state (shared by devices that can see the same path / copy).
pub struct FileSyncTransport {
    path: std::path::PathBuf,
}

impl FileSyncTransport {
    pub fn open(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl SyncTransport for FileSyncTransport {
    fn load(&self) -> Result<VaultSyncState, String> {
        if !self.path.exists() {
            return Ok(VaultSyncState::default());
        }
        let bytes = std::fs::read(&self.path).map_err(|e| e.to_string())?;
        if bytes.is_empty() {
            return Ok(VaultSyncState::default());
        }
        crate::sync_types::decode_cbor(&bytes)
    }

    fn save(&mut self, state: &VaultSyncState) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let bytes = crate::sync_types::encode_cbor(state)?;
        std::fs::write(&self.path, bytes).map_err(|e| e.to_string())
    }
}

/// In-memory buffer of sync state, loaded/committed via the secret store.
///
/// Used as the Freenet / single-node fallback so `SyncNow` works without a file
/// path. Also merges optional **VaultSync contract** bytes (UI-mediated Put/Get)
/// before syncing so multi-device network state can flow through the same path.
///
/// Owns a snapshot so it does not hold a store borrow during [`sync_vault`].
pub struct StoreSyncBuffer {
    state: VaultSyncState,
}

impl StoreSyncBuffer {
    pub fn load(store: &dyn SecretStore) -> Result<Self, String> {
        let state = match store.get(SECRET_SYNC_STATE) {
            None => VaultSyncState::default(),
            Some(bytes) if bytes.is_empty() => VaultSyncState::default(),
            Some(bytes) => crate::sync_types::decode_cbor(&bytes)?,
        };
        Ok(Self { state })
    }

    /// Merge remote contract state (CBOR `VaultSyncState`) into this buffer.
    pub fn merge_remote_cbor(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }
        let remote: VaultSyncState = crate::sync_types::decode_cbor(bytes)?;
        self.state.merge(&remote);
        Ok(())
    }

    pub fn commit(&self, store: &mut dyn SecretStore) -> Result<(), String> {
        let bytes = crate::sync_types::encode_cbor(&self.state)?;
        store.set(SECRET_SYNC_STATE, &bytes);
        Ok(())
    }

    /// Full MVR snapshot to publish to the VaultSync contract.
    pub fn encode_cbor(&self) -> Result<Vec<u8>, String> {
        crate::sync_types::encode_cbor(&self.state)
    }

    pub fn revision_count(&self) -> usize {
        self.state.revisions.len()
    }
}

impl SyncTransport for StoreSyncBuffer {
    fn load(&self) -> Result<VaultSyncState, String> {
        Ok(self.state.clone())
    }

    fn save(&mut self, state: &VaultSyncState) -> Result<(), String> {
        self.state = state.clone();
        Ok(())
    }
}

/// Canonical bytes signed for a revision (must match vault-sync contract).
pub fn revision_sign_bytes(rev: &EncryptedRevision) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"aegis/v1/sync-rev");
    for (dev, counter) in &rev.version_vector.0 {
        msg.extend_from_slice(dev.as_bytes());
        msg.push(0);
        msg.extend_from_slice(&counter.to_le_bytes());
    }
    msg.extend_from_slice(rev.device_id.as_bytes());
    msg.extend_from_slice(&rev.content_hash);
    msg.extend_from_slice(&rev.ciphertext);
    msg
}

pub fn sign_revision(keys: &DerivedKeys, mut rev: EncryptedRevision) -> EncryptedRevision {
    let sk = keys.signing_key();
    let msg = revision_sign_bytes(&rev);
    let sig = sk.sign(&msg);
    rev.signature = sig.to_bytes().to_vec();
    rev
}

pub fn verify_revision(owner_vk: &VerifyingKey, rev: &EncryptedRevision) -> bool {
    if rev.signature.len() != 64 {
        return false;
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&rev.signature);
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = revision_sign_bytes(rev);
    owner_vk.verify(&msg, &sig).is_ok()
}

/// Seal vault document for sync payload.
pub fn seal_doc_for_sync(
    keys: &DerivedKeys,
    vault_id: &str,
    doc: &VaultDocument,
) -> Result<(Vec<u8>, [u8; 32]), VaultError> {
    let mut pt = Vec::new();
    ciborium::into_writer(doc, &mut pt).map_err(|e| VaultError::Serde(e.to_string()))?;
    let content_hash = {
        let mut h = [0u8; 32];
        h.copy_from_slice(blake3::hash(&pt).as_bytes());
        h
    };
    let sealed = seal(
        &keys.vault_dek,
        EnvelopeKind::SyncPayload,
        vault_id.as_bytes(),
        b"sync-doc",
        &pt,
    )?;
    let ct = sealed.to_cbor()?;
    Ok((ct, content_hash))
}

pub fn open_doc_from_sync(
    keys: &DerivedKeys,
    vault_id: &str,
    ciphertext: &[u8],
) -> Result<VaultDocument, VaultError> {
    let sealed = crate::crypto::SealedBlob::from_cbor(ciphertext)?;
    let pt = open(
        &keys.vault_dek,
        vault_id.as_bytes(),
        b"sync-doc",
        &sealed,
    )?;
    ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncAction {
    Pushed,
    Pulled,
    UpToDate,
    Merged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncReport {
    pub action: SyncAction,
    pub remote_revisions: u32,
    pub detail: String,
}

/// Semantic score for picking among concurrent vault snapshots.
fn doc_rank(doc: &VaultDocument) -> (u64, usize, u64) {
    (
        doc.meta.updated_at,
        doc.entries.len() + doc.folders.len(),
        doc.entries.values().map(|e| e.updated_at).max().unwrap_or(0),
    )
}

/// Merge two vault documents field-wise (entries/folders by higher `updated_at`).
/// Only bumps `meta.updated_at` when entries/folders/deleted actually change.
fn merge_docs(local: &VaultDocument, remote: &VaultDocument, keep_device_id: &str) -> VaultDocument {
    let mut out = local.clone();
    out.meta.device_id = keep_device_id.to_string();
    let before_entries = out.entries.len();
    let before_folders = out.folders.len();
    let before_deleted = out.deleted.len();

    for (id, remote_e) in &remote.entries {
        match out.entries.get(id) {
            None => {
                out.entries.insert(id.clone(), remote_e.clone());
            }
            Some(local_e) if remote_e.updated_at >= local_e.updated_at => {
                out.entries.insert(id.clone(), remote_e.clone());
            }
            _ => {}
        }
    }
    for (id, remote_f) in &remote.folders {
        match out.folders.get(id) {
            None => {
                out.folders.insert(id.clone(), remote_f.clone());
            }
            Some(local_f) if remote_f.updated_at >= local_f.updated_at => {
                out.folders.insert(id.clone(), remote_f.clone());
            }
            _ => {}
        }
    }
    // Union tombstones
    for (id, t) in &remote.deleted {
        out.deleted.entry(id.clone()).or_insert_with(|| t.clone());
        // If tombstoned remotely, drop entry
        if out.deleted.contains_key(id) {
            out.entries.remove(id);
        }
    }

    let substantive = out.entries != local.entries
        || out.folders != local.folders
        || out.deleted != local.deleted
        || out.entries.len() != before_entries
        || out.folders.len() != before_folders
        || out.deleted.len() != before_deleted;
    if substantive {
        out.meta.updated_at = unix_now()
            .max(local.meta.updated_at)
            .max(remote.meta.updated_at);
    }
    out
}

/// True when remote merge changed vault data (not just meta).
fn data_differs(a: &VaultDocument, b: &VaultDocument) -> bool {
    a.entries != b.entries || a.folders != b.folders || a.deleted != b.deleted
}

/// Push local vault and pull/merge remote revisions (same MasterSecret).
pub fn sync_vault(
    keys: &DerivedKeys,
    master: &SecretKey,
    device_id: &str,
    vault_id: &str,
    local_doc: &mut VaultDocument,
    counter: &mut u64,
    transport: &mut dyn SyncTransport,
) -> Result<SyncReport, VaultError> {
    let _ = master;
    let mut remote = transport
        .load()
        .map_err(|e| VaultError::Msg(format!("sync load: {e}")))?;

    // Advance our device counter past anything we already published.
    for rev in &remote.revisions {
        if let Some(&c) = rev.version_vector.0.get(device_id) {
            if c > *counter {
                *counter = c;
            }
        }
    }

    // Decrypt all remote siblings we can open (same vault keys).
    let mut remote_docs: Vec<(String, VaultDocument)> = Vec::new();
    for rev in &remote.revisions {
        match open_doc_from_sync(keys, vault_id, &rev.ciphertext) {
            Ok(doc) => remote_docs.push((rev.device_id.clone(), doc)),
            Err(_) => continue,
        }
    }

    let local_before = local_doc.clone();
    let mut merged = local_doc.clone();
    for (_dev, rdoc) in &remote_docs {
        // If remote strictly dominates by rank and local is empty-ish, take remote wholesale.
        if doc_rank(rdoc) > doc_rank(&merged)
            && (merged.entries.is_empty() || rdoc.meta.updated_at > merged.meta.updated_at)
        {
            let keep = device_id.to_string();
            merged = rdoc.clone();
            merged.meta.device_id = keep;
        } else {
            merged = merge_docs(&merged, rdoc, device_id);
        }
    }

    // Remote applied only when entries/folders/tombstones actually changed.
    let applied_remote = data_differs(&merged, &local_before);

    *local_doc = merged;
    local_doc.meta.device_id = device_id.to_string();
    if applied_remote {
        local_doc.meta.updated_at = unix_now().max(local_doc.meta.updated_at);
    }

    // Publish only when this vault data is not already on the transport.
    //
    // Prefer semantic match against decrypted remotes: each Freenet request
    // reloads the vault from sealed storage, and re-CBOR can change the byte
    // hash even when entries/folders/deleted are identical. Hash match alone
    // would re-push every Sync.
    let already_semantic = remote_docs
        .iter()
        .any(|(_, d)| !data_differs(d, local_doc));
    let (ciphertext, content_hash) = seal_doc_for_sync(keys, vault_id, local_doc)?;
    let already = already_semantic
        || remote
            .revisions
            .iter()
            .any(|r| r.content_hash == content_hash);

    let published = if !already {
        *counter = counter.saturating_add(1);
        let mut vv = VersionVector::new();
        for _ in 0..*counter {
            vv.increment(device_id);
        }
        // Causal awareness of remotes we merged
        for rev in &remote.revisions {
            vv = vv.merge_max(&rev.version_vector);
        }
        vv.0.insert(device_id.to_string(), *counter);

        let local_rev = sign_revision(
            keys,
            EncryptedRevision {
                version_vector: vv,
                device_id: device_id.to_string(),
                signature: vec![],
                ciphertext,
                content_hash,
            },
        );
        remote.upsert(local_rev);
        transport
            .save(&remote)
            .map_err(|e| VaultError::Msg(format!("sync save: {e}")))?;
        true
    } else {
        false
    };

    // Classify from what actually happened — not meta-only churn.
    let action = match (applied_remote, published) {
        (false, false) => SyncAction::UpToDate,
        (false, true) => SyncAction::Pushed,
        (true, false) => SyncAction::Pulled,
        (true, true) => SyncAction::Merged,
    };

    Ok(SyncReport {
        action,
        remote_revisions: remote.revisions.len() as u32,
        detail: match action {
            SyncAction::UpToDate => "already in sync".into(),
            SyncAction::Pulled => "applied remote changes".into(),
            SyncAction::Merged => "merged local and remote".into(),
            SyncAction::Pushed => "published local vault".into(),
        },
    })
}

/// Owner verifying key bytes for contract params.
pub fn owner_vk_bytes(keys: &DerivedKeys) -> Vec<u8> {
    keys.verifying_key().to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_keys, SecretKey};
    use crate::types::{new_id, Entry, VaultDocument, VaultMeta};
    use crate::vault::MemoryStore;
    use std::sync::{Arc, Mutex};

    struct MemSync {
        state: Arc<Mutex<VaultSyncState>>,
    }

    impl SyncTransport for MemSync {
        fn load(&self) -> Result<VaultSyncState, String> {
            Ok(self.state.lock().unwrap().clone())
        }
        fn save(&mut self, state: &VaultSyncState) -> Result<(), String> {
            *self.state.lock().unwrap() = state.clone();
            Ok(())
        }
    }

    #[test]
    fn two_devices_converge() {
        let master = SecretKey::random();
        let keys = derive_keys(&master).unwrap();
        let shared = Arc::new(Mutex::new(VaultSyncState::default()));

        let vault_id = new_id();
        let mut doc_a = VaultDocument {
            meta: VaultMeta {
                vault_id: vault_id.clone(),
                format_version: 1,
                created_at: 1,
                updated_at: 1,
                device_id: "device-a".into(),
            },
            ..Default::default()
        };
        let mut entry = Entry::new(new_id(), "Shared");
        entry.password = "s3cret".into();
        doc_a.entries.insert(entry.id.clone(), entry);

        let mut counter_a = 0u64;
        let mut transport_a = MemSync {
            state: shared.clone(),
        };
        let r = sync_vault(
            &keys,
            &master,
            "device-a",
            &vault_id,
            &mut doc_a,
            &mut counter_a,
            &mut transport_a,
        )
        .unwrap();
        assert!(matches!(
            r.action,
            SyncAction::Pushed | SyncAction::Merged | SyncAction::UpToDate
        ));

        // Device B starts empty, pulls
        let mut doc_b = VaultDocument {
            meta: VaultMeta {
                vault_id: vault_id.clone(),
                format_version: 1,
                created_at: 1,
                updated_at: 1,
                device_id: "device-b".into(),
            },
            ..Default::default()
        };
        let mut counter_b = 0u64;
        let mut transport_b = MemSync {
            state: shared.clone(),
        };
        let r = sync_vault(
            &keys,
            &master,
            "device-b",
            &vault_id,
            &mut doc_b,
            &mut counter_b,
            &mut transport_b,
        )
        .unwrap();
        assert!(
            matches!(r.action, SyncAction::Pulled | SyncAction::Merged),
            "B should absorb A's vault: {:?}",
            r
        );
        assert_eq!(doc_b.entries.len(), 1);
        assert_eq!(
            doc_b.entries.values().next().unwrap().password,
            "s3cret"
        );

        // B adds entry, pushes
        let mut e2 = Entry::new(new_id(), "FromB");
        e2.password = "b".into();
        doc_b.entries.insert(e2.id.clone(), e2);
        let r = sync_vault(
            &keys,
            &master,
            "device-b",
            &vault_id,
            &mut doc_b,
            &mut counter_b,
            &mut transport_b,
        )
        .unwrap();
        assert!(matches!(
            r.action,
            SyncAction::Pushed | SyncAction::Merged | SyncAction::UpToDate
        ));

        // A absorbs B's version
        let r = sync_vault(
            &keys,
            &master,
            "device-a",
            &vault_id,
            &mut doc_a,
            &mut counter_a,
            &mut transport_a,
        )
        .unwrap();
        assert!(
            matches!(r.action, SyncAction::Pulled | SyncAction::Merged),
            "A should absorb B: {:?}",
            r
        );
        assert_eq!(doc_a.entries.len(), 2);

        let _ = MemoryStore::default();
    }

    #[test]
    fn local_only_edit_reports_pushed_not_pulled() {
        // Regression: after publishing, a later local create must report Pushed
        // (not Pulled just because an older remote revision is still on the transport).
        let master = SecretKey::random();
        let keys = derive_keys(&master).unwrap();
        let shared = Arc::new(Mutex::new(VaultSyncState::default()));
        let vault_id = new_id();

        let mut doc = VaultDocument {
            meta: VaultMeta {
                vault_id: vault_id.clone(),
                format_version: 1,
                created_at: 1,
                updated_at: 1,
                device_id: "device-a".into(),
            },
            ..Default::default()
        };
        let mut counter = 0u64;
        let mut transport = MemSync {
            state: shared.clone(),
        };

        let r = sync_vault(
            &keys,
            &master,
            "device-a",
            &vault_id,
            &mut doc,
            &mut counter,
            &mut transport,
        )
        .unwrap();
        assert_eq!(r.action, SyncAction::Pushed);

        // No-op re-sync should be up to date (same content already published).
        let r = sync_vault(
            &keys,
            &master,
            "device-a",
            &vault_id,
            &mut doc,
            &mut counter,
            &mut transport,
        )
        .unwrap();
        assert_eq!(
            r.action,
            SyncAction::UpToDate,
            "re-sync without edits: {:?}",
            r
        );

        // Local-only create, then sync → Pushed (not Pulled).
        let mut e = Entry::new(new_id(), "NewLocal");
        e.password = "x".into();
        doc.entries.insert(e.id.clone(), e);
        doc.meta.updated_at = 99;
        let r = sync_vault(
            &keys,
            &master,
            "device-a",
            &vault_id,
            &mut doc,
            &mut counter,
            &mut transport,
        )
        .unwrap();
        assert_eq!(
            r.action,
            SyncAction::Pushed,
            "local-only edit should push: {:?}",
            r
        );
        assert_eq!(doc.entries.len(), 1);
    }

    #[test]
    fn resync_after_vault_reload_is_up_to_date() {
        // Freenet path: each request reloads VaultDocument from sealed store.
        // Re-CBOR must not cause a spurious push.
        use crate::crypto::KdfProfile;
        use crate::messages::{VaultRequest, VaultResponse};
        use crate::vault::{dispatch, VaultSession, SECRET_SESSION};

        let mut store = MemoryStore::default();
        let mut session = None;
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "reload-sync-pass".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        let mut e = Entry::new(new_id(), "One");
        e.password = "p".into();
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry: e },
        );

        let r = dispatch(&mut store, &mut session, VaultRequest::SyncNow);
        assert!(
            matches!(
                r,
                VaultResponse::Synced {
                    action: ref a,
                    ..
                } if a == "pushed"
            ),
            "first sync: {r:?}"
        );

        // Simulate next Freenet ApplicationMessage: only master stays in
        // SECRET_SESSION; vault doc is re-opened from SECRET_VAULT.
        assert!(store.has(SECRET_SESSION));
        let mut session2 = VaultSession::try_resume(&store).unwrap();
        assert!(session2.is_some());

        let r = dispatch(&mut store, &mut session2, VaultRequest::SyncNow);
        assert!(
            matches!(
                r,
                VaultResponse::Synced {
                    action: ref a,
                    ..
                } if a == "up_to_date"
            ),
            "re-sync after reload must be up_to_date, got {r:?}"
        );

        // Third time still up to date
        let mut session3 = VaultSession::try_resume(&store).unwrap();
        let r = dispatch(&mut store, &mut session3, VaultRequest::SyncNow);
        assert!(
            matches!(
                r,
                VaultResponse::Synced {
                    action: ref a,
                    ..
                } if a == "up_to_date"
            ),
            "third sync: {r:?}"
        );
    }
}


