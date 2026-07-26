//! In-memory vault session logic (used by the delegate and unit tests).

use crate::crypto::{
    derive_keys, generate_password, generate_recovery_key_display, normalize_recovery_key, open,
    seal, unwrap_master, unwrap_master_with_aad, wrap_existing_master,
    wrap_existing_master_with_aad, wrap_master, DerivedKeys, EnvelopeKind, KdfProfile,
    MasterEnvelope, SecretKey, SealedBlob,
};
use crate::health::analyze_entries;
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::types::{
    new_id, unix_now, AuditEvent, AuditKind, EntryId, EntrySummary, Folder, Tombstone,
    VaultDocument, VaultMeta,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Secret-store key names used by the delegate (and mirrored in tests).
pub const SECRET_ENVELOPE: &[u8] = b"aegis/v1/envelope";
pub const SECRET_VAULT: &[u8] = b"aegis/v1/vault";
pub const SECRET_AUDIT: &[u8] = b"aegis/v1/audit";
pub const SECRET_SESSION: &[u8] = b"aegis/v1/session"; // MasterSecret while unlocked
pub const SECRET_SYNC_COUNTER: &[u8] = b"aegis/v1/sync-counter";
/// Encrypted multi-device sync MVR (local secret-store fallback; Freenet contract later).
pub const SECRET_SYNC_STATE: &[u8] = b"aegis/v1/sync-state";
/// MasterSecret wrapped under recovery key (AAD logical id `recovery`).
pub const SECRET_RECOVERY: &[u8] = b"aegis/v1/recovery-envelope";
const RECOVERY_AAD: &[u8] = b"recovery";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("serde: {0}")]
    Serde(String),
}

impl VaultError {
    pub fn code(&self) -> ErrorCode {
        match self {
            VaultError::Crypto(crate::crypto::CryptoError::Decrypt) => ErrorCode::AuthFailed,
            VaultError::Crypto(_) => ErrorCode::Crypto,
            VaultError::Msg(m) if m.contains("locked") => ErrorCode::Locked,
            VaultError::Msg(m) if m.contains("exists") => ErrorCode::AlreadyExists,
            VaultError::Msg(m) if m.contains("not found") => ErrorCode::NotFound,
            _ => ErrorCode::Internal,
        }
    }
}

/// Export file format: envelope + sealed vault under export passphrase (re-wrap).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    pub format: u16,
    pub envelope: MasterEnvelope,
    pub vault: SealedBlob,
}

/// Abstract secret storage so logic can run in unit tests without Freenet.
pub trait SecretStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn set(&mut self, key: &[u8], value: &[u8]);
    fn remove(&mut self, key: &[u8]);
    fn has(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }
}

/// Simple HashMap-backed store for tests and browser WASM.
#[derive(Default, Clone)]
pub struct MemoryStore {
    map: std::collections::HashMap<Vec<u8>, Vec<u8>>,
}

impl MemoryStore {
    /// Snapshot secrets as CBOR `[[key, value], ...]` (skips session key).
    pub fn export_cbor_skip_session(&self) -> Result<Vec<u8>, String> {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = self
            .map
            .iter()
            .filter(|(k, _)| k.as_slice() != SECRET_SESSION)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut out = Vec::new();
        ciborium::into_writer(&pairs, &mut out).map_err(|e| e.to_string())?;
        Ok(out)
    }

    /// Restore from [`export_cbor_skip_session`] output.
    pub fn import_cbor(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }
        let pairs: Vec<(Vec<u8>, Vec<u8>)> =
            ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
        self.map.clear();
        for (k, v) in pairs {
            self.map.insert(k, v);
        }
        Ok(())
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.map.insert(key.to_vec(), value.to_vec());
    }

    fn remove(&mut self, key: &[u8]) {
        self.map.remove(key);
    }
}

/// Unlocked vault session.
pub struct VaultSession {
    pub master: SecretKey,
    pub keys: DerivedKeys,
    pub doc: VaultDocument,
    pub audit: Vec<AuditEvent>,
}

impl VaultSession {
    pub fn create(
        store: &mut dyn SecretStore,
        passphrase: &str,
        profile: KdfProfile,
    ) -> Result<Self, VaultError> {
        if store.has(SECRET_ENVELOPE) {
            return Err(VaultError::Msg("vault already exists".into()));
        }
        let vault_id = new_id();
        let device_id = new_id();
        let (envelope, master) = wrap_master(passphrase, profile, &vault_id)?;
        let keys = derive_keys(&master)?;
        let now = unix_now();
        let doc = VaultDocument {
            meta: VaultMeta {
                vault_id: vault_id.clone(),
                format_version: 1,
                created_at: now,
                updated_at: now,
                device_id,
            },
            ..Default::default()
        };
        store.set(SECRET_ENVELOPE, &envelope.to_cbor()?);

        let mut session = Self {
            master,
            keys,
            doc,
            audit: Vec::new(),
        };
        session.audit_push(AuditKind::CreateVault, None, "vault created");
        session.persist(store)?;
        session.persist_session_flag(store);
        Ok(session)
    }

    pub fn unlock(store: &mut dyn SecretStore, passphrase: &str) -> Result<Self, VaultError> {
        let env_bytes = store
            .get(SECRET_ENVELOPE)
            .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
        let envelope = MasterEnvelope::from_cbor(&env_bytes)?;
        let master = unwrap_master(passphrase, &envelope)?;
        let keys = derive_keys(&master)?;

        let vault_bytes = store
            .get(SECRET_VAULT)
            .ok_or_else(|| VaultError::Msg("vault blob not found".into()))?;
        let sealed = SealedBlob::from_cbor(&vault_bytes)?;
        let pt = open(
            &keys.vault_dek,
            envelope.vault_id.as_bytes(),
            b"vault",
            &sealed,
        )?;
        let doc: VaultDocument =
            ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;

        let audit = load_audit(store, &keys, &envelope.vault_id).unwrap_or_default();

        let mut session = Self {
            master,
            keys,
            doc,
            audit,
        };
        session.audit_push(AuditKind::Unlock, None, "unlocked");
        session.persist_audit(store)?;
        session.persist_session_flag(store);
        Ok(session)
    }

    pub fn try_resume(store: &dyn SecretStore) -> Result<Option<Self>, VaultError> {
        let Some(master_bytes) = store.get(SECRET_SESSION) else {
            return Ok(None);
        };
        if master_bytes.len() != 32 {
            return Ok(None);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&master_bytes);
        let master = SecretKey(arr);
        let keys = derive_keys(&master)?;
        let env_bytes = store
            .get(SECRET_ENVELOPE)
            .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
        let envelope = MasterEnvelope::from_cbor(&env_bytes)?;
        let vault_bytes = store
            .get(SECRET_VAULT)
            .ok_or_else(|| VaultError::Msg("vault blob not found".into()))?;
        let sealed = SealedBlob::from_cbor(&vault_bytes)?;
        let pt = open(
            &keys.vault_dek,
            envelope.vault_id.as_bytes(),
            b"vault",
            &sealed,
        )?;
        let doc: VaultDocument =
            ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit = load_audit(store, &keys, &envelope.vault_id).unwrap_or_default();
        Ok(Some(Self {
            master,
            keys,
            doc,
            audit,
        }))
    }

    pub fn lock(&mut self, store: &mut dyn SecretStore) {
        self.audit_push(AuditKind::Lock, None, "locked");
        let _ = self.persist_audit(store);
        store.remove(SECRET_SESSION);
    }

    fn persist_session_flag(&self, store: &mut dyn SecretStore) {
        store.set(SECRET_SESSION, self.master.as_bytes());
    }

    /// Seal and store the vault document. Does **not** bump `meta.updated_at`
    /// (callers that mutate data should set it). Auto-bump here made every
    /// post-sync persist change the content hash so the next Sync always
    /// re-published.
    pub fn persist(&mut self, store: &mut dyn SecretStore) -> Result<(), VaultError> {
        let mut pt = Vec::new();
        ciborium::into_writer(&self.doc, &mut pt).map_err(|e| VaultError::Serde(e.to_string()))?;
        let sealed = seal(
            &self.keys.vault_dek,
            EnvelopeKind::VaultBlob,
            self.doc.meta.vault_id.as_bytes(),
            b"vault",
            &pt,
        )?;
        store.set(SECRET_VAULT, &sealed.to_cbor()?);

        // Envelope is only written on create/import; ensure it exists.
        if !store.has(SECRET_ENVELOPE) {
            return Err(VaultError::Msg("missing envelope".into()));
        }
        self.persist_audit(store)?;
        Ok(())
    }

    fn touch_meta(&mut self) {
        self.doc.meta.updated_at = unix_now();
    }

    fn persist_audit(&self, store: &mut dyn SecretStore) -> Result<(), VaultError> {
        let mut pt = Vec::new();
        ciborium::into_writer(&self.audit, &mut pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let sealed = seal(
            &self.keys.vault_dek,
            EnvelopeKind::AuditBlob,
            self.doc.meta.vault_id.as_bytes(),
            b"audit",
            &pt,
        )?;
        store.set(SECRET_AUDIT, &sealed.to_cbor()?);
        Ok(())
    }

    pub fn audit_push(&mut self, kind: AuditKind, entry_id: Option<EntryId>, detail: &str) {
        self.audit.push(AuditEvent {
            ts: unix_now(),
            kind,
            entry_id,
            detail: detail.to_string(),
        });
        // Cap local audit log size.
        const MAX: usize = 500;
        if self.audit.len() > MAX {
            let drain = self.audit.len() - MAX;
            self.audit.drain(0..drain);
        }
    }

    pub fn handle(
        &mut self,
        store: &mut dyn SecretStore,
        req: VaultRequest,
    ) -> Result<VaultResponse, VaultError> {
        match req {
            VaultRequest::Lock => {
                self.lock(store);
                Ok(VaultResponse::Locked)
            }
            VaultRequest::ListSummaries { query } => {
                let q = query.as_deref().map(|s| s.to_lowercase());
                let mut entries: Vec<EntrySummary> = self
                    .doc
                    .entries
                    .values()
                    .filter(|e| match &q {
                        None => true,
                        Some(q) => {
                            e.name.to_lowercase().contains(q)
                                || e.username.to_lowercase().contains(q)
                                || e.urls.iter().any(|u| u.to_lowercase().contains(q))
                                || e.tags.iter().any(|t| t.to_lowercase().contains(q))
                        }
                    })
                    .map(EntrySummary::from)
                    .collect();
                entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
                Ok(VaultResponse::Summaries { entries })
            }
            VaultRequest::GetEntry { id } => {
                let entry = self
                    .doc
                    .entries
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| VaultError::Msg("entry not found".into()))?;
                self.audit_push(AuditKind::View, Some(id), "view entry");
                self.persist_audit(store)?;
                Ok(VaultResponse::Entry { entry })
            }
            VaultRequest::UpsertEntry { mut entry } => {
                if entry.id.is_empty() {
                    entry.id = new_id();
                }
                let is_new = !self.doc.entries.contains_key(&entry.id);
                entry.updated_at = unix_now();
                if is_new && entry.created_at == 0 {
                    entry.created_at = entry.updated_at;
                }
                // Preserve / extend password history when the password changes.
                if let Some(prev) = self.doc.entries.get(&entry.id) {
                    if !prev.password.is_empty() && prev.password != entry.password {
                        let mut hist = entry.password_history.clone();
                        if hist.is_empty() {
                            hist = prev.password_history.clone();
                        }
                        hist.insert(
                            0,
                            crate::types::PasswordHistoryItem {
                                password: prev.password.clone(),
                                changed_at: prev.updated_at,
                            },
                        );
                        hist.truncate(crate::types::Entry::MAX_PASSWORD_HISTORY);
                        entry.password_history = hist;
                    } else if entry.password_history.is_empty()
                        && !prev.password_history.is_empty()
                    {
                        // Client omitted history — keep existing.
                        entry.password_history = prev.password_history.clone();
                    }
                }
                let id = entry.id.clone();
                self.doc.entries.insert(id.clone(), entry);
                self.touch_meta();
                self.audit_push(
                    if is_new {
                        AuditKind::Create
                    } else {
                        AuditKind::Update
                    },
                    Some(id),
                    if is_new { "create entry" } else { "update entry" },
                );
                self.persist(store)?;
                Ok(VaultResponse::Ok)
            }
            VaultRequest::DeleteEntry { id } => {
                if self.doc.entries.remove(&id).is_none() {
                    return Err(VaultError::Msg("entry not found".into()));
                }
                self.doc.deleted.insert(
                    id.clone(),
                    Tombstone {
                        deleted_at: unix_now(),
                        device_id: self.doc.meta.device_id.clone(),
                    },
                );
                self.touch_meta();
                self.audit_push(AuditKind::Delete, Some(id), "delete entry");
                self.persist(store)?;
                Ok(VaultResponse::Ok)
            }
            VaultRequest::UpsertFolder { mut folder } => {
                if folder.id.is_empty() {
                    folder.id = new_id();
                }
                folder.updated_at = unix_now();
                if folder.created_at == 0 {
                    folder.created_at = folder.updated_at;
                }
                self.doc.folders.insert(folder.id.clone(), folder);
                self.touch_meta();
                self.persist(store)?;
                Ok(VaultResponse::Ok)
            }
            VaultRequest::DeleteFolder { id } => {
                self.doc.folders.remove(&id);
                // Detach entries from folder.
                for e in self.doc.entries.values_mut() {
                    if e.folder_id.as_deref() == Some(id.as_str()) {
                        e.folder_id = None;
                    }
                }
                self.touch_meta();
                self.persist(store)?;
                Ok(VaultResponse::Ok)
            }
            VaultRequest::ListFolders => {
                let mut folders: Vec<Folder> = self.doc.folders.values().cloned().collect();
                folders.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(VaultResponse::Folders { folders })
            }
            VaultRequest::GeneratePassword { policy } => {
                let password = generate_password(&policy)?;
                self.audit_push(AuditKind::GeneratePassword, None, "generated password");
                self.persist_audit(store)?;
                Ok(VaultResponse::Password { password })
            }
            VaultRequest::GenerateTotp {
                secret,
                period,
                digits,
            } => {
                let period = period.unwrap_or(30);
                let digits = digits.unwrap_or(6);
                let now = unix_now();
                let code = crate::totp::generate_totp(&secret, now, period, digits)
                    .map_err(|e| VaultError::Msg(e.to_string()))?;
                let rem = crate::totp::totp_seconds_remaining(now, period);
                Ok(VaultResponse::Totp {
                    code,
                    seconds_remaining: rem as u32,
                    period: period as u32,
                })
            }
            VaultRequest::ChangePassphrase {
                current_passphrase,
                new_passphrase,
                kdf_profile,
            } => {
                self.change_passphrase(
                    store,
                    &current_passphrase,
                    &new_passphrase,
                    kdf_profile.unwrap_or(KdfProfile::Interactive),
                )?;
                Ok(VaultResponse::Ok)
            }
            VaultRequest::PasswordHealth => {
                let report = analyze_entries(self.doc.entries.values());
                self.audit_push(AuditKind::HealthCheck, None, "password health checked");
                self.persist_audit(store)?;
                Ok(VaultResponse::Health { report })
            }
            VaultRequest::GenerateRecoveryKey { kdf_profile } => {
                let key = self.generate_recovery_key(
                    store,
                    kdf_profile.unwrap_or(KdfProfile::Interactive),
                )?;
                Ok(VaultResponse::RecoveryKey { recovery_key: key })
            }
            VaultRequest::RevokeRecoveryKey => {
                store.remove(SECRET_RECOVERY);
                self.audit_push(AuditKind::RevokeRecovery, None, "recovery key revoked");
                self.persist_audit(store)?;
                Ok(VaultResponse::Ok)
            }
            // UnlockWithRecovery handled at dispatch (no session yet).
            VaultRequest::ExportEncrypted { passphrase } => {
                let blob = self.export_bundle(&passphrase)?;
                self.audit_push(AuditKind::Export, None, "exported vault");
                self.persist_audit(store)?;
                Ok(VaultResponse::Export { blob })
            }
            VaultRequest::GetAuditLog { limit } => {
                let n = limit.unwrap_or(100) as usize;
                let start = self.audit.len().saturating_sub(n);
                Ok(VaultResponse::Audit {
                    events: self.audit[start..].to_vec(),
                })
            }
            // Sync* handled in dispatch_with_sync / dispatch_sync.
            VaultRequest::SyncNow | VaultRequest::SyncWithRemote { .. } => Err(VaultError::Msg(
                "sync must be handled by dispatch_with_sync".into(),
            )),
            // Handled at dispatch level (no session required or special).
            VaultRequest::CreateVault { .. }
            | VaultRequest::Unlock { .. }
            | VaultRequest::UnlockWithRecovery { .. }
            | VaultRequest::Status
            | VaultRequest::ImportEncrypted { .. } => Err(VaultError::Msg(
                "request must be handled by dispatcher".into(),
            )),
        }
    }

    /// Create or replace recovery envelope; returns display recovery key (show once).
    pub fn generate_recovery_key(
        &mut self,
        store: &mut dyn SecretStore,
        profile: KdfProfile,
    ) -> Result<String, VaultError> {
        let display = generate_recovery_key_display();
        let normalized = normalize_recovery_key(&display);
        let env = wrap_existing_master_with_aad(
            &normalized,
            profile,
            &self.doc.meta.vault_id,
            &self.master,
            RECOVERY_AAD,
        )?;
        store.set(SECRET_RECOVERY, &env.to_cbor()?);
        self.audit_push(AuditKind::GenerateRecovery, None, "recovery key created");
        self.persist_audit(store)?;
        Ok(display)
    }

    /// Load vault using recovery key (same path as unlock after master unwrap).
    pub fn unlock_with_recovery(
        store: &mut dyn SecretStore,
        recovery_key: &str,
    ) -> Result<Self, VaultError> {
        let env_bytes = store
            .get(SECRET_RECOVERY)
            .ok_or_else(|| VaultError::Msg("no recovery key configured".into()))?;
        let envelope = MasterEnvelope::from_cbor(&env_bytes)?;
        let normalized = normalize_recovery_key(recovery_key);
        let master = unwrap_master_with_aad(&normalized, &envelope, RECOVERY_AAD)?;
        let keys = derive_keys(&master)?;

        let vault_bytes = store
            .get(SECRET_VAULT)
            .ok_or_else(|| VaultError::Msg("vault blob not found".into()))?;
        let sealed = SealedBlob::from_cbor(&vault_bytes)?;
        let pt = open(
            &keys.vault_dek,
            envelope.vault_id.as_bytes(),
            b"vault",
            &sealed,
        )?;
        let doc: VaultDocument =
            ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit = load_audit(store, &keys, &envelope.vault_id).unwrap_or_default();

        let mut session = Self {
            master,
            keys,
            doc,
            audit,
        };
        session.audit_push(AuditKind::UnlockRecovery, None, "unlocked with recovery key");
        session.persist_audit(store)?;
        session.persist_session_flag(store);
        Ok(session)
    }

    /// Re-wrap MasterSecret under a new passphrase. Does not re-encrypt vault entries.
    pub fn change_passphrase(
        &mut self,
        store: &mut dyn SecretStore,
        current: &str,
        new: &str,
        profile: KdfProfile,
    ) -> Result<(), VaultError> {
        if new.len() < 8 {
            return Err(VaultError::Msg(
                "new passphrase must be at least 8 characters".into(),
            ));
        }
        if current == new {
            return Err(VaultError::Msg(
                "new passphrase must differ from the current one".into(),
            ));
        }
        let env_bytes = store
            .get(SECRET_ENVELOPE)
            .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
        let envelope = MasterEnvelope::from_cbor(&env_bytes)?;
        // Verify current passphrase
        let verified = unwrap_master(current, &envelope)?;
        if verified.as_bytes() != self.master.as_bytes() {
            return Err(VaultError::Msg("current passphrase incorrect".into()));
        }
        let new_env =
            wrap_existing_master(new, profile, &self.doc.meta.vault_id, &self.master)?;
        store.set(SECRET_ENVELOPE, &new_env.to_cbor()?);
        self.audit_push(AuditKind::ChangePassphrase, None, "master passphrase changed");
        self.persist_audit(store)?;
        Ok(())
    }

    /// Multi-device sync via the provided transport (no contract blob).
    pub fn sync_now(
        &mut self,
        store: &mut dyn SecretStore,
        transport: &mut dyn crate::sync::SyncTransport,
    ) -> Result<VaultResponse, VaultError> {
        self.sync_now_with_publish(store, transport, Vec::new(), false)
    }

    /// Sync; when `include_contract_blob` is set, attach MVR + owner VK for contract Put.
    pub fn sync_now_with_publish(
        &mut self,
        store: &mut dyn SecretStore,
        transport: &mut dyn crate::sync::SyncTransport,
        contract_state: Vec<u8>,
        include_owner_vk: bool,
    ) -> Result<VaultResponse, VaultError> {
        let mut counter = load_sync_counter(store);
        let device_id = self.doc.meta.device_id.clone();
        let vault_id = self.doc.meta.vault_id.clone();
        let report = crate::sync::sync_vault(
            &self.keys,
            &self.master,
            &device_id,
            &vault_id,
            &mut self.doc,
            &mut counter,
            transport,
        )?;
        save_sync_counter(store, counter);
        self.audit_push(
            AuditKind::Sync,
            None,
            &format!(
                "{:?}: {} ({} rev)",
                report.action, report.detail, report.remote_revisions
            ),
        );
        self.persist(store)?;
        let action = match report.action {
            crate::sync::SyncAction::Pushed => "pushed",
            crate::sync::SyncAction::Pulled => "pulled",
            crate::sync::SyncAction::UpToDate => "up_to_date",
            crate::sync::SyncAction::Merged => "merged",
        };
        let owner_verifying_key = if include_owner_vk {
            crate::sync::owner_vk_bytes(&self.keys)
        } else {
            Vec::new()
        };
        Ok(VaultResponse::Synced {
            action: action.into(),
            remote_revisions: report.remote_revisions,
            detail: report.detail,
            contract_state,
            owner_verifying_key,
        })
    }

    fn export_bundle(&self, passphrase: &str) -> Result<Vec<u8>, VaultError> {
        // Re-wrap the *same* MasterSecret under the export passphrase.
        // Prefer a moderate profile for portable backups; re-wrap does not re-encrypt entry DEK.
        let envelope = wrap_existing_master(
            passphrase,
            KdfProfile::Mobile,
            &self.doc.meta.vault_id,
            &self.master,
        )?;

        let mut vault_pt = Vec::new();
        ciborium::into_writer(&self.doc, &mut vault_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        // Vault sealed under DEK derived from MasterSecret (export passphrase unwraps it).
        let vault_sealed = seal(
            &self.keys.vault_dek,
            EnvelopeKind::ExportBlob,
            self.doc.meta.vault_id.as_bytes(),
            b"export-vault",
            &vault_pt,
        )?;

        let bundle = ExportBundle {
            format: 1,
            envelope,
            vault: vault_sealed,
        };
        let mut out = Vec::new();
        ciborium::into_writer(&bundle, &mut out).map_err(|e| VaultError::Serde(e.to_string()))?;
        Ok(out)
    }
}

fn load_audit(
    store: &dyn SecretStore,
    keys: &DerivedKeys,
    vault_id: &str,
) -> Result<Vec<AuditEvent>, VaultError> {
    let Some(bytes) = store.get(SECRET_AUDIT) else {
        return Ok(Vec::new());
    };
    let sealed = SealedBlob::from_cbor(&bytes)?;
    let pt = open(&keys.vault_dek, vault_id.as_bytes(), b"audit", &sealed)?;
    ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))
}

/// Import an export bundle into an empty store.
pub fn import_bundle(
    store: &mut dyn SecretStore,
    blob: &[u8],
    passphrase: &str,
) -> Result<VaultSession, VaultError> {
    if store.has(SECRET_ENVELOPE) {
        return Err(VaultError::Msg("vault already exists".into()));
    }
    let bundle: ExportBundle =
        ciborium::from_reader(blob).map_err(|e| VaultError::Serde(e.to_string()))?;
    let master = unwrap_master(passphrase, &bundle.envelope)?;
    let keys = derive_keys(&master)?;
    let pt = open(
        &keys.vault_dek,
        bundle.envelope.vault_id.as_bytes(),
        b"export-vault",
        &bundle.vault,
    )?;
    let doc: VaultDocument =
        ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;

    store.set(SECRET_ENVELOPE, &bundle.envelope.to_cbor()?);
    // Re-seal vault as normal vault blob.
    let mut session = VaultSession {
        master,
        keys,
        doc,
        audit: Vec::new(),
    };
    session.audit_push(AuditKind::Import, None, "imported vault");
    session.persist(store)?;
    session.persist_session_flag(store);
    Ok(session)
}

fn load_sync_counter(store: &dyn SecretStore) -> u64 {
    store
        .get(SECRET_SYNC_COUNTER)
        .and_then(|b| {
            if b.len() == 8 {
                let mut a = [0u8; 8];
                a.copy_from_slice(&b);
                Some(u64::from_le_bytes(a))
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn save_sync_counter(store: &mut dyn SecretStore, counter: u64) {
    store.set(SECRET_SYNC_COUNTER, &counter.to_le_bytes());
}

/// Run sync via explicit transport or secret-store MVR (+ optional remote contract bytes).
fn dispatch_sync(
    store: &mut dyn SecretStore,
    session: &mut Option<VaultSession>,
    sync: Option<&mut dyn crate::sync::SyncTransport>,
    remote_state: &[u8],
) -> VaultResponse {
    let Some(s) = session.as_mut() else {
        return VaultResponse::err(ErrorCode::Locked, "vault is locked");
    };

    // Dev file transport: no contract blob (file is the multi-process channel).
    if let Some(transport) = sync {
        return match s.sync_now(store, transport) {
            Ok(r) => r,
            Err(e) => VaultResponse::err(e.code(), e.to_string()),
        };
    }

    let mut buf = match crate::sync::StoreSyncBuffer::load(store) {
        Ok(b) => b,
        Err(e) => {
            return VaultResponse::err(ErrorCode::Internal, format!("sync load: {e}"));
        }
    };
    if let Err(e) = buf.merge_remote_cbor(remote_state) {
        return VaultResponse::err(ErrorCode::Internal, format!("sync remote merge: {e}"));
    }
    match s.sync_now_with_publish(store, &mut buf, Vec::new(), true) {
        Ok(mut r) => {
            if let Err(e) = buf.commit(store) {
                return VaultResponse::err(ErrorCode::Internal, format!("sync save: {e}"));
            }
            // Attach publish blob after commit so it matches stored MVR.
            if let VaultResponse::Synced {
                ref mut contract_state,
                ..
            } = r
            {
                match buf.encode_cbor() {
                    Ok(bytes) => *contract_state = bytes,
                    Err(e) => {
                        return VaultResponse::err(
                            ErrorCode::Internal,
                            format!("sync encode: {e}"),
                        );
                    }
                }
            }
            r
        }
        Err(e) => VaultResponse::err(e.code(), e.to_string()),
    }
}

/// Top-level request dispatcher (session optional).
///
/// `SyncNow` / `SyncWithRemote` use secret-store MVR when no file transport is set.
pub fn dispatch(
    store: &mut dyn SecretStore,
    session: &mut Option<VaultSession>,
    req: VaultRequest,
) -> VaultResponse {
    dispatch_with_sync(store, session, req, None)
}

/// Dispatcher with optional multi-device sync transport.
///
/// When `sync` is `Some`, that transport is used (dev `FileSyncTransport`).
/// When `None`, `SyncNow` falls back to the secret-store MVR under
/// [`SECRET_SYNC_STATE`].
pub fn dispatch_with_sync(
    store: &mut dyn SecretStore,
    session: &mut Option<VaultSession>,
    req: VaultRequest,
    sync: Option<&mut dyn crate::sync::SyncTransport>,
) -> VaultResponse {
    match req {
        VaultRequest::Status => {
            let has_vault = store.has(SECRET_ENVELOPE);
            let unlocked = session.is_some();
            let vault_id = session.as_ref().map(|s| s.doc.meta.vault_id.clone());
            let has_recovery = store.has(SECRET_RECOVERY);
            VaultResponse::Status {
                has_vault,
                unlocked,
                vault_id,
                has_recovery,
            }
        }
        VaultRequest::CreateVault {
            passphrase,
            kdf_profile,
        } => match VaultSession::create(store, &passphrase, kdf_profile) {
            Ok(s) => {
                let vault_id = s.doc.meta.vault_id.clone();
                *session = Some(s);
                VaultResponse::Unlocked { vault_id }
            }
            Err(e) => VaultResponse::err(e.code(), e.to_string()),
        },
        VaultRequest::Unlock { passphrase } => match VaultSession::unlock(store, &passphrase) {
            Ok(s) => {
                let vault_id = s.doc.meta.vault_id.clone();
                *session = Some(s);
                VaultResponse::Unlocked { vault_id }
            }
            Err(e) => VaultResponse::err(e.code(), e.to_string()),
        },
        VaultRequest::UnlockWithRecovery { recovery_key } => {
            match VaultSession::unlock_with_recovery(store, &recovery_key) {
                Ok(s) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(s);
                    VaultResponse::Unlocked { vault_id }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
        VaultRequest::ImportEncrypted { blob, passphrase } => {
            match import_bundle(store, &blob, &passphrase) {
                Ok(s) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(s);
                    VaultResponse::Unlocked { vault_id }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
        VaultRequest::Lock => {
            if let Some(s) = session.as_mut() {
                s.lock(store);
            }
            *session = None;
            VaultResponse::Locked
        }
        VaultRequest::SyncNow => {
            dispatch_sync(store, session, sync, &[])
        }
        VaultRequest::SyncWithRemote { remote_state } => {
            // No external FileSyncTransport — contract path uses secret-store + remote merge.
            dispatch_sync(store, session, None, &remote_state)
        }
        other => {
            let Some(s) = session.as_mut() else {
                return VaultResponse::err(ErrorCode::Locked, "vault is locked");
            };
            match s.handle(store, other) {
                Ok(r) => r,
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfProfile;
    use crate::types::Entry;

    #[test]
    fn create_unlock_crud() {
        let mut store = MemoryStore::default();
        let mut session = None;

        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "test-pass".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        assert!(matches!(r, VaultResponse::Unlocked { .. }));

        let mut entry = Entry::new("", "Example");
        entry.username = "user".into();
        entry.password = "hunter2".into();
        entry.urls.push("https://example.com".into());

        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry: entry.clone() },
        );
        assert_eq!(r, VaultResponse::Ok);

        // Lock and unlock
        let r = dispatch(&mut store, &mut session, VaultRequest::Lock);
        assert_eq!(r, VaultResponse::Locked);
        assert!(session.is_none());

        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::Unlock {
                passphrase: "test-pass".into(),
            },
        );
        assert!(matches!(r, VaultResponse::Unlocked { .. }));

        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::ListSummaries { query: None },
        );
        match r {
            VaultResponse::Summaries { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "Example");
            }
            other => panic!("unexpected {other:?}"),
        }

        // Wrong password
        dispatch(&mut store, &mut session, VaultRequest::Lock);
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::Unlock {
                passphrase: "nope".into(),
            },
        );
        assert!(matches!(r, VaultResponse::Error { code: ErrorCode::AuthFailed, .. }));
    }

    #[test]
    fn recovery_key_unlock() {
        let mut store = MemoryStore::default();
        let mut session = None;
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "normal-passphrase".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        let mut entry = Entry::new("", "Keep");
        entry.password = "secret-entry".into();
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry },
        );

        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::GenerateRecoveryKey {
                kdf_profile: Some(KdfProfile::Test),
            },
        );
        let recovery_key = match r {
            VaultResponse::RecoveryKey { recovery_key } => recovery_key,
            other => panic!("expected recovery key: {other:?}"),
        };
        assert!(recovery_key.starts_with("AEGIS-"));

        dispatch(&mut store, &mut session, VaultRequest::Lock);
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::UnlockWithRecovery {
                recovery_key: recovery_key.clone(),
            },
        );
        assert!(matches!(r, VaultResponse::Unlocked { .. }));

        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::ListSummaries { query: None },
        );
        match r {
            VaultResponse::Summaries { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "Keep");
            }
            other => panic!("{other:?}"),
        }

        // Wrong recovery key fails
        dispatch(&mut store, &mut session, VaultRequest::Lock);
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::UnlockWithRecovery {
                recovery_key: "AEGIS-0000-0000-0000-0000-0000-0000-0000-0000".into(),
            },
        );
        assert!(matches!(r, VaultResponse::Error { code: ErrorCode::AuthFailed, .. }));
    }

    #[test]
    fn change_passphrase_rewraps() {
        let mut store = MemoryStore::default();
        let mut session = None;
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "old-pass-word".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::ChangePassphrase {
                current_passphrase: "old-pass-word".into(),
                new_passphrase: "new-pass-word".into(),
                kdf_profile: Some(KdfProfile::Test),
            },
        );
        assert_eq!(r, VaultResponse::Ok);

        dispatch(&mut store, &mut session, VaultRequest::Lock);
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::Unlock {
                passphrase: "old-pass-word".into(),
            },
        );
        assert!(matches!(r, VaultResponse::Error { code: ErrorCode::AuthFailed, .. }));

        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::Unlock {
                passphrase: "new-pass-word".into(),
            },
        );
        assert!(matches!(r, VaultResponse::Unlocked { .. }));
    }

    #[test]
    fn password_history_on_change() {
        let mut store = MemoryStore::default();
        let mut session = None;
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "test-pass-xx".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        let mut e = Entry::new("e1", "Site");
        e.password = "first-password".into();
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry: e.clone() },
        );
        e.password = "second-password".into();
        e.password_history = vec![]; // client may send empty
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry: e },
        );
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::GetEntry { id: "e1".into() },
        );
        match r {
            VaultResponse::Entry { entry } => {
                assert_eq!(entry.password, "second-password");
                assert_eq!(entry.password_history.len(), 1);
                assert_eq!(entry.password_history[0].password, "first-password");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn password_health_reports_issues() {
        let mut store = MemoryStore::default();
        let mut session = None;
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "test-pass-xx".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        let mut e = Entry::new("", "Weak");
        e.password = "password".into();
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry: e },
        );
        let r = dispatch(&mut store, &mut session, VaultRequest::PasswordHealth);
        match r {
            VaultResponse::Health { report } => {
                assert!(report.issue_count > 0);
                assert!(report.score < 100);
            }
            other => panic!("expected health, got {other:?}"),
        }
    }

    #[test]
    fn sync_now_uses_secret_store_fallback() {
        // Freenet path: dispatch() with no FileSyncTransport must still SyncNow.
        let mut store_a = MemoryStore::default();
        let mut session_a = None;
        dispatch(
            &mut store_a,
            &mut session_a,
            VaultRequest::CreateVault {
                passphrase: "sync-passphrase".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        let mut e = Entry::new("", "Synced");
        e.password = "from-a".into();
        dispatch(
            &mut store_a,
            &mut session_a,
            VaultRequest::UpsertEntry { entry: e },
        );

        let r = dispatch(&mut store_a, &mut session_a, VaultRequest::SyncNow);
        match &r {
            VaultResponse::Synced {
                action,
                remote_revisions,
                ..
            } => {
                assert!(
                    matches!(action.as_str(), "pushed" | "merged" | "up_to_date"),
                    "unexpected action {action}"
                );
                assert!(*remote_revisions >= 1);
            }
            other => panic!("expected Synced, got {other:?}"),
        }
        assert!(store_a.has(SECRET_SYNC_STATE));

        // Second "device": same MasterSecret via export/import, share sync blob.
        let export = match dispatch(
            &mut store_a,
            &mut session_a,
            VaultRequest::ExportEncrypted {
                passphrase: "sync-passphrase".into(),
            },
        ) {
            VaultResponse::Export { blob } => blob,
            other => panic!("export: {other:?}"),
        };

        let mut store_b = MemoryStore::default();
        let mut session_b = None;
        let r = dispatch(
            &mut store_b,
            &mut session_b,
            VaultRequest::ImportEncrypted {
                blob: export,
                passphrase: "sync-passphrase".into(),
            },
        );
        assert!(matches!(r, VaultResponse::Unlocked { .. }));

        // Hand B the encrypted MVR that A published into its secret store.
        store_b.set(
            SECRET_SYNC_STATE,
            &store_a.get(SECRET_SYNC_STATE).expect("sync state"),
        );

        // Clear B's entries so pull is observable (import already has them;
        // re-sync after local delete is harder — just assert SyncNow succeeds
        // and keeps the store key).
        let r = dispatch(&mut store_b, &mut session_b, VaultRequest::SyncNow);
        assert!(
            matches!(r, VaultResponse::Synced { .. }),
            "B SyncNow: {r:?}"
        );
        assert!(store_b.has(SECRET_SYNC_STATE));
    }


    #[test]
    fn summary_includes_feature_flags() {
        let mut store = MemoryStore::default();
        let mut session = None;
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "flags-test-pass".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        let mut e = Entry::new("", "Flagged");
        e.password = "secret".into();
        e.username = "bob".into();
        e.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        e.notes = "hello".into();
        e.urls.push("https://example.com".into());
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry: e },
        );
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::ListSummaries { query: None },
        );
        match r {
            VaultResponse::Summaries { entries } => {
                assert_eq!(entries.len(), 1);
                let s = &entries[0];
                assert!(s.has_password, "has_password");
                assert!(s.has_username, "has_username");
                assert!(s.has_totp, "has_totp");
                assert!(s.has_notes, "has_notes");
                assert!(s.has_url, "has_url");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn export_import_roundtrip() {
        let mut store = MemoryStore::default();
        let mut session = None;
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::CreateVault {
                passphrase: "alpha".into(),
                kdf_profile: KdfProfile::Test,
            },
        );
        let mut entry = Entry::new("", "Bank");
        entry.password = "pw".into();
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry },
        );

        let export = dispatch(
            &mut store,
            &mut session,
            VaultRequest::ExportEncrypted {
                passphrase: "alpha".into(),
            },
        );
        let blob = match export {
            VaultResponse::Export { blob } => blob,
            other => panic!("export failed: {other:?}"),
        };

        let mut store2 = MemoryStore::default();
        let mut session2 = None;
        let r = dispatch(
            &mut store2,
            &mut session2,
            VaultRequest::ImportEncrypted {
                blob,
                passphrase: "alpha".into(),
            },
        );
        assert!(matches!(r, VaultResponse::Unlocked { .. }));
        let r = dispatch(
            &mut store2,
            &mut session2,
            VaultRequest::ListSummaries { query: Some("bank".into()) },
        );
        match r {
            VaultResponse::Summaries { entries } => assert_eq!(entries.len(), 1),
            other => panic!("{other:?}"),
        }
    }
}
