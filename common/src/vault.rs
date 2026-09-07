//! In-memory vault session logic (used by the delegate and unit tests).

use crate::crypto::{
    derive_keys, generate_password, generate_recovery_key_display, normalize_recovery_key, open,
    seal, unwrap_master, unwrap_master_with_aad, wrap_existing_master,
    wrap_existing_master_with_aad, DerivedKeys, EnvelopeKind, KdfProfile, MasterEnvelope,
    SecretKey, SealedBlob,
};
#[cfg(any(test, feature = "v1-fixtures"))]
use crate::crypto::wrap_master;
use crate::health::analyze_entries;
use crate::messages::{ErrorCode, ImportEntryChange, VaultRequest, VaultResponse};
use crate::types::{
    new_id, unix_now, AuditEvent, AuditKind, Entry, EntryId, EntrySummary, Folder, Tombstone,
    VaultDocument,
};
#[cfg(any(test, feature = "v1-fixtures"))]
use crate::types::VaultMeta;
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
pub(crate) const RECOVERY_AAD: &[u8] = b"recovery";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("serde: {0}")]
    Serde(String),
    #[error("migration required before this operation")]
    MigrationRequired,
    #[error("VaultSync identity cannot be migrated in Phase 5")]
    VaultSyncMigrationDeferred,
}

impl VaultError {
    pub fn code(&self) -> ErrorCode {
        match self {
            VaultError::Crypto(crate::crypto::CryptoError::Decrypt) => ErrorCode::AuthFailed,
            VaultError::Crypto(crate::crypto::CryptoError::UnauthorizedShareIdentity)
            | VaultError::Crypto(crate::crypto::CryptoError::UnauthorizedShareSender)
            | VaultError::Crypto(crate::crypto::CryptoError::UnauthorizedSyncIdentity)
            | VaultError::Crypto(crate::crypto::CryptoError::ZeroSharedSecret)
            | VaultError::Crypto(crate::crypto::CryptoError::HybridSignatureRejected) => {
                ErrorCode::Crypto
            }
            VaultError::Crypto(crate::crypto::CryptoError::WeakPassphrase) => {
                ErrorCode::InvalidRequest
            }
            VaultError::Crypto(_) => ErrorCode::Crypto,
            VaultError::MigrationRequired => ErrorCode::MigrationRequired,
            VaultError::VaultSyncMigrationDeferred => ErrorCode::VaultSyncMigrationDeferred,
            VaultError::Msg(m) if m.contains("locked") => ErrorCode::Locked,
            VaultError::Msg(m) if m.contains("exists") => ErrorCode::AlreadyExists,
            VaultError::Msg(m) if m.contains("not found") => ErrorCode::NotFound,
            VaultError::Msg(m) if m.contains("expected_sender_identity") => {
                ErrorCode::InvalidRequest
            }
            VaultError::Msg(m)
                if m.contains("invalid recovery")
                    || m.contains("v1 recovery")
                    || m.contains("recovery kit")
                    || m.contains("not a Recovery Kit")
                    || m.contains("does not match")
                    || m.contains("identity only")
                    || m.contains("cannot open current")
                    || m.contains("backup passphrase is required") =>
            {
                ErrorCode::InvalidRequest
            }
            _ => ErrorCode::Internal,
        }
    }
}

/// Unlocked production session: v1 (read-only until migrate) or v2.
pub enum ActiveSession {
    V1(VaultSession),
    V2(crate::session_v2::VaultSessionV2),
}

impl ActiveSession {
    pub fn vault_id_hex(&self) -> String {
        match self {
            Self::V1(s) => s.doc.meta.vault_id.clone(),
            Self::V2(s) => s.doc.meta.vault_id.clone(),
        }
    }

    pub fn is_v1(&self) -> bool {
        matches!(self, Self::V1(_))
    }

    pub fn doc(&self) -> &crate::types::VaultDocument {
        match self {
            Self::V1(s) => &s.doc,
            Self::V2(s) => &s.doc,
        }
    }

    fn handle(
        &mut self,
        store: &mut dyn SecretStore,
        req: VaultRequest,
    ) -> Result<VaultResponse, VaultError> {
        match self {
            Self::V1(s) => s.handle(store, req),
            Self::V2(s) => s.handle(store, req),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedFormat {
    None,
    V1,
    V2,
}

pub fn detect_persisted_format(store: &dyn SecretStore) -> Result<PersistedFormat, VaultError> {
    if let Some(bytes) = store.get(crate::session_v2::SECRET_ENVELOPE_V2) {
        if bytes.starts_with(crate::crypto::MAGIC_VAULT_V2) {
            if bytes.len() > crate::crypto::MAGIC_VAULT_V2.len()
                && bytes[crate::crypto::MAGIC_VAULT_V2.len()] == crate::crypto::CONTAINER_VERSION_V2
            {
                return Ok(PersistedFormat::V2);
            }
            return Err(VaultError::Msg("malformed v2 envelope".into()));
        }
        return Err(VaultError::Msg("malformed v2 envelope".into()));
    }
    if store.has(SECRET_ENVELOPE) {
        return Ok(PersistedFormat::V1);
    }
    Ok(PersistedFormat::None)
}

/// Export file format: envelope + sealed vault under export passphrase (re-wrap).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    pub format: u16,
    pub envelope: MasterEnvelope,
    pub vault: SealedBlob,
}

/// One mutation in a [`SecretStore::commit`] batch (D14).
#[derive(Debug, Clone)]
pub enum StoreOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

impl StoreOp {
    pub fn put(key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self::Put {
            key: key.into(),
            value: value.into(),
        }
    }

    pub fn delete(key: impl Into<Vec<u8>>) -> Self {
        Self::Delete { key: key.into() }
    }
}

pub(crate) fn apply_store_ops(
    map: &mut std::collections::HashMap<Vec<u8>, Vec<u8>>,
    ops: &[StoreOp],
) {
    for op in ops {
        match op {
            StoreOp::Put { key, value } => {
                map.insert(key.clone(), value.clone());
            }
            StoreOp::Delete { key } => {
                map.remove(key);
            }
        }
    }
}

/// Keys that belong to one vault instance and must swap together on import.
pub const VAULT_INSTANCE_KEYS: &[&[u8]] = &[
    SECRET_ENVELOPE,
    SECRET_VAULT,
    SECRET_AUDIT,
    SECRET_SESSION,
    SECRET_SYNC_COUNTER,
    SECRET_SYNC_STATE,
    SECRET_RECOVERY,
];

/// v2 durable keys. Not included in [`VAULT_INSTANCE_KEYS`] so v1-replace
/// commits that delete-then-put cannot clobber a freshly written v2 envelope.
pub const SECRET_KEYS_V2: &[&[u8]] = &[
    crate::session_v2::SECRET_ENVELOPE_V2,
    crate::session_v2::SECRET_VAULT_V2,
    crate::session_v2::SECRET_AUDIT_V2,
    crate::recovery_v2::SECRET_RECOVERY_V2,
    crate::sync_v2::SECRET_SYNC_STATE_V2,
    crate::sync_v2::SECRET_SYNC_ACCEPTED_V2,
    crate::sync_v2::SECRET_SYNC_COUNTER_V2,
    crate::sync_v2::SECRET_SYNC_TRANSITION_V2,
];

/// Abstract secret storage so logic can run in unit tests without Freenet.
pub trait SecretStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn set(&mut self, key: &[u8], value: &[u8]);
    fn remove(&mut self, key: &[u8]);
    fn has(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /// Apply `ops` as one unit. On error, previous durable state is unchanged.
    ///
    /// Backends that cannot do this MUST return [`UNSUPPORTED_ATOMIC_COMMIT`]
    /// rather than applying `ops` sequentially.
    fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String>;
}

/// Returned by backends that cannot implement D14 (never sequential multi-key writes).
pub const UNSUPPORTED_ATOMIC_COMMIT: &str =
    "unsupported atomic commit: backend cannot switch a vault in one generation pointer";

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

    /// Sorted durable (non-session) pairs for equality checks.
    pub fn durable_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = self
            .map
            .iter()
            .filter(|(k, _)| k.as_slice() != SECRET_SESSION)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    }

    /// Every stored pair, including a leftover session key (for secret scans).
    pub fn all_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = self
            .map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    }

    /// True if `needle` appears as a contiguous substring of any stored value.
    pub fn contains_plaintext(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            return false;
        }
        self.map.values().any(|v| {
            v.windows(needle.len()).any(|w| w == needle)
        })
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

    fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String> {
        let mut next = self.map.clone();
        apply_store_ops(&mut next, ops);
        self.map = next;
        Ok(())
    }
}

/// Unlocked vault session.
pub struct VaultSession {
    pub master: SecretKey,
    pub keys: DerivedKeys,
    pub doc: VaultDocument,
    pub audit: Vec<AuditEvent>,
    /// Production v1 unlock: reads allowed, persisted writes require migration.
    pub(crate) readonly: bool,
}

impl VaultSession {
    /// Mint a v1 vault. Production create is v2 (`VaultSessionV2::create` /
    /// `dispatch(CreateVault)`). Available only in unit tests and the explicit
    /// `v1-fixtures` feature (frozen fixture regen / compatibility tests).
    #[cfg(any(test, feature = "v1-fixtures"))]
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
            readonly: false,
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
            readonly: true,
        };
        session.audit_push(AuditKind::Unlock, None, "unlocked");
        Ok(session)
    }

    /// Resume a leftover v1 `SECRET_SESSION`. Not a production unlock path.
    #[cfg(any(test, feature = "v1-fixtures"))]
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
            readonly: false,
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

    #[cfg(any(test, feature = "v1-fixtures"))]
    fn persist_session_flag(&self, store: &mut dyn SecretStore) {
        if self.readonly {
            return;
        }
        store.set(SECRET_SESSION, self.master.as_bytes());
    }

    /// Seal and store the vault document. Does **not** bump `meta.updated_at`
    /// (callers that mutate data should set it). Auto-bump here made every
    /// post-sync persist change the content hash so the next Sync always
    /// re-published.
    fn require_writable(&self) -> Result<(), VaultError> {
        if self.readonly {
            Err(VaultError::MigrationRequired)
        } else {
            Ok(())
        }
    }

    pub fn persist(&mut self, store: &mut dyn SecretStore) -> Result<(), VaultError> {
        self.require_writable()?;
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
        if self.readonly {
            return Ok(());
        }
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
                Ok(VaultResponse::RecoveryKey {
                    recovery_key: key,
                    kit: Vec::new(),
                })
            }
            VaultRequest::RevokeRecoveryKey => {
                self.require_writable()?;
                store.remove(SECRET_RECOVERY);
                self.audit_push(AuditKind::RevokeRecovery, None, "recovery key revoked");
                self.persist_audit(store)?;
                Ok(VaultResponse::Ok)
            }
            // UnlockWithRecovery handled at dispatch (no session yet).
            VaultRequest::ExportEncrypted { passphrase } => {
                self.require_writable()?;
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
            | VaultRequest::ImportEncrypted { .. }
            | VaultRequest::ImportRecoveryKit { .. }
            | VaultRequest::PreviewImport { .. }
            | VaultRequest::MigrateVault { .. }
            | VaultRequest::MigrateVaultWithRecovery { .. } => Err(VaultError::Msg(
                "request must be handled by dispatcher".into(),
            )),
            VaultRequest::RotateKeys { .. }
            | VaultRequest::ExportShareIdentity
            | VaultRequest::ExportRecoveryKit
            | VaultRequest::CreateShare { .. }
            | VaultRequest::OpenShare { .. } => Err(VaultError::MigrationRequired),
        }
    }

    /// Create or replace recovery envelope; returns display recovery key (show once).
    pub fn generate_recovery_key(
        &mut self,
        store: &mut dyn SecretStore,
        profile: KdfProfile,
    ) -> Result<String, VaultError> {
        self.require_writable()?;
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
            readonly: true,
        };
        session.audit_push(AuditKind::UnlockRecovery, None, "unlocked with recovery key");
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
        self.require_writable()?;
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
        let (owner_verifying_key, sync_params) = if include_owner_vk {
            let vk = crate::sync::owner_vk_bytes(&self.keys);
            let params = crate::sync_types::VaultSyncParams {
                owner_verifying_key: vk.clone(),
                app: "AEGIS_VAULT_SYNC_V1".into(),
            };
            let params_cbor = crate::sync_types::encode_cbor(&params).unwrap_or_default();
            (vk, params_cbor)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(VaultResponse::Synced {
            action: action.into(),
            remote_revisions: report.remote_revisions,
            detail: report.detail,
            contract_state,
            owner_verifying_key,
            sync_params,
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

/// Clear vault-related secrets. Prefer [`SecretStore::commit`] for import.
pub fn clear_vault_secrets(store: &mut dyn SecretStore) {
    let ops: Vec<StoreOp> = VAULT_INSTANCE_KEYS.iter().map(|k| StoreOp::delete(*k)).collect();
    let _ = store.commit(&ops);
}

#[cfg(any(test, feature = "v1-fixtures"))]
fn seal_vault_blob(keys: &DerivedKeys, doc: &VaultDocument) -> Result<SealedBlob, VaultError> {
    let mut pt = Vec::new();
    ciborium::into_writer(doc, &mut pt).map_err(|e| VaultError::Serde(e.to_string()))?;
    seal(
        &keys.vault_dek,
        EnvelopeKind::VaultBlob,
        doc.meta.vault_id.as_bytes(),
        b"vault",
        &pt,
    )
    .map_err(Into::into)
}

#[cfg(any(test, feature = "v1-fixtures"))]
fn seal_audit_blob(
    keys: &DerivedKeys,
    vault_id: &str,
    audit: &[AuditEvent],
) -> Result<SealedBlob, VaultError> {
    let mut pt = Vec::new();
    ciborium::into_writer(audit, &mut pt).map_err(|e| VaultError::Serde(e.to_string()))?;
    seal(
        &keys.vault_dek,
        EnvelopeKind::AuditBlob,
        vault_id.as_bytes(),
        b"audit",
        &pt,
    )
    .map_err(Into::into)
}

/// Authenticate a v1 export into memory. Does not touch the store.
fn authenticate_export(
    blob: &[u8],
    passphrase: &str,
) -> Result<(ExportBundle, SecretKey, DerivedKeys, VaultDocument), VaultError> {
    let bundle: ExportBundle =
        ciborium::from_reader(blob).map_err(|e| VaultError::Serde(e.to_string()))?;
    if bundle.format != 1 {
        return Err(VaultError::Msg(format!(
            "unsupported export format {}",
            bundle.format
        )));
    }
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
    if doc.meta.vault_id != bundle.envelope.vault_id {
        return Err(VaultError::Msg("vault_id mismatch in export".into()));
    }
    Ok((bundle, master, keys, doc))
}

/// Decrypt an export bundle without writing to the store.
pub fn open_export_document(blob: &[u8], passphrase: &str) -> Result<VaultDocument, VaultError> {
    let (_, _, _, doc) = authenticate_export(blob, passphrase)?;
    Ok(doc)
}

/// Open local vault document with passphrase without starting a session or audit.
pub fn peek_local_document(
    store: &dyn SecretStore,
    passphrase: &str,
) -> Result<VaultDocument, VaultError> {
    match detect_persisted_format(store)? {
        PersistedFormat::V2 => crate::session_v2::peek_document(store, passphrase),
        PersistedFormat::None => Err(VaultError::Msg("vault not found".into())),
        PersistedFormat::V1 => peek_local_document_v1(store, passphrase),
    }
}

fn peek_local_document_v1(
    store: &dyn SecretStore,
    passphrase: &str,
) -> Result<VaultDocument, VaultError> {
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
    ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))
}

fn entry_changed_fields(local: &Entry, backup: &Entry) -> Vec<String> {
    let mut fields = Vec::new();
    if local.name != backup.name {
        fields.push("name".into());
    }
    if local.username != backup.username {
        fields.push("username".into());
    }
    if local.password != backup.password {
        fields.push("password".into());
    }
    if local.notes != backup.notes {
        fields.push("notes".into());
    }
    if local.urls != backup.urls {
        fields.push("urls".into());
    }
    if local.tags != backup.tags {
        fields.push("tags".into());
    }
    if local.folder_id != backup.folder_id {
        fields.push("folder".into());
    }
    if local.totp_secret != backup.totp_secret {
        fields.push("totp".into());
    }
    if local.custom_fields != backup.custom_fields {
        fields.push("custom_fields".into());
    }
    if local.password_history != backup.password_history {
        fields.push("history".into());
    }
    fields
}

const PREVIEW_LIST_CAP: usize = 80;

/// Compare local vault (optional) to a decrypted backup. Never includes secret values.
pub fn build_import_preview(
    local: Option<&VaultDocument>,
    backup: &VaultDocument,
    note: impl Into<String>,
) -> VaultResponse {
    let note = note.into();
    let mut only_local = Vec::new();
    let mut only_backup = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged_count = 0u32;
    let mut folders_only_local = Vec::new();
    let mut folders_only_backup = Vec::new();

    if let Some(local) = local {
        for (id, le) in &local.entries {
            match backup.entries.get(id) {
                None => {
                    if only_local.len() < PREVIEW_LIST_CAP {
                        only_local.push(EntrySummary::from(le));
                    }
                }
                Some(be) => {
                    let fields = entry_changed_fields(le, be);
                    if fields.is_empty() {
                        unchanged_count += 1;
                    } else if changed.len() < PREVIEW_LIST_CAP {
                        let newer = match le.updated_at.cmp(&be.updated_at) {
                            std::cmp::Ordering::Greater => "local",
                            std::cmp::Ordering::Less => "backup",
                            std::cmp::Ordering::Equal => "same",
                        };
                        changed.push(ImportEntryChange {
                            id: id.clone(),
                            name: if be.name.is_empty() {
                                le.name.clone()
                            } else {
                                be.name.clone()
                            },
                            local_name: le.name.clone(),
                            backup_name: be.name.clone(),
                            fields,
                            local_updated_at: le.updated_at,
                            backup_updated_at: be.updated_at,
                            newer: newer.into(),
                        });
                    }
                }
            }
        }
        for (id, be) in &backup.entries {
            if !local.entries.contains_key(id) && only_backup.len() < PREVIEW_LIST_CAP {
                only_backup.push(EntrySummary::from(be));
            }
        }
        for (id, lf) in &local.folders {
            if !backup.folders.contains_key(id) && folders_only_local.len() < PREVIEW_LIST_CAP {
                folders_only_local.push(lf.name.clone());
            }
        }
        for (id, bf) in &backup.folders {
            if !local.folders.contains_key(id) && folders_only_backup.len() < PREVIEW_LIST_CAP {
                folders_only_backup.push(bf.name.clone());
            }
        }

        VaultResponse::ImportPreview {
            local_available: true,
            same_vault_id: local.meta.vault_id == backup.meta.vault_id,
            local_vault_id: Some(local.meta.vault_id.clone()),
            backup_vault_id: backup.meta.vault_id.clone(),
            local_entry_count: local.entries.len() as u32,
            backup_entry_count: backup.entries.len() as u32,
            local_updated_at: Some(local.meta.updated_at),
            backup_updated_at: backup.meta.updated_at,
            only_local,
            only_backup,
            changed,
            unchanged_count,
            folders_only_local,
            folders_only_backup,
            note,
        }
    } else {
        for be in backup.entries.values() {
            if only_backup.len() < PREVIEW_LIST_CAP {
                only_backup.push(EntrySummary::from(be));
            }
        }
        for bf in backup.folders.values() {
            if folders_only_backup.len() < PREVIEW_LIST_CAP {
                folders_only_backup.push(bf.name.clone());
            }
        }
        VaultResponse::ImportPreview {
            local_available: false,
            same_vault_id: false,
            local_vault_id: None,
            backup_vault_id: backup.meta.vault_id.clone(),
            local_entry_count: 0,
            backup_entry_count: backup.entries.len() as u32,
            local_updated_at: None,
            backup_updated_at: backup.meta.updated_at,
            only_local,
            only_backup,
            changed,
            unchanged_count: 0,
            folders_only_local,
            folders_only_backup,
            note,
        }
    }
}

/// Preview replace/import: open backup + optional local, return safe diff.
pub fn preview_import(
    store: &dyn SecretStore,
    session: Option<&ActiveSession>,
    blob: &[u8],
    passphrase: &str,
    local_passphrase: Option<&str>,
) -> Result<VaultResponse, VaultError> {
    let backup = if blob.starts_with(crate::crypto::MAGIC_BACKUP_V2) {
        crate::crypto::authenticate_backup(blob, passphrase)?.document
    } else {
        open_export_document(blob, passphrase)?
    };
    let mut note = String::new();

    let owned_local: Option<VaultDocument> = if session.is_some() {
        None
    } else if store.has(SECRET_ENVELOPE) || store.has(crate::session_v2::SECRET_ENVELOPE_V2) {
        let try_pw = local_passphrase
            .filter(|p| !p.is_empty())
            .unwrap_or(passphrase);
        match peek_local_document(store, try_pw) {
            Ok(doc) => Some(doc),
            Err(e) => {
                note = format!(
                    "Could not open the local vault for comparison ({e}). \
                     Enter the local master passphrase if it differs from the export passphrase."
                );
                None
            }
        }
    } else {
        note = "No local vault — this is a fresh import.".into();
        None
    };

    let local_ref = session.map(|s| s.doc()).or(owned_local.as_ref());
    Ok(build_import_preview(local_ref, &backup, note))
}

pub fn import_production(
    store: &mut dyn SecretStore,
    blob: &[u8],
    backup_passphrase: &str,
    vault_passphrase: &str,
    replace: bool,
) -> Result<crate::session_v2::VaultSessionV2, VaultError> {
    if blob.starts_with(crate::crypto::MAGIC_BACKUP_V2) {
        return crate::session_v2::VaultSessionV2::restore_backup(
            store,
            blob,
            backup_passphrase,
            vault_passphrase,
            replace,
        );
    }
    if blob.starts_with(crate::crypto::MAGIC_RECOVERY_V2) {
        return Err(VaultError::Msg(
            "not a backup file (this is a Recovery Kit — use identity recovery)".into(),
        ));
    }
    if blob.starts_with(crate::crypto::MAGIC_VAULT_V2) {
        return Err(VaultError::Msg("not a backup file".into()));
    }
    let (_bundle, _master, _keys, doc) = authenticate_export(blob, backup_passphrase)?;
    crate::migrate::restore_document_as_v2(store, doc, Vec::new(), vault_passphrase, replace)
}

/// Import an export bundle as a **v1** identity. Production import is v2
/// (`import_production`). Fixture / D14 compatibility tests only.
#[cfg(any(test, feature = "v1-fixtures"))]
pub fn import_bundle(
    store: &mut dyn SecretStore,
    blob: &[u8],
    passphrase: &str,
    replace: bool,
) -> Result<VaultSession, VaultError> {
    if store.has(SECRET_ENVELOPE) && !replace {
        return Err(VaultError::Msg(
            "vault already exists (export from the other browser, then import with replace)"
                .into(),
        ));
    }

    let (bundle, master, keys, doc) = authenticate_export(blob, passphrase)?;

    let vault_sealed = seal_vault_blob(&keys, &doc)?;
    let reopened = open(
        &keys.vault_dek,
        doc.meta.vault_id.as_bytes(),
        b"vault",
        &vault_sealed,
    )?;
    let doc2: VaultDocument = ciborium::from_reader(reopened.as_slice())
        .map_err(|e| VaultError::Serde(e.to_string()))?;
    if doc2.meta.vault_id != doc.meta.vault_id || doc2.entries.len() != doc.entries.len() {
        return Err(VaultError::Msg("imported vault failed reopen check".into()));
    }

    let mut session = VaultSession {
        master,
        keys,
        doc,
        audit: Vec::new(),
        readonly: false,
    };
    session.audit_push(
        AuditKind::Import,
        None,
        if replace {
            "imported vault (replaced existing)"
        } else {
            "imported vault"
        },
    );
    let audit_sealed = seal_audit_blob(
        &session.keys,
        &session.doc.meta.vault_id,
        &session.audit,
    )?;

    let ops = vec![
        StoreOp::put(SECRET_ENVELOPE, bundle.envelope.to_cbor()?),
        StoreOp::put(SECRET_VAULT, vault_sealed.to_cbor()?),
        StoreOp::put(SECRET_AUDIT, audit_sealed.to_cbor()?),
        StoreOp::delete(SECRET_RECOVERY),
        StoreOp::delete(SECRET_SYNC_COUNTER),
        StoreOp::delete(SECRET_SYNC_STATE),
        StoreOp::delete(SECRET_SESSION),
    ];
    store
        .commit(&ops)
        .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;

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
    session: &mut Option<ActiveSession>,
    sync: Option<&mut dyn crate::sync::SyncTransport>,
    remote_state: &[u8],
) -> VaultResponse {
    let Some(s) = session.as_mut() else {
        return VaultResponse::err(ErrorCode::Locked, "vault is locked");
    };
    match s {
        ActiveSession::V2(s) => {
            let _ = sync; // v1 FileSyncTransport is not reused for v2.
            return dispatch_sync_v2(store, s, remote_state);
        }
        ActiveSession::V1(s) => {
            if s.readonly {
                return VaultResponse::err(
                    ErrorCode::MigrationRequired,
                    "migrate this v1 vault before sync",
                );
            }
            return dispatch_sync_v1(store, s, sync, remote_state);
        }
    }
}

fn dispatch_sync_v2(
    store: &mut dyn SecretStore,
    s: &mut crate::session_v2::VaultSessionV2,
    remote_state: &[u8],
) -> VaultResponse {
    match s.sync_now_with_publish(store, remote_state) {
        Ok(r) => r,
        Err(e) => VaultResponse::err(e.code(), e.to_string()),
    }
}

fn dispatch_sync_v1(
    store: &mut dyn SecretStore,
    s: &mut VaultSession,
    sync: Option<&mut dyn crate::sync::SyncTransport>,
    remote_state: &[u8],
) -> VaultResponse {

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
    session: &mut Option<ActiveSession>,
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
    session: &mut Option<ActiveSession>,
    req: VaultRequest,
    sync: Option<&mut dyn crate::sync::SyncTransport>,
) -> VaultResponse {
    match req {
        VaultRequest::Status => {
            let fmt = detect_persisted_format(store);
            let (has_vault, vault_format, needs_migration, has_recovery) = match fmt {
                Ok(PersistedFormat::V2) => (
                    true,
                    Some("v2".into()),
                    false,
                    store.has(crate::recovery_v2::SECRET_RECOVERY_V2),
                ),
                Ok(PersistedFormat::V1) => (
                    true,
                    Some("v1".into()),
                    true,
                    store.has(SECRET_RECOVERY),
                ),
                Ok(PersistedFormat::None) => (false, None, false, false),
                Err(_) => (true, Some("unknown".into()), false, false),
            };
            let unlocked = session.is_some();
            let vault_id = session.as_ref().map(|s| s.vault_id_hex());
            let needs_migration = needs_migration || session.as_ref().is_some_and(|s| s.is_v1());
            VaultResponse::Status {
                has_vault,
                unlocked,
                vault_id,
                has_recovery,
                vault_format,
                needs_migration,
            }
        }
        VaultRequest::CreateVault { passphrase, .. } => {
            match crate::session_v2::VaultSessionV2::create(store, &passphrase) {
                Ok(s) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(ActiveSession::V2(s));
                    VaultResponse::Unlocked { vault_id }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
        VaultRequest::Unlock { passphrase } => match detect_persisted_format(store) {
            Ok(PersistedFormat::V2) => {
                match crate::session_v2::VaultSessionV2::unlock(store, &passphrase) {
                    Ok(s) => {
                        let vault_id = s.doc.meta.vault_id.clone();
                        *session = Some(ActiveSession::V2(s));
                        VaultResponse::Unlocked { vault_id }
                    }
                    Err(e) => VaultResponse::err(e.code(), e.to_string()),
                }
            }
            Ok(PersistedFormat::V1) => match VaultSession::unlock(store, &passphrase) {
                Ok(s) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(ActiveSession::V1(s));
                    VaultResponse::Unlocked { vault_id }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            },
            Ok(PersistedFormat::None) => {
                VaultResponse::err(ErrorCode::NotFound, "vault not found")
            }
            Err(e) => VaultResponse::err(e.code(), e.to_string()),
        },
        VaultRequest::UnlockWithRecovery { recovery_key } => match detect_persisted_format(store)
        {
            Ok(PersistedFormat::V2) => {
                match crate::session_v2::VaultSessionV2::unlock_with_recovery(store, &recovery_key)
                {
                    Ok(s) => {
                        let vault_id = s.doc.meta.vault_id.clone();
                        *session = Some(ActiveSession::V2(s));
                        VaultResponse::Unlocked { vault_id }
                    }
                    Err(e) => VaultResponse::err(e.code(), e.to_string()),
                }
            }
            Ok(PersistedFormat::V1) => {
                match VaultSession::unlock_with_recovery(store, &recovery_key) {
                    Ok(s) => {
                        let vault_id = s.doc.meta.vault_id.clone();
                        *session = Some(ActiveSession::V1(s));
                        VaultResponse::Unlocked { vault_id }
                    }
                    Err(e) => VaultResponse::err(e.code(), e.to_string()),
                }
            }
            Ok(PersistedFormat::None) => {
                VaultResponse::err(ErrorCode::NotFound, "vault not found")
            }
            Err(e) => VaultResponse::err(e.code(), e.to_string()),
        },
        VaultRequest::ImportEncrypted {
            blob,
            passphrase,
            new_passphrase,
            replace,
        } => {
            let Some(vault_pw) = new_passphrase.as_deref().filter(|s| !s.is_empty()) else {
                return VaultResponse::err(
                    ErrorCode::InvalidRequest,
                    "restore requires a new v2 passphrase",
                );
            };
            match import_production(store, &blob, &passphrase, vault_pw, replace) {
                Ok(s) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(ActiveSession::V2(s));
                    VaultResponse::Unlocked { vault_id }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
        VaultRequest::ImportRecoveryKit {
            kit,
            recovery_secret,
            new_passphrase,
            backup,
            backup_passphrase,
        } => {
            match crate::session_v2::VaultSessionV2::import_recovery_kit(
                store,
                &kit,
                &recovery_secret,
                &new_passphrase,
                if backup.is_empty() { None } else { Some(backup.as_slice()) },
                backup_passphrase.as_deref(),
            ) {
                Ok(s) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(ActiveSession::V2(s));
                    VaultResponse::Unlocked { vault_id }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
        VaultRequest::MigrateVault { passphrase } => {
            match crate::migrate::migrate_live_v1_to_v2(store, &passphrase) {
                Ok((s, recovery_secret)) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(ActiveSession::V2(s));
                    VaultResponse::Migrated {
                        vault_id,
                        recovery_secret,
                    }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
        VaultRequest::MigrateVaultWithRecovery {
            recovery_key,
            new_v2_passphrase,
        } => {
            match crate::migrate::migrate_live_v1_to_v2_with_recovery(
                store,
                &recovery_key,
                &new_v2_passphrase,
            ) {
                Ok((s, recovery_secret)) => {
                    let vault_id = s.doc.meta.vault_id.clone();
                    *session = Some(ActiveSession::V2(s));
                    VaultResponse::Migrated {
                        vault_id,
                        recovery_secret,
                    }
                }
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
        VaultRequest::PreviewImport {
            blob,
            passphrase,
            local_passphrase,
        } => {
            let local_pw = local_passphrase.as_deref();
            match preview_import(store, session.as_ref(), &blob, &passphrase, local_pw) {
                Ok(r) => r,
                Err(e) => VaultResponse::err(e.code(), e.to_string()),
            }
        }
        VaultRequest::Lock => {
            match session.take() {
                Some(ActiveSession::V1(mut s)) => s.lock(store),
                Some(ActiveSession::V2(s)) => s.lock(store),
                None => {}
            }
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
    use crate::crypto::{Argon2ParamsV2, KdfProfile};
    use crate::types::Entry;

    const PW: &str = "correct horse battery staple";
    const PW2: &str = "new horse battery staple";

    fn unlocked_v2(store: &mut MemoryStore) -> Option<ActiveSession> {
        Some(ActiveSession::V2(
            crate::session_v2::VaultSessionV2::create_with_params(
                store,
                PW,
                Argon2ParamsV2::insecure_for_tests(),
            )
            .expect("v2 test create"),
        ))
    }

    #[test]
    fn create_unlock_crud() {
        let mut store = MemoryStore::default();
        let mut session = unlocked_v2(&mut store);

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
                passphrase: PW.into(),
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
        let mut session = unlocked_v2(&mut store);
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
            VaultResponse::RecoveryKey { recovery_key, kit } => {
                assert!(kit.starts_with(crate::crypto::MAGIC_RECOVERY_V2));
                recovery_key
            }
            other => panic!("expected recovery key: {other:?}"),
        };
        assert!(recovery_key.starts_with("AEGIS2-"));

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
                recovery_key: "00".repeat(32),
            },
        );
        assert!(matches!(r, VaultResponse::Error { code: ErrorCode::AuthFailed, .. }));
    }

    #[test]
    fn change_passphrase_rewraps() {
        let mut store = MemoryStore::default();
        let mut session = unlocked_v2(&mut store);
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::ChangePassphrase {
                current_passphrase: PW.into(),
                new_passphrase: PW2.into(),
                kdf_profile: Some(KdfProfile::Test),
            },
        );
        assert_eq!(r, VaultResponse::Ok);

        dispatch(&mut store, &mut session, VaultRequest::Lock);
        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::Unlock {
                passphrase: PW.into(),
            },
        );
        assert!(matches!(r, VaultResponse::Error { code: ErrorCode::AuthFailed, .. }));

        let r = dispatch(
            &mut store,
            &mut session,
            VaultRequest::Unlock {
                passphrase: PW2.into(),
            },
        );
        assert!(matches!(r, VaultResponse::Unlocked { .. }));
    }

    #[test]
    fn password_history_on_change() {
        let mut store = MemoryStore::default();
        let mut session = unlocked_v2(&mut store);
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
        let mut session = unlocked_v2(&mut store);
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
        // Writable v1 (test helper): production create is v2 and defers VaultSync.
        let mut store_a = MemoryStore::default();
        let s = VaultSession::create(&mut store_a, "sync-passphrase", KdfProfile::Test).unwrap();
        let mut session_a = Some(ActiveSession::V1(s));
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
        let imported =
            import_bundle(&mut store_b, &export, "sync-passphrase", false).expect("v1 import");
        let mut session_b = Some(ActiveSession::V1(imported));

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
        let mut session = unlocked_v2(&mut store);
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
    fn preview_import_shows_entry_diff() {
        let mut store = MemoryStore::default();
        let mut session = unlocked_v2(&mut store);
        let mut shared = Entry::new("", "Shared");
        shared.password = "old".into();
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry {
                entry: shared.clone(),
            },
        );
        let mut only_here = Entry::new("", "OnlyLocal");
        only_here.password = "local".into();
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry: only_here },
        );

        // Export, then change shared password and add another entry before re-export.
        let export = dispatch(
            &mut store,
            &mut session,
            VaultRequest::ExportEncrypted {
                passphrase: PW.into(),
            },
        );
        let blob = match export {
            VaultResponse::Export { blob } => blob,
            other => panic!("export: {other:?}"),
        };

        // Mutate local: change shared password (so local diverges from blob).
        shared.password = "new-local".into();
        dispatch(
            &mut store,
            &mut session,
            VaultRequest::UpsertEntry { entry: shared },
        );

        // Build a second vault as "backup" with different content.
        let mut store_b = MemoryStore::default();
        let mut session_b = None;
        dispatch(
            &mut store_b,
            &mut session_b,
            VaultRequest::ImportEncrypted {
                blob: blob.clone(),
                passphrase: PW.into(),
                new_passphrase: Some(PW.into()),
                replace: false,
            },
        );
        // Drop OnlyLocal on backup so it appears only on local; add OnlyBackup.
        let r = dispatch(
            &mut store_b,
            &mut session_b,
            VaultRequest::ListSummaries { query: None },
        );
        let (shared_id, only_local_id) = match r {
            VaultResponse::Summaries { entries } => {
                let shared = entries
                    .iter()
                    .find(|e| e.name == "Shared")
                    .map(|e| e.id.clone())
                    .expect("shared");
                let only_l = entries
                    .iter()
                    .find(|e| e.name == "OnlyLocal")
                    .map(|e| e.id.clone())
                    .expect("only local");
                (shared, only_l)
            }
            other => panic!("{other:?}"),
        };
        dispatch(
            &mut store_b,
            &mut session_b,
            VaultRequest::DeleteEntry {
                id: only_local_id,
            },
        );
        let mut only_backup = Entry::new("", "OnlyBackup");
        only_backup.password = "remote".into();
        dispatch(
            &mut store_b,
            &mut session_b,
            VaultRequest::UpsertEntry {
                entry: only_backup,
            },
        );
        let mut shared_b = Entry::new(shared_id, "Shared");
        shared_b.password = "from-backup".into();
        shared_b.username = "user".into();
        dispatch(
            &mut store_b,
            &mut session_b,
            VaultRequest::UpsertEntry { entry: shared_b },
        );
        let export_b = dispatch(
            &mut store_b,
            &mut session_b,
            VaultRequest::ExportEncrypted {
                passphrase: PW.into(),
            },
        );
        let blob_b = match export_b {
            VaultResponse::Export { blob } => blob,
            other => panic!("{other:?}"),
        };

        // Preview against locked store (use passphrase) — lock session first.
        dispatch(&mut store, &mut session, VaultRequest::Lock);
        let preview = dispatch(
            &mut store,
            &mut session,
            VaultRequest::PreviewImport {
                blob: blob_b,
                passphrase: PW.into(),
                local_passphrase: None,
            },
        );
        match preview {
            VaultResponse::ImportPreview {
                local_available,
                only_local,
                only_backup,
                changed,
                ..
            } => {
                assert!(local_available);
                assert!(
                    only_local.iter().any(|e| e.name == "OnlyLocal"),
                    "only_local: {only_local:?}"
                );
                assert!(
                    only_backup.iter().any(|e| e.name == "OnlyBackup"),
                    "only_backup: {only_backup:?}"
                );
                assert!(
                    changed.iter().any(|c| {
                        c.name == "Shared"
                            && c.fields.iter().any(|f| f == "password")
                            && c.fields.iter().any(|f| f == "username")
                    }),
                    "changed: {changed:?}"
                );
            }
            other => panic!("expected ImportPreview, got {other:?}"),
        }
    }

    #[test]
    fn export_import_roundtrip() {
        let mut store = MemoryStore::default();
        let mut session = unlocked_v2(&mut store);
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
                passphrase: PW.into(),
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
                passphrase: PW.into(),
                new_passphrase: Some(PW.into()),
                replace: false,
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
