//! v2 unlocked session: RootSecret is memory-only. Not wired into `VaultSession::create`.

use crate::crypto::backup::{authenticate_backup, create_backup_with_params};
use crate::crypto::envelope_v2::{
    open_audit_v2, open_vault_v2, seal_audit_v2, seal_vault_v2, unwrap_root_v2, wrap_root_v2,
    AuditBlobV2, MasterEnvelopeV2, VaultBlobV2,
};
use crate::crypto::hybrid_sign::HybridSyncSigner;
#[cfg(not(test))]
use crate::crypto::envelope_v2::wrap_existing_root_v2;
use crate::crypto::hkdf_v2::derive_operational_keys;
use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::passphrase::validate_v2_passphrase;
use crate::crypto::secret::{OperationalKeys, RootSecret};
use crate::crypto::suite::KEY_EPOCH_INITIAL;
use crate::crypto::generate_password;
use crate::health::analyze_entries;
use crate::messages::{VaultRequest, VaultResponse};
use crate::recovery_v2::{
    decode_recovery_secret, encode_recovery_secret, unwrap_recovery, validate_candidate_recovery,
    wrap_recovery, wrap_recovery_with_secret, RecoveryWrapV2, SECRET_RECOVERY_V2,
};
use crate::types::{
    new_id, unix_now, AuditEvent, AuditKind, EntrySummary, Folder, Tombstone, VaultDocument,
    VaultMeta,
};
use crate::sync_v2::{
    encode_cbor as encode_sync_cbor, sign_transition_v2, StoreSyncBufferV2, SyncCounterV2,
    VaultSyncParamsV2, SECRET_SYNC_ACCEPTED_V2, SECRET_SYNC_COUNTER_V2, SECRET_SYNC_STATE_V2,
    SECRET_SYNC_TRANSITION_V2,
};
use crate::vault::{
    SecretStore, StoreOp, VaultError, SECRET_ENVELOPE, SECRET_SESSION, SECRET_SYNC_COUNTER,
    SECRET_SYNC_STATE, VAULT_INSTANCE_KEYS,
};

/// v2 store keys. There is no `aegis/v2/session`.
pub const SECRET_ENVELOPE_V2: &[u8] = b"aegis/v2/envelope";
pub const SECRET_VAULT_V2: &[u8] = b"aegis/v2/vault";
pub const SECRET_AUDIT_V2: &[u8] = b"aegis/v2/audit";



pub struct VaultSessionV2 {
    root: RootSecret,
    keys: OperationalKeys,
    vault_id: [u8; 16],
    key_epoch: u32,
    pub doc: VaultDocument,
    pub audit: Vec<AuditEvent>,
}

impl VaultSessionV2 {
    pub fn create(store: &mut dyn SecretStore, passphrase: &str) -> Result<Self, VaultError> {
        Self::create_with_params(store, passphrase, Argon2ParamsV2::for_generate())
    }

    pub fn create_with_params(
        store: &mut dyn SecretStore,
        passphrase: &str,
        kdf: Argon2ParamsV2,
    ) -> Result<Self, VaultError> {
        validate_v2_passphrase(passphrase)?;
        if store.has(SECRET_ENVELOPE_V2) || store.has(SECRET_ENVELOPE) {
            return Err(VaultError::Msg("vault already exists".into()));
        }
        let mut vault_id = [0u8; 16];
        crate::rng::fill_random(&mut vault_id);
        let (envelope, root) = wrap_root_v2_with_checked(passphrase, vault_id, kdf)?;
        let mut session = Self::from_root(root, vault_id, KEY_EPOCH_INITIAL, empty_doc(vault_id))?;
        session.audit_push(AuditKind::CreateVault, None, "vault created");
        let mut vault_pt = Vec::new();
        ciborium::into_writer(&session.doc, &mut vault_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let vault_blob = seal_vault_v2(
            &session.keys.vault_dek,
            session.vault_id,
            session.key_epoch,
            &vault_pt,
        )?;
        let mut audit_pt = Vec::new();
        ciborium::into_writer(&session.audit, &mut audit_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit_blob = seal_audit_v2(
            &session.keys.audit_dek,
            session.vault_id,
            session.key_epoch,
            &audit_pt,
        )?;
        store
            .commit(&[
                StoreOp::put(SECRET_ENVELOPE_V2, envelope.to_bytes()?),
                StoreOp::put(SECRET_VAULT_V2, vault_blob.to_bytes()?),
                StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?),
            ])
            .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
        debug_assert!(!store.has(SECRET_SESSION));
        Ok(session)
    }

    pub fn unlock(store: &mut dyn SecretStore, passphrase: &str) -> Result<Self, VaultError> {
        let env_bytes = store
            .get(SECRET_ENVELOPE_V2)
            .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
        let envelope = MasterEnvelopeV2::from_bytes(&env_bytes)?;
        let root = unwrap_root_for_session(passphrase, &envelope)?;
        let vault_id = envelope.vault_id_bytes()?;
        let vault_bytes = store
            .get(SECRET_VAULT_V2)
            .ok_or_else(|| VaultError::Msg("vault blob not found".into()))?;
        let blob = VaultBlobV2::from_bytes(&vault_bytes)?;
        if blob.key_epoch != envelope.key_epoch {
            // Mixed/partial rollback of persisted blobs. A coherent rollback of
            // envelope+vault+audit together is not visible here; that needs a
            // retained newer counter (Phase 7 VaultSync replay protection).
            return Err(VaultError::Msg("key_epoch mismatch".into()));
        }
        let keys = derive_operational_keys(&root, &vault_id)?;
        let pt = open_vault_v2(&keys.vault_dek, &blob)?;
        let doc: VaultDocument =
            ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit = load_audit_v2(store, &keys.audit_dek).unwrap_or_default();
        let mut session = Self {
            root,
            keys,
            vault_id,
            key_epoch: envelope.key_epoch,
            doc,
            audit,
        };
        session.audit_push(AuditKind::Unlock, None, "unlocked");
        Ok(session)
    }

    pub fn unlock_with_recovery(
        store: &mut dyn SecretStore,
        recovery_display: &str,
    ) -> Result<Self, VaultError> {
        let rec_bytes = store
            .get(SECRET_RECOVERY_V2)
            .ok_or_else(|| VaultError::Msg("no recovery key configured".into()))?;
        let wrap = RecoveryWrapV2::from_cbor(&rec_bytes)?;
        let recovery = decode_recovery_secret(recovery_display)?;
        let root = unwrap_recovery(&wrap, &recovery)?;
        let vault_id = envelope_vault_id_from_wrap(&wrap)?;
        let keys = derive_operational_keys(&root, &vault_id)?;
        let vault_bytes = store
            .get(SECRET_VAULT_V2)
            .ok_or_else(|| VaultError::Msg("vault blob not found".into()))?;
        let blob = VaultBlobV2::from_bytes(&vault_bytes)?;
        if blob.key_epoch != wrap.key_epoch {
            return Err(VaultError::Msg("key_epoch mismatch".into()));
        }
        let pt = open_vault_v2(&keys.vault_dek, &blob)?;
        let doc: VaultDocument =
            ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit = load_audit_v2(store, &keys.audit_dek).unwrap_or_default();
        Ok(Self {
            root,
            keys,
            vault_id,
            key_epoch: wrap.key_epoch,
            doc,
            audit,
        })
    }

    /// Drop in-memory root. Does not write RootSecret. Refresh requires unlock.
    pub fn lock(mut self, store: &mut dyn SecretStore) {
        self.audit_push(AuditKind::Lock, None, "locked");
        let _ = self.persist_audit(store);
    }

    pub fn change_passphrase(
        &mut self,
        store: &mut dyn SecretStore,
        current: &str,
        new: &str,
    ) -> Result<(), VaultError> {
        validate_v2_passphrase(new)?;
        if current == new {
            return Err(VaultError::Msg(
                "new passphrase must differ from the current one".into(),
            ));
        }
        let env_bytes = store
            .get(SECRET_ENVELOPE_V2)
            .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
        let envelope = MasterEnvelopeV2::from_bytes(&env_bytes)?;
        let verified = unwrap_root_for_session(current, &envelope)?;
        if verified.as_bytes() != self.root.as_bytes() {
            return Err(VaultError::Msg("current passphrase incorrect".into()));
        }
        #[cfg(test)]
        let new_env = crate::crypto::envelope_v2::wrap_existing_root_v2_unit_test(
            new,
            self.vault_id,
            self.key_epoch,
            &Argon2ParamsV2::insecure_for_tests(),
            &self.root,
        )?;
        #[cfg(not(test))]
        let new_env = wrap_existing_root_v2(
            new,
            self.vault_id,
            self.key_epoch,
            &Argon2ParamsV2::generate_v2(),
            &self.root,
        )?;
        self.audit_push(
            AuditKind::ChangePassphrase,
            None,
            "master passphrase changed",
        );
        let mut audit_pt = Vec::new();
        ciborium::into_writer(&self.audit, &mut audit_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit_blob = seal_audit_v2(
            &self.keys.audit_dek,
            self.vault_id,
            self.key_epoch,
            &audit_pt,
        )?;
        store
            .commit(&[
                StoreOp::put(SECRET_ENVELOPE_V2, new_env.to_bytes()?),
                StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?),
            ])
            .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
        Ok(())
    }

    /// Explicit full RootSecret rotation. Never invoked by unlock.
    pub fn rotate_keys(
        &mut self,
        store: &mut dyn SecretStore,
        passphrase: &str,
        recovery_key: Option<&str>,
    ) -> Result<Option<String>, VaultError> {
        if store.has(SECRET_SYNC_STATE) || store.has(SECRET_SYNC_COUNTER) {
            return Err(VaultError::VaultSyncMigrationDeferred);
        }
        let has_v2_sync = store.has(SECRET_SYNC_STATE_V2)
            || store.has(SECRET_SYNC_ACCEPTED_V2)
            || store.has(SECRET_SYNC_COUNTER_V2)
            || store.has(SECRET_SYNC_TRANSITION_V2);
        let env_bytes = store
            .get(SECRET_ENVELOPE_V2)
            .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
        let envelope = MasterEnvelopeV2::from_bytes(&env_bytes)?;
        if envelope.key_epoch != self.key_epoch {
            return Err(VaultError::Msg("key_epoch mismatch".into()));
        }
        let verified = unwrap_root_for_session(passphrase, &envelope)?;
        if verified.as_bytes() != self.root.as_bytes() {
            return Err(VaultError::Msg("current passphrase incorrect".into()));
        }
        let new_epoch = self
            .key_epoch
            .checked_add(1)
            .ok_or_else(|| VaultError::Msg("key_epoch overflow".into()))?;
        let new_root = RootSecret::random();
        if new_root.as_bytes() == self.root.as_bytes() {
            return Err(VaultError::Msg("root collision".into()));
        }
        let new_keys = derive_operational_keys(&new_root, &self.vault_id)?;

        self.audit_push(
            AuditKind::RotateKeys,
            None,
            "rotated vault cryptographic keys",
        );

        let mut vault_pt = Vec::new();
        ciborium::into_writer(&self.doc, &mut vault_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let vault_blob = seal_vault_v2(&new_keys.vault_dek, self.vault_id, new_epoch, &vault_pt)?;
        let mut audit_pt = Vec::new();
        ciborium::into_writer(&self.audit, &mut audit_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit_blob = seal_audit_v2(&new_keys.audit_dek, self.vault_id, new_epoch, &audit_pt)?;

        #[cfg(test)]
        let new_env = crate::crypto::envelope_v2::wrap_existing_root_v2_unit_test(
            passphrase,
            self.vault_id,
            new_epoch,
            &Argon2ParamsV2::insecure_for_tests(),
            &new_root,
        )?;
        #[cfg(not(test))]
        let new_env = wrap_existing_root_v2(
            passphrase,
            self.vault_id,
            new_epoch,
            &Argon2ParamsV2::generate_v2(),
            &new_root,
        )?;

        let mut minted_recovery: Option<String> = None;
        let mut rec_ops: Option<StoreOp> = None;
        if store.has(SECRET_RECOVERY_V2) {
            let rec_bytes = store
                .get(SECRET_RECOVERY_V2)
                .ok_or_else(|| VaultError::Msg("no recovery key configured".into()))?;
            let old_wrap = RecoveryWrapV2::from_cbor(&rec_bytes)?;
            let (rec_wrap, secret_for_candidate, minted) =
                if let Some(display) = recovery_key.filter(|s| !s.is_empty()) {
                    // Authenticate the supplied secret against the *current*
                    // epoch wrap before it may be reused at N+1.
                    let existing = decode_recovery_secret(display)?;
                    let old_root = unwrap_recovery(&old_wrap, &existing)?;
                    if old_root.as_bytes() != self.root.as_bytes() {
                        return Err(VaultError::Msg("recovery key does not match vault".into()));
                    }
                    let wrap = wrap_recovery_with_secret(
                        &new_root,
                        self.vault_id,
                        new_epoch,
                        &existing,
                    )?;
                    (wrap, existing, false)
                } else {
                    let (wrap, secret) = wrap_recovery(&new_root, self.vault_id, new_epoch)?;
                    (wrap, secret, true)
                };
            validate_candidate_recovery(
                &rec_wrap,
                &secret_for_candidate,
                &new_root,
                new_epoch,
            )?;
            if minted {
                minted_recovery = Some(encode_recovery_secret(&secret_for_candidate));
            }
            rec_ops = Some(StoreOp::put(SECRET_RECOVERY_V2, rec_wrap.to_cbor()?));
        }

        let opened = unwrap_root_for_session(passphrase, &new_env)?;
        if opened.as_bytes() != new_root.as_bytes() {
            return Err(VaultError::Msg("candidate reopen failed".into()));
        }
        if vault_blob.key_epoch != new_epoch || audit_blob.key_epoch != new_epoch {
            return Err(VaultError::Msg("candidate reopen failed".into()));
        }
        let reopened = open_vault_v2(&new_keys.vault_dek, &vault_blob)?;
        let doc2: VaultDocument =
            ciborium::from_reader(reopened.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;
        if doc2.entries.len() != self.doc.entries.len() {
            return Err(VaultError::Msg("candidate reopen failed".into()));
        }
        let _ = open_audit_v2(&new_keys.audit_dek, &audit_blob)?;

        let mut ops = vec![
            StoreOp::put(SECRET_ENVELOPE_V2, new_env.to_bytes()?),
            StoreOp::put(SECRET_VAULT_V2, vault_blob.to_bytes()?),
            StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?),
        ];
        if let Some(op) = rec_ops {
            ops.push(op);
        }
        if has_v2_sync {
            let old_signer = HybridSyncSigner::from_operational_keys(&self.keys);
            let new_signer = HybridSyncSigner::from_operational_keys(&new_keys);
            let transition = sign_transition_v2(
                &old_signer,
                &new_signer,
                self.vault_id,
                self.key_epoch,
                new_epoch,
            )?;
            let trans_bytes = encode_sync_cbor(&transition)
                .map_err(|e| VaultError::Serde(e))?;
            ops.push(StoreOp::put(SECRET_SYNC_TRANSITION_V2, trans_bytes));
            ops.push(StoreOp::put(
                SECRET_SYNC_COUNTER_V2,
                encode_sync_cbor(&SyncCounterV2 {
                    key_epoch: new_epoch,
                    counter: 0,
                })
                .map_err(|e| VaultError::Serde(e))?,
            ));
            let mut accepted = match store.get(SECRET_SYNC_ACCEPTED_V2) {
                Some(bytes) if !bytes.is_empty() => {
                    crate::sync_v2::decode_cbor(&bytes).map_err(|e| VaultError::Serde(e))?
                }
                _ => crate::sync_v2::SyncAcceptedTableV2::default(),
            };
            accepted.min_epoch = new_epoch;
            ops.push(StoreOp::put(
                SECRET_SYNC_ACCEPTED_V2,
                encode_sync_cbor(&accepted).map_err(|e| VaultError::Serde(e))?,
            ));
            if let Some(state_bytes) = store.get(SECRET_SYNC_STATE_V2) {
                if !state_bytes.is_empty() {
                    let mut state = crate::sync_v2::decode_state_v2(&state_bytes)
                        .map_err(|e| VaultError::Msg(e.to_string()))?;
                    if !state.transitions.iter().any(|t| t == &transition) {
                        state.transitions.push(transition);
                    }
                    ops.push(StoreOp::put(
                        SECRET_SYNC_STATE_V2,
                        encode_sync_cbor(&state).map_err(|e| VaultError::Serde(e))?,
                    ));
                }
            }
        }
        store
            .commit(&ops)
            .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;

        self.root = new_root;
        self.keys = new_keys;
        self.key_epoch = new_epoch;
        Ok(minted_recovery)
    }

    /// Hybrid VaultSync via secret-store MVR (+ optional remote contract CBOR).
    pub fn sync_now_with_publish(
        &mut self,
        store: &mut dyn SecretStore,
        remote_state: &[u8],
    ) -> Result<crate::messages::VaultResponse, VaultError> {
        let mut buf = StoreSyncBufferV2::load(store, self.key_epoch)
            .map_err(|e| VaultError::Msg(format!("sync load: {e}")))?;
        buf.merge_remote_cbor(remote_state)
            .map_err(|e| VaultError::Msg(format!("sync remote merge: {e}")))?;
        let device_id = self.doc.meta.device_id.clone();
        let mut counter = buf.counter.counter;
        let report = crate::sync_v2::sync_vault_v2(
            &self.keys,
            self.vault_id,
            self.key_epoch,
            &device_id,
            &mut self.doc,
            &mut buf.accepted,
            &mut counter,
            &mut buf.state,
        )?;
        buf.counter = SyncCounterV2 {
            key_epoch: self.key_epoch,
            counter,
        };
        buf.commit(store)
            .map_err(|e| VaultError::Msg(format!("sync save: {e}")))?;
        self.audit_push(
            crate::types::AuditKind::Sync,
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
        let signer = HybridSyncSigner::from_operational_keys(&self.keys);
        let identity = signer.identity();
        let params = VaultSyncParamsV2::from_identity(&identity);
        let params_cbor = encode_sync_cbor(&params).unwrap_or_default();
        let contract_state = buf.encode_cbor().unwrap_or_default();
        Ok(crate::messages::VaultResponse::Synced {
            action: action.into(),
            remote_revisions: report.remote_revisions,
            detail: report.detail,
            contract_state,
            owner_verifying_key: identity.ed25519_vk,
            sync_params: params_cbor,
        })
    }

    pub fn persist(&mut self, store: &mut dyn SecretStore) -> Result<(), VaultError> {
        let mut pt = Vec::new();
        ciborium::into_writer(&self.doc, &mut pt).map_err(|e| VaultError::Serde(e.to_string()))?;
        let blob = seal_vault_v2(&self.keys.vault_dek, self.vault_id, self.key_epoch, &pt)?;
        let mut audit_pt = Vec::new();
        ciborium::into_writer(&self.audit, &mut audit_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit_blob = seal_audit_v2(
            &self.keys.audit_dek,
            self.vault_id,
            self.key_epoch,
            &audit_pt,
        )?;
        store
            .commit(&[
                StoreOp::put(SECRET_VAULT_V2, blob.to_bytes()?),
                StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?),
            ])
            .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
        Ok(())
    }

    fn persist_audit(&self, store: &mut dyn SecretStore) -> Result<(), VaultError> {
        let mut pt = Vec::new();
        ciborium::into_writer(&self.audit, &mut pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let blob = seal_audit_v2(&self.keys.audit_dek, self.vault_id, self.key_epoch, &pt)?;
        store.set(SECRET_AUDIT_V2, &blob.to_bytes()?);
        Ok(())
    }

    fn audit_push(&mut self, kind: AuditKind, entry_id: Option<crate::types::EntryId>, detail: &str) {
        self.audit.push(AuditEvent {
            ts: unix_now(),
            kind,
            entry_id,
            detail: detail.to_string(),
        });
        const MAX: usize = 500;
        if self.audit.len() > MAX {
            let drain = self.audit.len() - MAX;
            self.audit.drain(0..drain);
        }
    }

    fn from_root(
        root: RootSecret,
        vault_id: [u8; 16],
        key_epoch: u32,
        doc: VaultDocument,
    ) -> Result<Self, VaultError> {
        let keys = derive_operational_keys(&root, &vault_id)?;
        Ok(Self {
            root,
            keys,
            vault_id,
            key_epoch,
            doc,
            audit: Vec::new(),
        })
    }

    pub fn export_backup(&self, backup_passphrase: &str) -> Result<Vec<u8>, VaultError> {
        let forbidden: &[&[u8]] = &[
            self.root.as_bytes().as_slice(),
            self.keys.vault_dek.as_bytes().as_slice(),
            self.keys.audit_dek.as_bytes().as_slice(),
            self.keys.sync_dek.as_bytes().as_slice(),
            self.keys.search_hmac.as_bytes().as_slice(),
            self.keys.sync_ed25519_seed.as_bytes().as_slice(),
            self.keys.sync_mldsa_seed.as_bytes().as_slice(),
            self.keys.share_x25519_seed.as_bytes().as_slice(),
            self.keys.share_mlkem_seed.as_bytes().as_slice(),
        ];
        create_backup_with_params(
            backup_passphrase,
            self.vault_id,
            &self.doc,
            &self.audit,
            Argon2ParamsV2::for_generate(),
            forbidden,
        )
        .map_err(Into::into)
    }

    pub fn restore_backup(
        store: &mut dyn SecretStore,
        blob: &[u8],
        backup_passphrase: &str,
        vault_passphrase: &str,
        replace: bool,
    ) -> Result<Self, VaultError> {
        let exists = store.has(SECRET_ENVELOPE_V2) || store.has(SECRET_ENVELOPE);
        if exists && !replace {
            return Err(VaultError::Msg("vault already exists".into()));
        }
        validate_v2_passphrase(vault_passphrase)?;
        let payload = authenticate_backup(blob, backup_passphrase)?;

        let mut new_vid = [0u8; 16];
        crate::rng::fill_random(&mut new_vid);
        let (envelope, root) = wrap_root_v2(vault_passphrase, new_vid)?;
        let mut doc = payload.document;
        doc.meta.vault_id = hex::encode(new_vid);
        doc.meta.device_id = new_id();
        doc.meta.format_version = 2;
        doc.meta.updated_at = unix_now();

        let mut session = Self::from_root(root, new_vid, KEY_EPOCH_INITIAL, doc)?;
        session.audit = payload.audit;
        session.audit_push(AuditKind::Import, None, "restored v2 backup (new identity)");

        let mut vault_pt = Vec::new();
        ciborium::into_writer(&session.doc, &mut vault_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let vault_blob = seal_vault_v2(
            &session.keys.vault_dek,
            session.vault_id,
            session.key_epoch,
            &vault_pt,
        )?;
        let mut audit_pt = Vec::new();
        ciborium::into_writer(&session.audit, &mut audit_pt)
            .map_err(|e| VaultError::Serde(e.to_string()))?;
        let audit_blob = seal_audit_v2(
            &session.keys.audit_dek,
            session.vault_id,
            session.key_epoch,
            &audit_pt,
        )?;

        let mut ops = Vec::new();
        if replace {
            for k in VAULT_INSTANCE_KEYS {
                ops.push(StoreOp::delete(*k));
            }
        }
        ops.push(StoreOp::delete(SECRET_RECOVERY_V2));
        for k in [
            SECRET_SYNC_STATE_V2,
            SECRET_SYNC_ACCEPTED_V2,
            SECRET_SYNC_COUNTER_V2,
            SECRET_SYNC_TRANSITION_V2,
        ] {
            ops.push(StoreOp::delete(k));
        }
        ops.push(StoreOp::put(SECRET_ENVELOPE_V2, envelope.to_bytes()?));
        ops.push(StoreOp::put(SECRET_VAULT_V2, vault_blob.to_bytes()?));
        ops.push(StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?));
        store
            .commit(&ops)
            .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
        Ok(session)
    }

    /// Identity-preserving recovery. Authenticates the kit fully before any
    /// store write. Never mints a new RootSecret (unlike backup restore).
    ///
    /// Existing v2 vault: lost-passphrase re-wrap. Requires exact
    /// `vault_id` and `key_epoch` match; recovered RootSecret must open the
    /// current vault and audit. Empty store: kit is identity only — a v2
    /// backup is required for data.
    pub fn import_recovery_kit(
        store: &mut dyn SecretStore,
        kit: &[u8],
        recovery_display: &str,
        vault_passphrase: &str,
        backup: Option<&[u8]>,
        backup_passphrase: Option<&str>,
    ) -> Result<Self, VaultError> {
        if kit.is_empty() {
            return Err(VaultError::Msg("recovery kit is required".into()));
        }
        if kit.starts_with(crate::crypto::MAGIC_BACKUP_V2)
            || kit.starts_with(crate::crypto::MAGIC_VAULT_V2)
            || kit.starts_with(crate::crypto::MAGIC_SYNC_V2)
        {
            return Err(VaultError::Msg(
                "not a Recovery Kit (this is a backup or vault file)".into(),
            ));
        }
        let wrap = RecoveryWrapV2::from_kit_bytes(kit)?;
        let recovery = decode_recovery_secret(recovery_display)?;
        let root = unwrap_recovery(&wrap, &recovery)?;
        let vault_id = wrap.vault_id_bytes()?;
        validate_candidate_recovery(&wrap, &recovery, &root, wrap.key_epoch)?;

        if store.has(SECRET_ENVELOPE_V2) {
            recover_existing_v2(
                store,
                wrap,
                root,
                vault_id,
                vault_passphrase,
            )
        } else if store.has(SECRET_ENVELOPE) {
            Err(VaultError::MigrationRequired)
        } else {
            recover_empty_with_backup(
                store,
                wrap,
                root,
                vault_id,
                vault_passphrase,
                backup,
                backup_passphrase,
            )
        }
    }

    #[cfg(test)]
    pub(crate) fn root_bytes_for_test(&self) -> [u8; 32] {
        *self.root.as_bytes()
    }

    #[cfg(test)]
    pub(crate) fn vault_dek_bytes_for_test(&self) -> [u8; 32] {
        *self.keys.vault_dek.as_bytes()
    }

    #[cfg(test)]
    pub(crate) fn vault_id_for_test(&self) -> [u8; 16] {
        self.vault_id
    }

    #[cfg(test)]
    pub(crate) fn key_epoch_for_test(&self) -> u32 {
        self.key_epoch
    }

    #[cfg(test)]
    pub(crate) fn keys_for_test(&self) -> &OperationalKeys {
        &self.keys
    }

    pub(crate) fn from_migrated(
        root: RootSecret,
        keys: OperationalKeys,
        vault_id: [u8; 16],
        key_epoch: u32,
        doc: VaultDocument,
        audit: Vec<AuditEvent>,
    ) -> Self {
        Self {
            root,
            keys,
            vault_id,
            key_epoch,
            doc,
            audit,
        }
    }

    pub fn handle(
        &mut self,
        store: &mut dyn SecretStore,
        req: VaultRequest,
    ) -> Result<VaultResponse, VaultError> {
        match req {
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
                        entry.password_history = prev.password_history.clone();
                    }
                }
                let id = entry.id.clone();
                self.doc.entries.insert(id.clone(), entry);
                self.doc.meta.updated_at = unix_now();
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
                self.doc.meta.updated_at = unix_now();
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
                self.doc.meta.updated_at = unix_now();
                self.persist(store)?;
                Ok(VaultResponse::Ok)
            }
            VaultRequest::DeleteFolder { id } => {
                self.doc.folders.remove(&id);
                for e in self.doc.entries.values_mut() {
                    if e.folder_id.as_deref() == Some(id.as_str()) {
                        e.folder_id = None;
                    }
                }
                self.doc.meta.updated_at = unix_now();
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
                ..
            } => {
                self.change_passphrase(store, &current_passphrase, &new_passphrase)?;
                Ok(VaultResponse::Ok)
            }
            VaultRequest::RotateKeys {
                passphrase,
                recovery_key,
            } => {
                let recovery_secret =
                    self.rotate_keys(store, &passphrase, recovery_key.as_deref())?;
                Ok(VaultResponse::Rotated {
                    vault_id: self.doc.meta.vault_id.clone(),
                    key_epoch: self.key_epoch,
                    recovery_secret,
                })
            }
            VaultRequest::PasswordHealth => {
                let report = analyze_entries(self.doc.entries.values());
                Ok(VaultResponse::Health { report })
            }
            VaultRequest::GenerateRecoveryKey { .. } => {
                let (wrap, secret) =
                    wrap_recovery(&self.root, self.vault_id, self.key_epoch)?;
                validate_candidate_recovery(&wrap, &secret, &self.root, self.key_epoch)?;
                let kit = wrap.to_kit_bytes()?;
                self.audit_push(
                    AuditKind::GenerateRecovery,
                    None,
                    "generated recovery kit (previous recovery credential retired)",
                );
                store
                    .commit(&[
                        StoreOp::put(SECRET_RECOVERY_V2, wrap.to_cbor()?),
                    ])
                    .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
                self.persist_audit(store)?;
                debug_assert!(!store.get(SECRET_RECOVERY_V2).is_some_and(|b| {
                    b.windows(32).any(|w| w == secret.as_bytes().as_slice())
                }));
                Ok(VaultResponse::RecoveryKey {
                    recovery_key: encode_recovery_secret(&secret),
                    kit,
                })
            }
            VaultRequest::ExportRecoveryKit => {
                let rec_bytes = store.get(SECRET_RECOVERY_V2).ok_or_else(|| {
                    VaultError::Msg("no recovery key configured".into())
                })?;
                let wrap = RecoveryWrapV2::from_cbor(&rec_bytes)?;
                Ok(VaultResponse::RecoveryKey {
                    recovery_key: String::new(),
                    kit: wrap.to_kit_bytes()?,
                })
            }
            VaultRequest::RevokeRecoveryKey => {
                self.audit_push(AuditKind::RevokeRecovery, None, "recovery kit revoked");
                store
                    .commit(&[StoreOp::delete(SECRET_RECOVERY_V2)])
                    .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
                self.persist_audit(store)?;
                Ok(VaultResponse::Ok)
            }
            VaultRequest::ExportEncrypted { passphrase } => {
                let blob = self.export_backup(&passphrase)?;
                Ok(VaultResponse::Export { blob })
            }
            VaultRequest::GetAuditLog { limit } => {
                let n = limit.unwrap_or(100) as usize;
                let start = self.audit.len().saturating_sub(n);
                Ok(VaultResponse::Audit {
                    events: self.audit[start..].to_vec(),
                })
            }
            VaultRequest::ExportShareIdentity => {
                let id = crate::share::export_share_identity(
                    &self.keys,
                    self.vault_id,
                    self.key_epoch,
                )?;
                Ok(VaultResponse::ShareIdentity { blob: id.to_cbor()? })
            }
            VaultRequest::CreateShare {
                entry_id,
                recipient_identity,
            } => {
                let entry = self
                    .doc
                    .entries
                    .get(&entry_id)
                    .ok_or_else(|| VaultError::Msg("entry not found".into()))?
                    .clone();
                let recipient = crate::share::SharePublicIdentityV2::from_cbor(&recipient_identity)?;
                let env = crate::share::create_share_envelope(
                    &self.keys,
                    self.vault_id,
                    self.key_epoch,
                    &recipient,
                    &entry,
                )?;
                self.audit_push(AuditKind::Share, Some(entry_id), "created hybrid share");
                self.persist_audit(store)?;
                Ok(VaultResponse::ShareEnvelope { blob: env.to_cbor()? })
            }
            VaultRequest::OpenShare {
                envelope,
                expected_sender_identity,
            } => {
                if expected_sender_identity.is_empty() {
                    return Err(VaultError::Msg(
                        "open_share requires expected_sender_identity".into(),
                    ));
                }
                let env = crate::share::ShareEnvelopeV2::from_cbor(&envelope)?;
                let expected =
                    crate::share::SharePublicIdentityV2::from_cbor(&expected_sender_identity)?;
                let entry = crate::share::open_share_envelope(
                    &self.keys,
                    self.vault_id,
                    self.key_epoch,
                    &env,
                    &expected,
                )?;
                self.audit_push(
                    AuditKind::Share,
                    Some(entry.id.clone()),
                    "opened hybrid share",
                );
                self.persist_audit(store)?;
                Ok(VaultResponse::Entry { entry })
            }
            VaultRequest::SyncNow | VaultRequest::SyncWithRemote { .. } => {
                Err(VaultError::Msg(
                    "request must be handled by dispatcher".into(),
                ))
            }
            _ => Err(VaultError::Msg(
                "request must be handled by dispatcher".into(),
            )),
        }
    }
}

/// Decrypt a v2 vault document without starting a session or writing audit.
pub fn peek_document(
    store: &dyn SecretStore,
    passphrase: &str,
) -> Result<VaultDocument, VaultError> {
    let env_bytes = store
        .get(SECRET_ENVELOPE_V2)
        .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
    let envelope = MasterEnvelopeV2::from_bytes(&env_bytes)?;
    let root = unwrap_root_for_session(passphrase, &envelope)?;
    let vault_id = envelope.vault_id_bytes()?;
    let vault_bytes = store
        .get(SECRET_VAULT_V2)
        .ok_or_else(|| VaultError::Msg("vault blob not found".into()))?;
    let blob = VaultBlobV2::from_bytes(&vault_bytes)?;
    if blob.key_epoch != envelope.key_epoch {
        return Err(VaultError::Msg("key_epoch mismatch".into()));
    }
    let keys = derive_operational_keys(&root, &vault_id)?;
    let pt = open_vault_v2(&keys.vault_dek, &blob)?;
    ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))
}

fn wrap_recovered_root(
    passphrase: &str,
    vault_id: [u8; 16],
    key_epoch: u32,
    root: &RootSecret,
) -> Result<MasterEnvelopeV2, VaultError> {
    #[cfg(test)]
    {
        return Ok(crate::crypto::envelope_v2::wrap_existing_root_v2_unit_test(
            passphrase,
            vault_id,
            key_epoch,
            &Argon2ParamsV2::insecure_for_tests(),
            root,
        )?);
    }
    #[cfg(not(test))]
    {
        wrap_existing_root_v2(
            passphrase,
            vault_id,
            key_epoch,
            &Argon2ParamsV2::generate_v2(),
            root,
        )
        .map_err(Into::into)
    }
}

fn recover_existing_v2(
    store: &mut dyn SecretStore,
    wrap: RecoveryWrapV2,
    root: RootSecret,
    vault_id: [u8; 16],
    vault_passphrase: &str,
) -> Result<VaultSessionV2, VaultError> {
    let env_bytes = store
        .get(SECRET_ENVELOPE_V2)
        .ok_or_else(|| VaultError::Msg("vault not found".into()))?;
    let local = MasterEnvelopeV2::from_bytes(&env_bytes)?;
    let local_vid = local.vault_id_bytes()?;
    if local_vid != vault_id {
        return Err(VaultError::Msg(
            "recovery kit vault_id does not match this vault".into(),
        ));
    }
    if local.key_epoch != wrap.key_epoch {
        return Err(VaultError::Msg(
            "recovery kit key_epoch does not match this vault".into(),
        ));
    }

    let vault_bytes = store
        .get(SECRET_VAULT_V2)
        .ok_or_else(|| VaultError::Msg("vault blob not found".into()))?;
    let vault_blob = VaultBlobV2::from_bytes(&vault_bytes)?;
    let blob_vid: [u8; 16] = vault_blob
        .vault_id
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Msg("invalid vault blob".into()))?;
    if blob_vid != vault_id {
        return Err(VaultError::Msg(
            "recovery kit vault_id does not match this vault".into(),
        ));
    }
    if vault_blob.key_epoch != wrap.key_epoch {
        return Err(VaultError::Msg(
            "recovery kit key_epoch does not match this vault".into(),
        ));
    }
    let keys = derive_operational_keys(&root, &vault_id)?;
    let pt = open_vault_v2(&keys.vault_dek, &vault_blob).map_err(|_| {
        VaultError::Msg("recovered root cannot open current vault".into())
    })?;
    let doc: VaultDocument =
        ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))?;
    let audit = load_audit_v2(store, &keys.audit_dek).map_err(|_| {
        VaultError::Msg("recovered root cannot open current audit".into())
    })?;

    validate_v2_passphrase(vault_passphrase)?;
    let envelope = wrap_recovered_root(vault_passphrase, vault_id, wrap.key_epoch, &root)?;
    let opened = unwrap_root_for_session(vault_passphrase, &envelope)?;
    if opened.as_bytes() != root.as_bytes() {
        return Err(VaultError::Msg("candidate recovery reopen failed".into()));
    }
    let reopened_vault = open_vault_v2(&keys.vault_dek, &vault_blob)?;
    if reopened_vault != pt {
        return Err(VaultError::Msg("candidate recovery reopen failed".into()));
    }
    let _ = load_audit_v2(store, &keys.audit_dek)?;

    let mut session = VaultSessionV2::from_root(root, vault_id, wrap.key_epoch, doc)?;
    session.audit = audit;
    session.audit_push(
        AuditKind::UnlockRecovery,
        None,
        "recovered existing vault with recovery kit (new passphrase)",
    );
    let mut audit_pt = Vec::new();
    ciborium::into_writer(&session.audit, &mut audit_pt)
        .map_err(|e| VaultError::Serde(e.to_string()))?;
    let audit_blob = seal_audit_v2(
        &session.keys.audit_dek,
        session.vault_id,
        session.key_epoch,
        &audit_pt,
    )?;
    let _ = open_audit_v2(&session.keys.audit_dek, &audit_blob)?;

    store
        .commit(&[
            StoreOp::put(SECRET_ENVELOPE_V2, envelope.to_bytes()?),
            StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?),
            StoreOp::put(SECRET_RECOVERY_V2, wrap.to_cbor()?),
        ])
        .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
    Ok(session)
}

fn recover_empty_with_backup(
    store: &mut dyn SecretStore,
    wrap: RecoveryWrapV2,
    root: RootSecret,
    vault_id: [u8; 16],
    vault_passphrase: &str,
    backup: Option<&[u8]>,
    backup_passphrase: Option<&str>,
) -> Result<VaultSessionV2, VaultError> {
    let Some(backup) = backup.filter(|b| !b.is_empty()) else {
        return Err(VaultError::Msg(
            "Recovery Kit restores identity only; provide a normal AEGIS_BACKUP_V2 file to recover vault data".into(),
        ));
    };
    if !backup.starts_with(crate::crypto::MAGIC_BACKUP_V2) {
        return Err(VaultError::Msg(
            "identity-preserving disaster recovery requires a v2 backup (AEGIS_BACKUP_V2)".into(),
        ));
    }
    let Some(backup_pw) = backup_passphrase.filter(|s| !s.is_empty()) else {
        return Err(VaultError::Msg(
            "backup passphrase is required to recover vault data".into(),
        ));
    };
    let payload = authenticate_backup(backup, backup_pw)?;
    let original: [u8; 16] = payload
        .original_vault_id
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Msg("invalid backup original_vault_id".into()))?;
    if original != vault_id {
        return Err(VaultError::Msg(
            "backup original_vault_id does not match recovery kit vault_id".into(),
        ));
    }

    validate_v2_passphrase(vault_passphrase)?;
    let envelope = wrap_recovered_root(vault_passphrase, vault_id, wrap.key_epoch, &root)?;
    let opened = unwrap_root_for_session(vault_passphrase, &envelope)?;
    if opened.as_bytes() != root.as_bytes() {
        return Err(VaultError::Msg("candidate recovery reopen failed".into()));
    }

    let mut doc = payload.document;
    doc.meta.vault_id = hex::encode(vault_id);
    doc.meta.device_id = new_id();
    doc.meta.format_version = 2;
    doc.meta.updated_at = unix_now();
    let mut session = VaultSessionV2::from_root(root, vault_id, wrap.key_epoch, doc)?;
    session.audit = payload.audit;
    session.audit_push(
        AuditKind::Import,
        None,
        "identity-preserving disaster recovery (kit identity + backup data)",
    );

    let mut vault_pt = Vec::new();
    ciborium::into_writer(&session.doc, &mut vault_pt)
        .map_err(|e| VaultError::Serde(e.to_string()))?;
    let vault_blob = seal_vault_v2(
        &session.keys.vault_dek,
        session.vault_id,
        session.key_epoch,
        &vault_pt,
    )?;
    let mut audit_pt = Vec::new();
    ciborium::into_writer(&session.audit, &mut audit_pt)
        .map_err(|e| VaultError::Serde(e.to_string()))?;
    let audit_blob = seal_audit_v2(
        &session.keys.audit_dek,
        session.vault_id,
        session.key_epoch,
        &audit_pt,
    )?;
    let _ = open_vault_v2(&session.keys.vault_dek, &vault_blob)?;
    let _ = open_audit_v2(&session.keys.audit_dek, &audit_blob)?;

    store
        .commit(&[
            StoreOp::put(SECRET_ENVELOPE_V2, envelope.to_bytes()?),
            StoreOp::put(SECRET_VAULT_V2, vault_blob.to_bytes()?),
            StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?),
            StoreOp::put(SECRET_RECOVERY_V2, wrap.to_cbor()?),
        ])
        .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
    Ok(session)
}

fn envelope_vault_id_from_wrap(wrap: &RecoveryWrapV2) -> Result<[u8; 16], VaultError> {
    wrap.vault_id
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Msg("invalid recovery wrap".into()))
}

pub fn install_new_v2_from_document(
    store: &mut dyn SecretStore,
    mut doc: VaultDocument,
    audit: Vec<AuditEvent>,
    vault_passphrase: &str,
    replace: bool,
) -> Result<VaultSessionV2, VaultError> {
    validate_v2_passphrase(vault_passphrase)?;
    let exists = store.has(SECRET_ENVELOPE_V2) || store.has(SECRET_ENVELOPE);
    if exists && !replace {
        return Err(VaultError::Msg("vault already exists".into()));
    }
    let mut vault_id = [0u8; 16];
    crate::rng::fill_random(&mut vault_id);
    let (envelope, root) = wrap_root_v2(vault_passphrase, vault_id)?;
    doc.meta.vault_id = hex::encode(vault_id);
    doc.meta.device_id = new_id();
    doc.meta.format_version = 2;
    doc.meta.updated_at = unix_now();
    let mut session = VaultSessionV2::from_root(root, vault_id, KEY_EPOCH_INITIAL, doc)?;
    session.audit = audit;
    session.audit_push(AuditKind::Import, None, "imported as new v2 vault");
    let mut vault_pt = Vec::new();
    ciborium::into_writer(&session.doc, &mut vault_pt)
        .map_err(|e| VaultError::Serde(e.to_string()))?;
    let vault_blob = seal_vault_v2(
        &session.keys.vault_dek,
        session.vault_id,
        session.key_epoch,
        &vault_pt,
    )?;
    let mut audit_pt = Vec::new();
    ciborium::into_writer(&session.audit, &mut audit_pt)
        .map_err(|e| VaultError::Serde(e.to_string()))?;
    let audit_blob = seal_audit_v2(
        &session.keys.audit_dek,
        session.vault_id,
        session.key_epoch,
        &audit_pt,
    )?;
    let mut ops = Vec::new();
    if replace {
        for k in VAULT_INSTANCE_KEYS {
            ops.push(StoreOp::delete(*k));
        }
    }
    ops.push(StoreOp::delete(SECRET_RECOVERY_V2));
    for k in [
        SECRET_SYNC_STATE_V2,
        SECRET_SYNC_ACCEPTED_V2,
        SECRET_SYNC_COUNTER_V2,
        SECRET_SYNC_TRANSITION_V2,
    ] {
        ops.push(StoreOp::delete(k));
    }
    ops.push(StoreOp::put(SECRET_ENVELOPE_V2, envelope.to_bytes()?));
    ops.push(StoreOp::put(SECRET_VAULT_V2, vault_blob.to_bytes()?));
    ops.push(StoreOp::put(SECRET_AUDIT_V2, audit_blob.to_bytes()?));
    store
        .commit(&ops)
        .map_err(|e| VaultError::Msg(format!("atomic commit failed: {e}")))?;
    Ok(session)
}

fn unwrap_root_for_session(
    passphrase: &str,
    envelope: &MasterEnvelopeV2,
) -> Result<RootSecret, VaultError> {
    #[cfg(any(test, feature = "insecure-kdf"))]
    {
        if envelope.kdf.memory_kib < crate::crypto::V2_MIN_MEMORY_KIB {
            return crate::crypto::envelope_v2::unwrap_root_v2_unit_test(passphrase, envelope)
                .map_err(Into::into);
        }
    }
    unwrap_root_v2(passphrase, envelope).map_err(Into::into)
}

fn wrap_root_v2_with_checked(
    passphrase: &str,
    vault_id: [u8; 16],
    kdf: Argon2ParamsV2,
) -> Result<(MasterEnvelopeV2, RootSecret), VaultError> {
    #[cfg(any(test, feature = "insecure-kdf"))]
    {
        if kdf.memory_kib < crate::crypto::V2_MIN_MEMORY_KIB {
            let root = RootSecret::random();
            let env = crate::crypto::envelope_v2::wrap_existing_root_v2_unit_test(
                passphrase,
                vault_id,
                KEY_EPOCH_INITIAL,
                &kdf,
                &root,
            )?;
            return Ok((env, root));
        }
    }
    crate::crypto::envelope_v2::wrap_root_v2_with_params(passphrase, vault_id, kdf)
        .map_err(VaultError::from)
}

fn empty_doc(vault_id: [u8; 16]) -> VaultDocument {
    let now = unix_now();
    VaultDocument {
        meta: VaultMeta {
            vault_id: hex::encode(vault_id),
            format_version: 2,
            created_at: now,
            updated_at: now,
            device_id: new_id(),
        },
        ..Default::default()
    }
}

fn load_audit_v2(
    store: &dyn SecretStore,
    audit_dek: &crate::crypto::secret::AuditDek,
) -> Result<Vec<AuditEvent>, VaultError> {
    let bytes = store
        .get(SECRET_AUDIT_V2)
        .ok_or_else(|| VaultError::Msg("audit not found".into()))?;
    let blob = AuditBlobV2::from_bytes(&bytes)?;
    let pt = open_audit_v2(audit_dek, &blob)?;
    ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MemoryStore;

    fn store_pairs(store: &MemoryStore) -> Vec<(Vec<u8>, Vec<u8>)> {
        let bytes = store.export_cbor_skip_session().unwrap();
        ciborium::from_reader(bytes.as_slice()).unwrap()
    }

    #[test]
    fn v2_session_is_memory_only_and_rewraps_same_root() {
        let mut store = MemoryStore::default();
        let mut session = VaultSessionV2::create(&mut store, "correct horse battery staple").unwrap();
        let root = session.root_bytes_for_test();
        session.doc.meta.updated_at = 1;
        session.persist(&mut store).unwrap();

        assert!(store.has(SECRET_ENVELOPE_V2));
        assert!(store.has(SECRET_VAULT_V2));
        assert!(store.has(SECRET_AUDIT_V2));
        assert!(!store.has(SECRET_SESSION));
        assert!(!store.has(b"aegis/v2/session"));
        assert!(!store.has(crate::vault::SECRET_ENVELOPE));
        assert!(!store.has(crate::vault::SECRET_VAULT));
        assert!(!store.has(crate::vault::SECRET_AUDIT));

        for (k, v) in store_pairs(&store) {
            assert!(
                !k.windows(7).any(|w| w == b"session"),
                "v2 store key {:?}",
                String::from_utf8_lossy(&k)
            );
            assert!(!v.windows(32).any(|w| w == root));
        }

        let vault_before = store.get(SECRET_VAULT_V2).unwrap();
        session
            .change_passphrase(&mut store, "correct horse battery staple", "new horse battery staple")
            .unwrap();
        assert_eq!(session.root_bytes_for_test(), root);
        assert_eq!(store.get(SECRET_VAULT_V2).unwrap(), vault_before);

        session.lock(&mut store);
        assert!(!store.has(SECRET_SESSION));
        assert!(VaultSessionV2::unlock(&mut store, "correct horse battery staple").is_err());
        let opened = VaultSessionV2::unlock(&mut store, "new horse battery staple").unwrap();
        assert_eq!(opened.root_bytes_for_test(), root);
        assert_eq!(opened.doc.meta.format_version, 2);
        assert!(!store.has(SECRET_SESSION));
    }

    #[test]
    fn v2_create_rejects_short_passphrase() {
        let mut store = MemoryStore::default();
        assert!(VaultSessionV2::create(&mut store, "short").is_err());
        assert!(!store.has(SECRET_ENVELOPE_V2));
    }

    #[test]
    fn v2_backup_restore_mints_new_identity() {
        use crate::crypto::backup::backup_contains_secret;
        use crate::crypto::envelope_v2::unwrap_root_v2;
        use crate::types::Entry;

        let mut live = MemoryStore::default();
        let mut session = VaultSessionV2::create(&mut live, "live-pass-phrase").unwrap();
        let mut e = Entry::new("e1", "Mail");
        e.password = "same-password-data".into();
        session.doc.entries.insert(e.id.clone(), e);
        session.persist(&mut live).unwrap();
        let live_root = session.root_bytes_for_test();
        let live_dek = session.vault_dek_bytes_for_test();
        let live_vid = session.vault_id_for_test();
        let live_envelope = live.get(SECRET_ENVELOPE_V2).unwrap();

        let backup = session.export_backup("backup-pass-word").unwrap();
        assert_eq!(&backup[..16], b"AEGIS_BACKUP_V2\x02");
        assert!(!backup_contains_secret(&backup, &live_root));
        assert!(!backup_contains_secret(&backup, &live_dek));

        let env = MasterEnvelopeV2::from_bytes(&live_envelope).unwrap();
        assert!(unwrap_root_v2("backup-pass-word", &env).is_err());
        assert!(unwrap_root_v2("live-pass-phrase", &env).is_ok());

        let snapshot = live.export_cbor_skip_session().unwrap();
        assert!(VaultSessionV2::restore_backup(
            &mut live,
            &backup,
            "wrong-backup-xx",
            "new-vault-pass-phrase",
            true
        )
        .is_err());
        assert_eq!(live.export_cbor_skip_session().unwrap(), snapshot);

        let mut restored_store = MemoryStore::default();
        let restored = VaultSessionV2::restore_backup(
            &mut restored_store,
            &backup,
            "backup-pass-word",
            "new-vault-pass-phrase",
            false,
        )
        .unwrap();
        assert_eq!(restored.doc.entries["e1"].password, "same-password-data");
        assert_ne!(restored.vault_id_for_test(), live_vid);
        assert_ne!(restored.root_bytes_for_test(), live_root);
        assert_ne!(restored.vault_dek_bytes_for_test(), live_dek);
        assert!(!restored_store.has(SECRET_SESSION));
        assert!(VaultSessionV2::unlock(&mut restored_store, "live-pass-phrase").is_err());

        let still = VaultSessionV2::unlock(&mut live, "live-pass-phrase").unwrap();
        assert_eq!(still.vault_id_for_test(), live_vid);
        assert_eq!(still.root_bytes_for_test(), live_root);
        assert_eq!(still.doc.entries["e1"].password, "same-password-data");
    }
}
