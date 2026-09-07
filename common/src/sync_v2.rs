//! Phase 7 hybrid VaultSync: Ed25519 AND ML-DSA-65, epoch-aware counters.
//!
//! Inner payload remains [`crate::crypto::SyncBlobV2`] (suite Core). The on-wire
//! revision is suite `AegisV2SyncHybrid2026`. Malformed hybrid objects never
//! fall back to v1 `EncryptedRevision` or Ed25519-only verification.

use crate::crypto::envelope_v2::{open_sync_v2, seal_sync_v2, SyncBlobV2};
use crate::crypto::hybrid_sign::{
    verify_hybrid, HybridSignatureV2, HybridSyncIdentityV2, HybridSyncSigner, ED25519_SIG_LEN,
    ED25519_VK_LEN, ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN,
};
use crate::crypto::magic::{decode_sync_v2, encode_sync_v2};
use crate::crypto::secret::OperationalKeys;
use crate::crypto::suite::{CryptoSuiteId, FORMAT_VERSION_V2};
use crate::crypto::transcript::{
    build_sync_signing_transcript, build_sync_transition_transcript,
};
use crate::crypto::{CryptoError, MAGIC_SYNC_V2};
use crate::sync::{data_differs, doc_rank, merge_docs, SyncAction, SyncReport};
use crate::types::{unix_now, VaultDocument};
use crate::vault::{SecretStore, StoreOp, VaultError};
use serde::{Deserialize, Serialize};

/// Freenet contract discriminator (params.app). Not D10 file magic.
/// External v2 sync bytes use [`crate::crypto::MAGIC_SYNC_V2`] (`AEGIS_SYNC_V2`).
pub const APP_VAULT_SYNC_V2: &str = "AEGIS_VAULT_SYNC_V2";

pub const SECRET_SYNC_STATE_V2: &[u8] = b"aegis/v2/sync-state";
pub const SECRET_SYNC_ACCEPTED_V2: &[u8] = b"aegis/v2/sync-accepted";
pub const SECRET_SYNC_COUNTER_V2: &[u8] = b"aegis/v2/sync-counter";
pub const SECRET_SYNC_TRANSITION_V2: &[u8] = b"aegis/v2/sync-transition";

/// Freenet / contract parameters for a v2 hybrid instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultSyncParamsV2 {
    #[serde(with = "serde_bytes")]
    pub ed25519_verifying_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ml_dsa_verifying_key: Vec<u8>,
    pub app: String,
}

impl VaultSyncParamsV2 {
    pub fn from_identity(id: &HybridSyncIdentityV2) -> Self {
        Self {
            ed25519_verifying_key: id.ed25519_vk.clone(),
            ml_dsa_verifying_key: id.ml_dsa_vk.clone(),
            app: APP_VAULT_SYNC_V2.into(),
        }
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.app != APP_VAULT_SYNC_V2 {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.ed25519_verifying_key.len() != ED25519_VK_LEN
            || self.ml_dsa_verifying_key.len() != ML_DSA_65_VK_LEN
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(())
    }

    pub fn identity(&self) -> Result<HybridSyncIdentityV2, CryptoError> {
        self.validate()?;
        Ok(HybridSyncIdentityV2 {
            ed25519_vk: self.ed25519_verifying_key.clone(),
            ml_dsa_vk: self.ml_dsa_verifying_key.clone(),
        })
    }
}

/// One hybrid-signed encrypted vault revision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedRevisionV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    pub device_id: String,
    pub counter: u64,
    pub parent_hash: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ed25519_vk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ml_dsa_vk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ed25519_signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ml_dsa_signature: Vec<u8>,
}

impl EncryptedRevisionV2 {
    pub fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_sync_hybrid()?;
        if self.vault_id.len() != 16 {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.ed25519_vk.len() != ED25519_VK_LEN
            || self.ml_dsa_vk.len() != ML_DSA_65_VK_LEN
            || self.ed25519_signature.len() != ED25519_SIG_LEN
            || self.ml_dsa_signature.len() != ML_DSA_65_SIG_LEN
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.ciphertext.is_empty()
            || self.ciphertext.len() > VaultSyncStateV2::MAX_CIPHERTEXT
        {
            return Err(CryptoError::ResourceLimit);
        }
        let hash = blake3::hash(&self.ciphertext);
        if hash.as_bytes() != &self.ciphertext_hash {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(())
    }

    pub fn vault_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }

    pub fn identity(&self) -> HybridSyncIdentityV2 {
        HybridSyncIdentityV2 {
            ed25519_vk: self.ed25519_vk.clone(),
            ml_dsa_vk: self.ml_dsa_vk.clone(),
        }
    }

    pub fn hybrid_signature(&self) -> HybridSignatureV2 {
        HybridSignatureV2 {
            ed25519: self.ed25519_signature.clone(),
            ml_dsa: self.ml_dsa_signature.clone(),
        }
    }

    pub fn signing_transcript(&self) -> Result<Vec<u8>, CryptoError> {
        let vault_id = self.vault_id_bytes()?;
        let metadata = self.identity().metadata()?;
        Ok(build_sync_signing_transcript(
            &vault_id,
            self.key_epoch,
            self.device_id.as_bytes(),
            self.counter,
            &self.parent_hash,
            &self.ciphertext_hash,
            &metadata,
        ))
    }

    pub fn revision_hash(&self) -> Result<[u8; 32], CryptoError> {
        Ok(*blake3::hash(&self.signing_transcript()?).as_bytes())
    }
}

/// Dual-signed old↔new hybrid identity continuity record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncIdentityTransitionV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub old_epoch: u32,
    pub new_epoch: u32,
    pub old_identity: HybridSyncIdentityV2,
    pub new_identity: HybridSyncIdentityV2,
    #[serde(with = "serde_bytes")]
    pub old_signs_new_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub old_signs_new_ml_dsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub new_signs_old_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub new_signs_old_ml_dsa: Vec<u8>,
}

impl SyncIdentityTransitionV2 {
    pub fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_sync_hybrid()?;
        if self.vault_id.len() != 16 {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.new_epoch != self.old_epoch.saturating_add(1) {
            return Err(CryptoError::InvalidEnvelope);
        }
        self.old_identity.validate()?;
        self.new_identity.validate()?;
        if self.old_signs_new_ed25519.len() != ED25519_SIG_LEN
            || self.old_signs_new_ml_dsa.len() != ML_DSA_65_SIG_LEN
            || self.new_signs_old_ed25519.len() != ED25519_SIG_LEN
            || self.new_signs_old_ml_dsa.len() != ML_DSA_65_SIG_LEN
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(())
    }

    pub fn vault_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }

    pub fn signing_transcript(&self) -> Result<Vec<u8>, CryptoError> {
        let vault_id = self.vault_id_bytes()?;
        Ok(build_sync_transition_transcript(
            &vault_id,
            self.old_epoch,
            self.new_epoch,
            &self.old_identity.metadata()?,
            &self.new_identity.metadata()?,
        ))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultSyncStateV2 {
    pub revisions: Vec<EncryptedRevisionV2>,
    #[serde(default)]
    pub transitions: Vec<SyncIdentityTransitionV2>,
}

impl VaultSyncStateV2 {
    pub const MAX_REVISIONS: usize = 8;
    pub const MAX_CIPHERTEXT: usize = 8 * 1024 * 1024;
    pub const MAX_TRANSITIONS: usize = 8;

    pub fn merge(&mut self, other: &VaultSyncStateV2) {
        for rev in &other.revisions {
            let _ = self.upsert(rev.clone());
        }
        for t in &other.transitions {
            if !self.transitions.iter().any(|e| e == t) {
                self.transitions.push(t.clone());
            }
        }
        self.prune();
    }

    /// Insert if this (device, epoch) counter is strictly newer. Returns whether stored.
    pub fn upsert(&mut self, rev: EncryptedRevisionV2) -> bool {
        if let Some(existing) = self
            .revisions
            .iter_mut()
            .find(|e| e.device_id == rev.device_id && e.key_epoch == rev.key_epoch)
        {
            if rev.counter <= existing.counter {
                return false;
            }
            *existing = rev;
            self.prune();
            return true;
        }
        self.revisions.push(rev);
        self.prune();
        true
    }

    fn prune(&mut self) {
        if self.revisions.len() > Self::MAX_REVISIONS {
            self.revisions
                .sort_by_key(|r| std::cmp::Reverse((r.key_epoch, r.counter)));
            self.revisions.truncate(Self::MAX_REVISIONS);
        }
        if self.transitions.len() > Self::MAX_TRANSITIONS {
            self.transitions
                .sort_by_key(|t| std::cmp::Reverse(t.new_epoch));
            self.transitions.truncate(Self::MAX_TRANSITIONS);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptedEntryV2 {
    pub device_id: String,
    pub key_epoch: u32,
    pub counter: u64,
    pub revision_hash: [u8; 32],
}

/// Persisted last-accepted counters per (device, epoch). Enables replay and
/// coherent rollback detection when this device retains newer state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncAcceptedTableV2 {
    pub entries: Vec<AcceptedEntryV2>,
    /// Data revisions below this epoch are stale after a verified transition.
    pub min_epoch: u32,
}

impl SyncAcceptedTableV2 {
    pub fn get(&self, device_id: &str, key_epoch: u32) -> Option<&AcceptedEntryV2> {
        self.entries
            .iter()
            .find(|e| e.device_id == device_id && e.key_epoch == key_epoch)
    }

    pub fn record(&mut self, device_id: String, key_epoch: u32, counter: u64, revision_hash: [u8; 32]) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.device_id == device_id && e.key_epoch == key_epoch)
        {
            e.counter = counter;
            e.revision_hash = revision_hash;
            return;
        }
        self.entries.push(AcceptedEntryV2 {
            device_id,
            key_epoch,
            counter,
            revision_hash,
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncCounterV2 {
    pub key_epoch: u32,
    pub counter: u64,
}

pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn decode_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| e.to_string())
}

/// Decode v2 sync CBOR. Magic-framed files use D10 `AEGIS_SYNC_V2 || 0x02`.
/// Other Aegis magics (including the Freenet app id `AEGIS_VAULT_SYNC_V2`) are
/// not file magic and are rejected before CBOR. Secret-store snapshots are
/// raw CBOR without a prefix.
pub fn decode_state_v2(bytes: &[u8]) -> Result<VaultSyncStateV2, CryptoError> {
    if bytes.len() > crate::crypto::backup::MAX_BACKUP_FILE {
        return Err(CryptoError::ResourceLimit);
    }
    let cbor = if bytes.starts_with(MAGIC_SYNC_V2) {
        decode_sync_v2(bytes)?
    } else if looks_like_other_aegis_magic(bytes) {
        return Err(CryptoError::InvalidMagic);
    } else {
        bytes
    };
    let state: VaultSyncStateV2 =
        ciborium::from_reader(cbor).map_err(|e| CryptoError::Serde(e.to_string()))?;
    Ok(state)
}

fn looks_like_other_aegis_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(crate::crypto::MAGIC_VAULT_V2)
        || bytes.starts_with(crate::crypto::MAGIC_BACKUP_V2)
        || bytes.starts_with(crate::crypto::MAGIC_RECOVERY_V2)
        || bytes.starts_with(b"AEGIS_VAULT_SYNC_V2")
}

pub fn encode_state_v2_file(state: &VaultSyncStateV2) -> Result<Vec<u8>, CryptoError> {
    let cbor = encode_cbor(state).map_err(CryptoError::Serde)?;
    Ok(encode_sync_v2(&cbor))
}

/// Verify a revision against a **trusted** identity.
///
/// `expected` must be the authorized [`HybridSyncIdentityV2`] for this vault
/// and accepted epoch — derived from the unlocked RootSecret hierarchy, or
/// the new identity after a dual-signed [`SyncIdentityTransitionV2`]. It must
/// never be taken from `rev.ed25519_vk` / `rev.ml_dsa_vk` alone: those fields
/// are untrusted wire claims. Both signatures are checked only after the
/// wire keys match `expected`.
pub fn verify_revision_v2(
    expected: &HybridSyncIdentityV2,
    rev: &EncryptedRevisionV2,
) -> Result<(), CryptoError> {
    rev.validate_header()?;
    expected.validate()?;
    if rev.identity() != *expected {
        return Err(CryptoError::UnauthorizedSyncIdentity);
    }
    let transcript = rev.signing_transcript()?;
    verify_hybrid(expected, &transcript, &rev.hybrid_signature())
}

/// Contract path: verify against params identity. Never Ed25519-only.
pub fn verify_revision_against_params(
    params: &VaultSyncParamsV2,
    rev: &EncryptedRevisionV2,
) -> Result<(), CryptoError> {
    let id = params.identity()?;
    verify_revision_v2(&id, rev)
}

pub fn verify_transition_v2(t: &SyncIdentityTransitionV2) -> Result<(), CryptoError> {
    t.validate_header()?;
    let transcript = t.signing_transcript()?;
    let old_sig = HybridSignatureV2 {
        ed25519: t.old_signs_new_ed25519.clone(),
        ml_dsa: t.old_signs_new_ml_dsa.clone(),
    };
    let new_sig = HybridSignatureV2 {
        ed25519: t.new_signs_old_ed25519.clone(),
        ml_dsa: t.new_signs_old_ml_dsa.clone(),
    };
    verify_hybrid(&t.old_identity, &transcript, &old_sig)?;
    verify_hybrid(&t.new_identity, &transcript, &new_sig)?;
    Ok(())
}

pub fn sign_revision_v2(
    signer: &HybridSyncSigner,
    vault_id: [u8; 16],
    key_epoch: u32,
    device_id: &str,
    counter: u64,
    parent_hash: [u8; 32],
    ciphertext: Vec<u8>,
) -> Result<EncryptedRevisionV2, CryptoError> {
    let identity = signer.identity();
    let ciphertext_hash = *blake3::hash(&ciphertext).as_bytes();
    let metadata = identity.metadata()?;
    let transcript = build_sync_signing_transcript(
        &vault_id,
        key_epoch,
        device_id.as_bytes(),
        counter,
        &parent_hash,
        &ciphertext_hash,
        &metadata,
    );
    let sig = signer.sign(&transcript);
    let rev = EncryptedRevisionV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2SyncHybrid2026,
        vault_id: vault_id.to_vec(),
        key_epoch,
        device_id: device_id.to_string(),
        counter,
        parent_hash,
        ciphertext_hash,
        ciphertext,
        ed25519_vk: identity.ed25519_vk,
        ml_dsa_vk: identity.ml_dsa_vk,
        ed25519_signature: sig.ed25519,
        ml_dsa_signature: sig.ml_dsa,
    };
    rev.validate_header()?;
    Ok(rev)
}

pub fn sign_transition_v2(
    old_signer: &HybridSyncSigner,
    new_signer: &HybridSyncSigner,
    vault_id: [u8; 16],
    old_epoch: u32,
    new_epoch: u32,
) -> Result<SyncIdentityTransitionV2, CryptoError> {
    let old_identity = old_signer.identity();
    let new_identity = new_signer.identity();
    let transcript = build_sync_transition_transcript(
        &vault_id,
        old_epoch,
        new_epoch,
        &old_identity.metadata()?,
        &new_identity.metadata()?,
    );
    let old_sig = old_signer.sign(&transcript);
    let new_sig = new_signer.sign(&transcript);
    let t = SyncIdentityTransitionV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2SyncHybrid2026,
        vault_id: vault_id.to_vec(),
        old_epoch,
        new_epoch,
        old_identity,
        new_identity,
        old_signs_new_ed25519: old_sig.ed25519,
        old_signs_new_ml_dsa: old_sig.ml_dsa,
        new_signs_old_ed25519: new_sig.ed25519,
        new_signs_old_ml_dsa: new_sig.ml_dsa,
    };
    verify_transition_v2(&t)?;
    Ok(t)
}

pub fn seal_doc_for_sync_v2(
    keys: &OperationalKeys,
    vault_id: [u8; 16],
    key_epoch: u32,
    doc: &VaultDocument,
) -> Result<Vec<u8>, VaultError> {
    let mut pt = Vec::new();
    ciborium::into_writer(doc, &mut pt).map_err(|e| VaultError::Serde(e.to_string()))?;
    let blob = seal_sync_v2(&keys.sync_dek, vault_id, key_epoch, &pt)?;
    Ok(blob.to_cbor()?)
}

pub fn open_doc_from_sync_v2(
    keys: &OperationalKeys,
    vault_id: [u8; 16],
    key_epoch: u32,
    ciphertext: &[u8],
) -> Result<VaultDocument, VaultError> {
    let blob = SyncBlobV2::from_cbor(ciphertext)?;
    if blob.key_epoch != key_epoch {
        return Err(VaultError::Msg("sync blob key_epoch mismatch".into()));
    }
    let vid: [u8; 16] = blob
        .vault_id
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Msg("sync blob vault_id".into()))?;
    if vid != vault_id {
        return Err(VaultError::Msg("sync blob vault_id mismatch".into()));
    }
    let pt = open_sync_v2(&keys.sync_dek, &blob)?;
    ciborium::from_reader(pt.as_slice()).map_err(|e| VaultError::Serde(e.to_string()))
}

pub fn check_monotonic(
    accepted: &SyncAcceptedTableV2,
    rev: &EncryptedRevisionV2,
) -> Result<[u8; 32], VaultError> {
    if rev.key_epoch < accepted.min_epoch {
        return Err(VaultError::Msg("stale epoch revision".into()));
    }
    let hash = rev
        .revision_hash()
        .map_err(|e| VaultError::Msg(e.to_string()))?;
    match accepted.get(&rev.device_id, rev.key_epoch) {
        None => {
            // First time this device+epoch is seen. Parent chaining applies
            // once we retain newer state (coherent rollback / substitution).
            Ok(hash)
        }
        Some(prev) => {
            if rev.counter <= prev.counter {
                return Err(VaultError::Msg("replayed or stale revision".into()));
            }
            if rev.parent_hash != prev.revision_hash {
                return Err(VaultError::Msg("history substitution".into()));
            }
            Ok(hash)
        }
    }
}

/// Apply a remote revision that has already passed hybrid verify + identity match.
fn apply_verified_revision(
    keys: &OperationalKeys,
    vault_id: [u8; 16],
    key_epoch: u32,
    local_identity: &HybridSyncIdentityV2,
    accepted: &mut SyncAcceptedTableV2,
    local_doc: &mut VaultDocument,
    device_id: &str,
    rev: &EncryptedRevisionV2,
) -> Result<bool, VaultError> {
    if rev.vault_id_bytes().ok() != Some(vault_id) {
        return Ok(false);
    }
    if rev.key_epoch != key_epoch {
        return Ok(false);
    }
    if &rev.identity() != local_identity {
        return Ok(false);
    }
    let hash = match check_monotonic(accepted, rev) {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    let remote_doc = match open_doc_from_sync_v2(keys, vault_id, key_epoch, &rev.ciphertext) {
        Ok(d) => d,
        Err(_) => return Ok(false),
    };
    let before = local_doc.clone();
    if doc_rank(&remote_doc) > doc_rank(local_doc)
        && (local_doc.entries.is_empty() || remote_doc.meta.updated_at > local_doc.meta.updated_at)
    {
        let keep = device_id.to_string();
        *local_doc = remote_doc;
        local_doc.meta.device_id = keep;
    } else {
        *local_doc = merge_docs(local_doc, &remote_doc, device_id);
    }
    accepted.record(rev.device_id.clone(), rev.key_epoch, rev.counter, hash);
    Ok(data_differs(&before, local_doc))
}

pub fn sync_vault_v2(
    keys: &OperationalKeys,
    vault_id: [u8; 16],
    key_epoch: u32,
    device_id: &str,
    local_doc: &mut VaultDocument,
    accepted: &mut SyncAcceptedTableV2,
    counter: &mut u64,
    state: &mut VaultSyncStateV2,
) -> Result<SyncReport, VaultError> {
    let signer = HybridSyncSigner::from_operational_keys(keys);
    let local_identity = signer.identity();

    for t in &state.transitions {
        if verify_transition_v2(t).is_err() {
            continue;
        }
        if t.vault_id_bytes().ok() != Some(vault_id) {
            continue;
        }
        if t.new_identity == local_identity && t.new_epoch == key_epoch {
            accepted.min_epoch = accepted.min_epoch.max(t.new_epoch);
        }
    }

    let mut applied_remote = false;
    let remote_snapshot = state.revisions.clone();
    for rev in &remote_snapshot {
        if verify_revision_v2(&local_identity, rev).is_err() {
            continue;
        }
        if apply_verified_revision(
            keys,
            vault_id,
            key_epoch,
            &local_identity,
            accepted,
            local_doc,
            device_id,
            rev,
        )? {
            applied_remote = true;
        }
    }

    local_doc.meta.device_id = device_id.to_string();
    if applied_remote {
        local_doc.meta.updated_at = unix_now().max(local_doc.meta.updated_at);
    }

    if let Some(prev) = accepted.get(device_id, key_epoch) {
        if prev.counter > *counter {
            *counter = prev.counter;
        }
    }

    let already_semantic = remote_snapshot.iter().any(|rev| {
        open_doc_from_sync_v2(keys, vault_id, key_epoch, &rev.ciphertext)
            .map(|d| !data_differs(&d, local_doc))
            .unwrap_or(false)
    });

    let ciphertext = seal_doc_for_sync_v2(keys, vault_id, key_epoch, local_doc)?;
    let content_hash = *blake3::hash(&ciphertext).as_bytes();
    let already = already_semantic
        || state
            .revisions
            .iter()
            .any(|r| r.ciphertext_hash == content_hash && r.key_epoch == key_epoch);

    let published = if !already {
        let parent = accepted
            .get(device_id, key_epoch)
            .map(|e| e.revision_hash)
            .unwrap_or([0u8; 32]);
        *counter = counter.saturating_add(1);
        let rev = sign_revision_v2(
            &signer,
            vault_id,
            key_epoch,
            device_id,
            *counter,
            parent,
            ciphertext,
        )?;
        let hash = rev.revision_hash()?;
        verify_revision_v2(&local_identity, &rev)?;
        state.upsert(rev);
        accepted.record(device_id.to_string(), key_epoch, *counter, hash);
        true
    } else {
        false
    };

    let action = match (applied_remote, published) {
        (false, false) => SyncAction::UpToDate,
        (false, true) => SyncAction::Pushed,
        (true, false) => SyncAction::Pulled,
        (true, true) => SyncAction::Merged,
    };
    Ok(SyncReport {
        action,
        remote_revisions: state.revisions.len() as u32,
        detail: match action {
            SyncAction::UpToDate => "already in sync".into(),
            SyncAction::Pulled => "applied remote changes".into(),
            SyncAction::Merged => "merged local and remote".into(),
            SyncAction::Pushed => "published local vault".into(),
        },
    })
}

/// In-memory v2 MVR + accepted table, loaded/committed via the secret store.
pub struct StoreSyncBufferV2 {
    pub state: VaultSyncStateV2,
    pub accepted: SyncAcceptedTableV2,
    pub counter: SyncCounterV2,
}

impl StoreSyncBufferV2 {
    pub fn load(store: &dyn SecretStore, key_epoch: u32) -> Result<Self, String> {
        let state = match store.get(SECRET_SYNC_STATE_V2) {
            None => VaultSyncStateV2::default(),
            Some(bytes) if bytes.is_empty() => VaultSyncStateV2::default(),
            Some(bytes) => decode_state_v2(&bytes).map_err(|e| e.to_string())?,
        };
        let accepted = match store.get(SECRET_SYNC_ACCEPTED_V2) {
            None => SyncAcceptedTableV2::default(),
            Some(bytes) if bytes.is_empty() => SyncAcceptedTableV2::default(),
            Some(bytes) => decode_cbor(&bytes)?,
        };
        let counter = match store.get(SECRET_SYNC_COUNTER_V2) {
            None => SyncCounterV2 {
                key_epoch,
                counter: 0,
            },
            Some(bytes) if bytes.is_empty() => SyncCounterV2 {
                key_epoch,
                counter: 0,
            },
            Some(bytes) => {
                let c: SyncCounterV2 = decode_cbor(&bytes)?;
                if c.key_epoch != key_epoch {
                    SyncCounterV2 {
                        key_epoch,
                        counter: 0,
                    }
                } else {
                    c
                }
            }
        };
        let mut buf = Self {
            state,
            accepted,
            counter,
        };
        if let Some(bytes) = store.get(SECRET_SYNC_TRANSITION_V2) {
            if !bytes.is_empty() {
                if let Ok(t) = decode_cbor::<SyncIdentityTransitionV2>(&bytes) {
                    if !buf.state.transitions.iter().any(|e| e == &t) {
                        buf.state.transitions.push(t);
                    }
                }
            }
        }
        Ok(buf)
    }

    pub fn merge_remote_cbor(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }
        let remote = decode_state_v2(bytes).map_err(|e| e.to_string())?;
        self.state.merge(&remote);
        Ok(())
    }

    pub fn commit(&self, store: &mut dyn SecretStore) -> Result<(), String> {
        store
            .commit(&[
                StoreOp::put(SECRET_SYNC_STATE_V2, encode_cbor(&self.state)?),
                StoreOp::put(SECRET_SYNC_ACCEPTED_V2, encode_cbor(&self.accepted)?),
                StoreOp::put(SECRET_SYNC_COUNTER_V2, encode_cbor(&self.counter)?),
            ])
            .map_err(|e| format!("atomic commit failed: {e}"))
    }

    pub fn encode_cbor(&self) -> Result<Vec<u8>, String> {
        encode_cbor(&self.state)
    }
}
