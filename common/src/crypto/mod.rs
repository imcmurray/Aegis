//! Aegis cryptography: v1 (legacy) plus v2 Core suite/envelopes (Phase 2–4).

mod v1;
pub use v1::*;

pub mod aead;
pub mod backup;
pub mod envelope_v2;
pub mod hkdf_v2;
pub mod hybrid_kem;
pub mod hybrid_sign;
pub mod kdf;
pub mod magic;
pub mod passphrase;
pub mod secret;
pub mod suite;
pub mod transcript;

pub use backup::{
    authenticate_backup, create_backup, BackupEnvelopeV2, BackupPayloadV2, MAX_BACKUP_FILE,
};
pub use envelope_v2::{
    open_audit_v2, open_sync_v2, open_vault_v2, peek_envelope_version, seal_audit_v2, seal_sync_v2,
    seal_vault_v2, unwrap_root_under_recovery, unwrap_root_v2, wrap_existing_root_v2,
    wrap_existing_root_v2_legacy_passphrase, wrap_root_under_recovery, wrap_root_v2,
    wrap_root_v2_with_params, AuditBlobV2, MasterEnvelopeV2, SyncBlobV2, VaultBlobV2,
    MAX_BLOB_CIPHERTEXT, MAX_VAULT_FILE,
};
pub use hkdf_v2::{
    derive_operational_keys, derive_recovery_kek, LABEL_AUDIT_DEK, LABEL_RECOVERY_KEK,
    LABEL_SEARCH_HMAC, LABEL_SHARE_HYBRID_KEK, LABEL_SHARE_MLKEM_SEED, LABEL_SHARE_X25519_SEED,
    LABEL_SYNC_DEK, LABEL_SYNC_ED25519_SEED, LABEL_SYNC_MLDSA_SEED, LABEL_VAULT_DEK,
    ROOT_DERIVED_LABELS,
};
pub use passphrase::{validate_v2_passphrase, V2_PASSPHRASE_MIN_CHARS};
pub use kdf::{
    argon2_work_factor, Argon2ParamsV2, KdfContext, MAX_ARGON2_ITERATIONS, MAX_ARGON2_MEMORY_KIB,
    MAX_ARGON2_PARALLELISM, MAX_ARGON2_WORK, V2_MIN_MEMORY_KIB,
};
pub use secret::{
    AuditDek, BackupKey, BackupWrapKek, OperationalKeys, RecoveryKek, RecoverySecret, RootSecret,
    SearchHmacKey, ShareContentKey, ShareMlkemSeed, ShareX25519Seed, HybridShareSecret, SyncDek,
    SyncEd25519Seed, SyncMldsaSeed, VaultDek, WrapKek,
};
pub use hybrid_sign::{
    verify_hybrid, HybridSignatureV2, HybridSyncIdentityV2, HybridSyncSigner, ED25519_SIG_LEN,
    ED25519_VK_LEN, ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN,
};
pub use magic::{
    decode_backup_v2, decode_recovery_v2, decode_sync_v2, decode_vault_v2, encode_backup_v2,
    encode_recovery_v2, encode_sync_v2, encode_vault_v2, CONTAINER_VERSION_V2, MAGIC_BACKUP_V2,
    MAGIC_RECOVERY_V2, MAGIC_SYNC_V2, MAGIC_VAULT_V2,
};
pub use suite::{
    CryptoSuiteId, ObjectKind, FORMAT_VERSION_V2, KEY_EPOCH_INITIAL, KIND_AUDIT_BLOB,
    KIND_BACKUP_WRAP, KIND_EXPORT_BLOB, KIND_MASTER_WRAP, KIND_RECOVERY_WRAP, KIND_SHARE_ENVELOPE,
    KIND_SHARE_IDENTITY, KIND_SHARE_PAYLOAD, KIND_SYNC_BLOB, KIND_SYNC_REVISION,
    KIND_SYNC_TRANSITION, KIND_VAULT_BLOB, SUITE_V2_CORE_2026, SUITE_V2_SHARE_HYBRID_2026,
    SUITE_V2_SYNC_HYBRID_2026,
};
pub use transcript::{
    build_recovery_wrap_transcript, build_share_identity_transcript, build_share_payload_transcript,
    build_share_transcript, build_sync_signing_transcript, build_sync_transition_transcript,
};
