//! Phase 5 / PR G: v2 is the production vault format.

use crate::crypto::{
    derive_keys, derive_operational_keys, open_vault_v2, unwrap_master, unwrap_root_v2, KdfProfile,
    MasterEnvelope, MasterEnvelopeV2, RootSecret, VaultBlobV2, CONTAINER_VERSION_V2,
    KEY_EPOCH_INITIAL, MAGIC_BACKUP_V2, MAGIC_VAULT_V2, SUITE_V2_CORE_2026, V2_MIN_MEMORY_KIB,
};
use crate::file_store::FileStore;
use crate::gen_store::GenerationStore;
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::migrate::{
    decode_v1_vault_id, migrate_live_v1_to_v2, migrate_live_v1_to_v2_with_recovery,
};
use crate::recovery_v2::{decode_recovery_secret, unwrap_recovery, RecoveryWrapV2, SECRET_RECOVERY_V2};
use crate::session_v2::{SECRET_AUDIT_V2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2};
use crate::types::Entry;
use crate::vault::{
    dispatch, import_bundle, ActiveSession, MemoryStore, SecretStore, StoreOp, VaultSession,
    SECRET_ENVELOPE, SECRET_RECOVERY, SECRET_SESSION, SECRET_SYNC_COUNTER, SECRET_SYNC_STATE,
    SECRET_VAULT,
    UNSUPPORTED_ATOMIC_COMMIT,
};

const VAULT_PASSPHRASE: &str = "correct horse battery staple";
const EXPORT_PASSPHRASE: &str = "export-passphrase-v1";
const ENTRY_NAME: &str = "GitHub";
const NEW_PASSWORD: &str = "new-password-v1";

fn fixture_dir(profile: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/v1")
        .join(profile)
}

fn load_bytes(profile: &str, name: &str) -> Vec<u8> {
    std::fs::read(fixture_dir(profile).join(name)).unwrap_or_else(|e| {
        panic!("missing fixture tests/fixtures/v1/{profile}/{name}: {e}")
    })
}

fn load_text(profile: &str, name: &str) -> String {
    String::from_utf8(load_bytes(profile, name))
        .unwrap()
        .trim()
        .to_string()
}

fn load_store(profile: &str) -> MemoryStore {
    let mut store = MemoryStore::default();
    store
        .import_cbor(&load_bytes(profile, "store.cbor"))
        .expect("store.cbor");
    store
}

fn assert_fixture_entry(doc: &crate::types::VaultDocument) {
    assert_eq!(doc.folders.len(), 1);
    assert_eq!(doc.entries.len(), 1);
    let entry = doc.entries.values().next().unwrap();
    assert_eq!(entry.name, ENTRY_NAME);
    assert_eq!(entry.username, "octocat");
    assert_eq!(entry.password, NEW_PASSWORD);
    assert_eq!(entry.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(entry.notes, "v1 fixture notes");
    assert_eq!(entry.urls, vec!["https://github.com".to_string()]);
    assert_eq!(entry.tags, vec!["dev".to_string()]);
    assert_eq!(entry.password_history.len(), 1);
    assert_eq!(entry.password_history[0].password, "old-password-v1");
    assert_eq!(entry.custom_fields.len(), 1);
    assert_eq!(entry.custom_fields[0].value, "1234");
}

struct FailCommitStore {
    inner: MemoryStore,
    fail: bool,
}

impl SecretStore for FailCommitStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.inner.set(key, value)
    }
    fn remove(&mut self, key: &[u8]) {
        self.inner.remove(key)
    }
    fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String> {
        if self.fail {
            return Err("simulated persistence failure".into());
        }
        self.inner.commit(ops)
    }
}

fn scan_forbidden(store: &MemoryStore, needles: &[&[u8]], label: &str) {
    for n in needles {
        assert!(
            !store.contains_plaintext(n),
            "{label}: secret leaked into persisted bytes"
        );
    }
}

#[test]
fn production_create_emits_only_v2() {
    let mut store = MemoryStore::default();
    let mut session = None;
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::CreateVault {
            passphrase: VAULT_PASSPHRASE.into(),
            kdf_profile: crate::crypto::KdfProfile::Test,
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    assert!(store.has(SECRET_ENVELOPE_V2));
    assert!(store.has(SECRET_VAULT_V2));
    assert!(store.has(SECRET_AUDIT_V2));
    assert!(!store.has(SECRET_ENVELOPE));
    assert!(!store.has(SECRET_VAULT));
    assert!(!store.has(SECRET_SESSION));
    assert!(!store.has(b"aegis/v2/session"));
    assert!(!store.has(SECRET_RECOVERY));

    let env = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_eq!(env.crypto_suite.to_u16(), SUITE_V2_CORE_2026);
    assert_eq!(env.key_epoch, KEY_EPOCH_INITIAL);
    assert_eq!(env.kdf.memory_kib, V2_MIN_MEMORY_KIB);
    assert_eq!(env.kdf.iterations, 3);
    assert_eq!(env.kdf.parallelism, 1);
    let raw = store.get(SECRET_ENVELOPE_V2).unwrap();
    assert!(raw.starts_with(MAGIC_VAULT_V2));
    assert_eq!(raw[MAGIC_VAULT_V2.len()], CONTAINER_VERSION_V2);

    let root = unwrap_root_v2(VAULT_PASSPHRASE, &env).unwrap();
    let vid = env.vault_id_bytes().unwrap();
    let keys = derive_operational_keys(&root, &vid).unwrap();
    scan_forbidden(
        &store,
        &[
            root.as_bytes().as_slice(),
            keys.vault_dek.as_bytes().as_slice(),
            keys.audit_dek.as_bytes().as_slice(),
            keys.sync_dek.as_bytes().as_slice(),
            keys.search_hmac.as_bytes().as_slice(),
            keys.sync_ed25519_seed.as_bytes().as_slice(),
            keys.sync_mldsa_seed.as_bytes().as_slice(),
            keys.share_x25519_seed.as_bytes().as_slice(),
            keys.share_mlkem_seed.as_bytes().as_slice(),
        ],
        "create",
    );

    dispatch(&mut store, &mut session, VaultRequest::Lock);
    assert!(session.is_none());
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    assert!(!store.has(SECRET_SESSION));
}

#[test]
fn production_create_enforces_d18() {
    let mut store = MemoryStore::default();
    let mut session = None;
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::CreateVault {
            passphrase: "short".into(),
            kdf_profile: crate::crypto::KdfProfile::Test,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { code: ErrorCode::InvalidRequest, .. }),
        "{r:?}"
    );
    assert!(!store.has(SECRET_ENVELOPE_V2));
}

fn migrate_profile(profile: &str) {
    let mut store = load_store(profile);
    let envelope = MasterEnvelope::from_cbor(&load_bytes(profile, "envelope.cbor")).unwrap();
    let v1_id = decode_v1_vault_id(&envelope.vault_id).unwrap();
    let master = unwrap_master(VAULT_PASSPHRASE, &envelope).unwrap();
    let v1_keys = derive_keys(&master).unwrap();
    let before = store.durable_pairs();
    let old_recovery = load_text(profile, "recovery-key.txt");

    let mut session = None;
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    assert!(session.as_ref().unwrap().is_v1());
    let upsert = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UpsertEntry {
            entry: Entry::new("", "blocked"),
        },
    );
    assert!(
        matches!(
            upsert,
            VaultResponse::Error {
                code: ErrorCode::MigrationRequired,
                ..
            }
        ),
        "v1 writes must require migration: {upsert:?}"
    );
    assert_eq!(before, store.durable_pairs(), "readonly unlock must not mutate");

    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::MigrateVault {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    let (vault_id, recovery_secret) = match r {
        VaultResponse::Migrated {
            vault_id,
            recovery_secret,
        } => (vault_id, recovery_secret),
        other => panic!("migrate: {other:?}"),
    };
    assert_eq!(hex::decode(&vault_id).unwrap(), v1_id);
    assert!(store.has(SECRET_ENVELOPE_V2));
    assert!(!store.has(SECRET_ENVELOPE));
    assert!(!store.has(SECRET_VAULT));
    assert!(!store.has(SECRET_RECOVERY));
    assert!(!store.has(SECRET_SESSION));
    assert!(store.has(SECRET_RECOVERY_V2));

    let env_v2 = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_eq!(env_v2.crypto_suite.to_u16(), SUITE_V2_CORE_2026);
    assert_eq!(env_v2.key_epoch, 0);
    assert_eq!(env_v2.kdf.memory_kib, V2_MIN_MEMORY_KIB);
    assert_eq!(env_v2.vault_id_bytes().unwrap(), v1_id);

    let root = unwrap_root_v2(VAULT_PASSPHRASE, &env_v2).unwrap();
    assert_ne!(root.as_bytes(), master.as_bytes());
    let keys = derive_operational_keys(&root, &v1_id).unwrap();
    assert_ne!(keys.vault_dek.as_bytes(), v1_keys.vault_dek.as_bytes());

    let blob = VaultBlobV2::from_bytes(&store.get(SECRET_VAULT_V2).unwrap()).unwrap();
    let reused = RootSecret::from_bytes(*master.as_bytes());
    let reused_keys = derive_operational_keys(&reused, &v1_id).unwrap();
    assert!(open_vault_v2(&reused_keys.vault_dek, &blob).is_err());
    let pt = open_vault_v2(&keys.vault_dek, &blob).unwrap();
    let doc: crate::types::VaultDocument =
        ciborium::from_reader(pt.as_slice()).unwrap();
    assert_eq!(doc.meta.format_version, 2);
    assert_fixture_entry(&doc);

    let rec_secret = decode_recovery_secret(&recovery_secret).unwrap();
    scan_forbidden(
        &store,
        &[
            root.as_bytes().as_slice(),
            keys.vault_dek.as_bytes().as_slice(),
            keys.audit_dek.as_bytes().as_slice(),
            rec_secret.as_bytes().as_slice(),
        ],
        "migrated",
    );

    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: old_recovery,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "old v1 recovery must not unlock v2: {r:?}"
    );
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: recovery_secret.clone(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");

    let wrap = RecoveryWrapV2::from_cbor(&store.get(SECRET_RECOVERY_V2).unwrap()).unwrap();
    let rec = decode_recovery_secret(&recovery_secret).unwrap();
    let unwrapped = unwrap_recovery(&wrap, &rec).unwrap();
    assert_eq!(unwrapped.as_bytes(), root.as_bytes());
}

#[test]
fn live_migrate_test_kdf_fixture() {
    migrate_profile("test-kdf");
}

#[test]
fn live_migrate_interactive_kdf_fixture() {
    migrate_profile("interactive-kdf");
}

#[test]
fn v1_master_secret_cannot_open_migrated_v2_vault() {
    let mut store = load_store("test-kdf");
    let envelope = MasterEnvelope::from_cbor(&store.get(SECRET_ENVELOPE).unwrap()).unwrap();
    let master = unwrap_master(VAULT_PASSPHRASE, &envelope).unwrap();
    migrate_live_v1_to_v2(&mut store, VAULT_PASSPHRASE).unwrap();
    let env_v2 = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    let blob = VaultBlobV2::from_bytes(&store.get(SECRET_VAULT_V2).unwrap()).unwrap();
    let vid = env_v2.vault_id_bytes().unwrap();
    let reused = RootSecret::from_bytes(*master.as_bytes());
    let reused_keys = derive_operational_keys(&reused, &vid).unwrap();
    assert!(open_vault_v2(&reused_keys.vault_dek, &blob).is_err());
    let root = unwrap_root_v2(VAULT_PASSPHRASE, &env_v2).unwrap();
    assert_ne!(root.as_bytes(), master.as_bytes());
    let keys = derive_operational_keys(&root, &vid).unwrap();
    assert!(open_vault_v2(&keys.vault_dek, &blob).is_ok());
}

#[test]
fn failed_migration_leaves_v1_byte_for_byte() {
    let inner = load_store("test-kdf");
    let before = inner.durable_pairs();
    let mut store = FailCommitStore {
        inner,
        fail: true,
    };
    let err = migrate_live_v1_to_v2(&mut store, VAULT_PASSPHRASE);
    assert!(err.is_err(), "commit failure must surface");
    assert_eq!(before, store.inner.durable_pairs());
    let mut session = None;
    let r = dispatch(
        &mut store.inner,
        &mut session,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    assert!(session.as_ref().unwrap().is_v1());
}

#[test]
fn wrong_passphrase_migration_leaves_v1() {
    let mut store = load_store("test-kdf");
    let before = store.durable_pairs();
    let err = migrate_live_v1_to_v2(&mut store, "definitely-wrong-passphrase");
    assert!(err.is_err());
    assert_eq!(before, store.durable_pairs());
}

#[test]
fn malformed_vault_id_migration_leaves_v1() {
    let mut store = load_store("test-kdf");
    let env_bytes = store.get(SECRET_ENVELOPE).unwrap();
    let mut envelope = MasterEnvelope::from_cbor(&env_bytes).unwrap();
    envelope.vault_id = "not-a-valid-hex-vault-id".into();
    store.set(SECRET_ENVELOPE, &envelope.to_cbor().unwrap());
    let before = store.durable_pairs();
    let err = migrate_live_v1_to_v2(&mut store, VAULT_PASSPHRASE);
    assert!(err.is_err());
    assert_eq!(before, store.durable_pairs());
}

#[test]
fn vaultsync_active_defers_passphrase_and_recovery_migration() {
    let old_recovery = load_text("test-kdf", "recovery-key.txt");
    let new_pw = "brand-new-v2-passphrase";

    let mut via_passphrase = load_store("test-kdf");
    via_passphrase.set(SECRET_SYNC_STATE, b"active-sync");
    let before_pw = via_passphrase.durable_pairs();
    let err = migrate_live_v1_to_v2(&mut via_passphrase, VAULT_PASSPHRASE);
    assert!(
        matches!(err, Err(crate::vault::VaultError::VaultSyncMigrationDeferred)),
        "passphrase migration must defer VaultSync: {:?}",
        err.err()
    );
    assert_eq!(before_pw, via_passphrase.durable_pairs());

    let mut via_recovery = load_store("test-kdf");
    via_recovery.set(SECRET_SYNC_COUNTER, &[1u8; 8]);
    let before_rec = via_recovery.durable_pairs();
    let err = migrate_live_v1_to_v2_with_recovery(&mut via_recovery, &old_recovery, new_pw);
    assert!(
        matches!(err, Err(crate::vault::VaultError::VaultSyncMigrationDeferred)),
        "recovery-key migration must defer VaultSync: {:?}",
        err.err()
    );
    assert_eq!(before_rec, via_recovery.durable_pairs());
}

#[test]
fn malformed_v2_never_falls_back_to_v1() {
    let mut store = load_store("test-kdf");
    let mut junk = MAGIC_VAULT_V2.to_vec();
    junk.push(0x99);
    junk.extend_from_slice(&[1, 2, 3, 4]);
    store.set(SECRET_ENVELOPE_V2, &junk);
    let mut session = None;
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "malformed v2 must fail closed: {r:?}"
    );
    assert!(session.is_none());
}

#[test]
fn v1_backup_restore_mints_new_identity() {
    let mut store = MemoryStore::default();
    let mut session = None;
    let blob = load_bytes("test-kdf", "export.aegis");
    let original = MasterEnvelope::from_cbor(&load_bytes("test-kdf", "envelope.cbor")).unwrap();
    let master = unwrap_master(EXPORT_PASSPHRASE, &{
        let bundle: crate::vault::ExportBundle =
            ciborium::from_reader(blob.as_slice()).unwrap();
        bundle.envelope
    })
    .unwrap();
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob,
            passphrase: EXPORT_PASSPHRASE.into(),
            new_passphrase: Some(VAULT_PASSPHRASE.into()),
            replace: false,
        },
    );
    let vault_id = match r {
        VaultResponse::Unlocked { vault_id } => vault_id,
        other => panic!("{other:?}"),
    };
    assert_ne!(vault_id, original.vault_id);
    assert!(store.has(SECRET_ENVELOPE_V2));
    assert!(!store.has(SECRET_ENVELOPE));
    let env = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    let root = unwrap_root_v2(VAULT_PASSPHRASE, &env).unwrap();
    assert_ne!(root.as_bytes(), master.as_bytes());
    let keys = derive_operational_keys(&root, &env.vault_id_bytes().unwrap()).unwrap();
    let blob = VaultBlobV2::from_bytes(&store.get(SECRET_VAULT_V2).unwrap()).unwrap();
    let reused = RootSecret::from_bytes(*master.as_bytes());
    let reused_keys = derive_operational_keys(&reused, &env.vault_id_bytes().unwrap()).unwrap();
    assert!(open_vault_v2(&reused_keys.vault_dek, &blob).is_err());
    let pt = open_vault_v2(&keys.vault_dek, &blob).unwrap();
    let doc: crate::types::VaultDocument =
        ciborium::from_reader(pt.as_slice()).unwrap();
    assert_eq!(doc.meta.format_version, 2);
    assert_fixture_entry(&doc);
}

#[test]
fn live_migrate_keeps_vault_id_backup_restore_does_not() {
    let mut live = load_store("test-kdf");
    let original = MasterEnvelope::from_cbor(&live.get(SECRET_ENVELOPE).unwrap()).unwrap();
    let v1_id = decode_v1_vault_id(&original.vault_id).unwrap();
    let (migrated, _) = migrate_live_v1_to_v2(&mut live, VAULT_PASSPHRASE).unwrap();
    assert_eq!(hex::decode(&migrated.doc.meta.vault_id).unwrap(), v1_id);

    let mut restored = MemoryStore::default();
    let mut session = None;
    dispatch(
        &mut restored,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob: load_bytes("test-kdf", "export.aegis"),
            passphrase: EXPORT_PASSPHRASE.into(),
            new_passphrase: Some(VAULT_PASSPHRASE.into()),
            replace: false,
        },
    );
    let restored_id = session.as_ref().unwrap().vault_id_hex();
    assert_ne!(hex::decode(&restored_id).unwrap(), v1_id);
}

#[test]
fn v2_backup_export_and_restore_new_identity() {
    let mut store = MemoryStore::default();
    let mut session = None;
    dispatch(
        &mut store,
        &mut session,
        VaultRequest::CreateVault {
            passphrase: VAULT_PASSPHRASE.into(),
            kdf_profile: crate::crypto::KdfProfile::Interactive,
        },
    );
    let mut e = Entry::new("", "Mail");
    e.password = "same-password-data".into();
    dispatch(
        &mut store,
        &mut session,
        VaultRequest::UpsertEntry { entry: e },
    );
    let live_env = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    let live_root = unwrap_root_v2(VAULT_PASSPHRASE, &live_env).unwrap();
    let live_id = live_env.vault_id_bytes().unwrap();

    let export = dispatch(
        &mut store,
        &mut session,
        VaultRequest::ExportEncrypted {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    let blob = match export {
        VaultResponse::Export { blob } => blob,
        other => panic!("{other:?}"),
    };
    assert!(blob.starts_with(MAGIC_BACKUP_V2));
    assert_eq!(blob[MAGIC_BACKUP_V2.len()], CONTAINER_VERSION_V2);

    let new_live = "brand-new-live-vault-pw";
    let mut store2 = MemoryStore::default();
    let mut session2 = None;
    let r = dispatch(
        &mut store2,
        &mut session2,
        VaultRequest::ImportEncrypted {
            blob: blob.clone(),
            passphrase: VAULT_PASSPHRASE.into(),
            new_passphrase: None,
            replace: false,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { code: ErrorCode::InvalidRequest, .. }),
        "missing new_passphrase must fail closed: {r:?}"
    );
    assert!(!store2.has(SECRET_ENVELOPE_V2));

    let r = dispatch(
        &mut store2,
        &mut session2,
        VaultRequest::ImportEncrypted {
            blob: blob.clone(),
            passphrase: VAULT_PASSPHRASE.into(),
            new_passphrase: Some("short".into()),
            replace: false,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { code: ErrorCode::InvalidRequest, .. }),
        "weak new passphrase must be D18-rejected: {r:?}"
    );
    assert!(!store2.has(SECRET_ENVELOPE_V2));

    let before = store.durable_pairs();
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob: blob.clone(),
            passphrase: "wrong-backup-pass-phrase".into(),
            new_passphrase: Some(new_live.into()),
            replace: true,
        },
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(before, store.durable_pairs());

    let r = dispatch(
        &mut store2,
        &mut session2,
        VaultRequest::ImportEncrypted {
            blob,
            passphrase: VAULT_PASSPHRASE.into(),
            new_passphrase: Some(new_live.into()),
            replace: false,
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let env2 = MasterEnvelopeV2::from_bytes(&store2.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_ne!(env2.vault_id_bytes().unwrap(), live_id);
    assert!(unwrap_root_v2(VAULT_PASSPHRASE, &env2).is_err());
    let root2 = unwrap_root_v2(new_live, &env2).unwrap();
    assert_ne!(root2.as_bytes(), live_root.as_bytes());
}

#[test]
fn generation_store_migrate_is_atomic() {
    let mut g = GenerationStore::new(load_store("test-kdf"));
    let (session, _) = migrate_live_v1_to_v2(&mut g, VAULT_PASSPHRASE).unwrap();
    assert_eq!(session.doc.meta.format_version, 2);
    assert!(g.get(SECRET_ENVELOPE_V2).is_some());
    assert!(g.get(SECRET_ENVELOPE).is_none());
}

#[test]
fn generation_crash_before_pointer_keeps_v1() {
    let mut raw = load_store("test-kdf");
    let new_gen = b"cafebabedeadbeef".to_vec();
    raw.set(
        &{
            let mut k = b"aegis/gen/".to_vec();
            k.extend_from_slice(&new_gen);
            k.push(b'/');
            k.extend_from_slice(SECRET_ENVELOPE_V2);
            k
        },
        b"candidate-v2",
    );
    let store = GenerationStore::new(raw);
    assert!(store.get(SECRET_ENVELOPE).is_some());
    assert!(store.get(SECRET_ENVELOPE_V2).is_none());
}

#[test]
fn file_store_migrate_roundtrip() {
    let mut nonce = [0u8; 8];
    crate::rng::fill_random(&mut nonce);
    let dir = std::env::temp_dir().join(format!("aegis-p5-{}", hex::encode(nonce)));
    let mut fs = FileStore::open(&dir).unwrap();
    let mut v1 = VaultSession::create(&mut fs, VAULT_PASSPHRASE, crate::crypto::KdfProfile::Test)
        .unwrap();
    let mut e = Entry::new("", "Disk");
    e.password = "on-disk".into();
    v1.handle(&mut fs, VaultRequest::UpsertEntry { entry: e }).unwrap();
    v1.lock(&mut fs);

    let (session, rec) = migrate_live_v1_to_v2(&mut fs, VAULT_PASSPHRASE).unwrap();
    assert_eq!(session.doc.meta.format_version, 2);
    drop(session);

    let mut fs2 = FileStore::open(&dir).unwrap();
    let mut sess = None;
    let r = dispatch(
        &mut fs2,
        &mut sess,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    assert!(!sess.as_ref().unwrap().is_v1());
    let _ = rec;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsupported_commit_does_not_migrate() {
    struct Reject(MemoryStore);
    impl SecretStore for Reject {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.get(key)
        }
        fn set(&mut self, key: &[u8], value: &[u8]) {
            self.0.set(key, value)
        }
        fn remove(&mut self, key: &[u8]) {
            self.0.remove(key)
        }
        fn commit(&mut self, _ops: &[StoreOp]) -> Result<(), String> {
            Err(UNSUPPORTED_ATOMIC_COMMIT.into())
        }
    }
    let inner = load_store("test-kdf");
    let before = inner.durable_pairs();
    let mut store = Reject(inner);
    let err = migrate_live_v1_to_v2(&mut store, VAULT_PASSPHRASE);
    assert!(err.is_err());
    assert_eq!(before, store.0.durable_pairs());
}

#[test]
fn v2_sync_is_hybrid() {
    let mut store = MemoryStore::default();
    let mut session = None;
    dispatch(
        &mut store,
        &mut session,
        VaultRequest::CreateVault {
            passphrase: VAULT_PASSPHRASE.into(),
            kdf_profile: crate::crypto::KdfProfile::Test,
        },
    );
    let r = dispatch(&mut store, &mut session, VaultRequest::SyncNow);
    assert!(
        matches!(r, VaultResponse::Synced { .. }),
        "Phase 7 hybrid VaultSync must not be deferred: {r:?}"
    );
}

#[test]
fn v1_export_helper_still_roundtrips_for_compat_tests() {
    let mut store = MemoryStore::default();
    let s = VaultSession::create(
        &mut store,
        VAULT_PASSPHRASE,
        crate::crypto::KdfProfile::Test,
    )
    .unwrap();
    let blob = {
        let mut session = Some(ActiveSession::V1(s));
        match dispatch(
            &mut store,
            &mut session,
            VaultRequest::ExportEncrypted {
                passphrase: EXPORT_PASSPHRASE.into(),
            },
        ) {
            VaultResponse::Export { blob } => blob,
            other => panic!("{other:?}"),
        }
    };
    let mut store2 = MemoryStore::default();
    let imported = import_bundle(&mut store2, &blob, EXPORT_PASSPHRASE, false).unwrap();
    assert_eq!(imported.doc.meta.format_version, 1);
}

#[test]
fn d18_not_applied_on_unlock() {
    // Historical v1 passphrase unlocks even though Test KDF vaults used the
    // fixture passphrase (which happens to meet D18). A too-short production
    // create is rejected above; unlock of an existing v2 uses unwrap only.
    let mut store = MemoryStore::default();
    let mut session = None;
    dispatch(
        &mut store,
        &mut session,
        VaultRequest::CreateVault {
            passphrase: VAULT_PASSPHRASE.into(),
            kdf_profile: crate::crypto::KdfProfile::Test,
        },
    );
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
}

const SHORT_EXPORT_PW: &str = "shortpw1"; // 8 chars — valid v1, below D18

fn short_password_v1_export() -> (Vec<u8>, [u8; 32]) {
    let mut store = MemoryStore::default();
    let mut s = VaultSession::create(&mut store, "legacy-master", KdfProfile::Test).unwrap();
    let mut e = Entry::new("", ENTRY_NAME);
    e.password = NEW_PASSWORD.into();
    e.username = "octocat".into();
    s.handle(&mut store, VaultRequest::UpsertEntry { entry: e })
        .unwrap();
    let master = *s.master.as_bytes();
    let mut session = Some(ActiveSession::V1(s));
    let blob = match dispatch(
        &mut store,
        &mut session,
        VaultRequest::ExportEncrypted {
            passphrase: SHORT_EXPORT_PW.into(),
        },
    ) {
        VaultResponse::Export { blob } => blob,
        other => panic!("{other:?}"),
    };
    (blob, master)
}

#[test]
fn legacy_v1_export_short_password_restores_only_with_new_d18_passphrase() {
    let (blob, old_master) = short_password_v1_export();
    assert!(SHORT_EXPORT_PW.chars().count() < 12);

    let mut empty = MemoryStore::default();
    let mut session = None;
    let r = dispatch(
        &mut empty,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob: blob.clone(),
            passphrase: SHORT_EXPORT_PW.into(),
            new_passphrase: None,
            replace: false,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { code: ErrorCode::InvalidRequest, .. }),
        "legacy restore must require a new v2 passphrase: {r:?}"
    );
    assert!(!empty.has(SECRET_ENVELOPE_V2));

    let r = dispatch(
        &mut empty,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob: blob.clone(),
            passphrase: SHORT_EXPORT_PW.into(),
            new_passphrase: Some("short".into()),
            replace: false,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { code: ErrorCode::InvalidRequest, .. }),
        "weak new v2 passphrase must be rejected by D18: {r:?}"
    );
    assert!(!empty.has(SECRET_ENVELOPE_V2));

    let mut existing = load_store("test-kdf");
    let before = existing.durable_pairs();
    let r = dispatch(
        &mut existing,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob: blob.clone(),
            passphrase: "wrong-legacy".into(),
            new_passphrase: Some(VAULT_PASSPHRASE.into()),
            replace: true,
        },
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(before, existing.durable_pairs());

    let r = dispatch(
        &mut empty,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob,
            passphrase: SHORT_EXPORT_PW.into(),
            new_passphrase: Some(VAULT_PASSPHRASE.into()),
            replace: false,
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let env = MasterEnvelopeV2::from_bytes(&empty.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    let root = unwrap_root_v2(VAULT_PASSPHRASE, &env).unwrap();
    assert_ne!(root.as_bytes().as_slice(), old_master.as_slice());
    let reused = RootSecret::from_bytes(old_master);
    let reused_keys = derive_operational_keys(&reused, &env.vault_id_bytes().unwrap()).unwrap();
    let vault_blob = VaultBlobV2::from_bytes(&empty.get(SECRET_VAULT_V2).unwrap()).unwrap();
    assert!(open_vault_v2(&reused_keys.vault_dek, &vault_blob).is_err());
    dispatch(&mut empty, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut empty,
        &mut session,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
}

#[test]
fn recovery_key_migrates_without_old_passphrase() {
    let mut store = load_store("test-kdf");
    let envelope = MasterEnvelope::from_cbor(&store.get(SECRET_ENVELOPE).unwrap()).unwrap();
    let v1_id = decode_v1_vault_id(&envelope.vault_id).unwrap();
    let master = unwrap_master(VAULT_PASSPHRASE, &envelope).unwrap();
    let v1_keys = derive_keys(&master).unwrap();
    let old_recovery = load_text("test-kdf", "recovery-key.txt");
    let new_pw = "brand-new-v2-passphrase";

    let mut session = None;
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::MigrateVaultWithRecovery {
            recovery_key: old_recovery.clone(),
            new_v2_passphrase: new_pw.into(),
        },
    );
    let (vault_id, recovery_secret) = match r {
        VaultResponse::Migrated {
            vault_id,
            recovery_secret,
        } => (vault_id, recovery_secret),
        other => panic!("{other:?}"),
    };
    assert_eq!(hex::decode(&vault_id).unwrap(), v1_id);
    assert!(!store.has(SECRET_ENVELOPE));
    assert!(!store.has(SECRET_RECOVERY));
    assert!(store.has(SECRET_ENVELOPE_V2));
    assert!(store.has(SECRET_RECOVERY_V2));

    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "old v1 passphrase must not be required/usable after recovery migrate: {r:?}"
    );
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: new_pw.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");

    let env_v2 = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    let root = unwrap_root_v2(new_pw, &env_v2).unwrap();
    assert_ne!(root.as_bytes(), master.as_bytes());
    let keys = derive_operational_keys(&root, &v1_id).unwrap();
    assert_ne!(keys.vault_dek.as_bytes(), v1_keys.vault_dek.as_bytes());
    let blob = VaultBlobV2::from_bytes(&store.get(SECRET_VAULT_V2).unwrap()).unwrap();
    let pt = open_vault_v2(&keys.vault_dek, &blob).unwrap();
    let doc: crate::types::VaultDocument =
        ciborium::from_reader(pt.as_slice()).unwrap();
    assert_eq!(doc.meta.format_version, 2);
    assert_fixture_entry(&doc);

    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: old_recovery,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "old v1 recovery must not unlock v2: {r:?}"
    );
    let wrap = RecoveryWrapV2::from_cbor(&store.get(SECRET_RECOVERY_V2).unwrap()).unwrap();
    let rec = decode_recovery_secret(&recovery_secret).unwrap();
    let unwrapped = unwrap_recovery(&wrap, &rec).unwrap();
    assert_eq!(unwrapped.as_bytes(), root.as_bytes());
    assert!(!store.contains_plaintext(rec.as_bytes()));
}

#[test]
fn recovery_migration_failures_leave_v1_recovery_path() {
    let inner = load_store("test-kdf");
    let old_recovery = load_text("test-kdf", "recovery-key.txt");
    let new_pw = "brand-new-v2-passphrase";

    let before = inner.durable_pairs();
    let mut store = inner.clone();
    let mut session = None;
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::MigrateVaultWithRecovery {
            recovery_key: "AEGIS-0000-0000-0000-0000-0000-0000-0000-0000".into(),
            new_v2_passphrase: new_pw.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(before, store.durable_pairs());

    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::MigrateVaultWithRecovery {
            recovery_key: old_recovery.clone(),
            new_v2_passphrase: "short".into(),
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { code: ErrorCode::InvalidRequest, .. }),
        "weak new passphrase: {r:?}"
    );
    assert_eq!(before, store.durable_pairs());

    let mut fail = FailCommitStore {
        inner: load_store("test-kdf"),
        fail: true,
    };
    let err = migrate_live_v1_to_v2_with_recovery(&mut fail, &old_recovery, new_pw);
    assert!(err.is_err());
    assert_eq!(before, fail.inner.durable_pairs());

    let mut session = None;
    let r = dispatch(
        &mut fail.inner,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: old_recovery,
        },
    );
    assert!(
        matches!(r, VaultResponse::Unlocked { .. }),
        "original recovery path must remain usable: {r:?}"
    );
}
