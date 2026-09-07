//! Phase 1 / PR B: freeze v1 formats and behaviors.
//!
//! No production crypto changes. Fixtures under `tests/fixtures/v1/` are the
//! compatibility corpus — do not regenerate after Phase 2.

use crate::crypto::{
    derive_keys, normalize_recovery_key, open, unwrap_master, unwrap_master_with_aad, KdfProfile,
    MAGIC_VAULT_V2, MasterEnvelope, MasterEnvelopeV2, SealedBlob, VaultBlobV2,
};
use sha2::{Digest, Sha256};
use crate::messages::{VaultRequest, VaultResponse};
use crate::types::{CustomField, Entry, FieldKind, Folder};
use crate::gen_store::GenerationStore;
use crate::vault::{
    dispatch, import_bundle, ActiveSession, ExportBundle, MemoryStore, SecretStore, StoreOp,
    VaultSession, SECRET_AUDIT, SECRET_ENVELOPE, SECRET_RECOVERY, SECRET_SESSION,
    SECRET_SYNC_COUNTER, SECRET_SYNC_STATE, SECRET_VAULT, UNSUPPORTED_ATOMIC_COMMIT,
};

const VAULT_PASSPHRASE: &str = "correct horse battery staple";
const EXPORT_PASSPHRASE: &str = "export-passphrase-v1";
const ENTRY_NAME: &str = "GitHub";
const FOLDER_NAME: &str = "Work";
const TOTP: &str = "JBSWY3DPEHPK3PXP";
const OLD_PASSWORD: &str = "old-password-v1";
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

fn expected_document(doc: &crate::types::VaultDocument) {
    assert_eq!(doc.meta.format_version, 1);
    assert_eq!(doc.folders.len(), 1);
    let folder = doc.folders.values().next().unwrap();
    assert_eq!(folder.name, FOLDER_NAME);
    assert_eq!(doc.entries.len(), 1);
    let entry = doc.entries.values().next().unwrap();
    assert_eq!(entry.name, ENTRY_NAME);
    assert_eq!(entry.username, "octocat");
    assert_eq!(entry.password, NEW_PASSWORD);
    assert_eq!(entry.totp_secret.as_deref(), Some(TOTP));
    assert_eq!(entry.notes, "v1 fixture notes");
    assert_eq!(entry.urls, vec!["https://github.com".to_string()]);
    assert_eq!(entry.tags, vec!["dev".to_string()]);
    assert_eq!(entry.folder_id.as_deref(), Some(folder.id.as_str()));
    assert_eq!(entry.password_history.len(), 1);
    assert_eq!(entry.password_history[0].password, OLD_PASSWORD);
    assert_eq!(entry.custom_fields.len(), 1);
    assert_eq!(entry.custom_fields[0].name, "PIN");
    assert_eq!(entry.custom_fields[0].value, "1234");
}

fn populate_vault(store: &mut MemoryStore, profile: KdfProfile) -> String {
    let s = VaultSession::create(store, VAULT_PASSPHRASE, profile).expect("v1 create");
    let mut session = Some(ActiveSession::V1(s));

    let r = dispatch(
        store,
        &mut session,
        VaultRequest::UpsertFolder {
            folder: Folder {
                id: String::new(),
                name: FOLDER_NAME.into(),
                parent: None,
                created_at: 0,
                updated_at: 0,
            },
        },
    );
    assert_eq!(r, VaultResponse::Ok);

    let folders = match dispatch(store, &mut session, VaultRequest::ListFolders) {
        VaultResponse::Folders { folders } => folders,
        other => panic!("{other:?}"),
    };
    let folder_id = folders[0].id.clone();

    let mut entry = Entry::new("", ENTRY_NAME);
    entry.folder_id = Some(folder_id);
    entry.username = "octocat".into();
    entry.password = OLD_PASSWORD.into();
    entry.notes = "v1 fixture notes".into();
    entry.urls.push("https://github.com".into());
    entry.tags.push("dev".into());
    entry.totp_secret = Some(TOTP.into());
    entry.custom_fields.push(CustomField {
        id: "pin1".into(),
        name: "PIN".into(),
        value: "1234".into(),
        kind: FieldKind::Hidden,
    });
    assert_eq!(
        dispatch(
            store,
            &mut session,
            VaultRequest::UpsertEntry { entry: entry.clone() }
        ),
        VaultResponse::Ok
    );

    let id = match dispatch(
        store,
        &mut session,
        VaultRequest::ListSummaries { query: None },
    ) {
        VaultResponse::Summaries { entries } => entries[0].id.clone(),
        other => panic!("{other:?}"),
    };
    let mut stored = match dispatch(store, &mut session, VaultRequest::GetEntry { id }) {
        VaultResponse::Entry { entry } => entry,
        other => panic!("{other:?}"),
    };
    stored.password = NEW_PASSWORD.into();
    assert_eq!(
        dispatch(
            store,
            &mut session,
            VaultRequest::UpsertEntry { entry: stored }
        ),
        VaultResponse::Ok
    );

    let recovery = match dispatch(
        store,
        &mut session,
        VaultRequest::GenerateRecoveryKey {
            kdf_profile: Some(profile),
        },
    ) {
        VaultResponse::RecoveryKey { recovery_key, .. } => recovery_key,
        other => panic!("{other:?}"),
    };

    let export = match dispatch(
        store,
        &mut session,
        VaultRequest::ExportEncrypted {
            passphrase: EXPORT_PASSPHRASE.into(),
        },
    ) {
        VaultResponse::Export { blob } => blob,
        other => panic!("{other:?}"),
    };

    // Persist export next to the store snapshot (caller writes files).
    store
        .set(b"__fixture_export", &export);

    recovery
}

fn write_profile_fixtures(profile_name: &str, profile: KdfProfile) {
    let dir = fixture_dir(profile_name);
    std::fs::create_dir_all(&dir).unwrap();
    let mut store = MemoryStore::default();
    let recovery = populate_vault(&mut store, profile);
    let export = store.get(b"__fixture_export").expect("export stashed");
    store.remove(b"__fixture_export");

    std::fs::write(dir.join("store.cbor"), store.export_cbor_skip_session().unwrap()).unwrap();
    std::fs::write(dir.join("export.aegis"), &export).unwrap();
    std::fs::write(dir.join("envelope.cbor"), store.get(SECRET_ENVELOPE).unwrap()).unwrap();
    std::fs::write(dir.join("vault.cbor"), store.get(SECRET_VAULT).unwrap()).unwrap();
    std::fs::write(
        dir.join("recovery-envelope.cbor"),
        store.get(SECRET_RECOVERY).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("recovery-key.txt"), format!("{recovery}\n")).unwrap();
}

/// Rebuild frozen bytes. Ignored unless `AEGIS_REGEN_V1_FIXTURES=1`.
#[test]
#[ignore]
fn regen_v1_fixtures() {
    assert_eq!(
        std::env::var("AEGIS_REGEN_V1_FIXTURES").ok().as_deref(),
        Some("1"),
        "refusing to regenerate without AEGIS_REGEN_V1_FIXTURES=1"
    );
    write_profile_fixtures("test-kdf", KdfProfile::Test);
    write_profile_fixtures("interactive-kdf", KdfProfile::Interactive);
}

fn assert_v1_store_and_export(profile_name: &str, expected_vault_profile: KdfProfile) {
    let mut store = load_store(profile_name);
    assert!(store.has(SECRET_ENVELOPE));
    assert!(store.has(SECRET_VAULT));
    assert!(store.has(SECRET_RECOVERY));
    assert!(!store.has(SECRET_SESSION));

    let envelope = MasterEnvelope::from_cbor(&load_bytes(profile_name, "envelope.cbor")).unwrap();
    assert_eq!(envelope.kdf.profile, expected_vault_profile);
    assert_eq!(envelope.sealed.version, 1);

    let mut session = None;
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: VAULT_PASSPHRASE.into(),
        },
    );
    match r {
        VaultResponse::Unlocked { vault_id } => {
            assert_eq!(vault_id, envelope.vault_id);
        }
        other => panic!("unlock: {other:?}"),
    }
    expected_document(session.as_ref().unwrap().doc());

    let recovery_key = load_text(profile_name, "recovery-key.txt");
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: recovery_key.clone(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    expected_document(session.as_ref().unwrap().doc());

    let rec_env =
        MasterEnvelope::from_cbor(&load_bytes(profile_name, "recovery-envelope.cbor")).unwrap();
    let master_vault = unwrap_master(VAULT_PASSPHRASE, &envelope).unwrap();
    let master_rec = unwrap_master_with_aad(
        &normalize_recovery_key(&recovery_key),
        &rec_env,
        b"recovery",
    )
    .unwrap();
    assert_eq!(
        master_vault.as_bytes(),
        master_rec.as_bytes(),
        "v1 recovery wraps the live MasterSecret"
    );

    let export_bytes = load_bytes(profile_name, "export.aegis");
    let bundle: ExportBundle = ciborium::from_reader(export_bytes.as_slice()).unwrap();
    assert_eq!(bundle.format, 1);
    assert_eq!(
        bundle.envelope.kdf.profile,
        KdfProfile::Mobile,
        "v1 export always uses Mobile KDF"
    );
    let master_export = unwrap_master(EXPORT_PASSPHRASE, &bundle.envelope).unwrap();
    assert_eq!(
        master_vault.as_bytes(),
        master_export.as_bytes(),
        "v1 export re-wraps the live MasterSecret (CRYPTO-V2 §21)"
    );

    let keys = derive_keys(&master_export).unwrap();
    let pt = open(
        &keys.vault_dek,
        bundle.envelope.vault_id.as_bytes(),
        b"export-vault",
        &bundle.vault,
    )
    .unwrap();
    let doc: crate::types::VaultDocument =
        ciborium::from_reader(pt.as_slice()).unwrap();
    expected_document(&doc);

    // Separate vault blob file must open under the live DEK.
    let vault_blob = SealedBlob::from_cbor(&load_bytes(profile_name, "vault.cbor")).unwrap();
    let pt = open(
        &keys.vault_dek,
        envelope.vault_id.as_bytes(),
        b"vault",
        &vault_blob,
    )
    .unwrap();
    let doc: crate::types::VaultDocument =
        ciborium::from_reader(pt.as_slice()).unwrap();
    expected_document(&doc);
}

#[test]
fn v1_test_kdf_fixtures_unlock_and_export_contains_master() {
    assert_v1_store_and_export("test-kdf", KdfProfile::Test);
}

#[test]
fn v1_interactive_kdf_fixtures_unlock_and_export_contains_master() {
    assert_v1_store_and_export("interactive-kdf", KdfProfile::Interactive);
}

#[test]
fn v1_fixtures_are_rejected_by_v2_parsers() {
    for profile in ["test-kdf", "interactive-kdf"] {
        let envelope = load_bytes(profile, "envelope.cbor");
        assert!(
            MasterEnvelopeV2::from_cbor(&envelope).is_err(),
            "{profile} master envelope parsed as v2"
        );
        let recovery = load_bytes(profile, "recovery-envelope.cbor");
        assert!(
            MasterEnvelopeV2::from_cbor(&recovery).is_err(),
            "{profile} recovery envelope parsed as v2"
        );
        let vault = load_bytes(profile, "vault.cbor");
        assert!(
            VaultBlobV2::from_cbor(&vault).is_err(),
            "{profile} vault blob parsed as VaultBlobV2"
        );
        assert!(
            MasterEnvelopeV2::from_bytes(&envelope).is_err(),
            "{profile} raw v1 envelope accepted by v2 external decoder"
        );
        let mut fake = MAGIC_VAULT_V2.to_vec();
        fake.push(0x02);
        fake.extend_from_slice(&envelope);
        assert!(
            MasterEnvelopeV2::from_bytes(&fake).is_err(),
            "{profile} v1 CBOR with fake v2 prefix parsed as v2"
        );
    }
}

#[test]
fn v1_fixture_sha256sums_match() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1");
    let sums = std::fs::read_to_string(root.join("SHA256SUMS")).expect("SHA256SUMS");
    for line in sums.lines().filter(|l| !l.is_empty()) {
        let (hash, path) = line.split_once("  ").expect("hash  path");
        let bytes = std::fs::read(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        let got = hex::encode(Sha256::digest(&bytes));
        assert_eq!(got, hash, "hash mismatch for {path}");
    }
}

#[test]
fn v1_frozen_export_imports_into_empty_store() {
    let mut store = MemoryStore::default();
    let mut session = None;
    let blob = load_bytes("test-kdf", "export.aegis");
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
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let doc = session.as_ref().unwrap().doc();
    assert_eq!(doc.meta.format_version, 2);
    assert_eq!(doc.entries.len(), 1);
    let entry = doc.entries.values().next().unwrap();
    assert_eq!(entry.name, ENTRY_NAME);
    assert_eq!(entry.password, NEW_PASSWORD);
    assert_eq!(entry.username, "octocat");
    let original = MasterEnvelope::from_cbor(&load_bytes("test-kdf", "envelope.cbor")).unwrap();
    assert_ne!(doc.meta.vault_id, original.vault_id);
    assert!(store.has(crate::session_v2::SECRET_ENVELOPE_V2));
    assert!(!store.has(SECRET_ENVELOPE));
}

fn seeded_local_vault() -> MemoryStore {
    let mut store = MemoryStore::default();
    let mut s = VaultSession::create(&mut store, VAULT_PASSPHRASE, KdfProfile::Test).unwrap();
    let mut entry = Entry::new("", "MustSurvive");
    entry.password = "local-only".into();
    s.handle(
        &mut store,
        VaultRequest::UpsertEntry { entry },
    )
    .unwrap();
    s.lock(&mut store);
    store
}

fn assert_store_unchanged(before: &[(Vec<u8>, Vec<u8>)], store: &MemoryStore, why: &str) {
    assert_eq!(before, &store.durable_pairs()[..], "{why}");
    assert!(store.has(SECRET_ENVELOPE), "{why}: envelope still present");
}

#[test]
fn v1_replace_import_corrupt_must_leave_store_unchanged() {
    let mut store = seeded_local_vault();
    let before = store.durable_pairs();
    let err = import_bundle(&mut store, b"not-a-valid-aegis-bundle", "nope", true);
    assert!(err.is_err(), "malformed CBOR must fail");
    assert_store_unchanged(&before, &store, "malformed CBOR");
}

#[test]
fn v1_replace_import_wrong_password_leaves_store_unchanged() {
    let mut store = seeded_local_vault();
    let before = store.durable_pairs();
    let blob = load_bytes("test-kdf", "export.aegis");
    let err = import_bundle(&mut store, &blob, "wrong-password", true);
    assert!(err.is_err(), "wrong password must fail");
    assert_store_unchanged(&before, &store, "wrong password");
}

#[test]
fn v1_replace_import_corrupt_ciphertext_leaves_store_unchanged() {
    let mut store = seeded_local_vault();
    let before = store.durable_pairs();
    let mut blob = load_bytes("test-kdf", "export.aegis");
    let idx = blob.len() / 2;
    blob[idx] ^= 0xff;
    let err = import_bundle(&mut store, &blob, EXPORT_PASSPHRASE, true);
    assert!(err.is_err(), "corrupt ciphertext must fail");
    assert_store_unchanged(&before, &store, "corrupt ciphertext");
}

#[test]
fn v1_replace_import_without_flag_does_not_touch_existing() {
    let mut store = seeded_local_vault();
    let before = store.durable_pairs();
    let blob = load_bytes("test-kdf", "export.aegis");
    let err = import_bundle(&mut store, &blob, EXPORT_PASSPHRASE, false);
    assert!(err.is_err(), "replace=false must refuse existing vault");
    assert_store_unchanged(&before, &store, "replace=false");
}

#[test]
fn v1_replace_import_success_installs_backup() {
    let mut store = seeded_local_vault();
    let blob = load_bytes("test-kdf", "export.aegis");
    let session = import_bundle(&mut store, &blob, EXPORT_PASSPHRASE, true).expect("replace");
    expected_document(&session.doc);
    assert!(store.has(SECRET_ENVELOPE));
    assert!(store.has(SECRET_VAULT));
}

#[test]
fn v1_successful_replace_drops_stale_auxiliary_secrets() {
    let mut store = MemoryStore::default();
    let s = VaultSession::create(&mut store, VAULT_PASSPHRASE, KdfProfile::Test).unwrap();
    let mut session = Some(ActiveSession::V1(s));
    let mut entry = Entry::new("", "VaultA-Only");
    entry.password = "secret-a".into();
    dispatch(
        &mut store,
        &mut session,
        VaultRequest::UpsertEntry { entry },
    );
    let recovery_a = match dispatch(
        &mut store,
        &mut session,
        VaultRequest::GenerateRecoveryKey {
            kdf_profile: Some(KdfProfile::Test),
        },
    ) {
        VaultResponse::RecoveryKey { recovery_key, .. } => recovery_key,
        other => panic!("{other:?}"),
    };
    store.set(SECRET_SYNC_STATE, b"stale-sync-state");
    store.set(SECRET_SYNC_COUNTER, &[7u8; 8]);

    let envelope_a = store.get(SECRET_ENVELOPE).unwrap();
    let vault_a = store.get(SECRET_VAULT).unwrap();
    let audit_a = store.get(SECRET_AUDIT).unwrap();
    let recovery_blob_a = store.get(SECRET_RECOVERY).unwrap();
    assert!(store.has(SECRET_SESSION));

    let blob = load_bytes("test-kdf", "export.aegis");
    let imported = import_bundle(&mut store, &blob, EXPORT_PASSPHRASE, true).expect("replace");
    expected_document(&imported.doc);
    session = Some(ActiveSession::V1(imported));

    assert_ne!(store.get(SECRET_ENVELOPE).unwrap(), envelope_a);
    assert_ne!(store.get(SECRET_VAULT).unwrap(), vault_a);
    let audit_b = store.get(SECRET_AUDIT).expect("audit recreated");
    assert_ne!(audit_b, audit_a, "audit A must not survive");
    assert!(
        store.get(SECRET_RECOVERY).is_none(),
        "recovery A must not survive; it wraps MasterSecret A"
    );
    assert_ne!(
        recovery_blob_a,
        store.get(SECRET_RECOVERY).unwrap_or_default()
    );
    assert!(store.get(SECRET_SYNC_STATE).is_none());
    assert!(store.get(SECRET_SYNC_COUNTER).is_none());

    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: recovery_a,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "old recovery key must not unlock replaced vault: {r:?}"
    );
}

#[test]
fn generation_store_replace_is_atomic_and_drops_stale_recovery() {
    let mut g = GenerationStore::new(MemoryStore::default());
    let s = VaultSession::create(&mut g, VAULT_PASSPHRASE, KdfProfile::Test).unwrap();
    let mut session = Some(ActiveSession::V1(s));
    let mut entry = Entry::new("", "MustSurvive");
    entry.password = "local-only".into();
    dispatch(
        &mut g,
        &mut session,
        VaultRequest::UpsertEntry { entry },
    );
    let recovery_a = match dispatch(
        &mut g,
        &mut session,
        VaultRequest::GenerateRecoveryKey {
            kdf_profile: Some(KdfProfile::Test),
        },
    ) {
        VaultResponse::RecoveryKey { recovery_key, .. } => recovery_key,
        other => panic!("{other:?}"),
    };
    assert!(g.get(SECRET_RECOVERY).is_some());

    let blob = load_bytes("test-kdf", "export.aegis");
    import_bundle(&mut g, &blob, EXPORT_PASSPHRASE, true).expect("gen-store replace");
    assert!(g.get(SECRET_RECOVERY).is_none());
    expected_document(
        &crate::vault::peek_local_document(&g, EXPORT_PASSPHRASE).unwrap(),
    );

    session = None;
    let r = dispatch(
        &mut g,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: recovery_a,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "old recovery must not unlock after generation replace: {r:?}"
    );
}

struct RejectAtomicStore {
    inner: MemoryStore,
}

impl SecretStore for RejectAtomicStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.inner.set(key, value);
    }
    fn remove(&mut self, key: &[u8]) {
        self.inner.remove(key);
    }
    fn commit(&mut self, _ops: &[StoreOp]) -> Result<(), String> {
        Err(UNSUPPORTED_ATOMIC_COMMIT.into())
    }
}

#[test]
fn unsupported_atomic_commit_does_not_mutate() {
    let inner = seeded_local_vault();
    let before = inner.durable_pairs();
    let mut store = RejectAtomicStore { inner };
    let blob = load_bytes("test-kdf", "export.aegis");
    let err = import_bundle(&mut store, &blob, EXPORT_PASSPHRASE, true);
    assert!(err.is_err());
    assert_eq!(before, store.inner.durable_pairs());
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
        self.inner.set(key, value);
    }
    fn remove(&mut self, key: &[u8]) {
        self.inner.remove(key);
    }
    fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String> {
        if self.fail {
            return Err("simulated persistence failure".into());
        }
        self.inner.commit(ops)
    }
}

#[test]
fn v1_replace_import_commit_failure_leaves_store_unchanged() {
    let inner = seeded_local_vault();
    let before = inner.durable_pairs();
    let mut store = FailCommitStore { inner, fail: true };
    let blob = load_bytes("test-kdf", "export.aegis");
    let err = import_bundle(&mut store, &blob, EXPORT_PASSPHRASE, true);
    assert!(err.is_err(), "commit failure must surface");
    assert_eq!(
        before,
        store.inner.durable_pairs(),
        "simulated commit failure must not apply candidate"
    );
}
