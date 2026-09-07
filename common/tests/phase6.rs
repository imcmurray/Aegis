//! Phase 6 / PR H: explicit full RootSecret rotation.

use crate::crypto::envelope_v2::open_vault_v2;
use crate::crypto::hkdf_v2::derive_operational_keys;
use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::secret::RootSecret;
use crate::crypto::{KdfProfile, MasterEnvelopeV2, VaultBlobV2};
use crate::file_store::FileStore;
use crate::gen_store::GenerationStore;
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::recovery_v2::{decode_recovery_secret, unwrap_recovery, RecoveryWrapV2, SECRET_RECOVERY_V2};
use crate::session_v2::{VaultSessionV2, SECRET_AUDIT_V2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2};
use crate::types::Entry;
use crate::vault::{
    dispatch, ActiveSession, MemoryStore, SecretStore, StoreOp, VaultSession, SECRET_SYNC_STATE,
    UNSUPPORTED_ATOMIC_COMMIT,
};

const PW: &str = "correct horse battery staple";

fn unlocked_v2(store: &mut MemoryStore) -> Option<ActiveSession> {
    let mut session = VaultSessionV2::create_with_params(
        store,
        PW,
        Argon2ParamsV2::insecure_for_tests(),
    )
    .expect("v2 create");
    let mut e = Entry::new("e1", "Mail");
    e.password = "inbox-secret".into();
    session.doc.entries.insert(e.id.clone(), e);
    session.persist(store).expect("persist");
    Some(ActiveSession::V2(session))
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

#[test]
fn unlock_does_not_rotate() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let epoch0 = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap())
        .unwrap()
        .key_epoch;
    assert_eq!(epoch0, 0);
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock { passphrase: PW.into() },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let epoch1 = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap())
        .unwrap()
        .key_epoch;
    assert_eq!(epoch1, 0);
}

#[test]
fn rotate_keys_fresh_root_same_vault_id_epoch_plus_one() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (vid, old_root) = match session.as_ref().unwrap() {
        ActiveSession::V2(s) => (s.vault_id_for_test(), s.root_bytes_for_test()),
        ActiveSession::V1(_) => panic!("expected v2"),
    };
    let old_keys = derive_operational_keys(&RootSecret::from_bytes(old_root), &vid).unwrap();
    let old_vault = store.get(SECRET_VAULT_V2).unwrap();
    let old_audit = store.get(SECRET_AUDIT_V2).unwrap();

    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    match r {
        VaultResponse::Rotated {
            vault_id,
            key_epoch,
            recovery_secret,
        } => {
            assert_eq!(hex::decode(&vault_id).unwrap(), vid);
            assert_eq!(key_epoch, 1);
            assert!(recovery_secret.is_none());
        }
        other => panic!("{other:?}"),
    }

    let env1 = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_eq!(env1.key_epoch, 1);
    assert_eq!(env1.vault_id_bytes().unwrap(), vid);
    let new_root = match session.as_ref().unwrap() {
        ActiveSession::V2(s) => s.root_bytes_for_test(),
        ActiveSession::V1(_) => panic!("expected v2"),
    };
    assert_ne!(&new_root, &old_root);
    let new_keys = derive_operational_keys(&RootSecret::from_bytes(new_root), &vid).unwrap();
    assert_ne!(new_keys.vault_dek.as_bytes(), old_keys.vault_dek.as_bytes());
    assert_ne!(new_keys.audit_dek.as_bytes(), old_keys.audit_dek.as_bytes());
    assert_ne!(new_keys.sync_dek.as_bytes(), old_keys.sync_dek.as_bytes());
    assert_ne!(
        new_keys.search_hmac.as_bytes(),
        old_keys.search_hmac.as_bytes()
    );
    assert_ne!(
        new_keys.sync_ed25519_seed.as_bytes(),
        old_keys.sync_ed25519_seed.as_bytes()
    );
    assert_ne!(
        new_keys.sync_mldsa_seed.as_bytes(),
        old_keys.sync_mldsa_seed.as_bytes()
    );
    assert_ne!(
        new_keys.share_x25519_seed.as_bytes(),
        old_keys.share_x25519_seed.as_bytes()
    );
    assert_ne!(
        new_keys.share_mlkem_seed.as_bytes(),
        old_keys.share_mlkem_seed.as_bytes()
    );

    let blob = VaultBlobV2::from_bytes(&store.get(SECRET_VAULT_V2).unwrap()).unwrap();
    assert_eq!(blob.key_epoch, 1);
    assert!(open_vault_v2(&old_keys.vault_dek, &blob).is_err());
    let pt = open_vault_v2(&new_keys.vault_dek, &blob).unwrap();
    let doc: crate::types::VaultDocument = ciborium::from_reader(pt.as_slice()).unwrap();
    assert_eq!(doc.entries.len(), 1);
    assert_eq!(
        doc.entries.values().next().unwrap().password,
        "inbox-secret"
    );

    let reused = RootSecret::from_bytes(old_root);
    let reused_keys = derive_operational_keys(&reused, &vid).unwrap();
    assert!(open_vault_v2(&reused_keys.vault_dek, &blob).is_err());

    assert_ne!(store.get(SECRET_VAULT_V2).unwrap(), old_vault);
    assert_ne!(store.get(SECRET_AUDIT_V2).unwrap(), old_audit);

    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock { passphrase: PW.into() },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
}

#[test]
fn wrong_passphrase_rotation_leaves_epoch() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let before = store.durable_pairs();
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: "wrong-pass-phrase-here".into(),
            recovery_key: None,
        },
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(before, store.durable_pairs());
    let env = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_eq!(env.key_epoch, 0);
}

#[test]
fn rotation_commit_failure_leaves_old_epoch() {
    let mut inner_store = MemoryStore::default();
    let mut session = unlocked_v2(&mut inner_store);
    let before = inner_store.durable_pairs();
    let mut store = FailCommitStore {
        inner: inner_store,
        fail: true,
    };
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(before, store.inner.durable_pairs());
}

#[test]
fn rotation_unsupported_commit_leaves_old_epoch() {
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
    let mut inner = MemoryStore::default();
    let mut session = unlocked_v2(&mut inner);
    let before = inner.durable_pairs();
    let mut store = Reject(inner);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(before, store.0.durable_pairs());
}

#[test]
fn mixed_epoch_blobs_fail_closed() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let old_vault = store.get(SECRET_VAULT_V2).unwrap();
    dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    store.set(SECRET_VAULT_V2, &old_vault);
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock { passphrase: PW.into() },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "mixed-epoch / partial rollback must fail: {r:?}"
    );
    // Coherent rollback of envelope+vault+audit together is not detected by
    // local epoch equality; that needs retained newer state (Phase 7).
}

#[test]
fn vaultsync_blocks_rotation() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    store.set(SECRET_SYNC_STATE, b"active");
    let before = store.durable_pairs();
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    assert!(
        matches!(
            r,
            VaultResponse::Error {
                code: ErrorCode::VaultSyncMigrationDeferred,
                ..
            }
        ),
        "{r:?}"
    );
    assert_eq!(before, store.durable_pairs());
}

#[test]
fn v1_session_cannot_rotate() {
    let mut store = MemoryStore::default();
    let s = VaultSession::create(&mut store, PW, KdfProfile::Test).unwrap();
    let mut session = Some(ActiveSession::V1(s));
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    assert!(
        matches!(
            r,
            VaultResponse::Error {
                code: ErrorCode::MigrationRequired,
                ..
            }
        ),
        "{r:?}"
    );
}

#[test]
fn wrong_recovery_secret_aborts_rotation_and_leaves_epoch() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let rec = match dispatch(
        &mut store,
        &mut session,
        VaultRequest::GenerateRecoveryKey { kdf_profile: None },
    ) {
        VaultResponse::RecoveryKey { recovery_key, .. } => recovery_key,
        other => panic!("{other:?}"),
    };
    let before = store.durable_pairs();
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: Some("00".repeat(32)),
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "wrong recovery secret must abort: {r:?}"
    );
    assert_eq!(before, store.durable_pairs());
    let env = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_eq!(env.key_epoch, 0);
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: rec,
        },
    );
    assert!(
        matches!(r, VaultResponse::Unlocked { .. }),
        "original recovery path must remain: {r:?}"
    );
}

#[test]
fn recovery_secret_can_be_preserved_or_replaced() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let rec = match dispatch(
        &mut store,
        &mut session,
        VaultRequest::GenerateRecoveryKey { kdf_profile: None },
    ) {
        VaultResponse::RecoveryKey { recovery_key, .. } => recovery_key,
        other => panic!("{other:?}"),
    };

    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: Some(rec.clone()),
        },
    );
    match r {
        VaultResponse::Rotated {
            key_epoch,
            recovery_secret,
            ..
        } => {
            assert_eq!(key_epoch, 1);
            assert!(recovery_secret.is_none());
        }
        other => panic!("{other:?}"),
    }
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: rec.clone(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");

    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    let new_rec = match r {
        VaultResponse::Rotated {
            key_epoch,
            recovery_secret,
            ..
        } => {
            assert_eq!(key_epoch, 2);
            recovery_secret.expect("new recovery minted")
        }
        other => panic!("{other:?}"),
    };
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: rec,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "old recovery must not unlock after replacement: {r:?}"
    );
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: new_rec.clone(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let wrap = RecoveryWrapV2::from_cbor(&store.get(SECRET_RECOVERY_V2).unwrap()).unwrap();
    assert_eq!(wrap.key_epoch, 2);
    let secret = decode_recovery_secret(&new_rec).unwrap();
    let root = unwrap_recovery(&wrap, &secret).unwrap();
    let live = match session.as_ref().unwrap() {
        ActiveSession::V2(s) => s.root_bytes_for_test(),
        ActiveSession::V1(_) => panic!("expected v2"),
    };
    assert_eq!(root.as_bytes(), &live);
    assert!(!store.contains_plaintext(secret.as_bytes()));
}

#[test]
fn generation_store_rotation_is_atomic() {
    let mut raw = MemoryStore::default();
    let mut s = unlocked_v2(&mut raw);
    drop(s.take());
    let mut g = GenerationStore::new(raw);
    let opened = VaultSessionV2::unlock(&mut g, PW).unwrap();
    let mut session = Some(ActiveSession::V2(opened));
    let r = dispatch(
        &mut g,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    assert!(matches!(r, VaultResponse::Rotated { key_epoch: 1, .. }), "{r:?}");
    let env = MasterEnvelopeV2::from_bytes(&g.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_eq!(env.key_epoch, 1);
}

#[test]
fn file_store_rotation_roundtrip() {
    let mut nonce = [0u8; 8];
    crate::rng::fill_random(&mut nonce);
    let dir = std::env::temp_dir().join(format!("aegis-p6-{}", hex::encode(nonce)));
    let mut fs = FileStore::open(&dir).unwrap();
    let mut session = {
        let s = VaultSessionV2::create_with_params(
            &mut fs,
            PW,
            Argon2ParamsV2::insecure_for_tests(),
        )
        .unwrap();
        Some(ActiveSession::V2(s))
    };
    let r = dispatch(
        &mut fs,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    assert!(matches!(r, VaultResponse::Rotated { key_epoch: 1, .. }), "{r:?}");
    drop(session);
    let mut fs2 = FileStore::open(&dir).unwrap();
    let mut sess = None;
    let r = dispatch(
        &mut fs2,
        &mut sess,
        VaultRequest::Unlock { passphrase: PW.into() },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let env = MasterEnvelopeV2::from_bytes(&fs2.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_eq!(env.key_epoch, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn change_passphrase_after_rotation_keeps_new_root() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    let root = match session.as_ref().unwrap() {
        ActiveSession::V2(s) => s.root_bytes_for_test(),
        ActiveSession::V1(_) => panic!("expected v2"),
    };
    let new_pw = "new horse battery staple";
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::ChangePassphrase {
            current_passphrase: PW.into(),
            new_passphrase: new_pw.into(),
            kdf_profile: None,
        },
    );
    assert_eq!(r, VaultResponse::Ok);
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let env2 = MasterEnvelopeV2::from_bytes(&store.get(SECRET_ENVELOPE_V2).unwrap()).unwrap();
    assert_eq!(env2.key_epoch, 1);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: new_pw.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let root2 = match session.as_ref().unwrap() {
        ActiveSession::V2(s) => s.root_bytes_for_test(),
        ActiveSession::V1(_) => panic!("expected v2"),
    };
    assert_eq!(root, root2);
}
