//! Phase 9 / PR K: Recovery Kit productization.

use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::suite::{KIND_RECOVERY_WRAP, SUITE_V2_CORE_2026};
use crate::crypto::{
    CryptoSuiteId, MAGIC_BACKUP_V2, MAGIC_RECOVERY_V2, MAGIC_SYNC_V2, MAGIC_VAULT_V2,
};
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::recovery_v2::{
    decode_recovery_secret, encode_recovery_secret, unwrap_recovery, RecoveryWrapV2,
};
use crate::session_v2::{VaultSessionV2, SECRET_ENVELOPE_V2};
use crate::types::Entry;
use crate::vault::{dispatch, ActiveSession, MemoryStore, SecretStore, VaultSession};

const PW: &str = "correct horse battery staple";
const PW2: &str = "another horse battery staple";

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

fn generate_kit(store: &mut MemoryStore, session: &mut Option<ActiveSession>) -> (String, Vec<u8>) {
    match dispatch(
        store,
        session,
        VaultRequest::GenerateRecoveryKey { kdf_profile: None },
    ) {
        VaultResponse::RecoveryKey { recovery_key, kit } => (recovery_key, kit),
        other => panic!("{other:?}"),
    }
}

fn import_kit(
    kit: Vec<u8>,
    secret: impl Into<String>,
    new_pw: impl Into<String>,
    backup: Vec<u8>,
    backup_pw: Option<String>,
) -> VaultRequest {
    VaultRequest::ImportRecoveryKit {
        kit,
        recovery_secret: secret.into(),
        new_passphrase: new_pw.into(),
        backup,
        backup_passphrase: backup_pw,
    }
}

fn v2_ids(session: &Option<ActiveSession>) -> ([u8; 16], u32, [u8; 32]) {
    match session.as_ref().unwrap() {
        ActiveSession::V2(s) => (
            s.vault_id_for_test(),
            s.key_epoch_for_test(),
            s.root_bytes_for_test(),
        ),
        ActiveSession::V1(_) => panic!("expected v2"),
    }
}

#[test]
fn suite_and_kind_are_core_recovery_wrap() {
    assert_eq!(SUITE_V2_CORE_2026, 0x0002);
    assert_eq!(KIND_RECOVERY_WRAP, 0x000C);
    assert_eq!(CryptoSuiteId::AegisV2Core2026.to_u16(), 0x0002);
}

#[test]
fn kit_magic_is_distinct_and_kit_has_no_plaintext_root() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, kit) = generate_kit(&mut store, &mut session);
    assert!(kit.starts_with(MAGIC_RECOVERY_V2));
    assert_eq!(kit[MAGIC_RECOVERY_V2.len()], 0x02);
    assert!(!kit.starts_with(MAGIC_VAULT_V2));
    assert!(!kit.starts_with(MAGIC_BACKUP_V2));
    assert!(!kit.starts_with(MAGIC_SYNC_V2));
    let (vid, _epoch, root) = v2_ids(&session);
    assert!(!kit.windows(32).any(|w| w == root.as_slice()));
    let rec = decode_recovery_secret(&secret).unwrap();
    assert!(!kit.windows(32).any(|w| w == rec.as_bytes().as_slice()));
    assert!(!store.contains_plaintext(rec.as_bytes()));
    assert!(!store.contains_plaintext(&root));
    let wrap = RecoveryWrapV2::from_kit_bytes(&kit).unwrap();
    assert_eq!(wrap.crypto_suite, CryptoSuiteId::AegisV2Core2026);
    assert_eq!(wrap.object_kind, KIND_RECOVERY_WRAP);
    assert_eq!(wrap.vault_id.as_slice(), vid.as_slice());
    assert_eq!(
        unwrap_recovery(&wrap, &rec).unwrap().as_bytes(),
        &root
    );
}

#[test]
fn recovery_import_restores_same_identity_backup_does_not() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (vid, epoch, root) = v2_ids(&session);
    let (secret, kit) = generate_kit(&mut store, &mut session);
    let backup = match dispatch(
        &mut store,
        &mut session,
        VaultRequest::ExportEncrypted {
            passphrase: PW.into(),
        },
    ) {
        VaultResponse::Export { blob } => blob,
        other => panic!("{other:?}"),
    };
    assert!(backup.starts_with(MAGIC_BACKUP_V2));
    assert!(!backup.starts_with(MAGIC_RECOVERY_V2));
    let rec = decode_recovery_secret(&secret).unwrap();
    assert!(!backup.windows(32).any(|w| w == rec.as_bytes().as_slice()));
    assert!(!backup.windows(32).any(|w| w == root.as_slice()));

    let mut kit_only = MemoryStore::default();
    let mut kit_only_session = None;
    let r = dispatch(
        &mut kit_only,
        &mut kit_only_session,
        import_kit(kit.clone(), secret.clone(), PW2, Vec::new(), None),
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "kit alone must not restore an empty install: {r:?}"
    );
    assert!(!kit_only.has(SECRET_ENVELOPE_V2));

    let mut recovered = MemoryStore::default();
    let mut rec_session = None;
    let r = dispatch(
        &mut recovered,
        &mut rec_session,
        import_kit(
            kit,
            secret.clone(),
            PW2,
            backup.clone(),
            Some(PW.into()),
        ),
    );
    match r {
        VaultResponse::Unlocked { vault_id } => {
            assert_eq!(vault_id, hex::encode(vid));
        }
        other => panic!("{other:?}"),
    }
    let (rec_vid, rec_epoch, rec_root) = v2_ids(&rec_session);
    assert_eq!(rec_vid, vid);
    assert_eq!(rec_epoch, epoch);
    assert_eq!(rec_root, root);
    assert!(!recovered.contains_plaintext(rec.as_bytes()));
    let r = dispatch(
        &mut recovered,
        &mut rec_session,
        VaultRequest::ListSummaries { query: None },
    );
    match r {
        VaultResponse::Summaries { entries } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name, "Mail");
        }
        other => panic!("{other:?}"),
    }

    let mut from_backup = MemoryStore::default();
    let mut bak_session = None;
    let r = dispatch(
        &mut from_backup,
        &mut bak_session,
        VaultRequest::ImportEncrypted {
            blob: backup,
            passphrase: PW.into(),
            new_passphrase: Some(PW2.into()),
            replace: false,
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let (bak_vid, _, bak_root) = v2_ids(&bak_session);
    assert_ne!(bak_vid, vid, "backup restore must mint a new vault_id");
    assert_ne!(bak_root, root, "backup restore must mint a new RootSecret");
}

#[test]
fn corrupt_or_wrong_type_kits_fail_closed() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, kit) = generate_kit(&mut store, &mut session);

    let cases: Vec<Vec<u8>> = {
        let mut magic = kit.clone();
        magic[0] ^= 0x01;
        let mut ver = kit.clone();
        ver[MAGIC_RECOVERY_V2.len()] = 0x03;
        let mut body = kit.clone();
        let last = body.len() - 1;
        body[last] ^= 0xff;
        vec![
            magic,
            ver,
            body,
            Vec::new(),
            b"\xa0".to_vec(),
            MAGIC_BACKUP_V2.to_vec(),
            MAGIC_VAULT_V2.to_vec(),
        ]
    };
    for bad in cases {
        let mut dest = MemoryStore::default();
        let mut sess = None;
        let r = dispatch(
            &mut dest,
            &mut sess,
            import_kit(bad, secret.clone(), PW2, Vec::new(), None),
        );
        assert!(
            matches!(r, VaultResponse::Error { .. }),
            "malformed kit must fail closed: {r:?}"
        );
        assert!(sess.is_none());
        assert!(!dest.has(SECRET_ENVELOPE_V2));
    }
}

#[test]
fn tampered_authenticated_fields_fail_closed() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, kit) = generate_kit(&mut store, &mut session);
    let wrap = RecoveryWrapV2::from_kit_bytes(&kit).unwrap();

    let mut suite = wrap.clone();
    suite.crypto_suite = CryptoSuiteId::AegisV2ShareHybrid2026;
    let mut kind = wrap.clone();
    kind.object_kind = 0x0001;
    let mut epoch = wrap.clone();
    epoch.key_epoch = wrap.key_epoch.wrapping_add(1);
    let mut vid = wrap.clone();
    vid.vault_id[0] ^= 0xff;
    let mut ver = wrap.clone();
    ver.format_version = 1;
    let mut nonce = wrap.clone();
    nonce.nonce[0] ^= 0xff;
    let mut ct = wrap.clone();
    ct.wrapped_root[0] ^= 0xff;

    for tampered in [suite, kind, epoch, vid, ver, nonce, ct] {
        let bytes = tampered.to_kit_bytes().unwrap();
        let mut dest = MemoryStore::default();
        let mut sess = None;
        let r = dispatch(
            &mut dest,
            &mut sess,
            import_kit(bytes, secret.clone(), PW2, Vec::new(), None),
        );
        assert!(
            matches!(r, VaultResponse::Error { .. }),
            "tamper must fail closed: {r:?}"
        );
        assert!(!dest.has(SECRET_ENVELOPE_V2));
    }
}

#[test]
fn failed_import_does_not_destroy_existing_vault() {
    let mut live = MemoryStore::default();
    let mut session = unlocked_v2(&mut live);
    let before = live.durable_pairs();
    let (vid, epoch, root) = v2_ids(&session);
    let (secret, kit) = generate_kit(&mut live, &mut session);
    let after_gen = live.durable_pairs();

    let mut bad = kit.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xff;
    let r = dispatch(
        &mut live,
        &mut session,
        import_kit(bad, secret.clone(), PW2, Vec::new(), None),
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(live.durable_pairs(), after_gen);
    let (vid2, epoch2, root2) = v2_ids(&session);
    assert_eq!(vid2, vid);
    assert_eq!(epoch2, epoch);
    assert_eq!(root2, root);

    let backup_as_kit = match dispatch(
        &mut live,
        &mut session,
        VaultRequest::ExportEncrypted {
            passphrase: PW.into(),
        },
    ) {
        VaultResponse::Export { blob } => blob,
        other => panic!("{other:?}"),
    };
    let r = dispatch(
        &mut live,
        &mut session,
        import_kit(
            backup_as_kit.clone(),
            secret.clone(),
            PW2,
            Vec::new(),
            None,
        ),
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(live.durable_pairs(), after_gen);

    let r = dispatch(
        &mut live,
        &mut session,
        VaultRequest::ImportEncrypted {
            blob: kit,
            passphrase: secret,
            new_passphrase: Some(PW2.into()),
            replace: true,
        },
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(live.durable_pairs(), after_gen);
    assert_ne!(before, after_gen, "generate must persist a wrap");
}

#[test]
fn regeneration_retires_previous_secret_and_uses_fresh_nonce() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (old_secret, old_kit) = generate_kit(&mut store, &mut session);
    let old_wrap = RecoveryWrapV2::from_kit_bytes(&old_kit).unwrap();
    let (new_secret, new_kit) = generate_kit(&mut store, &mut session);
    let new_wrap = RecoveryWrapV2::from_kit_bytes(&new_kit).unwrap();
    assert_ne!(old_wrap.nonce, new_wrap.nonce);
    assert_ne!(old_secret, new_secret);

    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: old_secret,
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "old recovery must be retired: {r:?}"
    );
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: new_secret.clone(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let rec = decode_recovery_secret(&new_secret).unwrap();
    assert!(!store.contains_plaintext(rec.as_bytes()));
}

#[test]
fn display_secret_is_checksummed_256_bit_and_rejects_v1() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, _kit) = generate_kit(&mut store, &mut session);
    assert!(secret.starts_with("AEGIS2-"));
    let rec = decode_recovery_secret(&secret).unwrap();
    assert_eq!(rec.as_bytes().len(), 32);
    assert_eq!(
        encode_recovery_secret(&rec).replace('-', ""),
        secret.replace('-', "")
    );
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: "AEGIS-0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ".into(),
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "v1 recovery must not unlock v2: {r:?}"
    );
}

#[test]
fn v1_recovery_remains_legacy_migration_only() {
    let mut store = MemoryStore::default();
    let s = VaultSession::create(&mut store, PW, crate::crypto::KdfProfile::Test).unwrap();
    let mut session = Some(ActiveSession::V1(s));
    let rec = match dispatch(
        &mut store,
        &mut session,
        VaultRequest::GenerateRecoveryKey {
            kdf_profile: Some(crate::crypto::KdfProfile::Test),
        },
    ) {
        VaultResponse::RecoveryKey { recovery_key, kit } => {
            assert!(kit.is_empty(), "v1 must not emit a v2 Recovery Kit");
            recovery_key
        }
        other => panic!("{other:?}"),
    };
    assert!(rec.starts_with("AEGIS-"));
    assert!(!rec.starts_with("AEGIS2-"));
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: rec,
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
}

#[test]
fn export_kit_does_not_mint_a_new_secret() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, kit) = generate_kit(&mut store, &mut session);
    let r = dispatch(&mut store, &mut session, VaultRequest::ExportRecoveryKit);
    match r {
        VaultResponse::RecoveryKey {
            recovery_key,
            kit: exported,
        } => {
            assert!(recovery_key.is_empty());
            assert_eq!(exported, kit);
        }
        other => panic!("{other:?}"),
    }
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: secret,
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
}

#[test]
fn existing_vault_lost_passphrase_recovery_does_not_need_old_passphrase() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, kit) = generate_kit(&mut store, &mut session);
    let (vid, epoch, root) = v2_ids(&session);
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    assert!(session.is_none());

    let before = store.durable_pairs();
    let r = dispatch(
        &mut store,
        &mut session,
        import_kit(kit, secret.clone(), PW2, Vec::new(), None),
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let (vid2, epoch2, root2) = v2_ids(&session);
    assert_eq!(vid2, vid);
    assert_eq!(epoch2, epoch);
    assert_eq!(root2, root);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::ListSummaries { query: None },
    );
    match r {
        VaultResponse::Summaries { entries } => {
            assert_eq!(entries[0].name, "Mail");
        }
        other => panic!("{other:?}"),
    }
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: PW.into(),
        },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "old passphrase must not unlock: {r:?}"
    );
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::Unlock {
            passphrase: PW2.into(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::UnlockWithRecovery {
            recovery_key: secret.clone(),
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    let rec = decode_recovery_secret(&secret).unwrap();
    assert!(!store.contains_plaintext(rec.as_bytes()));
    assert_ne!(store.durable_pairs(), before);
}

#[test]
fn weak_new_passphrase_and_wrong_secret_leave_existing_vault() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, kit) = generate_kit(&mut store, &mut session);
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let after_gen = store.durable_pairs();

    let r = dispatch(
        &mut store,
        &mut session,
        import_kit(kit.clone(), secret.clone(), "password", Vec::new(), None),
    );
    assert!(
        matches!(
            r,
            VaultResponse::Error {
                code: ErrorCode::InvalidRequest,
                ..
            }
        ),
        "{r:?}"
    );
    assert_eq!(store.durable_pairs(), after_gen);

    let r = dispatch(
        &mut store,
        &mut session,
        import_kit(
            kit,
            "00".repeat(32),
            PW2,
            Vec::new(),
            None,
        ),
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(store.durable_pairs(), after_gen);
}

#[test]
fn wrong_vault_id_and_stale_or_future_epoch_are_rejected() {
    let mut store_a = MemoryStore::default();
    let mut session_a = unlocked_v2(&mut store_a);
    let (secret_a, kit_a) = generate_kit(&mut store_a, &mut session_a);

    let mut store_b = MemoryStore::default();
    let mut session_b = unlocked_v2(&mut store_b);
    dispatch(&mut store_b, &mut session_b, VaultRequest::Lock);
    let after_b = store_b.durable_pairs();
    let r = dispatch(
        &mut store_b,
        &mut session_b,
        import_kit(kit_a.clone(), secret_a.clone(), PW2, Vec::new(), None),
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(store_b.durable_pairs(), after_b);

    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, kit) = generate_kit(&mut store, &mut session);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    assert!(matches!(r, VaultResponse::Rotated { key_epoch: 1, .. }), "{r:?}");
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let after_rot = store.durable_pairs();
    let r = dispatch(
        &mut store,
        &mut session,
        import_kit(kit, secret, PW2, Vec::new(), None),
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "stale epoch-0 kit must not roll back epoch 1: {r:?}"
    );
    assert_eq!(store.durable_pairs(), after_rot);

    let mut live = MemoryStore::default();
    let mut live_session = unlocked_v2(&mut live);
    let (_s, _k) = generate_kit(&mut live, &mut live_session);
    let (live_vid, live_epoch, live_root) = v2_ids(&live_session);
    let (future_wrap, future_secret) = crate::recovery_v2::wrap_recovery(
        &crate::crypto::secret::RootSecret::from_bytes(live_root),
        live_vid,
        live_epoch + 9,
    )
    .unwrap();
    dispatch(&mut live, &mut live_session, VaultRequest::Lock);
    let after_live = live.durable_pairs();
    let r = dispatch(
        &mut live,
        &mut live_session,
        import_kit(
            future_wrap.to_kit_bytes().unwrap(),
            crate::recovery_v2::encode_recovery_secret(&future_secret),
            PW2,
            Vec::new(),
            None,
        ),
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "future-epoch kit must be rejected: {r:?}"
    );
    assert_eq!(live.durable_pairs(), after_live);
}

#[test]
fn recovered_root_must_open_current_vault_and_audit_before_commit() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let (secret, kit) = generate_kit(&mut store, &mut session);
    dispatch(&mut store, &mut session, VaultRequest::Lock);
    let mut vault = store.get(crate::session_v2::SECRET_VAULT_V2).unwrap();
    let last = vault.len() - 1;
    vault[last] ^= 0xff;
    store.set(crate::session_v2::SECRET_VAULT_V2, &vault);
    let after = store.durable_pairs();
    let r = dispatch(
        &mut store,
        &mut session,
        import_kit(kit, secret, PW2, Vec::new(), None),
    );
    assert!(matches!(r, VaultResponse::Error { .. }), "{r:?}");
    assert_eq!(store.durable_pairs(), after);
}
