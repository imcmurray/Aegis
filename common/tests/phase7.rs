//! Phase 7 / PR I: hybrid VaultSync (Ed25519 AND ML-DSA-65).

use crate::crypto::hkdf_v2::derive_operational_keys;
use crate::crypto::hybrid_sign::{
    verify_hybrid, HybridSignatureV2, HybridSyncIdentityV2, HybridSyncSigner, ML_DSA_65_SIG_LEN,
    ML_DSA_65_VK_LEN,
};
use crate::crypto::secret::{SyncEd25519Seed, SyncMldsaSeed};
use crate::crypto::CryptoError;
use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::secret::RootSecret;
use crate::crypto::suite::{CryptoSuiteId, KIND_SYNC_REVISION, SUITE_V2_SYNC_HYBRID_2026};
use crate::crypto::{
    build_sync_signing_transcript, decode_sync_v2, encode_sync_v2, MAGIC_SYNC_V2, VaultBlobV2,
};
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::session_v2::{VaultSessionV2, SECRET_VAULT_V2};
use crate::sync_types::{EncryptedRevision, VaultSyncState};
use crate::sync_v2::{
    check_monotonic, decode_state_v2, encode_cbor, encode_state_v2_file, open_doc_from_sync_v2,
    seal_doc_for_sync_v2, sign_revision_v2, sign_transition_v2, verify_revision_v2,
    verify_transition_v2, SyncAcceptedTableV2,
    VaultSyncParamsV2, VaultSyncStateV2, APP_VAULT_SYNC_V2, SECRET_SYNC_STATE_V2,
    SECRET_SYNC_TRANSITION_V2,
};
use crate::types::Entry;
use crate::crypto::KdfProfile;
use crate::vault::{
    dispatch, ActiveSession, MemoryStore, SecretStore, VaultSession, SECRET_SYNC_STATE,
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

fn signer_from_session(s: &VaultSessionV2) -> HybridSyncSigner {
    HybridSyncSigner::from_operational_keys(s.keys_for_test())
}

fn attacker_signer() -> HybridSyncSigner {
    HybridSyncSigner::from_seeds(
        &SyncEd25519Seed::random_for_tests(),
        &SyncMldsaSeed::random_for_tests(),
    )
}

#[test]
fn suite_and_kind_are_hybrid_revision() {
    assert_eq!(SUITE_V2_SYNC_HYBRID_2026, 0x0003);
    assert_eq!(KIND_SYNC_REVISION, 0x0007);
    assert_eq!(
        CryptoSuiteId::AegisV2SyncHybrid2026.to_u16(),
        0x0003
    );
}

#[test]
fn hybrid_and_matrix_accepts_only_both() {
    let mut store = MemoryStore::default();
    let session = unlocked_v2(&mut store).unwrap();
    let ActiveSession::V2(s) = session else {
        panic!("v2");
    };
    let signer = signer_from_session(&s);
    let id = signer.identity();
    assert_eq!(id.ml_dsa_vk.len(), ML_DSA_65_VK_LEN);
    let ct = seal_doc_for_sync_v2(s.keys_for_test(), s.vault_id_for_test(), 0, &s.doc).unwrap();
    let rev = sign_revision_v2(&signer, s.vault_id_for_test(), 0, "dev-a", 1, [0u8; 32], ct)
        .unwrap();
    assert_eq!(rev.crypto_suite, CryptoSuiteId::AegisV2SyncHybrid2026);
    assert!(verify_revision_v2(&id, &rev).is_ok());

    let mut ed_only = rev.clone();
    ed_only.ml_dsa_signature = vec![0u8; ML_DSA_65_SIG_LEN];
    assert!(verify_revision_v2(&id, &ed_only).is_err());

    let mut pq_only = rev.clone();
    pq_only.ed25519_signature = vec![0u8; 64];
    assert!(verify_revision_v2(&id, &pq_only).is_err());

    let mut truncated = rev.clone();
    truncated.ml_dsa_signature.truncate(16);
    assert!(verify_revision_v2(&id, &truncated).is_err());

    let mut core_suite = rev.clone();
    core_suite.crypto_suite = CryptoSuiteId::AegisV2Core2026;
    assert!(verify_revision_v2(&id, &core_suite).is_err());
}

#[test]
fn transcript_binds_identity_fields() {
    let vid = [9u8; 16];
    let parent = [0x11u8; 32];
    let ct_hash = [0x22u8; 32];
    let meta = vec![0x33u8; 32 + ML_DSA_65_VK_LEN];
    let a = build_sync_signing_transcript(&vid, 3, b"dev", 8, &parent, &ct_hash, &meta);
    assert!(a.starts_with(b"Aegis"));
    assert_eq!(&a[7..9], &[0x03, 0x00]);
    let b = build_sync_signing_transcript(&vid, 4, b"dev", 8, &parent, &ct_hash, &meta);
    assert_ne!(a, b);
    let c = build_sync_signing_transcript(&vid, 3, b"other", 8, &parent, &ct_hash, &meta);
    assert_ne!(a, c);
    let d = build_sync_signing_transcript(&vid, 3, b"dev", 9, &parent, &ct_hash, &meta);
    assert_ne!(a, d);
    let e = build_sync_signing_transcript(&vid, 3, b"dev", 8, &[0x12; 32], &ct_hash, &meta);
    assert_ne!(a, e);
}

#[test]
fn v1_revision_does_not_decode_as_v2() {
    let v1 = VaultSyncState {
        revisions: vec![EncryptedRevision {
            version_vector: Default::default(),
            device_id: "d".into(),
            signature: vec![0; 64],
            ciphertext: vec![1, 2, 3],
            content_hash: [0u8; 32],
        }],
    };
    let bytes = crate::sync_types::encode_cbor(&v1).unwrap();
    assert!(decode_state_v2(&bytes).is_err());
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::SyncWithRemote { remote_state: bytes },
    );
    assert!(
        matches!(r, VaultResponse::Error { .. }),
        "v1 remote must fail closed, got {r:?}"
    );
}

#[test]
fn replay_and_parent_substitution_are_rejected() {
    let mut store = MemoryStore::default();
    let session = unlocked_v2(&mut store).unwrap();
    let ActiveSession::V2(s) = session else {
        panic!("v2");
    };
    let signer = signer_from_session(&s);
    let vid = s.vault_id_for_test();
    let ct = seal_doc_for_sync_v2(s.keys_for_test(), vid, 0, &s.doc).unwrap();
    let rev1 = sign_revision_v2(&signer, vid, 0, "dev-a", 1, [0u8; 32], ct.clone()).unwrap();
    let mut accepted = SyncAcceptedTableV2::default();
    let h1 = check_monotonic(&accepted, &rev1).unwrap();
    accepted.record("dev-a".into(), 0, 1, h1);

    assert!(check_monotonic(&accepted, &rev1)
        .unwrap_err()
        .to_string()
        .contains("replay"));

    let rev2_bad_parent =
        sign_revision_v2(&signer, vid, 0, "dev-a", 2, [0xAAu8; 32], ct.clone()).unwrap();
    assert!(check_monotonic(&accepted, &rev2_bad_parent)
        .unwrap_err()
        .to_string()
        .contains("history substitution"));

    let rev2 = sign_revision_v2(&signer, vid, 0, "dev-a", 2, h1, ct).unwrap();
    assert!(check_monotonic(&accepted, &rev2).is_ok());
}

#[test]
fn inner_ciphertext_is_core_sync_blob_not_vault_dek() {
    let mut store = MemoryStore::default();
    let session = unlocked_v2(&mut store).unwrap();
    let ActiveSession::V2(s) = session else {
        panic!("v2");
    };
    let vid = s.vault_id_for_test();
    let ct = seal_doc_for_sync_v2(s.keys_for_test(), vid, 0, &s.doc).unwrap();
    let opened = open_doc_from_sync_v2(s.keys_for_test(), vid, 0, &ct).unwrap();
    assert_eq!(opened.entries.len(), s.doc.entries.len());
    // Vault DEK cannot stand in for SyncDek: open_sync uses sync-dek AAD.
    let vault_bytes = store.get(SECRET_VAULT_V2).unwrap();
    let blob = VaultBlobV2::from_bytes(&vault_bytes).unwrap();
    assert_ne!(blob.crypto_suite, CryptoSuiteId::AegisV2SyncHybrid2026);
}

#[test]
fn magic_sync_v2_round_trip() {
    let state = VaultSyncStateV2::default();
    let framed = encode_state_v2_file(&state).unwrap();
    assert!(framed.starts_with(MAGIC_SYNC_V2));
    assert_eq!(framed[MAGIC_SYNC_V2.len()], 0x02);
    let decoded = decode_state_v2(&framed).unwrap();
    assert!(decoded.revisions.is_empty());
    assert!(decode_sync_v2(&encode_sync_v2(&[0xa0])).is_ok());
}

#[test]
fn sync_now_v2_is_not_deferred() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let r = dispatch(&mut store, &mut session, VaultRequest::SyncNow);
    match r {
        VaultResponse::Synced { action, .. } => {
            assert!(action == "pushed" || action == "up_to_date" || action == "merged");
        }
        other => panic!("expected synced, got {other:?}"),
    }
    assert!(store.has(SECRET_SYNC_STATE_V2));
}

#[test]
fn two_devices_converge_on_hybrid_mvr() {
    let mut store_a = MemoryStore::default();
    let mut session_a = unlocked_v2(&mut store_a);
    let r = dispatch(&mut store_a, &mut session_a, VaultRequest::SyncNow);
    assert!(matches!(r, VaultResponse::Synced { .. }), "{r:?}");

    let mut store_b = store_a.clone();
    let mut session_b = Some(ActiveSession::V2(
        VaultSessionV2::unlock(&mut store_b, PW).unwrap(),
    ));
    if let Some(ActiveSession::V2(s)) = session_b.as_mut() {
        s.doc.meta.device_id = "device-b".into();
    }

    let mut e = Entry::new("e2", "Bank");
    e.password = "bank-secret".into();
    if let Some(ActiveSession::V2(s)) = session_a.as_mut() {
        s.doc.entries.insert(e.id.clone(), e);
        s.persist(&mut store_a).unwrap();
    }
    let r = dispatch(&mut store_a, &mut session_a, VaultRequest::SyncNow);
    let VaultResponse::Synced { contract_state, .. } = r else {
        panic!("a sync: {r:?}");
    };

    let r = dispatch(
        &mut store_b,
        &mut session_b,
        VaultRequest::SyncWithRemote {
            remote_state: contract_state,
        },
    );
    assert!(matches!(r, VaultResponse::Synced { .. }), "b sync: {r:?}");
    let ActiveSession::V2(b) = session_b.as_ref().unwrap() else {
        panic!("v2");
    };
    assert!(
        b.doc.entries.values().any(|e| e.name == "Bank"),
        "B should have pulled Bank"
    );
}

#[test]
fn rotation_writes_dual_signed_transition_and_rejects_old_epoch() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let _ = dispatch(&mut store, &mut session, VaultRequest::SyncNow);
    assert!(store.has(SECRET_SYNC_STATE_V2));

    let old_epoch = if let Some(ActiveSession::V2(s)) = &session {
        s.key_epoch_for_test()
    } else {
        panic!("v2");
    };
    let old_signer = if let Some(ActiveSession::V2(s)) = &session {
        signer_from_session(s)
    } else {
        panic!("v2");
    };
    let old_id = old_signer.identity();
    let vid = if let Some(ActiveSession::V2(s)) = &session {
        s.vault_id_for_test()
    } else {
        panic!("v2");
    };
    let old_ct = if let Some(ActiveSession::V2(s)) = &session {
        seal_doc_for_sync_v2(s.keys_for_test(), vid, old_epoch, &s.doc).unwrap()
    } else {
        panic!("v2");
    };
    let old_rev = sign_revision_v2(&old_signer, vid, old_epoch, "dev-a", 1, [0u8; 32], old_ct)
        .unwrap();

    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    match r {
        VaultResponse::Rotated { key_epoch, .. } => assert_eq!(key_epoch, old_epoch + 1),
        other => panic!("rotate: {other:?}"),
    }
    assert!(store.has(SECRET_SYNC_TRANSITION_V2));
    let t: crate::sync_v2::SyncIdentityTransitionV2 =
        crate::sync_v2::decode_cbor(&store.get(SECRET_SYNC_TRANSITION_V2).unwrap()).unwrap();
    assert!(verify_transition_v2(&t).is_ok());
    assert_eq!(t.old_identity, old_id);
    assert_ne!(t.new_identity, old_id);

    let new_signer = if let Some(ActiveSession::V2(s)) = &session {
        signer_from_session(s)
    } else {
        panic!("v2");
    };
    assert!(verify_revision_v2(&new_signer.identity(), &old_rev).is_err());

    let accepted = SyncAcceptedTableV2 {
        min_epoch: old_epoch + 1,
        entries: vec![],
    };
    assert!(check_monotonic(&accepted, &old_rev)
        .unwrap_err()
        .to_string()
        .contains("stale epoch"));
}

#[test]
fn v1_sync_keys_still_defer_rotation() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    store.set(SECRET_SYNC_STATE, b"v1-sync");
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
}

#[test]
fn v1_session_sync_is_unchanged_ed25519() {
    let mut store = MemoryStore::default();
    let session = VaultSession::create(&mut store, "test-pass", KdfProfile::Test).unwrap();
    let mut wrap = Some(ActiveSession::V1(session));
    let r = dispatch(&mut store, &mut wrap, VaultRequest::SyncNow);
    assert!(matches!(r, VaultResponse::Synced { .. }), "{r:?}");
}

#[test]
fn params_v2_app_id() {
    let keys = derive_operational_keys(&RootSecret::from_bytes([3; 32]), &[1u8; 16]).unwrap();
    let signer = HybridSyncSigner::from_seeds(&keys.sync_ed25519_seed, &keys.sync_mldsa_seed);
    let params = VaultSyncParamsV2::from_identity(&signer.identity());
    assert_eq!(params.app, APP_VAULT_SYNC_V2);
    params.validate().unwrap();
}

#[test]
fn transition_requires_both_identities() {
    let a = derive_operational_keys(&RootSecret::from_bytes([1; 32]), &[7u8; 16]).unwrap();
    let b = derive_operational_keys(&RootSecret::from_bytes([2; 32]), &[7u8; 16]).unwrap();
    let old_s = HybridSyncSigner::from_seeds(&a.sync_ed25519_seed, &a.sync_mldsa_seed);
    let new_s = HybridSyncSigner::from_seeds(&b.sync_ed25519_seed, &b.sync_mldsa_seed);
    let t = sign_transition_v2(&old_s, &new_s, [7u8; 16], 0, 1).unwrap();
    assert!(verify_transition_v2(&t).is_ok());
    let mut broken = t.clone();
    broken.old_signs_new_ml_dsa = vec![0u8; ML_DSA_65_SIG_LEN];
    assert!(verify_transition_v2(&broken).is_err());
    let mut broken = t.clone();
    broken.new_signs_old_ed25519 = vec![0u8; 64];
    assert!(verify_transition_v2(&broken).is_err());
}

#[test]
fn seeds_change_on_rotation() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let old_id = if let Some(ActiveSession::V2(s)) = &session {
        signer_from_session(s).identity()
    } else {
        panic!("v2");
    };
    let _ = dispatch(&mut store, &mut session, VaultRequest::SyncNow);
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::RotateKeys {
            passphrase: PW.into(),
            recovery_key: None,
        },
    );
    assert!(matches!(r, VaultResponse::Rotated { .. }), "{r:?}");
    let new_id = if let Some(ActiveSession::V2(s)) = &session {
        signer_from_session(s).identity()
    } else {
        panic!("v2");
    };
    assert_ne!(old_id, new_id);
}

#[test]
fn local_sync_never_opens_unverified_revision() {
    let mut store = MemoryStore::default();
    let mut session = unlocked_v2(&mut store);
    let _ = dispatch(&mut store, &mut session, VaultRequest::SyncNow);
    let ActiveSession::V2(s) = session.as_ref().unwrap() else {
        panic!("v2");
    };
    let signer = signer_from_session(s);
    let vid = s.vault_id_for_test();
    let mut forged_doc = s.doc.clone();
    let mut evil = Entry::new("evil", "Evil");
    evil.password = "pwned".into();
    forged_doc.entries.insert(evil.id.clone(), evil);
    let ct = seal_doc_for_sync_v2(s.keys_for_test(), vid, 0, &forged_doc).unwrap();
    let mut rev = sign_revision_v2(&signer, vid, 0, "attacker", 1, [0u8; 32], ct).unwrap();
    rev.ed25519_signature = vec![1u8; 64];
    let mut remote = VaultSyncStateV2::default();
    remote.revisions.push(rev);
    let bytes = encode_cbor(&remote).unwrap();

    let before = s.doc.entries.len();
    let r = dispatch(
        &mut store,
        &mut session,
        VaultRequest::SyncWithRemote { remote_state: bytes },
    );
    assert!(matches!(r, VaultResponse::Synced { .. }), "{r:?}");
    let ActiveSession::V2(s) = session.as_ref().unwrap() else {
        panic!("v2");
    };
    assert_eq!(s.doc.entries.len(), before);
    assert!(!s.doc.entries.values().any(|e| e.name == "Evil"));
}

#[test]
fn attacker_hybrid_keys_are_rejected_even_when_both_signatures_verify() {
    let mut store = MemoryStore::default();
    let session = unlocked_v2(&mut store).unwrap();
    let ActiveSession::V2(s) = session else {
        panic!("v2");
    };
    let trusted = signer_from_session(&s);
    let trusted_id = trusted.identity();
    let attacker = attacker_signer();
    let attacker_id = attacker.identity();
    assert_ne!(trusted_id, attacker_id);

    let vid = s.vault_id_for_test();
    let device = s.doc.meta.device_id.clone();
    let ct = seal_doc_for_sync_v2(s.keys_for_test(), vid, 0, &s.doc).unwrap();
    let rev = sign_revision_v2(&attacker, vid, 0, &device, 1, [0u8; 32], ct).unwrap();

    let transcript = rev.signing_transcript().unwrap();
    assert!(
        verify_hybrid(&attacker_id, &transcript, &rev.hybrid_signature()).is_ok(),
        "attacker signatures must verify under attacker keys"
    );
    assert_eq!(
        verify_revision_v2(&trusted_id, &rev),
        Err(CryptoError::UnauthorizedSyncIdentity)
    );
}

#[test]
fn substituting_only_ed25519_or_only_mldsa_key_is_rejected() {
    let mut store = MemoryStore::default();
    let session = unlocked_v2(&mut store).unwrap();
    let ActiveSession::V2(s) = session else {
        panic!("v2");
    };
    let trusted = signer_from_session(&s);
    let trusted_id = trusted.identity();
    let attacker = attacker_signer();
    let attacker_id = attacker.identity();
    let vid = s.vault_id_for_test();
    let ct = seal_doc_for_sync_v2(s.keys_for_test(), vid, 0, &s.doc).unwrap();

    let mut ed_only = sign_revision_v2(&trusted, vid, 0, "dev-a", 1, [0u8; 32], ct.clone()).unwrap();
    ed_only.ed25519_vk = attacker_id.ed25519_vk.clone();
    assert_eq!(
        verify_revision_v2(&trusted_id, &ed_only),
        Err(CryptoError::UnauthorizedSyncIdentity)
    );

    let mut pq_only = sign_revision_v2(&trusted, vid, 0, "dev-a", 1, [0u8; 32], ct.clone()).unwrap();
    pq_only.ml_dsa_vk = attacker_id.ml_dsa_vk.clone();
    assert_eq!(
        verify_revision_v2(&trusted_id, &pq_only),
        Err(CryptoError::UnauthorizedSyncIdentity)
    );

    // Mixed identity, both halves signed correctly over the mixed transcript.
    let mixed = HybridSyncIdentityV2 {
        ed25519_vk: attacker_id.ed25519_vk.clone(),
        ml_dsa_vk: trusted_id.ml_dsa_vk.clone(),
    };
    let ciphertext_hash = *blake3::hash(&ct).as_bytes();
    let transcript = build_sync_signing_transcript(
        &vid,
        0,
        b"dev-a",
        1,
        &[0u8; 32],
        &ciphertext_hash,
        &mixed.metadata().unwrap(),
    );
    let ed_sig = attacker.sign(&transcript);
    let pq_sig = trusted.sign(&transcript);
    let mixed_sig = HybridSignatureV2 {
        ed25519: ed_sig.ed25519,
        ml_dsa: pq_sig.ml_dsa,
    };
    assert!(verify_hybrid(&mixed, &transcript, &mixed_sig).is_ok());
    let mixed_rev = crate::sync_v2::EncryptedRevisionV2 {
        format_version: 2,
        crypto_suite: CryptoSuiteId::AegisV2SyncHybrid2026,
        vault_id: vid.to_vec(),
        key_epoch: 0,
        device_id: "dev-a".into(),
        counter: 1,
        parent_hash: [0u8; 32],
        ciphertext_hash,
        ciphertext: ct,
        ed25519_vk: mixed.ed25519_vk.clone(),
        ml_dsa_vk: mixed.ml_dsa_vk.clone(),
        ed25519_signature: mixed_sig.ed25519,
        ml_dsa_signature: mixed_sig.ml_dsa,
    };
    assert_eq!(
        verify_revision_v2(&trusted_id, &mixed_rev),
        Err(CryptoError::UnauthorizedSyncIdentity)
    );
}

#[test]
fn d10_sync_magic_is_aegis_sync_v2_not_contract_app_id() {
    assert_eq!(MAGIC_SYNC_V2, b"AEGIS_SYNC_V2");
    assert_ne!(MAGIC_SYNC_V2, APP_VAULT_SYNC_V2.as_bytes());
    let framed = encode_state_v2_file(&VaultSyncStateV2::default()).unwrap();
    assert!(framed.starts_with(MAGIC_SYNC_V2));
    assert_eq!(framed[MAGIC_SYNC_V2.len()], 0x02);
    decode_state_v2(&framed).unwrap();

    let mut wrong_magic = framed.clone();
    wrong_magic.splice(0..MAGIC_SYNC_V2.len(), b"AEGIS_VAULT_SYNC_V2".iter().copied());
    assert_eq!(decode_state_v2(&wrong_magic), Err(CryptoError::InvalidMagic));
    assert_eq!(
        decode_sync_v2(b"AEGIS_VAULT_SYNC_V2\x02\xa0"),
        Err(CryptoError::InvalidMagic)
    );

    let mut bad_ver = encode_sync_v2(&[0xa0]);
    bad_ver[MAGIC_SYNC_V2.len()] = 0x03;
    assert_eq!(
        decode_sync_v2(&bad_ver),
        Err(CryptoError::UnsupportedVersion(3))
    );
}
