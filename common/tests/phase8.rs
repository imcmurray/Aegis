//! Phase 8 / PR J: hybrid sharing (X25519 AND ML-KEM-768, D5 combiner).

use crate::crypto::hkdf_v2::derive_operational_keys;
use crate::crypto::hybrid_kem::{combine_hybrid_secret, MLKEM_768_EK_LEN};
use crate::crypto::hybrid_sign::HybridSyncSigner;
use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::secret::{RootSecret, ShareX25519Seed};
use crate::crypto::suite::{CryptoSuiteId, KIND_SHARE_ENVELOPE, SUITE_V2_SHARE_HYBRID_2026};
use crate::crypto::CryptoError;
use crate::messages::{VaultRequest, VaultResponse};
use crate::session_v2::VaultSessionV2;
use crate::crypto::hybrid_sign::verify_hybrid;
use crate::share::{
    authorize_share_sender, create_share_envelope, export_share_identity, open_share_envelope,
    verify_share_identity, SharePublicIdentityV2,
};
use crate::types::Entry;
use crate::vault::{dispatch, ActiveSession, MemoryStore};

const PW: &str = "correct horse battery staple";
const PW2: &str = "another horse battery staple";

fn identity_of(s: &VaultSessionV2) -> SharePublicIdentityV2 {
    export_share_identity(s.keys_for_test(), s.vault_id_for_test(), s.key_epoch_for_test()).unwrap()
}

fn unlocked_v2(store: &mut MemoryStore, pw: &str) -> VaultSessionV2 {
    let mut session = VaultSessionV2::create_with_params(
        store,
        pw,
        Argon2ParamsV2::insecure_for_tests(),
    )
    .expect("v2 create");
    let mut e = Entry::new("e1", "Shared login");
    e.password = "share-secret".into();
    session.doc.entries.insert(e.id.clone(), e);
    session.persist(store).expect("persist");
    session
}

#[test]
fn suite_is_share_hybrid() {
    assert_eq!(SUITE_V2_SHARE_HYBRID_2026, 0x0004);
    assert_eq!(KIND_SHARE_ENVELOPE, 0x000A);
    assert_eq!(
        CryptoSuiteId::AegisV2ShareHybrid2026.to_u16(),
        0x0004
    );
}

#[test]
fn share_round_trip_between_two_vaults() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let recip = export_share_identity(b.keys_for_test(), b.vault_id_for_test(), b.key_epoch_for_test())
        .unwrap();
    let entry = a.doc.entries.get("e1").unwrap();
    let env = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip,
        entry,
    )
    .unwrap();
    assert_eq!(env.crypto_suite, CryptoSuiteId::AegisV2ShareHybrid2026);
    let opened = open_share_envelope(
        b.keys_for_test(),
        b.vault_id_for_test(),
        b.key_epoch_for_test(),
        &env,
        &identity_of(&a),
    )
    .unwrap();
    assert_eq!(opened.password, "share-secret");
}

#[test]
fn dispatch_export_create_open_share() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let mut sess_a = Some(ActiveSession::V2(a));
    let mut sess_b = Some(ActiveSession::V2(b));
    let id = dispatch(&mut store_b, &mut sess_b, VaultRequest::ExportShareIdentity);
    let VaultResponse::ShareIdentity { blob: recip } = id else {
        panic!("{id:?}");
    };
    let sender_id = dispatch(&mut store_a, &mut sess_a, VaultRequest::ExportShareIdentity);
    let VaultResponse::ShareIdentity { blob: sender_blob } = sender_id else {
        panic!("{sender_id:?}");
    };
    let created = dispatch(
        &mut store_a,
        &mut sess_a,
        VaultRequest::CreateShare {
            entry_id: "e1".into(),
            recipient_identity: recip,
        },
    );
    let VaultResponse::ShareEnvelope { blob: env } = created else {
        panic!("{created:?}");
    };
    let opened = dispatch(
        &mut store_b,
        &mut sess_b,
        VaultRequest::OpenShare {
            envelope: env,
            expected_sender_identity: sender_blob,
        },
    );
    match opened {
        VaultResponse::Entry { entry } => assert_eq!(entry.password, "share-secret"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn substituting_recipient_x25519_is_rejected() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let mut recip =
        export_share_identity(b.keys_for_test(), b.vault_id_for_test(), b.key_epoch_for_test())
            .unwrap();
    recip.x25519_public_key = ShareX25519Seed::random_for_tests()
        .as_bytes()
        .to_vec();
    assert_eq!(
        verify_share_identity(&recip),
        Err(CryptoError::UnauthorizedShareIdentity)
    );
    let entry = a.doc.entries.get("e1").unwrap();
    assert!(create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip,
        entry,
    )
    .is_err());
}

#[test]
fn substituting_recipient_mlkem_is_rejected() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let mut recip =
        export_share_identity(b.keys_for_test(), b.vault_id_for_test(), b.key_epoch_for_test())
            .unwrap();
    let other = derive_operational_keys(&RootSecret::from_bytes([9; 32]), &[2u8; 16]).unwrap();
    recip.ml_kem_768_public_key =
        crate::crypto::hybrid_kem::mlkem_ek_from_seed(&other.share_mlkem_seed).unwrap();
    assert_eq!(recip.ml_kem_768_public_key.len(), MLKEM_768_EK_LEN);
    assert_eq!(
        verify_share_identity(&recip),
        Err(CryptoError::UnauthorizedShareIdentity)
    );
    let entry = a.doc.entries.get("e1").unwrap();
    assert!(create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip,
        entry,
    )
    .is_err());
}

#[test]
fn attacker_signed_mixed_identity_is_not_accepted_by_victim() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let mut store_c = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let c = unlocked_v2(&mut store_c, "third horse battery staple");
    let victim =
        export_share_identity(b.keys_for_test(), b.vault_id_for_test(), b.key_epoch_for_test())
            .unwrap();
    let mut mixed =
        export_share_identity(c.keys_for_test(), c.vault_id_for_test(), c.key_epoch_for_test())
            .unwrap();
    mixed.ml_kem_768_public_key = victim.ml_kem_768_public_key.clone();
    // Re-sign mixed keys with attacker (C) signing identity.
    let signer = HybridSyncSigner::from_operational_keys(c.keys_for_test());
    mixed.signing_identity = signer.identity();
    let t = crate::crypto::build_share_identity_transcript(
        &c.vault_id_for_test(),
        c.key_epoch_for_test(),
        &mixed.x25519_public_key,
        &mixed.ml_kem_768_public_key,
        &mixed.signing_identity.metadata().unwrap(),
    );
    let sig = signer.sign(&t);
    mixed.ed25519_signature = sig.ed25519;
    mixed.ml_dsa_signature = sig.ml_dsa;
    mixed.vault_id = c.vault_id_for_test().to_vec();
    assert!(verify_share_identity(&mixed).is_ok());

    let entry = a.doc.entries.get("e1").unwrap();
    let env = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &mixed,
        entry,
    )
    .unwrap();
    assert_eq!(
        open_share_envelope(
            b.keys_for_test(),
            b.vault_id_for_test(),
            b.key_epoch_for_test(),
            &env,
            &identity_of(&a),
        )
        .unwrap_err(),
        CryptoError::UnauthorizedShareIdentity
    );
}

#[test]
fn altered_mlkem_ciphertext_does_not_open() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let recip =
        export_share_identity(b.keys_for_test(), b.vault_id_for_test(), b.key_epoch_for_test())
            .unwrap();
    let entry = a.doc.entries.get("e1").unwrap();
    let mut env = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip,
        entry,
    )
    .unwrap();
    env.mlkem_ciphertext[0] ^= 0x01;
    assert!(open_share_envelope(
        b.keys_for_test(),
        b.vault_id_for_test(),
        b.key_epoch_for_test(),
        &env,
        &identity_of(&a),
    )
    .is_err());
}

#[test]
fn wrong_recipient_cannot_open() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let mut store_c = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let c = unlocked_v2(&mut store_c, "third horse battery staple");
    let recip =
        export_share_identity(b.keys_for_test(), b.vault_id_for_test(), b.key_epoch_for_test())
            .unwrap();
    let entry = a.doc.entries.get("e1").unwrap();
    let env = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip,
        entry,
    )
    .unwrap();
    assert_eq!(
        open_share_envelope(
            c.keys_for_test(),
            c.vault_id_for_test(),
            c.key_epoch_for_test(),
            &env,
            &identity_of(&a),
        )
        .unwrap_err(),
        CryptoError::UnauthorizedShareIdentity
    );
}

#[test]
fn missing_pq_or_core_suite_fails_closed() {
    let mut id = SharePublicIdentityV2 {
        format_version: 2,
        crypto_suite: CryptoSuiteId::AegisV2Core2026,
        vault_id: vec![0; 16],
        key_epoch: 0,
        x25519_public_key: vec![1; 32],
        ml_kem_768_public_key: vec![2; MLKEM_768_EK_LEN],
        signing_identity: crate::crypto::hybrid_sign::HybridSyncIdentityV2 {
            ed25519_vk: vec![3; 32],
            ml_dsa_vk: vec![4; 1952],
        },
        ed25519_signature: vec![5; 64],
        ml_dsa_signature: vec![6; 3309],
    };
    assert!(id.validate_header().is_err());
    id.crypto_suite = CryptoSuiteId::AegisV2SyncHybrid2026;
    assert!(id.validate_header().is_err());
    id.crypto_suite = CryptoSuiteId::AegisV2ShareHybrid2026;
    id.ml_kem_768_public_key.clear();
    assert!(id.validate_header().is_err());
}

#[test]
fn either_kem_component_changes_hybrid_secret() {
    let a = combine_hybrid_secret(&[1u8; 32], &[2u8; 32], b"share-t").unwrap();
    let b = combine_hybrid_secret(&[3u8; 32], &[2u8; 32], b"share-t").unwrap();
    let c = combine_hybrid_secret(&[1u8; 32], &[4u8; 32], b"share-t").unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
    assert_ne!(a.as_bytes(), c.as_bytes());
}

#[test]
fn attacker_sender_is_rejected_even_when_both_signatures_verify() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let mut store_c = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let c = unlocked_v2(&mut store_c, "third horse battery staple");
    let recip = identity_of(&b);
    let entry = a.doc.entries.get("e1").unwrap();
    let env = create_share_envelope(
        c.keys_for_test(),
        c.vault_id_for_test(),
        c.key_epoch_for_test(),
        &recip,
        entry,
    )
    .unwrap();
    let transcript = env.signing_transcript().unwrap();
    assert!(
        verify_hybrid(&env.sender_identity, &transcript, &env.hybrid_signature()).is_ok(),
        "attacker signatures must verify under attacker keys"
    );
    assert_eq!(
        authorize_share_sender(&identity_of(&a), &env),
        Err(CryptoError::UnauthorizedShareSender)
    );
    assert_eq!(
        open_share_envelope(
            b.keys_for_test(),
            b.vault_id_for_test(),
            b.key_epoch_for_test(),
            &env,
            &identity_of(&a),
        )
        .unwrap_err(),
        CryptoError::UnauthorizedShareSender
    );
}

#[test]
fn substituting_only_sender_ed25519_or_only_mldsa_is_rejected() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let mut store_c = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let c = unlocked_v2(&mut store_c, "third horse battery staple");
    let recip = identity_of(&b);
    let entry = a.doc.entries.get("e1").unwrap();
    let env = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip,
        entry,
    )
    .unwrap();
    let expected = identity_of(&a);
    let attacker = identity_of(&c);

    let mut ed_only = env.clone();
    ed_only.sender_identity.ed25519_vk = attacker.signing_identity.ed25519_vk.clone();
    assert_eq!(
        authorize_share_sender(&expected, &ed_only),
        Err(CryptoError::UnauthorizedShareSender)
    );

    let mut pq_only = env.clone();
    pq_only.sender_identity.ml_dsa_vk = attacker.signing_identity.ml_dsa_vk.clone();
    assert_eq!(
        authorize_share_sender(&expected, &pq_only),
        Err(CryptoError::UnauthorizedShareSender)
    );
}

#[test]
fn share_is_epoch_bound_after_recipient_rotation() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let mut b = unlocked_v2(&mut store_b, PW2);
    let recip_n = identity_of(&b);
    let x25519_n = recip_n.x25519_public_key.clone();
    let mlkem_n = recip_n.ml_kem_768_public_key.clone();
    let env = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip_n,
        a.doc.entries.get("e1").unwrap(),
    )
    .unwrap();
    open_share_envelope(
        b.keys_for_test(),
        b.vault_id_for_test(),
        b.key_epoch_for_test(),
        &env,
        &identity_of(&a),
    )
    .unwrap();

    b.rotate_keys(&mut store_b, PW2, None).unwrap();
    assert_eq!(b.key_epoch_for_test(), 1);
    let recip_n1 = identity_of(&b);
    assert_ne!(recip_n1.x25519_public_key, x25519_n);
    assert_ne!(recip_n1.ml_kem_768_public_key, mlkem_n);
    assert_eq!(recip_n1.key_epoch, 1);

    assert_eq!(
        open_share_envelope(
            b.keys_for_test(),
            b.vault_id_for_test(),
            b.key_epoch_for_test(),
            &env,
            &identity_of(&a),
        )
        .unwrap_err(),
        CryptoError::UnauthorizedShareIdentity
    );

    let env2 = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip_n1,
        a.doc.entries.get("e1").unwrap(),
    )
    .unwrap();
    let opened = open_share_envelope(
        b.keys_for_test(),
        b.vault_id_for_test(),
        b.key_epoch_for_test(),
        &env2,
        &identity_of(&a),
    )
    .unwrap();
    assert_eq!(opened.password, "share-secret");
}

#[test]
fn sender_rotation_does_not_attribute_old_offer_as_current_identity() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let mut a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let recip = identity_of(&b);
    let env = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip,
        a.doc.entries.get("e1").unwrap(),
    )
    .unwrap();
    a.rotate_keys(&mut store_a, PW, None).unwrap();
    let current_a = identity_of(&a);
    assert_ne!(current_a.signing_identity, env.sender_identity);
    assert_eq!(current_a.key_epoch, 1);
    assert_eq!(
        open_share_envelope(
            b.keys_for_test(),
            b.vault_id_for_test(),
            b.key_epoch_for_test(),
            &env,
            &current_a,
        )
        .unwrap_err(),
        CryptoError::UnauthorizedShareSender
    );
}

#[test]
fn share_transcript_is_d1_framed_not_cbor() {
    let vid = [9u8; 16];
    let t = crate::crypto::build_share_transcript(
        &vid,
        0x0102_0304,
        b"sender",
        b"recipient",
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 16],
    );
    assert!(t.starts_with(b"Aegis"));
    assert_eq!(&t[5..7], &[0x02, 0x00]); // format version 2
    assert_eq!(&t[7..9], &[0x04, 0x00]); // suite 0x0004
    assert_eq!(&t[9..11], &[0x0A, 0x00]); // kind ShareEnvelope
    assert_eq!(&t[11..27], &vid);
    assert_eq!(&t[27..31], &[0x04, 0x03, 0x02, 0x01]);
    assert_ne!(t[0], 0xa1); // not a CBOR map
    let ident = crate::crypto::build_share_identity_transcript(
        &vid,
        0x0102_0304,
        &[0x11; 32],
        &[0x33; 32],
        b"sig",
    );
    assert_eq!(&ident[9..11], &[0x09, 0x00]); // kind ShareIdentity
    assert_ne!(&ident[9..11], &t[9..11]);
}

#[test]
fn share_envelope_tamper_of_authenticated_fields_fails() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let recip = identity_of(&b);
    let expected = identity_of(&a);
    let env = create_share_envelope(
        a.keys_for_test(),
        a.vault_id_for_test(),
        a.key_epoch_for_test(),
        &recip,
        a.doc.entries.get("e1").unwrap(),
    )
    .unwrap();

    let open = |e: &crate::share::ShareEnvelopeV2| {
        open_share_envelope(
            b.keys_for_test(),
            b.vault_id_for_test(),
            b.key_epoch_for_test(),
            e,
            &expected,
        )
    };

    let mut e = env.clone();
    e.format_version = 99;
    assert!(open(&e).is_err());

    let mut e = env.clone();
    e.crypto_suite = CryptoSuiteId::AegisV2Core2026;
    assert!(open(&e).is_err());
    e.crypto_suite = CryptoSuiteId::AegisV2SyncHybrid2026;
    assert!(open(&e).is_err());

    let mut e = env.clone();
    e.key_epoch = e.key_epoch.wrapping_add(1);
    assert!(open(&e).is_err());

    let mut e = env.clone();
    e.vault_id[0] ^= 0x01;
    assert!(open(&e).is_err());

    let mut e = env.clone();
    e.share_id[0] ^= 0x01;
    assert!(open(&e).is_err());

    let mut e = env.clone();
    e.sender_identity.ed25519_vk[0] ^= 0x01;
    assert!(open(&e).is_err());

    let mut e = env.clone();
    e.recipient_identity.x25519_public_key[0] ^= 0x01;
    assert!(open(&e).is_err());
}

#[test]
fn missing_expected_sender_fails_closed() {
    let mut store_a = MemoryStore::default();
    let mut store_b = MemoryStore::default();
    let a = unlocked_v2(&mut store_a, PW);
    let b = unlocked_v2(&mut store_b, PW2);
    let mut sess_a = Some(ActiveSession::V2(a));
    let mut sess_b = Some(ActiveSession::V2(b));
    let recip = dispatch(&mut store_b, &mut sess_b, VaultRequest::ExportShareIdentity);
    let VaultResponse::ShareIdentity { blob: recip } = recip else {
        panic!("{recip:?}");
    };
    let created = dispatch(
        &mut store_a,
        &mut sess_a,
        VaultRequest::CreateShare {
            entry_id: "e1".into(),
            recipient_identity: recip,
        },
    );
    let VaultResponse::ShareEnvelope { blob: env } = created else {
        panic!("{created:?}");
    };
    let r = dispatch(
        &mut store_b,
        &mut sess_b,
        VaultRequest::OpenShare {
            envelope: env,
            expected_sender_identity: vec![],
        },
    );
    match r {
        VaultResponse::Error {
            code: crate::messages::ErrorCode::InvalidRequest,
            ..
        } => {}
        other => panic!("{other:?}"),
    }
}
