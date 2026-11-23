//! Delegate session token tests (D19). Included via `lib.rs` (`autotests = false`).

use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::KdfProfile;
use crate::delegate_session::{
    inspect_token, issue_token, process_message, resume_from_token, rotate_session_key, IpcRequest,
    IpcResponse, SessionOrigin, MAX_TOKEN_LEN, SECRET_DELEGATE_SESSION_KEY, SESSION_ABSOLUTE_SECS,
    SESSION_IDLE_SECS,
};
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::session_v2::VaultSessionV2;
use crate::types::Entry;
use crate::vault::{MemoryStore, SecretStore, VaultSession};
use serde::Deserialize;
use std::cell::Cell;

const PW: &str = "correct horse battery staple";
const NOW: u64 = 1_700_000_000;
const ORIGIN_A: SessionOrigin = SessionOrigin::WebApp([0xA1; 32]);
const ORIGIN_B: SessionOrigin = SessionOrigin::WebApp([0xB2; 32]);
const OTHER: SessionOrigin = SessionOrigin::Other;

thread_local! {
    static RNG_STATE: Cell<u64> = const { Cell::new(0x9E37_79B9_7F4A_7C15) };
}

/// Deterministic per-thread splitmix64 stream (never repeats within a test).
fn fill(b: &mut [u8]) {
    RNG_STATE.with(|st| {
        for x in b.iter_mut() {
            let mut z = st.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
            st.set(z);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *x = ((z ^ (z >> 31)) & 0xff) as u8;
        }
    });
}

#[derive(Deserialize)]
struct KsRec {
    #[serde(with = "serde_bytes")]
    kid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

fn ks(store: &MemoryStore) -> KsRec {
    let b = store.get(SECRET_DELEGATE_SESSION_KEY).expect("K_s present");
    ciborium::from_reader(b.as_slice()).expect("K_s decodes")
}

fn seeded_store() -> MemoryStore {
    let mut store = MemoryStore::default();
    let mut s =
        VaultSessionV2::create_with_params(&mut store, PW, Argon2ParamsV2::insecure_for_tests())
            .unwrap();
    for (id, pw) in [("e1", "pw-one"), ("e2", "pw-two")] {
        let mut e = Entry::new(id, format!("name-{id}"));
        e.password = pw.into();
        s.doc.entries.insert(id.to_string(), e);
    }
    s.persist(&mut store).unwrap();
    store
}

fn envelope(token: Option<Vec<u8>>, req: VaultRequest, v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&IpcRequest { v, token, req }, &mut out).unwrap();
    out
}

fn call_origin(
    store: &mut MemoryStore,
    token: Option<Vec<u8>>,
    req: VaultRequest,
    now: u64,
    origin: &SessionOrigin,
) -> IpcResponse {
    let payload = envelope(token, req, 1);
    let mut rng = fill;
    let out = process_message(store, &payload, now, origin, &mut rng).expect("process");
    ciborium::from_reader(out.as_slice()).expect("decode response")
}

fn call(store: &mut MemoryStore, token: Option<Vec<u8>>, req: VaultRequest, now: u64) -> IpcResponse {
    call_origin(store, token, req, now, &OTHER)
}

fn unlock_req() -> VaultRequest {
    VaultRequest::Unlock { passphrase: PW.into() }
}

fn list_req() -> VaultRequest {
    VaultRequest::ListSummaries { query: None }
}

/// Unlock via envelope and return the token.
fn unlock_token(store: &mut MemoryStore, now: u64, origin: &SessionOrigin) -> Vec<u8> {
    let r = call_origin(store, None, unlock_req(), now, origin);
    assert!(matches!(r.resp, VaultResponse::Unlocked { .. }), "{:?}", r.resp);
    r.token.expect("token after unlock")
}

/// Rotate K_s and mint a token directly for a freshly unlocked session.
fn direct_token(
    store: &mut MemoryStore,
    issued_at: u64,
    now: u64,
    origin: &SessionOrigin,
) -> (Vec<u8>, VaultSessionV2) {
    let session = VaultSessionV2::unlock(store, PW).unwrap();
    let mut rng = fill;
    rotate_session_key(store, &mut rng);
    let mut rng = fill;
    let t = issue_token(&*store, &session, issued_at, now, origin, &mut rng).expect("issue");
    (t, session)
}

fn is_locked_error(r: &VaultResponse) -> bool {
    matches!(r, VaultResponse::Error { code: ErrorCode::Locked, .. })
}

// ---- Criterion 2: round trip ----------------------------------------------

#[test]
fn unlock_then_resume_round_trip() {
    let mut store = seeded_store();
    let r = call(&mut store, None, unlock_req(), NOW);
    assert!(matches!(r.resp, VaultResponse::Unlocked { .. }));
    assert_eq!(r.v, 1);
    let token = r.token.expect("token after unlock");
    assert!(store.get(SECRET_DELEGATE_SESSION_KEY).is_some());

    let r = call(&mut store, Some(token.clone()), list_req(), NOW + 5);
    match r.resp {
        VaultResponse::Summaries { entries } => assert_eq!(entries.len(), 2),
        other => panic!("expected Summaries, got {other:?}"),
    }
    assert!(r.token.is_some());

    let r = call(&mut store, Some(token), VaultRequest::Status, NOW + 6);
    match r.resp {
        VaultResponse::Status { unlocked, .. } => assert!(unlocked),
        other => panic!("expected Status, got {other:?}"),
    }
}

#[test]
fn no_token_means_locked() {
    let mut store = seeded_store();
    let r = call(&mut store, None, list_req(), NOW);
    assert!(is_locked_error(&r.resp), "{:?}", r.resp);
    assert!(r.token.is_none());
    let r = call(&mut store, None, VaultRequest::Status, NOW);
    assert!(matches!(r.resp, VaultResponse::Status { unlocked: false, .. }));
}

#[test]
fn garbage_token_is_treated_as_locked() {
    let mut store = seeded_store();
    let _ = unlock_token(&mut store, NOW, &OTHER);
    let r = call(&mut store, Some(vec![1, 2, 3]), list_req(), NOW + 1);
    assert!(is_locked_error(&r.resp));
    assert!(r.token.is_none());
}

// ---- Criterion 3: resume fidelity ------------------------------------------

#[test]
fn resume_fidelity_same_vault_and_entries() {
    let mut store = seeded_store();
    let (token, original) = direct_token(&mut store, NOW, NOW, &OTHER);
    let (resumed, issued) = resume_from_token(&store, &token, NOW + 1, &OTHER).expect("resume");
    assert_eq!(issued, NOW);
    assert_eq!(resumed.vault_id(), original.vault_id());
    assert_eq!(resumed.key_epoch(), original.key_epoch());
    let a: Vec<_> = original
        .doc
        .entries
        .iter()
        .map(|(k, e)| (k.clone(), e.password.clone()))
        .collect();
    let b: Vec<_> = resumed
        .doc
        .entries
        .iter()
        .map(|(k, e)| (k.clone(), e.password.clone()))
        .collect();
    assert_eq!(a.len(), 2);
    assert_eq!(a, b);
}

// ---- Criterion 4: tamper at every index ------------------------------------

#[test]
fn tamper_every_byte_rejected() {
    let mut store = seeded_store();
    let (token, _s) = direct_token(&mut store, NOW, NOW, &OTHER);
    assert!(resume_from_token(&store, &token, NOW, &OTHER).is_some());
    for i in 0..token.len() {
        for mask in [0x01u8, 0x80u8] {
            let mut t = token.clone();
            t[i] ^= mask;
            assert!(
                resume_from_token(&store, &t, NOW, &OTHER).is_none(),
                "flip of byte {i} mask {mask:#x} accepted"
            );
        }
    }
}

#[test]
fn truncated_and_extended_tokens_rejected() {
    let mut store = seeded_store();
    let (token, _s) = direct_token(&mut store, NOW, NOW, &OTHER);
    for n in 0..token.len() {
        assert!(resume_from_token(&store, &token[..n], NOW, &OTHER).is_none(), "len {n}");
    }
    let mut ext = token.clone();
    ext.push(0);
    assert!(resume_from_token(&store, &ext, NOW, &OTHER).is_none());
    let big = vec![0x01u8; MAX_TOKEN_LEN + 1];
    assert!(resume_from_token(&store, &big, NOW, &OTHER).is_none());
    assert!(inspect_token(&store, &big, &OTHER).is_none());
}

// ---- Criterion 5: K_s rotation on Lock -------------------------------------

#[test]
fn lock_then_unlock_rejects_old_token() {
    let mut store = seeded_store();
    let old = unlock_token(&mut store, NOW, &OTHER);
    let r = call(&mut store, Some(old.clone()), VaultRequest::Lock, NOW + 1);
    assert!(r.token.is_none());
    let new = unlock_token(&mut store, NOW + 2, &OTHER);
    assert!(resume_from_token(&store, &old, NOW + 3, &OTHER).is_none());
    assert!(resume_from_token(&store, &new, NOW + 3, &OTHER).is_some());
    let r = call(&mut store, Some(old), list_req(), NOW + 3);
    assert!(is_locked_error(&r.resp));
}

#[test]
fn lock_without_token_rotates_ks() {
    let mut store = seeded_store();
    let _ = unlock_token(&mut store, NOW, &OTHER);
    let before = ks(&store);
    let r = call(&mut store, None, VaultRequest::Lock, NOW + 1);
    assert!(r.token.is_none());
    let after = ks(&store);
    assert_ne!(before.kid, after.kid);
    assert_ne!(before.key, after.key);
}

#[test]
fn lock_with_valid_token_kills_that_token_even_without_reunlock() {
    let mut store = seeded_store();
    let t = unlock_token(&mut store, NOW, &OTHER);
    let _ = call(&mut store, Some(t.clone()), VaultRequest::Lock, NOW + 1);
    assert!(resume_from_token(&store, &t, NOW + 2, &OTHER).is_none());
}

// ---- Criterion 6: origin binding -------------------------------------------

#[test]
fn origin_binding() {
    let mut store = seeded_store();
    let (ta, _s) = direct_token(&mut store, NOW, NOW, &ORIGIN_A);
    assert!(resume_from_token(&store, &ta, NOW, &ORIGIN_A).is_some());
    assert!(resume_from_token(&store, &ta, NOW, &ORIGIN_B).is_none());
    assert!(resume_from_token(&store, &ta, NOW, &OTHER).is_none());
    assert!(inspect_token(&store, &ta, &ORIGIN_B).is_none());

    let mut rng = fill;
    let s2 = VaultSessionV2::unlock(&mut store, PW).unwrap();
    let to = issue_token(&store, &s2, NOW, NOW, &OTHER, &mut rng).unwrap();
    assert!(resume_from_token(&store, &to, NOW, &OTHER).is_some());
    assert!(resume_from_token(&store, &to, NOW, &ORIGIN_A).is_none());
}

#[test]
fn origin_binding_through_process_message() {
    let mut store = seeded_store();
    let t = unlock_token(&mut store, NOW, &ORIGIN_A);
    let r = call_origin(&mut store, Some(t.clone()), list_req(), NOW + 1, &ORIGIN_B);
    assert!(is_locked_error(&r.resp));
    let r = call_origin(&mut store, Some(t), list_req(), NOW + 1, &ORIGIN_A);
    assert!(matches!(r.resp, VaultResponse::Summaries { .. }));
}

#[test]
fn aad_bytes_shape() {
    assert_eq!(ORIGIN_A.aad_bytes(), vec![0xA1; 32]);
    assert_eq!(OTHER.aad_bytes(), vec![0x00]);
}

// ---- Criterion 7: idle expiry ----------------------------------------------

#[test]
fn idle_expiry_boundary() {
    let mut store = seeded_store();
    let (t, _s) = direct_token(&mut store, NOW, NOW, &OTHER);
    assert_eq!(SESSION_IDLE_SECS, 900);
    assert!(resume_from_token(&store, &t, NOW + 900, &OTHER).is_some());
    assert!(resume_from_token(&store, &t, NOW + 901, &OTHER).is_none());
}

// ---- Criterion 8: absolute cap ---------------------------------------------

#[test]
fn absolute_cap_chain() {
    let mut store = seeded_store();
    let t0 = NOW;
    let (mut token, _s) = direct_token(&mut store, t0, t0, &OTHER);
    assert_eq!(SESSION_ABSOLUTE_SECS, 43_200);
    let mut now = t0;
    // Keep alive every 900 s up to exactly issued_at + 43_200.
    while now < t0 + SESSION_ABSOLUTE_SECS {
        now += 900;
        let (s, issued) = resume_from_token(&store, &token, now, &OTHER)
            .unwrap_or_else(|| panic!("chain broke at +{}", now - t0));
        assert_eq!(issued, t0);
        let mut rng = fill;
        token = issue_token(&store, &s, issued, now, &OTHER, &mut rng).unwrap();
    }
    assert_eq!(now, t0 + SESSION_ABSOLUTE_SECS);
    // Token re-issued at exactly the cap: idle-valid, but past the cap one second later.
    assert!(resume_from_token(&store, &token, t0 + SESSION_ABSOLUTE_SECS, &OTHER).is_some());
    assert!(resume_from_token(&store, &token, t0 + SESSION_ABSOLUTE_SECS + 1, &OTHER).is_none());
}

#[test]
fn absolute_cap_through_process_message() {
    let mut store = seeded_store();
    let mut token = unlock_token(&mut store, NOW, &OTHER);
    let mut now = NOW;
    for _ in 0..48 {
        now += 900;
        let r = call(&mut store, Some(token), VaultRequest::Status, now);
        assert!(matches!(r.resp, VaultResponse::Status { unlocked: true, .. }));
        token = r.token.expect("reissued");
    }
    let r = call(&mut store, Some(token.clone()), VaultRequest::Status, now + 1);
    assert!(matches!(r.resp, VaultResponse::Status { unlocked: false, .. }));
    assert!(r.token.is_none());
}

// ---- Criterion 9: clock unavailable ----------------------------------------

#[test]
fn now_zero_fails_closed() {
    let mut store = seeded_store();
    let (t, s) = direct_token(&mut store, NOW, NOW, &OTHER);
    assert!(resume_from_token(&store, &t, 0, &OTHER).is_none());
    let mut rng = fill;
    assert!(issue_token(&store, &s, NOW, 0, &OTHER, &mut rng).is_none());

    let r = call(&mut store, Some(t), VaultRequest::Status, 0);
    assert!(matches!(r.resp, VaultResponse::Status { unlocked: false, .. }));
}

#[test]
fn unlock_with_no_clock_succeeds_once_without_token() {
    let mut store = seeded_store();
    let r = call(&mut store, None, unlock_req(), 0);
    assert!(matches!(r.resp, VaultResponse::Unlocked { .. }));
    assert!(r.token.is_none());
}

// ---- Criterion 10: vault_id mismatch ---------------------------------------

#[test]
fn vault_id_mismatch_rejected() {
    let mut store_a = seeded_store();
    let (t, _s) = direct_token(&mut store_a, NOW, NOW, &OTHER);
    let mut store_b = MemoryStore::default();
    drop(
        VaultSessionV2::create_with_params(&mut store_b, PW, Argon2ParamsV2::insecure_for_tests())
            .unwrap(),
    );
    store_b.set(SECRET_DELEGATE_SESSION_KEY, &store_a.get(SECRET_DELEGATE_SESSION_KEY).unwrap());
    assert!(inspect_token(&store_b, &t, &OTHER).is_some(), "token still opens");
    assert!(resume_from_token(&store_b, &t, NOW, &OTHER).is_none());
    let r = call(&mut store_b, Some(t), VaultRequest::Status, NOW);
    assert!(matches!(r.resp, VaultResponse::Status { unlocked: false, .. }));
}

#[test]
fn empty_store_rejects_token() {
    let mut store = seeded_store();
    let (t, _s) = direct_token(&mut store, NOW, NOW, &OTHER);
    let mut empty = MemoryStore::default();
    empty.set(SECRET_DELEGATE_SESSION_KEY, &store.get(SECRET_DELEGATE_SESSION_KEY).unwrap());
    assert!(resume_from_token(&empty, &t, NOW, &OTHER).is_none());
}

// ---- Criterion 11: key_epoch mismatch --------------------------------------

#[test]
fn rotate_keys_invalidates_old_token_and_issues_new_epoch() {
    let mut store = seeded_store();
    let old = unlock_token(&mut store, NOW, &OTHER);
    let old_info = inspect_token(&store, &old, &OTHER).unwrap();
    let ks_before = ks(&store);

    let r = call(
        &mut store,
        Some(old.clone()),
        VaultRequest::RotateKeys { passphrase: PW.into(), recovery_key: None },
        NOW + 1,
    );
    let new_epoch = match r.resp {
        VaultResponse::Rotated { key_epoch, .. } => key_epoch,
        other => panic!("expected Rotated, got {other:?}"),
    };
    assert_eq!(new_epoch, old_info.key_epoch + 1);
    let new = r.token.expect("token with Rotated");

    // K_s itself is not rotated by RotateKeys.
    let ks_after = ks(&store);
    assert_eq!(ks_before.kid, ks_after.kid);
    assert_eq!(ks_before.key, ks_after.key);

    assert!(resume_from_token(&store, &old, NOW + 2, &OTHER).is_none());
    assert!(resume_from_token(&store, &new, NOW + 2, &OTHER).is_some());
    assert_eq!(inspect_token(&store, &new, &OTHER).unwrap().key_epoch, new_epoch);
}

// ---- Criterion 12: read-only resume ----------------------------------------

#[test]
fn resume_is_read_only() {
    let mut store = seeded_store();
    let (t, _s) = direct_token(&mut store, NOW, NOW, &OTHER);
    let before = store.durable_pairs();
    let (resumed, _) = resume_from_token(&store, &t, NOW + 1, &OTHER).unwrap();
    assert_eq!(store.durable_pairs(), before);

    // Audit not extended: a real unlock pushes one in-memory Unlock event.
    let mut clone = store.clone();
    let unlocked = VaultSessionV2::unlock(&mut clone, PW).unwrap();
    assert_eq!(resumed.audit.len() + 1, unlocked.audit.len());

    let r = call(&mut store, Some(t.clone()), list_req(), NOW + 2);
    assert!(matches!(r.resp, VaultResponse::Summaries { .. }));
    assert_eq!(store.durable_pairs(), before);
    let r = call(&mut store, Some(t), VaultRequest::Status, NOW + 2);
    assert!(matches!(r.resp, VaultResponse::Status { unlocked: true, .. }));
    assert_eq!(store.durable_pairs(), before);
}

// ---- Criterion 13: no root leak --------------------------------------------

fn contains_window(hay: &[u8], needle: &[u8; 32]) -> bool {
    hay.windows(32).any(|w| w == needle)
}

#[test]
fn no_root_in_token_or_store() {
    let mut store = seeded_store();
    let (t, s) = direct_token(&mut store, NOW, NOW, &OTHER);
    let root = s.root_bytes_for_test();
    assert!(!contains_window(&t, &root));
    for (k, v) in store.all_pairs() {
        assert!(!contains_window(&v, &root), "root in store value {:?}", String::from_utf8_lossy(&k));
    }
    // Same via the envelope path (including the K_s record).
    let t2 = unlock_token(&mut store, NOW + 1, &OTHER);
    assert!(!contains_window(&t2, &root));
    for (_, v) in store.all_pairs() {
        assert!(!contains_window(&v, &root));
    }
    assert!(store.get(SECRET_DELEGATE_SESSION_KEY).is_some());
}

// ---- Criterion 14: legacy --------------------------------------------------

#[test]
fn legacy_bare_status_leaves_ks_alone() {
    let mut store = seeded_store();
    let payload = VaultRequest::Status.to_cbor().unwrap();
    let mut rng = fill;
    let out = process_message(&mut store, &payload, NOW, &OTHER, &mut rng).unwrap();
    match VaultResponse::from_cbor(&out).expect("bare response") {
        VaultResponse::Status { has_vault: true, unlocked: false, .. } => {}
        other => panic!("{other:?}"),
    }
    assert!(store.get(SECRET_DELEGATE_SESSION_KEY).is_none());
}

#[test]
fn legacy_bare_lock_and_unlock_do_not_touch_ks() {
    let mut store = seeded_store();
    let _ = unlock_token(&mut store, NOW, &OTHER);
    let before = store.get(SECRET_DELEGATE_SESSION_KEY).unwrap();
    for req in [VaultRequest::Lock, unlock_req()] {
        let payload = req.to_cbor().unwrap();
        let mut rng = fill;
        let out = process_message(&mut store, &payload, NOW + 1, &OTHER, &mut rng).unwrap();
        assert!(VaultResponse::from_cbor(&out).is_ok());
        assert_eq!(store.get(SECRET_DELEGATE_SESSION_KEY).unwrap(), before);
    }
}

#[test]
fn legacy_bare_create_vault_on_empty_store() {
    let mut store = MemoryStore::default();
    let payload = VaultRequest::CreateVault {
        passphrase: PW.into(),
        kdf_profile: KdfProfile::Test,
    }
    .to_cbor()
    .unwrap();
    let mut rng = fill;
    let out = process_message(&mut store, &payload, NOW, &OTHER, &mut rng).unwrap();
    let resp = VaultResponse::from_cbor(&out).expect("bare response");
    assert!(!matches!(resp, VaultResponse::Error { .. }), "{resp:?}");
    assert!(store.get(SECRET_DELEGATE_SESSION_KEY).is_none());
}

// ---- Criterion 15: re-issue ------------------------------------------------

#[test]
fn reissue_keeps_issued_at_and_extends_expiry() {
    let mut store = seeded_store();
    let t1 = unlock_token(&mut store, NOW, &OTHER);
    let i1 = inspect_token(&store, &t1, &OTHER).unwrap();
    assert_eq!(i1.issued_at, NOW);
    assert_eq!(i1.expires_at, NOW + 900);

    let later = NOW + 600;
    let r = call(&mut store, Some(t1.clone()), list_req(), later);
    let t2 = r.token.unwrap();
    assert_ne!(t1, t2);
    let i2 = inspect_token(&store, &t2, &OTHER).unwrap();
    assert_eq!(i2.issued_at, NOW);
    assert_eq!(i2.expires_at, later + 900);
    assert_eq!(i2.kid, i1.kid);
    assert_eq!(i2.vault_id, i1.vault_id);
}

#[test]
fn issue_token_uses_fresh_nonce_each_time() {
    let mut store = seeded_store();
    let (_t, s) = direct_token(&mut store, NOW, NOW, &OTHER);
    let mut rng = fill;
    let a = issue_token(&store, &s, NOW, NOW, &OTHER, &mut rng).unwrap();
    let b = issue_token(&store, &s, NOW, NOW, &OTHER, &mut rng).unwrap();
    assert_ne!(a, b);
    assert_ne!(&a[17..41], &b[17..41], "nonces differ");
    assert_eq!(a[0], 0x01);
}

// ---- Criterion 16: establishing rotates ------------------------------------

#[test]
fn successful_unlock_rotates_ks() {
    let mut store = seeded_store();
    let _ = unlock_token(&mut store, NOW, &OTHER);
    let k1 = ks(&store);
    let _ = unlock_token(&mut store, NOW + 1, &OTHER);
    let k2 = ks(&store);
    assert_ne!(k1.kid, k2.kid);
    assert_ne!(k1.key, k2.key);
}

#[test]
fn second_tab_unlock_kicks_first_tab() {
    let mut store = seeded_store();
    let tab1 = unlock_token(&mut store, NOW, &OTHER);
    let _tab2 = unlock_token(&mut store, NOW + 1, &OTHER);
    let r = call(&mut store, Some(tab1), list_req(), NOW + 2);
    assert!(is_locked_error(&r.resp));
}

#[test]
fn failed_unlock_while_locked_does_not_rotate_ks() {
    let mut store = seeded_store();
    let _ = unlock_token(&mut store, NOW, &OTHER);
    let _ = call(&mut store, None, VaultRequest::Lock, NOW + 1);
    let before = store.get(SECRET_DELEGATE_SESSION_KEY).unwrap();
    let r = call(
        &mut store,
        None,
        VaultRequest::Unlock { passphrase: "wrong passphrase here".into() },
        NOW + 2,
    );
    assert!(matches!(r.resp, VaultResponse::Error { .. }));
    assert!(r.token.is_none());
    assert_eq!(store.get(SECRET_DELEGATE_SESSION_KEY).unwrap(), before);
}

#[test]
fn failed_unlock_on_fresh_store_creates_no_ks() {
    let mut store = seeded_store();
    let r = call(
        &mut store,
        None,
        VaultRequest::Unlock { passphrase: "wrong passphrase here".into() },
        NOW,
    );
    assert!(matches!(r.resp, VaultResponse::Error { .. }));
    assert!(r.token.is_none());
    assert!(store.get(SECRET_DELEGATE_SESSION_KEY).is_none());
}

#[test]
fn failed_unlock_while_unlocked_keeps_session_and_issued_at() {
    let mut store = seeded_store();
    let t = unlock_token(&mut store, NOW, &OTHER);
    let before = store.get(SECRET_DELEGATE_SESSION_KEY).unwrap();
    let r = call(
        &mut store,
        Some(t),
        VaultRequest::Unlock { passphrase: "wrong passphrase here".into() },
        NOW + 100,
    );
    assert!(matches!(r.resp, VaultResponse::Error { .. }), "{:?}", r.resp);
    assert_eq!(store.get(SECRET_DELEGATE_SESSION_KEY).unwrap(), before);
    let nt = r.token.expect("session kept, token re-issued");
    let info = inspect_token(&store, &nt, &OTHER).unwrap();
    assert_eq!(info.issued_at, NOW);
    assert_eq!(info.expires_at, NOW + 100 + 900);
}

#[test]
fn envelope_create_vault_establishes_and_rotates() {
    let mut store = MemoryStore::default();
    let r = call(
        &mut store,
        None,
        VaultRequest::CreateVault { passphrase: PW.into(), kdf_profile: KdfProfile::Test },
        NOW,
    );
    assert!(!matches!(r.resp, VaultResponse::Error { .. }), "{:?}", r.resp);
    let t = r.token.expect("token after create");
    assert!(store.get(SECRET_DELEGATE_SESSION_KEY).is_some());
    assert!(resume_from_token(&store, &t, NOW + 1, &OTHER).is_some());
}

// ---- Criterion 17: v1 ------------------------------------------------------

#[test]
fn v1_vault_unlock_has_no_token() {
    let mut store = MemoryStore::default();
    drop(VaultSession::create(&mut store, PW, KdfProfile::Test).unwrap());
    let r = call(&mut store, None, unlock_req(), NOW);
    assert!(matches!(r.resp, VaultResponse::Unlocked { .. }), "{:?}", r.resp);
    assert!(r.token.is_none());
}

// ---- Criterion 18: envelope version ----------------------------------------

#[test]
fn unsupported_envelope_version_rejected_without_touching_store() {
    let mut store = seeded_store();
    let _ = unlock_token(&mut store, NOW, &OTHER);
    let before = store.durable_pairs();
    let payload = envelope(None, VaultRequest::Status, 2);
    let mut rng = fill;
    let out = process_message(&mut store, &payload, NOW, &OTHER, &mut rng).unwrap();
    let r: IpcResponse = ciborium::from_reader(out.as_slice()).unwrap();
    assert_eq!(r.v, 1);
    assert!(r.token.is_none());
    assert!(matches!(
        r.resp,
        VaultResponse::Error { code: ErrorCode::InvalidRequest, .. }
    ));
    assert_eq!(store.durable_pairs(), before);
}

// ---- Malformed payloads ----------------------------------------------------

#[test]
fn undecodable_payload_is_err_without_leaking_bytes() {
    let mut store = seeded_store();
    let mut rng = fill;
    let e = process_message(&mut store, &[0xff, 0xff, 0xff], NOW, &OTHER, &mut rng).unwrap_err();
    assert!(!e.contains("255") && !e.to_lowercase().contains("ffff"));
    // A CBOR value that is neither envelope nor request.
    let mut rng = fill;
    assert!(process_message(&mut store, &[0x01], NOW, &OTHER, &mut rng).is_err());
}

// ---- K_s record robustness -------------------------------------------------

#[test]
fn malformed_ks_disables_tokens() {
    let mut store = seeded_store();
    let (t, s) = direct_token(&mut store, NOW, NOW, &OTHER);
    store.set(SECRET_DELEGATE_SESSION_KEY, b"not cbor");
    assert!(resume_from_token(&store, &t, NOW, &OTHER).is_none());
    let mut rng = fill;
    assert!(issue_token(&store, &s, NOW, NOW, &OTHER, &mut rng).is_none());
    store.remove(SECRET_DELEGATE_SESSION_KEY);
    assert!(resume_from_token(&store, &t, NOW, &OTHER).is_none());
    let mut rng = fill;
    assert!(issue_token(&store, &s, NOW, NOW, &OTHER, &mut rng).is_none());
}

#[test]
fn rotate_session_key_writes_16_and_32_bytes() {
    let mut store = MemoryStore::default();
    let mut rng = fill;
    rotate_session_key(&mut store, &mut rng);
    let k = ks(&store);
    assert_eq!(k.kid.len(), 16);
    assert_eq!(k.key.len(), 32);
}
