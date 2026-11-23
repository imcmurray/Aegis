//! Delegate upgrade (D20) tests. Included via `lib.rs` (`autotests = false`).

use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::KdfProfile;
use crate::delegate_session::{
    process_message, IpcRequest, IpcResponse, SessionOrigin, SECRET_DELEGATE_SESSION_KEY,
};
use crate::gen_store::{GenerationStore, ACTIVE_GEN_KEY};
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::session_v2::{VaultSessionV2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2};
use crate::types::Entry;
use crate::upgrade::{UpgradeSnapshot, MAX_UPGRADE_SNAPSHOT};
use crate::vault::{
    dispatch, ActiveSession, MemoryStore, SecretStore, StoreOp, VaultSession, SECRET_KEYS_V2,
    SECRET_SESSION,
};
use std::cell::Cell;

const PW: &str = "correct horse battery staple";
const NOW: u64 = 1_700_000_000;
const ORIGIN_A: SessionOrigin = SessionOrigin::WebApp([0xA1; 32]);
const ORIGIN_B: SessionOrigin = SessionOrigin::WebApp([0xB2; 32]);
const OTHER: SessionOrigin = SessionOrigin::Other;

thread_local! {
    static RNG_STATE: Cell<u64> = const { Cell::new(0x1234_5678_9ABC_DEF1) };
}

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

fn seed_vault<S: SecretStore>(store: &mut S) {
    let mut s =
        VaultSessionV2::create_with_params(store, PW, Argon2ParamsV2::insecure_for_tests())
            .unwrap();
    for (id, pw) in [("e1", "pw-one"), ("e2", "pw-two")] {
        let mut e = Entry::new(id, format!("name-{id}"));
        e.password = pw.into();
        s.doc.entries.insert(id.to_string(), e);
    }
    s.persist(store).unwrap();
}

fn seeded_store() -> MemoryStore {
    let mut store = MemoryStore::default();
    seed_vault(&mut store);
    store
}

fn call_origin(
    store: &mut dyn SecretStore,
    token: Option<Vec<u8>>,
    req: VaultRequest,
    origin: &SessionOrigin,
) -> IpcResponse {
    let mut payload = Vec::new();
    ciborium::into_writer(&IpcRequest { v: 1, token, req }, &mut payload).unwrap();
    let mut rng = fill;
    let out = process_message(store, &payload, NOW, origin, &mut rng).expect("process");
    ciborium::from_reader(out.as_slice()).expect("decode response")
}

fn unlock_req() -> VaultRequest {
    VaultRequest::Unlock { passphrase: PW.into() }
}

fn unlock(store: &mut dyn SecretStore, origin: &SessionOrigin) -> (Vec<u8>, String) {
    let r = call_origin(store, None, unlock_req(), origin);
    match r.resp {
        VaultResponse::Unlocked { vault_id } => (r.token.expect("token"), vault_id),
        other => panic!("unlock failed: {other:?}"),
    }
}

fn export(store: &mut dyn SecretStore, token: Option<Vec<u8>>, origin: &SessionOrigin) -> IpcResponse {
    call_origin(store, token, VaultRequest::ExportForUpgrade {}, origin)
}

fn export_ok(store: &mut dyn SecretStore, token: Vec<u8>) -> Vec<u8> {
    match export(store, Some(token), &ORIGIN_A).resp {
        VaultResponse::UpgradeSnapshot { snapshot } => snapshot,
        other => panic!("export failed: {other:?}"),
    }
}

fn import(store: &mut dyn SecretStore, snapshot: Vec<u8>, origin: &SessionOrigin) -> IpcResponse {
    call_origin(store, None, VaultRequest::ImportUpgradeSnapshot { snapshot }, origin)
}

fn is_locked(r: &VaultResponse) -> bool {
    matches!(r, VaultResponse::Error { code: ErrorCode::Locked, .. })
}

fn is_invalid(r: &VaultResponse) -> bool {
    matches!(r, VaultResponse::Error { code: ErrorCode::InvalidRequest, .. })
}

fn decode_snap(bytes: &[u8]) -> UpgradeSnapshot {
    ciborium::from_reader(bytes).expect("snapshot decodes")
}

fn encode_snap(s: &UpgradeSnapshot) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(s, &mut out).unwrap();
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn summaries(store: &mut dyn SecretStore, token: Vec<u8>) -> Vec<(String, String)> {
    let r = call_origin(store, Some(token), VaultRequest::ListSummaries { query: None }, &ORIGIN_A);
    match r.resp {
        VaultResponse::Summaries { entries } => {
            let mut v: Vec<_> = entries.into_iter().map(|e| (e.id, e.name)).collect();
            v.sort();
            v
        }
        other => panic!("expected Summaries, got {other:?}"),
    }
}

fn round_trip<S: SecretStore>(mut a: S) {
    let (token, vid_a) = unlock(&mut a, &ORIGIN_A);
    let names_a = summaries(&mut a, token.clone());
    assert_eq!(names_a.len(), 2);
    let snap = export_ok(&mut a, token);

    let mut b = MemoryStore::default();
    let r = import(&mut b, snap, &ORIGIN_A);
    assert_eq!(r.resp, VaultResponse::Ok, "{:?}", r.resp);
    assert!(r.token.is_none(), "import must not issue a token");

    let (token_b, vid_b) = unlock(&mut b, &ORIGIN_A);
    assert_eq!(vid_a, vid_b);
    let env_a = a.get(SECRET_ENVELOPE_V2).unwrap();
    let env_b = b.get(SECRET_ENVELOPE_V2).unwrap();
    assert_eq!(env_a, env_b);
    assert_eq!(summaries(&mut b, token_b), names_a);
}

// ---- 1: round trip -----------------------------------------------------------

#[test]
fn ac1_round_trip_memory_store() {
    round_trip(seeded_store());
}

#[test]
fn ac1_round_trip_generation_store() {
    let mut gs = GenerationStore::new(MemoryStore::default());
    seed_vault(&mut gs);
    // Force an additional generation commit.
    let mut s = VaultSessionV2::unlock(&mut gs, PW).unwrap();
    let mut e = Entry::new("e3", "name-e3");
    e.password = "pw-three".into();
    s.doc.entries.insert("e3".into(), e);
    s.persist(&mut gs).unwrap();
    assert!(gs.get(ACTIVE_GEN_KEY).is_some(), "a generation was committed");

    let (token, _) = unlock(&mut gs, &ORIGIN_A);
    let snap = export_ok(&mut gs, token.clone());
    let decoded = decode_snap(&snap);
    for (k, _) in &decoded.records {
        assert!(SECRET_KEYS_V2.contains(&k.as_slice()));
    }
    let names = summaries(&mut gs, token);
    assert_eq!(names.len(), 3);

    let mut b = MemoryStore::default();
    assert_eq!(import(&mut b, snap, &ORIGIN_A).resp, VaultResponse::Ok);
    let (tb, _) = unlock(&mut b, &ORIGIN_A);
    assert_eq!(summaries(&mut b, tb), names);
}

// ---- 2-5: refusals -------------------------------------------------------------

#[test]
fn ac2_export_without_or_with_garbage_token_is_locked() {
    let mut store = seeded_store();
    let _ = unlock(&mut store, &ORIGIN_A);
    let r = export(&mut store, None, &ORIGIN_A);
    assert!(is_locked(&r.resp), "{:?}", r.resp);
    let r = export(&mut store, Some(vec![7u8; 64]), &ORIGIN_A);
    assert!(is_locked(&r.resp), "{:?}", r.resp);
    match r.resp {
        VaultResponse::Error { message, .. } => assert_eq!(message, "vault is locked"),
        _ => unreachable!(),
    }
}

#[test]
fn ac3_export_with_token_from_other_origin_is_locked() {
    let mut store = seeded_store();
    let (token, _) = unlock(&mut store, &ORIGIN_A);
    let r = export(&mut store, Some(token), &ORIGIN_B);
    assert!(is_locked(&r.resp), "{:?}", r.resp);
}

#[test]
fn ac4_export_under_origin_other_is_locked() {
    let mut store = seeded_store();
    let (token, _) = unlock(&mut store, &OTHER);
    // The token resumes normally under Other.
    let r = call_origin(&mut store, Some(token.clone()), VaultRequest::ListSummaries { query: None }, &OTHER);
    assert!(matches!(r.resp, VaultResponse::Summaries { .. }), "{:?}", r.resp);
    let r = export(&mut store, Some(token), &OTHER);
    match r.resp {
        VaultResponse::Error { code: ErrorCode::Locked, message } => {
            assert_eq!(message, "vault is locked")
        }
        other => panic!("expected locked, got {other:?}"),
    }
}

#[test]
fn ac5_export_as_bare_legacy_payload_is_locked() {
    let mut store = seeded_store();
    let _ = unlock(&mut store, &ORIGIN_A);
    let mut payload = Vec::new();
    ciborium::into_writer(&VaultRequest::ExportForUpgrade {}, &mut payload).unwrap();
    let mut rng = fill;
    let out = process_message(&mut store, &payload, NOW, &ORIGIN_A, &mut rng).unwrap();
    let resp: VaultResponse = ciborium::from_reader(out.as_slice()).unwrap();
    assert!(is_locked(&resp), "{resp:?}");
}

#[test]
fn export_for_v1_vault_is_locked() {
    let mut store = MemoryStore::default();
    drop(VaultSession::create(&mut store, PW, KdfProfile::Test).unwrap());
    let r = export(&mut store, Some(vec![1; 64]), &ORIGIN_A);
    assert!(is_locked(&r.resp), "{:?}", r.resp);
}

// ---- 6: snapshot contents -------------------------------------------------------

#[test]
fn ac6_snapshot_contents() {
    let mut store = seeded_store();
    store.set(SECRET_SESSION, b"PLANTED-SESSION-VALUE-xyz");
    let (token, _) = unlock(&mut store, &ORIGIN_A);
    let snap = export_ok(&mut store, token);
    let decoded = decode_snap(&snap);

    let mut seen: Vec<Vec<u8>> = Vec::new();
    for (k, _) in &decoded.records {
        assert!(SECRET_KEYS_V2.contains(&k.as_slice()), "unexpected key");
        assert!(!seen.contains(&k.to_vec()), "duplicate key");
        seen.push(k.to_vec());
    }
    // Present in SECRET_KEYS_V2 order.
    let order: Vec<usize> = decoded
        .records
        .iter()
        .map(|(k, _)| SECRET_KEYS_V2.iter().position(|s| *s == k.as_slice()).unwrap())
        .collect();
    let mut sorted = order.clone();
    sorted.sort();
    assert_eq!(order, sorted);
    // Raw stored bytes.
    for (k, v) in &decoded.records {
        assert_eq!(store.get(k).unwrap(), v.to_vec());
    }

    let ks_rec = store.get(SECRET_DELEGATE_SESSION_KEY).expect("K_s present");
    let ks_val: ciborium::Value = ciborium::from_reader(ks_rec.as_slice()).unwrap();
    assert!(!contains(&snap, &ks_rec));
    // K_s key material itself must not appear.
    if let ciborium::Value::Map(m) = ks_val {
        for (_, v) in m {
            if let ciborium::Value::Bytes(b) = v {
                assert!(!contains(&snap, &b), "K_s material leaked");
            }
        }
    }
    for needle in [
        &b"aegis.v2.delegate_session_key"[..],
        b"aegis/v1/session",
        b"aegis/v1/active-gen",
        b"aegis/gen/",
        b"PLANTED-SESSION-VALUE-xyz",
    ] {
        assert!(!contains(&snap, needle), "snapshot leaks {:?}", String::from_utf8_lossy(needle));
    }

    // Root and operational DEKs never appear in the snapshot.
    let native = VaultSessionV2::unlock(&mut store, PW).unwrap();
    assert!(!contains(&snap, native.root_secret().as_bytes().as_slice()), "root leaked");
    for dek in native.operational_key_bytes_for_tests() {
        assert!(!contains(&snap, dek), "DEK leaked");
    }
}

// ---- 7: no durable writes --------------------------------------------------------

#[test]
fn ac7_export_has_no_durable_writes() {
    let mut store = seeded_store();
    let (token, _) = unlock(&mut store, &ORIGIN_A);
    let strip = |s: &MemoryStore| -> Vec<(Vec<u8>, Vec<u8>)> {
        s.durable_pairs()
            .into_iter()
            .filter(|(k, _)| k.as_slice() != SECRET_DELEGATE_SESSION_KEY)
            .collect()
    };
    let before = strip(&store);
    let _ = export_ok(&mut store, token);
    assert_eq!(before, strip(&store));
}

// ---- 8-9: import preconditions ----------------------------------------------------

fn valid_snapshot() -> Vec<u8> {
    let mut a = seeded_store();
    let (t, _) = unlock(&mut a, &ORIGIN_A);
    export_ok(&mut a, t)
}

#[test]
fn ac8_import_into_v2_vault_refused_unchanged() {
    let snap = valid_snapshot();
    let mut store = seeded_store();
    let before = store.all_pairs();
    let r = import(&mut store, snap, &ORIGIN_A);
    match r.resp {
        VaultResponse::Error { code: ErrorCode::InvalidRequest, message } => {
            assert_eq!(message, "upgrade import not permitted")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(before, store.all_pairs());
}

#[test]
fn ac8_import_into_v1_vault_refused_unchanged() {
    let snap = valid_snapshot();
    let mut store = MemoryStore::default();
    drop(VaultSession::create(&mut store, PW, KdfProfile::Test).unwrap());
    // Pre-existing behaviour: every envelope request drops a stale v1
    // unlocked-session record (`cleanup_v1_session_key`), unrelated to import.
    let strip = |s: &MemoryStore| -> Vec<(Vec<u8>, Vec<u8>)> {
        s.all_pairs().into_iter().filter(|(k, _)| k.as_slice() != SECRET_SESSION).collect()
    };
    let before = strip(&store);
    assert!(!before.is_empty());
    let r = import(&mut store, snap, &ORIGIN_A);
    assert!(is_invalid(&r.resp), "{:?}", r.resp);
    assert_eq!(before, strip(&store));
    assert!(store.get(SECRET_ENVELOPE_V2).is_none(), "no v2 record written");
}

#[test]
fn import_into_malformed_envelope_refused_unchanged() {
    let snap = valid_snapshot();
    let mut store = MemoryStore::default();
    store.set(SECRET_ENVELOPE_V2, b"garbage");
    let before = store.all_pairs();
    let r = import(&mut store, snap, &ORIGIN_A);
    assert!(is_invalid(&r.resp), "{:?}", r.resp);
    assert_eq!(before, store.all_pairs());
}

#[test]
fn ac9_import_with_origin_other_refused() {
    let snap = valid_snapshot();
    let mut store = MemoryStore::default();
    let r = import(&mut store, snap, &OTHER);
    assert!(is_invalid(&r.resp), "{:?}", r.resp);
    assert!(store.all_pairs().is_empty());
}

#[test]
fn ac9_import_as_bare_payload_refused() {
    let snap = valid_snapshot();
    let mut store = MemoryStore::default();
    let mut payload = Vec::new();
    ciborium::into_writer(&VaultRequest::ImportUpgradeSnapshot { snapshot: snap }, &mut payload)
        .unwrap();
    let mut rng = fill;
    let out = process_message(&mut store, &payload, NOW, &ORIGIN_A, &mut rng).unwrap();
    let resp: VaultResponse = ciborium::from_reader(out.as_slice()).unwrap();
    assert!(is_invalid(&resp), "{resp:?}");
    assert!(store.all_pairs().is_empty());
}

// ---- 10: validation ----------------------------------------------------------------

fn expect_rejected(snap: Vec<u8>, what: &str) {
    let mut store = MemoryStore::default();
    let r = import(&mut store, snap, &ORIGIN_A);
    match r.resp {
        VaultResponse::Error { code: ErrorCode::InvalidRequest, message } => {
            assert_eq!(message, "invalid upgrade snapshot", "{what}")
        }
        other => panic!("{what}: expected invalid_request, got {other:?}"),
    }
    assert!(store.all_pairs().is_empty(), "{what}: store must stay empty");
}

fn mutated(f: impl FnOnce(&mut UpgradeSnapshot)) -> Vec<u8> {
    let mut s = decode_snap(&valid_snapshot());
    f(&mut s);
    encode_snap(&s)
}

#[test]
fn ac10_unknown_key() {
    expect_rejected(
        mutated(|s| {
            s.records.push((
                serde_bytes::ByteBuf::from(b"aegis.v2.bogus".to_vec()),
                serde_bytes::ByteBuf::from(vec![1]),
            ))
        }),
        "unknown key",
    );
}

#[test]
fn ac10_session_key_rejected() {
    expect_rejected(
        mutated(|s| {
            s.records.push((
                serde_bytes::ByteBuf::from(SECRET_DELEGATE_SESSION_KEY.to_vec()),
                serde_bytes::ByteBuf::from(vec![1]),
            ))
        }),
        "K_s key",
    );
}

#[test]
fn ac10_duplicate_key() {
    expect_rejected(
        mutated(|s| {
            let r = s.records[0].clone();
            s.records.push(r);
        }),
        "duplicate",
    );
}

#[test]
fn ac10_missing_envelope() {
    expect_rejected(
        mutated(|s| s.records.retain(|(k, _)| k.as_slice() != SECRET_ENVELOPE_V2)),
        "missing envelope",
    );
}

#[test]
fn ac10_missing_vault() {
    expect_rejected(
        mutated(|s| s.records.retain(|(k, _)| k.as_slice() != SECRET_VAULT_V2)),
        "missing vault",
    );
}

#[test]
fn ac10_vault_id_mismatch() {
    expect_rejected(mutated(|s| s.vault_id = vec![0x42; 16]), "vault_id mismatch");
}

#[test]
fn ac10_vault_id_wrong_length() {
    expect_rejected(mutated(|s| s.vault_id = vec![0x42; 15]), "vault_id length");
}

#[test]
fn ac10_key_epoch_mismatch() {
    expect_rejected(mutated(|s| s.key_epoch += 1), "key_epoch mismatch");
}

#[test]
fn ac10_version_2() {
    expect_rejected(mutated(|s| s.v = 2), "v=2");
}

#[test]
fn ac10_oversize() {
    expect_rejected(vec![0u8; MAX_UPGRADE_SNAPSHOT + 1], "oversize");
}

#[test]
fn ac10_garbage_bytes() {
    expect_rejected(vec![0xff, 0x00, 0x13], "garbage");
}

#[test]
fn ac10_unknown_field_rejected() {
    // Valid snapshot re-encoded as a map with an extra field.
    let s = decode_snap(&valid_snapshot());
    let v = ciborium::Value::Map(vec![
        (ciborium::Value::Text("v".into()), ciborium::Value::Integer(1u32.into())),
        (ciborium::Value::Text("vault_id".into()), ciborium::Value::Bytes(s.vault_id.clone())),
        (ciborium::Value::Text("key_epoch".into()), ciborium::Value::Integer(s.key_epoch.into())),
        (
            ciborium::Value::Text("records".into()),
            ciborium::Value::Array(
                s.records
                    .iter()
                    .map(|(k, v)| {
                        ciborium::Value::Array(vec![
                            ciborium::Value::Bytes(k.to_vec()),
                            ciborium::Value::Bytes(v.to_vec()),
                        ])
                    })
                    .collect(),
            ),
        ),
        (ciborium::Value::Text("extra".into()), ciborium::Value::Integer(1.into())),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&v, &mut out).unwrap();
    expect_rejected(out, "unknown field");
}

// ---- 11: atomic import ---------------------------------------------------------------

#[derive(Default)]
struct FailCommitStore {
    inner: MemoryStore,
    sets: u32,
    removes: u32,
}

impl SecretStore for FailCommitStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.sets += 1;
        self.inner.set(key, value)
    }
    fn remove(&mut self, key: &[u8]) {
        self.removes += 1;
        self.inner.remove(key)
    }
    fn commit(&mut self, _ops: &[StoreOp]) -> Result<(), String> {
        Err("boom".into())
    }
}

#[test]
fn ac11_failing_commit_is_storage_error_with_no_writes() {
    let snap = valid_snapshot();
    let mut store = FailCommitStore::default();
    let r = import(&mut store, snap, &ORIGIN_A);
    match r.resp {
        VaultResponse::Error { code: ErrorCode::Storage, message } => {
            assert!(message.starts_with("atomic commit failed: "), "{message}")
        }
        other => panic!("expected storage, got {other:?}"),
    }
    assert!(store.inner.all_pairs().is_empty());
    assert_eq!(store.sets, 0);
    assert_eq!(store.removes, 0);
}

#[test]
fn import_success_uses_no_set_or_remove() {
    // Counting store whose commit delegates to the inner store.
    struct Counting {
        inner: MemoryStore,
        sets: u32,
        removes: u32,
        commits: u32,
    }
    impl SecretStore for Counting {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.get(key)
        }
        fn set(&mut self, key: &[u8], value: &[u8]) {
            self.sets += 1;
            self.inner.set(key, value)
        }
        fn remove(&mut self, key: &[u8]) {
            self.removes += 1;
            self.inner.remove(key)
        }
        fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String> {
            self.commits += 1;
            self.inner.commit(ops)
        }
    }
    let snap = valid_snapshot();
    let mut store = Counting { inner: MemoryStore::default(), sets: 0, removes: 0, commits: 0 };
    let r = import(&mut store, snap, &ORIGIN_A);
    assert_eq!(r.resp, VaultResponse::Ok);
    assert_eq!((store.sets, store.removes, store.commits), (0, 0, 1));
}

// ---- 12: sync after import --------------------------------------------------------------

fn sync_ids(store: &mut dyn SecretStore, token: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let r = call_origin(
        store,
        Some(token),
        VaultRequest::SyncWithRemote { remote_state: vec![] },
        &ORIGIN_A,
    );
    match r.resp {
        VaultResponse::Synced { owner_verifying_key, sync_params, .. } => {
            (owner_verifying_key, sync_params)
        }
        other => panic!("expected synced, got {other:?}"),
    }
}

#[test]
fn ac12_sync_identity_preserved() {
    let mut a = seeded_store();
    let (ta, _) = unlock(&mut a, &ORIGIN_A);
    let ids_a = sync_ids(&mut a, ta.clone());
    assert!(!ids_a.0.is_empty());
    let snap = export_ok(&mut a, ta);

    let mut b = MemoryStore::default();
    assert_eq!(import(&mut b, snap, &ORIGIN_A).resp, VaultResponse::Ok);
    let (tb, _) = unlock(&mut b, &ORIGIN_A);
    let ids_b = sync_ids(&mut b, tb);
    assert_eq!(ids_a, ids_b);
}

// ---- 13: legacy building blocks ------------------------------------------------------------

#[test]
fn ac13_legacy_encrypted_backup_path() {
    let mut a = seeded_store();
    let mut sess_a: Option<ActiveSession> = None;
    assert!(matches!(
        dispatch(&mut a, &mut sess_a, unlock_req()),
        VaultResponse::Unlocked { .. }
    ));
    let blob = match dispatch(
        &mut a,
        &mut sess_a,
        VaultRequest::ExportEncrypted { passphrase: "P_backup-one-time".into() },
    ) {
        VaultResponse::Export { blob, .. } => blob,
        other => panic!("{other:?}"),
    };

    let mut b = MemoryStore::default();
    let mut sess_b: Option<ActiveSession> = None;
    let new_pw = "a different live passphrase";
    let r = dispatch(
        &mut b,
        &mut sess_b,
        VaultRequest::ImportEncrypted {
            blob,
            passphrase: "P_backup-one-time".into(),
            new_passphrase: Some(new_pw.into()),
            replace: false,
        },
    );
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");
    assert!(matches!(dispatch(&mut b, &mut sess_b, VaultRequest::Lock), VaultResponse::Locked));
    let r = dispatch(&mut b, &mut sess_b, VaultRequest::Unlock { passphrase: new_pw.into() });
    assert!(matches!(r, VaultResponse::Unlocked { .. }), "{r:?}");

    let list = |s: &mut MemoryStore, sess: &mut Option<ActiveSession>| match dispatch(
        s,
        sess,
        VaultRequest::ListSummaries { query: None },
    ) {
        VaultResponse::Summaries { entries } => {
            let mut v: Vec<_> = entries.into_iter().map(|e| (e.id, e.name)).collect();
            v.sort();
            v
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(list(&mut a, &mut sess_a), list(&mut b, &mut sess_b));
}

// ---- 14: plain dispatch ----------------------------------------------------------------------

#[test]
fn ac14_plain_dispatch_refuses() {
    let mut store = seeded_store();
    let mut sess: Option<ActiveSession> = None;
    assert!(matches!(
        dispatch(&mut store, &mut sess, unlock_req()),
        VaultResponse::Unlocked { .. }
    ));
    let r = dispatch(&mut store, &mut sess, VaultRequest::ExportForUpgrade {});
    assert!(is_locked(&r), "{r:?}");

    let snap = valid_snapshot();
    let mut empty = MemoryStore::default();
    let mut none: Option<ActiveSession> = None;
    let r = dispatch(&mut empty, &mut none, VaultRequest::ImportUpgradeSnapshot { snapshot: snap });
    assert!(is_invalid(&r), "{r:?}");
    assert!(empty.all_pairs().is_empty());
}

// ---- 15: messages round trip -----------------------------------------------------------------------

#[test]
fn ac15_new_variants_round_trip() {
    let reqs = [
        VaultRequest::ExportForUpgrade {},
        VaultRequest::ImportUpgradeSnapshot { snapshot: vec![1, 2, 3, 250] },
    ];
    for r in reqs {
        let b = r.to_cbor().unwrap();
        assert_eq!(VaultRequest::from_cbor(&b).unwrap(), r);
    }
    let resp = VaultResponse::UpgradeSnapshot { snapshot: vec![9, 8, 7] };
    let b = resp.to_cbor().unwrap();
    assert_eq!(VaultResponse::from_cbor(&b).unwrap(), resp);
}

#[test]
fn snapshot_limit_is_8_mib() {
    assert_eq!(MAX_UPGRADE_SNAPSHOT, 8 * 1024 * 1024);
}
