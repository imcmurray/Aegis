//! Integration tests for the D21 link-a-device flow (through `process_message`).
//! Included from `lib.rs` with `#[path]`, like `delegate_upgrade.rs`.

use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::KdfProfile;
use crate::delegate_session::{
    process_message, IpcRequest, IpcResponse, SessionOrigin, SECRET_DELEGATE_SESSION_KEY,
};
use crate::link::{
    decode_link_code, derive_link_keys, encode_link_code, open_link_payload, seal_link_payload,
    sign_link_state, verify_link_state, LinkAckBody, LinkDropParams, LinkDropState, LinkPayloadV1,
    LinkSecret, ERR_LINK_EXPIRED, ERR_LINK_INVALID, ERR_LINK_NOT_A_CODE, ERR_LINK_NOT_PERMITTED,
    ERR_LINK_PASSPHRASE, ERR_LINK_TYPO, ERR_LINK_USED, KIND_ACK, KIND_OFFER, KIND_TOMBSTONE,
    LINK_RECORD_KEYS, LINK_TTL_SECS, MAX_LINK_STATE, SEQ_ACK, SEQ_OFFER, SEQ_TOMBSTONE,
};
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::session_v2::{VaultSessionV2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2};
use crate::types::Entry;
use crate::vault::{
    dispatch, ActiveSession, MemoryStore, SecretStore, StoreOp, VaultSession, SECRET_SESSION,
};
use std::cell::Cell;

const PW: &str = "correct horse battery staple";
const NOW: u64 = 1_700_000_000;
const ORIGIN_A: SessionOrigin = SessionOrigin::WebApp([0xA1; 32]);
const ORIGIN_B: SessionOrigin = SessionOrigin::WebApp([0xB2; 32]);
const OTHER: SessionOrigin = SessionOrigin::Other;

thread_local! {
    static RNG_STATE: Cell<u64> = const { Cell::new(0x0FED_CBA9_8765_4321) };
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

fn call_at(
    store: &mut dyn SecretStore,
    token: Option<Vec<u8>>,
    req: VaultRequest,
    origin: &SessionOrigin,
    now: u64,
) -> IpcResponse {
    let mut payload = Vec::new();
    ciborium::into_writer(&IpcRequest { v: 1, token, req }, &mut payload).unwrap();
    let mut rng = fill;
    let out = process_message(store, &payload, now, origin, &mut rng).expect("process");
    ciborium::from_reader(out.as_slice()).expect("decode response")
}

fn call(
    store: &mut dyn SecretStore,
    token: Option<Vec<u8>>,
    req: VaultRequest,
    origin: &SessionOrigin,
) -> IpcResponse {
    call_at(store, token, req, origin, NOW)
}

fn unlock(store: &mut dyn SecretStore, origin: &SessionOrigin) -> Vec<u8> {
    let r = call(store, None, VaultRequest::Unlock { passphrase: PW.into() }, origin);
    match r.resp {
        VaultResponse::Unlocked { .. } => r.token.expect("token"),
        other => panic!("unlock failed: {other:?}"),
    }
}

struct Offer {
    code: String,
    params: Vec<u8>,
    state: Vec<u8>,
    expires_at: u64,
}

fn create_offer(store: &mut dyn SecretStore, token: Vec<u8>) -> Offer {
    let r = call(store, Some(token), VaultRequest::CreateLinkOffer {}, &ORIGIN_A);
    match r.resp {
        VaultResponse::LinkOffer { code, params, state, expires_at } => {
            Offer { code, params, state, expires_at }
        }
        other => panic!("create offer failed: {other:?}"),
    }
}

fn accept_req(code: &str, state: &[u8], pw: &str) -> VaultRequest {
    VaultRequest::AcceptLink { code: code.into(), state: state.to_vec(), passphrase: pw.into() }
}

fn err_of(r: &VaultResponse) -> (ErrorCode, String) {
    match r {
        VaultResponse::Error { code, message } => (*code, message.clone()),
        other => panic!("expected error, got {other:?}"),
    }
}

fn is_locked(r: &VaultResponse) -> bool {
    matches!(r, VaultResponse::Error { code: ErrorCode::Locked, message } if message == "vault is locked")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn names(store: &mut dyn SecretStore, token: Vec<u8>, origin: &SessionOrigin) -> Vec<String> {
    let r = call(store, Some(token), VaultRequest::ListSummaries { query: None }, origin);
    match r.resp {
        VaultResponse::Summaries { entries } => {
            let mut v: Vec<_> = entries.into_iter().map(|e| e.id).collect();
            v.sort();
            v
        }
        other => panic!("expected Summaries, got {other:?}"),
    }
}

fn keys_for(code: &str) -> (crate::link::LinkKeys, Vec<u8>) {
    let secret = decode_link_code(code).unwrap();
    let keys = derive_link_keys(&secret);
    let params = LinkDropParams::from_keys(&keys).to_cbor();
    (keys, params)
}

fn open_payload(offer: &Offer) -> LinkPayloadV1 {
    let (keys, params) = keys_for(&offer.code);
    let st = LinkDropState::from_cbor(&offer.state).unwrap();
    let pt = open_link_payload(&keys, &params, &st.body).unwrap();
    ciborium::from_reader(pt.as_slice()).unwrap()
}

/// Re-seal and sign a (possibly modified) payload with keys derived from the code.
fn reseal(code: &str, payload: &LinkPayloadV1) -> Vec<u8> {
    let (keys, params) = keys_for(code);
    let mut pt = Vec::new();
    ciborium::into_writer(payload, &mut pt).unwrap();
    let mut rng = fill;
    let sealed = seal_link_payload(&keys, &params, &pt, &mut rng).unwrap();
    sign_link_state(&keys, &params, SEQ_OFFER, KIND_OFFER, sealed).to_cbor()
}

fn clone_payload(p: &LinkPayloadV1) -> LinkPayloadV1 {
    LinkPayloadV1 {
        v: p.v,
        vault_id: p.vault_id.clone(),
        key_epoch: p.key_epoch,
        created_at: p.created_at,
        expires_at: p.expires_at,
        records: p.records.clone(),
    }
}

fn fresh_offer() -> (MemoryStore, Vec<u8>, Offer) {
    let mut a = seeded_store();
    let t = unlock(&mut a, &ORIGIN_A);
    let o = create_offer(&mut a, t.clone());
    (a, t, o)
}

/// Accept expecting an error; store must be byte-for-byte unchanged and no token.
fn assert_accept_refused(
    req: VaultRequest,
    origin: &SessionOrigin,
    now: u64,
    want: (ErrorCode, &str),
) {
    let mut b = MemoryStore::default();
    assert_accept_refused_on(&mut b, req, origin, now, want);
}

fn assert_accept_refused_on(
    b: &mut MemoryStore,
    req: VaultRequest,
    origin: &SessionOrigin,
    now: u64,
    want: (ErrorCode, &str),
) {
    let before = b.all_pairs();
    let r = call_at(b, None, req, origin, now);
    let (code, msg) = err_of(&r.resp);
    assert_eq!((code, msg.as_str()), want, "{:?}", r.resp);
    assert!(r.token.is_none(), "refusal must not issue a token");
    let after = b.all_pairs();
    if before != after {
        let keys = |v: &Vec<(Vec<u8>, Vec<u8>)>| -> Vec<String> {
            v.iter().map(|(k, _)| String::from_utf8_lossy(k).into_owned()).collect()
        };
        let changed: Vec<String> = after
            .iter()
            .filter(|p| !before.contains(p))
            .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
            .collect();
        panic!(
            "store changed by refused AcceptLink: before keys {:?}, after keys {:?}, changed/added {:?}",
            keys(&before),
            keys(&after),
            changed
        );
    }
}

// ---- AC4: end to end ---------------------------------------------------------------

#[test]
fn ac4_end_to_end_link_and_sync() {
    let mut a = seeded_store();
    let ta = unlock(&mut a, &ORIGIN_A);
    // A runs a sync first.
    let ra = call(&mut a, Some(ta.clone()), VaultRequest::SyncWithRemote { remote_state: vec![] }, &ORIGIN_A);
    let (state_a, vk_a, params_a) = match ra.resp {
        VaultResponse::Synced { contract_state, owner_verifying_key, sync_params, .. } => {
            (contract_state, owner_verifying_key, sync_params)
        }
        other => panic!("{other:?}"),
    };
    let ta = ra.token.unwrap_or(ta);
    let offer = create_offer(&mut a, ta.clone());
    assert!(offer.code.starts_with("AEGL-"));
    assert_eq!(offer.expires_at, NOW + LINK_TTL_SECS);

    let mut b = MemoryStore::default();
    let r = call(&mut b, None, accept_req(&offer.code, &offer.state, PW), &ORIGIN_B);
    let (vid_hex, hash, ack) = match r.resp {
        VaultResponse::Linked { vault_id, device_id_hash, ack_state } => {
            (vault_id, device_id_hash, ack_state)
        }
        other => panic!("accept failed: {other:?}"),
    };
    let tb = r.token.expect("token issued on link");

    // Ack is a valid seq-2 ack state for the code's params and names B's device.
    let ack_state = LinkDropState::from_cbor(&ack).unwrap();
    assert_eq!((ack_state.seq, ack_state.kind.as_str()), (SEQ_ACK, KIND_ACK));
    verify_link_state(&offer.params, &ack_state).unwrap();
    let body: LinkAckBody = ciborium::from_reader(ack_state.body.as_slice()).unwrap();
    assert_eq!(body.device_id_hash, hash);

    // Same entries, vault_id, key_epoch; different device_id.
    assert_eq!(names(&mut b, tb.clone(), &ORIGIN_B), vec!["e1", "e2"]);
    let sa = VaultSessionV2::unlock(&mut a, PW).unwrap();
    let sb = VaultSessionV2::unlock(&mut b, PW).unwrap();
    assert_eq!(sa.vault_id(), sb.vault_id());
    assert_eq!(sa.key_epoch(), sb.key_epoch());
    assert_ne!(sa.doc.meta.device_id, sb.doc.meta.device_id);
    let hex: String = sb.vault_id().iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(vid_hex, hex);
    assert_eq!(hash, blake3::hash(sb.doc.meta.device_id.as_bytes()).as_bytes().to_vec());
    drop((sa, sb));

    // B's first sync against A's state succeeds with the same identity.
    let rb = call(&mut b, Some(tb.clone()), VaultRequest::SyncWithRemote { remote_state: state_a }, &ORIGIN_B);
    let (state_b0, vk_b, params_b) = match rb.resp {
        VaultResponse::Synced { contract_state, owner_verifying_key, sync_params, .. } => {
            (contract_state, owner_verifying_key, sync_params)
        }
        other => panic!("B sync failed: {other:?}"),
    };
    assert_eq!(vk_a, vk_b);
    assert_eq!(params_a, params_b);
    assert!(!state_b0.is_empty());
    let tb = rb.token.unwrap_or(tb);

    // B adds an entry and publishes.
    let mut e = Entry::new("e3", "name-e3");
    e.password = "pw-three".into();
    let r = call(&mut b, Some(tb.clone()), VaultRequest::UpsertEntry { entry: e }, &ORIGIN_B);
    assert!(!matches!(r.resp, VaultResponse::Error { .. }), "{:?}", r.resp);
    let tb = r.token.unwrap_or(tb);
    let rb = call(&mut b, Some(tb.clone()), VaultRequest::SyncWithRemote { remote_state: state_b0 }, &ORIGIN_B);
    let state_b1 = match rb.resp {
        VaultResponse::Synced { contract_state, .. } => contract_state,
        other => panic!("{other:?}"),
    };

    // A pulls B's state and both list the same entries.
    let r = call(&mut a, Some(ta.clone()), VaultRequest::SyncWithRemote { remote_state: state_b1 }, &ORIGIN_A);
    assert!(matches!(r.resp, VaultResponse::Synced { .. }), "{:?}", r.resp);
    let ta = r.token.unwrap_or(ta);
    let tb = rb.token.unwrap_or(tb);
    assert_eq!(names(&mut a, ta, &ORIGIN_A), vec!["e1", "e2", "e3"]);
    assert_eq!(names(&mut b, tb, &ORIGIN_B), vec!["e1", "e2", "e3"]);
}

// ---- AC5: payload contents -----------------------------------------------------------

#[test]
fn ac5_payload_contents_and_no_secret_leak() {
    let mut a = seeded_store();
    a.set(SECRET_SESSION, b"PLANTED-SESSION-VALUE-xyz");
    a.set(b"aegis/v1/planted", b"PLANTED-V1-KEY-VALUE");
    let t = unlock(&mut a, &ORIGIN_A);
    let r = call(&mut a, Some(t.clone()), VaultRequest::SyncWithRemote { remote_state: vec![] }, &ORIGIN_A);
    let t = r.token.unwrap_or(t);
    let offer = create_offer(&mut a, t);

    let (keys, params) = keys_for(&offer.code);
    let st = LinkDropState::from_cbor(&offer.state).unwrap();
    let pt = open_link_payload(&keys, &params, &st.body).unwrap();
    let payload: LinkPayloadV1 = ciborium::from_reader(pt.as_slice()).unwrap();

    let want: Vec<Vec<u8>> = LINK_RECORD_KEYS
        .iter()
        .filter(|k| a.get(k).is_some())
        .map(|k| k.to_vec())
        .collect();
    let got: Vec<Vec<u8>> = payload.records.iter().map(|(k, _)| k.to_vec()).collect();
    assert_eq!(got, want, "record key set / order");
    assert!(got.iter().any(|k| k == SECRET_ENVELOPE_V2));
    assert!(got.iter().any(|k| k == SECRET_VAULT_V2));
    for (k, v) in &payload.records {
        assert_eq!(a.get(k).unwrap(), v.to_vec());
    }

    let ks = a.get(SECRET_DELEGATE_SESSION_KEY).expect("K_s present");
    let native = VaultSessionV2::unlock(&mut a, PW).unwrap();
    let mut secrets: Vec<Vec<u8>> = vec![ks, b"PLANTED-SESSION-VALUE-xyz".to_vec(), b"PLANTED-V1-KEY-VALUE".to_vec()];
    secrets.push(native.root_secret().as_bytes().to_vec());
    for d in native.operational_key_bytes_for_tests() {
        secrets.push(d.to_vec());
    }
    let names: [&[u8]; 8] = [
        b"aegis/v1/session",
        b"aegis/v2/audit",
        b"aegis/v2/sync-state",
        b"aegis/v2/sync-accepted",
        b"aegis/v2/sync-counter",
        b"aegis/v1/",
        b"aegis/gen/",
        b"aegis/v1/active-gen",
    ];
    for hay in [pt.as_slice(), offer.state.as_slice()] {
        for s in &secrets {
            assert!(!contains(hay, s), "secret value leaked");
        }
    }
    for n in names {
        assert!(!contains(&pt, n), "forbidden key name in payload: {}", String::from_utf8_lossy(n));
        assert!(!contains(&offer.state, n));
    }
}

// ---- AC6: CreateLinkOffer refusals ---------------------------------------------------

#[test]
fn ac6_create_offer_refusals() {
    let mut a = seeded_store();
    let t = unlock(&mut a, &ORIGIN_A);
    let ot = unlock(&mut a, &OTHER);

    // `ot` (a valid Other-origin token) is covered by
    // `ac6_create_offer_other_origin_issues_no_token` below.
    let r = call(&mut a, Some(ot), VaultRequest::CreateLinkOffer {}, &OTHER);
    assert!(is_locked(&r.resp), "{:?}", r.resp);
    for (token, origin) in [
        (None, &ORIGIN_A),
        (Some(vec![7u8; 64]), &ORIGIN_A),
        (Some(t.clone()), &ORIGIN_B), // token from another origin
    ] {
        let r = call(&mut a, token, VaultRequest::CreateLinkOffer {}, origin);
        assert!(is_locked(&r.resp), "{:?}", r.resp);
        assert!(r.token.is_none(), "token issued on refusal for case origin {origin:?}");
    }

    // now == 0
    let r = call_at(&mut a, Some(t.clone()), VaultRequest::CreateLinkOffer {}, &ORIGIN_A, 0);
    assert!(is_locked(&r.resp), "{:?}", r.resp);

    // bare legacy payload
    let mut payload = Vec::new();
    ciborium::into_writer(&VaultRequest::CreateLinkOffer {}, &mut payload).unwrap();
    let mut rng = fill;
    let out = process_message(&mut a, &payload, NOW, &ORIGIN_A, &mut rng).unwrap();
    let resp: VaultResponse = ciborium::from_reader(out.as_slice()).unwrap();
    assert!(is_locked(&resp), "{resp:?}");

    // plain dispatch
    let mut sess: Option<ActiveSession> = None;
    let _ = dispatch(&mut a, &mut sess, VaultRequest::Unlock { passphrase: PW.into() });
    let resp = dispatch(&mut a, &mut sess, VaultRequest::CreateLinkOffer {});
    assert!(is_locked(&resp), "{resp:?}");

    // v1 vault
    let mut v1 = MemoryStore::default();
    drop(VaultSession::create(&mut v1, PW, KdfProfile::Test).unwrap());
    let r = call(&mut v1, Some(vec![1; 64]), VaultRequest::CreateLinkOffer {}, &ORIGIN_A);
    assert!(is_locked(&r.resp), "{:?}", r.resp);
}

/// Spec AC6: refused with Locked *and no token* for an `Other` origin.
#[test]
fn ac6_create_offer_other_origin_issues_no_token() {
    let mut a = seeded_store();
    let ot = unlock(&mut a, &OTHER);
    let r = call(&mut a, Some(ot), VaultRequest::CreateLinkOffer {}, &OTHER);
    assert!(is_locked(&r.resp), "{:?}", r.resp);
    assert!(r.token.is_none(), "token issued with the Locked refusal");
}

#[test]
fn ac6_create_offer_does_not_write_and_mints_independent_codes() {
    let mut a = seeded_store();
    let t = unlock(&mut a, &ORIGIN_A);
    let before = a.durable_pairs();
    let o1 = create_offer(&mut a, t.clone());
    let o2 = create_offer(&mut a, t);
    assert_eq!(before, a.durable_pairs(), "CreateLinkOffer wrote to the store");
    assert_ne!(o1.code, o2.code);
    assert_ne!(o1.params, o2.params);
}

// ---- AC7: AcceptLink refusals ---------------------------------------------------------

#[test]
fn ac7_wrong_passphrase() {
    let (_a, _t, o) = fresh_offer();
    assert_accept_refused(
        accept_req(&o.code, &o.state, "not the passphrase"),
        &ORIGIN_B,
        NOW,
        (ErrorCode::AuthFailed, ERR_LINK_PASSPHRASE),
    );
}

#[test]
fn ac7_different_valid_code() {
    let (mut a, t, o1) = fresh_offer();
    let o2 = create_offer(&mut a, t);
    assert_accept_refused(
        accept_req(&o2.code, &o1.state, PW),
        &ORIGIN_B,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_INVALID),
    );
}

#[test]
fn ac7_typo_and_not_a_code() {
    let (_a, _t, o) = fresh_offer();
    // Flip the last (checksum) char to a different alphabet char.
    let mut chars: Vec<char> = o.code.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    let typo: String = chars.into_iter().collect();
    assert_accept_refused(
        accept_req(&typo, &o.state, PW),
        &ORIGIN_B,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_TYPO),
    );
    assert_accept_refused(
        accept_req("hello", &o.state, PW),
        &ORIGIN_B,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_NOT_A_CODE),
    );
}

#[test]
fn ac7_tampered_sealed_bytes_resigned() {
    let (_a, _t, o) = fresh_offer();
    let (keys, params) = keys_for(&o.code);
    let mut st = LinkDropState::from_cbor(&o.state).unwrap();
    let n = st.body.len() / 2;
    st.body[n] ^= 0x01;
    let bad = sign_link_state(&keys, &params, st.seq, &st.kind, st.body).to_cbor();
    assert_accept_refused(
        accept_req(&o.code, &bad, PW),
        &ORIGIN_B,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_INVALID),
    );
}

#[test]
fn ac7_flipped_signature_byte() {
    let (_a, _t, o) = fresh_offer();
    let mut st = LinkDropState::from_cbor(&o.state).unwrap();
    st.sig[10] ^= 0x01;
    assert_accept_refused(
        accept_req(&o.code, &st.to_cbor(), PW),
        &ORIGIN_B,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_INVALID),
    );
}

#[test]
fn ac7_garbage_empty_and_oversize_state() {
    let (_a, _t, o) = fresh_offer();
    for bad in [vec![], vec![0xff; 20], vec![0u8; MAX_LINK_STATE + 1]] {
        assert_accept_refused(
            accept_req(&o.code, &bad, PW),
            &ORIGIN_B,
            NOW,
            (ErrorCode::InvalidRequest, ERR_LINK_INVALID),
        );
    }
}

#[test]
fn ac7_ack_and_tombstone_states_are_used() {
    let (_a, _t, o) = fresh_offer();
    let (keys, params) = keys_for(&o.code);
    let ack = sign_link_state(&keys, &params, SEQ_ACK, KIND_ACK, vec![0u8; 8]).to_cbor();
    let tomb = sign_link_state(&keys, &params, SEQ_TOMBSTONE, KIND_TOMBSTONE, vec![]).to_cbor();
    for st in [ack, tomb] {
        assert_accept_refused(
            accept_req(&o.code, &st, PW),
            &ORIGIN_B,
            NOW,
            (ErrorCode::InvalidRequest, ERR_LINK_USED),
        );
    }
}

#[test]
fn ac7_expiry_boundary() {
    let (_a, _t, o) = fresh_offer();
    assert_accept_refused(
        accept_req(&o.code, &o.state, PW),
        &ORIGIN_B,
        o.expires_at,
        (ErrorCode::InvalidRequest, ERR_LINK_EXPIRED),
    );
    assert_accept_refused(
        accept_req(&o.code, &o.state, PW),
        &ORIGIN_B,
        o.expires_at + 1000,
        (ErrorCode::InvalidRequest, ERR_LINK_EXPIRED),
    );
    // one second before expiry succeeds
    let mut b = MemoryStore::default();
    let r = call_at(&mut b, None, accept_req(&o.code, &o.state, PW), &ORIGIN_B, o.expires_at - 1);
    assert!(matches!(r.resp, VaultResponse::Linked { .. }), "{:?}", r.resp);
}

#[test]
fn ac7_unknown_and_duplicate_record_keys() {
    let (_a, _t, o) = fresh_offer();
    let base = open_payload(&o);

    let mut unknown = clone_payload(&base);
    unknown.records.push((
        serde_bytes::ByteBuf::from(b"aegis/v2/audit".to_vec()),
        serde_bytes::ByteBuf::from(vec![1, 2, 3]),
    ));
    let mut dup = clone_payload(&base);
    let first = dup.records[0].clone();
    dup.records.push(first);

    for p in [unknown, dup] {
        let st = reseal(&o.code, &p);
        assert_accept_refused(
            accept_req(&o.code, &st, PW),
            &ORIGIN_B,
            NOW,
            (ErrorCode::InvalidRequest, ERR_LINK_INVALID),
        );
    }
}

#[test]
fn ac7_header_mismatch_and_missing_records() {
    let (_a, _t, o) = fresh_offer();
    let base = open_payload(&o);

    let mut vid = clone_payload(&base);
    vid.vault_id[0] ^= 0xff;
    let mut epoch = clone_payload(&base);
    epoch.key_epoch += 1;
    let mut no_vault = clone_payload(&base);
    no_vault.records.retain(|(k, _)| k.as_slice() != SECRET_VAULT_V2);
    let mut no_env = clone_payload(&base);
    no_env.records.retain(|(k, _)| k.as_slice() != SECRET_ENVELOPE_V2);
    let mut bad_ver = clone_payload(&base);
    bad_ver.v = 2;

    for p in [vid, epoch, no_vault, no_env, bad_ver] {
        let st = reseal(&o.code, &p);
        assert_accept_refused(
            accept_req(&o.code, &st, PW),
            &ORIGIN_B,
            NOW,
            (ErrorCode::InvalidRequest, ERR_LINK_INVALID),
        );
    }
}

#[test]
fn ac7_vault_already_exists() {
    let (_a, _t, o) = fresh_offer();
    let mut v2 = seeded_store();
    assert_accept_refused_on(
        &mut v2,
        accept_req(&o.code, &o.state, PW),
        &ORIGIN_B,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_NOT_PERMITTED),
    );
}

/// Spec 25: a refused AcceptLink leaves the store byte-for-byte unchanged, v1 included.
#[test]
fn ac7_vault_already_exists_v1_store_unchanged() {
    let (_a, _t, o) = fresh_offer();
    let mut v1 = MemoryStore::default();
    drop(VaultSession::create(&mut v1, PW, KdfProfile::Test).unwrap());
    assert_accept_refused_on(
        &mut v1,
        accept_req(&o.code, &o.state, PW),
        &ORIGIN_B,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_NOT_PERMITTED),
    );
}

#[test]
fn ac7_other_origin_and_plain_dispatch_and_bare() {
    let (_a, _t, o) = fresh_offer();
    assert_accept_refused(
        accept_req(&o.code, &o.state, PW),
        &OTHER,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_NOT_PERMITTED),
    );

    let mut b = MemoryStore::default();
    let mut sess: Option<ActiveSession> = None;
    let resp = dispatch(&mut b, &mut sess, accept_req(&o.code, &o.state, PW));
    assert_eq!(err_of(&resp), (ErrorCode::InvalidRequest, ERR_LINK_NOT_PERMITTED.to_string()));
    assert!(b.all_pairs().is_empty());

    let mut payload = Vec::new();
    ciborium::into_writer(&accept_req(&o.code, &o.state, PW), &mut payload).unwrap();
    let mut rng = fill;
    let out = process_message(&mut b, &payload, NOW, &ORIGIN_B, &mut rng).unwrap();
    let resp: VaultResponse = ciborium::from_reader(out.as_slice()).unwrap();
    assert_eq!(err_of(&resp), (ErrorCode::InvalidRequest, ERR_LINK_NOT_PERMITTED.to_string()));
    assert!(b.all_pairs().is_empty());
}

// ---- AC8: atomicity --------------------------------------------------------------------

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
fn ac8_failing_commit_is_storage_error_with_no_writes() {
    let (_a, _t, o) = fresh_offer();
    let mut b = FailCommitStore::default();
    let r = call(&mut b, None, accept_req(&o.code, &o.state, PW), &ORIGIN_B);
    match r.resp {
        VaultResponse::Error { code: ErrorCode::Storage, message } => {
            assert!(message.starts_with("atomic commit failed: "), "{message}")
        }
        other => panic!("expected storage error, got {other:?}"),
    }
    assert!(r.token.is_none());
    assert!(b.inner.all_pairs().is_empty());
    assert_eq!((b.sets, b.removes), (0, 0));
}

// ---- AC9: SignLinkState -----------------------------------------------------------------

#[test]
fn ac9_sign_tombstone() {
    let (mut a, t, o) = fresh_offer();
    let r = call(
        &mut a,
        Some(t.clone()),
        VaultRequest::SignLinkState { code: o.code.clone(), seq: 3, kind: "tombstone".into() },
        &ORIGIN_A,
    );
    let state = match r.resp {
        VaultResponse::LinkState { state } => state,
        other => panic!("{other:?}"),
    };
    let st = LinkDropState::from_cbor(&state).unwrap();
    assert_eq!((st.seq, st.kind.as_str(), st.body.len()), (3, "tombstone", 0));
    verify_link_state(&o.params, &st).unwrap();

    // Accept with the tombstone now says used.
    assert_accept_refused(
        accept_req(&o.code, &state, PW),
        &ORIGIN_B,
        NOW,
        (ErrorCode::InvalidRequest, ERR_LINK_USED),
    );

    // refused without auth
    let r = call(
        &mut a,
        None,
        VaultRequest::SignLinkState { code: o.code.clone(), seq: 3, kind: "tombstone".into() },
        &ORIGIN_A,
    );
    assert!(is_locked(&r.resp), "{:?}", r.resp);
    // other origin
    let r = call(
        &mut a,
        Some(t.clone()),
        VaultRequest::SignLinkState { code: o.code.clone(), seq: 3, kind: "tombstone".into() },
        &OTHER,
    );
    assert!(is_locked(&r.resp), "{:?}", r.resp);
    // plain dispatch
    let mut sess: Option<ActiveSession> = None;
    let resp = dispatch(
        &mut a,
        &mut sess,
        VaultRequest::SignLinkState { code: o.code.clone(), seq: 3, kind: "tombstone".into() },
    );
    assert!(is_locked(&resp), "{resp:?}");

    // kind ack -> InvalidRequest
    let r = call(
        &mut a,
        Some(t.clone()),
        VaultRequest::SignLinkState { code: o.code.clone(), seq: 2, kind: "ack".into() },
        &ORIGIN_A,
    );
    assert_eq!(err_of(&r.resp).0, ErrorCode::InvalidRequest);

    // bad code
    let r = call(
        &mut a,
        Some(t),
        VaultRequest::SignLinkState { code: "nope".into(), seq: 3, kind: "tombstone".into() },
        &ORIGIN_A,
    );
    assert_eq!(err_of(&r.resp), (ErrorCode::InvalidRequest, ERR_LINK_NOT_A_CODE.to_string()));
}

// ---- AC10: LinkLocate --------------------------------------------------------------------

#[test]
fn ac10_link_locate() {
    let secret = LinkSecret::from_bytes([7u8; 20]);
    let code = encode_link_code(&secret);
    let want = LinkDropParams::from_keys(&derive_link_keys(&secret)).to_cbor();

    let mut store = MemoryStore::default();
    let mut sess: Option<ActiveSession> = None;
    match dispatch(&mut store, &mut sess, VaultRequest::LinkLocate { code: code.clone() }) {
        VaultResponse::LinkLocation { params } => assert_eq!(params, want),
        other => panic!("{other:?}"),
    }
    let r = call(&mut store, None, VaultRequest::LinkLocate { code: code.clone() }, &OTHER);
    match r.resp {
        VaultResponse::LinkLocation { params } => assert_eq!(params, want),
        other => panic!("{other:?}"),
    }
    assert!(store.all_pairs().is_empty(), "locate must not touch the store");

    let mut chars: Vec<char> = code.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    let typo: String = chars.into_iter().collect();
    let resp = dispatch(&mut store, &mut sess, VaultRequest::LinkLocate { code: typo });
    assert_eq!(err_of(&resp), (ErrorCode::InvalidRequest, ERR_LINK_TYPO.to_string()));
    let resp = dispatch(&mut store, &mut sess, VaultRequest::LinkLocate { code: "AEGIS2-AAAA".into() });
    assert_eq!(err_of(&resp), (ErrorCode::InvalidRequest, ERR_LINK_NOT_A_CODE.to_string()));
}

// ---- Spec 26/27: double accept, A untouched ------------------------------------------------

#[test]
fn two_accepts_each_get_own_device_id_and_a_is_untouched() {
    let (a, _t, o) = fresh_offer();
    let a_before = a.all_pairs();
    let mut b1 = MemoryStore::default();
    let mut b2 = MemoryStore::default();
    for b in [&mut b1, &mut b2] {
        let r = call(b, None, accept_req(&o.code, &o.state, PW), &ORIGIN_B);
        assert!(matches!(r.resp, VaultResponse::Linked { .. }), "{:?}", r.resp);
    }
    let d1 = VaultSessionV2::unlock(&mut b1, PW).unwrap().doc.meta.device_id.clone();
    let d2 = VaultSessionV2::unlock(&mut b2, PW).unwrap().doc.meta.device_id.clone();
    assert_ne!(d1, d2);
    assert_eq!(a_before, a.all_pairs());
}

#[test]
fn linked_store_has_no_foreign_sync_state_and_fresh_audit() {
    let mut a = seeded_store();
    let t = unlock(&mut a, &ORIGIN_A);
    let r = call(&mut a, Some(t.clone()), VaultRequest::SyncWithRemote { remote_state: vec![] }, &ORIGIN_A);
    let t = r.token.unwrap_or(t);
    let o = create_offer(&mut a, t);
    let mut b = MemoryStore::default();
    let r = call(&mut b, None, accept_req(&o.code, &o.state, PW), &ORIGIN_B);
    assert!(matches!(r.resp, VaultResponse::Linked { .. }));
    for k in [
        crate::sync_v2::SECRET_SYNC_STATE_V2,
        crate::sync_v2::SECRET_SYNC_ACCEPTED_V2,
        crate::sync_v2::SECRET_SYNC_COUNTER_V2,
    ] {
        assert!(b.get(k).is_none(), "{}", String::from_utf8_lossy(k));
    }
    assert!(b.get(crate::session_v2::SECRET_AUDIT_V2).is_some());
    assert_ne!(
        a.get(crate::session_v2::SECRET_AUDIT_V2),
        b.get(crate::session_v2::SECRET_AUDIT_V2),
        "audit must not travel"
    );
    assert_eq!(a.get(SECRET_ENVELOPE_V2), b.get(SECRET_ENVELOPE_V2));
}
