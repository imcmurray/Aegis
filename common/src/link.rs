//! Link a second device over Freenet (D21).
//!
//! Device A (unlocked) mints a one-time link code and publishes a sealed,
//! signed offer to an `aegis-link-drop` contract that is located by the code
//! alone. Device B (empty delegate) enters the code and the master passphrase,
//! the delegate validates the offer and installs the vault with the same
//! identity but its own `device_id`.
//!
//! The link secret never leaves the code: the contract parameters, the signing
//! key and the AEAD key are all derived from it with HKDF. The payload carries
//! only records that are already encrypted at rest (envelope, vault, recovery,
//! sync transition). It never carries the root, a DEK or K_s.

use crate::crypto::{MasterEnvelopeV2, VaultBlobV2};
use crate::delegate_session::{RngFn, SessionOrigin};
use crate::messages::{ErrorCode, VaultResponse};
use crate::recovery_v2::SECRET_RECOVERY_V2;
use crate::session_v2::{
    install_linked_v2, VaultSessionV2, SECRET_ENVELOPE_V2, SECRET_VAULT_V2,
};
use crate::sync_v2::SECRET_SYNC_TRANSITION_V2;
use crate::vault::{
    detect_persisted_format, ActiveSession, PersistedFormat, SecretStore, VaultError,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const APP_LINK_V1: &str = "AEGIS_LINK_V1";
pub const LINK_SECRET_LEN: usize = 20;
pub const LINK_TTL_SECS: u64 = 600;
pub const LINK_PAYLOAD_VERSION: u32 = 1;
/// Offer body cap.
pub const MAX_LINK_SEALED: usize = 4 * 1024 * 1024;
/// Ack / tombstone body cap.
pub const MAX_LINK_SMALL_BODY: usize = 256;
/// Encoded state cap, checked before CBOR parse.
pub const MAX_LINK_STATE: usize = MAX_LINK_SEALED + 1024;
pub const LINK_HKDF_SALT: &[u8] = b"aegis/v2/link";
pub const LABEL_LINK_SIGN: &[u8] = b"aegis/v2/link/sign";
pub const LABEL_LINK_KEY: &[u8] = b"aegis/v2/link/key";
pub const LINK_DISPLAY_PREFIX: &str = "AEGL-";
pub const KIND_OFFER: &str = "offer";
pub const KIND_ACK: &str = "ack";
pub const KIND_TOMBSTONE: &str = "tombstone";
pub const SEQ_OFFER: u64 = 1;
pub const SEQ_ACK: u64 = 2;
pub const SEQ_TOMBSTONE: u64 = 3;
/// Exactly these keys may travel in a link payload, in this order.
pub const LINK_RECORD_KEYS: &[&[u8]] = &[
    SECRET_ENVELOPE_V2,
    SECRET_VAULT_V2,
    SECRET_RECOVERY_V2,
    SECRET_SYNC_TRANSITION_V2,
];

pub const ERR_LINK_TYPO: &str = "That link code has a typo";
pub const ERR_LINK_NOT_A_CODE: &str = "That is not a link code";
pub const ERR_LINK_EXPIRED: &str = "This link code has expired";
pub const ERR_LINK_USED: &str = "This link code was already used or cancelled";
pub const ERR_LINK_INVALID: &str = "invalid link offer";
pub const ERR_LINK_NOT_PERMITTED: &str = "link not permitted";
pub const ERR_LINK_TOO_LARGE: &str = "vault too large to link";
pub const ERR_LINK_PASSPHRASE: &str = "wrong passphrase";

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_PARAMS_LEN: usize = 256;
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PAYLOAD_CHARS: usize = 32; // 160 bits / 5
const CODE_CHARS: usize = PAYLOAD_CHARS + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    NotACode,
    Typo,
    Invalid,
    Expired,
    Used,
    TooLarge,
}

impl LinkError {
    /// User-facing text (the `ERR_LINK_*` constants).
    pub fn message(&self) -> &'static str {
        match self {
            LinkError::NotACode => ERR_LINK_NOT_A_CODE,
            LinkError::Typo => ERR_LINK_TYPO,
            LinkError::Invalid => ERR_LINK_INVALID,
            LinkError::Expired => ERR_LINK_EXPIRED,
            LinkError::Used => ERR_LINK_USED,
            LinkError::TooLarge => ERR_LINK_TOO_LARGE,
        }
    }
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// 20 random bytes. Never cloned, serialized or logged.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LinkSecret([u8; LINK_SECRET_LEN]);

impl std::fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkSecret([REDACTED])")
    }
}

impl LinkSecret {
    pub fn from_bytes(b: [u8; LINK_SECRET_LEN]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; LINK_SECRET_LEN] {
        &self.0
    }

    pub fn generate(rng: RngFn<'_>) -> Self {
        let mut b = [0u8; LINK_SECRET_LEN];
        rng(&mut b);
        let s = Self(b);
        b.zeroize();
        s
    }
}

fn encode_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 0x1f) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(CROCKFORD[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn decode_base32_20(s: &str) -> Option<[u8; LINK_SECRET_LEN]> {
    if s.len() != PAYLOAD_CHARS {
        return None;
    }
    let mut out = [0u8; LINK_SECRET_LEN];
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut n = 0usize;
    for c in s.bytes() {
        let idx = CROCKFORD.iter().position(|&x| x == c)? as u32;
        acc = (acc << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[n] = ((acc >> bits) & 0xff) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    if n != LINK_SECRET_LEN {
        return None;
    }
    Some(out)
}

/// Top 10 bits of SHA-256(secret), as two Base32 chars (recovery-style).
fn checksum_chars(secret: &[u8; LINK_SECRET_LEN]) -> [char; 2] {
    let hash = Sha256::digest(secret);
    let bits = u16::from(hash[0]) << 2 | u16::from(hash[1]) >> 6;
    [
        CROCKFORD[((bits >> 5) & 0x1f) as usize] as char,
        CROCKFORD[(bits & 0x1f) as usize] as char,
    ]
}

/// `AEGL-` + 32 Base32 chars + 2 checksum chars, grouped in 4s with `-`.
pub fn encode_link_code(secret: &LinkSecret) -> String {
    let mut body = encode_base32(secret.as_bytes());
    let [c0, c1] = checksum_chars(secret.as_bytes());
    body.push(c0);
    body.push(c1);
    let parts: Vec<&str> = body
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!("{LINK_DISPLAY_PREFIX}{}", parts.join("-"))
}

/// Tolerant parse: trim, drop whitespace and `-`, uppercase, optional `AEGL`
/// prefix, Crockford aliases. `NotACode` for shape errors, `Typo` for a bad checksum.
pub fn decode_link_code(code: &str) -> Result<LinkSecret, LinkError> {
    let mut s: String = code
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if s.len() == CODE_CHARS + 4 && s.starts_with("AEGL") {
        s = s[4..].to_string();
    }
    if s.len() != CODE_CHARS {
        return Err(LinkError::NotACode);
    }
    let mapped: String = s
        .chars()
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            'U' => 'V',
            other => other,
        })
        .collect();
    if !mapped.bytes().all(|b| CROCKFORD.contains(&b)) {
        return Err(LinkError::NotACode);
    }
    let (payload, cs) = mapped.split_at(PAYLOAD_CHARS);
    let mut bytes = decode_base32_20(payload).ok_or(LinkError::NotACode)?;
    let expect = checksum_chars(&bytes);
    let got: Vec<char> = cs.chars().collect();
    if got.len() != 2 || got[0] != expect[0] || got[1] != expect[1] {
        bytes.zeroize();
        return Err(LinkError::Typo);
    }
    let secret = LinkSecret::from_bytes(bytes);
    bytes.zeroize();
    Ok(secret)
}

/// Signing key + AEAD key derived from the link secret.
pub struct LinkKeys {
    signing: SigningKey,
    aead_key: [u8; 32],
}

impl Drop for LinkKeys {
    fn drop(&mut self) {
        self.aead_key.zeroize();
    }
}

impl std::fmt::Debug for LinkKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkKeys([REDACTED])")
    }
}

pub fn derive_link_keys(secret: &LinkSecret) -> LinkKeys {
    let hk = Hkdf::<Sha256>::new(Some(LINK_HKDF_SALT), secret.as_bytes());
    let mut seed = [0u8; 32];
    let mut aead_key = [0u8; 32];
    // 32-byte output is far below the HKDF limit: expand cannot fail.
    hk.expand(LABEL_LINK_SIGN, &mut seed)
        .expect("hkdf expand 32");
    hk.expand(LABEL_LINK_KEY, &mut aead_key)
        .expect("hkdf expand 32");
    let signing = SigningKey::from_bytes(&seed);
    seed.zeroize();
    LinkKeys { signing, aead_key }
}

impl LinkKeys {
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Test/diagnostic: the AEAD key bytes.
    #[cfg(test)]
    pub(crate) fn aead_key_for_test(&self) -> [u8; 32] {
        self.aead_key
    }

    /// Test/diagnostic: the Ed25519 seed bytes.
    #[cfg(test)]
    pub(crate) fn signing_seed_for_test(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }
}

fn encode_cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    // Writing to a Vec cannot fail for these plain structs.
    let _ = ciborium::into_writer(v, &mut out);
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkDropParams {
    pub app: String,
    #[serde(with = "serde_bytes")]
    pub ed25519_vk: Vec<u8>,
}

impl LinkDropParams {
    pub fn from_keys(keys: &LinkKeys) -> Self {
        Self {
            app: APP_LINK_V1.to_string(),
            ed25519_vk: keys.verifying_key_bytes().to_vec(),
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        encode_cbor(self)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, LinkError> {
        if bytes.len() > MAX_PARAMS_LEN {
            return Err(LinkError::Invalid);
        }
        let p: Self = ciborium::from_reader(bytes).map_err(|_| LinkError::Invalid)?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), LinkError> {
        if self.app != APP_LINK_V1 {
            return Err(LinkError::Invalid);
        }
        let vk: [u8; 32] = self
            .ed25519_vk
            .as_slice()
            .try_into()
            .map_err(|_| LinkError::Invalid)?;
        VerifyingKey::from_bytes(&vk).map_err(|_| LinkError::Invalid)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkDropState {
    pub seq: u64,
    pub kind: String,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl LinkDropState {
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_cbor(self)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, LinkError> {
        if bytes.len() > MAX_LINK_STATE {
            return Err(LinkError::Invalid);
        }
        ciborium::from_reader(bytes).map_err(|_| LinkError::Invalid)
    }
}

pub fn kind_rank(kind: &str) -> Option<u8> {
    match kind {
        KIND_OFFER => Some(0),
        KIND_ACK => Some(1),
        KIND_TOMBSTONE => Some(2),
        _ => None,
    }
}

fn body_cap(kind: &str) -> usize {
    if kind == KIND_OFFER {
        MAX_LINK_SEALED
    } else {
        MAX_LINK_SMALL_BODY
    }
}

/// `"AEGIS_LINK_V1" || u32_be(len(params)) || params || u64_be(seq) || u8(len(kind)) || kind || body`
pub fn link_sign_bytes(params_cbor: &[u8], seq: u64, kind: &str, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(APP_LINK_V1.len() + 4 + params_cbor.len() + 8 + 1 + kind.len() + body.len());
    m.extend_from_slice(APP_LINK_V1.as_bytes());
    m.extend_from_slice(&(params_cbor.len() as u32).to_be_bytes());
    m.extend_from_slice(params_cbor);
    m.extend_from_slice(&seq.to_be_bytes());
    m.push(kind.len() as u8);
    m.extend_from_slice(kind.as_bytes());
    m.extend_from_slice(body);
    m
}

pub fn sign_link_state(
    keys: &LinkKeys,
    params_cbor: &[u8],
    seq: u64,
    kind: &str,
    body: Vec<u8>,
) -> LinkDropState {
    let msg = link_sign_bytes(params_cbor, seq, kind, &body);
    let sig = keys.signing.sign(&msg);
    LinkDropState {
        seq,
        kind: kind.to_string(),
        body,
        sig: sig.to_bytes().to_vec(),
    }
}

pub fn verify_link_state(params_cbor: &[u8], state: &LinkDropState) -> Result<(), LinkError> {
    let params = LinkDropParams::from_cbor(params_cbor)?;
    if kind_rank(&state.kind).is_none() {
        return Err(LinkError::Invalid);
    }
    if state.body.len() > body_cap(&state.kind) {
        return Err(LinkError::Invalid);
    }
    let sig: [u8; 64] = state
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| LinkError::Invalid)?;
    let vk: [u8; 32] = params
        .ed25519_vk
        .as_slice()
        .try_into()
        .map_err(|_| LinkError::Invalid)?;
    let vk = VerifyingKey::from_bytes(&vk).map_err(|_| LinkError::Invalid)?;
    let msg = link_sign_bytes(params_cbor, state.seq, &state.kind, &state.body);
    vk.verify_strict(&msg, &Signature::from_bytes(&sig))
        .map_err(|_| LinkError::Invalid)
}

/// Greater of `a`, `b` under the total order `(seq, kind_rank, body, sig)`.
pub fn merge_link_states(a: &LinkDropState, b: &LinkDropState) -> LinkDropState {
    let key = |s: &LinkDropState| (s.seq, kind_rank(&s.kind).unwrap_or(u8::MAX));
    let ord = key(a)
        .cmp(&key(b))
        .then_with(|| a.body.cmp(&b.body))
        .then_with(|| a.sig.cmp(&b.sig));
    if ord == std::cmp::Ordering::Less {
        b.clone()
    } else {
        a.clone()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkPayloadV1 {
    pub v: u32,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub records: Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkAckBody {
    #[serde(with = "serde_bytes")]
    pub device_id_hash: Vec<u8>,
}

fn link_aad(params_cbor: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(APP_LINK_V1.len() + params_cbor.len());
    aad.extend_from_slice(APP_LINK_V1.as_bytes());
    aad.extend_from_slice(params_cbor);
    aad
}

/// `nonce(24) || XChaCha20-Poly1305(aead_key, nonce, plaintext, AAD = "AEGIS_LINK_V1" || params_cbor)`.
pub fn seal_link_payload(
    keys: &LinkKeys,
    params_cbor: &[u8],
    plaintext: &[u8],
    rng: RngFn<'_>,
) -> Result<Vec<u8>, LinkError> {
    if NONCE_LEN + plaintext.len() + TAG_LEN > MAX_LINK_SEALED {
        return Err(LinkError::TooLarge);
    }
    let mut nonce = [0u8; NONCE_LEN];
    rng(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.aead_key).map_err(|_| LinkError::Invalid)?;
    let aad = link_aad(params_cbor);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| LinkError::Invalid)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_link_payload(
    keys: &LinkKeys,
    params_cbor: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, LinkError> {
    if sealed.len() < NONCE_LEN + TAG_LEN || sealed.len() > MAX_LINK_SEALED {
        return Err(LinkError::Invalid);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.aead_key).map_err(|_| LinkError::Invalid)?;
    let aad = link_aad(params_cbor);
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &aad,
            },
        )
        .map_err(|_| LinkError::Invalid)
}

pub struct LinkOffer {
    pub code: String,
    pub params: Vec<u8>,
    pub state: Vec<u8>,
    pub expires_at: u64,
}

fn locked() -> VaultError {
    VaultError::Msg("vault is locked".into())
}

/// Reads `LINK_RECORD_KEYS` via `store.get` (the logical view). The envelope's
/// vault_id/key_epoch must match the session. No store writes.
pub fn create_link_offer(
    store: &dyn SecretStore,
    session: &VaultSessionV2,
    now: u64,
    rng: RngFn<'_>,
) -> Result<LinkOffer, VaultError> {
    if now == 0 {
        return Err(locked());
    }
    let env_bytes = store.get(SECRET_ENVELOPE_V2).ok_or_else(locked)?;
    let env = MasterEnvelopeV2::from_bytes(&env_bytes).map_err(|_| locked())?;
    let env_vid = env.vault_id_bytes().map_err(|_| locked())?;
    if env_vid != session.vault_id() || env.key_epoch != session.key_epoch() {
        return Err(locked());
    }

    let mut records = Vec::new();
    for key in LINK_RECORD_KEYS {
        if let Some(value) = store.get(key) {
            records.push((
                serde_bytes::ByteBuf::from(key.to_vec()),
                serde_bytes::ByteBuf::from(value),
            ));
        }
    }
    if !records.iter().any(|(k, _)| k.as_slice() == SECRET_VAULT_V2) {
        return Err(locked());
    }

    let expires_at = now.saturating_add(LINK_TTL_SECS);
    let payload = LinkPayloadV1 {
        v: LINK_PAYLOAD_VERSION,
        vault_id: session.vault_id().to_vec(),
        key_epoch: session.key_epoch(),
        created_at: now,
        expires_at,
        records,
    };
    let plaintext = encode_cbor(&payload);

    let secret = LinkSecret::generate(&mut *rng);
    let keys = derive_link_keys(&secret);
    let params = LinkDropParams::from_keys(&keys).to_cbor();
    let sealed = seal_link_payload(&keys, &params, &plaintext, &mut *rng)
        .map_err(|_| VaultError::Msg(ERR_LINK_TOO_LARGE.into()))?;
    let state = sign_link_state(&keys, &params, SEQ_OFFER, KIND_OFFER, sealed).to_cbor();
    Ok(LinkOffer {
        code: encode_link_code(&secret),
        params,
        state,
        expires_at,
    })
}

pub struct LinkAccepted {
    pub session: VaultSessionV2,
    pub device_id_hash: [u8; 32],
    pub ack_state: Vec<u8>,
}

fn err(code: ErrorCode, msg: &str) -> VaultResponse {
    VaultResponse::err(code, msg)
}

fn invalid_req(e: LinkError) -> VaultResponse {
    err(ErrorCode::InvalidRequest, e.message())
}

/// Full validation, unlock in memory, then ONE `store.commit`. Errors are the
/// finished error response (code + `ERR_LINK_*` text). No store write happens
/// before the final commit.
pub fn accept_link(
    store: &mut dyn SecretStore,
    code: &str,
    state: &[u8],
    passphrase: &str,
    now: u64,
) -> Result<LinkAccepted, VaultResponse> {
    if !matches!(detect_persisted_format(&*store), Ok(PersistedFormat::None)) {
        return Err(err(ErrorCode::InvalidRequest, ERR_LINK_NOT_PERMITTED));
    }
    let secret = decode_link_code(code).map_err(invalid_req)?;
    let keys = derive_link_keys(&secret);
    drop(secret);
    let params = LinkDropParams::from_keys(&keys).to_cbor();

    if state.is_empty() || state.len() > MAX_LINK_STATE {
        return Err(invalid_req(LinkError::Invalid));
    }
    let st = LinkDropState::from_cbor(state).map_err(invalid_req)?;
    verify_link_state(&params, &st).map_err(invalid_req)?;
    if st.kind != KIND_OFFER {
        return Err(invalid_req(LinkError::Used));
    }

    let mut plaintext = open_link_payload(&keys, &params, &st.body).map_err(invalid_req)?;
    let payload: Result<LinkPayloadV1, _> = ciborium::from_reader(plaintext.as_slice());
    plaintext.zeroize();
    let payload = payload.map_err(|_| invalid_req(LinkError::Invalid))?;
    if payload.v != LINK_PAYLOAD_VERSION {
        return Err(invalid_req(LinkError::Invalid));
    }
    if now >= payload.expires_at {
        return Err(invalid_req(LinkError::Expired));
    }
    let records = validate_records(&payload).map_err(invalid_req)?;

    let session = match install_linked_v2(store, &records, passphrase) {
        Ok(s) => s,
        Err(e) => {
            let msg = e.to_string();
            return Err(if e.code() == ErrorCode::AuthFailed {
                err(ErrorCode::AuthFailed, ERR_LINK_PASSPHRASE)
            } else if msg.starts_with(crate::upgrade::ERR_COMMIT_PREFIX) {
                err(ErrorCode::Storage, &msg)
            } else {
                invalid_req(LinkError::Invalid)
            });
        }
    };

    let mut device_id_hash = [0u8; 32];
    device_id_hash.copy_from_slice(blake3::hash(session.doc.meta.device_id.as_bytes()).as_bytes());
    let ack_body = encode_cbor(&LinkAckBody {
        device_id_hash: device_id_hash.to_vec(),
    });
    let ack_state = sign_link_state(&keys, &params, SEQ_ACK, KIND_ACK, ack_body).to_cbor();
    Ok(LinkAccepted {
        session,
        device_id_hash,
        ack_state,
    })
}

/// Payload-level checks. Returns the records as owned pairs.
fn validate_records(p: &LinkPayloadV1) -> Result<Vec<(Vec<u8>, Vec<u8>)>, LinkError> {
    if p.vault_id.len() != 16 {
        return Err(LinkError::Invalid);
    }
    let mut seen: Vec<&[u8]> = Vec::new();
    for (k, _) in &p.records {
        let k = k.as_slice();
        if !LINK_RECORD_KEYS.contains(&k) || seen.contains(&k) {
            return Err(LinkError::Invalid);
        }
        seen.push(k);
    }
    let find = |key: &[u8]| {
        p.records
            .iter()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, v)| v.as_slice())
    };
    let env_bytes = find(SECRET_ENVELOPE_V2).ok_or(LinkError::Invalid)?;
    let vault_bytes = find(SECRET_VAULT_V2).ok_or(LinkError::Invalid)?;
    let env = MasterEnvelopeV2::from_bytes(env_bytes).map_err(|_| LinkError::Invalid)?;
    let env_vid = env.vault_id_bytes().map_err(|_| LinkError::Invalid)?;
    if env_vid.as_slice() != p.vault_id.as_slice() || env.key_epoch != p.key_epoch {
        return Err(LinkError::Invalid);
    }
    let blob = VaultBlobV2::from_bytes(vault_bytes).map_err(|_| LinkError::Invalid)?;
    if blob.key_epoch != p.key_epoch || blob.vault_id != p.vault_id {
        return Err(LinkError::Invalid);
    }
    Ok(p.records
        .iter()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect())
}

/// `LinkLocate`: pure. Params for the contract instance derived from the code.
pub fn handle_link_locate(code: &str) -> VaultResponse {
    match decode_link_code(code) {
        Ok(secret) => {
            let keys = derive_link_keys(&secret);
            VaultResponse::LinkLocation {
                params: LinkDropParams::from_keys(&keys).to_cbor(),
            }
        }
        Err(e) => invalid_req(e),
    }
}

/// Auth shared by `CreateLinkOffer` / `SignLinkState`: a session resumed from a
/// valid token in this request, for a WebApp origin. Every refusal looks the same.
fn authorised_session<'a>(
    session: &'a Option<ActiveSession>,
    resumed: bool,
    origin: &SessionOrigin,
    now: u64,
) -> Option<&'a VaultSessionV2> {
    if now == 0 || !resumed || !matches!(origin, SessionOrigin::WebApp(_)) {
        return None;
    }
    match session {
        Some(ActiveSession::V2(s)) => Some(s),
        _ => None,
    }
}

pub fn handle_create_link_offer(
    store: &dyn SecretStore,
    session: &Option<ActiveSession>,
    resumed: bool,
    origin: &SessionOrigin,
    now: u64,
    rng: RngFn<'_>,
) -> VaultResponse {
    let refuse = || err(ErrorCode::Locked, "vault is locked");
    let Some(s) = authorised_session(session, resumed, origin, now) else {
        return refuse();
    };
    match create_link_offer(store, s, now, rng) {
        Ok(o) => VaultResponse::LinkOffer {
            code: o.code,
            params: o.params,
            state: o.state,
            expires_at: o.expires_at,
        },
        Err(VaultError::Msg(m)) if m == ERR_LINK_TOO_LARGE => {
            err(ErrorCode::InvalidRequest, ERR_LINK_TOO_LARGE)
        }
        Err(_) => refuse(),
    }
}

pub fn handle_sign_link_state(
    session: &Option<ActiveSession>,
    resumed: bool,
    origin: &SessionOrigin,
    now: u64,
    code: &str,
    seq: u64,
    kind: &str,
) -> VaultResponse {
    if authorised_session(session, resumed, origin, now).is_none() {
        return err(ErrorCode::Locked, "vault is locked");
    }
    if kind != KIND_TOMBSTONE {
        return err(ErrorCode::InvalidRequest, ERR_LINK_INVALID);
    }
    let secret = match decode_link_code(code) {
        Ok(s) => s,
        Err(e) => return invalid_req(e),
    };
    let keys = derive_link_keys(&secret);
    let params = LinkDropParams::from_keys(&keys).to_cbor();
    let st = sign_link_state(&keys, &params, seq, KIND_TOMBSTONE, Vec::new());
    VaultResponse::LinkState {
        state: st.to_cbor(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hkdf_v2::{
        LABEL_RECOVERY_KEK, LABEL_SHARE_HYBRID_KEK, ROOT_DERIVED_LABELS,
    };

    fn rng_fill(b: &mut [u8]) {
        crate::rng::fill_random(b);
    }

    fn secret(n: u8) -> LinkSecret {
        LinkSecret::from_bytes([n; 20])
    }

    #[test]
    fn code_round_trips_and_has_shape() {
        for _ in 0..50 {
            let s = LinkSecret::generate(&mut rng_fill);
            let code = encode_link_code(&s);
            assert!(code.starts_with("AEGL-"));
            let body = &code[5..];
            let groups: Vec<&str> = body.split('-').collect();
            assert_eq!(groups.len(), 9);
            assert!(groups[..8].iter().all(|g| g.len() == 4));
            assert_eq!(groups[8].len(), 2);
            assert_eq!(body.replace('-', "").len(), 34);
            let back = decode_link_code(&code).unwrap();
            assert_eq!(back.as_bytes(), s.as_bytes());
        }
    }

    #[test]
    fn decode_is_tolerant() {
        let s = secret(0x5a);
        let code = encode_link_code(&s);
        let lower = code.to_lowercase();
        assert_eq!(decode_link_code(&lower).unwrap().as_bytes(), s.as_bytes());
        let spaced = format!("  {}  ", code.replace('-', " "));
        assert_eq!(decode_link_code(&spaced).unwrap().as_bytes(), s.as_bytes());
        let nodash = code.replace('-', "");
        assert_eq!(decode_link_code(&nodash).unwrap().as_bytes(), s.as_bytes());
        let no_prefix = code.strip_prefix("AEGL-").unwrap();
        assert_eq!(decode_link_code(no_prefix).unwrap().as_bytes(), s.as_bytes());
        let extra = code.replace('-', "--");
        assert_eq!(decode_link_code(&extra).unwrap().as_bytes(), s.as_bytes());
    }

    #[test]
    fn decode_errors() {
        let code = encode_link_code(&secret(7));
        // Change a payload char.
        let mut chars: Vec<char> = code.chars().collect();
        let i = 6;
        chars[i] = if chars[i] == '0' { '1' } else { '0' };
        let bad: String = chars.iter().collect();
        assert_eq!(decode_link_code(&bad).unwrap_err(), LinkError::Typo);
        // Change a checksum char.
        let mut chars: Vec<char> = code.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let bad: String = chars.iter().collect();
        assert_eq!(decode_link_code(&bad).unwrap_err(), LinkError::Typo);
        // Shape errors.
        assert_eq!(decode_link_code("").unwrap_err(), LinkError::NotACode);
        assert_eq!(decode_link_code("AEGL-1234").unwrap_err(), LinkError::NotACode);
        let invalid = format!("AEGL-{}", "!".repeat(34));
        assert_eq!(decode_link_code(&invalid).unwrap_err(), LinkError::NotACode);
        let rec = crate::recovery_v2::encode_recovery_secret(
            &crate::crypto::secret::RecoverySecret::from_bytes([3u8; 32]),
        );
        assert_eq!(decode_link_code(&rec).unwrap_err(), LinkError::NotACode);
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(format!("{:?}", secret(1)), "LinkSecret([REDACTED])");
    }

    #[test]
    fn labels_are_distinct_and_keys_deterministic() {
        assert_ne!(LABEL_LINK_SIGN, LABEL_LINK_KEY);
        let mut all = ROOT_DERIVED_LABELS.to_vec();
        all.push(LABEL_RECOVERY_KEK);
        all.push(LABEL_SHARE_HYBRID_KEK);
        for l in all {
            assert_ne!(l, LABEL_LINK_SIGN);
            assert_ne!(l, LABEL_LINK_KEY);
        }
        let a = derive_link_keys(&secret(9));
        let b = derive_link_keys(&secret(9));
        let c = derive_link_keys(&secret(10));
        assert_ne!(a.signing_seed_for_test(), a.aead_key_for_test());
        assert_eq!(a.signing_seed_for_test(), b.signing_seed_for_test());
        assert_eq!(a.aead_key_for_test(), b.aead_key_for_test());
        assert_ne!(a.aead_key_for_test(), c.aead_key_for_test());
        assert_eq!(format!("{a:?}"), "LinkKeys([REDACTED])");
    }

    #[test]
    fn params_are_deterministic_and_validated() {
        let k = derive_link_keys(&secret(2));
        let p = LinkDropParams::from_keys(&k);
        assert_eq!(p.to_cbor(), LinkDropParams::from_keys(&derive_link_keys(&secret(2))).to_cbor());
        assert_eq!(LinkDropParams::from_cbor(&p.to_cbor()).unwrap(), p);
        let mut bad = p.clone();
        bad.app = "OTHER".into();
        assert!(LinkDropParams::from_cbor(&bad.to_cbor()).is_err());
        let mut bad = p;
        bad.ed25519_vk = vec![1; 31];
        assert!(LinkDropParams::from_cbor(&bad.to_cbor()).is_err());
    }

    fn signed(k: &LinkKeys, p: &[u8], seq: u64, kind: &str, body: &[u8]) -> LinkDropState {
        sign_link_state(k, p, seq, kind, body.to_vec())
    }

    #[test]
    fn sign_verify() {
        let k = derive_link_keys(&secret(4));
        let p = LinkDropParams::from_keys(&k).to_cbor();
        for (seq, kind, body) in [
            (1, KIND_OFFER, &b"sealed"[..]),
            (2, KIND_ACK, &b"ack"[..]),
            (3, KIND_TOMBSTONE, &b""[..]),
        ] {
            let st = signed(&k, &p, seq, kind, body);
            verify_link_state(&p, &st).unwrap();
            assert_eq!(LinkDropState::from_cbor(&st.to_cbor()).unwrap(), st);
            // Flipped sig, changed body/seq/kind all fail.
            let mut bad = st.clone();
            bad.sig[0] ^= 1;
            assert!(verify_link_state(&p, &bad).is_err());
            let mut bad = st.clone();
            bad.body.push(0);
            assert!(verify_link_state(&p, &bad).is_err());
            let mut bad = st.clone();
            bad.seq += 1;
            assert!(verify_link_state(&p, &bad).is_err());
        }
        // Another key.
        let other = derive_link_keys(&secret(5));
        let st = signed(&other, &p, 1, KIND_OFFER, b"x");
        assert!(verify_link_state(&p, &st).is_err());
        // Unknown kind, short sig, oversize bodies.
        let st = signed(&k, &p, 1, "weird", b"x");
        assert!(verify_link_state(&p, &st).is_err());
        let mut st = signed(&k, &p, 1, KIND_OFFER, b"x");
        st.sig.pop();
        assert!(verify_link_state(&p, &st).is_err());
        let st = signed(&k, &p, 2, KIND_ACK, &vec![0u8; MAX_LINK_SMALL_BODY + 1]);
        assert!(verify_link_state(&p, &st).is_err());
        let st = signed(&k, &p, 3, KIND_TOMBSTONE, &vec![0u8; MAX_LINK_SMALL_BODY + 1]);
        assert!(verify_link_state(&p, &st).is_err());
        let st = signed(&k, &p, 1, KIND_OFFER, &vec![0u8; MAX_LINK_SEALED + 1]);
        assert!(verify_link_state(&p, &st).is_err());
        let st = signed(&k, &p, 1, KIND_OFFER, &vec![0u8; MAX_LINK_SEALED]);
        verify_link_state(&p, &st).unwrap();
        // Wrong params app.
        let bad_params = LinkDropParams {
            app: "X".into(),
            ed25519_vk: k.verifying_key_bytes().to_vec(),
        }
        .to_cbor();
        let st = signed(&k, &bad_params, 1, KIND_OFFER, b"x");
        assert!(verify_link_state(&bad_params, &st).is_err());
    }

    #[test]
    fn sign_bytes_layout() {
        let m = link_sign_bytes(b"PP", 0x0102, "ack", b"BB");
        let mut e = b"AEGIS_LINK_V1".to_vec();
        e.extend_from_slice(&[0, 0, 0, 2]);
        e.extend_from_slice(b"PP");
        e.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 2]);
        e.push(3);
        e.extend_from_slice(b"ack");
        e.extend_from_slice(b"BB");
        assert_eq!(m, e);
    }

    #[test]
    fn oversize_state_is_rejected_before_parse() {
        assert_eq!(
            LinkDropState::from_cbor(&vec![0u8; MAX_LINK_STATE + 1]).unwrap_err(),
            LinkError::Invalid
        );
    }

    #[test]
    fn merge_is_max_of_total_order() {
        let k = derive_link_keys(&secret(6));
        let p = LinkDropParams::from_keys(&k).to_cbor();
        let offer = signed(&k, &p, 1, KIND_OFFER, b"o");
        let ack = signed(&k, &p, 2, KIND_ACK, b"a");
        let tomb = signed(&k, &p, 3, KIND_TOMBSTONE, b"");
        let tomb_low = signed(&k, &p, 1, KIND_TOMBSTONE, b"");
        assert_eq!(merge_link_states(&offer, &ack), ack);
        assert_eq!(merge_link_states(&ack, &offer), ack);
        assert_eq!(merge_link_states(&ack, &tomb), tomb);
        assert_eq!(merge_link_states(&offer, &offer), offer);
        // Equal seq: tombstone > offer.
        assert_eq!(merge_link_states(&offer, &tomb_low), tomb_low);
        // Higher seq beats a higher kind rank.
        let ack_hi = signed(&k, &p, 5, KIND_ACK, b"a");
        assert_eq!(merge_link_states(&ack_hi, &tomb), ack_hi);
        // Same seq and kind: body decides, in either order.
        let o2 = signed(&k, &p, 1, KIND_OFFER, b"p");
        assert_eq!(merge_link_states(&offer, &o2), merge_link_states(&o2, &offer));
    }

    #[test]
    fn seal_open_round_trip_and_binding() {
        let k = derive_link_keys(&secret(8));
        let p = LinkDropParams::from_keys(&k).to_cbor();
        let sealed = seal_link_payload(&k, &p, b"hello payload", &mut rng_fill).unwrap();
        assert_eq!(sealed.len(), 24 + 13 + 16);
        assert_eq!(open_link_payload(&k, &p, &sealed).unwrap(), b"hello payload");
        // Fresh nonce each time.
        let sealed2 = seal_link_payload(&k, &p, b"hello payload", &mut rng_fill).unwrap();
        assert_ne!(sealed, sealed2);
        // Wrong key, wrong params, tampered, truncated.
        let other = derive_link_keys(&secret(9));
        assert!(open_link_payload(&other, &p, &sealed).is_err());
        assert!(open_link_payload(&k, b"other-params", &sealed).is_err());
        let mut t = sealed.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(open_link_payload(&k, &p, &t).is_err());
        assert!(open_link_payload(&k, &p, &sealed[..30]).is_err());
    }
}
