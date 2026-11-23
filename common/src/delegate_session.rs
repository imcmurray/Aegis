//! Freenet delegate session token (D19).
//!
//! The vault-delegate runs fresh for every request, so an unlocked session
//! would be forgotten at once. While a v2 vault is unlocked the delegate hands
//! the UI an opaque token sealed under a rotating session-wrap key K_s (kept in
//! the delegate secret store). The UI sends it back with each request and the
//! delegate rebuilds the session from it without Argon2.
//!
//! Everything here is a pure function over `(store, now, origin, rng)`.

use crate::crypto::secret::RootSecret;
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::session_v2::VaultSessionV2;
use crate::upgrade::{
    export_upgrade_snapshot, import_upgrade_snapshot, ERR_COMMIT_PREFIX, ERR_INVALID,
    ERR_TOO_LARGE,
};
use crate::vault::{
    detect_persisted_format, dispatch, ActiveSession, PersistedFormat, SecretStore, VaultError,
    SECRET_SESSION,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret-store key for K_s. CBOR value: SessionKeyRecord.
pub const SECRET_DELEGATE_SESSION_KEY: &[u8] = b"aegis.v2.delegate_session_key";
pub const TOKEN_VERSION: u8 = 0x01;
pub const TOKEN_AAD_LABEL: &[u8] = b"aegis/v2/delegate-session-token/v1";
pub const IPC_VERSION: u32 = 1;
pub const SESSION_IDLE_SECS: u64 = 15 * 60;
pub const SESSION_ABSOLUTE_SECS: u64 = 12 * 60 * 60;
/// Upper bound on accepted token length (checked before any parsing).
pub const MAX_TOKEN_LEN: usize = 512;

const KID_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MIN_TOKEN_LEN: usize = 1 + KID_LEN + NONCE_LEN + TAG_LEN;

/// Who sent the request, as seen by the delegate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOrigin {
    /// MessageOrigin::WebApp(ContractInstanceId) — the 32 id bytes.
    WebApp([u8; 32]),
    /// origin None, or any other / unknown origin.
    Other,
}

impl SessionOrigin {
    /// WebApp(id) -> id (32 bytes); Other -> [0x00] (1 byte).
    pub fn aad_bytes(&self) -> Vec<u8> {
        match self {
            SessionOrigin::WebApp(id) => id.to_vec(),
            SessionOrigin::Other => vec![0x00],
        }
    }
}

/// Random source: fills the slice with CSPRNG bytes.
pub type RngFn<'a> = &'a mut dyn FnMut(&mut [u8]);

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct SessionKeyRecord {
    #[serde(with = "serde_bytes")]
    kid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct TokenClaims {
    #[serde(with = "serde_bytes")]
    root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    vault_id: Vec<u8>,
    key_epoch: u32,
    issued_at: u64,
    expires_at: u64,
}

/// Non-secret view of a token, for tests/diagnostics. Never contains root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub kid: [u8; 16],
    pub vault_id: [u8; 16],
    pub key_epoch: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}

fn load_session_key(store: &dyn SecretStore) -> Option<SessionKeyRecord> {
    let mut bytes = store.get(SECRET_DELEGATE_SESSION_KEY)?;
    let rec: Result<SessionKeyRecord, _> = ciborium::from_reader(bytes.as_slice());
    bytes.zeroize();
    let rec = rec.ok()?;
    if rec.kid.len() != KID_LEN || rec.key.len() != KEY_LEN {
        return None;
    }
    Some(rec)
}

fn token_aad(kid: &[u8], origin: &SessionOrigin) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TOKEN_AAD_LABEL.len() + kid.len() + 32);
    aad.extend_from_slice(TOKEN_AAD_LABEL);
    aad.extend_from_slice(kid);
    aad.extend_from_slice(&origin.aad_bytes());
    aad
}

/// Overwrite K_s with fresh random kid (16) + key (32) via store.set.
pub fn rotate_session_key(store: &mut dyn SecretStore, rng: RngFn<'_>) {
    let mut rec = SessionKeyRecord {
        kid: vec![0u8; KID_LEN],
        key: vec![0u8; KEY_LEN],
    };
    rng(&mut rec.kid);
    rng(&mut rec.key);
    let mut buf = Vec::new();
    if ciborium::into_writer(&rec, &mut buf).is_ok() {
        store.set(SECRET_DELEGATE_SESSION_KEY, &buf);
    }
    buf.zeroize();
}

/// Seal a token for `session` under the current K_s. None if K_s is
/// missing or malformed, or now == 0. expires_at = now + SESSION_IDLE_SECS.
/// Reads the store only; never writes.
pub fn issue_token(
    store: &dyn SecretStore,
    session: &VaultSessionV2,
    issued_at: u64,
    now: u64,
    origin: &SessionOrigin,
    rng: RngFn<'_>,
) -> Option<Vec<u8>> {
    if now == 0 {
        return None;
    }
    let ks = load_session_key(store)?;
    let claims = TokenClaims {
        root: session.root_secret().as_bytes().to_vec(),
        vault_id: session.vault_id().to_vec(),
        key_epoch: session.key_epoch(),
        issued_at,
        expires_at: now.saturating_add(SESSION_IDLE_SECS),
    };
    let mut pt = Vec::new();
    ciborium::into_writer(&claims, &mut pt).ok()?;
    let mut nonce = [0u8; NONCE_LEN];
    rng(&mut nonce);
    let aad = token_aad(&ks.kid, origin);
    let cipher = XChaCha20Poly1305::new_from_slice(&ks.key).ok();
    let ct = cipher.and_then(|c| {
        c.encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: &aad,
            },
        )
        .ok()
    });
    pt.zeroize();
    let ct = ct?;
    let mut out = Vec::with_capacity(1 + KID_LEN + NONCE_LEN + ct.len());
    out.push(TOKEN_VERSION);
    out.extend_from_slice(&ks.kid);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Version, kid, AEAD (with origin AAD) and strict claims decode. No time checks.
fn open_token(
    store: &dyn SecretStore,
    token: &[u8],
    origin: &SessionOrigin,
) -> Option<([u8; 16], TokenClaims)> {
    if token.len() < MIN_TOKEN_LEN || token.len() > MAX_TOKEN_LEN {
        return None;
    }
    if token[0] != TOKEN_VERSION {
        return None;
    }
    let ks = load_session_key(store)?;
    let kid = &token[1..1 + KID_LEN];
    if !bool::from(kid.ct_eq(ks.kid.as_slice())) {
        return None;
    }
    let nonce = &token[1 + KID_LEN..1 + KID_LEN + NONCE_LEN];
    let ct = &token[1 + KID_LEN + NONCE_LEN..];
    let aad = token_aad(kid, origin);
    let cipher = XChaCha20Poly1305::new_from_slice(&ks.key).ok()?;
    let mut pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &aad,
            },
        )
        .ok()?;
    let claims: Result<TokenClaims, _> = ciborium::from_reader(pt.as_slice());
    pt.zeroize();
    let claims = claims.ok()?;
    if claims.root.len() != 32 || claims.vault_id.len() != 16 {
        return None;
    }
    let mut kid_arr = [0u8; 16];
    kid_arr.copy_from_slice(kid);
    Some((kid_arr, claims))
}

/// Validate a token and rebuild the session (no Argon2, no audit push, no
/// store writes). Returns (session, issued_at). Any failure -> None.
pub fn resume_from_token(
    store: &dyn SecretStore,
    token: &[u8],
    now: u64,
    origin: &SessionOrigin,
) -> Option<(VaultSessionV2, u64)> {
    if now == 0 {
        return None;
    }
    let (_, claims) = open_token(store, token, origin)?;
    if now > claims.expires_at || now > claims.issued_at.saturating_add(SESSION_ABSOLUTE_SECS) {
        return None;
    }
    if !matches!(detect_persisted_format(store), Ok(PersistedFormat::V2)) {
        return None;
    }
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&claims.root);
    let root = RootSecret::from_bytes(root_arr);
    root_arr.zeroize();
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&claims.vault_id);
    let session = VaultSessionV2::resume_from_root(store, root, vault_id, claims.key_epoch).ok()?;
    Some((session, claims.issued_at))
}

/// Decrypt + decode only (version, kid, AEAD, origin), with no time or
/// envelope checks. Test/diagnostic helper; returns no secret.
pub fn inspect_token(
    store: &dyn SecretStore,
    token: &[u8],
    origin: &SessionOrigin,
) -> Option<TokenInfo> {
    let (kid, claims) = open_token(store, token, origin)?;
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&claims.vault_id);
    Some(TokenInfo {
        kid,
        vault_id,
        key_epoch: claims.key_epoch,
        issued_at: claims.issued_at,
        expires_at: claims.expires_at,
    })
}

/// IPC envelope (local UI<->delegate only). Field order v, token, req.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcRequest {
    pub v: u32,
    #[serde(default, with = "serde_bytes")]
    pub token: Option<Vec<u8>>,
    pub req: VaultRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcResponse {
    pub v: u32,
    #[serde(default, with = "serde_bytes")]
    pub token: Option<Vec<u8>>,
    pub resp: VaultResponse,
}

fn encode_err<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|_| "response encoding failed".to_string())?;
    Ok(out)
}

fn cleanup_v1_session_key(store: &mut dyn SecretStore, session: &Option<ActiveSession>) {
    if store.has(SECRET_SESSION) && !matches!(session, Some(ActiveSession::V1(_))) {
        store.remove(SECRET_SESSION);
    }
}

/// D20 export: only with a session resumed from a token, for a WebApp origin.
/// Every refusal looks the same.
fn handle_export_for_upgrade(
    store: &dyn SecretStore,
    session: &Option<ActiveSession>,
    resumed: bool,
    origin: &SessionOrigin,
) -> VaultResponse {
    let refuse = || VaultResponse::err(ErrorCode::Locked, "vault is locked");
    if !resumed || !matches!(origin, SessionOrigin::WebApp(_)) {
        return refuse();
    }
    let Some(ActiveSession::V2(s)) = session else {
        return refuse();
    };
    match export_upgrade_snapshot(store, s) {
        Ok(snapshot) => VaultResponse::UpgradeSnapshot { snapshot },
        Err(VaultError::Msg(m)) if m == ERR_TOO_LARGE => {
            VaultResponse::err(ErrorCode::InvalidRequest, ERR_TOO_LARGE)
        }
        Err(_) => refuse(),
    }
}

/// D20 import: only for a WebApp origin into a store with no vault at all.
fn handle_import_upgrade_snapshot(
    store: &mut dyn SecretStore,
    origin: &SessionOrigin,
    snapshot: &[u8],
) -> VaultResponse {
    let refuse = || VaultResponse::err(ErrorCode::InvalidRequest, "upgrade import not permitted");
    if !matches!(origin, SessionOrigin::WebApp(_)) {
        return refuse();
    }
    if !matches!(detect_persisted_format(&*store), Ok(PersistedFormat::None)) {
        return refuse();
    }
    match import_upgrade_snapshot(store, snapshot) {
        Ok(()) => VaultResponse::Ok,
        Err(VaultError::Msg(m)) if m.starts_with(ERR_COMMIT_PREFIX) => {
            VaultResponse::err(ErrorCode::Storage, m)
        }
        Err(_) => VaultResponse::err(ErrorCode::InvalidRequest, ERR_INVALID),
    }
}

/// Entry point used by the delegate. Accepts either an IpcRequest envelope or
/// a bare VaultRequest (legacy). Returns the CBOR bytes to send back.
/// Err only when the payload is not decodable CBOR of either shape.
pub fn process_message(
    store: &mut dyn SecretStore,
    payload: &[u8],
    now: u64,
    origin: &SessionOrigin,
    rng: RngFn<'_>,
) -> Result<Vec<u8>, String> {
    let value: ciborium::Value =
        ciborium::from_reader(payload).map_err(|_| "invalid request encoding".to_string())?;

    let version = match &value {
        ciborium::Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            ciborium::Value::Text(t) if t == "v" => Some(v.clone()),
            _ => None,
        }),
        _ => None,
    };
    drop(value);

    let Some(version) = version else {
        // Legacy bare VaultRequest: identical to the pre-token behaviour.
        let req =
            VaultRequest::from_cbor(payload).map_err(|_| "invalid request encoding".to_string())?;
        let mut session = None;
        let resp = dispatch(store, &mut session, req);
        cleanup_v1_session_key(store, &session);
        return resp.to_cbor();
    };

    let is_v1 = matches!(&version, ciborium::Value::Integer(i) if i128::from(*i) == IPC_VERSION as i128);
    if !is_v1 {
        return encode_err(&IpcResponse {
            v: IPC_VERSION,
            token: None,
            resp: VaultResponse::err(ErrorCode::InvalidRequest, "unsupported request envelope"),
        });
    }

    let env: IpcRequest =
        ciborium::from_reader(payload).map_err(|_| "invalid request envelope".to_string())?;
    let IpcRequest { token, req, .. } = env;

    let (mut session, mut issued_at) = match token
        .as_deref()
        .and_then(|t| resume_from_token(&*store, t, now, origin))
    {
        Some((s, issued)) => (Some(ActiveSession::V2(s)), issued),
        None => (None, 0),
    };
    let started_some = session.is_some();

    let is_lock = matches!(req, VaultRequest::Lock);
    let establishing = matches!(
        req,
        VaultRequest::CreateVault { .. }
            | VaultRequest::Unlock { .. }
            | VaultRequest::UnlockWithRecovery { .. }
            | VaultRequest::ImportEncrypted { .. }
            | VaultRequest::ImportRecoveryKit { .. }
            | VaultRequest::MigrateVault { .. }
            | VaultRequest::MigrateVaultWithRecovery { .. }
    );

    let resp = match req {
        VaultRequest::ExportForUpgrade {} => {
            handle_export_for_upgrade(&*store, &session, started_some, origin)
        }
        VaultRequest::ImportUpgradeSnapshot { snapshot } => {
            handle_import_upgrade_snapshot(store, origin, &snapshot)
        }
        req => dispatch(store, &mut session, req),
    };
    cleanup_v1_session_key(store, &session);

    let established = establishing
        && !matches!(resp, VaultResponse::Error { .. })
        && matches!(session, Some(ActiveSession::V2(_)));
    let ended = started_some && session.is_none();

    if established || ended || is_lock {
        rotate_session_key(store, &mut *rng);
    }
    if established {
        issued_at = now;
    }

    let new_token = match &session {
        Some(ActiveSession::V2(s)) => issue_token(&*store, s, issued_at, now, origin, &mut *rng),
        _ => None,
    };

    encode_err(&IpcResponse {
        v: IPC_VERSION,
        token: new_token,
        resp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_envelope_encodings() {
        let req = IpcRequest {
            v: 1,
            token: None,
            req: VaultRequest::Status,
        };
        let mut out = Vec::new();
        ciborium::into_writer(&req, &mut out).unwrap();
        assert_eq!(
            hex::encode(&out),
            "a361760165746f6b656ef663726571a1626f7066737461747573"
        );
        let back: IpcRequest = ciborium::from_reader(out.as_slice()).unwrap();
        assert_eq!(back, req);

        let resp = IpcResponse {
            v: 1,
            token: None,
            resp: VaultResponse::Locked,
        };
        let mut out = Vec::new();
        ciborium::into_writer(&resp, &mut out).unwrap();
        assert_eq!(
            hex::encode(&out),
            "a361760165746f6b656ef66472657370a16474797065666c6f636b6564"
        );
    }
}
