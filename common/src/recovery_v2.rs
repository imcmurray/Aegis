//! v2 Recovery Kit: identity-preserving wrap of RootSecret.
//!
//! External file: `AEGIS_RECOVERY_V2 || 0x02 || CBOR(RecoveryWrapV2)`.
//! Internal store (`SECRET_RECOVERY_V2`) holds the same CBOR body without magic.
//! RecoverySecret is never written to SecretStore.

use crate::crypto::envelope_v2::{unwrap_root_under_recovery, wrap_root_under_recovery};
use crate::crypto::hkdf_v2::derive_recovery_kek;
use crate::crypto::magic::{decode_recovery_v2, encode_recovery_v2};
use crate::crypto::secret::{RecoverySecret, RootSecret};
use crate::crypto::suite::{CryptoSuiteId, FORMAT_VERSION_V2, KIND_RECOVERY_WRAP};
use crate::crypto::CryptoError;
use crate::vault::VaultError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SECRET_RECOVERY_V2: &[u8] = b"aegis/v2/recovery";

/// Recovery Kit files are tiny (wrapped 32-byte RootSecret). Fail closed above this.
pub const MAX_RECOVERY_KIT_FILE: usize = 64 * 1024;

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DISPLAY_PREFIX: &str = "AEGIS2-";
const V1_DISPLAY_PREFIX: &str = "AEGIS-";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryWrapV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    pub object_kind: u16,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub wrapped_root: Vec<u8>,
}

impl RecoveryWrapV2 {
    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        let w: Self =
            ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))?;
        w.validate_header()?;
        Ok(w)
    }

    fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_core()?;
        if self.object_kind != KIND_RECOVERY_WRAP {
            return Err(CryptoError::UnsupportedObjectKind(self.object_kind));
        }
        if self.vault_id.len() != 16 || self.nonce.len() != 24 {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(())
    }

    /// External Recovery Kit: `AEGIS_RECOVERY_V2 || 0x02 || CBOR`.
    pub fn to_kit_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(encode_recovery_v2(&self.to_cbor()?))
    }

    pub fn from_kit_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_RECOVERY_KIT_FILE {
            return Err(CryptoError::ResourceLimit);
        }
        Self::from_cbor(decode_recovery_v2(bytes)?)
    }

    pub fn vault_id_bytes(&self) -> Result<[u8; 16], VaultError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Msg("invalid recovery wrap".into()))
    }
}

/// One-time display form: Crockford Base32 of the 256-bit secret plus a SHA-256
/// checksum. Entropy is not reduced. Not stored.
pub fn encode_recovery_secret(secret: &RecoverySecret) -> String {
    let payload = encode_crockford(secret.as_bytes());
    let [c0, c1] = checksum_chars(secret.as_bytes());
    let mut body = payload;
    body.push(c0);
    body.push(c1);
    let mut parts = Vec::with_capacity(14);
    for chunk in body.as_bytes().chunks(4) {
        parts.push(std::str::from_utf8(chunk).unwrap_or("").to_string());
    }
    format!("{DISPLAY_PREFIX}{}", parts.join("-"))
}

pub fn decode_recovery_secret(display: &str) -> Result<RecoverySecret, VaultError> {
    let trimmed = display.trim();
    if trimmed.is_empty() {
        return Err(VaultError::Msg("invalid recovery secret".into()));
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with(&V1_DISPLAY_PREFIX.to_ascii_lowercase())
        && !lower.starts_with("aegis2-")
    {
        return Err(VaultError::Msg(
            "v1 recovery keys cannot unlock a v2 vault".into(),
        ));
    }
    let without_prefix = trimmed
        .strip_prefix(DISPLAY_PREFIX)
        .or_else(|| trimmed.strip_prefix("aegis2-"))
        .or_else(|| trimmed.strip_prefix("Aegis2-"))
        .unwrap_or(trimmed);

    let compact: String = without_prefix
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();

    if compact.len() == 64 && compact.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(&compact)
            .map_err(|_| VaultError::Msg("invalid recovery secret".into()))?;
        if bytes.len() != 32 {
            return Err(VaultError::Msg("invalid recovery secret".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(RecoverySecret::from_bytes(arr));
    }

    let mapped: String = compact
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            'U' => 'V',
            other => other,
        })
        .collect();

    if mapped.len() == 32 {
        return Err(VaultError::Msg(
            "v1 recovery keys cannot unlock a v2 vault".into(),
        ));
    }
    if mapped.len() != 54 {
        return Err(VaultError::Msg("invalid recovery secret".into()));
    }
    let (payload, cs) = mapped.split_at(52);
    let secret_bytes = decode_crockford32(payload)?;
    let expect = checksum_chars(&secret_bytes);
    let got: Vec<char> = cs.chars().collect();
    if got.len() != 2 || got[0] != expect[0] || got[1] != expect[1] {
        return Err(VaultError::Msg("invalid recovery secret".into()));
    }
    Ok(RecoverySecret::from_bytes(secret_bytes))
}

pub fn wrap_recovery(
    root: &RootSecret,
    vault_id: [u8; 16],
    key_epoch: u32,
) -> Result<(RecoveryWrapV2, RecoverySecret), VaultError> {
    let recovery = RecoverySecret::random();
    let env = wrap_recovery_with_secret(root, vault_id, key_epoch, &recovery)?;
    Ok((env, recovery))
}

pub fn wrap_recovery_with_secret(
    root: &RootSecret,
    vault_id: [u8; 16],
    key_epoch: u32,
    recovery: &RecoverySecret,
) -> Result<RecoveryWrapV2, VaultError> {
    let kek = derive_recovery_kek(recovery, &vault_id)?;
    let (nonce, wrapped) = wrap_root_under_recovery(&kek, vault_id, key_epoch, root)?;
    Ok(RecoveryWrapV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2Core2026,
        object_kind: KIND_RECOVERY_WRAP,
        vault_id: vault_id.to_vec(),
        key_epoch,
        nonce: nonce.to_vec(),
        wrapped_root: wrapped,
    })
}

/// Candidate-first recovery check: unwrap must yield `expected_root` at `expected_epoch`.
pub fn validate_candidate_recovery(
    wrap: &RecoveryWrapV2,
    recovery: &RecoverySecret,
    expected_root: &RootSecret,
    expected_epoch: u32,
) -> Result<(), VaultError> {
    if wrap.key_epoch != expected_epoch {
        return Err(VaultError::Msg("candidate recovery epoch mismatch".into()));
    }
    let opened = unwrap_recovery(wrap, recovery)?;
    if opened.as_bytes() != expected_root.as_bytes() {
        return Err(VaultError::Msg("candidate recovery reopen failed".into()));
    }
    Ok(())
}

pub fn unwrap_recovery(
    wrap: &RecoveryWrapV2,
    recovery: &RecoverySecret,
) -> Result<RootSecret, VaultError> {
    wrap.validate_header().map_err(VaultError::from)?;
    let vault_id = wrap.vault_id_bytes()?;
    let kek = derive_recovery_kek(recovery, &vault_id)?;
    Ok(unwrap_root_under_recovery(
        &kek,
        vault_id,
        wrap.key_epoch,
        &wrap.nonce,
        &wrap.wrapped_root,
    )?)
}

fn checksum_chars(secret: &[u8; 32]) -> [char; 2] {
    let hash = Sha256::digest(secret);
    let bits = u16::from(hash[0]) << 2 | u16::from(hash[1]) >> 6;
    [
        CROCKFORD[((bits >> 5) & 0x1f) as usize] as char,
        CROCKFORD[(bits & 0x1f) as usize] as char,
    ]
}

fn encode_crockford(data: &[u8]) -> String {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    for &b in data {
        bits = (bits << 8) | u32::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 0x1f) as usize;
            out.push(CROCKFORD[idx] as char);
        }
    }
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 0x1f) as usize;
        out.push(CROCKFORD[idx] as char);
    }
    out
}

fn decode_crockford32(s: &str) -> Result<[u8; 32], VaultError> {
    if s.len() != 52 {
        return Err(VaultError::Msg("invalid recovery secret".into()));
    }
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(32);
    for c in s.chars() {
        let idx = CROCKFORD
            .iter()
            .position(|&b| b == c as u8)
            .ok_or_else(|| VaultError::Msg("invalid recovery secret".into()))?;
        bits = (bits << 5) | idx as u32;
        nbits += 5;
        while nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    if out.len() != 32 {
        return Err(VaultError::Msg("invalid recovery secret".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret::RootSecret;
    use crate::crypto::{MAGIC_BACKUP_V2, MAGIC_RECOVERY_V2, MAGIC_VAULT_V2};

    fn vid() -> [u8; 16] {
        [0x42; 16]
    }

    #[test]
    fn candidate_recovery_accepts_matching_wrap() {
        let root = RootSecret::random();
        let (wrap, secret) = wrap_recovery(&root, vid(), 1).unwrap();
        validate_candidate_recovery(&wrap, &secret, &root, 1).unwrap();
    }

    #[test]
    fn candidate_recovery_rejects_epoch_mismatch() {
        let root = RootSecret::random();
        let (mut wrap, secret) = wrap_recovery(&root, vid(), 1).unwrap();
        wrap.key_epoch = 2;
        let err = validate_candidate_recovery(&wrap, &secret, &root, 1).unwrap_err();
        assert!(err.to_string().contains("epoch mismatch"));
    }

    #[test]
    fn candidate_recovery_rejects_corrupt_wrap() {
        let root = RootSecret::random();
        let (mut wrap, secret) = wrap_recovery(&root, vid(), 1).unwrap();
        wrap.wrapped_root[0] ^= 0xff;
        assert!(validate_candidate_recovery(&wrap, &secret, &root, 1).is_err());
    }

    #[test]
    fn candidate_recovery_rejects_wrong_root() {
        let root = RootSecret::random();
        let other = RootSecret::random();
        let (wrap, secret) = wrap_recovery(&root, vid(), 1).unwrap();
        assert!(validate_candidate_recovery(&wrap, &secret, &other, 1).is_err());
    }

    #[test]
    fn kit_file_is_recovery_magic_then_version_then_cbor() {
        let root = RootSecret::random();
        let (wrap, secret) = wrap_recovery(&root, vid(), 0).unwrap();
        let kit = wrap.to_kit_bytes().unwrap();
        assert!(kit.starts_with(MAGIC_RECOVERY_V2));
        assert_eq!(kit[MAGIC_RECOVERY_V2.len()], 0x02);
        assert!(!kit.starts_with(MAGIC_VAULT_V2));
        assert!(!kit.starts_with(MAGIC_BACKUP_V2));
        assert!(!kit.windows(32).any(|w| w == root.as_bytes().as_slice()));
        assert!(!kit.windows(32).any(|w| w == secret.as_bytes().as_slice()));
        let opened = RecoveryWrapV2::from_kit_bytes(&kit).unwrap();
        assert_eq!(opened.object_kind, KIND_RECOVERY_WRAP);
        assert_eq!(unwrap_recovery(&opened, &secret).unwrap().as_bytes(), root.as_bytes());
    }

    #[test]
    fn display_secret_is_checksummed_and_256_bit() {
        let secret = RecoverySecret::from_bytes([0x11; 32]);
        let display = encode_recovery_secret(&secret);
        assert!(display.starts_with(DISPLAY_PREFIX));
        assert!(!display.starts_with(V1_DISPLAY_PREFIX) || display.starts_with(DISPLAY_PREFIX));
        let back = decode_recovery_secret(&display).unwrap();
        assert_eq!(back.as_bytes(), secret.as_bytes());
        let mut chars: Vec<char> = display.chars().collect();
        let idx = chars.iter().rposition(|c| *c != '-' && *c != '2').unwrap();
        chars[idx] = if chars[idx] == '0' { '1' } else { '0' };
        let flipped: String = chars.into_iter().collect();
        assert!(decode_recovery_secret(&flipped).is_err());
        let hex = hex::encode(secret.as_bytes());
        assert_eq!(
            decode_recovery_secret(&hex).unwrap().as_bytes(),
            secret.as_bytes()
        );
        assert!(decode_recovery_secret("AEGIS-0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ").is_err());
    }

    #[test]
    fn regeneration_uses_a_fresh_nonce() {
        let root = RootSecret::random();
        let rec = RecoverySecret::random();
        let a = wrap_recovery_with_secret(&root, vid(), 0, &rec).unwrap();
        let b = wrap_recovery_with_secret(&root, vid(), 0, &rec).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.wrapped_root, b.wrapped_root);
        assert_eq!(unwrap_recovery(&a, &rec).unwrap().as_bytes(), root.as_bytes());
        assert_eq!(unwrap_recovery(&b, &rec).unwrap().as_bytes(), root.as_bytes());
    }
}
