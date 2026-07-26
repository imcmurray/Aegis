//! Core cryptography for Aegis vaults.
//!
//! Algorithms: Argon2id, XChaCha20-Poly1305, HKDF-SHA256, Ed25519 (via derived seed).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const AEGIS_DOMAIN: &[u8] = b"aegis/v1";
pub const ENVELOPE_VERSION: u16 = 1;
const MASTER_SECRET_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong key or corrupt data)")]
    Decrypt,
    #[error("kdf failed: {0}")]
    Kdf(String),
    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u16),
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("invalid key length")]
    KeyLength,
    #[error("serialization error: {0}")]
    Serde(String),
}

/// Argon2id memory/time profiles.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum KdfProfile {
    /// 64 MiB, t=3 — default desktop.
    #[default]
    Interactive,
    /// 32 MiB, t=2 — constrained devices.
    Mobile,
    /// 128 MiB, t=4, p=2 — high security.
    High,
    /// Tiny params for unit tests only — not production safe.
    Test,
}

impl KdfProfile {
    pub fn params(self) -> Result<Params, CryptoError> {
        let (m_kib, t, p) = match self {
            KdfProfile::Interactive => (64 * 1024, 3u32, 1u32),
            KdfProfile::Mobile => (32 * 1024, 2, 1),
            KdfProfile::High => (128 * 1024, 4, 2),
            KdfProfile::Test => (8, 1, 1),
        };
        Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|e| CryptoError::Kdf(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub profile: KdfProfile,
    /// 16-byte salt (serde as bytes).
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
}

impl KdfParams {
    pub fn generate(profile: KdfProfile) -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        crate::rng::fill_random(&mut salt);
        Self { profile, salt }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    MasterWrap,
    VaultBlob,
    ExportBlob,
    SyncPayload,
    AuditBlob,
}

impl EnvelopeKind {
    fn aad_tag(self) -> u8 {
        match self {
            EnvelopeKind::MasterWrap => 1,
            EnvelopeKind::VaultBlob => 2,
            EnvelopeKind::ExportBlob => 3,
            EnvelopeKind::SyncPayload => 4,
            EnvelopeKind::AuditBlob => 5,
        }
    }
}

/// Versioned AEAD blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedBlob {
    pub version: u16,
    pub kind: EnvelopeKind,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl SealedBlob {
    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))
    }
}

/// Stored alongside the vault: wraps MasterSecret under KEK derived from passphrase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasterEnvelope {
    pub kdf: KdfParams,
    pub sealed: SealedBlob,
    pub vault_id: String,
    pub created_at: u64,
}

impl MasterEnvelope {
    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))
    }
}

/// 32-byte secret key material, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; KEY_LEN]);

impl SecretKey {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        crate::rng::fill_random(&mut k);
        Self(k)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// Keys derived from MasterSecret via HKDF.
#[derive(Clone, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub vault_dek: SecretKey,
    pub sync_sign_seed: SecretKey,
    pub sync_addr: SecretKey,
    pub search_hmac: SecretKey,
    pub share_ecdh_seed: SecretKey,
}

impl DerivedKeys {
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.sync_sign_seed.as_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKeys([REDACTED])")
    }
}

fn build_aad(kind: EnvelopeKind, vault_id: &[u8], logical_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AEGIS_DOMAIN.len() + 1 + vault_id.len() + logical_id.len());
    aad.extend_from_slice(AEGIS_DOMAIN);
    aad.push(kind.aad_tag());
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(logical_id);
    aad
}

fn argon2_kek(passphrase: &str, kdf: &KdfParams) -> Result<SecretKey, CryptoError> {
    let params = kdf.profile.params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Use raw hash API for fixed 32-byte output (not PHC string).
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), &kdf.salt, &mut out)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(SecretKey(out))
}

/// Seal plaintext under a 32-byte key.
pub fn seal(
    key: &SecretKey,
    kind: EnvelopeKind,
    vault_id: &[u8],
    logical_id: &[u8],
    plaintext: &[u8],
) -> Result<SealedBlob, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::KeyLength)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    crate::rng::fill_random(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = build_aad(kind, vault_id, logical_id);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(SealedBlob {
        version: ENVELOPE_VERSION,
        kind,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Open a sealed blob.
pub fn open(
    key: &SecretKey,
    vault_id: &[u8],
    logical_id: &[u8],
    blob: &SealedBlob,
) -> Result<Vec<u8>, CryptoError> {
    if blob.version != ENVELOPE_VERSION {
        return Err(CryptoError::UnsupportedVersion(blob.version));
    }
    if blob.nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::KeyLength)?;
    let nonce = XNonce::from_slice(&blob.nonce);
    let aad = build_aad(blob.kind, vault_id, logical_id);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

/// Create a new MasterSecret wrapped under the passphrase.
pub fn wrap_master(
    passphrase: &str,
    profile: KdfProfile,
    vault_id: &str,
) -> Result<(MasterEnvelope, SecretKey), CryptoError> {
    let master = SecretKey::random();
    let env = wrap_existing_master(passphrase, profile, vault_id, &master)?;
    Ok((env, master))
}

/// Wrap an existing MasterSecret under a passphrase (export / re-key / recovery).
pub fn wrap_existing_master(
    passphrase: &str,
    profile: KdfProfile,
    vault_id: &str,
    master: &SecretKey,
) -> Result<MasterEnvelope, CryptoError> {
    wrap_existing_master_with_aad(passphrase, profile, vault_id, master, b"master")
}

/// Like [`wrap_existing_master`] but with a custom AAD logical id (e.g. recovery).
pub fn wrap_existing_master_with_aad(
    passphrase: &str,
    profile: KdfProfile,
    vault_id: &str,
    master: &SecretKey,
    logical_id: &[u8],
) -> Result<MasterEnvelope, CryptoError> {
    let kdf = KdfParams::generate(profile);
    let kek = argon2_kek(passphrase, &kdf)?;
    let sealed = seal(
        &kek,
        EnvelopeKind::MasterWrap,
        vault_id.as_bytes(),
        logical_id,
        master.as_bytes(),
    )?;
    Ok(MasterEnvelope {
        kdf,
        sealed,
        vault_id: vault_id.to_string(),
        created_at: crate::types::unix_now(),
    })
}

/// Unwrap MasterSecret from envelope + passphrase with custom AAD logical id.
pub fn unwrap_master_with_aad(
    passphrase: &str,
    env: &MasterEnvelope,
    logical_id: &[u8],
) -> Result<SecretKey, CryptoError> {
    let kek = argon2_kek(passphrase, &env.kdf)?;
    let bytes = open(
        &kek,
        env.vault_id.as_bytes(),
        logical_id,
        &env.sealed,
    )?;
    if bytes.len() != MASTER_SECRET_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }
    let mut arr = [0u8; MASTER_SECRET_LEN];
    arr.copy_from_slice(&bytes);
    Ok(SecretKey(arr))
}

/// Generate a high-entropy recovery key string (160 bits, Crockford Base32 groups).
///
/// Format: `AEGIS-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (32 chars of payload).
pub fn generate_recovery_key_display() -> String {
    let mut raw = [0u8; 20];
    crate::rng::fill_random(&mut raw);
    let b32 = encode_crockford_base32(&raw);
    // 32 chars → 8 groups of 4
    let mut parts = Vec::with_capacity(8);
    for chunk in b32.as_bytes().chunks(4) {
        parts.push(std::str::from_utf8(chunk).unwrap_or("").to_string());
    }
    format!("AEGIS-{}", parts.join("-"))
}

/// Normalize user-entered recovery key for KDF input (strip spaces/dashes, upper).
pub fn normalize_recovery_key(input: &str) -> String {
    // Strip product prefix before Crockford remapping (I→1 would break "AEGIS").
    let trimmed = input.trim();
    let without_prefix = trimmed
        .strip_prefix("AEGIS-")
        .or_else(|| trimmed.strip_prefix("aegis-"))
        .or_else(|| trimmed.strip_prefix("AEGIS"))
        .or_else(|| trimmed.strip_prefix("aegis"))
        .unwrap_or(trimmed);

    without_prefix
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        // Crockford: map ambiguous chars
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            'U' => 'V',
            other => other,
        })
        .collect()
}

fn encode_crockford_base32(data: &[u8]) -> String {
    const ALPH: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    for &b in data {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 0x1f) as usize;
            out.push(ALPH[idx] as char);
        }
    }
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 0x1f) as usize;
        out.push(ALPH[idx] as char);
    }
    out
}

/// Unwrap MasterSecret from envelope + passphrase.
pub fn unwrap_master(passphrase: &str, env: &MasterEnvelope) -> Result<SecretKey, CryptoError> {
    unwrap_master_with_aad(passphrase, env, b"master")
}

/// Derive purpose-separated keys from MasterSecret.
pub fn derive_keys(master: &SecretKey) -> Result<DerivedKeys, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(AEGIS_DOMAIN), master.as_bytes());

    fn expand(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<SecretKey, CryptoError> {
        let mut out = [0u8; KEY_LEN];
        hk.expand(info, &mut out).map_err(|_| CryptoError::Hkdf)?;
        Ok(SecretKey(out))
    }

    Ok(DerivedKeys {
        vault_dek: expand(&hk, b"aegis/v1/vault-dek")?,
        sync_sign_seed: expand(&hk, b"aegis/v1/sync-sign")?,
        sync_addr: expand(&hk, b"aegis/v1/sync-addr")?,
        search_hmac: expand(&hk, b"aegis/v1/search-hmac")?,
        share_ecdh_seed: expand(&hk, b"aegis/v1/share-ecdh")?,
    })
}

/// Password generator policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratorPolicy {
    pub length: u32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// If true, generate a memorable passphrase (word-like chunks).
    pub memorable: bool,
    pub word_count: u32,
}

impl Default for GeneratorPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            memorable: false,
            word_count: 5,
        }
    }
}

const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I/O
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz"; // no l
const DIGITS: &[u8] = b"23456789"; // no 0/1
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}?,.";

const WORDS: &[&str] = &[
    "alpha", "bravo", "coral", "delta", "ember", "flint", "grove", "harbor", "ivory", "jade",
    "kite", "lunar", "maple", "nova", "orbit", "prism", "quartz", "ridge", "solar", "tide",
    "umbra", "vapor", "willow", "xenon", "yellow", "zephyr", "anchor", "beacon", "cinder",
    "drift", "echo", "frost", "glimmer", "haven", "indigo", "jasper",
];

/// Generate a password or memorable passphrase. Uses OsRng.
pub fn generate_password(policy: &GeneratorPolicy) -> Result<String, CryptoError> {
    if policy.memorable {
        return Ok(generate_memorable(policy.word_count.max(3)));
    }

    let mut charset = Vec::new();
    if policy.uppercase {
        charset.extend_from_slice(UPPER);
    }
    if policy.lowercase {
        charset.extend_from_slice(LOWER);
    }
    if policy.digits {
        charset.extend_from_slice(DIGITS);
    }
    if policy.symbols {
        charset.extend_from_slice(SYMBOLS);
    }
    if charset.is_empty() {
        charset.extend_from_slice(LOWER);
    }

    let len = policy.length.clamp(8, 128) as usize;
    let mut out = Vec::with_capacity(len);

    // Guarantee at least one from each selected set.
    let mut required = Vec::new();
    if policy.uppercase {
        required.push(pick(UPPER));
    }
    if policy.lowercase {
        required.push(pick(LOWER));
    }
    if policy.digits {
        required.push(pick(DIGITS));
    }
    if policy.symbols {
        required.push(pick(SYMBOLS));
    }
    for b in required.into_iter().take(len) {
        out.push(b);
    }
    while out.len() < len {
        out.push(pick(&charset));
    }
    // Fisher–Yates shuffle
    for i in (1..out.len()).rev() {
        let j = (random_u32() as usize) % (i + 1);
        out.swap(i, j);
    }
    Ok(String::from_utf8(out).expect("charset is ascii"))
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    crate::rng::fill_random(&mut b);
    u32::from_le_bytes(b)
}

fn pick(set: &[u8]) -> u8 {
    set[(random_u32() as usize) % set.len()]
}

fn generate_memorable(word_count: u32) -> String {
    let n = word_count.clamp(3, 12) as usize;
    let mut parts = Vec::with_capacity(n);
    for _ in 0..n {
        let w = WORDS[(random_u32() as usize) % WORDS.len()];
        let digit = (random_u32() % 10) as u8;
        parts.push(format!("{w}{digit}"));
    }
    parts.join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = SecretKey::random();
        let pt = b"hello vault secret";
        let blob = seal(&key, EnvelopeKind::VaultBlob, b"vid", b"entry1", pt).unwrap();
        let out = open(&key, b"vid", b"entry1", &blob).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = SecretKey::random();
        let blob = seal(&key, EnvelopeKind::VaultBlob, b"vid", b"a", b"data").unwrap();
        assert!(open(&key, b"vid", b"b", &blob).is_err());
    }

    #[test]
    fn master_wrap_unwrap() {
        let (env, master) = wrap_master("correct horse battery staple", KdfProfile::Test, "vault01")
            .unwrap();
        let opened = unwrap_master("correct horse battery staple", &env).unwrap();
        assert_eq!(master.as_bytes(), opened.as_bytes());
        assert!(unwrap_master("wrong passphrase", &env).is_err());
    }

    #[test]
    fn derive_keys_deterministic() {
        let master = SecretKey([7u8; 32]);
        let a = derive_keys(&master).unwrap();
        let b = derive_keys(&master).unwrap();
        assert_eq!(a.vault_dek.as_bytes(), b.vault_dek.as_bytes());
        assert_eq!(a.sync_sign_seed.as_bytes(), b.sync_sign_seed.as_bytes());
        // Purpose separation
        assert_ne!(a.vault_dek.as_bytes(), a.sync_sign_seed.as_bytes());
    }

    #[test]
    fn generator_length_and_charset() {
        let p = GeneratorPolicy {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: false,
            memorable: false,
            word_count: 5,
        };
        let pw = generate_password(&p).unwrap();
        assert_eq!(pw.len(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn memorable_has_hyphens() {
        let p = GeneratorPolicy {
            memorable: true,
            word_count: 4,
            ..Default::default()
        };
        let pw = generate_password(&p).unwrap();
        assert_eq!(pw.matches('-').count(), 3);
    }

    #[test]
    fn envelope_cbor_roundtrip() {
        let (env, _) = wrap_master("pw", KdfProfile::Test, "v").unwrap();
        let bytes = env.to_cbor().unwrap();
        let back = MasterEnvelope::from_cbor(&bytes).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn recovery_key_format_and_normalize() {
        let k = generate_recovery_key_display();
        assert!(k.starts_with("AEGIS-"));
        let n = normalize_recovery_key(&k);
        assert_eq!(n.len(), 32);
        // spaces/dashes ignored
        assert_eq!(
            normalize_recovery_key(&k.to_lowercase().replace('-', " ")),
            n
        );
    }

    #[test]
    fn recovery_wrap_unwrap() {
        let master = SecretKey::random();
        let display = generate_recovery_key_display();
        let norm = normalize_recovery_key(&display);
        let env = wrap_existing_master_with_aad(
            &norm,
            KdfProfile::Test,
            "vid",
            &master,
            b"recovery",
        )
        .unwrap();
        let opened = unwrap_master_with_aad(&norm, &env, b"recovery").unwrap();
        assert_eq!(opened.as_bytes(), master.as_bytes());
        assert!(unwrap_master_with_aad("wrong", &env, b"recovery").is_err());
    }
}
