//! MasterEnvelopeV2 and VaultBlobV2. Storage suite is AegisV2Core2026 only (D11).

use super::aead;
use super::kdf::{derive_kek, Argon2ParamsV2, KdfContext};
use super::passphrase::validate_v2_passphrase;
use super::magic::{decode_vault_v2, encode_vault_v2, CONTAINER_VERSION_V2, MAGIC_VAULT_V2};
use super::secret::{AuditDek, RecoveryKek, RootSecret, SyncDek, VaultDek};
use super::suite::{CryptoSuiteId, FORMAT_VERSION_V2, KEY_EPOCH_INITIAL};
use super::transcript::{
    build_audit_blob_transcript, build_master_wrap_transcript, build_recovery_wrap_transcript,
    build_sync_blob_transcript, build_vault_blob_transcript,
};
use super::v1::CryptoError;
use serde::{Deserialize, Serialize};

const LOGICAL_MASTER: &[u8] = b"master";

/// External vault/master/audit/sync blob cap (D12). Same order as backup files.
pub const MAX_VAULT_FILE: usize = 16 * 1024 * 1024;
pub const MAX_BLOB_CIPHERTEXT: usize = 8 * 1024 * 1024;

fn reject_oversized(bytes: &[u8]) -> Result<(), CryptoError> {
    if bytes.len() > MAX_VAULT_FILE {
        return Err(CryptoError::ResourceLimit);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MasterEnvelopeV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub kdf: Argon2ParamsV2,
    pub key_epoch: u32,
    #[serde(with = "serde_bytes")]
    pub wrap_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub wrapped_root_secret: Vec<u8>,
    pub created_at: u64,
}

impl MasterEnvelopeV2 {
    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        let env: Self =
            ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))?;
        env.validate_header()?;
        Ok(env)
    }

    /// D10 wire form: `AEGIS_VAULT_V2 || 0x02 || CBOR`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(encode_vault_v2(&self.to_cbor()?))
    }

    /// External v2 decoder. Rejects missing/wrong magic before CBOR parse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        reject_oversized(bytes)?;
        Self::from_cbor(decode_vault_v2(bytes)?)
    }

    fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_core()?;
        if self.vault_id.len() != 16 {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.wrap_nonce.len() != aead::NONCE_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.wrapped_root_secret.len() > MAX_BLOB_CIPHERTEXT {
            return Err(CryptoError::ResourceLimit);
        }
        Ok(())
    }

    pub fn vault_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultBlobV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl VaultBlobV2 {
    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        let blob: Self =
            ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))?;
        blob.validate_header()?;
        Ok(blob)
    }

    /// D10 wire form: `AEGIS_VAULT_V2 || 0x02 || CBOR`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(encode_vault_v2(&self.to_cbor()?))
    }

    /// External v2 decoder. Rejects missing/wrong magic before CBOR parse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        reject_oversized(bytes)?;
        Self::from_cbor(decode_vault_v2(bytes)?)
    }

    fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_core()?;
        if self.vault_id.len() != 16 || self.nonce.len() != aead::NONCE_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.ciphertext.len() > MAX_BLOB_CIPHERTEXT {
            return Err(CryptoError::ResourceLimit);
        }
        Ok(())
    }

    pub fn vault_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }
}

/// Create a new RootSecret wrapped under the passphrase (production 64 MiB Argon2).
pub fn wrap_root_v2(
    passphrase: &str,
    vault_id: [u8; 16],
) -> Result<(MasterEnvelopeV2, RootSecret), CryptoError> {
    let kdf = Argon2ParamsV2::for_generate();
    #[cfg(any(test, feature = "insecure-kdf"))]
    {
        if matches!(kdf.generate_context(), crate::crypto::KdfContext::V2UnitTest) {
            let root = RootSecret::random();
            let env = wrap_existing_root_v2_unit_test(
                passphrase,
                vault_id,
                KEY_EPOCH_INITIAL,
                &kdf,
                &root,
            )?;
            return Ok((env, root));
        }
    }
    wrap_root_v2_with_params(passphrase, vault_id, kdf)
}

pub fn wrap_root_v2_with_params(
    passphrase: &str,
    vault_id: [u8; 16],
    kdf: Argon2ParamsV2,
) -> Result<(MasterEnvelopeV2, RootSecret), CryptoError> {
    kdf.validate(KdfContext::V2Generate)?;
    let root = RootSecret::random();
    let env = wrap_existing_root_v2(passphrase, vault_id, KEY_EPOCH_INITIAL, &kdf, &root)?;
    Ok((env, root))
}

pub fn wrap_existing_root_v2(
    passphrase: &str,
    vault_id: [u8; 16],
    key_epoch: u32,
    kdf: &Argon2ParamsV2,
    root: &RootSecret,
) -> Result<MasterEnvelopeV2, CryptoError> {
    wrap_existing_root_inner(
        passphrase,
        vault_id,
        key_epoch,
        kdf,
        root,
        true,
        KdfContext::V2Generate,
    )
}

/// Live v1→v2 migration: wrap a fresh RootSecret under the *existing* passphrase
/// without re-applying D18. Unlock of historical vaults is not a create path.
pub fn wrap_existing_root_v2_legacy_passphrase(
    passphrase: &str,
    vault_id: [u8; 16],
    key_epoch: u32,
    kdf: &Argon2ParamsV2,
    root: &RootSecret,
) -> Result<MasterEnvelopeV2, CryptoError> {
    wrap_existing_root_inner(
        passphrase,
        vault_id,
        key_epoch,
        kdf,
        root,
        false,
        KdfContext::V2Generate,
    )
}

#[cfg(any(test, feature = "insecure-kdf"))]
pub(crate) fn wrap_existing_root_v2_unit_test(
    passphrase: &str,
    vault_id: [u8; 16],
    key_epoch: u32,
    kdf: &Argon2ParamsV2,
    root: &RootSecret,
) -> Result<MasterEnvelopeV2, CryptoError> {
    wrap_existing_root_inner(
        passphrase,
        vault_id,
        key_epoch,
        kdf,
        root,
        true,
        KdfContext::V2UnitTest,
    )
}

fn wrap_existing_root_inner(
    passphrase: &str,
    vault_id: [u8; 16],
    key_epoch: u32,
    kdf: &Argon2ParamsV2,
    root: &RootSecret,
    enforce_d18: bool,
    ctx: KdfContext,
) -> Result<MasterEnvelopeV2, CryptoError> {
    if enforce_d18 {
        validate_v2_passphrase(passphrase)?;
    }
    kdf.validate(ctx)?;
    let kek = derive_kek(passphrase, kdf, ctx)?;
    let aad = build_master_wrap_transcript(&vault_id, key_epoch, LOGICAL_MASTER);
    let (nonce, wrapped) = aead::seal(kek.as_bytes(), &aad, root.as_bytes())?;
    Ok(MasterEnvelopeV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2Core2026,
        vault_id: vault_id.to_vec(),
        kdf: kdf.clone(),
        key_epoch,
        wrap_nonce: nonce.to_vec(),
        wrapped_root_secret: wrapped,
        created_at: crate::types::unix_now(),
    })
}

pub fn unwrap_root_v2(
    passphrase: &str,
    env: &MasterEnvelopeV2,
) -> Result<RootSecret, CryptoError> {
    env.validate_header()?;
    env.kdf.validate(KdfContext::V2Import)?;
    let vault_id = env.vault_id_bytes()?;
    let kek = derive_kek(passphrase, &env.kdf, KdfContext::V2Import)?;
    let aad = build_master_wrap_transcript(&vault_id, env.key_epoch, LOGICAL_MASTER);
    let pt = aead::open(kek.as_bytes(), &env.wrap_nonce, &aad, &env.wrapped_root_secret)?;
    if pt.len() != 32 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pt);
    Ok(RootSecret::from_bytes(arr))
}

#[cfg(any(test, feature = "insecure-kdf"))]
pub(crate) fn unwrap_root_v2_unit_test(
    passphrase: &str,
    env: &MasterEnvelopeV2,
) -> Result<RootSecret, CryptoError> {
    env.validate_header()?;
    env.kdf.validate(KdfContext::V2UnitTest)?;
    let vault_id = env.vault_id_bytes()?;
    let kek = derive_kek(passphrase, &env.kdf, KdfContext::V2UnitTest)?;
    let aad = build_master_wrap_transcript(&vault_id, env.key_epoch, LOGICAL_MASTER);
    let pt = aead::open(kek.as_bytes(), &env.wrap_nonce, &aad, &env.wrapped_root_secret)?;
    if pt.len() != 32 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pt);
    Ok(RootSecret::from_bytes(arr))
}

fn framed_blob(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (nonce, ciphertext) = aead::seal(key, aad, plaintext)?;
    Ok((nonce.to_vec(), ciphertext))
}

pub fn seal_vault_v2(
    vault_dek: &VaultDek,
    vault_id: [u8; 16],
    key_epoch: u32,
    plaintext: &[u8],
) -> Result<VaultBlobV2, CryptoError> {
    let aad = build_vault_blob_transcript(&vault_id, key_epoch);
    let (nonce, ciphertext) = framed_blob(vault_dek.as_bytes(), &aad, plaintext)?;
    Ok(VaultBlobV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2Core2026,
        vault_id: vault_id.to_vec(),
        key_epoch,
        nonce,
        ciphertext,
    })
}

pub fn open_vault_v2(vault_dek: &VaultDek, blob: &VaultBlobV2) -> Result<Vec<u8>, CryptoError> {
    blob.validate_header()?;
    let vault_id = blob.vault_id_bytes()?;
    let aad = build_vault_blob_transcript(&vault_id, blob.key_epoch);
    aead::open(vault_dek.as_bytes(), &blob.nonce, &aad, &blob.ciphertext)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditBlobV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl AuditBlobV2 {
    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        let blob: Self =
            ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))?;
        blob.validate_header()?;
        Ok(blob)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(encode_vault_v2(&self.to_cbor()?))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        reject_oversized(bytes)?;
        Self::from_cbor(decode_vault_v2(bytes)?)
    }

    fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_core()?;
        if self.vault_id.len() != 16 || self.nonce.len() != aead::NONCE_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.ciphertext.len() > MAX_BLOB_CIPHERTEXT {
            return Err(CryptoError::ResourceLimit);
        }
        Ok(())
    }

    fn vault_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }
}

pub fn seal_audit_v2(
    audit_dek: &AuditDek,
    vault_id: [u8; 16],
    key_epoch: u32,
    plaintext: &[u8],
) -> Result<AuditBlobV2, CryptoError> {
    let aad = build_audit_blob_transcript(&vault_id, key_epoch);
    let (nonce, ciphertext) = framed_blob(audit_dek.as_bytes(), &aad, plaintext)?;
    Ok(AuditBlobV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2Core2026,
        vault_id: vault_id.to_vec(),
        key_epoch,
        nonce,
        ciphertext,
    })
}

pub fn open_audit_v2(audit_dek: &AuditDek, blob: &AuditBlobV2) -> Result<Vec<u8>, CryptoError> {
    blob.validate_header()?;
    let vault_id = blob.vault_id_bytes()?;
    let aad = build_audit_blob_transcript(&vault_id, blob.key_epoch);
    aead::open(audit_dek.as_bytes(), &blob.nonce, &aad, &blob.ciphertext)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncBlobV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    pub key_epoch: u32,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl SyncBlobV2 {
    pub fn to_cbor(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CryptoError> {
        let blob: Self =
            ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))?;
        blob.validate_header()?;
        Ok(blob)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(encode_vault_v2(&self.to_cbor()?))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        reject_oversized(bytes)?;
        Self::from_cbor(decode_vault_v2(bytes)?)
    }

    fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_core()?;
        if self.vault_id.len() != 16 || self.nonce.len() != aead::NONCE_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.ciphertext.len() > MAX_BLOB_CIPHERTEXT {
            return Err(CryptoError::ResourceLimit);
        }
        Ok(())
    }

    fn vault_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.vault_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }
}

pub fn seal_sync_v2(
    sync_dek: &SyncDek,
    vault_id: [u8; 16],
    key_epoch: u32,
    plaintext: &[u8],
) -> Result<SyncBlobV2, CryptoError> {
    let aad = build_sync_blob_transcript(&vault_id, key_epoch);
    let (nonce, ciphertext) = framed_blob(sync_dek.as_bytes(), &aad, plaintext)?;
    Ok(SyncBlobV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2Core2026,
        vault_id: vault_id.to_vec(),
        key_epoch,
        nonce,
        ciphertext,
    })
}

pub fn open_sync_v2(sync_dek: &SyncDek, blob: &SyncBlobV2) -> Result<Vec<u8>, CryptoError> {
    blob.validate_header()?;
    let vault_id = blob.vault_id_bytes()?;
    let aad = build_sync_blob_transcript(&vault_id, blob.key_epoch);
    aead::open(sync_dek.as_bytes(), &blob.nonce, &aad, &blob.ciphertext)
}

/// Wrap RootSecret under RecoveryKek (no Argon2). Fresh 24-byte nonce per call.
pub fn wrap_root_under_recovery(
    kek: &RecoveryKek,
    vault_id: [u8; 16],
    key_epoch: u32,
    root: &RootSecret,
) -> Result<([u8; aead::NONCE_LEN], Vec<u8>), CryptoError> {
    let aad = build_recovery_wrap_transcript(&vault_id, key_epoch);
    aead::seal(kek.as_bytes(), &aad, root.as_bytes())
}

pub fn unwrap_root_under_recovery(
    kek: &RecoveryKek,
    vault_id: [u8; 16],
    key_epoch: u32,
    nonce: &[u8],
    wrapped: &[u8],
) -> Result<RootSecret, CryptoError> {
    let aad = build_recovery_wrap_transcript(&vault_id, key_epoch);
    let pt = aead::open(kek.as_bytes(), nonce, &aad, wrapped)?;
    if pt.len() != 32 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pt);
    Ok(RootSecret::from_bytes(arr))
}

/// Detect envelope version without committing to a CBOR parse.
///
/// v2 vault/master artifacts are identified by D10 magic + container version byte.
/// Raw CBOR without magic is not v2. v1 remains unframed CBOR.
pub fn peek_envelope_version(bytes: &[u8]) -> Option<u16> {
    if bytes.starts_with(MAGIC_VAULT_V2) {
        if bytes.len() > MAGIC_VAULT_V2.len() && bytes[MAGIC_VAULT_V2.len()] == CONTAINER_VERSION_V2
        {
            return Some(u16::from(CONTAINER_VERSION_V2));
        }
        return None;
    }
    if super::v1::MasterEnvelope::from_cbor(bytes).is_ok() {
        return Some(1);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hkdf_v2::derive_operational_keys;
    use crate::crypto::suite::SUITE_V2_CORE_2026;
    use crate::crypto::v1::{unwrap_master, wrap_master, KdfProfile, MasterEnvelope};

    fn test_vid() -> [u8; 16] {
        [0x11; 16]
    }

    #[test]
    fn v2_wrap_unwrap_roundtrip() {
        let params = Argon2ParamsV2::insecure_for_tests();
        let (env, root) = wrap_root_for_tests("pw-v2", test_vid(), params).unwrap();
        assert_eq!(env.format_version, 2);
        assert_eq!(env.crypto_suite.to_u16(), SUITE_V2_CORE_2026);
        assert_eq!(env.vault_id.len(), 16);
        assert_eq!(env.wrap_nonce.len(), 24);
        let opened = unwrap_root_for_tests("pw-v2", &env).unwrap();
        assert_eq!(opened.as_bytes(), root.as_bytes());
        assert!(unwrap_root_for_tests("wrong", &env).is_err());
    }

    fn wrap_root_for_tests(
        passphrase: &str,
        vault_id: [u8; 16],
        kdf: Argon2ParamsV2,
    ) -> Result<(MasterEnvelopeV2, RootSecret), CryptoError> {
        let root = RootSecret::random();
        let kek_bytes = {
            // Tests only: skip V2Generate floor.
            let p = argon2::Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
            let argon2 = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                p,
            );
            let mut out = [0u8; 32];
            argon2
                .hash_password_into(passphrase.as_bytes(), &kdf.salt, &mut out)
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
            out
        };
        let aad = build_master_wrap_transcript(&vault_id, KEY_EPOCH_INITIAL, LOGICAL_MASTER);
        let (nonce, wrapped) = aead::seal(&kek_bytes, &aad, root.as_bytes())?;
        let env = MasterEnvelopeV2 {
            format_version: FORMAT_VERSION_V2,
            crypto_suite: CryptoSuiteId::AegisV2Core2026,
            vault_id: vault_id.to_vec(),
            kdf,
            key_epoch: KEY_EPOCH_INITIAL,
            wrap_nonce: nonce.to_vec(),
            wrapped_root_secret: wrapped,
            created_at: 0,
        };
        Ok((env, root))
    }

    fn unwrap_root_for_tests(
        passphrase: &str,
        env: &MasterEnvelopeV2,
    ) -> Result<RootSecret, CryptoError> {
        env.validate_header()?;
        let vault_id = env.vault_id_bytes()?;
        let p = argon2::Params::new(
            env.kdf.memory_kib,
            env.kdf.iterations,
            env.kdf.parallelism,
            Some(32),
        )
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            p,
        );
        let mut kek_bytes = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), &env.kdf.salt, &mut kek_bytes)
            .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        let aad = build_master_wrap_transcript(&vault_id, env.key_epoch, LOGICAL_MASTER);
        let pt = aead::open(&kek_bytes, &env.wrap_nonce, &aad, &env.wrapped_root_secret)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pt);
        Ok(RootSecret::from_bytes(arr))
    }

    #[test]
    fn vault_blob_roundtrip_and_aad_binds_epoch() {
        let dek = VaultDek::random_for_tests();
        let vid = test_vid();
        let blob = seal_vault_v2(&dek, vid, 0, b"doc-bytes").unwrap();
        assert_eq!(blob.format_version, 2);
        assert_eq!(blob.nonce.len(), 24);
        assert_eq!(open_vault_v2(&dek, &blob).unwrap(), b"doc-bytes");
        let mut other_epoch = blob.clone();
        other_epoch.key_epoch = 1;
        assert!(open_vault_v2(&dek, &other_epoch).is_err());
        let mut other_id = blob.clone();
        other_id.vault_id = [0x22; 16].to_vec();
        assert!(open_vault_v2(&dek, &other_id).is_err());
    }

    #[test]
    fn unknown_suite_fails_closed() {
        let params = Argon2ParamsV2::insecure_for_tests();
        let (mut env, _) = wrap_root_for_tests("pw", test_vid(), params).unwrap();
        env.crypto_suite = CryptoSuiteId::AegisV2SyncHybrid2026;
        let bytes = env.to_cbor().unwrap();
        let err = MasterEnvelopeV2::from_cbor(&bytes).unwrap_err();
        assert!(matches!(err, CryptoError::UnsupportedSuite(0x0003)));
    }

    #[test]
    fn unknown_numeric_suite_id_fails_closed() {
        #[derive(Serialize)]
        struct Wire {
            format_version: u16,
            crypto_suite: u16,
            #[serde(with = "serde_bytes")]
            vault_id: Vec<u8>,
            kdf: Argon2ParamsV2,
            key_epoch: u32,
            #[serde(with = "serde_bytes")]
            wrap_nonce: Vec<u8>,
            #[serde(with = "serde_bytes")]
            wrapped_root_secret: Vec<u8>,
            created_at: u64,
        }
        let params = Argon2ParamsV2::insecure_for_tests();
        let (env, _) = wrap_root_for_tests("pw", test_vid(), params).unwrap();
        let fake = Wire {
            format_version: 2,
            crypto_suite: 0x9999,
            vault_id: env.vault_id,
            kdf: env.kdf,
            key_epoch: 0,
            wrap_nonce: env.wrap_nonce,
            wrapped_root_secret: env.wrapped_root_secret,
            created_at: 0,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&fake, &mut bytes).unwrap();
        let err = MasterEnvelopeV2::from_cbor(&bytes).unwrap_err();
        match err {
            CryptoError::UnsupportedSuite(0x9999) | CryptoError::Serde(_) => {}
            other => panic!("expected unsupported suite, got {other:?}"),
        }
    }

    #[test]
    fn v2_cbor_is_not_a_v1_master_envelope() {
        let params = Argon2ParamsV2::insecure_for_tests();
        let (env, _) = wrap_root_for_tests("pw", test_vid(), params).unwrap();
        let inner = env.to_cbor().unwrap();
        assert!(MasterEnvelope::from_cbor(&inner).is_err());
        let framed = env.to_bytes().unwrap();
        assert!(MasterEnvelope::from_cbor(&framed).is_err());
        assert_eq!(peek_envelope_version(&framed), Some(2));
        assert_eq!(peek_envelope_version(&inner), None);
    }

    #[test]
    fn d10_framed_roundtrip_and_reject_malformed() {
        let params = Argon2ParamsV2::insecure_for_tests();
        let (env, _) = wrap_root_for_tests("pw", test_vid(), params).unwrap();
        let framed = env.to_bytes().unwrap();
        assert_eq!(&framed[..14], MAGIC_VAULT_V2);
        assert_eq!(framed[14], 0x02);
        let opened = MasterEnvelopeV2::from_bytes(&framed).unwrap();
        assert_eq!(opened.vault_id, env.vault_id);

        let inner = env.to_cbor().unwrap();
        assert_eq!(
            MasterEnvelopeV2::from_bytes(&inner),
            Err(CryptoError::InvalidMagic),
            "raw v2 CBOR without magic must be rejected by the external decoder"
        );

        let mut bad_magic = framed.clone();
        bad_magic[3] ^= 0x01;
        assert_eq!(
            MasterEnvelopeV2::from_bytes(&bad_magic),
            Err(CryptoError::InvalidMagic)
        );

        let mut bad_ver = framed.clone();
        bad_ver[14] = 0x99;
        assert_eq!(
            MasterEnvelopeV2::from_bytes(&bad_ver),
            Err(CryptoError::UnsupportedVersion(0x99))
        );

        let (v1, _) = wrap_master("pw", KdfProfile::Test, "hex-id").unwrap();
        let v1_cbor = v1.to_cbor().unwrap();
        let mut fake = MAGIC_VAULT_V2.to_vec();
        fake.push(0x02);
        fake.extend_from_slice(&v1_cbor);
        assert!(
            MasterEnvelopeV2::from_bytes(&fake).is_err(),
            "v1 CBOR with a fake v2 prefix must not parse as MasterEnvelopeV2"
        );
        assert_eq!(peek_envelope_version(&v1_cbor), Some(1));
        assert_eq!(peek_envelope_version(&fake), Some(2));
        assert!(MasterEnvelopeV2::from_bytes(&fake).is_err());

        let dek = VaultDek::random_for_tests();
        let blob = seal_vault_v2(&dek, test_vid(), 0, b"doc").unwrap();
        let blob_framed = blob.to_bytes().unwrap();
        assert_eq!(&blob_framed[..15], b"AEGIS_VAULT_V2\x02");
        assert_eq!(VaultBlobV2::from_bytes(&blob_framed).unwrap().ciphertext, blob.ciphertext);
        assert_eq!(
            VaultBlobV2::from_bytes(&blob.to_cbor().unwrap()),
            Err(CryptoError::InvalidMagic)
        );
    }

    #[test]
    fn v2_wrap_never_emits_v1_sealed_blob() {
        let params = Argon2ParamsV2::insecure_for_tests();
        let (env, _) = wrap_root_for_tests("pw", test_vid(), params).unwrap();
        assert_ne!(env.format_version, 1);
        assert_eq!(env.crypto_suite, CryptoSuiteId::AegisV2Core2026);
        // v1 wrap still exists on the v1 path:
        let (v1, _) = wrap_master("pw", KdfProfile::Test, "hex-id").unwrap();
        assert_eq!(v1.sealed.version, 1);
        assert!(unwrap_master("pw", &v1).is_ok());
    }

    #[test]
    fn wrong_key_modified_nonce_fails() {
        let dek = VaultDek::random_for_tests();
        let blob = seal_vault_v2(&dek, test_vid(), 0, b"x").unwrap();
        assert!(open_vault_v2(&VaultDek::random_for_tests(), &blob).is_err());
        let mut n = blob.clone();
        n.nonce[0] ^= 1;
        assert!(open_vault_v2(&dek, &n).is_err());
        let mut c = blob.clone();
        c.ciphertext[0] ^= 1;
        assert!(open_vault_v2(&dek, &c).is_err());
    }

    #[test]
    fn v2_nonces_are_fresh_24_bytes() {
        let dek = VaultDek::random_for_tests();
        let a = seal_vault_v2(&dek, test_vid(), 0, b"x").unwrap();
        let b = seal_vault_v2(&dek, test_vid(), 0, b"x").unwrap();
        assert_eq!(a.nonce.len(), 24);
        assert_eq!(b.nonce.len(), 24);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn production_constructors_reject_below_64_mib() {
        let weak = Argon2ParamsV2::insecure_for_tests();
        assert!(wrap_root_v2_with_params("pw", test_vid(), weak.clone()).is_err());
        let (env, _) = wrap_root_for_tests("pw", test_vid(), weak).unwrap();
        assert!(
            unwrap_root_v2("pw", &env).is_err(),
            "production unwrap must reject test-sized Argon2"
        );
    }

    #[test]
    fn production_wrap_root_v2_roundtrip_is_not_v1() {
        let (env, root) = wrap_root_v2("pw-prod-v2-long", test_vid()).unwrap();
        assert_eq!(env.format_version, FORMAT_VERSION_V2);
        assert_eq!(env.crypto_suite, CryptoSuiteId::AegisV2Core2026);
        assert_eq!(env.vault_id.len(), 16);
        assert_eq!(env.wrap_nonce.len(), 24);
        assert_eq!(env.kdf.memory_kib, 64 * 1024);
        assert_eq!(env.kdf.iterations, 3);
        assert_eq!(env.kdf.algorithm, 2);
        assert_eq!(env.kdf.version, 19);
        let opened = unwrap_root_v2("pw-prod-v2-long", &env).unwrap();
        assert_eq!(opened.as_bytes(), root.as_bytes());
        let framed = env.to_bytes().unwrap();
        assert_eq!(&framed[..15], b"AEGIS_VAULT_V2\x02");
        assert!(MasterEnvelope::from_cbor(&framed).is_err());
        assert_eq!(peek_envelope_version(&framed), Some(2));
        let opened_bytes = MasterEnvelopeV2::from_bytes(&framed).unwrap();
        assert_eq!(
            unwrap_root_v2("pw-prod-v2-long", &opened_bytes).unwrap().as_bytes(),
            root.as_bytes()
        );
    }

    #[test]
    fn unknown_format_version_and_short_vault_id_fail_closed() {
        let params = Argon2ParamsV2::insecure_for_tests();
        let (mut env, _) = wrap_root_for_tests("pw", test_vid(), params).unwrap();
        env.format_version = 3;
        assert!(matches!(
            MasterEnvelopeV2::from_cbor(&env.to_cbor().unwrap()),
            Err(CryptoError::UnsupportedVersion(3))
        ));
        env.format_version = FORMAT_VERSION_V2;
        env.vault_id = vec![1, 2, 3];
        assert!(matches!(
            MasterEnvelopeV2::from_cbor(&env.to_cbor().unwrap()),
            Err(CryptoError::InvalidEnvelope)
        ));
        env.vault_id = test_vid().to_vec();
        env.wrap_nonce = vec![0u8; 12];
        assert!(matches!(
            MasterEnvelopeV2::from_cbor(&env.to_cbor().unwrap()),
            Err(CryptoError::InvalidEnvelope)
        ));
    }

    #[test]
    fn vault_blob_hybrid_suite_fails_closed() {
        let dek = VaultDek::random_for_tests();
        let mut blob = seal_vault_v2(&dek, test_vid(), 0, b"doc").unwrap();
        blob.crypto_suite = CryptoSuiteId::AegisV2ShareHybrid2026;
        let err = VaultBlobV2::from_cbor(&blob.to_cbor().unwrap()).unwrap_err();
        assert!(matches!(err, CryptoError::UnsupportedSuite(0x0004)));
    }

    #[test]
    fn extra_envelope_fields_are_rejected() {
        #[derive(Serialize)]
        struct Extra {
            format_version: u16,
            crypto_suite: CryptoSuiteId,
            #[serde(with = "serde_bytes")]
            vault_id: Vec<u8>,
            kdf: Argon2ParamsV2,
            key_epoch: u32,
            #[serde(with = "serde_bytes")]
            wrap_nonce: Vec<u8>,
            #[serde(with = "serde_bytes")]
            wrapped_root_secret: Vec<u8>,
            created_at: u64,
            mlkem_ciphertext: Vec<u8>,
        }
        let params = Argon2ParamsV2::insecure_for_tests();
        let (env, _) = wrap_root_for_tests("pw", test_vid(), params).unwrap();
        let fake = Extra {
            format_version: env.format_version,
            crypto_suite: env.crypto_suite,
            vault_id: env.vault_id,
            kdf: env.kdf,
            key_epoch: env.key_epoch,
            wrap_nonce: env.wrap_nonce,
            wrapped_root_secret: env.wrapped_root_secret,
            created_at: env.created_at,
            mlkem_ciphertext: vec![1, 2, 3],
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&fake, &mut bytes).unwrap();
        assert!(
            MasterEnvelopeV2::from_cbor(&bytes).is_err(),
            "0x0002 envelope must not carry extra PQ fields (D11)"
        );
    }

    #[test]
    fn outer_v2_prefix_rejects_inner_format_version_mismatch() {
        let params = Argon2ParamsV2::insecure_for_tests();
        let (mut env, _) = wrap_root_for_tests("pw", test_vid(), params).unwrap();
        env.format_version = 1;
        let framed = encode_vault_v2(&env.to_cbor().unwrap());
        assert_eq!(framed[14], 0x02);
        assert_eq!(
            MasterEnvelopeV2::from_bytes(&framed),
            Err(CryptoError::UnsupportedVersion(1))
        );
        env.format_version = 3;
        let framed = encode_vault_v2(&env.to_cbor().unwrap());
        assert_eq!(
            MasterEnvelopeV2::from_bytes(&framed),
            Err(CryptoError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn audit_and_sync_use_own_deks_not_vault_dek() {
        let root = RootSecret::from_bytes([0x5a; 32]);
        let keys = derive_operational_keys(&root, &test_vid()).unwrap();
        let audit = seal_audit_v2(&keys.audit_dek, test_vid(), 0, b"audit-log").unwrap();
        let sync = seal_sync_v2(&keys.sync_dek, test_vid(), 0, b"sync-pt").unwrap();
        let vault = seal_vault_v2(&keys.vault_dek, test_vid(), 0, b"vault-pt").unwrap();

        assert_eq!(open_audit_v2(&keys.audit_dek, &audit).unwrap(), b"audit-log");
        assert_eq!(open_sync_v2(&keys.sync_dek, &sync).unwrap(), b"sync-pt");
        assert_eq!(open_vault_v2(&keys.vault_dek, &vault).unwrap(), b"vault-pt");

        assert!(open_audit_v2(&keys.audit_dek, &AuditBlobV2 {
            format_version: vault.format_version,
            crypto_suite: vault.crypto_suite,
            vault_id: vault.vault_id.clone(),
            key_epoch: vault.key_epoch,
            nonce: vault.nonce.clone(),
            ciphertext: vault.ciphertext.clone(),
        }).is_err());
        assert!(open_vault_v2(&keys.vault_dek, &VaultBlobV2 {
            format_version: audit.format_version,
            crypto_suite: audit.crypto_suite,
            vault_id: audit.vault_id.clone(),
            key_epoch: audit.key_epoch,
            nonce: audit.nonce.clone(),
            ciphertext: audit.ciphertext.clone(),
        }).is_err());
        assert!(open_sync_v2(&keys.sync_dek, &SyncBlobV2 {
            format_version: vault.format_version,
            crypto_suite: vault.crypto_suite,
            vault_id: vault.vault_id.clone(),
            key_epoch: vault.key_epoch,
            nonce: vault.nonce.clone(),
            ciphertext: vault.ciphertext.clone(),
        }).is_err());
    }

    #[test]
    fn recovery_kek_wraps_root_without_root_as_ikm() {
        use crate::crypto::hkdf_v2::{derive_recovery_kek, LABEL_RECOVERY_KEK};
        use crate::crypto::secret::RecoverySecret;
        use hkdf::Hkdf;
        use sha2::Sha256;

        let vault_id = test_vid();
        let root = RootSecret::from_bytes([0x11; 32]);
        let recovery = RecoverySecret::from_bytes([0x22; 32]);
        let kek = derive_recovery_kek(&recovery, &vault_id).unwrap();

        let hk_root = Hkdf::<Sha256>::new(Some(vault_id.as_slice()), root.as_bytes());
        let mut from_root = [0u8; 32];
        hk_root.expand(LABEL_RECOVERY_KEK, &mut from_root).unwrap();
        assert_ne!(
            kek.as_bytes(),
            &from_root,
            "RecoveryKek must not be HKDF(RootSecret, recovery-kek)"
        );

        let (nonce, wrapped) = wrap_root_under_recovery(&kek, vault_id, 0, &root).unwrap();
        let opened = unwrap_root_under_recovery(&kek, vault_id, 0, &nonce, &wrapped).unwrap();
        assert_eq!(opened.as_bytes(), root.as_bytes());
        let other = derive_recovery_kek(&RecoverySecret::from_bytes([0x33; 32]), &vault_id).unwrap();
        assert!(unwrap_root_under_recovery(&other, vault_id, 0, &nonce, &wrapped).is_err());
    }
}
