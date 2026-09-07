//! Hybrid VaultSync signatures: Ed25519 AND ML-DSA-65 over the same transcript.
//!
//! Never accept either signature alone. Seeds come from the Phase 3 HKDF
//! hierarchy (`sync-ed25519-seed`, `sync-mldsa-seed`).

use super::secret::{SyncEd25519Seed, SyncMldsaSeed};
use super::v1::CryptoError;
use ed25519_dalek::{Signature as EdSignature, Signer as EdSigner, Verifier as EdVerifier, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as MlDsaSignature,
    Signer as MlDsaSigner, SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifier,
    VerifyingKey as MlDsaVerifyingKey,
};
use serde::{Deserialize, Serialize};

/// FIPS 204 ML-DSA-65 verifying key size.
pub const ML_DSA_65_VK_LEN: usize = 1952;
/// FIPS 204 ML-DSA-65 signature size.
pub const ML_DSA_65_SIG_LEN: usize = 3309;
pub const ED25519_VK_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;

/// Public hybrid sync identity for one RootSecret epoch (vault-wide).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HybridSyncIdentityV2 {
    #[serde(with = "serde_bytes")]
    pub ed25519_vk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ml_dsa_vk: Vec<u8>,
}

impl HybridSyncIdentityV2 {
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.ed25519_vk.len() != ED25519_VK_LEN || self.ml_dsa_vk.len() != ML_DSA_65_VK_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(())
    }

    /// Transcript metadata: `ed25519_vk || ml_dsa_vk`.
    pub fn metadata(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate()?;
        let mut out = Vec::with_capacity(ED25519_VK_LEN + ML_DSA_65_VK_LEN);
        out.extend_from_slice(&self.ed25519_vk);
        out.extend_from_slice(&self.ml_dsa_vk);
        Ok(out)
    }
}

/// Hybrid signature pair. Both members are required; neither is sufficient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HybridSignatureV2 {
    #[serde(with = "serde_bytes")]
    pub ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ml_dsa: Vec<u8>,
}

impl HybridSignatureV2 {
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.ed25519.len() != ED25519_SIG_LEN || self.ml_dsa.len() != ML_DSA_65_SIG_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(())
    }
}

pub struct HybridSyncSigner {
    ed25519: EdSigningKey,
    ml_dsa: MlDsaSigningKey<MlDsa65>,
}

impl HybridSyncSigner {
    /// Derive the vault-wide hybrid identity from the Phase 3 RootSecret children.
    pub fn from_operational_keys(keys: &super::secret::OperationalKeys) -> Self {
        Self::from_seeds(&keys.sync_ed25519_seed, &keys.sync_mldsa_seed)
    }

    pub fn from_seeds(ed25519_seed: &SyncEd25519Seed, mldsa_seed: &SyncMldsaSeed) -> Self {
        let ed25519 = EdSigningKey::from_bytes(ed25519_seed.as_bytes());
        let seed = B32::from(*mldsa_seed.as_bytes());
        let ml_dsa = MlDsaSigningKey::<MlDsa65>::from_seed(&seed);
        Self { ed25519, ml_dsa }
    }

    pub fn identity(&self) -> HybridSyncIdentityV2 {
        HybridSyncIdentityV2 {
            ed25519_vk: self.ed25519.verifying_key().to_bytes().to_vec(),
            ml_dsa_vk: self.ml_dsa.as_ref().encode().to_vec(),
        }
    }

    pub fn sign(&self, transcript: &[u8]) -> HybridSignatureV2 {
        let ed = EdSigner::sign(&self.ed25519, transcript);
        let pq = MlDsaSigner::sign(&self.ml_dsa, transcript);
        HybridSignatureV2 {
            ed25519: ed.to_bytes().to_vec(),
            ml_dsa: pq.encode().to_vec(),
        }
    }
}

/// Verify Ed25519 AND ML-DSA-65. Either failure (or missing/malformed) rejects.
pub fn verify_hybrid(
    identity: &HybridSyncIdentityV2,
    transcript: &[u8],
    signature: &HybridSignatureV2,
) -> Result<(), CryptoError> {
    identity.validate()?;
    signature.validate()?;

    let ed_ok = verify_ed25519(&identity.ed25519_vk, transcript, &signature.ed25519);
    let pq_ok = verify_mldsa(&identity.ml_dsa_vk, transcript, &signature.ml_dsa);
    if ed_ok && pq_ok {
        Ok(())
    } else {
        Err(CryptoError::HybridSignatureRejected)
    }
}

fn verify_ed25519(vk_bytes: &[u8], transcript: &[u8], sig_bytes: &[u8]) -> bool {
    if vk_bytes.len() != ED25519_VK_LEN || sig_bytes.len() != ED25519_SIG_LEN {
        return false;
    }
    let vk_arr: [u8; 32] = match vk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(vk) = EdVerifyingKey::from_bytes(&vk_arr) else {
        return false;
    };
    let sig = EdSignature::from_bytes(&sig_arr);
    vk.verify(transcript, &sig).is_ok()
}

fn verify_mldsa(vk_bytes: &[u8], transcript: &[u8], sig_bytes: &[u8]) -> bool {
    if vk_bytes.len() != ML_DSA_65_VK_LEN || sig_bytes.len() != ML_DSA_65_SIG_LEN {
        return false;
    }
    let Ok(vk_enc) = EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes) else {
        return false;
    };
    let Ok(sig_enc) = EncodedSignature::<MlDsa65>::try_from(sig_bytes) else {
        return false;
    };
    let Some(sig) = MlDsaSignature::<MlDsa65>::decode(&sig_enc) else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&vk_enc);
    vk.verify(transcript, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hkdf_v2::derive_operational_keys;
    use crate::crypto::secret::RootSecret;

    fn signer() -> HybridSyncSigner {
        let keys = derive_operational_keys(&RootSecret::from_bytes([0x42; 32]), &[7u8; 16]).unwrap();
        HybridSyncSigner::from_seeds(&keys.sync_ed25519_seed, &keys.sync_mldsa_seed)
    }

    #[test]
    fn fips_sizes_match() {
        let s = signer();
        let id = s.identity();
        assert_eq!(id.ed25519_vk.len(), ED25519_VK_LEN);
        assert_eq!(id.ml_dsa_vk.len(), ML_DSA_65_VK_LEN);
        let sig = s.sign(b"transcript");
        assert_eq!(sig.ed25519.len(), ED25519_SIG_LEN);
        assert_eq!(sig.ml_dsa.len(), ML_DSA_65_SIG_LEN);
    }

    #[test]
    fn both_signatures_required() {
        let s = signer();
        let id = s.identity();
        let msg = b"aegis hybrid kat";
        let sig = s.sign(msg);
        assert!(verify_hybrid(&id, msg, &sig).is_ok());

        let mut ed_only = sig.clone();
        ed_only.ml_dsa = vec![0u8; ML_DSA_65_SIG_LEN];
        assert_eq!(
            verify_hybrid(&id, msg, &ed_only),
            Err(CryptoError::HybridSignatureRejected)
        );

        let mut pq_only = sig.clone();
        pq_only.ed25519 = vec![0u8; ED25519_SIG_LEN];
        assert_eq!(
            verify_hybrid(&id, msg, &pq_only),
            Err(CryptoError::HybridSignatureRejected)
        );

        let mut truncated = sig.clone();
        truncated.ml_dsa.truncate(100);
        assert_eq!(
            verify_hybrid(&id, msg, &truncated),
            Err(CryptoError::InvalidEnvelope)
        );
    }

    #[test]
    fn wrong_transcript_is_rejected() {
        let s = signer();
        let id = s.identity();
        let sig = s.sign(b"one");
        assert!(verify_hybrid(&id, b"two", &sig).is_err());
    }

    #[test]
    fn seeds_are_phase3_hierarchy() {
        let a = derive_operational_keys(&RootSecret::from_bytes([1; 32]), &[9u8; 16]).unwrap();
        let b = derive_operational_keys(&RootSecret::from_bytes([1; 32]), &[9u8; 16]).unwrap();
        let sa = HybridSyncSigner::from_seeds(&a.sync_ed25519_seed, &a.sync_mldsa_seed);
        let sb = HybridSyncSigner::from_seeds(&b.sync_ed25519_seed, &b.sync_mldsa_seed);
        assert_eq!(sa.identity(), sb.identity());
        let other = derive_operational_keys(&RootSecret::from_bytes([2; 32]), &[9u8; 16]).unwrap();
        let so = HybridSyncSigner::from_seeds(&other.sync_ed25519_seed, &other.sync_mldsa_seed);
        assert_ne!(sa.identity(), so.identity());
    }
}
