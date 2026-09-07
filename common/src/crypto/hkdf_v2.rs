//! v2 HKDF-SHA256 hierarchy (D3). Salt = 16-byte vault_id. Unique info labels.

use super::secret::{
    AuditDek, OperationalKeys, RecoveryKek, RecoverySecret, RootSecret, SearchHmacKey,
    ShareMlkemSeed, ShareX25519Seed, SyncDek, SyncEd25519Seed, SyncMldsaSeed, VaultDek,
    MLKEM_SEED_LEN,
};
use super::v1::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;

pub const LABEL_VAULT_DEK: &[u8] = b"aegis/v2/vault-dek";
pub const LABEL_AUDIT_DEK: &[u8] = b"aegis/v2/audit-dek";
pub const LABEL_SYNC_DEK: &[u8] = b"aegis/v2/sync-dek";
pub const LABEL_SEARCH_HMAC: &[u8] = b"aegis/v2/search-hmac";
pub const LABEL_SYNC_ED25519_SEED: &[u8] = b"aegis/v2/sync-ed25519-seed";
pub const LABEL_SYNC_MLDSA_SEED: &[u8] = b"aegis/v2/sync-mldsa-seed";
pub const LABEL_SHARE_X25519_SEED: &[u8] = b"aegis/v2/share-x25519-seed";
pub const LABEL_SHARE_MLKEM_SEED: &[u8] = b"aegis/v2/share-mlkem-seed";
/// HKDF info for RecoveryKek. IKM is RecoverySecret, never RootSecret (§27).
pub const LABEL_RECOVERY_KEK: &[u8] = b"aegis/v2/recovery-kek";
/// Combiner info (D5). Not derived from RootSecret or RecoverySecret.
pub const LABEL_SHARE_HYBRID_KEK: &[u8] = b"aegis/v2/share/hybrid-kek";

/// Labels expanded from RootSecret. Recovery and hybrid labels are not in this list.
pub const ROOT_DERIVED_LABELS: &[&[u8]] = &[
    LABEL_VAULT_DEK,
    LABEL_AUDIT_DEK,
    LABEL_SYNC_DEK,
    LABEL_SEARCH_HMAC,
    LABEL_SYNC_ED25519_SEED,
    LABEL_SYNC_MLDSA_SEED,
    LABEL_SHARE_X25519_SEED,
    LABEL_SHARE_MLKEM_SEED,
];

fn expand32(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).map_err(|_| CryptoError::Hkdf)?;
    Ok(out)
}

/// HKDF-SHA256(IKM = RootSecret, salt = vault_id, info = label).
pub fn derive_operational_keys(
    root: &RootSecret,
    vault_id: &[u8; 16],
) -> Result<OperationalKeys, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(vault_id.as_slice()), root.as_bytes());
    let mut mlkem = [0u8; MLKEM_SEED_LEN];
    hk.expand(LABEL_SHARE_MLKEM_SEED, &mut mlkem)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(OperationalKeys {
        vault_dek: VaultDek::from_bytes(expand32(&hk, LABEL_VAULT_DEK)?),
        audit_dek: AuditDek::from_bytes(expand32(&hk, LABEL_AUDIT_DEK)?),
        sync_dek: SyncDek::from_bytes(expand32(&hk, LABEL_SYNC_DEK)?),
        search_hmac: SearchHmacKey::from_bytes(expand32(&hk, LABEL_SEARCH_HMAC)?),
        sync_ed25519_seed: SyncEd25519Seed::from_bytes(expand32(&hk, LABEL_SYNC_ED25519_SEED)?),
        sync_mldsa_seed: SyncMldsaSeed::from_bytes(expand32(&hk, LABEL_SYNC_MLDSA_SEED)?),
        share_x25519_seed: ShareX25519Seed::from_bytes(expand32(&hk, LABEL_SHARE_X25519_SEED)?),
        share_mlkem_seed: ShareMlkemSeed::from_bytes(mlkem),
    })
}

/// HKDF-SHA256(IKM = RecoverySecret, salt = vault_id, info = "aegis/v2/recovery-kek").
/// RootSecret is not an input. Full Recovery Kit file format is Phase 9.
pub fn derive_recovery_kek(
    recovery: &RecoverySecret,
    vault_id: &[u8; 16],
) -> Result<RecoveryKek, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(vault_id.as_slice()), recovery.as_bytes());
    Ok(RecoveryKek::from_bytes(expand32(&hk, LABEL_RECOVERY_KEK)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::v1::{derive_keys, SecretKey};
    use std::collections::HashSet;

    fn vid(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn all_v2_labels_are_unique_and_domain_separated() {
        let mut all = ROOT_DERIVED_LABELS.to_vec();
        all.push(LABEL_RECOVERY_KEK);
        all.push(LABEL_SHARE_HYBRID_KEK);
        let set: HashSet<&[u8]> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
        for label in &all {
            assert!(label.starts_with(b"aegis/v2/"));
            assert!(!label.starts_with(b"aegis/v1/"));
        }
        assert!(!ROOT_DERIVED_LABELS.contains(&LABEL_RECOVERY_KEK));
        assert!(!ROOT_DERIVED_LABELS.contains(&LABEL_SHARE_HYBRID_KEK));
    }

    #[test]
    fn derive_is_deterministic_and_purpose_separated() {
        let root = RootSecret::from_bytes([0x11; 32]);
        let a = derive_operational_keys(&root, &vid(7)).unwrap();
        let b = derive_operational_keys(&root, &vid(7)).unwrap();
        assert_eq!(a.vault_dek.as_bytes(), b.vault_dek.as_bytes());
        assert_eq!(a.audit_dek.as_bytes(), b.audit_dek.as_bytes());
        assert_eq!(a.share_mlkem_seed.as_bytes().len(), 64);

        let keys: [&[u8]; 7] = [
            a.vault_dek.as_bytes(),
            a.audit_dek.as_bytes(),
            a.sync_dek.as_bytes(),
            a.search_hmac.as_bytes(),
            a.sync_ed25519_seed.as_bytes(),
            a.sync_mldsa_seed.as_bytes(),
            a.share_x25519_seed.as_bytes(),
        ];
        for i in 0..keys.len() {
            for j in 0..keys.len() {
                if i != j {
                    assert_ne!(keys[i], keys[j], "labels {i} and {j} collided");
                }
            }
        }
        assert_ne!(&a.share_mlkem_seed.as_bytes()[..32], a.vault_dek.as_bytes());
    }

    #[test]
    fn salt_and_ikm_are_bound() {
        let root = RootSecret::from_bytes([0x11; 32]);
        let other_root = RootSecret::from_bytes([0x22; 32]);
        let a = derive_operational_keys(&root, &vid(1)).unwrap();
        let b = derive_operational_keys(&root, &vid(2)).unwrap();
        let c = derive_operational_keys(&other_root, &vid(1)).unwrap();
        assert_ne!(a.vault_dek.as_bytes(), b.vault_dek.as_bytes());
        assert_ne!(a.vault_dek.as_bytes(), c.vault_dek.as_bytes());
        assert_ne!(a.audit_dek.as_bytes(), b.audit_dek.as_bytes());
    }

    #[test]
    fn v2_does_not_dual_derive_with_v1() {
        let bytes = [0x42u8; 32];
        let v1 = derive_keys(&SecretKey(bytes)).unwrap();
        let v2 = derive_operational_keys(&RootSecret::from_bytes(bytes), &vid(0)).unwrap();
        assert_ne!(v1.vault_dek.as_bytes(), v2.vault_dek.as_bytes());
        assert_ne!(v1.search_hmac.as_bytes(), v2.search_hmac.as_bytes());
    }

    #[test]
    fn operational_keys_redact_debug() {
        let keys = derive_operational_keys(&RootSecret::from_bytes([9; 32]), &vid(1)).unwrap();
        let s = format!("{keys:?}");
        assert_eq!(s, "OperationalKeys([REDACTED])");
        assert!(!s.contains("09"));
    }
}
