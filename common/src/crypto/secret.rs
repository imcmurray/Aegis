//! Distinct secret newtypes. No Serialize/Display/Clone on secret-bearing types.

use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_LEN: usize = 32;
/// FIPS 203 ML-KEM.KeyGen_internal: `d` (32) || `z` (32).
pub const MLKEM_SEED_LEN: usize = 64;

macro_rules! secret32 {
    ($name:ident, $debug:literal) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; KEY_LEN]);

        impl $name {
            pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            #[cfg(test)]
            pub fn random_for_tests() -> Self {
                let mut k = [0u8; KEY_LEN];
                crate::rng::fill_random(&mut k);
                Self(k)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str($debug)
            }
        }
    };
}

secret32!(VaultDek, "VaultDek([REDACTED])");
secret32!(AuditDek, "AuditDek([REDACTED])");
secret32!(SyncDek, "SyncDek([REDACTED])");
secret32!(SearchHmacKey, "SearchHmacKey([REDACTED])");
secret32!(SyncEd25519Seed, "SyncEd25519Seed([REDACTED])");
secret32!(SyncMldsaSeed, "SyncMldsaSeed([REDACTED])");
secret32!(ShareX25519Seed, "ShareX25519Seed([REDACTED])");
secret32!(ShareContentKey, "ShareContentKey([REDACTED])");
secret32!(HybridShareSecret, "HybridShareSecret([REDACTED])");
secret32!(RecoveryKek, "RecoveryKek([REDACTED])");
secret32!(WrapKek, "WrapKek([REDACTED])");
secret32!(BackupWrapKek, "BackupWrapKek([REDACTED])");

impl ShareContentKey {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        crate::rng::fill_random(&mut k);
        Self::from_bytes(k)
    }
}

/// Independent 256-bit CSPRNG. Encrypts a backup snapshot; never a live RootSecret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BackupKey([u8; KEY_LEN]);

impl BackupKey {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        crate::rng::fill_random(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupKey([REDACTED])")
    }
}

/// Independent 256-bit CSPRNG recovery secret (§27). Not derived from RootSecret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoverySecret([u8; KEY_LEN]);

impl RecoverySecret {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        crate::rng::fill_random(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for RecoverySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverySecret([REDACTED])")
    }
}

/// Random 256-bit root secret wrapped by the passphrase KEK.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootSecret([u8; KEY_LEN]);

impl RootSecret {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        crate::rng::fill_random(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for RootSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootSecret([REDACTED])")
    }
}

/// 64-byte ML-KEM-768 seed material (`d || z`). Not a live ML-KEM key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShareMlkemSeed([u8; MLKEM_SEED_LEN]);

impl ShareMlkemSeed {
    pub(crate) fn from_bytes(bytes: [u8; MLKEM_SEED_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; MLKEM_SEED_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for ShareMlkemSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShareMlkemSeed([REDACTED])")
    }
}

/// All RootSecret children. No Clone — copy would duplicate live key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OperationalKeys {
    pub vault_dek: VaultDek,
    pub audit_dek: AuditDek,
    pub sync_dek: SyncDek,
    pub search_hmac: SearchHmacKey,
    pub sync_ed25519_seed: SyncEd25519Seed,
    pub sync_mldsa_seed: SyncMldsaSeed,
    pub share_x25519_seed: ShareX25519Seed,
    pub share_mlkem_seed: ShareMlkemSeed,
}

impl std::fmt::Debug for OperationalKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperationalKeys([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn root_secret_zeroizes_and_redacts_debug() {
        let mut root = RootSecret::from_bytes([0xAB; 32]);
        assert_eq!(format!("{root:?}"), "RootSecret([REDACTED])");
        root.zeroize();
        assert_eq!(root.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn derived_types_redact_debug() {
        assert_eq!(format!("{:?}", VaultDek::from_bytes([1; 32])), "VaultDek([REDACTED])");
        assert_eq!(format!("{:?}", AuditDek::from_bytes([1; 32])), "AuditDek([REDACTED])");
        assert_eq!(format!("{:?}", SyncDek::from_bytes([1; 32])), "SyncDek([REDACTED])");
        assert_eq!(
            format!("{:?}", ShareMlkemSeed::from_bytes([1; 64])),
            "ShareMlkemSeed([REDACTED])"
        );
    }
}
