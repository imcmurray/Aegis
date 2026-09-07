//! Stable numeric crypto-suite IDs (D2 / D11). Never reuse an ID.

use super::CryptoError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `AegisV1Legacy` — decoder only after v2 is default.
pub const SUITE_V1_LEGACY: u16 = 0x0001;
/// `AegisV2Core2026` — Argon2id + XChaCha20-Poly1305 + HKDF-SHA-256. Not hybrid.
pub const SUITE_V2_CORE_2026: u16 = 0x0002;
/// `AegisV2SyncHybrid2026` — Ed25519 AND ML-DSA-65 over the same transcript (Phase 7).
pub const SUITE_V2_SYNC_HYBRID_2026: u16 = 0x0003;
/// `AegisV2ShareHybrid2026` — X25519 AND ML-KEM-768 plus hybrid signatures (Phase 8).
pub const SUITE_V2_SHARE_HYBRID_2026: u16 = 0x0004;

/// Wire format version for v2 envelopes.
pub const FORMAT_VERSION_V2: u16 = 2;

/// Initial key epoch (incremented on full rotation, Phase 6).
pub const KEY_EPOCH_INITIAL: u32 = 0;

/// D1 `kind_u16` — Aegis-owned permanent IDs. Never reuse. Never `as u16` on an enum.
pub const KIND_MASTER_WRAP: u16 = 0x0001;
pub const KIND_VAULT_BLOB: u16 = 0x0002;
pub const KIND_AUDIT_BLOB: u16 = 0x0003;
pub const KIND_SYNC_BLOB: u16 = 0x0004;
pub const KIND_EXPORT_BLOB: u16 = 0x0005;
pub const KIND_BACKUP_WRAP: u16 = 0x0006;
/// Hybrid VaultSync revision signing transcript (Phase 7). Not a reuse of SyncBlob.
pub const KIND_SYNC_REVISION: u16 = 0x0007;
/// Dual-signed old↔new sync-identity transition (Phase 7).
pub const KIND_SYNC_TRANSITION: u16 = 0x0008;
/// Recipient share-identity certification (Phase 8).
pub const KIND_SHARE_IDENTITY: u16 = 0x0009;
/// Hybrid share offer / wrap AAD (Phase 8).
pub const KIND_SHARE_ENVELOPE: u16 = 0x000A;
/// Share payload AEAD AAD (Phase 8).
pub const KIND_SHARE_PAYLOAD: u16 = 0x000B;
/// Recovery Kit wrap of RootSecret under RecoveryKek (Phase 9). Core suite, not hybrid.
pub const KIND_RECOVERY_WRAP: u16 = 0x000C;

/// Object kind bound into D1 AAD. Wire value is [`Self::to_u16`], not declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    MasterWrap,
    VaultBlob,
    AuditBlob,
    SyncBlob,
    ExportBlob,
    BackupWrap,
    SyncRevision,
    SyncTransition,
    ShareIdentity,
    ShareEnvelope,
    SharePayload,
    RecoveryWrap,
}

impl ObjectKind {
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::MasterWrap => KIND_MASTER_WRAP,
            Self::VaultBlob => KIND_VAULT_BLOB,
            Self::AuditBlob => KIND_AUDIT_BLOB,
            Self::SyncBlob => KIND_SYNC_BLOB,
            Self::ExportBlob => KIND_EXPORT_BLOB,
            Self::BackupWrap => KIND_BACKUP_WRAP,
            Self::SyncRevision => KIND_SYNC_REVISION,
            Self::SyncTransition => KIND_SYNC_TRANSITION,
            Self::ShareIdentity => KIND_SHARE_IDENTITY,
            Self::ShareEnvelope => KIND_SHARE_ENVELOPE,
            Self::SharePayload => KIND_SHARE_PAYLOAD,
            Self::RecoveryWrap => KIND_RECOVERY_WRAP,
        }
    }

    pub fn from_u16(id: u16) -> Result<Self, CryptoError> {
        match id {
            KIND_MASTER_WRAP => Ok(Self::MasterWrap),
            KIND_VAULT_BLOB => Ok(Self::VaultBlob),
            KIND_AUDIT_BLOB => Ok(Self::AuditBlob),
            KIND_SYNC_BLOB => Ok(Self::SyncBlob),
            KIND_EXPORT_BLOB => Ok(Self::ExportBlob),
            KIND_BACKUP_WRAP => Ok(Self::BackupWrap),
            KIND_SYNC_REVISION => Ok(Self::SyncRevision),
            KIND_SYNC_TRANSITION => Ok(Self::SyncTransition),
            KIND_SHARE_IDENTITY => Ok(Self::ShareIdentity),
            KIND_SHARE_ENVELOPE => Ok(Self::ShareEnvelope),
            KIND_SHARE_PAYLOAD => Ok(Self::SharePayload),
            KIND_RECOVERY_WRAP => Ok(Self::RecoveryWrap),
            other => Err(CryptoError::UnsupportedObjectKind(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSuiteId {
    AegisV1Legacy,
    AegisV2Core2026,
    AegisV2SyncHybrid2026,
    AegisV2ShareHybrid2026,
}

impl CryptoSuiteId {
    pub fn to_u16(self) -> u16 {
        match self {
            Self::AegisV1Legacy => SUITE_V1_LEGACY,
            Self::AegisV2Core2026 => SUITE_V2_CORE_2026,
            Self::AegisV2SyncHybrid2026 => SUITE_V2_SYNC_HYBRID_2026,
            Self::AegisV2ShareHybrid2026 => SUITE_V2_SHARE_HYBRID_2026,
        }
    }

    pub fn from_u16(id: u16) -> Result<Self, CryptoError> {
        match id {
            SUITE_V1_LEGACY => Ok(Self::AegisV1Legacy),
            SUITE_V2_CORE_2026 => Ok(Self::AegisV2Core2026),
            SUITE_V2_SYNC_HYBRID_2026 => Ok(Self::AegisV2SyncHybrid2026),
            SUITE_V2_SHARE_HYBRID_2026 => Ok(Self::AegisV2ShareHybrid2026),
            other => Err(CryptoError::UnsupportedSuite(other)),
        }
    }

    /// Storage / master-wrap / vault-blob must be Core, never hybrid (D11).
    pub fn require_v2_core(self) -> Result<(), CryptoError> {
        if self == Self::AegisV2Core2026 {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedSuite(self.to_u16()))
        }
    }

    /// VaultSync revision / transition objects must be hybrid (D11). Never Core or v1.
    pub fn require_v2_sync_hybrid(self) -> Result<(), CryptoError> {
        if self == Self::AegisV2SyncHybrid2026 {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedSuite(self.to_u16()))
        }
    }

    /// Share identity / envelope objects must be hybrid share suite (D11).
    pub fn require_v2_share_hybrid(self) -> Result<(), CryptoError> {
        if self == Self::AegisV2ShareHybrid2026 {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedSuite(self.to_u16()))
        }
    }
}

impl Serialize for CryptoSuiteId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.to_u16())
    }
}

impl<'de> Deserialize<'de> for CryptoSuiteId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = u16::deserialize(deserializer)?;
        Self::from_u16(id).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_ids_are_stable() {
        assert_eq!(CryptoSuiteId::AegisV1Legacy.to_u16(), 0x0001);
        assert_eq!(CryptoSuiteId::AegisV2Core2026.to_u16(), 0x0002);
        assert_eq!(CryptoSuiteId::AegisV2SyncHybrid2026.to_u16(), 0x0003);
        assert_eq!(CryptoSuiteId::AegisV2ShareHybrid2026.to_u16(), 0x0004);
        assert_eq!(
            CryptoSuiteId::from_u16(0x0002).unwrap(),
            CryptoSuiteId::AegisV2Core2026
        );
    }

    #[test]
    fn unknown_and_zero_suite_ids_fail_closed() {
        assert!(matches!(
            CryptoSuiteId::from_u16(0),
            Err(CryptoError::UnsupportedSuite(0))
        ));
        assert!(matches!(
            CryptoSuiteId::from_u16(0x0005),
            Err(CryptoError::UnsupportedSuite(0x0005))
        ));
        assert!(matches!(
            CryptoSuiteId::from_u16(0x9999),
            Err(CryptoError::UnsupportedSuite(0x9999))
        ));
    }

    #[test]
    fn hybrid_suites_are_not_valid_storage_suites() {
        assert!(CryptoSuiteId::AegisV2Core2026.require_v2_core().is_ok());
        assert!(CryptoSuiteId::AegisV1Legacy.require_v2_core().is_err());
        assert!(CryptoSuiteId::AegisV2SyncHybrid2026.require_v2_core().is_err());
        assert!(CryptoSuiteId::AegisV2ShareHybrid2026.require_v2_core().is_err());
        assert!(CryptoSuiteId::AegisV2SyncHybrid2026
            .require_v2_sync_hybrid()
            .is_ok());
        assert!(CryptoSuiteId::AegisV2Core2026
            .require_v2_sync_hybrid()
            .is_err());
        assert!(CryptoSuiteId::AegisV1Legacy.require_v2_sync_hybrid().is_err());
        assert!(CryptoSuiteId::AegisV2ShareHybrid2026
            .require_v2_share_hybrid()
            .is_ok());
        assert!(CryptoSuiteId::AegisV2Core2026.require_v2_share_hybrid().is_err());
        assert!(CryptoSuiteId::AegisV2SyncHybrid2026
            .require_v2_share_hybrid()
            .is_err());
    }

    #[test]
    fn object_kind_ids_are_explicit_not_enum_order() {
        assert_eq!(KIND_MASTER_WRAP, 0x0001);
        assert_eq!(KIND_VAULT_BLOB, 0x0002);
        assert_eq!(KIND_AUDIT_BLOB, 0x0003);
        assert_eq!(KIND_SYNC_BLOB, 0x0004);
        assert_eq!(KIND_EXPORT_BLOB, 0x0005);
        assert_eq!(KIND_BACKUP_WRAP, 0x0006);
        assert_eq!(KIND_SYNC_REVISION, 0x0007);
        assert_eq!(KIND_SYNC_TRANSITION, 0x0008);
        assert_eq!(KIND_SHARE_IDENTITY, 0x0009);
        assert_eq!(KIND_SHARE_ENVELOPE, 0x000A);
        assert_eq!(KIND_SHARE_PAYLOAD, 0x000B);
        assert_eq!(KIND_RECOVERY_WRAP, 0x000C);
        assert_eq!(ObjectKind::MasterWrap.to_u16(), 0x0001);
        assert_eq!(ObjectKind::VaultBlob.to_u16(), 0x0002);
        assert_eq!(ObjectKind::AuditBlob.to_u16(), 0x0003);
        assert_eq!(ObjectKind::SyncBlob.to_u16(), 0x0004);
        assert_eq!(ObjectKind::ExportBlob.to_u16(), 0x0005);
        assert_eq!(ObjectKind::BackupWrap.to_u16(), 0x0006);
        assert_eq!(ObjectKind::SyncRevision.to_u16(), 0x0007);
        assert_eq!(ObjectKind::SyncTransition.to_u16(), 0x0008);
        assert_eq!(ObjectKind::ShareIdentity.to_u16(), 0x0009);
        assert_eq!(ObjectKind::ShareEnvelope.to_u16(), 0x000A);
        assert_eq!(ObjectKind::SharePayload.to_u16(), 0x000B);
        assert_eq!(ObjectKind::RecoveryWrap.to_u16(), 0x000C);
        // Declaration order is Master, Vault, Audit, Sync, Export. If to_u16 were
        // `self as u16` with default discriminants, MasterWrap would be 0, not 1.
        assert_ne!(ObjectKind::MasterWrap.to_u16(), 0);
        assert!(matches!(
            ObjectKind::from_u16(0),
            Err(CryptoError::UnsupportedObjectKind(0))
        ));
        assert!(matches!(
            ObjectKind::from_u16(0x000D),
            Err(CryptoError::UnsupportedObjectKind(0x000D))
        ));
    }

    #[test]
    fn suite_id_cbor_is_u16_not_variant_name() {
        let mut buf = Vec::new();
        ciborium::into_writer(&CryptoSuiteId::AegisV2Core2026, &mut buf).unwrap();
        let id: u16 = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(id, 0x0002);
        let mut unknown = Vec::new();
        ciborium::into_writer(&0xABCDu16, &mut unknown).unwrap();
        let err: Result<CryptoSuiteId, _> = ciborium::from_reader(unknown.as_slice());
        assert!(err.is_err());
    }
}
