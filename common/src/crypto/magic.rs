//! D10 file magic: ASCII marker + version byte, then CBOR.
//!
//! Reject unknown magic / version **before** deserialization.

use super::v1::CryptoError;

/// D10 magics. Recovery/sync containers land in later phases.
pub const MAGIC_VAULT_V2: &[u8] = b"AEGIS_VAULT_V2";
pub const MAGIC_BACKUP_V2: &[u8] = b"AEGIS_BACKUP_V2";
pub const MAGIC_RECOVERY_V2: &[u8] = b"AEGIS_RECOVERY_V2";
pub const MAGIC_SYNC_V2: &[u8] = b"AEGIS_SYNC_V2";

/// Container version byte after the ASCII magic. Independent of the CBOR `format_version` field.
pub const CONTAINER_VERSION_V2: u8 = 0x02;

pub fn encode_vault_v2(cbor: &[u8]) -> Vec<u8> {
    encode(MAGIC_VAULT_V2, CONTAINER_VERSION_V2, cbor)
}

/// Strip `AEGIS_VAULT_V2 || 0x02`. Does not parse CBOR.
pub fn decode_vault_v2(bytes: &[u8]) -> Result<&[u8], CryptoError> {
    decode(MAGIC_VAULT_V2, bytes)
}

pub fn encode_backup_v2(cbor: &[u8]) -> Vec<u8> {
    encode(MAGIC_BACKUP_V2, CONTAINER_VERSION_V2, cbor)
}

/// Strip `AEGIS_BACKUP_V2 || 0x02`. Does not parse CBOR.
pub fn decode_backup_v2(bytes: &[u8]) -> Result<&[u8], CryptoError> {
    decode(MAGIC_BACKUP_V2, bytes)
}

pub fn encode_sync_v2(cbor: &[u8]) -> Vec<u8> {
    encode(MAGIC_SYNC_V2, CONTAINER_VERSION_V2, cbor)
}

/// Strip `AEGIS_SYNC_V2 || 0x02`. Does not parse CBOR.
pub fn decode_sync_v2(bytes: &[u8]) -> Result<&[u8], CryptoError> {
    decode(MAGIC_SYNC_V2, bytes)
}

pub fn encode_recovery_v2(cbor: &[u8]) -> Vec<u8> {
    encode(MAGIC_RECOVERY_V2, CONTAINER_VERSION_V2, cbor)
}

/// Strip `AEGIS_RECOVERY_V2 || 0x02`. Does not parse CBOR.
pub fn decode_recovery_v2(bytes: &[u8]) -> Result<&[u8], CryptoError> {
    decode(MAGIC_RECOVERY_V2, bytes)
}

fn encode(magic: &[u8], version: u8, cbor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(magic.len() + 1 + cbor.len());
    out.extend_from_slice(magic);
    out.push(version);
    out.extend_from_slice(cbor);
    out
}

fn decode<'a>(magic: &[u8], bytes: &'a [u8]) -> Result<&'a [u8], CryptoError> {
    let need = magic.len().saturating_add(1);
    if bytes.len() < need || !bytes.starts_with(magic) {
        return Err(CryptoError::InvalidMagic);
    }
    let version = bytes[magic.len()];
    if version != CONTAINER_VERSION_V2 {
        return Err(CryptoError::UnsupportedVersion(u16::from(version)));
    }
    Ok(&bytes[need..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magics_are_exact_ascii_and_distinct() {
        assert_eq!(MAGIC_VAULT_V2, b"AEGIS_VAULT_V2");
        assert_eq!(MAGIC_VAULT_V2.len(), 14);
        assert_eq!(MAGIC_BACKUP_V2, b"AEGIS_BACKUP_V2");
        assert_eq!(MAGIC_BACKUP_V2.len(), 15);
        assert_eq!(CONTAINER_VERSION_V2, 0x02);
        assert_ne!(MAGIC_VAULT_V2, MAGIC_BACKUP_V2);
        assert_ne!(MAGIC_VAULT_V2, MAGIC_RECOVERY_V2);
        assert_ne!(MAGIC_VAULT_V2, MAGIC_SYNC_V2);
        assert_eq!(MAGIC_SYNC_V2, b"AEGIS_SYNC_V2");
        assert_eq!(MAGIC_SYNC_V2.len(), 13);
        assert_eq!(MAGIC_RECOVERY_V2, b"AEGIS_RECOVERY_V2");
        assert_eq!(MAGIC_RECOVERY_V2.len(), 17);
    }

    #[test]
    fn recovery_magic_is_not_vault_backup_or_sync() {
        let framed = encode_recovery_v2(b"\xa0");
        assert_eq!(&framed[..17], MAGIC_RECOVERY_V2);
        assert_eq!(framed[17], 0x02);
        assert_eq!(decode_recovery_v2(&framed).unwrap(), b"\xa0");
        assert_eq!(
            decode_recovery_v2(&encode_vault_v2(b"\xa0")),
            Err(CryptoError::InvalidMagic)
        );
        assert_eq!(
            decode_recovery_v2(&encode_backup_v2(b"\xa0")),
            Err(CryptoError::InvalidMagic)
        );
        assert_eq!(
            decode_recovery_v2(&encode_sync_v2(b"\xa0")),
            Err(CryptoError::InvalidMagic)
        );
        assert_eq!(
            decode_vault_v2(&framed),
            Err(CryptoError::InvalidMagic)
        );
        assert_eq!(
            decode_backup_v2(&framed),
            Err(CryptoError::InvalidMagic)
        );
        let mut ver = framed.clone();
        ver[MAGIC_RECOVERY_V2.len()] = 0x03;
        assert_eq!(
            decode_recovery_v2(&ver),
            Err(CryptoError::UnsupportedVersion(3))
        );
        assert_eq!(decode_recovery_v2(b"\xa0"), Err(CryptoError::InvalidMagic));
    }

    #[test]
    fn sync_magic_is_not_vault_or_backup() {
        let framed = encode_sync_v2(b"\xa0");
        assert_eq!(&framed[..13], MAGIC_SYNC_V2);
        assert_eq!(framed[13], 0x02);
        assert_eq!(decode_sync_v2(&framed).unwrap(), b"\xa0");
        assert_eq!(decode_sync_v2(&encode_vault_v2(b"\xa0")), Err(CryptoError::InvalidMagic));
        assert_eq!(decode_vault_v2(&framed), Err(CryptoError::InvalidMagic));
    }

    #[test]
    fn encode_is_magic_then_version_then_cbor() {
        let framed = encode_vault_v2(b"\xa0");
        assert_eq!(&framed[..14], MAGIC_VAULT_V2);
        assert_eq!(framed[14], 0x02);
        assert_eq!(&framed[15..], b"\xa0");
    }

    #[test]
    fn altered_magic_is_rejected_before_cbor() {
        let mut framed = encode_vault_v2(&[0xff; 8]);
        framed[0] ^= 0x01;
        assert_eq!(decode_vault_v2(&framed), Err(CryptoError::InvalidMagic));
        assert_eq!(decode_vault_v2(b""), Err(CryptoError::InvalidMagic));
        assert_eq!(
            decode_vault_v2(MAGIC_VAULT_V2),
            Err(CryptoError::InvalidMagic)
        );
        assert_eq!(
            decode_vault_v2(MAGIC_BACKUP_V2),
            Err(CryptoError::InvalidMagic)
        );
    }

    #[test]
    fn sync_wrong_magic_and_version_are_rejected_before_cbor() {
        assert_eq!(
            decode_sync_v2(b"AEGIS_VAULT_SYNC_V2\x02\xa0"),
            Err(CryptoError::InvalidMagic)
        );
        assert_eq!(
            decode_sync_v2(&encode_vault_v2(b"\xa0")),
            Err(CryptoError::InvalidMagic)
        );
        let mut framed = encode_sync_v2(&[0xff; 8]);
        framed[MAGIC_SYNC_V2.len()] = 0x03;
        assert_eq!(
            decode_sync_v2(&framed),
            Err(CryptoError::UnsupportedVersion(3))
        );
        framed[MAGIC_SYNC_V2.len()] = 0x01;
        assert_eq!(
            decode_sync_v2(&framed),
            Err(CryptoError::UnsupportedVersion(1))
        );
        framed[0] ^= 0x01;
        assert_eq!(decode_sync_v2(&framed), Err(CryptoError::InvalidMagic));
    }

    #[test]
    fn unknown_container_version_is_rejected_before_cbor() {
        let mut framed = encode_vault_v2(&[0xff; 8]);
        framed[MAGIC_VAULT_V2.len()] = 0x03;
        assert_eq!(
            decode_vault_v2(&framed),
            Err(CryptoError::UnsupportedVersion(3))
        );
        framed[MAGIC_VAULT_V2.len()] = 0x01;
        assert_eq!(
            decode_vault_v2(&framed),
            Err(CryptoError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn raw_cbor_without_magic_is_rejected() {
        assert_eq!(decode_vault_v2(&[0xa1, 0x00]), Err(CryptoError::InvalidMagic));
    }
}
