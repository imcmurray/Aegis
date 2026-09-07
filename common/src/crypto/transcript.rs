//! D1 length-prefixed transcripts. Not CBOR map bytes.

use super::suite::{
    ObjectKind, FORMAT_VERSION_V2, SUITE_V2_CORE_2026, SUITE_V2_SHARE_HYBRID_2026,
    SUITE_V2_SYNC_HYBRID_2026,
};

const MAGIC: &[u8] = b"Aegis";

fn push_u16_le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    push_u32_le(out, field.len() as u32);
    out.extend_from_slice(field);
}

fn header_with_suite(
    suite: u16,
    kind: ObjectKind,
    vault_id: &[u8; 16],
    key_epoch: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + 2 * 3 + 16 + 4);
    out.extend_from_slice(MAGIC);
    push_u16_le(&mut out, FORMAT_VERSION_V2);
    push_u16_le(&mut out, suite);
    push_u16_le(&mut out, kind.to_u16());
    out.extend_from_slice(vault_id);
    push_u32_le(&mut out, key_epoch);
    out
}

fn header(kind: ObjectKind, vault_id: &[u8; 16], key_epoch: u32) -> Vec<u8> {
    header_with_suite(SUITE_V2_CORE_2026, kind, vault_id, key_epoch)
}

/// AAD for wrapping RootSecret under the passphrase KEK.
pub fn build_master_wrap_transcript(
    vault_id: &[u8; 16],
    key_epoch: u32,
    logical_id: &[u8],
) -> Vec<u8> {
    let mut out = header(ObjectKind::MasterWrap, vault_id, key_epoch);
    push_lp(&mut out, logical_id);
    out
}

/// AAD for VaultBlobV2 (document ciphertext).
pub fn build_vault_blob_transcript(vault_id: &[u8; 16], key_epoch: u32) -> Vec<u8> {
    header(ObjectKind::VaultBlob, vault_id, key_epoch)
}

/// AAD for AuditBlobV2.
pub fn build_audit_blob_transcript(vault_id: &[u8; 16], key_epoch: u32) -> Vec<u8> {
    header(ObjectKind::AuditBlob, vault_id, key_epoch)
}

/// AAD for SyncBlobV2 (inner ciphertext; suite Core, kind 0x0004).
pub fn build_sync_blob_transcript(vault_id: &[u8; 16], key_epoch: u32) -> Vec<u8> {
    header(ObjectKind::SyncBlob, vault_id, key_epoch)
}

/// Hybrid revision signing transcript (suite 0x0003, kind SyncRevision).
///
/// Extra fields: `lp(device_id) || counter_u64_le || parent_hash_32 ||
/// ciphertext_hash_32 || lp(metadata)`. Metadata is `ed25519_vk || ml_dsa_vk`.
pub fn build_sync_signing_transcript(
    vault_id: &[u8; 16],
    key_epoch: u32,
    device_id: &[u8],
    counter: u64,
    parent_hash: &[u8; 32],
    ciphertext_hash: &[u8; 32],
    metadata: &[u8],
) -> Vec<u8> {
    let mut out = header_with_suite(
        SUITE_V2_SYNC_HYBRID_2026,
        ObjectKind::SyncRevision,
        vault_id,
        key_epoch,
    );
    push_lp(&mut out, device_id);
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(parent_hash);
    out.extend_from_slice(ciphertext_hash);
    push_lp(&mut out, metadata);
    out
}

/// Dual-signed identity-transition transcript (suite 0x0003, kind SyncTransition).
/// Header `key_epoch` is the new epoch. Both old and new identities sign this.
pub fn build_sync_transition_transcript(
    vault_id: &[u8; 16],
    old_epoch: u32,
    new_epoch: u32,
    old_metadata: &[u8],
    new_metadata: &[u8],
) -> Vec<u8> {
    let mut out = header_with_suite(
        SUITE_V2_SYNC_HYBRID_2026,
        ObjectKind::SyncTransition,
        vault_id,
        new_epoch,
    );
    out.extend_from_slice(&old_epoch.to_le_bytes());
    push_lp(&mut out, old_metadata);
    push_lp(&mut out, new_metadata);
    out
}

/// AAD for wrapping BackupKey. Public fields only: container_id + canonical KDF params.
pub fn build_backup_wrap_transcript(container_id: &[u8; 16], kdf_aad: &[u8]) -> Vec<u8> {
    let mut out = header(ObjectKind::BackupWrap, container_id, 0);
    push_lp(&mut out, kdf_aad);
    out
}

/// AAD for encrypted BackupPayloadV2. Same public fields; not original_vault_id.
pub fn build_backup_payload_transcript(container_id: &[u8; 16], kdf_aad: &[u8]) -> Vec<u8> {
    let mut out = header(ObjectKind::ExportBlob, container_id, 0);
    push_lp(&mut out, kdf_aad);
    out
}

/// Hybrid share-identity certification (suite 0x0004, kind ShareIdentity).
/// Extra fields: `lp(x25519_pk) || lp(mlkem_ek) || lp(signing_identity_metadata)`.
pub fn build_share_identity_transcript(
    vault_id: &[u8; 16],
    key_epoch: u32,
    x25519_pk: &[u8],
    mlkem_ek: &[u8],
    signing_metadata: &[u8],
) -> Vec<u8> {
    let mut out = header_with_suite(
        SUITE_V2_SHARE_HYBRID_2026,
        ObjectKind::ShareIdentity,
        vault_id,
        key_epoch,
    );
    push_lp(&mut out, x25519_pk);
    push_lp(&mut out, mlkem_ek);
    push_lp(&mut out, signing_metadata);
    out
}

/// D5 share transcript (suite 0x0004, kind ShareEnvelope). SHA-256 of this
/// is the combiner salt. Extra fields are all length-prefixed.
pub fn build_share_transcript(
    vault_id: &[u8; 16],
    key_epoch: u32,
    sender_identity: &[u8],
    recipient_identity: &[u8],
    ephemeral_x25519: &[u8],
    recipient_x25519: &[u8],
    recipient_mlkem: &[u8],
    mlkem_ciphertext: &[u8],
    share_id: &[u8],
) -> Vec<u8> {
    let mut out = header_with_suite(
        SUITE_V2_SHARE_HYBRID_2026,
        ObjectKind::ShareEnvelope,
        vault_id,
        key_epoch,
    );
    push_lp(&mut out, sender_identity);
    push_lp(&mut out, recipient_identity);
    push_lp(&mut out, ephemeral_x25519);
    push_lp(&mut out, recipient_x25519);
    push_lp(&mut out, recipient_mlkem);
    push_lp(&mut out, mlkem_ciphertext);
    push_lp(&mut out, share_id);
    out
}

/// AAD for wrapping RootSecret under RecoveryKek (suite 0x0002, kind RecoveryWrap).
/// Binds format version, Core suite, object kind, vault_id, and key_epoch.
pub fn build_recovery_wrap_transcript(vault_id: &[u8; 16], key_epoch: u32) -> Vec<u8> {
    header(ObjectKind::RecoveryWrap, vault_id, key_epoch)
}

/// AAD for the share payload AEAD (suite 0x0004, kind SharePayload).
pub fn build_share_payload_transcript(
    vault_id: &[u8; 16],
    key_epoch: u32,
    share_id: &[u8],
) -> Vec<u8> {
    let mut out = header_with_suite(
        SUITE_V2_SHARE_HYBRID_2026,
        ObjectKind::SharePayload,
        vault_id,
        key_epoch,
    );
    push_lp(&mut out, share_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcripts_are_deterministic_and_distinct() {
        let vid = [7u8; 16];
        let a = build_master_wrap_transcript(&vid, 0, b"master");
        let b = build_master_wrap_transcript(&vid, 0, b"master");
        assert_eq!(a, b);
        assert!(a.starts_with(b"Aegis"));
        let vault = build_vault_blob_transcript(&vid, 0);
        assert_ne!(a, vault);
        let epoch1 = build_vault_blob_transcript(&vid, 1);
        assert_ne!(vault, epoch1);
        let other_id = build_master_wrap_transcript(&vid, 0, b"recovery");
        assert_ne!(a, other_id);
    }

    #[test]
    fn extra_fields_are_length_prefixed() {
        let vid = [1u8; 16];
        let t = build_master_wrap_transcript(&vid, 0, b"master");
        // magic(5) + ver(2)+suite(2)+kind(2)+vid(16)+epoch(4) + len(4) + "master"
        assert_eq!(t.len(), 5 + 2 + 2 + 2 + 16 + 4 + 4 + 6);
        let lp = u32::from_le_bytes(t[t.len() - 10..t.len() - 6].try_into().unwrap());
        assert_eq!(lp, 6);
        assert_eq!(&t[t.len() - 6..], b"master");
    }

    #[test]
    fn d1_header_is_little_endian_and_binds_suite_version_kind_epoch() {
        let vid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let t = build_vault_blob_transcript(&vid, 0x0102_0304);
        assert_eq!(&t[0..5], b"Aegis");
        assert_eq!(&t[5..7], &[0x02, 0x00]); // format version 2 LE
        assert_eq!(&t[7..9], &[0x02, 0x00]); // suite 0x0002 LE
        assert_eq!(&t[9..11], &[0x02, 0x00]); // kind VaultBlob 0x0002 LE
        assert_eq!(&t[11..27], &vid);
        assert_eq!(&t[27..31], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(t.len(), 31);

        let master = build_master_wrap_transcript(&vid, 0, b"master");
        assert_eq!(&master[9..11], &[0x01, 0x00]); // kind MasterWrap 0x0001 LE
        assert_eq!(
            &build_audit_blob_transcript(&vid, 0)[9..11],
            &[0x03, 0x00]
        );
        assert_eq!(&build_sync_blob_transcript(&vid, 0)[9..11], &[0x04, 0x00]);
        let rev = build_sync_signing_transcript(
            &vid,
            0x0102_0304,
            b"dev-a",
            7,
            &[0x11; 32],
            &[0x22; 32],
            b"meta",
        );
        assert_eq!(&rev[7..9], &[0x03, 0x00]); // suite 0x0003 LE
        assert_eq!(&rev[9..11], &[0x07, 0x00]); // kind SyncRevision
        let trans = build_sync_transition_transcript(&vid, 0, 1, b"old", b"new");
        assert_eq!(&trans[7..9], &[0x03, 0x00]);
        assert_eq!(&trans[9..11], &[0x08, 0x00]); // kind SyncTransition
        assert_ne!(rev, trans);
        let cid = [0xAAu8; 16];
        let kdf_aad = b"kdf-canon";
        let wrap = build_backup_wrap_transcript(&cid, kdf_aad);
        assert_eq!(&wrap[9..11], &[0x06, 0x00]);
        assert_eq!(&wrap[11..27], &cid);
        let payload = build_backup_payload_transcript(&cid, kdf_aad);
        assert_eq!(&payload[9..11], &[0x05, 0x00]);
        assert_ne!(wrap, payload);
        let wrap2 = build_backup_wrap_transcript(&cid, b"other-kdf");
        assert_ne!(wrap, wrap2);
        let rec = build_recovery_wrap_transcript(&vid, 0x0102_0304);
        assert_eq!(&rec[5..7], &[0x02, 0x00]); // format version 2
        assert_eq!(&rec[7..9], &[0x02, 0x00]); // Core suite 0x0002
        assert_eq!(&rec[9..11], &[0x0C, 0x00]); // kind RecoveryWrap
        assert_eq!(&rec[11..27], &vid);
        assert_eq!(&rec[27..31], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(rec.len(), 31);
        assert_ne!(rec, build_master_wrap_transcript(&vid, 0x0102_0304, b"recovery"));
    }
}
