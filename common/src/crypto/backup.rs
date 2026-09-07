//! v2 encrypted backup: independent BackupKey, never live RootSecret (CRYPTO-V2 §21–25).

use super::aead;
use super::kdf::{derive_backup_wrap_kek, Argon2ParamsV2, KdfContext};
use super::passphrase::validate_v2_passphrase;
use super::magic::{decode_backup_v2, encode_backup_v2};
use super::secret::BackupKey;
use super::suite::{CryptoSuiteId, FORMAT_VERSION_V2};
use super::transcript::{build_backup_payload_transcript, build_backup_wrap_transcript};
use super::v1::CryptoError;
use crate::types::{AuditEvent, VaultDocument};
use serde::{Deserialize, Serialize};

pub const MAX_BACKUP_FILE: usize = 16 * 1024 * 1024;
pub const MAX_CIPHERTEXT: usize = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 50_000;
pub const MAX_FOLDERS: usize = 5_000;
pub const MAX_STRING_LEN: usize = 8 * 1024;
pub const MAX_CUSTOM_FIELDS: usize = 64;
pub const MAX_COLLECTION: usize = 64;
const SNAPSHOT_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupEnvelopeV2 {
    pub format_version: u16,
    pub crypto_suite: CryptoSuiteId,
    #[serde(with = "serde_bytes")]
    pub container_id: Vec<u8>,
    pub kdf: Argon2ParamsV2,
    #[serde(with = "serde_bytes")]
    pub key_wrap_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub wrapped_backup_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub payload_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub encrypted_payload: Vec<u8>,
}

impl BackupEnvelopeV2 {
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

    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(encode_backup_v2(&self.to_cbor()?))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_BACKUP_FILE {
            return Err(CryptoError::ResourceLimit);
        }
        Self::from_cbor(decode_backup_v2(bytes)?)
    }

    fn validate_header(&self) -> Result<(), CryptoError> {
        if self.format_version != FORMAT_VERSION_V2 {
            return Err(CryptoError::UnsupportedVersion(self.format_version));
        }
        self.crypto_suite.require_v2_core()?;
        if self.container_id.len() != 16
            || self.key_wrap_nonce.len() != aead::NONCE_LEN
            || self.payload_nonce.len() != aead::NONCE_LEN
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        if self.wrapped_backup_key.len() > MAX_CIPHERTEXT
            || self.encrypted_payload.len() > MAX_CIPHERTEXT
        {
            return Err(CryptoError::ResourceLimit);
        }
        Ok(())
    }

    pub fn container_id_bytes(&self) -> Result<[u8; 16], CryptoError> {
        self.container_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)
    }

}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupPayloadV2 {
    pub snapshot_version: u16,
    #[serde(with = "serde_bytes")]
    pub original_vault_id: Vec<u8>,
    pub exported_at: u64,
    pub document: VaultDocument,
    #[serde(default)]
    pub audit: Vec<AuditEvent>,
}

pub fn create_backup(
    backup_passphrase: &str,
    original_vault_id: [u8; 16],
    document: &VaultDocument,
    audit: &[AuditEvent],
) -> Result<Vec<u8>, CryptoError> {
    create_backup_with_params(
        backup_passphrase,
        original_vault_id,
        document,
        audit,
        Argon2ParamsV2::generate_v2(),
        &[],
    )
}

pub fn create_backup_with_params(
    backup_passphrase: &str,
    original_vault_id: [u8; 16],
    document: &VaultDocument,
    audit: &[AuditEvent],
    kdf: Argon2ParamsV2,
    forbidden_secrets: &[&[u8]],
) -> Result<Vec<u8>, CryptoError> {
    validate_v2_passphrase(backup_passphrase)?;
    kdf.validate(KdfContext::V2Generate)?;
    validate_payload_document(document)?;

    let mut container_id = [0u8; 16];
    crate::rng::fill_random(&mut container_id);
    let backup_key = BackupKey::random();

    let payload = BackupPayloadV2 {
        snapshot_version: SNAPSHOT_VERSION,
        original_vault_id: original_vault_id.to_vec(),
        exported_at: crate::types::unix_now(),
        document: document.clone(),
        audit: audit.to_vec(),
    };
    reject_secret_bearing_payload(&payload)?;
    let mut payload_cbor = Vec::new();
    ciborium::into_writer(&payload, &mut payload_cbor)
        .map_err(|e| CryptoError::Serde(e.to_string()))?;
    if payload_cbor.len() > MAX_CIPHERTEXT {
        return Err(CryptoError::ResourceLimit);
    }
    assert_plaintext_has_no_live_secrets(&payload_cbor, forbidden_secrets)?;

    let kdf_aad = kdf.aad_bytes();
    let wrap_aad = build_backup_wrap_transcript(&container_id, &kdf_aad);
    let payload_aad = build_backup_payload_transcript(&container_id, &kdf_aad);
    let kek = derive_backup_wrap_kek(backup_passphrase, &kdf, KdfContext::V2Generate)?;
    let (key_wrap_nonce, wrapped_backup_key) =
        aead::seal(kek.as_bytes(), &wrap_aad, backup_key.as_bytes())?;
    let (payload_nonce, encrypted_payload) =
        aead::seal(backup_key.as_bytes(), &payload_aad, &payload_cbor)?;

    let env = BackupEnvelopeV2 {
        format_version: FORMAT_VERSION_V2,
        crypto_suite: CryptoSuiteId::AegisV2Core2026,
        container_id: container_id.to_vec(),
        kdf,
        key_wrap_nonce: key_wrap_nonce.to_vec(),
        wrapped_backup_key,
        payload_nonce: payload_nonce.to_vec(),
        encrypted_payload,
    };
    let bytes = env.to_bytes()?;
    if bytes.len() > MAX_BACKUP_FILE {
        return Err(CryptoError::ResourceLimit);
    }
    Ok(bytes)
}

/// Authenticate a backup fully in memory. Does not touch a store. D12 before Argon2.
pub fn authenticate_backup(
    bytes: &[u8],
    backup_passphrase: &str,
) -> Result<BackupPayloadV2, CryptoError> {
    if bytes.len() > MAX_BACKUP_FILE {
        return Err(CryptoError::ResourceLimit);
    }
    let env = BackupEnvelopeV2::from_bytes(bytes)?;
    env.kdf.validate(KdfContext::V2Import)?;
    let container_id = env.container_id_bytes()?;
    let kdf_aad = env.kdf.aad_bytes();
    let kek = derive_backup_wrap_kek(backup_passphrase, &env.kdf, KdfContext::V2Import)?;

    let wrap_aad = build_backup_wrap_transcript(&container_id, &kdf_aad);
    let key_pt = aead::open(
        kek.as_bytes(),
        &env.key_wrap_nonce,
        &wrap_aad,
        &env.wrapped_backup_key,
    )?;
    if key_pt.len() != 32 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_pt);
    let backup_key = BackupKey::from_bytes(key_arr);

    let payload_aad = build_backup_payload_transcript(&container_id, &kdf_aad);
    let payload_pt = aead::open(
        backup_key.as_bytes(),
        &env.payload_nonce,
        &payload_aad,
        &env.encrypted_payload,
    )?;
    let payload: BackupPayloadV2 =
        ciborium::from_reader(payload_pt.as_slice()).map_err(|e| CryptoError::Serde(e.to_string()))?;
    if payload.snapshot_version != SNAPSHOT_VERSION {
        return Err(CryptoError::UnsupportedVersion(payload.snapshot_version));
    }
    if payload.original_vault_id.len() != 16 {
        return Err(CryptoError::InvalidEnvelope);
    }
    reject_secret_bearing_payload(&payload)?;
    validate_payload_document(&payload.document)?;
    Ok(payload)
}

pub fn validate_payload_document(doc: &VaultDocument) -> Result<(), CryptoError> {
    if doc.entries.len() > MAX_ENTRIES || doc.folders.len() > MAX_FOLDERS {
        return Err(CryptoError::ResourceLimit);
    }
    for folder in doc.folders.values() {
        check_str(&folder.id)?;
        check_str(&folder.name)?;
    }
    for entry in doc.entries.values() {
        check_str(&entry.id)?;
        check_str(&entry.name)?;
        check_str(&entry.username)?;
        check_str(&entry.password)?;
        check_str(&entry.notes)?;
        if entry.urls.len() > MAX_COLLECTION || entry.tags.len() > MAX_COLLECTION {
            return Err(CryptoError::ResourceLimit);
        }
        if entry.custom_fields.len() > MAX_CUSTOM_FIELDS {
            return Err(CryptoError::ResourceLimit);
        }
        for u in &entry.urls {
            check_str(u)?;
        }
        for t in &entry.tags {
            check_str(t)?;
        }
        for cf in &entry.custom_fields {
            check_str(&cf.id)?;
            check_str(&cf.name)?;
            check_str(&cf.value)?;
        }
        if let Some(totp) = &entry.totp_secret {
            check_str(totp)?;
        }
        for h in &entry.password_history {
            check_str(&h.password)?;
        }
    }
    Ok(())
}

fn check_str(s: &str) -> Result<(), CryptoError> {
    if s.len() > MAX_STRING_LEN {
        Err(CryptoError::ResourceLimit)
    } else {
        Ok(())
    }
}

const FORBIDDEN_PAYLOAD_KEYS: &[&str] = &[
    "root_secret",
    "wrapped_root_secret",
    "vault_dek",
    "audit_dek",
    "sync_dek",
    "search_hmac",
    "recovery_secret",
    "recovery_kek",
    "backup_key",
    "kek",
    "wrap_kek",
    "sync_ed25519_seed",
    "sync_mldsa_seed",
    "share_x25519_seed",
    "share_mlkem_seed",
    "master",
    "session",
];

fn reject_secret_bearing_payload(payload: &BackupPayloadV2) -> Result<(), CryptoError> {
    let mut cbor = Vec::new();
    ciborium::into_writer(payload, &mut cbor).map_err(|e| CryptoError::Serde(e.to_string()))?;
    let value: ciborium::value::Value =
        ciborium::from_reader(cbor.as_slice()).map_err(|e| CryptoError::Serde(e.to_string()))?;
    let ciborium::value::Value::Map(map) = value else {
        return Err(CryptoError::InvalidEnvelope);
    };
    for (k, _) in &map {
        let ciborium::value::Value::Text(name) = k else {
            continue;
        };
        if FORBIDDEN_PAYLOAD_KEYS.iter().any(|f| *f == name.as_str()) {
            return Err(CryptoError::InvalidEnvelope);
        }
    }
    Ok(())
}

fn contains_secret(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() >= 16 && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Scan bytes for a secret (tests + plaintext isolation).
pub fn backup_contains_secret(haystack: &[u8], secret: &[u8; 32]) -> bool {
    contains_secret(haystack, secret)
}

fn assert_plaintext_has_no_live_secrets(
    plaintext: &[u8],
    secrets: &[&[u8]],
) -> Result<(), CryptoError> {
    for s in secrets {
        if contains_secret(plaintext, s) {
            return Err(CryptoError::InvalidEnvelope);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{Argon2ParamsV2, V2_MIN_MEMORY_KIB};
    use crate::crypto::secret::RootSecret;
    use crate::crypto::magic::{CONTAINER_VERSION_V2, MAGIC_BACKUP_V2, MAGIC_VAULT_V2};
    use crate::types::{unix_now, Entry, VaultMeta};

    fn vid() -> [u8; 16] {
        [0x42; 16]
    }

    fn sample_doc() -> VaultDocument {
        let mut doc = VaultDocument {
            meta: VaultMeta {
                vault_id: hex::encode(vid()),
                format_version: 2,
                created_at: unix_now(),
                updated_at: unix_now(),
                device_id: "dev1".into(),
            },
            ..Default::default()
        };
        let mut e = Entry::new("e1", "GitHub");
        e.password = "hunter2-not-identity".into();
        e.username = "octocat".into();
        doc.entries.insert(e.id.clone(), e);
        doc
    }

    #[test]
    fn backup_file_is_magic_then_version_then_cbor() {
        let bytes = create_backup("backup-pass-word", vid(), &sample_doc(), &[]).unwrap();
        assert_eq!(&bytes[..16], b"AEGIS_BACKUP_V2\x02");
        assert_eq!(&bytes[..MAGIC_BACKUP_V2.len()], MAGIC_BACKUP_V2);
        assert_eq!(bytes[MAGIC_BACKUP_V2.len()], CONTAINER_VERSION_V2);
        assert_ne!(&bytes[..14], MAGIC_VAULT_V2);
        let payload = authenticate_backup(&bytes, "backup-pass-word").unwrap();
        assert_eq!(
            payload.document.entries["e1"].password,
            "hunter2-not-identity"
        );
        assert_eq!(payload.original_vault_id, vid());
        assert!(authenticate_backup(&bytes, "wrong-pass-word").is_err());
    }

    #[test]
    fn backup_rejects_bad_magic_and_version_before_cbor() {
        let bytes = create_backup("backup-pass-word", vid(), &sample_doc(), &[]).unwrap();
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert_eq!(
            BackupEnvelopeV2::from_bytes(&bad),
            Err(CryptoError::InvalidMagic)
        );
        let mut ver = bytes.clone();
        ver[MAGIC_BACKUP_V2.len()] = 0x01;
        assert_eq!(
            BackupEnvelopeV2::from_bytes(&ver),
            Err(CryptoError::UnsupportedVersion(1))
        );
        assert_eq!(
            BackupEnvelopeV2::from_bytes(&bytes[MAGIC_BACKUP_V2.len() + 1..]),
            Err(CryptoError::InvalidMagic)
        );
        let env = BackupEnvelopeV2::from_bytes(&bytes).unwrap();
        assert_eq!(env.kdf.memory_kib, 64 * 1024);
        assert!(env.kdf.memory_kib >= V2_MIN_MEMORY_KIB);
    }

    #[test]
    fn d12_rejects_hostile_kdf_before_argon2() {
        let bytes = create_backup("backup-pass-word", vid(), &sample_doc(), &[]).unwrap();
        let mut env = BackupEnvelopeV2::from_bytes(&bytes).unwrap();
        env.kdf.memory_kib = 256 * 1024;
        env.kdf.iterations = 8;
        let framed = env.to_bytes().unwrap();
        let err = authenticate_backup(&framed, "backup-pass-word").unwrap_err();
        assert_eq!(err, CryptoError::InvalidKdfParams);
        env.kdf.memory_kib = 32 * 1024;
        env.kdf.iterations = 2;
        let framed = env.to_bytes().unwrap();
        assert_eq!(
            authenticate_backup(&framed, "backup-pass-word").unwrap_err(),
            CryptoError::InvalidKdfParams
        );
    }

    #[test]
    fn d12_rejects_oversized_file_before_parse() {
        let huge = vec![0u8; MAX_BACKUP_FILE + 1];
        assert_eq!(
            BackupEnvelopeV2::from_bytes(&huge),
            Err(CryptoError::ResourceLimit)
        );
        assert_eq!(
            authenticate_backup(&huge, "backup-pass-word"),
            Err(CryptoError::ResourceLimit)
        );
    }

    #[test]
    fn backup_generate_rejects_below_64_mib() {
        let mut kdf = Argon2ParamsV2::insecure_for_tests();
        kdf.memory_kib = 32 * 1024;
        kdf.iterations = 2;
        assert!(create_backup_with_params(
            "backup-pass-word",
            vid(),
            &sample_doc(),
            &[],
            kdf,
            &[],
        )
        .is_err());
    }

    #[test]
    fn backup_api_rejects_short_passphrase() {
        let doc = sample_doc();
        assert!(create_backup("", vid(), &doc, &[]).is_err());
        assert!(create_backup("short", vid(), &doc, &[]).is_err());
        assert!(create_backup("12345678", vid(), &doc, &[]).is_err());
        assert!(create_backup("password", vid(), &doc, &[]).is_err());
        assert!(create_backup("aaaaaaaaaaaa", vid(), &doc, &[]).is_err());
    }

    #[test]
    fn plaintext_payload_must_not_contain_live_secrets() {
        let root = RootSecret::from_bytes([0x11; 32]);
        let dek = [0x22u8; 32];
        let mut doc = sample_doc();
        doc.entries.get_mut("e1").unwrap().notes = String::from_utf8(root.as_bytes().to_vec()).unwrap();
        assert!(create_backup_with_params(
            "backup-pass-word",
            vid(),
            &doc,
            &[],
            Argon2ParamsV2::generate_v2(),
            &[root.as_bytes().as_slice(), dek.as_slice()],
        )
        .is_err());
    }

    #[test]
    fn payload_type_has_no_secret_bearing_fields() {
        let payload = BackupPayloadV2 {
            snapshot_version: 2,
            original_vault_id: vid().to_vec(),
            exported_at: 0,
            document: sample_doc(),
            audit: vec![],
        };
        reject_secret_bearing_payload(&payload).unwrap();

        #[derive(Serialize)]
        struct Planted {
            snapshot_version: u16,
            #[serde(with = "serde_bytes")]
            original_vault_id: Vec<u8>,
            exported_at: u64,
            document: VaultDocument,
            audit: Vec<crate::types::AuditEvent>,
            root_secret: Vec<u8>,
        }
        let fake = Planted {
            snapshot_version: 2,
            original_vault_id: vid().to_vec(),
            exported_at: 0,
            document: sample_doc(),
            audit: vec![],
            root_secret: vec![0x11; 32],
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&fake, &mut bytes).unwrap();
        assert!(
            BackupPayloadV2::try_from_cbor_for_test(&bytes).is_err(),
            "extra secret field must fail deny_unknown_fields"
        );
    }

    #[test]
    fn original_vault_id_is_not_on_public_envelope() {
        let bytes = create_backup("backup-pass-word", vid(), &sample_doc(), &[]).unwrap();
        let env = BackupEnvelopeV2::from_bytes(&bytes).unwrap();
        let outer = env.to_cbor().unwrap();
        let value: ciborium::value::Value = ciborium::from_reader(outer.as_slice()).unwrap();
        let ciborium::value::Value::Map(map) = value else {
            panic!("envelope is not a map");
        };
        let keys: Vec<String> = map
            .iter()
            .filter_map(|(k, _)| match k {
                ciborium::value::Value::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        assert!(
            !keys.iter().any(|k| k == "original_vault_id"),
            "public envelope keys: {keys:?}"
        );
        let payload = authenticate_backup(&bytes, "backup-pass-word").unwrap();
        assert_eq!(payload.original_vault_id, vid());
    }

    #[test]
    fn aad_binds_container_id_and_kdf() {
        let bytes = create_backup("backup-pass-word", vid(), &sample_doc(), &[]).unwrap();
        let mut env = BackupEnvelopeV2::from_bytes(&bytes).unwrap();
        env.container_id = [0x77; 16].to_vec();
        assert!(authenticate_backup(&env.to_bytes().unwrap(), "backup-pass-word").is_err());
        let mut env = BackupEnvelopeV2::from_bytes(&bytes).unwrap();
        env.kdf.salt[0] ^= 1;
        assert!(authenticate_backup(&env.to_bytes().unwrap(), "backup-pass-word").is_err());
    }
}

impl BackupPayloadV2 {
    #[cfg(test)]
    fn try_from_cbor_for_test(bytes: &[u8]) -> Result<Self, CryptoError> {
        ciborium::from_reader(bytes).map_err(|e| CryptoError::Serde(e.to_string()))
    }
}
