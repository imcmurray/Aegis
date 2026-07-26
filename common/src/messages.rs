//! UI ↔ Vault Delegate message protocol (CBOR over ApplicationMessage payload).

use crate::crypto::{GeneratorPolicy, KdfProfile};
use crate::health::HealthReport;
use crate::types::{AuditEvent, Entry, EntryId, EntrySummary, Folder, FolderId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum VaultRequest {
    /// Create a new vault. Fails if one already exists in this delegate.
    CreateVault {
        passphrase: String,
        #[serde(default)]
        kdf_profile: KdfProfile,
    },
    Unlock {
        passphrase: String,
    },
    Lock,
    /// Whether a vault envelope exists and whether the session is unlocked.
    Status,
    ListSummaries {
        /// Optional substring filter (name, username, url, tags) — applied after decrypt.
        #[serde(default)]
        query: Option<String>,
    },
    GetEntry {
        id: EntryId,
    },
    UpsertEntry {
        entry: Entry,
    },
    DeleteEntry {
        id: EntryId,
    },
    UpsertFolder {
        folder: Folder,
    },
    DeleteFolder {
        id: FolderId,
    },
    ListFolders,
    GeneratePassword {
        #[serde(default)]
        policy: GeneratorPolicy,
    },
    /// Encrypted backup blob (MasterEnvelope + sealed vault), for offline export.
    ExportEncrypted {
        /// Passphrase used to re-wrap export (defaults to requiring unlocked session + this pw).
        passphrase: String,
    },
    ImportEncrypted {
        #[serde(with = "serde_bytes")]
        blob: Vec<u8>,
        passphrase: String,
        /// If true, wipe existing vault secrets and replace (re-sync another browser).
        #[serde(default)]
        replace: bool,
    },
    GetAuditLog {
        #[serde(default)]
        limit: Option<u32>,
    },
    /// Push/pull encrypted vault via sync transport (file or secret-store MVR).
    SyncNow,
    /// Multi-device: merge optional remote VaultSyncState (contract CBOR), sync,
    /// return state blob for the UI to Put on the VaultSync contract.
    SyncWithRemote {
        /// CBOR-encoded [`crate::sync_types::VaultSyncState`] from the network.
        /// Empty = no remote yet (first publish).
        #[serde(default, with = "serde_bytes")]
        remote_state: Vec<u8>,
    },
    /// Compute a TOTP code from a Base32 secret (does not log the secret).
    GenerateTotp {
        secret: String,
        #[serde(default)]
        period: Option<u64>,
        #[serde(default)]
        digits: Option<u32>,
    },
    /// Re-wrap MasterSecret under a new passphrase (vault DEK unchanged).
    ChangePassphrase {
        current_passphrase: String,
        new_passphrase: String,
        #[serde(default)]
        kdf_profile: Option<KdfProfile>,
    },
    /// Local password-health report (no network).
    PasswordHealth,
    /// Create/replace recovery key envelope; returns the key once (store offline).
    GenerateRecoveryKey {
        #[serde(default)]
        kdf_profile: Option<KdfProfile>,
    },
    /// Unlock using a recovery key instead of the master passphrase.
    UnlockWithRecovery {
        recovery_key: String,
    },
    /// Remove recovery key envelope (cannot unlock via recovery afterward).
    RevokeRecoveryKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VaultResponse {
    Ok,
    Status {
        has_vault: bool,
        unlocked: bool,
        vault_id: Option<String>,
        #[serde(default)]
        has_recovery: bool,
    },
    Unlocked {
        vault_id: String,
    },
    Locked,
    Summaries {
        entries: Vec<EntrySummary>,
    },
    Entry {
        entry: Entry,
    },
    Folders {
        folders: Vec<Folder>,
    },
    Password {
        password: String,
    },
    Totp {
        code: String,
        /// Seconds remaining in the current period.
        seconds_remaining: u32,
        period: u32,
    },
    Export {
        #[serde(with = "serde_bytes")]
        blob: Vec<u8>,
    },
    Audit {
        events: Vec<AuditEvent>,
    },
    /// Result of a multi-device sync attempt.
    Synced {
        action: String,
        remote_revisions: u32,
        detail: String,
        /// Full VaultSyncState CBOR — UI should Put/Update this on VaultSync.
        /// Empty when the transport was file-only (dev) and no publish blob was built.
        #[serde(default, with = "serde_bytes")]
        contract_state: Vec<u8>,
        /// Ed25519 owner verifying key (32) — Freenet identity for this vault.
        #[serde(default, with = "serde_bytes")]
        owner_verifying_key: Vec<u8>,
        /// CBOR [`crate::sync_types::VaultSyncParams`] for contract instance address.
        #[serde(default, with = "serde_bytes")]
        sync_params: Vec<u8>,
    },
    Health {
        report: HealthReport,
    },
    /// Shown only once when generating a recovery key — never logged server-side.
    RecoveryKey {
        recovery_key: String,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotFound,
    AlreadyExists,
    Locked,
    Unlocked,
    AuthFailed,
    InvalidRequest,
    Crypto,
    Storage,
    NotImplemented,
    Internal,
}

impl VaultRequest {
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| e.to_string())?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(bytes).map_err(|e| e.to_string())
    }
}

impl VaultResponse {
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| e.to_string())?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(bytes).map_err(|e| e.to_string())
    }

    pub fn err(code: ErrorCode, message: impl Into<String>) -> Self {
        VaultResponse::Error {
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_cbor() {
        let req = VaultRequest::Status;
        let bytes = req.to_cbor().unwrap();
        let back = VaultRequest::from_cbor(&bytes).unwrap();
        assert_eq!(req, back);

        let resp = VaultResponse::Status {
            has_vault: true,
            unlocked: false,
            vault_id: Some("abc".into()),
            has_recovery: false,
        };
        let bytes = resp.to_cbor().unwrap();
        let back = VaultResponse::from_cbor(&bytes).unwrap();
        assert_eq!(resp, back);
    }

    /// Golden vectors for TypeScript CBOR interop (`ui/src/cbor.test` / fixtures).
    #[test]
    fn golden_vectors_stable() {
        let cases: Vec<(&str, VaultRequest)> = vec![
            ("status", VaultRequest::Status),
            ("lock", VaultRequest::Lock),
            (
                "unlock",
                VaultRequest::Unlock {
                    passphrase: "secret".into(),
                },
            ),
            (
                "create_vault",
                VaultRequest::CreateVault {
                    passphrase: "secret".into(),
                    kdf_profile: KdfProfile::Test,
                },
            ),
            (
                "list_summaries_none",
                VaultRequest::ListSummaries { query: None },
            ),
            (
                "list_summaries_q",
                VaultRequest::ListSummaries {
                    query: Some("git".into()),
                },
            ),
            (
                "get_entry",
                VaultRequest::GetEntry {
                    id: "deadbeef".into(),
                },
            ),
            (
                "delete_entry",
                VaultRequest::DeleteEntry {
                    id: "deadbeef".into(),
                },
            ),
            ("list_folders", VaultRequest::ListFolders),
            ("sync_now", VaultRequest::SyncNow),
            (
                "generate_password",
                VaultRequest::GeneratePassword {
                    policy: GeneratorPolicy {
                        length: 20,
                        uppercase: true,
                        lowercase: true,
                        digits: true,
                        symbols: true,
                        memorable: false,
                        word_count: 5,
                    },
                },
            ),
        ];

        for (name, req) in cases {
            let bytes = req.to_cbor().unwrap();
            let round = VaultRequest::from_cbor(&bytes).unwrap();
            assert_eq!(round, req, "request {name}");
            // Ensure non-empty and starts with a CBOR map (major type 5 → 0xa0-0xbf or 0xb8..)
            assert!(!bytes.is_empty(), "{name} empty");
            let first = bytes[0];
            assert!(
                (0xa0..=0xbf).contains(&first) || first == 0xb8 || first == 0xb9,
                "{name}: expected map, got 0x{first:02x}"
            );
        }

        let resp_cases = vec![
            VaultResponse::Ok,
            VaultResponse::Locked,
            VaultResponse::Unlocked {
                vault_id: "vid".into(),
            },
            VaultResponse::Status {
                has_vault: false,
                unlocked: false,
                vault_id: None,
                has_recovery: false,
            },
            VaultResponse::Password {
                password: "xY9!".into(),
            },
            VaultResponse::err(ErrorCode::Locked, "vault is locked"),
            VaultResponse::Export {
                blob: vec![0xde, 0xad, 0xbe, 0xef],
            },
        ];
        for resp in resp_cases {
            let bytes = resp.to_cbor().unwrap();
            let round = VaultResponse::from_cbor(&bytes).unwrap();
            assert_eq!(round, resp);
        }
    }

    #[test]
    fn print_golden_hex_for_ts() {
        // Run with: cargo test -p aegis-common print_golden_hex -- --nocapture
        let req = VaultRequest::Status;
        println!("STATUS_REQ={}", hex::encode(req.to_cbor().unwrap()));
        let req = VaultRequest::Unlock {
            passphrase: "secret".into(),
        };
        println!("UNLOCK_REQ={}", hex::encode(req.to_cbor().unwrap()));
        let resp = VaultResponse::Status {
            has_vault: true,
            unlocked: false,
            vault_id: Some("abc".into()),
            has_recovery: false,
        };
        println!("STATUS_RESP={}", hex::encode(resp.to_cbor().unwrap()));
        let resp = VaultResponse::Export {
            blob: vec![1, 2, 3, 4],
        };
        println!("EXPORT_RESP={}", hex::encode(resp.to_cbor().unwrap()));
    }

    /// cbor-x may emit longer definite-length map headers (e.g. 0xb9 00 01 …).
    /// Ensure ciborium still accepts those encodings.
    #[test]
    fn decode_cborx_style_status_map() {
        // b9 00 01 = map(1 as u16), 62 6f 70 = "op", 66 73 74 61 74 75 73 = "status"
        let cborx = hex::decode("b90001626f7066737461747573").unwrap();
        let req = VaultRequest::from_cbor(&cborx).unwrap();
        assert_eq!(req, VaultRequest::Status);

        // Compact form from ciborium
        let compact = hex::decode("a1626f7066737461747573").unwrap();
        assert_eq!(
            VaultRequest::from_cbor(&compact).unwrap(),
            VaultRequest::Status
        );
    }
}
