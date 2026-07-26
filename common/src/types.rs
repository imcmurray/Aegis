//! Vault document types (plaintext — only ever live unlocked inside the delegate).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type FolderId = String;
pub type EntryId = String;
pub type FieldId = String;
pub type ItemId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultMeta {
    /// Random vault identifier (16 bytes, hex-encoded for JSON/TS ergonomics).
    pub vault_id: String,
    pub format_version: u16,
    pub created_at: u64,
    pub updated_at: u64,
    /// Stable id for this device (used in CRDT version vectors).
    pub device_id: String,
}

impl Default for VaultMeta {
    fn default() -> Self {
        Self {
            vault_id: String::new(),
            format_version: 1,
            created_at: 0,
            updated_at: 0,
            device_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VaultDocument {
    pub meta: VaultMeta,
    pub folders: BTreeMap<FolderId, Folder>,
    pub entries: BTreeMap<EntryId, Entry>,
    pub deleted: BTreeMap<ItemId, Tombstone>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Folder {
    pub id: FolderId,
    pub name: String,
    pub parent: Option<FolderId>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub id: EntryId,
    pub folder_id: Option<FolderId>,
    /// Display name, e.g. "GitHub".
    pub name: String,
    /// URL match patterns for autofill.
    pub urls: Vec<String>,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub custom_fields: Vec<CustomField>,
    pub tags: Vec<String>,
    /// Optional TOTP secret (Base32), e.g. from an authenticator setup key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    /// Previous passwords for this entry (newest first). Capped server-side.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_history: Vec<PasswordHistoryItem>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Entry {
    pub const MAX_PASSWORD_HISTORY: usize = 10;

    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let now = unix_now();
        Self {
            id: id.into(),
            folder_id: None,
            name: name.into(),
            urls: Vec::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
            custom_fields: Vec::new(),
            tags: Vec::new(),
            totp_secret: None,
            password_history: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordHistoryItem {
    pub password: String,
    pub changed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomField {
    pub id: FieldId,
    pub name: String,
    pub value: String,
    pub kind: FieldKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    #[default]
    Text,
    Hidden,
    Boolean,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    pub deleted_at: u64,
    pub device_id: String,
}

/// Summary safe to list in UI (still sensitive metadata — only after unlock).
///
/// Includes feature flags so the list can show content pills without loading
/// full entry secrets (password/TOTP values are never included).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: EntryId,
    pub folder_id: Option<FolderId>,
    pub name: String,
    pub urls: Vec<String>,
    pub username: String,
    pub tags: Vec<String>,
    pub updated_at: u64,
    /// Non-empty password field.
    #[serde(default)]
    pub has_password: bool,
    /// Non-empty username field.
    #[serde(default)]
    pub has_username: bool,
    /// TOTP seed configured.
    #[serde(default)]
    pub has_totp: bool,
    /// Non-empty notes.
    #[serde(default)]
    pub has_notes: bool,
    /// At least one URL.
    #[serde(default)]
    pub has_url: bool,
    /// Number of custom fields (0 = none).
    #[serde(default)]
    pub custom_field_count: u32,
    /// Password history present.
    #[serde(default)]
    pub has_history: bool,
}

impl From<&Entry> for EntrySummary {
    fn from(e: &Entry) -> Self {
        Self {
            id: e.id.clone(),
            folder_id: e.folder_id.clone(),
            name: e.name.clone(),
            urls: e.urls.clone(),
            username: e.username.clone(),
            tags: e.tags.clone(),
            updated_at: e.updated_at,
            has_password: !e.password.is_empty(),
            has_username: !e.username.is_empty(),
            has_totp: e
                .totp_secret
                .as_ref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false),
            has_notes: !e.notes.trim().is_empty(),
            has_url: e.urls.iter().any(|u| !u.trim().is_empty()),
            custom_field_count: e.custom_fields.len() as u32,
            has_history: !e.password_history.is_empty(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub ts: u64,
    pub kind: AuditKind,
    pub entry_id: Option<EntryId>,
    /// Human-readable detail — must never contain secrets.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    CreateVault,
    Unlock,
    Lock,
    View,
    Copy,
    Create,
    Update,
    Delete,
    Export,
    Import,
    GeneratePassword,
    Sync,
    Share,
    ChangePassphrase,
    HealthCheck,
    GenerateRecovery,
    UnlockRecovery,
    RevokeRecovery,
}

/// Unix time in seconds. Returns 0 if the system clock is unavailable.
pub fn unix_now() -> u64 {
    #[cfg(feature = "freenet-host")]
    {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            return freenet_stdlib::time::now().timestamp().max(0) as u64;
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            return SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        }
    }

    #[cfg(not(feature = "freenet-host"))]
    {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            // Browser / non-Freenet WASM: js Date
            return (js_sys::Date::now() / 1000.0).floor().max(0.0) as u64;
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }
    }
}

/// Random hex id (16 bytes → 32 hex chars).
pub fn new_id() -> String {
    let mut buf = [0u8; 16];
    crate::rng::fill_random(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_roundtrip_cbor() {
        let mut e = Entry::new("abc", "GitHub");
        e.username = "alice".into();
        e.password = "s3cret".into();
        e.urls.push("https://github.com".into());

        let mut bytes = Vec::new();
        ciborium::into_writer(&e, &mut bytes).unwrap();
        let back: Entry = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(e, back);
    }
}
