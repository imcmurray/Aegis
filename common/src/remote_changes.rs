//! Device-local remote change log (D22).
//!
//! After a sync that pulls changes from another device, the delegate records
//! *which* entries changed and *which fields* changed, never secret values. The
//! log is sealed under its own DEK, stored at `aegis/v2/remote-changes`, and is
//! never exported, linked or synced.

use crate::crypto::{
    open_remote_changes_v2, seal_remote_changes_v2, RemoteChangesBlobV2, RemoteChangesDek,
};
use crate::types::{CustomField, Entry, EntryId, FieldKind, VaultDocument};
use crate::vault::{SecretStore, VaultError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SECRET_REMOTE_CHANGES_V2: &[u8] = b"aegis/v2/remote-changes";
pub const MAX_REMOTE_CHANGES: usize = 500;
pub const REMOTE_CHANGES_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;
pub const REMOTE_CHANGES_LOG_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteChangeKind {
    Added,
    Modified,
    Deleted,
}

/// Non-secret value. CBOR: text string or array of text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ChangeValue {
    Text(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldChange {
    /// "name"|"username"|"password"|"urls"|"notes"|"tags"|"folder"|"totp"|"custom:<field id>"
    pub field: String,
    /// Custom fields only: the field's display name (new name, else old). Never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<ChangeValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<ChangeValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteChange {
    pub entry_id: EntryId,
    pub kind: RemoteChangeKind,
    pub changed_at: u64,
    /// When this device recorded/last updated the record (30-day + cap pruning).
    #[serde(default)]
    pub recorded_at: u64,
    /// Deleted records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteChangeSummary {
    pub kind: RemoteChangeKind,
    pub changed_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteChangeLog {
    pub v: u16,
    pub records: Vec<RemoteChange>,
}

/// Borrowed view used to serialize with the current log version.
#[derive(Serialize)]
struct LogRef<'a> {
    v: u16,
    records: &'a [RemoteChange],
}

fn text(s: &str) -> Option<ChangeValue> {
    Some(ChangeValue::Text(s.to_string()))
}

fn list(v: &[String]) -> Option<ChangeValue> {
    Some(ChangeValue::List(v.to_vec()))
}

fn folder_name(entry: &Entry, doc: &VaultDocument) -> String {
    entry
        .folder_id
        .as_ref()
        .and_then(|id| doc.folders.get(id))
        .map(|f| f.name.clone())
        .unwrap_or_default()
}

fn valueless(field: &str) -> FieldChange {
    FieldChange {
        field: field.to_string(),
        label: None,
        old: None,
        new: None,
    }
}

fn custom_key(id: &str) -> String {
    format!("custom:{id}")
}

/// Pure diff of two entries (non-secret values only), canonical field order.
pub fn diff_entry_fields(
    old: &Entry,
    old_doc: &VaultDocument,
    new: &Entry,
    new_doc: &VaultDocument,
) -> Vec<FieldChange> {
    let mut out = Vec::new();
    if old.name != new.name {
        out.push(FieldChange {
            field: "name".into(),
            label: None,
            old: text(&old.name),
            new: text(&new.name),
        });
    }
    if old.username != new.username {
        out.push(FieldChange {
            field: "username".into(),
            label: None,
            old: text(&old.username),
            new: text(&new.username),
        });
    }
    if old.password != new.password {
        out.push(valueless("password"));
    }
    if old.urls != new.urls {
        out.push(FieldChange {
            field: "urls".into(),
            label: None,
            old: list(&old.urls),
            new: list(&new.urls),
        });
    }
    if old.notes != new.notes {
        out.push(valueless("notes"));
    }
    if old.tags != new.tags {
        out.push(FieldChange {
            field: "tags".into(),
            label: None,
            old: list(&old.tags),
            new: list(&new.tags),
        });
    }
    if old.folder_id != new.folder_id {
        out.push(FieldChange {
            field: "folder".into(),
            label: None,
            old: text(&folder_name(old, old_doc)),
            new: text(&folder_name(new, new_doc)),
        });
    }
    if old.totp_secret != new.totp_secret {
        out.push(valueless("totp"));
    }

    let old_by_id: BTreeMap<&str, &CustomField> = old
        .custom_fields
        .iter()
        .map(|c| (c.id.as_str(), c))
        .collect();
    let new_ids: std::collections::BTreeSet<&str> =
        new.custom_fields.iter().map(|c| c.id.as_str()).collect();

    for nf in &new.custom_fields {
        match old_by_id.get(nf.id.as_str()) {
            None => {
                let mut fc = FieldChange {
                    field: custom_key(&nf.id),
                    label: Some(nf.name.clone()),
                    old: None,
                    new: None,
                };
                if nf.kind != FieldKind::Hidden {
                    fc.new = text(&nf.value);
                }
                out.push(fc);
            }
            Some(of) => {
                if of.name != nf.name || of.value != nf.value || of.kind != nf.kind {
                    let mut fc = FieldChange {
                        field: custom_key(&nf.id),
                        label: Some(nf.name.clone()),
                        old: None,
                        new: None,
                    };
                    if of.kind != FieldKind::Hidden && nf.kind != FieldKind::Hidden {
                        fc.old = text(&of.value);
                        fc.new = text(&nf.value);
                    }
                    out.push(fc);
                }
            }
        }
    }
    for of in &old.custom_fields {
        if !new_ids.contains(of.id.as_str()) {
            let mut fc = FieldChange {
                field: custom_key(&of.id),
                label: Some(of.name.clone()),
                old: None,
                new: None,
            };
            if of.kind != FieldKind::Hidden {
                fc.old = text(&of.value);
            }
            out.push(fc);
        }
    }
    out
}

fn record_time(r: &RemoteChange) -> u64 {
    if r.recorded_at == 0 {
        r.changed_at
    } else {
        r.recorded_at
    }
}

impl RemoteChangeLog {
    pub fn new() -> Self {
        Self {
            v: REMOTE_CHANGES_LOG_VERSION,
            records: Vec::new(),
        }
    }

    /// Compare pre-merge `before` with merged `after`; returns entries observed changed
    /// (distinct entry ids) and folds them into the log.
    pub fn record_merge(&mut self, before: &VaultDocument, after: &VaultDocument, now: u64) -> u32 {
        let nz = |t: u64| if t == 0 { now } else { t };
        let mut observed: Vec<RemoteChange> = Vec::new();

        for (id, new_entry) in &after.entries {
            match before.entries.get(id) {
                None => observed.push(RemoteChange {
                    entry_id: id.clone(),
                    kind: RemoteChangeKind::Added,
                    changed_at: nz(new_entry.updated_at),
                    recorded_at: now,
                    entry_name: None,
                    fields: Vec::new(),
                }),
                Some(old_entry) => {
                    let fields = diff_entry_fields(old_entry, before, new_entry, after);
                    if !fields.is_empty() {
                        observed.push(RemoteChange {
                            entry_id: id.clone(),
                            kind: RemoteChangeKind::Modified,
                            changed_at: nz(new_entry.updated_at),
                            recorded_at: now,
                            entry_name: None,
                            fields,
                        });
                    }
                }
            }
        }
        for (id, old_entry) in &before.entries {
            if !after.entries.contains_key(id) {
                let at = after.deleted.get(id).map(|t| t.deleted_at).unwrap_or(0);
                observed.push(RemoteChange {
                    entry_id: id.clone(),
                    kind: RemoteChangeKind::Deleted,
                    changed_at: nz(at),
                    recorded_at: now,
                    entry_name: Some(old_entry.name.clone()),
                    fields: Vec::new(),
                });
            }
        }

        let n = observed.len() as u32;
        for obs in observed {
            self.fold(obs);
        }
        n
    }

    fn fold(&mut self, n: RemoteChange) {
        let Some(pos) = self.records.iter().position(|r| r.entry_id == n.entry_id) else {
            self.records.push(n);
            return;
        };
        let r_kind = self.records[pos].kind;
        match (r_kind, n.kind) {
            (RemoteChangeKind::Added, RemoteChangeKind::Modified) => {
                let r = &mut self.records[pos];
                r.changed_at = n.changed_at;
                r.recorded_at = n.recorded_at;
                r.fields.clear();
            }
            (RemoteChangeKind::Added, RemoteChangeKind::Deleted) => {
                self.records.remove(pos);
            }
            (RemoteChangeKind::Modified, RemoteChangeKind::Modified) => {
                let r = &mut self.records[pos];
                for nf in n.fields {
                    match r.fields.iter().position(|f| f.field == nf.field) {
                        Some(i) => {
                            let existing = &mut r.fields[i];
                            let was_added_custom = existing.old.is_none() && existing.new.is_some();
                            let now_removed_custom = nf.old.is_some() && nf.new.is_none();
                            existing.new = nf.new;
                            if nf.label.is_some() {
                                existing.label = nf.label;
                            }
                            let revert = existing.old.is_some()
                                && existing.new.is_some()
                                && existing.old == existing.new;
                            // A custom field added then removed again nets to nothing.
                            let cancelled = existing.field.starts_with("custom:")
                                && was_added_custom
                                && now_removed_custom;
                            if revert || cancelled {
                                r.fields.remove(i);
                            }
                        }
                        None => r.fields.push(nf),
                    }
                }
                r.changed_at = r.changed_at.max(n.changed_at);
                r.recorded_at = n.recorded_at;
                if r.fields.is_empty() {
                    self.records.remove(pos);
                }
            }
            (RemoteChangeKind::Modified, RemoteChangeKind::Deleted) => {
                self.records[pos] = RemoteChange {
                    fields: Vec::new(),
                    ..n
                };
            }
            // Deleted→Added (whole-document replace) and any other combination:
            // the newest observation wins.
            _ => self.records[pos] = n,
        }
    }

    /// Removes any record for the id.
    pub fn clear_entry(&mut self, entry_id: &str) -> bool {
        let before = self.records.len();
        self.records.retain(|r| r.entry_id != entry_id);
        self.records.len() != before
    }

    /// Removes the added/modified record for the id.
    pub fn ack_entry(&mut self, entry_id: &str) -> bool {
        let before = self.records.len();
        self.records
            .retain(|r| !(r.entry_id == entry_id && r.kind != RemoteChangeKind::Deleted));
        self.records.len() != before
    }

    /// Removes all deleted records.
    pub fn ack_removed(&mut self) -> bool {
        let before = self.records.len();
        self.records.retain(|r| r.kind != RemoteChangeKind::Deleted);
        self.records.len() != before
    }

    pub fn summary_for(&self, entry_id: &str) -> Option<RemoteChangeSummary> {
        self.record_for(entry_id).map(|r| RemoteChangeSummary {
            kind: r.kind,
            changed_at: r.changed_at,
        })
    }

    pub fn record_for(&self, entry_id: &str) -> Option<RemoteChange> {
        self.records
            .iter()
            .find(|r| r.entry_id == entry_id && r.kind != RemoteChangeKind::Deleted)
            .cloned()
    }

    /// Deleted records, newest `changed_at` first.
    pub fn removed(&self) -> Vec<RemoteChange> {
        let mut v: Vec<RemoteChange> = self
            .records
            .iter()
            .filter(|r| r.kind == RemoteChangeKind::Deleted)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.changed_at.cmp(&a.changed_at));
        v
    }

    pub fn prune(&mut self, now: u64) {
        self.records
            .retain(|r| record_time(r).saturating_add(REMOTE_CHANGES_MAX_AGE_SECS) >= now);
        if self.records.len() > MAX_REMOTE_CHANGES {
            let mut idx: Vec<usize> = (0..self.records.len()).collect();
            idx.sort_by_key(|&i| (self.records[i].recorded_at, self.records[i].changed_at));
            let drop: std::collections::HashSet<usize> = idx
                .into_iter()
                .take(self.records.len() - MAX_REMOTE_CHANGES)
                .collect();
            let mut i = 0usize;
            self.records.retain(|_| {
                let keep = !drop.contains(&i);
                i += 1;
                keep
            });
        }
    }
}

/// Seal the log: `RemoteChangesBlobV2::to_bytes` over the CBOR `{ v: 1, records }`.
pub fn seal_log(
    dek: &RemoteChangesDek,
    vault_id: [u8; 16],
    key_epoch: u32,
    log: &RemoteChangeLog,
) -> Result<Vec<u8>, VaultError> {
    let mut pt = Vec::new();
    ciborium::into_writer(
        &LogRef {
            v: REMOTE_CHANGES_LOG_VERSION,
            records: &log.records,
        },
        &mut pt,
    )
    .map_err(|e| VaultError::Serde(e.to_string()))?;
    Ok(seal_remote_changes_v2(dek, vault_id, key_epoch, &pt)?.to_bytes()?)
}

/// Decrypt the stored log to its CBOR plaintext, or `None` on any failure.
fn open_log_plaintext(
    store: &dyn SecretStore,
    dek: &RemoteChangesDek,
    vault_id: [u8; 16],
    key_epoch: u32,
) -> Option<Vec<u8>> {
    let bytes = store.get(SECRET_REMOTE_CHANGES_V2)?;
    let blob = RemoteChangesBlobV2::from_bytes(&bytes).ok()?;
    if blob.vault_id.as_slice() != vault_id.as_slice() || blob.key_epoch != key_epoch {
        return None;
    }
    open_remote_changes_v2(dek, &blob).ok()
}

/// Missing, undecodable, wrong vault/epoch or failed AEAD → empty log. Never errors.
pub fn load_log(
    store: &dyn SecretStore,
    dek: &RemoteChangesDek,
    vault_id: [u8; 16],
    key_epoch: u32,
) -> RemoteChangeLog {
    let Some(pt) = open_log_plaintext(store, dek, vault_id, key_epoch) else {
        return RemoteChangeLog::new();
    };
    match ciborium::from_reader::<RemoteChangeLog, _>(pt.as_slice()) {
        Ok(mut log) if log.v == REMOTE_CHANGES_LOG_VERSION => {
            log.prune(crate::types::unix_now());
            log
        }
        _ => RemoteChangeLog::new(),
    }
}

/// Test-only: the decrypted log plaintext as stored (empty when absent).
#[cfg(test)]
pub(crate) fn stored_plaintext_for_test(
    store: &dyn SecretStore,
    dek: &RemoteChangesDek,
    vault_id: [u8; 16],
    key_epoch: u32,
) -> Vec<u8> {
    open_log_plaintext(store, dek, vault_id, key_epoch).unwrap_or_default()
}
