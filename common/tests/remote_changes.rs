//! D22 remote change log tests. Included from `lib.rs` with `#[path]`.
//!
//! Two devices as in `phase7.rs::two_devices_converge_on_hybrid_mvr`: B is a clone of
//! A's store, unlocked with a different `device_id`, and pulls A's `contract_state`
//! through `SyncWithRemote`.

use crate::crypto::hkdf_v2::{
    derive_remote_changes_dek, LABEL_REMOTE_CHANGES_DEK, ROOT_DERIVED_LABELS,
};
use crate::crypto::kdf::Argon2ParamsV2;
use crate::crypto::secret::{RemoteChangesDek, RootSecret};
use crate::crypto::suite::{ObjectKind, KIND_REMOTE_CHANGES};
use crate::crypto::{open_remote_changes_v2, RemoteChangesBlobV2};
use crate::delegate_session::SessionOrigin;
use crate::link::{decode_link_code, derive_link_keys, open_link_payload, LinkDropParams, LinkDropState, LinkPayloadV1};
use crate::messages::{ErrorCode, VaultRequest, VaultResponse};
use crate::remote_changes::{
    load_log, seal_log, ChangeValue, RemoteChange, RemoteChangeKind, RemoteChangeLog,
    RemoteChangeSummary, MAX_REMOTE_CHANGES, REMOTE_CHANGES_MAX_AGE_SECS,
    SECRET_REMOTE_CHANGES_V2,
};
use crate::session_v2::{VaultSessionV2, SECRET_AUDIT_V2, SECRET_VAULT_V2};
use crate::types::{CustomField, Entry, EntrySummary, FieldKind, PasswordHistoryItem, unix_now};
use crate::upgrade::{export_upgrade_snapshot, import_upgrade_snapshot, UpgradeSnapshot};
use crate::vault::{dispatch, ActiveSession, MemoryStore, SecretStore, StoreOp};
use std::cell::Cell;

const PW: &str = "correct horse battery staple";

// ---------------------------------------------------------------- helpers

/// Records every `commit` as a list of (is_put, key).
struct RecordingStore {
    inner: MemoryStore,
    commits: Vec<Vec<(bool, Vec<u8>)>>,
}

impl SecretStore for RecordingStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.inner.set(key, value)
    }
    fn remove(&mut self, key: &[u8]) {
        self.inner.remove(key)
    }
    fn commit(&mut self, ops: &[StoreOp]) -> Result<(), String> {
        self.commits.push(
            ops.iter()
                .map(|o| match o {
                    StoreOp::Put { key, .. } => (true, key.clone()),
                    StoreOp::Delete { key } => (false, key.clone()),
                })
                .collect(),
        );
        self.inner.commit(ops)
    }
}

struct Dev<S: SecretStore> {
    store: S,
    session: Option<ActiveSession>,
}

impl<S: SecretStore> Dev<S> {
    fn req(&mut self, r: VaultRequest) -> VaultResponse {
        dispatch(&mut self.store, &mut self.session, r)
    }

    fn v2(&self) -> &VaultSessionV2 {
        match self.session.as_ref().expect("unlocked") {
            ActiveSession::V2(s) => s,
            _ => panic!("v2 expected"),
        }
    }

    fn summaries(&mut self) -> Vec<EntrySummary> {
        match self.req(VaultRequest::ListSummaries { query: None }) {
            VaultResponse::Summaries { entries } => entries,
            other => panic!("summaries: {other:?}"),
        }
    }

    fn summary(&mut self, id: &str) -> Option<RemoteChangeSummary> {
        self.summaries()
            .into_iter()
            .find(|e| e.id == id)
            .and_then(|e| e.remote_change)
    }

    fn any_summary_change(&mut self) -> bool {
        self.summaries().iter().any(|e| e.remote_change.is_some())
    }

    fn get(&mut self, id: &str) -> (Entry, Option<RemoteChange>) {
        match self.req(VaultRequest::GetEntry { id: id.into() }) {
            VaultResponse::Entry {
                entry,
                remote_change,
            } => (entry, remote_change),
            other => panic!("get_entry: {other:?}"),
        }
    }

    fn removed(&mut self) -> Vec<RemoteChange> {
        match self.req(VaultRequest::ListRemovedRemote {}) {
            VaultResponse::RemovedRemote { entries } => entries,
            other => panic!("removed: {other:?}"),
        }
    }

    fn upsert(&mut self, entry: Entry) {
        let r = self.req(VaultRequest::UpsertEntry { entry });
        assert!(matches!(r, VaultResponse::Ok), "upsert: {r:?}");
    }

    fn delete(&mut self, id: &str) {
        let r = self.req(VaultRequest::DeleteEntry { id: id.into() });
        assert!(matches!(r, VaultResponse::Ok), "delete: {r:?}");
    }

    /// Edit an existing entry through `GetEntry` + `UpsertEntry`.
    fn edit(&mut self, id: &str, f: impl FnOnce(&mut Entry)) {
        let (mut e, _) = self.get(id);
        f(&mut e);
        self.upsert(e);
    }

    /// `SyncNow`, returning the contract state to publish.
    fn push(&mut self) -> Vec<u8> {
        match self.req(VaultRequest::SyncNow) {
            VaultResponse::Synced { contract_state, .. } => contract_state,
            other => panic!("sync_now: {other:?}"),
        }
    }

    /// `SyncWithRemote`, returning `remote_changed`.
    fn pull(&mut self, state: Vec<u8>) -> u32 {
        match self.req(VaultRequest::SyncWithRemote {
            remote_state: state,
        }) {
            VaultResponse::Synced { remote_changed, .. } => remote_changed,
            other => panic!("sync_with_remote: {other:?}"),
        }
    }

    fn log(&self) -> &RemoteChangeLog {
        self.v2().remote_changes_for_test()
    }

    fn relock(&mut self) {
        assert!(matches!(self.req(VaultRequest::Lock), VaultResponse::Ok | VaultResponse::Locked));
        assert!(self.session.is_none());
        let r = self.req(VaultRequest::Unlock {
            passphrase: PW.into(),
        });
        assert!(matches!(r, VaultResponse::Unlocked { .. }), "unlock: {r:?}");
    }
}

fn base_entry(id: &str, name: &str) -> Entry {
    let mut e = Entry::new(id, name);
    e.username = "alice".into();
    e.password = "base-password".into();
    e.notes = "base notes".into();
    e.urls = vec!["https://old.example.com".into()];
    e.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
    e
}

/// A with entries e1 "Mail" and e2 "Bank", already synced once.
fn device_a() -> Dev<MemoryStore> {
    let mut store = MemoryStore::default();
    let s = VaultSessionV2::create_with_params(&mut store, PW, Argon2ParamsV2::insecure_for_tests())
        .expect("create");
    let mut a = Dev {
        store,
        session: Some(ActiveSession::V2(s)),
    };
    a.upsert(base_entry("e1", "Mail"));
    a.upsert(base_entry("e2", "Bank"));
    let _ = a.push();
    a
}

fn spawn_b<S: SecretStore>(a: &Dev<MemoryStore>, wrap: impl FnOnce(MemoryStore) -> S) -> Dev<S> {
    let mut store = wrap(a.store.clone());
    let mut s = VaultSessionV2::unlock(&mut store, PW).expect("b unlock");
    s.doc.meta.device_id = "device-b".into();
    Dev {
        store,
        session: Some(ActiveSession::V2(s)),
    }
}

fn pair() -> (Dev<MemoryStore>, Dev<MemoryStore>) {
    let a = device_a();
    let b = spawn_b(&a, |s| s);
    (a, b)
}

/// A pushes, B pulls; returns `remote_changed`.
fn a_to_b(a: &mut Dev<MemoryStore>, b: &mut Dev<MemoryStore>) -> u32 {
    let st = a.push();
    b.pull(st)
}

fn field<'a>(rc: &'a RemoteChange, name: &str) -> &'a crate::remote_changes::FieldChange {
    rc.fields
        .iter()
        .find(|f| f.field == name)
        .unwrap_or_else(|| panic!("field {name} missing in {:?}", rc.fields))
}

fn text(s: &str) -> Option<ChangeValue> {
    Some(ChangeValue::Text(s.into()))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn rc(id: &str, kind: RemoteChangeKind, changed_at: u64, recorded_at: u64) -> RemoteChange {
    RemoteChange {
        entry_id: id.into(),
        kind,
        changed_at,
        recorded_at,
        entry_name: None,
        fields: Vec::new(),
    }
}

// ---------------------------------------------------------------- AC1

#[test]
fn ac1_added_entry_is_reported_on_b() {
    let (mut a, mut b) = pair();
    let mut e = Entry::new("e3", "GitHub");
    e.password = "gh-pass".into();
    a.upsert(e);
    let n = a_to_b(&mut a, &mut b);
    assert_eq!(n, 1, "Synced.remote_changed");
    let s = b.summary("e3").expect("summary remote_change");
    assert_eq!(s.kind, RemoteChangeKind::Added);
    let (_, r) = b.get("e3");
    let r = r.expect("get_entry remote_change");
    assert_eq!(r.kind, RemoteChangeKind::Added);
    // Others untouched.
    assert!(b.summary("e1").is_none());
    assert!(b.summary("e2").is_none());
}

#[test]
fn ac1_first_pull_of_identical_state_records_nothing() {
    let (mut a, mut b) = pair();
    let n = a_to_b(&mut a, &mut b);
    assert_eq!(n, 0);
    assert!(!b.any_summary_change());
    assert!(b.removed().is_empty());
    // A never wrote the key (no sync brought changes).
    assert!(!b.store.has(SECRET_REMOTE_CHANGES_V2));
    assert!(!a.store.has(SECRET_REMOTE_CHANGES_V2));
}

#[test]
fn get_entry_does_not_ack() {
    let (mut a, mut b) = pair();
    a.upsert(Entry::new("e3", "GitHub"));
    a_to_b(&mut a, &mut b);
    let _ = b.get("e3");
    let _ = b.get("e3");
    assert!(b.summary("e3").is_some());
}

// ---------------------------------------------------------------- AC2

#[test]
fn ac2_modified_fields_recorded_without_secret_values() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| {
        e.username = "alice2".into();
        e.password = "new-password".into();
        e.notes = "new notes".into();
        e.totp_secret = Some("MFRGGZDFMZTWQ2LK".into());
        e.urls = vec!["https://example.com".into()];
    });
    assert_eq!(a_to_b(&mut a, &mut b), 1);
    let (_, r) = b.get("e1");
    let r = r.expect("record");
    assert_eq!(r.kind, RemoteChangeKind::Modified);
    let u = field(&r, "username");
    assert_eq!(u.old, text("alice"));
    assert_eq!(u.new, text("alice2"));
    let urls = field(&r, "urls");
    assert_eq!(
        urls.old,
        Some(ChangeValue::List(vec!["https://old.example.com".into()]))
    );
    assert_eq!(
        urls.new,
        Some(ChangeValue::List(vec!["https://example.com".into()]))
    );
    for name in ["password", "notes", "totp"] {
        let f = field(&r, name);
        assert!(f.old.is_none() && f.new.is_none(), "{name} must carry no values: {f:?}");
    }
    // Unchanged fields are not listed.
    assert!(r.fields.iter().all(|f| f.field != "name"));
}

#[test]
fn ac2_canonical_field_order() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| {
        e.name = "Mail2".into();
        e.username = "u2".into();
        e.password = "p2".into();
        e.urls = vec!["https://x.example".into()];
        e.notes = "n2".into();
        e.tags = vec!["t".into()];
        e.totp_secret = None;
    });
    a_to_b(&mut a, &mut b);
    let r = b.get("e1").1.unwrap();
    let names: Vec<&str> = r.fields.iter().map(|f| f.field.as_str()).collect();
    assert_eq!(
        names,
        vec!["name", "username", "password", "urls", "notes", "tags", "totp"]
    );
}

#[test]
fn ac2_password_history_only_change_is_not_a_change() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| {
        e.password_history = vec![PasswordHistoryItem {
            password: "hist-only".into(),
            changed_at: 5,
        }];
    });
    let n = a_to_b(&mut a, &mut b);
    assert_eq!(n, 0);
    assert!(b.summary("e1").is_none());
}

#[test]
fn custom_fields_text_values_kept_hidden_values_never() {
    let (mut a, mut b) = pair();
    // Establish custom fields on both devices first.
    a.edit("e1", |e| {
        e.custom_fields = vec![
            CustomField {
                id: "cf-t".into(),
                name: "Account no".into(),
                value: "TXT-OLD".into(),
                kind: FieldKind::Text,
            },
            CustomField {
                id: "cf-h".into(),
                name: "Pin".into(),
                value: "HIDDEN-OLD".into(),
                kind: FieldKind::Hidden,
            },
        ];
    });
    a_to_b(&mut a, &mut b);
    b.relock();
    // Ack so the next diff is against the settled state.
    let _ = b.req(VaultRequest::AckRemoteChange { id: "e1".into() });
    a.edit("e1", |e| {
        e.custom_fields[0].value = "TXT-NEW".into();
        e.custom_fields[1].value = "HIDDEN-NEW".into();
    });
    assert_eq!(a_to_b(&mut a, &mut b), 1);
    let r = b.get("e1").1.unwrap();
    let t = field(&r, "custom:cf-t");
    assert_eq!(t.label.as_deref(), Some("Account no"));
    assert_eq!(t.old, text("TXT-OLD"));
    assert_eq!(t.new, text("TXT-NEW"));
    let h = field(&r, "custom:cf-h");
    assert_eq!(h.label.as_deref(), Some("Pin"));
    assert!(h.old.is_none() && h.new.is_none());
}

// ---------------------------------------------------------------- AC3

#[test]
fn ac3_remote_delete_lists_removed_entry_by_name() {
    let (mut a, mut b) = pair();
    a.delete("e2");
    assert_eq!(a_to_b(&mut a, &mut b), 1);
    let removed = b.removed();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].kind, RemoteChangeKind::Deleted);
    assert_eq!(removed[0].entry_id, "e2");
    assert_eq!(removed[0].entry_name.as_deref(), Some("Bank"));
    assert!(b.summaries().iter().all(|s| s.id != "e2"));
    assert!(b.summary("e2").is_none());
}

// ---------------------------------------------------------------- AC4

#[test]
fn ac4_local_edits_never_create_records_but_do_on_the_other_device() {
    let (mut a, mut b) = pair();
    b.upsert(Entry::new("e3", "Local new"));
    b.edit("e1", |e| e.username = "bob-local".into());
    b.delete("e2");
    let st_b = b.push();
    assert!(b.removed().is_empty());
    assert!(!b.any_summary_change());
    assert!(b.log().records.is_empty());

    // A pulls B's edits and gets records; B still has none.
    let n = a.pull(st_b);
    assert!(n >= 1, "A should observe B's changes, got {n}");
    assert!(a.summary("e3").is_some());
    assert_eq!(a.summary("e3").unwrap().kind, RemoteChangeKind::Added);
    assert_eq!(a.summary("e1").unwrap().kind, RemoteChangeKind::Modified);
    let removed = a.removed();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].entry_name.as_deref(), Some("Bank"));
    assert!(b.log().records.is_empty());
}

// ---------------------------------------------------------------- AC5

#[test]
fn ac5_local_upsert_clears_record() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a_to_b(&mut a, &mut b);
    assert!(b.summary("e1").is_some());
    b.edit("e1", |e| e.notes = "mine".into());
    assert!(b.summary("e1").is_none());
    assert!(b.log().records.is_empty());
    // Persisted: key is gone after the commit.
    assert!(!b.store.has(SECRET_REMOTE_CHANGES_V2));
}

#[test]
fn ac5_local_delete_clears_record_and_creates_no_deleted_record() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a_to_b(&mut a, &mut b);
    b.delete("e1");
    assert!(b.summary("e1").is_none());
    assert!(b.removed().is_empty());
}

// ---------------------------------------------------------------- AC6

#[test]
fn ac6_two_syncs_before_ack_coalesce_old_and_new() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "a".into());
    a_to_b(&mut a, &mut b);
    // ack the base change so "a" is the settled value, then drive a->b->c.
    // (base username was "alice"; the first record is alice -> a.)
    let r = b.get("e1").1.unwrap();
    assert_eq!(field(&r, "username").old, text("alice"));
    assert_eq!(field(&r, "username").new, text("a"));

    a.edit("e1", |e| e.username = "b".into());
    a_to_b(&mut a, &mut b);
    a.edit("e1", |e| e.username = "c".into());
    a_to_b(&mut a, &mut b);
    let r = b.get("e1").1.unwrap();
    assert_eq!(r.fields.len(), 1);
    assert_eq!(field(&r, "username").old, text("alice"));
    assert_eq!(field(&r, "username").new, text("c"));
}

#[test]
fn ac6_revert_drops_field_and_removes_empty_record() {
    let (mut a, mut b) = pair();
    // base username is "alice"; change away and back.
    a.edit("e1", |e| e.username = "zed".into());
    a_to_b(&mut a, &mut b);
    assert_eq!(field(&b.get("e1").1.unwrap(), "username").new, text("zed"));
    a.edit("e1", |e| e.username = "alice".into());
    a_to_b(&mut a, &mut b);
    assert!(b.summary("e1").is_none(), "record must vanish after a revert");
    assert!(b.get("e1").1.is_none());
}

#[test]
fn ac6_revert_keeps_other_fields() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| {
        e.username = "zed".into();
        e.name = "Mail2".into();
    });
    a_to_b(&mut a, &mut b);
    a.edit("e1", |e| e.username = "alice".into());
    a_to_b(&mut a, &mut b);
    let r = b.get("e1").1.expect("record remains for name");
    assert!(r.fields.iter().all(|f| f.field != "username"));
    assert_eq!(field(&r, "name").new, text("Mail2"));
}

#[test]
fn ac6_secret_fields_are_never_dropped_as_reverted() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.password = "other".into());
    a_to_b(&mut a, &mut b);
    a.edit("e1", |e| e.password = "base-password".into());
    a_to_b(&mut a, &mut b);
    let r = b.get("e1").1.expect("password record stays until acked");
    assert!(r.fields.iter().any(|f| f.field == "password"));
}

#[test]
fn ac6_added_then_modified_stays_added() {
    let (mut a, mut b) = pair();
    a.upsert(Entry::new("e5", "Fresh"));
    a_to_b(&mut a, &mut b);
    a.edit("e5", |e| e.name = "Fresh2".into());
    a_to_b(&mut a, &mut b);
    let s = b.summary("e5").unwrap();
    assert_eq!(s.kind, RemoteChangeKind::Added);
    let r = b.get("e5").1.unwrap();
    assert!(r.fields.is_empty());
}

#[test]
fn added_then_deleted_before_ack_leaves_nothing() {
    let (mut a, mut b) = pair();
    a.upsert(Entry::new("e5", "Fresh"));
    a_to_b(&mut a, &mut b);
    a.delete("e5");
    a_to_b(&mut a, &mut b);
    assert!(b.summary("e5").is_none());
    assert!(b.removed().is_empty());
}

#[test]
fn modified_then_deleted_becomes_deleted_record() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "zed".into());
    a_to_b(&mut a, &mut b);
    a.delete("e1");
    a_to_b(&mut a, &mut b);
    assert!(b.summary("e1").is_none());
    let removed = b.removed();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].entry_name.as_deref(), Some("Mail"));
    assert!(removed[0].fields.is_empty());
}

// ---------------------------------------------------------------- unit: record_merge

#[test]
fn record_merge_unit_added_modified_deleted_and_count() {
    use crate::types::{Tombstone, VaultDocument};
    let a = device_a();
    let mut before: VaultDocument = a.v2().doc.clone();
    let mut after = before.clone();
    after.entries.insert("n".into(), Entry::new("n", "New"));
    after.entries.get_mut("e1").unwrap().username = "changed".into();
    after.entries.remove("e2");
    after.deleted.insert(
        "e2".into(),
        Tombstone {
            deleted_at: 4242,
            device_id: "x".into(),
        },
    );
    let mut log = RemoteChangeLog::new();
    let n = log.record_merge(&before, &after, 1_000);
    assert_eq!(n, 3);
    assert_eq!(log.summary_for("n").unwrap().kind, RemoteChangeKind::Added);
    assert_eq!(log.summary_for("e1").unwrap().kind, RemoteChangeKind::Modified);
    let removed = log.removed();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].changed_at, 4242, "uses tombstone deleted_at");
    assert_eq!(removed[0].entry_name.as_deref(), Some("Bank"));
    assert_eq!(removed[0].recorded_at, 1_000);
    // A deleted record has no summary and no record_for.
    assert!(log.summary_for("e2").is_none());
    assert!(log.record_for("e2").is_none());

    // updated_at-only difference is not a change.
    before.entries.get_mut("e1").unwrap().updated_at += 5;
    let mut log2 = RemoteChangeLog::new();
    let mut same = before.clone();
    same.entries.get_mut("e1").unwrap().updated_at += 10;
    assert_eq!(log2.record_merge(&before, &same, 1), 0);
    assert!(log2.records.is_empty());
}

#[test]
fn record_merge_deleted_without_tombstone_uses_now() {
    let a = device_a();
    let before = a.v2().doc.clone();
    let mut after = before.clone();
    after.entries.remove("e2");
    let mut log = RemoteChangeLog::new();
    assert_eq!(log.record_merge(&before, &after, 777), 1);
    assert_eq!(log.removed()[0].changed_at, 777);
}

#[test]
fn removed_is_newest_first() {
    let mut log = RemoteChangeLog::new();
    for (id, at) in [("a", 10u64), ("b", 30), ("c", 20)] {
        let mut r = rc(id, RemoteChangeKind::Deleted, at, at);
        r.entry_name = Some(id.into());
        log.records.push(r);
    }
    let ids: Vec<_> = log.removed().into_iter().map(|r| r.entry_id).collect();
    assert_eq!(ids, vec!["b", "c", "a"]);
}

// ---------------------------------------------------------------- AC7

#[test]
fn ac7_ack_removes_summary_and_is_idempotent() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a_to_b(&mut a, &mut b);
    assert!(b.summary("e1").is_some());
    let r = b.req(VaultRequest::AckRemoteChange { id: "e1".into() });
    assert!(matches!(r, VaultResponse::Ok), "{r:?}");
    assert!(b.summary("e1").is_none());
    assert!(b.get("e1").1.is_none());
    // Second ack and unknown id: Ok.
    for id in ["e1", "does-not-exist"] {
        let r = b.req(VaultRequest::AckRemoteChange { id: id.into() });
        assert!(matches!(r, VaultResponse::Ok), "{r:?}");
    }
    // Ack is durable.
    b.relock();
    assert!(b.summary("e1").is_none());
}

#[test]
fn ac7_ack_removed_empties_list() {
    let (mut a, mut b) = pair();
    a.delete("e2");
    a_to_b(&mut a, &mut b);
    assert_eq!(b.removed().len(), 1);
    let r = b.req(VaultRequest::AckRemovedRemote {});
    assert!(matches!(r, VaultResponse::Ok), "{r:?}");
    assert!(b.removed().is_empty());
    let r = b.req(VaultRequest::AckRemovedRemote {});
    assert!(matches!(r, VaultResponse::Ok), "{r:?}");
    b.relock();
    assert!(b.removed().is_empty());
}

#[test]
fn ac7_ack_of_id_with_only_deleted_record_does_nothing() {
    let (mut a, mut b) = pair();
    a.delete("e2");
    a_to_b(&mut a, &mut b);
    let r = b.req(VaultRequest::AckRemoteChange { id: "e2".into() });
    assert!(matches!(r, VaultResponse::Ok), "{r:?}");
    assert_eq!(b.removed().len(), 1, "deleted record must survive entry ack");
}

#[test]
fn ac7_acks_write_no_audit_events_and_ack_only_touches_log_key() {
    let a = device_a();
    let rec = RecordingStore {
        inner: MemoryStore::default(),
        commits: Vec::new(),
    };
    let mut b = spawn_b(&a, |m| RecordingStore { inner: m, ..rec });
    let mut a = a;
    a.edit("e1", |e| e.username = "alice2".into());
    let st = a.push();
    b.pull(st);
    let audit_before = b.store.get(SECRET_AUDIT_V2);
    b.store.commits.clear();
    let r = b.req(VaultRequest::AckRemoteChange { id: "e1".into() });
    assert!(matches!(r, VaultResponse::Ok));
    assert_eq!(b.store.commits.len(), 1);
    assert_eq!(
        b.store.commits[0],
        vec![(false, SECRET_REMOTE_CHANGES_V2.to_vec())],
        "ack commits only the log op"
    );
    assert_eq!(audit_before, b.store.get(SECRET_AUDIT_V2));
    // No-op ack writes nothing at all.
    b.store.commits.clear();
    let _ = b.req(VaultRequest::AckRemoteChange { id: "e1".into() });
    let _ = b.req(VaultRequest::AckRemovedRemote {});
    assert!(b.store.commits.is_empty(), "{:?}", b.store.commits);
}

// ---------------------------------------------------------------- AC8

#[test]
fn ac8_records_survive_lock_unlock_and_resume() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a.delete("e2");
    a.upsert(Entry::new("e3", "GitHub"));
    a_to_b(&mut a, &mut b);
    let before = b.log().clone();
    assert_eq!(before.records.len(), 3);

    b.relock();
    assert_eq!(b.log(), &before);
    assert_eq!(b.summary("e1").unwrap().kind, RemoteChangeKind::Modified);
    assert_eq!(b.summary("e3").unwrap().kind, RemoteChangeKind::Added);
    assert_eq!(b.removed().len(), 1);

    let (root, vid, epoch) = {
        let s = b.v2();
        (s.root_bytes_for_test(), s.vault_id(), s.key_epoch())
    };
    let resumed =
        VaultSessionV2::resume_from_root(&b.store, RootSecret::from_bytes(root), vid, epoch)
            .expect("resume");
    assert_eq!(resumed.remote_changes_for_test(), &before);
}

// ---------------------------------------------------------------- AC9

fn upgrade_keys(store: &MemoryStore, s: &VaultSessionV2) -> (UpgradeSnapshot, Vec<u8>) {
    let bytes = export_upgrade_snapshot(store, s).expect("export");
    let snap: UpgradeSnapshot = ciborium::from_reader(bytes.as_slice()).unwrap();
    (snap, bytes)
}

#[test]
fn ac9_upgrade_snapshot_never_carries_the_log() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a_to_b(&mut a, &mut b);
    assert!(b.store.has(SECRET_REMOTE_CHANGES_V2), "precondition");
    let (snap, bytes) = upgrade_keys(&b.store, b.v2());
    assert!(snap
        .records
        .iter()
        .all(|(k, _)| k.as_slice() != SECRET_REMOTE_CHANGES_V2));
    assert!(!contains(&bytes, SECRET_REMOTE_CHANGES_V2));

    // Injecting the key makes the import fail closed.
    let mut bad = UpgradeSnapshot {
        v: snap.v,
        vault_id: snap.vault_id.clone(),
        key_epoch: snap.key_epoch,
        records: snap.records.clone(),
    };
    bad.records.push((
        serde_bytes::ByteBuf::from(SECRET_REMOTE_CHANGES_V2.to_vec()),
        serde_bytes::ByteBuf::from(b.store.get(SECRET_REMOTE_CHANGES_V2).unwrap()),
    ));
    let mut out = Vec::new();
    ciborium::into_writer(&bad, &mut out).unwrap();
    let mut empty = MemoryStore::default();
    assert!(import_upgrade_snapshot(&mut empty, &out).is_err());
    assert!(!empty.has(SECRET_REMOTE_CHANGES_V2));
    // The clean one imports and leaves no log behind.
    import_upgrade_snapshot(&mut empty, &bytes).expect("clean import");
    assert!(!empty.has(SECRET_REMOTE_CHANGES_V2));
}

thread_local! {
    static RNG_STATE: Cell<u64> = const { Cell::new(0x1234_5678_9ABC_DEF0) };
}

fn fill(b: &mut [u8]) {
    RNG_STATE.with(|st| {
        for x in b.iter_mut() {
            let mut z = st.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
            st.set(z);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *x = ((z ^ (z >> 31)) & 0xff) as u8;
        }
    });
}

#[test]
fn ac9_link_offer_payload_never_carries_the_log() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a_to_b(&mut a, &mut b);
    assert!(b.store.has(SECRET_REMOTE_CHANGES_V2), "precondition");
    let mut rng = fill;
    let offer =
        crate::link::create_link_offer(&b.store, b.v2(), 1_700_000_000, &mut rng).expect("offer");
    let secret = decode_link_code(&offer.code).unwrap();
    let keys = derive_link_keys(&secret);
    let params = LinkDropParams::from_keys(&keys).to_cbor();
    let st = LinkDropState::from_cbor(&offer.state).unwrap();
    let pt = open_link_payload(&keys, &params, &st.body).unwrap();
    let payload: LinkPayloadV1 = ciborium::from_reader(pt.as_slice()).unwrap();
    assert!(!payload.records.is_empty());
    assert!(payload
        .records
        .iter()
        .all(|(k, _)| k.as_slice() != SECRET_REMOTE_CHANGES_V2));
    assert!(!contains(&pt, SECRET_REMOTE_CHANGES_V2));
    let _ = SessionOrigin::Other;
}

// ---------------------------------------------------------------- AC10

#[test]
fn ac10_no_secret_values_anywhere() {
    const PW_OLD: &str = "SECRET-PW-OLD-9d1f3c7a";
    const PW_NEW: &str = "SECRET-PW-NEW-4be2a0c1";
    const TOTP_OLD: &str = "SECRETTOTPOLD7Q2W3E4R";
    const TOTP_NEW: &str = "SECRETTOTPNEW5T6Y7U8I";
    const NOTES_OLD: &str = "SECRET-NOTES-OLD-b83d";
    const NOTES_NEW: &str = "SECRET-NOTES-NEW-17ac";
    const HID_OLD: &str = "SECRET-HIDDEN-OLD-55e0";
    const HID_NEW: &str = "SECRET-HIDDEN-NEW-c9a4";
    const HIST: &str = "SECRET-HISTORY-ENTRY-02fd";

    let mut store = MemoryStore::default();
    let s = VaultSessionV2::create_with_params(&mut store, PW, Argon2ParamsV2::insecure_for_tests())
        .unwrap();
    let mut a = Dev {
        store,
        session: Some(ActiveSession::V2(s)),
    };
    let mut e = Entry::new("e1", "Mail");
    e.password = PW_OLD.into();
    e.totp_secret = Some(TOTP_OLD.into());
    e.notes = NOTES_OLD.into();
    e.password_history = vec![PasswordHistoryItem {
        password: HIST.into(),
        changed_at: 3,
    }];
    e.custom_fields = vec![
        CustomField {
            id: "h".into(),
            name: "Pin".into(),
            value: HID_OLD.into(),
            kind: FieldKind::Hidden,
        },
        CustomField {
            id: "t".into(),
            name: "Account".into(),
            value: "TEXT-OLD-VALUE".into(),
            kind: FieldKind::Text,
        },
    ];
    a.upsert(e);
    let _ = a.push();
    let mut b = spawn_b(&a, |s| s);

    a.edit("e1", |e| {
        e.password = PW_NEW.into();
        e.totp_secret = Some(TOTP_NEW.into());
        e.notes = NOTES_NEW.into();
        e.custom_fields[0].value = HID_NEW.into();
        e.custom_fields[1].value = "TEXT-NEW-VALUE".into();
    });
    assert_eq!(a_to_b(&mut a, &mut b), 1);

    let secrets = [
        PW_OLD, PW_NEW, TOTP_OLD, TOTP_NEW, NOTES_OLD, NOTES_NEW, HID_OLD, HID_NEW, HIST,
    ];
    let pt = b.v2().remote_changes_plaintext_for_test(&b.store);
    assert!(!pt.is_empty(), "log plaintext should decrypt");
    for s in secrets {
        assert!(!contains(&pt, s.as_bytes()), "{s} leaked into log plaintext");
        assert!(!b.store.contains_plaintext(s.as_bytes()), "{s} in store");
    }
    // Non-secret Text custom field carries both values.
    assert!(contains(&pt, b"TEXT-OLD-VALUE"));
    assert!(contains(&pt, b"TEXT-NEW-VALUE"));

    // Response CBOR.
    let (_, r) = b.get("e1");
    let mut cbor = Vec::new();
    ciborium::into_writer(&r.unwrap(), &mut cbor).unwrap();
    let sums = b.summaries();
    ciborium::into_writer(&sums.iter().map(|s| s.remote_change.clone()).collect::<Vec<_>>(), &mut cbor)
        .unwrap();
    for s in secrets {
        assert!(!contains(&cbor, s.as_bytes()), "{s} leaked into response");
    }
    assert!(contains(&cbor, b"TEXT-NEW-VALUE"));
}

// ---------------------------------------------------------------- AC11

#[test]
fn ac11_cap_drops_oldest_keeps_500() {
    let now = 10_000_000u64;
    let mut log = RemoteChangeLog::new();
    for i in 0..510u64 {
        log.records
            .push(rc(&format!("e{i}"), RemoteChangeKind::Added, now - 600 + i, now - 600 + i));
    }
    log.prune(now);
    assert_eq!(log.records.len(), MAX_REMOTE_CHANGES);
    // Oldest ten (e0..e9) are gone; newest remain.
    assert!(log.records.iter().all(|r| {
        let n: u64 = r.entry_id[1..].parse().unwrap();
        n >= 10
    }));
}

#[test]
fn ac11_age_prune() {
    let now = 100_000_000u64;
    let mut log = RemoteChangeLog::new();
    log.records.push(rc(
        "old",
        RemoteChangeKind::Added,
        now,
        now - REMOTE_CHANGES_MAX_AGE_SECS - 1,
    ));
    log.records.push(rc(
        "edge",
        RemoteChangeKind::Added,
        now,
        now - REMOTE_CHANGES_MAX_AGE_SECS,
    ));
    // recorded_at == 0 falls back to changed_at.
    log.records.push(rc(
        "old-legacy",
        RemoteChangeKind::Added,
        now - REMOTE_CHANGES_MAX_AGE_SECS - 5,
        0,
    ));
    log.records.push(rc("legacy-new", RemoteChangeKind::Added, now - 5, 0));
    log.records.push(rc("fresh", RemoteChangeKind::Added, now, now));
    log.prune(now);
    let mut ids: Vec<_> = log.records.iter().map(|r| r.entry_id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, vec!["edge", "fresh", "legacy-new"]);
}

// ---------------------------------------------------------------- AC12

#[test]
fn ac12_garbage_log_is_ignored_and_replaced() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a_to_b(&mut a, &mut b);
    b.store.set(SECRET_REMOTE_CHANGES_V2, b"\xff\x00garbage-bytes");
    b.relock();
    assert!(!b.any_summary_change());
    assert!(b.removed().is_empty());
    // Next persist: log empty + key exists → deleted.
    b.upsert(Entry::new("local", "Local"));
    assert!(!b.store.has(SECRET_REMOTE_CHANGES_V2));
}

#[test]
fn ac12_garbage_log_then_sync_writes_a_valid_log() {
    let (mut a, mut b) = pair();
    b.store.set(SECRET_REMOTE_CHANGES_V2, b"not a blob");
    b.relock();
    a.upsert(Entry::new("e3", "GitHub"));
    a_to_b(&mut a, &mut b);
    assert!(b.summary("e3").is_some());
    b.relock();
    assert!(b.summary("e3").is_some(), "valid log written over the garbage");
}

// ---------------------------------------------------------------- AC13

#[test]
fn ac13_sync_commits_vault_and_log_together() {
    let a = device_a();
    let mut b = spawn_b(&a, |m| RecordingStore {
        inner: m,
        commits: Vec::new(),
    });
    let mut a = a;
    a.upsert(Entry::new("e3", "GitHub"));
    let st = a.push();
    b.store.commits.clear();
    assert_eq!(b.pull(st), 1);
    let log_commits: Vec<_> = b
        .store
        .commits
        .iter()
        .filter(|c| c.iter().any(|(put, k)| *put && k == SECRET_REMOTE_CHANGES_V2))
        .collect();
    assert_eq!(log_commits.len(), 1, "commits: {:?}", b.store.commits);
    assert!(
        log_commits[0]
            .iter()
            .any(|(put, k)| *put && k == SECRET_VAULT_V2),
        "log must be committed together with the vault"
    );
}

#[test]
fn ac13_generation_store_carries_log_across_unrelated_commit() {
    use crate::gen_store::GenerationStore;
    let a = device_a();
    let mut a = a;
    let mut b = spawn_b(&a, GenerationStore::new);
    a.upsert(Entry::new("e3", "GitHub"));
    let st = a.push();
    assert_eq!(b.pull(st), 1);
    assert!(b.summary("e3").is_some());

    // A commit that does not mention the log key.
    b.store
        .commit(&[StoreOp::put(b"aegis/v2/unrelated".to_vec(), b"x".to_vec())])
        .unwrap();
    assert!(b.store.has(SECRET_REMOTE_CHANGES_V2), "log carried by tracked_keys");
    b.relock();
    assert!(b.summary("e3").is_some());

    // Audit-only style commit through a local upsert as well.
    b.upsert(Entry::new("e9", "Other"));
    b.relock();
    assert!(b.summary("e3").is_some());
}

// ---------------------------------------------------------------- AC14

#[test]
fn ac14_sealed_log_is_bound_to_its_dek_vault_and_epoch() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a_to_b(&mut a, &mut b);
    let bytes = b.store.get(SECRET_REMOTE_CHANGES_V2).unwrap();
    let blob = RemoteChangesBlobV2::from_bytes(&bytes).unwrap();
    let [vault_dek, audit_dek, sync_dek] = {
        let k = b.v2().operational_key_bytes_for_tests();
        [k[0].to_vec(), k[1].to_vec(), k[2].to_vec()]
    };
    for k in [vault_dek, audit_dek, sync_dek] {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&k);
        assert!(
            open_remote_changes_v2(&RemoteChangesDek::from_bytes(arr), &blob).is_err(),
            "other DEKs must not open the log"
        );
    }
    let (root, vid, epoch) = {
        let s = b.v2();
        (s.root_bytes_for_test(), s.vault_id(), s.key_epoch())
    };
    let dek = derive_remote_changes_dek(&RootSecret::from_bytes(root), &vid).unwrap();
    assert!(open_remote_changes_v2(&dek, &blob).is_ok());

    // Header tampering → empty log.
    let mut s = MemoryStore::default();
    let log = RemoteChangeLog {
        v: 1,
        records: vec![rc("x", RemoteChangeKind::Added, unix_now(), unix_now())],
    };
    s.set(SECRET_REMOTE_CHANGES_V2, &seal_log(&dek, vid, epoch, &log).unwrap());
    assert_eq!(load_log(&s, &dek, vid, epoch).records, log.records);
    assert!(load_log(&s, &dek, vid, epoch + 1).records.is_empty());
    let mut other_vid = vid;
    other_vid[0] ^= 0xFF;
    assert!(load_log(&s, &dek, other_vid, epoch).records.is_empty());

    let mut t = RemoteChangesBlobV2::from_bytes(&s.get(SECRET_REMOTE_CHANGES_V2).unwrap()).unwrap();
    t.vault_id = other_vid.to_vec();
    s.set(SECRET_REMOTE_CHANGES_V2, &t.to_bytes().unwrap());
    assert!(load_log(&s, &dek, vid, epoch).records.is_empty());
    let mut t = RemoteChangesBlobV2::from_bytes(&seal_log(&dek, vid, epoch, &log).unwrap()).unwrap();
    t.key_epoch = epoch + 1;
    s.set(SECRET_REMOTE_CHANGES_V2, &t.to_bytes().unwrap());
    assert!(load_log(&s, &dek, vid, epoch).records.is_empty());
    assert!(load_log(&s, &dek, vid, epoch + 1).records.is_empty(), "AAD mismatch");
}

#[test]
fn ac14_kind_and_label_registry() {
    assert_eq!(KIND_REMOTE_CHANGES, 0x000D);
    assert!(matches!(ObjectKind::from_u16(0x000D), Ok(ObjectKind::RemoteChanges)));
    assert_eq!(ObjectKind::RemoteChanges.to_u16(), 0x000D);
    assert!(ObjectKind::from_u16(0x000E).is_err());
    let mut seen = std::collections::HashSet::new();
    for l in ROOT_DERIVED_LABELS {
        assert!(seen.insert(*l), "duplicate label {:?}", String::from_utf8_lossy(l));
    }
    assert!(ROOT_DERIVED_LABELS.contains(&LABEL_REMOTE_CHANGES_DEK));
    assert_eq!(LABEL_REMOTE_CHANGES_DEK, b"aegis/v2/remote-changes-dek");
    let t = crate::crypto::build_remote_changes_transcript(&[7u8; 16], 3);
    assert_eq!(&t[9..11], &[0x0D, 0x00]);
}

#[test]
fn log_key_is_not_in_exported_key_lists() {
    use crate::link::LINK_RECORD_KEYS;
    use crate::vault::{LOCAL_ONLY_KEYS_V2, SECRET_KEYS_V2, VAULT_INSTANCE_KEYS};
    assert!(LOCAL_ONLY_KEYS_V2.contains(&SECRET_REMOTE_CHANGES_V2));
    assert!(!SECRET_KEYS_V2.contains(&SECRET_REMOTE_CHANGES_V2));
    assert!(!VAULT_INSTANCE_KEYS.contains(&SECRET_REMOTE_CHANGES_V2));
    assert!(!LINK_RECORD_KEYS.contains(&SECRET_REMOTE_CHANGES_V2));
}

// ---------------------------------------------------------------- AC15

#[test]
fn ac15_rotation_keeps_records() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a.delete("e2");
    a_to_b(&mut a, &mut b);
    let old_epoch = b.v2().key_epoch();
    let r = b.req(VaultRequest::RotateKeys {
        passphrase: PW.into(),
        recovery_key: None,
    });
    match r {
        VaultResponse::Rotated { key_epoch, .. } => assert_eq!(key_epoch, old_epoch + 1),
        other => panic!("rotate: {other:?}"),
    }
    assert!(b.summary("e1").is_some());
    assert_eq!(b.removed().len(), 1);
    b.relock();
    assert_eq!(b.v2().key_epoch(), old_epoch + 1);
    assert_eq!(b.summary("e1").unwrap().kind, RemoteChangeKind::Modified);
    assert_eq!(b.removed().len(), 1);
}

#[test]
fn rotation_with_empty_log_and_no_key_adds_no_key() {
    let (_a, mut b) = pair();
    let r = b.req(VaultRequest::RotateKeys {
        passphrase: PW.into(),
        recovery_key: None,
    });
    assert!(matches!(r, VaultResponse::Rotated { .. }), "{r:?}");
    assert!(!b.store.has(SECRET_REMOTE_CHANGES_V2));
}

// ---------------------------------------------------------------- AC16 (wire)

fn to_value<T: serde::Serialize>(v: &T) -> ciborium::Value {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).unwrap();
    ciborium::from_reader(out.as_slice()).unwrap()
}

fn map_get<'a>(v: &'a ciborium::Value, key: &str) -> Option<&'a ciborium::Value> {
    match v {
        ciborium::Value::Map(m) => m
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

#[test]
fn ac16_new_requests_encode_as_op_maps_and_round_trip() {
    for (req, op) in [
        (VaultRequest::AckRemoteChange { id: "e1".into() }, "ack_remote_change"),
        (VaultRequest::ListRemovedRemote {}, "list_removed_remote"),
        (VaultRequest::AckRemovedRemote {}, "ack_removed_remote"),
    ] {
        let v = to_value(&req);
        assert_eq!(map_get(&v, "op").and_then(|x| x.as_text()), Some(op));
        let mut bytes = Vec::new();
        ciborium::into_writer(&req, &mut bytes).unwrap();
        let back: VaultRequest = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, req);
    }
    let v = to_value(&VaultRequest::AckRemoteChange { id: "e1".into() });
    assert_eq!(map_get(&v, "id").and_then(|x| x.as_text()), Some("e1"));
}

#[test]
fn ac16_responses_round_trip_and_skip_absent_change() {
    let change = RemoteChange {
        entry_id: "e1".into(),
        kind: RemoteChangeKind::Modified,
        changed_at: 9,
        recorded_at: 10,
        entry_name: None,
        fields: vec![
            crate::remote_changes::FieldChange {
                field: "urls".into(),
                label: None,
                old: Some(ChangeValue::List(vec!["a".into()])),
                new: Some(ChangeValue::List(vec!["b".into(), "c".into()])),
            },
            crate::remote_changes::FieldChange {
                field: "password".into(),
                label: None,
                old: None,
                new: None,
            },
        ],
    };
    for resp in [
        VaultResponse::Entry {
            entry: Entry::new("e1", "Mail"),
            remote_change: Some(change.clone()),
        },
        VaultResponse::RemovedRemote {
            entries: vec![change.clone()],
        },
        VaultResponse::RemovedRemote { entries: vec![] },
    ] {
        let mut bytes = Vec::new();
        ciborium::into_writer(&resp, &mut bytes).unwrap();
        let back: VaultResponse = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, resp);
    }
    let none = VaultResponse::Entry {
        entry: Entry::new("e1", "Mail"),
        remote_change: None,
    };
    assert!(map_get(&to_value(&none), "remote_change").is_none());
    let sum = EntrySummary::from(&Entry::new("e1", "Mail"));
    assert!(sum.remote_change.is_none());
    assert!(map_get(&to_value(&sum), "remote_change").is_none());
    let mut with = sum.clone();
    with.remote_change = Some(RemoteChangeSummary {
        kind: RemoteChangeKind::Added,
        changed_at: 5,
    });
    let v = to_value(&with);
    let rc_v = map_get(&v, "remote_change").expect("present");
    assert_eq!(map_get(rc_v, "kind").and_then(|x| x.as_text()), Some("added"));
}

#[test]
fn ac16_synced_remote_changed_defaults_to_zero_for_old_responses() {
    // An old Synced encoding (no remote_changed key) decodes with 0.
    let resp = VaultResponse::Synced {
        action: "pushed".into(),
        remote_revisions: 0,
        detail: String::new(),
        contract_state: vec![],
        owner_verifying_key: vec![],
        sync_params: vec![],
        remote_changed: 0,
    };
    let v = to_value(&resp);
    let ciborium::Value::Map(m) = v else { panic!("map") };
    let stripped: Vec<_> = m
        .into_iter()
        .filter(|(k, _)| k.as_text() != Some("remote_changed"))
        .collect();
    let mut bytes = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(stripped), &mut bytes).unwrap();
    let back: VaultResponse = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(back, resp);
}

// ---------------------------------------------------------------- AC17

#[test]
fn ac17_locked_session_rejects_new_ops() {
    let mut store = MemoryStore::default();
    let mut session: Option<ActiveSession> = None;
    for req in [
        VaultRequest::AckRemoteChange { id: "e1".into() },
        VaultRequest::ListRemovedRemote {},
        VaultRequest::AckRemovedRemote {},
    ] {
        match dispatch(&mut store, &mut session, req) {
            VaultResponse::Error { code, message } => {
                assert_eq!(code, ErrorCode::Locked);
                assert_eq!(message, "vault is locked");
            }
            other => panic!("expected Locked error, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------- misc: new instance

#[test]
fn new_vault_that_never_synced_never_gets_the_key() {
    let a = device_a();
    assert!(!a.store.has(SECRET_REMOTE_CHANGES_V2));
}

#[test]
fn other_ops_leave_the_log_alone() {
    let (mut a, mut b) = pair();
    a.edit("e1", |e| e.username = "alice2".into());
    a_to_b(&mut a, &mut b);
    let before = b.log().clone();
    let r = b.req(VaultRequest::UpsertFolder {
        folder: crate::types::Folder {
            id: "f1".into(),
            name: "Work".into(),
            parent: None,
            created_at: 0,
            updated_at: 0,
        },
    });
    assert!(matches!(r, VaultResponse::Ok), "{r:?}");
    assert_eq!(b.log(), &before);
    let r = b.req(VaultRequest::DeleteFolder { id: "f1".into() });
    assert!(matches!(r, VaultResponse::Ok), "{r:?}");
    assert_eq!(b.log(), &before);
}

#[test]
fn folder_change_shows_folder_names() {
    let (mut a, mut b) = pair();
    let r = a.req(VaultRequest::UpsertFolder {
        folder: crate::types::Folder {
            id: "f1".into(),
            name: "Work".into(),
            parent: None,
            created_at: 0,
            updated_at: 0,
        },
    });
    assert!(matches!(r, VaultResponse::Ok));
    a.edit("e1", |e| e.folder_id = Some("f1".into()));
    a_to_b(&mut a, &mut b);
    let r = b.get("e1").1.unwrap();
    let f = field(&r, "folder");
    assert_eq!(f.old, text(""));
    assert_eq!(f.new, text("Work"));
}
