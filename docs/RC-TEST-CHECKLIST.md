# Aegis v2.0.0-rc.1 test checklist

Human soak for [v2.0.0-rc.1](https://github.com/imcmurray/Aegis/releases/tag/v2.0.0-rc.1). Mix normal use, destructive/recovery paths, and security regressions. The goal is to test like a user, not to repeat the automated RC suite.

That suite already passed (Chromium/Firefox 42/42, dedicated parser fuzz, hosted security CI). Ticking this list is **not** a claim of formal verification or absolute security.

**Build:** GitHub Release `v2.0.0-rc.1`, or the production UI (`2.0.0-rc.1` in the header badge / document title). Use isolated browser profiles for restore, disaster recovery, and corruption tests. Keep copies of backups and kits **before** destructive steps.

Record failures with the [bug report template](#21-bug-report-template).

---

## 1. Installation / first run

- [ ] Open Aegis in Chromium/Chrome
- [ ] Open Aegis in Firefox
- [ ] Confirm version displays `2.0.0-rc.1`
- [ ] Confirm a brand-new browser profile shows the Create Vault screen
- [ ] Create a vault with a strong passphrase
- [ ] Weak passphrase is rejected
- [ ] Long passphrase works
- [ ] Passphrase containing spaces works exactly as entered
- [ ] Unicode passphrase works
- [ ] Refresh/reload after vault creation
- [ ] Vault remains available after browser restart

## 2. Basic vault operations

- [ ] Add a login/password entry
- [ ] Edit an entry
- [ ] Delete an entry
- [ ] Create multiple folders
- [ ] Move entries between folders
- [ ] Add multiple tags
- [ ] Add URL fields
- [ ] Add custom fields
- [ ] Add TOTP if supported by the UI
- [ ] Add password history / change a password
- [ ] Search finds expected entries
- [ ] Search does not produce unexpected entries
- [ ] Large notes/fields work normally
- [ ] Lock and unlock repeatedly
- [ ] Close browser completely, reopen, unlock

## 3. Wrong-credential testing

- [ ] Wrong vault passphrase fails
- [ ] Failed unlock does not damage the vault
- [ ] Correct passphrase still works after several failed attempts
- [ ] Leading/trailing spaces in the real passphrase are significant
- [ ] Case changes do not accidentally unlock
- [ ] RecoverySecret cannot be used as the normal vault passphrase

## 4. Passphrase change

- [ ] Change master passphrase
- [ ] Old passphrase stops working
- [ ] New passphrase works
- [ ] Vault contents remain intact
- [ ] `vault_id` remains unchanged
- [ ] `key_epoch` remains unchanged
- [ ] Existing Recovery Kit still works
- [ ] Backup created before passphrase change remains restorable with its backup password
- [ ] Lock/reload/unlock with new passphrase

## 5. Normal backup

- [ ] Export `.aegis` backup
- [ ] Backup requires a strong backup passphrase
- [ ] Vault passphrase and backup passphrase can be different
- [ ] Save backup somewhere outside the browser/device
- [ ] Restore backup into an empty browser profile
- [ ] Restore requires the backup password
- [ ] Restore separately requires a new live-vault passphrase
- [ ] Missing new vault passphrase is rejected
- [ ] Weak new vault passphrase is rejected
- [ ] Wrong backup password fails
- [ ] Failed restore leaves existing vault untouched
- [ ] Restored entries/folders/TOTP/history are preserved
- [ ] Restored vault has a different `vault_id`
- [ ] Restored vault therefore has a new cryptographic identity

## 6. Backup isolation test

This is one of the most important v2 properties.

- [ ] Create backup A
- [ ] Record/export enough information to identify the original vault
- [ ] Rotate the live vault afterward
- [ ] Restore backup A separately
- [ ] Confirm the restored backup does not assume the current live vault identity
- [ ] Confirm backup password does not unlock the current live vault
- [ ] Confirm ordinary restore creates a fresh RootSecret/identity

## 7. Recovery Kit generation

- [ ] Generate Recovery Kit
- [ ] `.aegis-recovery` file downloads
- [ ] RecoverySecret begins with expected `AEGIS2-…` representation
- [ ] RecoverySecret is shown once
- [ ] Close the one-time display
- [ ] RecoverySecret is not shown again
- [ ] Reload browser and confirm it is not displayed
- [ ] Re-download Recovery Kit without generating a new RecoverySecret
- [ ] Confirm warning says Kit + RecoverySecret grants control of the identity
- [ ] Confirm UI recommends storing the two separately

## 8. Lost-passphrase recovery

Simulate genuinely forgetting the password.

- [ ] Create test vault and Recovery Kit
- [ ] Add several entries
- [ ] Lock vault
- [ ] Use Forgot passphrase / Recovery Kit
- [ ] Supply Recovery Kit
- [ ] Supply RecoverySecret
- [ ] Supply new strong vault passphrase
- [ ] Do **not** supply old vault passphrase
- [ ] Recovery succeeds
- [ ] All entries remain intact
- [ ] Same `vault_id`
- [ ] Same `key_epoch`
- [ ] New passphrase unlocks
- [ ] Old passphrase no longer matters
- [ ] Wrong RecoverySecret fails cleanly
- [ ] Weak new passphrase fails cleanly

## 9. Recovery Kit epoch tests

- [ ] Generate Recovery Kit at epoch 0
- [ ] Rotate cryptographic keys → epoch 1
- [ ] Attempt recovery using stale epoch-0 Recovery Kit
- [ ] Confirm it is rejected against the current vault
- [ ] Generate/use current Recovery Kit
- [ ] Confirm current Kit works
- [ ] Wrong-vault Recovery Kit is rejected

## 10. Full disaster recovery

Simulate losing the entire browser/device. You should have:

- normal `.aegis` backup
- backup password
- `.aegis-recovery`
- RecoverySecret
- new desired vault passphrase

Then:

- [ ] Use a completely empty browser profile
- [ ] Choose identity-preserving disaster recovery
- [ ] Supply Recovery Kit + RecoverySecret
- [ ] Supply `.aegis` backup + backup password
- [ ] Supply new live-vault passphrase
- [ ] Recovery succeeds
- [ ] Entries/folders/history/TOTP survive
- [ ] `vault_id` matches the original identity
- [ ] Recovery differs from ordinary backup restore
- [ ] Wrong backup + correct Recovery Kit fails
- [ ] Correct backup + wrong RecoverySecret fails
- [ ] Recovery Kit from another vault + backup fails
- [ ] Failed recovery leaves the destination clean/intact

## 11. Cryptographic rotation

- [ ] Record current `vault_id`
- [ ] Record current `key_epoch`
- [ ] Rotate cryptographic keys
- [ ] `vault_id` remains unchanged
- [ ] `key_epoch` increments exactly once
- [ ] Vault entries remain unchanged
- [ ] Same passphrase still unlocks
- [ ] Recovery Kit handling matches expectations
- [ ] If preserving RecoverySecret, enter correct current secret
- [ ] Wrong recovery secret aborts rotation
- [ ] If replacing RecoverySecret, new secret is shown once
- [ ] Old RecoverySecret no longer works after replacement
- [ ] Lock/reload/unlock after rotation
- [ ] Change passphrase after rotation and verify everything still works

## 12. Sharing — recipient identity

- [ ] Export SharePublicIdentityV2
- [ ] Import/use recipient identity
- [ ] Create a share
- [ ] Recipient opens share successfully
- [ ] Expected sender identity is required
- [ ] Missing sender identity is rejected
- [ ] Wrong sender identity is rejected
- [ ] Wrong recipient cannot open
- [ ] Modified share envelope fails
- [ ] Corrupted ML-KEM ciphertext fails
- [ ] Core-only/non-hybrid share is rejected

## 13. Sharing — rotation

- [ ] Export recipient share identity at epoch N
- [ ] Create an unopened share to that identity
- [ ] Rotate recipient to epoch N+1
- [ ] Old unopened share is rejected
- [ ] Export new recipient identity
- [ ] New identity differs
- [ ] Create share using new identity
- [ ] New share opens normally
- [ ] Previously imported plaintext remains available

## 14. VaultSync — local

- [ ] Run local v2 sync
- [ ] First revision publishes successfully
- [ ] Additional revision increments counter
- [ ] Sync after editing an entry works
- [ ] Replay/stale revision is rejected
- [ ] Old-epoch revision is rejected after rotation
- [ ] Local state survives browser reload
- [ ] No v1 fallback occurs

## 15. VaultSync — Freenet / mesh, when available

Not part of automated RC validation (no peer). High-value if two Freenet-enabled devices are available.

- [ ] Connect two real Aegis peers
- [ ] Exchange v2 revisions
- [ ] Changes on device A appear on device B
- [ ] Changes on B appear on A
- [ ] Conflicting revisions behave predictably
- [ ] Disconnect/reconnect catches up correctly
- [ ] Replay an older revision and verify rejection
- [ ] Rotate one side and verify identity transition
- [ ] Old sync identity cannot continue authorizing current revisions
- [ ] Network loss during sync does not corrupt local vault

## 16. v1 compatibility / migration

- [ ] Open known-good v1 vault
- [ ] v1 opens read-only
- [ ] Attempt v1 write → migration required
- [ ] Migrate with historical passphrase
- [ ] All data survives
- [ ] New v2 RootSecret is generated
- [ ] Existing live `vault_id` remains as designed
- [ ] New Recovery Kit generated
- [ ] Old v1 recovery path is retired
- [ ] Migrate using v1 recovery key only
- [ ] Supply new D18-compliant v2 passphrase
- [ ] Wrong v1 recovery key fails unchanged
- [ ] Active legacy VaultSync prevents migration rather than silently losing sync identity
- [ ] v1 cannot be newly created from production UI

## 17. Import / corruption testing

Keep copies before doing these.

- [ ] Import random file as `.aegis`
- [ ] Import Recovery Kit as `.aegis`
- [ ] Import `.aegis` as Recovery Kit
- [ ] Truncate backup
- [ ] Flip bytes in backup
- [ ] Truncate Recovery Kit
- [ ] Flip bytes in Recovery Kit
- [ ] Modify version byte
- [ ] Modify magic bytes
- [ ] Import malformed share
- [ ] Import malformed sync object
- [ ] Existing vault stays untouched after every failure

## 18. Browser persistence / privacy

- [ ] Inspect IndexedDB while vault is locked
- [ ] Confirm no `aegis/v2/session`
- [ ] Confirm no plaintext RootSecret
- [ ] Confirm no RecoverySecret
- [ ] Confirm no plaintext vault entries
- [ ] Lock application
- [ ] Reload
- [ ] Browser Back/Forward doesn't reveal secret display
- [ ] RecoverySecret one-time UI doesn't return after refresh
- [ ] Password inputs clear after operations
- [ ] Browser console contains no passwords / RootSecret / RecoverySecret

## 19. Browser compatibility

Repeat the important flows in both browsers.

**Chromium**

- [ ] Create
- [ ] CRUD
- [ ] Reload/unlock
- [ ] Backup
- [ ] Recovery
- [ ] Rotation
- [ ] Sharing
- [ ] Sync

**Firefox**

- [ ] Create
- [ ] CRUD
- [ ] Reload/unlock
- [ ] Backup
- [ ] Recovery
- [ ] Rotation
- [ ] Sharing
- [ ] Sync

## 20. Real-world soak testing

For the RC period:

- [ ] Use Aegis as your normal password manager for several days
- [ ] Lock/unlock many times
- [ ] Restart browser/computer
- [ ] Create backups on different days
- [ ] Restore at least one real RC backup into an isolated profile
- [ ] Generate and safely store a real Recovery Kit
- [ ] Try recovery before relying on that Kit
- [ ] Share between two identities multiple times
- [ ] Rotate once during the RC period
- [ ] Look for slowdowns, UI races, unexpected error messages, or stale state

## 21. Bug report template

For anything that fails, record:

```
Aegis version: 2.0.0-rc.1
Browser + exact version:
OS:
Operation being attempted:
Expected behavior:
Actual behavior:
Reproducible? Yes/No
Steps to reproduce:
Console error (after checking it contains no secrets):
Whether vault data was altered:
Whether lock/reload resolved it:
Whether Chromium and Firefox behave differently:
```

## 22. Before promoting RC → v2.0.0

- [ ] No unresolved data-loss bugs
- [ ] No unresolved authentication bypasses
- [ ] No unresolved backup/recovery failures
- [ ] No unresolved rotation failures
- [ ] No unresolved share identity issues
- [ ] No unresolved sync replay/identity issues
- [ ] Review all GitHub issues opened against v2.0.0-rc.1
- [ ] Recheck RustSec
- [ ] Recheck cargo-deny
- [ ] Recheck npm production audit
- [ ] Run workspace test suite
- [ ] Run WASM checks
- [ ] Production UI build
- [ ] Chromium final smoke
- [ ] Firefox final smoke
- [ ] Update `2.0.0-rc.1` → `2.0.0`
- [ ] Update CHANGELOG
- [ ] Verify release notes
- [ ] Tag exact final commit
- [ ] Publish non-prerelease
- [ ] Verify GitHub `releases/latest` changes to `v2.0.0`
