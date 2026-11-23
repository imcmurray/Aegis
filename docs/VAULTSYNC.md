# VaultSync — multi-device mesh (Freenet identity)

## Identity model (no Google / browser profile)

```
Master passphrase → WrapKek → RootSecret (memory-only)
  → vault-dek / audit-dek / sync-dek
  → sync-ed25519-seed AND sync-mldsa-seed  → HybridSyncIdentityV2
```

- **Only an unlocked v2 session** that holds RootSecret can sign revisions.
- A revision is accepted only if **both** Ed25519 and ML-DSA-65 verify over the D1 transcript **and** the wire keys match the authorized identity for this vault/epoch. Envelope-carried keys alone are not attribution.
- After rotation, old-epoch revisions are rejected; a dual-signed transition record authorizes the new identity.
- File/wire magic is `AEGIS_SYNC_V2`. The Freenet contract app id `AEGIS_VAULT_SYNC_V2` is not file magic.
- Local coherent rollback detection is counter-monotonic per device+epoch. A fully consistent older snapshot can still look valid if no newer counter was retained — that limit is architectural, not a parser bug.

## Contract

- WASM: `aegis_vault_sync.wasm`
- Params (CBOR): v2 `{ ed25519_verifying_key, ml_dsa_verifying_key, app: "AEGIS_VAULT_SYNC_V2" }`
- Instance id: `blake3(code_hash ‖ params_cbor)` (Freenet standard)
- State: signed encrypted revisions (MVR); contract never sees plaintext passwords

## Sync flow (UI + peer)

1. Unlock vault (delegate).
2. `SyncWithRemote` (may start with empty remote) → `contract_state`, `sync_params`, `owner_verifying_key`.
3. `Get` contract for that instance id (miss = first device).
4. `SyncWithRemote` again with remote bytes if any → merge.
5. `Put` (first) or `Update(State)` (later) with new `contract_state`.

## Using two computers

The sync identity comes from the vault's random RootSecret, not from the passphrase. A vault created on device B with the same passphrase has a different RootSecret, so it would sync to a different contract. Device B has to join device A's vault, not create its own. The primary way is a one-time **link code**.

### Link a device (primary)

1. Both: a Freenet peer, and Aegis opened once with `?register=1` to install the delegate.
2. Device A (unlocked): Settings → **Link a device** → **Create link code**. A shows the `AEGL-…` code (also as a QR), a 10-minute countdown and "Waiting for the new device…".
3. Device B (empty delegate, "Create vault" screen): in the **Link this device** card enter the code and the master passphrase of the vault, then press **Link**. B gets the same vault ID, key epoch, entries and sync identity, and its own device ID. A shows "Linked a new device".
4. Both: press **Sync** (B pulls A's latest revision; later edits sync both ways). Both use the same sync contract.

The code expires after 10 minutes, can be cancelled, and is invalidated with a tombstone once used. You need the code **and** the master passphrase; the code alone opens nothing. See `docs/FREENET.md` ("Linking a second device") and `docs/CRYPTO-V2-DECISIONS.md` D21.

### Disaster recovery (Recovery Kit + backup)

If device A is gone, or you cannot create a link code, use a Recovery Kit plus a backup:

1. Device A (unlocked, earlier): Settings → **Recovery Kit** → generate it, keeping the `.aegis-recovery` file and the `AEGIS2-…` secret. Also **Export** a normal `.aegis` backup.
2. Device B (empty delegate, "Create vault" screen): use **Disaster recovery (same identity)** with the kit, its secret, the backup and its password, plus a live passphrase for B. B keeps the vault ID and sync owner key and gets its own device ID.
3. Device A: edit → **Sync**. Device B: unlock → **Sync** → pull/merge. Both use the same sync contract.

Kit + secret = control of the vault identity. Move them out of band and store them apart.

A plain `.aegis` Export/Import moves the entries but mints a **new** identity, so the two copies would not sync with each other.

### Seeing what changed on another device

After a **Sync** that pulls edits from another device, the status line adds "· N entries updated from another device" and the entry list marks those entries with a **New** or **Updated** pill. Open an entry to see a "Changed on another device" panel listing what changed (for example `Username: alice → alice2`, `URLs: added …`, `Password changed`); the pill goes away once you have opened it. Passwords, notes, authenticator seeds and hidden custom fields are never shown, only that they changed. Entries another device deleted are named in a dismissible notice above the folder tree.

The list of changes is kept by the delegate on this device only, encrypted, and is never synced or exported. Your own edits never create entries in it, and it keeps at most 500 records for 30 days. See `docs/CRYPTO-V2-DECISIONS.md` D22.

## Browser mode

`?mode=browser` stays local (IndexedDB). Mesh Sync requires Freenet mode.
