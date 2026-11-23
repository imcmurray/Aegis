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

The sync identity comes from the vault's random RootSecret, not from the passphrase. A vault created on device B with the same passphrase has a different RootSecret, so it would sync to a different contract. Device B needs device A's RootSecret, and today the only way to carry it is a Recovery Kit plus a backup:

1. Both: a Freenet peer, and Aegis opened once with `?register=1` to install the delegate.
2. Device A (unlocked): Settings → **Recovery Kit** → generate it, keeping the `.aegis-recovery` file and the `AEGIS2-…` secret. Then **Export** a normal `.aegis` backup.
3. Device B (empty delegate, "Create vault" screen): use **Disaster recovery (same identity)** with the kit, its secret, the backup and its password, plus a live passphrase for B. B keeps the vault ID and sync owner key and gets its own device ID.
4. Device A: edit → **Sync**. Device B: unlock → **Sync** → pull/merge. Both use the same sync contract.

Kit + secret = control of the vault identity. Move them out of band and store them apart. A dedicated "link a device" flow is future work.

A plain `.aegis` Export/Import moves the entries but mints a **new** identity, so the two copies would not sync with each other.

## Browser mode

`?mode=browser` stays local (IndexedDB). Mesh Sync requires Freenet mode.
