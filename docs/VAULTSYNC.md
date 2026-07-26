# VaultSync — multi-device mesh (Freenet identity)

## Identity model (no Google / browser profile)

```
Master passphrase
  → MasterSecret
      → vault-dek          (passwords)
      → sync-sign Ed25519  → owner_verifying_key  ← “you” on the mesh
```

- **Only an unlocked session** that holds MasterSecret can sign revisions.
- Nobody can “id as you” without passphrase/recovery (see threat model).
- Optional future Freenet IAM is separate; this is sufficient for vault ownership.

## Contract

- WASM: `aegis_vault_sync.wasm`
- Params (CBOR): `{ owner_verifying_key: [u8;32], app: "AEGIS_VAULT_SYNC_V1" }`
- Instance id: `blake3(code_hash ‖ params_cbor)` (Freenet standard)
- State: signed encrypted revisions (MVR); contract never sees plaintext passwords

## Sync flow (UI + peer)

1. Unlock vault (delegate).
2. `SyncWithRemote` (may start with empty remote) → `contract_state`, `sync_params`, `owner_verifying_key`.
3. `Get` contract for that instance id (miss = first device).
4. `SyncWithRemote` again with remote bytes if any → merge.
5. `Put` (first) or `Update(State)` (later) with new `contract_state`.

## Using two computers

1. Both: Freenet peer + Aegis `?mode=freenet&register=1` once.
2. Both: same master passphrase (same identity keys).
3. Device A: edit → **Sync**.
4. Device B: unlock → **Sync** → pull/merge.

Until mesh works on your peer version, keep **Export/Import** as backup.

## Browser mode

`?mode=browser` stays local (IndexedDB). Mesh Sync requires Freenet mode.
