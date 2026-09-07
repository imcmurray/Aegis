# Aegis Architecture

Decentralized password manager on **next-generation Freenet** (contracts + delegates).  
No central servers; private vault data lives in a **Delegate**; multi-device and sharing use **encrypted Contracts**.

## Goals (MVP)

- Master-passphrase unlock of a client-side encrypted vault
- Password generator, entries, folders, search, autofill-friendly schema
- Multi-device sync via encrypted vault state (only the user’s devices decrypt)
- Encrypted backup/export
- Local audit log

## Component map

```
Browser UI  ──WebSocket──►  Freenet Core (local peer)
                               │
                               ├─ Vault Delegate  (private: DEK, crypto, audit)
                               │
                               └─ Contracts
                                    ├─ VaultSync   (ciphertext only, multi-device)
                                    └─ Share*      (phase 3: capability-wrapped items)
```

| Component | Trust zone | Plaintext secrets? | Role |
|-----------|------------|--------------------|------|
| **Vault Delegate** | Local Core | Yes, after unlock | KDF, AEAD, CRUD, audit, sync encrypt/sign |
| **VaultSync Contract** | Network | Never | Replicated encrypted revisions + write auth |
| **Share contracts** | Network | Never | Phase 3 — ECIES-wrapped item keys |
| **UI** | Browser iframe | Transient display only | UX; messages only via Core |

## Key hierarchy (v2 production)

```
Master passphrase
    │ Argon2id ≥ 64 MiB (WrapKek)     independent RecoverySecret (256-bit CSPRNG)
    ▼                                          │ HKDF recovery-kek
RootSecret (32 B, memory-only)  ◄── wrap ──────┘  Recovery Kit file
    │ HKDF-SHA256, salt = vault_id
    ├─ vault-dek / audit-dek / sync-dek / search-hmac
    ├─ sync-ed25519-seed + sync-mldsa-seed     (suite 0x0003, AND)
    └─ share-x25519-seed + share-mlkem-seed    (suite 0x0004, D5 combiner)
```

Passphrase change re-wraps the **same** RootSecret (no vault re-encrypt, epoch unchanged).  
Full rotation mints a new RootSecret, increments `key_epoch`, and replaces sync/share identities.  
Normal backups do **not** contain RootSecret and restore as a **new** identity.  
A Recovery Kit restores the **same** identity; it is not a backup.

## Private vs shared state

| Need | Where |
|------|--------|
| Only my devices | Delegate secrets + optional encrypted VaultSync |
| Another Freenet identity | Share contract + capability crypto |
| App packaging | Web container contract (UI assets only) |

**Never** put vault plaintext, DEK, or master secret in a contract.

## Data model (summary)

- **VaultDocument**: folders, entries (name, urls, username, password, notes, custom fields), tombstones
- **Entry**: autofill-friendly (`urls`, `username`, `password`)
- **VaultSyncState**: multi-value register of `EncryptedRevision` (cleartext version vectors + opaque ciphertext + owner signature)
- **AuditEvent**: local only in MVP (no secrets in detail strings)

See `common/src/types.rs` for the source of truth.

## Freenet patterns (from River / docs)

- **River chat-delegate**: holds keys, signs without export → Aegis vault-delegate does the same for vault ops
- **River private rooms**: AES-GCM + ECIES distribution → Aegis vault uses passphrase-derived DEK; shares use ECIES later
- **Composable contracts / freenet-scaffold**: useful for share inboxes; VaultSync can stay a thin signed MVR
- **Platform gap**: core cross-device delegate sync is not shipped yet (see freenet-core #4560 / vault-delegate discussions). Aegis implements **app-level** VaultSync.

## Tech stack

| Layer | Choice |
|-------|--------|
| Contracts / delegates | Rust → `wasm32-unknown-unknown`, `freenet-stdlib` 0.8.x |
| Shared types / crypto | `common` crate (serde + CBOR + AEAD + Argon2id) |
| UI | TypeScript + Vite + `@freenetorg/freenet-stdlib` |
| AEAD | XChaCha20-Poly1305 |
| KDF | Argon2id |
| Signatures | Ed25519 **AND** ML-DSA-65 on sync (0x0003) |
| Share KEM | X25519 **AND** ML-KEM-768 (0x0004) |
| Storage AEAD | XChaCha20-Poly1305 (Core 0x0002) |

## Implementation status

Phases 0–9 of [`CRYPTO-V2.md`](./CRYPTO-V2.md) §66 are implemented. Phase 10 is hardening, fuzzing, dependency review, and documentation — not a new protocol.

v1 remains decode/migration only. Production create/unlock/backup/sync/share/recovery is v2.

## Repository layout

```
Aegis/
├── docs/                 # architecture, threat model, crypto
├── common/               # types, crypto, vault logic, messages
├── contracts/vault-sync/ # encrypted multi-device state
├── delegates/vault-delegate/
├── ui/                   # Vite + TypeScript
└── tests/                # integration / vectors (via common unit tests for now)
```

## Security pointers

Full threat model: [THREAT_MODEL.md](./THREAT_MODEL.md)  
Crypto details (implemented v2): [CRYPTO.md](./CRYPTO.md)  
v2 contract / gap / decisions: [CRYPTO-V2.md](./CRYPTO-V2.md), [CRYPTO-V2-GAP.md](./CRYPTO-V2-GAP.md), [CRYPTO-V2-DECISIONS.md](./CRYPTO-V2-DECISIONS.md)
