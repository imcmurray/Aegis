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

## Key hierarchy

```
Master Passphrase
    │ Argon2id(salt, params)
    ▼
  KEK  ──unwrap──►  MasterSecret (32 B random)
                        │ HKDF-SHA256 labels
                        ├─ aegis/v1/vault-dek
                        ├─ aegis/v1/sync-sign   (Ed25519)
                        ├─ aegis/v1/sync-addr
                        ├─ aegis/v1/search-hmac (optional)
                        └─ aegis/v1/share-ecdh  (X25519, phase 3)
```

Passphrase change re-wraps `MasterSecret` only (no full vault re-encrypt).  
Optional recovery key wraps `MasterSecret` independently.

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
| Signatures | Ed25519 |
| ECDH (shares) | X25519 |

## Phased roadmap

1. **Phase 1** — Local vault (create/unlock/CRUD/generator/export/audit) — *current scaffold target*
2. **Phase 2** — VaultSync multi-device
3. **Phase 3** — Secure sharing
4. **Phase 4** — TOTP, attachments, health dashboard, emergency access, biometrics

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
Crypto details: [CRYPTO.md](./CRYPTO.md)
