# Aegis Cryptography

## Algorithms (v1)

| Purpose | Algorithm | Notes |
|---------|-----------|--------|
| Passphrase KDF | Argon2id | Salt 16 bytes; params profiled (see below) |
| Vault / envelope AEAD | XChaCha20-Poly1305 | 24-byte nonce, 16-byte tag |
| Key derivation | HKDF-SHA256 | Domain-separated labels |
| Sync write auth | Ed25519 | Contract verifies under owner VK |
| Share key wrap (phase 3) | X25519 + HKDF + AEAD | River private-room analog |

## KDF profiles

| Profile | Memory | Iterations | Parallelism | Use |
|---------|--------|------------|-------------|-----|
| `Interactive` | 64 MiB | 3 | 1 | Default desktop |
| `Mobile` | 32 MiB | 2 | 1 | Constrained peers |
| `High` | 128 MiB | 4 | 2 | High-security vaults |
| `Test` | 8 KiB | 1 | 1 | Unit tests only |

## Envelope formats

All sealed blobs are versioned:

```
AegisEnvelopeV1 {
  version: u16 = 1,
  kind: enum { MasterWrap, VaultBlob, ExportBlob, SyncPayload },
  nonce: [u8; 24],
  ciphertext: bytes,   // includes Poly1305 tag (as produced by crate)
}
```

**AAD** (where applicable): `b"aegis/v1" || kind || vault_id || logical_id`

## HKDF labels

| Label | Output |
|-------|--------|
| `aegis/v1/vault-dek` | 32-byte vault DEK |
| `aegis/v1/sync-sign` | 32-byte Ed25519 seed |
| `aegis/v1/sync-addr` | 32-byte addressing material |
| `aegis/v1/search-hmac` | 32-byte HMAC key (optional) |
| `aegis/v1/share-ecdh` | 32-byte X25519 seed (phase 3) |

## Master wrap

1. Generate random `MasterSecret` (32 B) and `salt` (16 B).
2. `KEK = Argon2id(passphrase, salt, params)`.
3. Seal `MasterSecret` under KEK → stored in delegate secret `aegis/v1/envelope`.
4. Vault document sealed under `vault-dek` → `aegis/v1/vault`.

## Test vectors

Unit tests in `common` pin seal/open round-trips and Argon2 unwrap.  
Do not treat `Test` KDF profile as production strength.

## What must never appear on the network in cleartext

- Passwords, notes, TOTP seeds, attachment bytes
- MasterSecret, KEK, vault DEK
- Recovery key material
- Unblinded search queries (if network search is ever added)
