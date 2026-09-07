# Frozen Aegis v1 fixtures

Phase 1 / PR B. These bytes are the v1 compatibility corpus.

**All passphrases, recovery keys, TOTP seeds, and passwords in this directory are synthetic test data.** They were generated for CI. They are not a real user's vault and must never be treated as leaked credentials.

**Do not regenerate after Phase 2 lands.** Later code must prove it can still read *these* files, not a freshly minted envelope from current `wrap_master`. `SHA256SUMS` is hashed in CI so accidental regeneration is a test failure.

Regenerate only if a v1 encoder bug is found *before* Phase 2, with:

```bash
AEGIS_REGEN_V1_FIXTURES=1 cargo test -p aegis-common --test v1_compat regen_v1_fixtures -- --ignored --nocapture
```

## Contents

| Path | What |
|------|------|
| `test-kdf/` | Vault created with `KdfProfile::Test` (8 KiB Argon2). Fast tests. |
| `interactive-kdf/` | Vault created with `KdfProfile::Interactive` (64 MiB Argon2). Proves production-strength envelopes decode. |

Each directory:

| File | Format |
|------|--------|
| `store.cbor` | `MemoryStore::export_cbor_skip_session` — envelope, vault blob, audit, recovery envelope. No session key. |
| `export.aegis` | v1 `ExportBundle` CBOR (`format: 1`). Export passphrase is **not** the vault passphrase. Envelope is **Mobile** KDF wrapping the **same** MasterSecret as the live vault (v1 defect §21). |
| `envelope.cbor` | `MasterEnvelope` from `aegis/v1/envelope`. |
| `vault.cbor` | `SealedBlob` from `aegis/v1/vault`. |
| `recovery-envelope.cbor` | `MasterEnvelope` from `aegis/v1/recovery-envelope`, AAD logical id `recovery`. |
| `recovery-key.txt` | Display form of the recovery key (`AEGIS-…`). Test secret, not a user secret. |

## Passphrases (test-only)

- Vault: `correct horse battery staple`
- Export: `export-passphrase-v1`

Documented v1 properties these files exist to pin:

1. Export re-wraps the live MasterSecret (not an independent BackupKey).
2. Export KDF is `Mobile` even when the vault is `Interactive`.
3. Recovery envelope unwraps the same MasterSecret.
4. Vault document preserves folder, TOTP, password history, custom fields.
