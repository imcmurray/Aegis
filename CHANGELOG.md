# Changelog

## [0.1.0] — 2026-07-26

First public release.

### Features

- **Browser vault** (default): real Argon2id + XChaCha20 crypto in WASM, sealed secrets in IndexedDB — no Freenet required
- **Freenet mode** (optional): vault-delegate + VaultSync mesh Put/Get/Update under owner verifying key identity
- **Dev mode**: local Rust HTTP vault server
- Entries, folders, labels, TOTP, password health, generator, recovery key
- Encrypted export/import (`.aegis`)
- GitHub Pages deploy workflow

### Identity (VaultSync)

- Owner identity = Ed25519 key derived from MasterSecret (not third-party login)
- Only an unlocked session can sign sync revisions

### Known limits

- Browser vault is per browser profile; multi-device without Freenet uses Export/Import
- Freenet mesh requires a local peer and may vary by peer/fdev version
- Optional Freenet IAM layer deferred
