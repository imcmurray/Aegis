# Changelog

## [Unreleased]

### Native CLI

- Production `aegis` binary (`tools/cli`, package `aegis-cli`): file-backed vault under `~/.local/share/aegis/`, unix-socket session agent, JSON/CBOR `VaultRequest` RPC (`--protocol-version` = 1)
- Not a wrapper around `aegis-dev-vault-server`; no TCP
- `cargo install --path tools/cli` — see [docs/CLI.md](docs/CLI.md)
- `aegis import --replace` restores a `.aegis` backup over an existing vault (still requires a new live passphrase)

## [2.0.0-rc.1] — 2026-09-06

Aegis v2 has completed its planned architecture, implementation, adversarial review, browser validation, fuzzing, and security-CI gates; this does not constitute a claim of formal verification or absolute security.

Application version is `2.0.0-rc.1` (workspace crates + UI). Provenance:

- `b33e6eb` — RC-validated implementation
- `275be3e` — changelog notes
- this commit — same implementation plus release metadata/versioning (the `v2.0.0-rc.1` tag should point here)

### Release-candidate gates

- Architecture contract, Phases 0–10 / PRs B–L, and §72 implementation review: accepted
- Production UI/WASM: 42/42 Chromium 153.0.8010.12, 42/42 Firefox 155.0 (IndexedDB, backup/restore, Recovery Kit, rotation, hybrid share, old-epoch share rejection, local v2 VaultSync)
- Dedicated libFuzzer campaigns: 79,818,627 inputs across seven parser surfaces; no crashes, hangs, or OOMs
- Hosted GitHub Actions: Rust tests, WASM, UI, CSP, frozen v1 fixtures, ML-DSA/ML-KEM ACVP, RustSec, cargo-deny, production `npm audit --omit=dev`

### v2 behavior (relative to 0.1.x)

- Independent `.aegis` backups mint a **new** live identity; Recovery Kit + secret preserve identity
- Atomic persistence / candidate-then-commit; passphrase change does not rotate `RootSecret`
- Explicit cryptographic rotation increments `key_epoch` and invalidates unopened hybrid shares to the old identity
- Hybrid PQ sync/share suites (`0x0003` / `0x0004`); expected-sender required to open a share

### Not claimed / not reopened

- Not formally verified; not a claim of absolute security
- Documented limits remain: coherent local rollback without retained newer state; empty-install stale-kit detection; unlocked-process memory; GitHub Pages meta-CSP cannot enforce `frame-ancestors`
- Freenet mesh Sync is still peer-gated; production browser UI disables it without a peer
- Independent professional cryptographic audit would be additional assurance, not an unresolved defect from this review

## [0.1.1] — 2026-07-26

### Multi-device / unlock UX

- **Replace vault from backup** on the locked unlock screen (`import_encrypted` with `replace: true`) for re-syncing a stale browser
- **`preview_import` dry-run**: compare local vs backup (only-local, only-backup, changed fields — no secret values)
- Preview results in a **modal** (“Changes if you replace”) with Close / Replace; short confirm after review
- Compact full-width unlock card: passphrase + Unlock on one row; recovery and replace side-by-side collapsibles

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
