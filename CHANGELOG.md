# Changelog

## [Unreleased]

Crypto suites, wire formats and the CLI protocol (`1`) are unchanged.

### Added

- Freenet delegate upgrade path (D20). A committed history manifest (`delegates/vault-delegate/history.json`) lists earlier vault delegates. When the current delegate has no vault, the UI finds one under an earlier delegate and offers "Upgrade your vault"; after the passphrase it moves the vault over. Delegates with the new `ExportForUpgrade` op keep the vault identity; older ones (such as the live `Br4Y…` build) move through an encrypted backup and the vault gets a new sync identity. Adds `ExportForUpgrade` / `ImportUpgradeSnapshot` (envelope-only). Crypto, persisted formats and the CLI protocol are unchanged; the delegate WASM hash changes.

### Changed

- Freenet web container: a "Connecting to your Freenet node…" screen with a spinner and elapsed time shows while the peer connection opens, and Sync shows a spinner with a running clock.

### Fixed

- Freenet web container on Firefox showed "freenet (unreachable)": Firefox's first relayed WebSocket attempt fails and the node's shell retries it, which took longer than the UI's 5 s open timeout. The open timeout is now 20 s, and the peer probe allows 20 s inside a container. A real connection failure now shows the underlying error.
- Freenet Sync reported "Request timeout" although the publish succeeded: the node answers a Put/Update only after network routing (46 s to 2 min observed), and freenet-stdlib gives up after 30 s. On that timeout Sync now reads the contract back and reports success when the node already holds exactly the published state ("stored on this node; network still confirming").
- Downloads (Recovery Kit, `.aegis` backup, share files) did nothing in a Freenet web container on Firefox: a `blob:` download from the sandboxed opaque-origin frame becomes `blob:null/…`, which the node shell's CSP blocks. Inside a container Aegis now hands the file to the shell's download relay (`postMessage` to the serving node's origin only).
- Inside a Freenet web container Aegis always uses the Freenet delegate. The node's shell mirrors in-frame navigation into the address bar, so a `?mode=browser` picked once stuck across refreshes; the advanced backend links are hidden there.
- The Freenet vault no longer re-locks after every request. The delegate now returns a session token sealed under a rotating key in its secret store; the UI holds it in tab memory and sends it back, so an unlocked v2 vault stays unlocked until Lock, 15 min idle, a 12 h cap or another tab unlocking (D19). This adds a new local-only UI↔delegate IPC envelope `{v, token, req|resp}`; crypto suites, persisted formats and the CLI protocol are unchanged. The delegate WASM hash changes.
- A real Freenet node (freenet 0.2.16x) rejected `aegis_vault_sync.wasm` and `aegis_vault_delegate.wasm` because they imported `__wbindgen_placeholder__` / `__wbindgen_externref_xform__`. Root cause: `aegis-common` unconditionally enabled getrandom 0.2 `js`, `js-sys` and getrandom 0.4 `wasm_js` on `wasm32-unknown-unknown`, which compiled wasm-bindgen glue into the Freenet WASM. Those are now behind a new `browser` feature (used only by `aegis-browser-wasm`). The contract and delegate import only `freenet_*` host modules.
- All Freenet randomness now comes from the host RNG (`freenet_stdlib::rand`): getrandom 0.2 through the registered custom hook, and getrandom 0.4 (reached via ml-dsa/ml-kem) through its `custom` backend. A host length mismatch panics instead of truncating or zero-padding. `.cargo/config.toml` defaults wasm32 to `getrandom_backend="custom"`; the browser build overrides it with `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`. Mixed or missing backends fail the build.
- Freenet-hosted Aegis showed "Peer offline". Freenet 0.2.16x serves web containers in a sandboxed iframe and injects inline scripts, including the WebSocket bridge, and Aegis's CSP (`script-src 'self' 'wasm-unsafe-eval'`) blocked them. `scripts/publish-freenet.sh` now publishes a separate `ui-freenet` copy whose CSP allows exactly the node's injected scripts by sha256 (`scripts/freenet-csp-hashes.py`, read from the live node at publish time), not `'unsafe-inline'`. The GitHub Pages CSP is unchanged. If a node upgrade changes the bridge, Aegis now reports "Bridge blocked: republish" instead of "Peer offline".

### Changed

- Bumped `freenet-stdlib` to 0.12.1 and `@freenetorg/freenet-stdlib` to 0.4.0.
- CI now builds both Freenet WASMs and fails if either imports a module not starting with `freenet_` or contains `__wbindgen` (`scripts/check-wasm-imports.py`, also run by `scripts/build-wasm.sh` and `cargo make build`).

### Freenet contract identity changed again

The contract and delegate WASM bytes change again, so their Freenet code hashes and instance addresses change too.


## [2.0.0-rc.2] — 2026-11-22

Security dependency refresh. Crypto suites, wire formats and the CLI protocol (`1`) are unchanged. Application version is `2.0.0-rc.2`.

### Security

- `ctutils` 0.4.2 → 0.4.8 (RUSTSEC-2026-0385: non-constant-time mask generation and `u128` comparisons). It is reached via `blake3` → `digest` in every crate, including the contract and delegate.
- `tokio` 1.53.1 → 1.54.1 (RUSTSEC-2026-0386: `AsyncFd` I/O-safety unsoundness). Only `tools/dev-vault-server` uses it.
- `chrono` (RUSTSEC-2026-0543, unmaintained) is ignored in `deny.toml` and `.cargo/audit.toml`, with the reason recorded. It is a mandatory dependency of `freenet-stdlib` (0.8.4 through 0.12.1), and its in-memory layout is the Freenet host-time ABI, so Aegis cannot swap it unilaterally.

### Freenet contract identity changed

The VaultSync contract and vault delegate WASM differ from rc.1, so their Freenet instance addresses differ too (address = code hash + params). No real vaults existed on the rc.1 contract. Release build (`--release`, wasm32-unknown-unknown, rustc 1.98.1) sha256:

- `aegis_vault_sync.wasm` `b216eba06170ec9d163557858550abc174208b4d28be171af677139f17ac3086`
- `aegis_vault_delegate.wasm` `27387dddcaabee8b386713848af791d6b1064a7b2311b1b5183e0899f0fe73f8`

## [2.0.0-rc.1.1] — 2026-09-11

Follow-on to `v2.0.0-rc.1` (semver spelling of an rc1-1). Crypto/protocol unchanged. Application version is `2.0.0-rc.1.1`.

### Native CLI

- Production `aegis` binary (`tools/cli`): file-backed vault under `~/.local/share/aegis/`, unix-socket session agent, JSON/CBOR RPC (`--protocol-version` = 1)
- Attested linux-x86_64 artifact: GitHub Actions `--locked` build (rustc 1.98.1), `SHA256SUMS`, and provenance attestation. That is the binary omarchy-aegis verifies.
- `aegis import --replace` wipes an existing vault and restores `.aegis` **data** as a **new** live identity (D18: new live passphrase ≠ backup password). Default import still refuses if a vault exists. Not Recovery Kit identity-preserving restore. `--preview` conflicts with `--replace`.
- See [docs/CLI.md](docs/CLI.md)

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
