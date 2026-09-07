# Aegis development guide

## Three vault backends

| Mode | URL | Crypto | When to use |
|------|-----|--------|-------------|
| **mock** | `http://localhost:5173/` or `?mode=mock` | Browser Web Crypto (weak) | UI-only iteration |
| **dev** | `?mode=dev` | **Real** Argon2id + XChaCha20 via Rust | Default for security-sensitive testing |
| **freenet** | `?mode=freenet` | Real crypto in vault-delegate WASM | On a Freenet peer |

## Quick paths

### UI + mock (no Rust server)

```bash
cd ui && npm ci && npm run dev
# open http://localhost:5173/
```

Runtime JavaScript is **self-hosted only** (Vite bundles `node_modules`; no CDN scripts). Production builds inject a strict **meta** CSP (`default-src 'self'`; `script-src 'self' 'wasm-unsafe-eval'`; no `'unsafe-inline'` / `'unsafe-eval'`). The Vite dev server omits CSP so HMR works.

`frame-ancestors` is **not** in that meta policy: browsers ignore it on `<meta http-equiv>` (CSP Level 3). GitHub Pages cannot send CSP headers, so framing is not a claimed control there. A future reverse proxy/CDN should add `Content-Security-Policy: …; frame-ancestors 'none'` as an HTTP header.

`connect-src` allows `'self'` plus `http://127.0.0.1:8787` (`?mode=dev`) and `ws://127.0.0.1:7509` (`?mode=freenet`). A custom `AEGIS_DEV_PORT` is not in the production policy.

### UI + real crypto (recommended next)

Terminal 1:

```bash
cargo run -p aegis-dev-vault-server
# listens on http://127.0.0.1:8787
```

If you see **Address already in use**, a prior instance is still running:

```bash
ss -ltnp | grep 8787
kill <pid>
# or use another port:
AEGIS_DEV_PORT=8788 cargo run -p aegis-dev-vault-server
# then open: http://localhost:5173/?mode=dev&devUrl=http://127.0.0.1:8788
# (production CSP allows only :8787; custom ports are a local-dev concern)
```

Terminal 2:

```bash
cd ui && npm run dev
# open http://localhost:5173/?mode=dev
```

Badge should read **`dev vault (rust)`**.  
Check: create vault → add entry → lock → unlock again.

### Persistence & multi-device sync (dev)

Encrypted vault material is stored under:

```
~/.local/share/aegis-dev/secrets/   # envelope + sealed vault
~/.local/share/aegis-dev/sync/      # multi-device sync ciphertext
```

Override with `AEGIS_DEV_DATA=/path/to/dir`.

**Sync:** with the vault unlocked, click **Sync** in the UI (`SyncNow`).  
On the **dev server**, that pushes/pulls an encrypted revision into the shared
sync file. Two machines that share that path (or copy the `sync/` file) can
converge if they use the same master passphrase / MasterSecret.

On **Freenet** (`mode=freenet`), the same button uses a secret-store-backed MVR
(`aegis/v1/sync-state`) on the local node — no more “sync transport not
configured”. Network multi-device via the VaultSync contract is still TODO.

Restart the dev server — your vault should still unlock (session key is not persisted; you re-enter the passphrase).

### Folders, TOTP, auto-lock, health, settings

- **Folders** — left panel: create/filter/delete; assign on each entry.
- **TOTP** — paste a Base32 authenticator seed on an entry; live 6-digit code + countdown; Copy code.
- **Auto-lock** — configurable idle timeout (Settings; default 5 min; stored in `localStorage`).
- **Health** — toolbar button; local analysis for empty / short / weak charset / reused / common passwords. Click an issue to open that entry.
- **Settings** — change master passphrase (re-wraps MasterSecret only; entries stay encrypted under the same DEK).
- **Recovery key** — Settings → Generate recovery key (shown once). Unlock screen can use recovery key if passphrase is lost. Revoke anytime. Recovery wraps the same MasterSecret under a separate high-entropy key (`AEGIS-XXXX-…`).

### Reset local dev vault

```bash
rm -rf ~/.local/share/aegis-dev
# then restart aegis-dev-vault-server
```

### CBOR golden vectors

```bash
# Rust
cargo test -p aegis-common golden_vectors -- --nocapture
cargo test -p aegis-common print_golden_hex -- --nocapture

# TypeScript (must match Rust hex)
cd ui && npm run test:cbor
```

### Build WASM

```bash
cargo build --release --target wasm32-unknown-unknown \
  -p aegis-vault-sync --features freenet-main-contract
cargo build --release --target wasm32-unknown-unknown \
  -p aegis-vault-delegate --features freenet-main-delegate
```

Artifacts:

- `target/wasm32-unknown-unknown/release/aegis_vault_sync.wasm`
- `target/wasm32-unknown-unknown/release/aegis_vault_delegate.wasm`

## Freenet peer path (when `freenet` / `fdev` are installed)

```bash
# Install from freenet-core (see https://freenet.org/build/manual/tutorial/)
freenet local

# Publish / register the vault-delegate (exact fdev flags evolve — check fdev --help)
fdev -p 7509 publish \
  --code target/wasm32-unknown-unknown/release/aegis_vault_delegate.wasm \
  delegate
```

Then open the UI through the peer (or Vite with `/v1` proxy) with:

```
?mode=freenet&delegateKey=<base58>&codeHash=<base58>
```

Or set once:

```js
localStorage.setItem("aegis.delegateKey", "...");
localStorage.setItem("aegis.codeHash", "...");
```

Delegate messages use **CBOR** `VaultRequest` / `VaultResponse` (same as the dev server).

## Protocol

- **Wire format:** CBOR (ciborium on Rust, cbor-x on TS)
- **Request tag field:** `op` (snake_case)
- **Response tag field:** `type` (snake_case)
- **Binary fields** (`blob`): CBOR major type 2 (byte string), not array of ints

See `common/src/messages.rs` and `ui/src/cbor.ts`.

## Crypto modules

Production create/unlock/backup/sync/share/recovery is **v2** (`VaultSessionV2`). v1 (`v1.rs`) is decode/migration only. Frozen v1 fixtures: `common/tests/fixtures/v1/` — do not regenerate.

See [CRYPTO.md](./CRYPTO.md) for suites, magics, backup vs Recovery Kit, and hybrid rules.

## Parser fuzzing (Phase 10)

CI runs a deterministic parser smoke (`common/tests/phase10.rs`) over random/mutated inputs for every §56 external decoder. That is not a substitute for a long libFuzzer campaign.

Longer runs (nightly + clang):

```bash
cargo install cargo-fuzz
cd fuzz
# optional: seed corpora with valid fixtures
mkdir -p corpus/master_envelope_v2
cp ../common/tests/fixtures/v1/*.cbor corpus/v1_master_envelope/ 2>/dev/null || true
cargo +nightly fuzz run master_envelope_v2
cargo +nightly fuzz run vault_blob_v2
cargo +nightly fuzz run backup_envelope_v2
cargo +nightly fuzz run recovery_kit_v2
cargo +nightly fuzz run sync_state_v2
cargo +nightly fuzz run share_envelope_v2
cargo +nightly fuzz run v1_master_envelope
```

The `fuzz/` package is **not** a workspace member (libfuzzer-sys / nightly). Do not add it to the root `Cargo.toml`.
