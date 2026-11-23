# Running Aegis on Freenet

This guide gets the vault-delegate onto a local Freenet peer and the UI talking to it.

> Until Freenet is installed, keep using `?mode=dev` (real crypto via `aegis-dev-vault-server`).

## Prerequisites

1. **Rust** + `wasm32-unknown-unknown`
2. **Freenet + fdev** (from [freenet-core](https://github.com/freenet/freenet-core)):

```bash
git clone https://github.com/freenet/freenet-core.git
cd freenet-core
cargo install --path crates/core    # installs `freenet`
cargo install --path crates/fdev    # installs `fdev`
```

3. **Node** 20+ for the UI

## 1. Build WASM + stage for the UI

```bash
cd /path/to/Aegis
chmod +x scripts/build-wasm.sh
./scripts/build-wasm.sh
```

This produces:

- `ui/public/aegis_vault_delegate.wasm`
- `ui/public/aegis_vault_sync.wasm`
- `ui/public/aegis_vault_delegate.hash.json` (blake3 / base58 code hash)

## 2. Start a local Freenet peer

```bash
freenet local
# WebSocket API default: ws://127.0.0.1:7509/v1/contract/command
```

## 3. Register the vault-delegate

### Option A — from the UI (experimental)

```bash
cd ui && npm run dev
# IMPORTANT: only add register=1 once; large WASM can drop the WebSocket (code 1006)
# open http://localhost:5173/?mode=freenet&register=1
# then reload WITHOUT register=1:
# open http://localhost:5173/?mode=freenet
```

The client sends `RegisterDelegate` using the staged WASM + hash file, stores
instance key + code hash in `localStorage`, and reconnects.

**Note:** freenet-stdlib requires `cipher` (32 bytes) + `nonce` (24 bytes) on
register; empty arrays crash the peer (`TryFromSliceError`). Aegis sends zeros
for local unencrypted secret storage.

Prefer **fdev** if browser register still drops the peer (very large WASM).

### Option B — fdev (preferred when CLI is available)

```bash
# Check exact subcommands for your fdev version:
fdev --help

# Typical pattern (names evolve — adjust to your fdev):
fdev -p 7509 publish \
  --code target/wasm32-unknown-unknown/release/aegis_vault_delegate.wasm \
  delegate
```

Copy the printed **delegate key** / **code hash** into the UI:

```
http://localhost:5173/?mode=freenet&delegateKey=BASE58&codeHash=BASE58
```

Or once in the browser console:

```js
localStorage.setItem("aegis.delegateKey", "<base58>");
localStorage.setItem("aegis.codeHash", "<base58>");
location.href = "/?mode=freenet";
```

## 4. Open the app

| URL | Meaning |
|-----|---------|
| `/?mode=dev` | Local HTTP vault (recommended day-to-day) |
| `/?mode=freenet` | Freenet peer + delegate |
| `/?mode=freenet&ws=127.0.0.1:7509` | Explicit peer host |
| `/?mode=freenet&register=1` | Try auto-register WASM |

Badge should read **`freenet delegate`** when keys work and the peer answers.

## Protocol

- UI → Freenet Core → **vault-delegate** (`ApplicationMessage` payload = CBOR envelope `{v: 1, token, req}`, where `req` is a `VaultRequest` and `token` is a byte string or null)
- Response: CBOR envelope `{v: 1, token, resp}`, where `resp` is a `VaultResponse`
- The envelope is local-only (UI ↔ delegate). It is not a persisted or network format. A bare `VaultRequest` / `VaultResponse` (no `v`) is still accepted and answered statelessly with no token.
- Secrets stay in the delegate secret store (same as dev server FileStore, but Freenet-managed)

### How a Freenet session stays unlocked

The delegate runs fresh for every request, so it cannot remember an unlock. Instead:

1. After a successful unlock of a v2 vault the delegate returns an opaque **session token** in the reply envelope. It is sealed under a rotating key (K_s) that lives in the delegate secret store, and it is bound to the Aegis web-app origin.
2. The UI keeps the token in tab memory only (never in storage, the URL or logs) and sends it with every request. The delegate uses it to rebuild the session without Argon2 and returns a fresh token.
3. The vault stays unlocked until **15 min idle**, **12 h absolute** (from the unlock), **Lock**, or another tab unlocks.
4. **Reload means locked**: the token is not persisted, so a page reload starts at the unlock screen.
5. **Two tabs kick each other out**: each unlock rotates K_s, so the older tab's token stops working and that tab sees "locked" on its next request.
6. **Lock kills every token**: Lock rotates K_s, so any copy of an earlier token is dead.

Design and threat analysis: `docs/CRYPTO-V2-DECISIONS.md` D19.

## Upgrading Aegis on Freenet

Freenet stores a delegate's secrets under `blake3(code_hash || params)`, so a new delegate WASM starts with an empty store. Aegis keeps a manifest of earlier delegates in `delegates/vault-delegate/history.json` (staged as `aegis_vault_delegate.history.json`).

1. Open the new Aegis. If the new delegate has no vault but an earlier one does, you see **Upgrade your vault**.
2. Enter your master passphrase and press **Upgrade**.
3. If the old delegate supports `ExportForUpgrade`, the vault moves with the same identity. Otherwise it moves through an encrypted backup with a random one-time password and gets a **new sync identity**; re-link your other devices afterwards.

The old delegate's copy is left in place. If the upgrade fails, nothing in the old delegate changed and you can retry. Design: `docs/CRYPTO-V2-DECISIONS.md` D20.

## WASM import rule

Contract and delegate WASM may import **only `freenet_*` host modules**. A real
node rejects anything else, so wasm-bindgen / js-sys must never reach them
(`__wbindgen_placeholder__` and `env` imports are both fatal).

- `aegis-common` feature `freenet-host`: host RNG and time via `freenet-stdlib`
  (getrandom 0.2 custom hook + getrandom 0.4 `custom` backend). Used by the
  contract and delegate.
- `aegis-common` feature `browser`: WebCrypto RNG (getrandom `js` / `wasm_js`)
  and js-sys time. Used only by `aegis-browser-wasm`. The two features are
  mutually exclusive on wasm32-unknown-unknown (`compile_error!`).
- `.cargo/config.toml` defaults wasm32 to `getrandom_backend="custom"`. The
  browser build overrides it with
  `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'` (set per command, see
  `scripts/build-wasm.sh`).
- Check built artifacts (exit 0 = ok, 1 = violation, 2 = bad input):

  ```bash
  python3 scripts/check-wasm-imports.py \
    target/wasm32-unknown-unknown/release/aegis_vault_sync.wasm \
    target/wasm32-unknown-unknown/release/aegis_vault_delegate.wasm
  ```

  `scripts/build-wasm.sh`, `cargo make build` and CI run it automatically.
- Build each WASM crate with its own `cargo build -p …` command. Never do a
  combined `--workspace` wasm build: it unifies features and trips the guard.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Badge stays mock / freenet fails | Is `freenet local` running? Console for WebSocket errors |
| “delegate keys missing” | `build-wasm.sh`, register, set localStorage keys |
| Status probe timeout | Delegate not registered or wrong key |
| CORS / WS from Vite | Client targets `127.0.0.1:7509` automatically on port 5173 |

## Dev vs Freenet

| | `mode=dev` | `mode=freenet` |
|--|------------|----------------|
| Crypto | Same (`aegis-common`) | Same (in WASM delegate) |
| Store | `~/.local/share/aegis-dev` | Freenet secret store |
| Sync | File CRDT (`FileSyncTransport`) | Secret-store MVR (`aegis/v1/sync-state`); VaultSync contract next |

**Sync on Freenet today:** the UI calls `SyncWithRemote`, which merges any cached
VaultSync MVR, updates the local secret-store MVR, and returns `contract_state` +
`owner_verifying_key` for network Put. The blob is cached in `localStorage` as a
bridge; full contract Put/Get is next (see [PUBLISH.md](./PUBLISH.md)).

## River-style packaging

```bash
./scripts/package-release.sh
freenet local   # other terminal
./scripts/publish-freenet.sh
```

Details: [PUBLISH.md](./PUBLISH.md).
