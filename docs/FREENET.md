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

- UI → Freenet Core → **vault-delegate** (`ApplicationMessage` payload = CBOR `VaultRequest`)
- Response: CBOR `VaultResponse`
- Secrets stay in the delegate secret store (same as dev server FileStore, but Freenet-managed)

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
