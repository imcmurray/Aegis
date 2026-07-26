# Publishing Aegis like River

Goal: **anyone with a Freenet peer** can open Aegis, register the vault-delegate, and use their own encrypted vault — no Vite, no central server.

## Architecture (River-shaped)

```
User browser
    │  loads UI from web container (or static host)
    ▼
Freenet peer (local)
    ├─ vault-delegate  (private secrets, crypto)  ← per user / per node
    └─ VaultSync contract (encrypted MVR only)    ← multi-device (wiring in progress)
```

| Piece | Status |
|-------|--------|
| Vault crypto + delegate | Done |
| Static UI package | Done (`scripts/package-release.sh`) |
| Web container publish | Done (`scripts/publish-freenet.sh`) |
| Sync → contract blob (`SyncWithRemote`) | Done (UI caches blob; full Put next) |
| Auto Put/Get VaultSync on network | In progress |
| App catalog listing | Later |

## One-time setup

```bash
# Toolchain
rustup target add wasm32-unknown-unknown
# freenet + fdev from freenet-core (see docs/FREENET.md)

# Node for UI build
cd ui && npm install
```

## Build a release bundle

```bash
./scripts/package-release.sh
# → dist/freenet-release/
#      ui/          production static site (+ wasm)
#      wasm/        delegate + vault-sync + hashes
#      MANIFEST.json
```

Share that directory (or a zip) with testers, **or** publish it onto Freenet (next).

## Publish to a local Freenet peer

```bash
# Terminal 1
freenet local

# Terminal 2
./scripts/publish-freenet.sh
# first run creates website key "aegis" via fdev website init
```

### Expected results

| Step | Expected |
|------|----------|
| Website publish | **Success** — URL like `http://127.0.0.1:7509/v1/contract/web/C…/` |
| Delegate CLI publish | **Skipped** — use UI `?register=1` (raw WASM is not fdev-packaged) |
| VaultSync template | Optional; empty state must be `{revisions:[]}` CBOR |

**Open your app:**

```
http://127.0.0.1:7509/v1/contract/web/<CONTRACT_KEY>/?register=1
```

After the badge shows **freenet delegate**, drop `register=1` and use the app.

### Sandbox note (localStorage)

Freenet serves the UI in a **sandboxed iframe** without `allow-same-origin`. Browsers then block `localStorage` (`Forbidden in a sandboxed document…`).

Aegis uses a **safe storage helper** (`ui/src/storage.ts`):

- Prefer `localStorage` / `sessionStorage` when allowed  
- Else **in-memory** for the tab (reload may need `?register=1` again)  
- Delegate keys still load from `aegis_vault_delegate.hash.json` after each register  

If the badge shows **mock (freenet offline)**, check the console for WebSocket errors — storage alone should no longer abort Freenet setup.

Back up `~/.config/freenet/website-keys/aegis.toml` — without it you cannot update the website.

Optional env:

| Variable | Default | Meaning |
|----------|---------|---------|
| `WEBSITE_KEY` | `aegis` | `fdev website` key name |
| `AEGIS_FREENET_PORT` | `7509` | Peer WebSocket API port |
| `AEGIS_RELEASE_DIR` | `dist/freenet-release` | Bundle path |

Flags:

- `--skip-build` — publish existing bundle only  
- `--no-delegate` — website only  

## What each user does

1. Run a Freenet peer (`freenet local` or a network peer).  
2. Open the published web container URL **or** a static host of `dist/freenet-release/ui`.  
3. First visit: `?mode=freenet&register=1` once (registers vault-delegate).  
4. Reload without `register=1`, create vault, use Aegis.

Each peer has **its own secret store**. Users do **not** share vaults unless they export/import or (later) Sync over VaultSync.

## Multi-device Sync (current behavior)

1. **Dev mode** (`?mode=dev`): `SyncNow` uses a shared file under `~/.local/share/aegis-dev/sync/`.  
2. **Freenet mode**: UI calls `SyncWithRemote` with any cached contract MVR; delegate merges, re-seals, returns:
   - `contract_state` — CBOR `VaultSyncState` to Put on the network  
   - `owner_verifying_key` — for `VaultSyncParams` (contract instance identity)  
3. UI currently **caches** that blob in `localStorage` so re-sync converges on the same browser; **network Put/Get** is the next wiring step (same contract code in `contracts/vault-sync`).

## VaultSync contract (network)

- Code: `contracts/vault-sync` → `aegis_vault_sync.wasm`  
- State: multi-value register of **signed encrypted** revisions only  
- Parameters: `VaultSyncParams { owner_verifying_key, app: "AEGIS_VAULT_SYNC_V1" }`  
- Instance address is derived from code hash **and** params → **one contract instance per vault owner**

Publish empty template (optional):

```bash
# after package-release.sh
fdev -p 7509 publish \
  --code dist/freenet-release/wasm/aegis_vault_sync.wasm \
  contract \
  --state /path/to/empty.cbor   # or let publish-freenet.sh do it
```

Real instances must use **params = CBOR(VaultSyncParams with that owner's VK)** from a successful `SyncWithRemote` response.

## Tester checklist

- [ ] `freenet local` running  
- [ ] Bundle built / website published  
- [ ] Badge shows **freenet delegate**  
- [ ] Create vault, add entry, labels, Password/2FA chips  
- [ ] Export backup  
- [ ] Sync reports `Pushed` then `UpToDate`  
- [ ] Second browser profile: import backup **or** (when Put is live) Sync from contract  

## Security notes

- Never put plaintext passwords in contracts.  
- Web container is **public code** (like any website).  
- Secrets live only in the **delegate secret store** on the user’s peer.  
- Treat website signing keys (`~/.config/freenet/website-keys/`) as release credentials.

## Roadmap after this doc

1. UI `Put`/`Get`/`Update` VaultSync using `owner_verifying_key` + staged contract WASM  
2. Subscribe for live multi-device updates  
3. First-run wizard: peer check → auto-register delegate → create vault  
4. Optional: list Aegis in a Freenet app directory  

See also: [FREENET.md](./FREENET.md), [ARCHITECTURE.md](./ARCHITECTURE.md).
