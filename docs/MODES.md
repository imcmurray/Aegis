# Aegis modes — browser, Freenet, or local server

You can use Aegis **without Freenet**. Freenet is an **optional** backend.

| Mode | URL | Needs | Crypto | Storage |
|------|-----|--------|--------|---------|
| **browser** (default) | `/` or `?mode=browser` | Just a browser | Real (WASM Argon2id + XChaCha20) | IndexedDB on that browser |
| **freenet** | `?mode=freenet` or Freenet web container | Local Freenet peer | Real (vault-delegate) | Freenet secret store |
| **dev** | `?mode=dev` | `aegis-dev-vault-server` | Real (native Rust) | `~/.local/share/aegis-dev` |
| **mock** | `?mode=mock` | Nothing | Weak (demo only) | Memory / storage helper |

## Recommended for most people (including GitHub Pages)

```
https://you.github.io/Aegis/          # or any static host
```

- No `freenet local`
- No Rust install
- Vault sealed in **this browser’s IndexedDB**
- Export backup to move devices / recover

**Limits:** data is per-browser profile (not multi-device until you Export/Import or use Freenet Sync). Clearing site data wipes the vault unless you exported.

## Optional: Freenet

For mesh / multi-device / River-style:

1. Install Freenet, run `freenet local`
2. Open `?mode=freenet&register=1` once (or the web-container URL with `?register=1`)
3. Badge: **freenet delegate**

See [FREENET.md](./FREENET.md) and [PUBLISH.md](./PUBLISH.md).

## Optional: Dev server (contributors)

```bash
cargo run -p aegis-dev-vault-server
# UI: ?mode=dev
```

## GitHub Pages

```bash
./scripts/package-release.sh
# Publish dist/freenet-release/ui (includes browser-wasm/) to gh-pages
```

Default mode is **browser** — visitors get a working vault with no Freenet.

To try Freenet from Pages, users still need a local peer; HTTPS→`ws://127.0.0.1` may be blocked (mixed content). Prefer HTTP local UI or Freenet web container for Freenet mode.

## Choosing multi-device (recommended UX)

**Do not** pick VaultSync at unlock. Flow:

1. Create / unlock the **browser vault** (default on GitHub Pages).
2. Use the vault normally.
3. When you want another PC:
   - **Export → Import** (always works), or  
   - **Settings → Multi-device & Sync** → opt into Freenet (peer required), then **Sync**.

VaultSync is **optional** and tied to the **same** vault identity (master passphrase → owner key). It is not a separate “login” product.

## Choosing a mode in the UI

Advanced backends are under a collapsed “Advanced backends” control:

`browser (default) · freenet · dev (Rust) · mock`
