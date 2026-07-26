# Aegis

**Password manager** with real client-side crypto — works in a normal browser, and optionally on [Freenet](https://freenet.org).

| Who | How |
|-----|-----|
| **Everyone** | Open the site → **browser vault** (WASM + IndexedDB). No install. |
| **Freenet users** | Optional `?mode=freenet` with a local peer |
| **Developers** | Optional `?mode=dev` Rust server |

> **Try it:** after deploy → `https://YOUR_USER.github.io/Aegis/`  
> Local: `./scripts/deploy-github-pages.sh` then `npx serve dist/freenet-release/ui -l 4173`

## For end users

1. Open the hosted URL (or local serve).
2. Create a master passphrase when prompted.
3. Add logins, labels, TOTP, folders.
4. **Export** encrypted backups regularly.

You do **not** need Freenet. See [docs/ACCESS.md](docs/ACCESS.md).

## Modes

| Mode | URL | Needs |
|------|-----|--------|
| **browser** (default) | `/` | Browser only |
| freenet | `?mode=freenet&register=1` | `freenet local` |
| dev | `?mode=dev` | `cargo run -p aegis-dev-vault-server` |
| mock | `?mode=mock` | Demo only |

Details: [docs/MODES.md](docs/MODES.md)

## Deploy so others can open it (GitHub Pages)

```bash
# One-time on GitHub: create empty repo, then:
git init
git add .
git commit -m "Aegis: browser vault + optional Freenet"
git branch -M main
git remote add origin git@github.com:YOUR_USER/Aegis.git
git push -u origin main
```

Then:

1. Repo **Settings → Pages → Source: GitHub Actions**
2. Push to `main` (or run the **Deploy GitHub Pages** workflow)
3. Share `https://YOUR_USER.github.io/Aegis/`

Workflow: [`.github/workflows/pages.yml`](.github/workflows/pages.yml)  
Local package only: `./scripts/deploy-github-pages.sh`

## Developer quick start

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.100   # match wasm-bindgen crate if needed

./scripts/build-wasm.sh
cd ui && npm install && npm run dev
# http://localhost:5173/  → browser vault
```

```bash
cargo test --workspace
./scripts/package-release.sh    # → dist/freenet-release/
```

## Docs

| Document | Contents |
|----------|----------|
| [docs/ACCESS.md](docs/ACCESS.md) | **How people use Aegis** |
| [docs/MODES.md](docs/MODES.md) | Browser / Freenet / dev matrix |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, keys, roadmap |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Adversaries & guarantees |
| [docs/CRYPTO.md](docs/CRYPTO.md) | Algorithms |
| [docs/FREENET.md](docs/FREENET.md) | Peer + delegate |
| [docs/PUBLISH.md](docs/PUBLISH.md) | Freenet web container publish |
| [docs/VAULTSYNC.md](docs/VAULTSYNC.md) | **Multi-device mesh Sync (owner key identity)** |
| [docs/DEV.md](docs/DEV.md) | Local development |

## Layout

```
Aegis/
├── common/                   # types, crypto, vault logic
├── contracts/vault-sync/     # encrypted multi-device contract (WASM)
├── delegates/vault-delegate/ # Freenet private vault agent (WASM)
├── tools/browser-wasm/       # browser vault (wasm-bindgen)
├── tools/dev-vault-server/   # local HTTP vault
├── ui/                       # TypeScript + Vite
├── scripts/                  # build, package, publish, pages
└── docs/
```

## Design snapshot

- Master passphrase → Argon2id → wraps `MasterSecret`
- Vault DEK seals the document (XChaCha20-Poly1305)
- Browser: WASM crypto + IndexedDB for sealed blobs
- Freenet: delegate secrets; contracts never see plaintext

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/build-wasm.sh` | Freenet WASM + browser WASM → `ui/public` |
| `scripts/package-release.sh` | Full static site under `dist/freenet-release/ui` |
| `scripts/deploy-github-pages.sh` | Package + print Pages instructions |
| `scripts/publish-freenet.sh` | Optional Freenet web container publish |

## License

MIT OR Apache-2.0
