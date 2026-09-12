# How to use Aegis (for everyone)

Aegis is a password manager that works in the browser, as a native CLI, or (optionally) on Freenet. **You do not need Freenet** to get started.

## 1. Open in the browser (recommended)

If the project is on **GitHub Pages**:

```
https://YOUR_USER.github.io/YOUR_REPO/
```

Or serve a release yourself:

```bash
npx --yes serve dist/freenet-release/ui -l 4173
# open http://localhost:4173/
```

1. Badge should say **browser vault**
2. Create a master passphrase
3. Add passwords, labels, TOTP, etc.
4. Use **Export** to download an encrypted backup (store it safely)

Your sealed vault lives in **this browser’s IndexedDB**. Clearing site data deletes it unless you exported.

### Move to another browser / computer

1. Export from the old browser (encrypted `.aegis` file)
2. Open Aegis on the new browser
3. Import the file + passphrase

## 2. Native CLI (desktop)

```bash
# Attested linux-x86_64 binary: see docs/CLI.md (GitHub Release + SHA-256).
# Developer-only: cargo install --locked --path tools/cli
aegis create          # passphrase via tty (never argv)
aegis unlock
aegis search github
aegis copy <id>       # clipboard wipe after 30s
aegis export vault.aegis
```

Sealed vault: `~/.local/share/aegis/`. Session lives in `aegis agent` (unix socket). Export/import `.aegis` files round-trip with the browser UI (restore uses a **new** live passphrase, not the backup password). `aegis import --replace` overwrites an existing vault the same way — still a **new** identity, not Recovery Kit restore.

Details: [CLI.md](./CLI.md)

## 3. Optional: Freenet

For Freenet-native hosting and (later) multi-device mesh sync:

1. Install Freenet and run `freenet local`
2. Open the app with `?mode=freenet&register=1` once
3. Reload without `register=1`

Details: [FREENET.md](./FREENET.md) · [PUBLISH.md](./PUBLISH.md)

## 4. Optional: Dev server (developers)

```bash
cargo run -p aegis-dev-vault-server
# UI: ?mode=dev
```

## Modes cheat sheet

| Mode | Query | Needs |
|------|--------|--------|
| Browser (default) | _(none)_ or `?mode=browser` | Browser only |
| Native CLI | `aegis` | `~/.local/share/aegis/` |
| Freenet | `?mode=freenet` | Local Freenet peer |
| Dev | `?mode=dev` | Rust vault server on :8787 |
| Mock | `?mode=mock` | Demo only — not for real secrets |

Full matrix: [MODES.md](./MODES.md)

## Security basics

- Prefer a long unique master passphrase
- Export and store offline backups
- Recovery keys: generate once, store offline, never in email
- Freenet / browser sandboxes may use ephemeral storage — export still works
