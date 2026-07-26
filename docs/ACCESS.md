# How to use Aegis (for everyone)

Aegis is a password manager that works in three ways. **You do not need Freenet** to get started.

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

## 2. Optional: Freenet

For Freenet-native hosting and (later) multi-device mesh sync:

1. Install Freenet and run `freenet local`
2. Open the app with `?mode=freenet&register=1` once
3. Reload without `register=1`

Details: [FREENET.md](./FREENET.md) · [PUBLISH.md](./PUBLISH.md)

## 3. Optional: Dev server (developers)

```bash
cargo run -p aegis-dev-vault-server
# UI: ?mode=dev
```

## Modes cheat sheet

| Mode | Query | Needs |
|------|--------|--------|
| Browser (default) | _(none)_ or `?mode=browser` | Browser only |
| Freenet | `?mode=freenet` | Local Freenet peer |
| Dev | `?mode=dev` | Rust vault server on :8787 |
| Mock | `?mode=mock` | Demo only — not for real secrets |

Full matrix: [MODES.md](./MODES.md)

## Security basics

- Prefer a long unique master passphrase
- Export and store offline backups
- Recovery keys: generate once, store offline, never in email
- Freenet / browser sandboxes may use ephemeral storage — export still works
