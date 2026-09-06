export const releases = [
  {
    version: '0.1.1',
    date: '2026-07-26',
    title: 'Multi-device and unlock experience',
    items: [
      'Replace vault from backup on the locked unlock screen, for re-syncing a stale browser',
      'Preview import: compare local vault against a backup before replacing (only-local, only-backup, changed fields, never secret values)',
      'Preview results shown in a modal with Close and Replace',
      'Compact unlock card: passphrase and Unlock on one row, recovery and replace side by side',
    ],
  },
  {
    version: '0.1.0',
    date: '2026-07-26',
    title: 'First public release',
    items: [
      'Browser vault by default: Argon2id and XChaCha20-Poly1305 in WASM, sealed secrets in IndexedDB, no Freenet required',
      'Optional Freenet mode with vault delegate and VaultSync mesh under an owner verifying key',
      'Developer mode with a local Rust vault server',
      'Entries, folders, labels, TOTP, password health, generator, recovery key',
      'Encrypted export and import (.aegis)',
      'Owner identity is an Ed25519 key derived from the master secret; only an unlocked session can sign sync revisions',
    ],
  },
] as const;
