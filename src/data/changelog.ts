export const releases = [
  {
    version: '2.0.0-rc.1',
    date: '2026-09-06',
    title: 'Aegis v2 release candidate',
    items: [
      'New v2 cryptographic core: a memory-only RootSecret wrapped by Argon2id at 64 MiB or more, with every operational key derived per vault',
      'Hybrid post-quantum sync: revisions must verify under both Ed25519 and ML-DSA-65',
      'Hybrid post-quantum sharing: a single entry can be sealed to another user under X25519 and ML-KEM-768 together',
      'Recovery Kit (.aegis-recovery) plus a separate recovery secret preserves your vault identity; a normal .aegis backup restores as a new identity',
      'Explicit key rotation: mints a new RootSecret, increments the key epoch, and invalidates unopened shares to the old identity',
      'Atomic persistence: imports, recovery and rotation authenticate first and commit only on success',
      'Strict Content Security Policy in production builds; runtime JavaScript is self-hosted only',
      'Passphrase floor raised to 12 characters',
      'Existing 0.1 vaults migrate to v2 on unlock and receive a recovery secret',
      'Validation: 42 of 42 browser scenarios in Chromium and Firefox, 79.8 million fuzzer inputs across seven parser surfaces without a crash, FIPS 203 and 204 test vectors, RustSec and cargo-deny in CI',
      'Not claimed: formal verification or an independent professional audit',
    ],
  },
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
