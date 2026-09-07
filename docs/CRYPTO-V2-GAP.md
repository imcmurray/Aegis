# Aegis v2 gap matrix

Classification of every item in [`CRYPTO-V2.md`](./CRYPTO-V2.md) (§1–§72 + Final design rule) against the v1 code. Decisions live in [`CRYPTO-V2-DECISIONS.md`](./CRYPTO-V2-DECISIONS.md). Do not treat this file as a license to rewrite the spec.

| Col | Meaning |
|---|---|
| Kind | principle / format / behavior / test / process / forbidden |
| v1 | `matches` / `partial` / `contradicts` / `missing` / `n/a` |
| Phase | spec §66 phase this unblocks (0 = analysis, 1b/1c = pre-v2 hotfixes) |

Principles constrain every PR; they are not implementation tickets.

## Matrix

| ID | Title | Kind | v1 | Evidence | Phase | Open |
|---|---|---|---|---|---|---|
| §1 | Objective | principle | partial | v1 has client-side XChaCha + Argon2 + Ed25519 (`docs/CRYPTO.md`). Missing PQ, backup/root separation, rotation, agility, transactional import. | 2–10 | — |
| §2 | Security philosophy | principle | partial | No homemade primitives (`common/src/crypto.rs` uses argon2/chacha/hkdf/ed25519 crates). Hybrid PQ absent. | 2–8 | — |
| §2.1 | Never invent cryptography | forbidden | matches | Uses crates; no local Argon2/XChaCha/ML-KEM implementations. | all | D6, D16 |
| §2.2 | Symmetric foundation stays XChaCha20-Poly1305 | format | matches | `XChaCha20Poly1305`, 256-bit keys. | 2 | — |
| §2.3 | Hybrid PQ during transition | format | missing | No ML-KEM / ML-DSA. Sync is Ed25519 only (`common/src/sync.rs`). Share is an X25519 *seed* only. | 7–8 | D5, D11 |
| §3 | Baseline crypto suite | format | missing | No `CryptoSuiteId`. Algorithms are implicit in v1 code. | 2 | D2, D11 |
| §4 | Crypto agility, allow-listed suites only | format | contradicts | `if blob.version != ENVELOPE_VERSION` (`crypto.rs`). No suite allow-list; attacker cannot mix algorithms today only because there is one hard-coded set. | 2 | D2, D11 |
| §5 | Core key hierarchy (RootSecret, KEK wrap only) | format | partial | Random 32-byte `MasterSecret` wrapped by Argon2 KEK — same *shape*, wrong *name/roles*. KEK does not encrypt entries. No AuditDEK/SyncDEK/PQ seeds. | 3 | — |
| §6 | Domain-separated HKDF | format | partial | v1 labels `aegis/v1/*`; HKDF salt is `b"aegis/v1"`, not `vault_id` (`derive_keys`). `sync_addr` and `search_hmac` are derived and **never read** (search is plaintext substring after decrypt). Missing v2 labels. | 3 | D3 |
| §7 | vault_id is 128-bit binary UUID | format | contradicts | `VaultMeta.vault_id: String` — `new_id()` hex-encodes 16 random bytes to 32 ASCII chars. AAD uses `vault_id.as_bytes()` (**32 UTF-8 hex bytes**, not the 16-byte UUID). | 2 | — |
| §8 | Serialize Argon2 params, not only profile names | format | contradicts | `KdfParams { profile, salt }` — memory/t/p are *not* on the wire. | 2 | D8 |
| §9 | Argon2 policy (64 MiB min, 128 MiB preferred) | behavior | contradicts | Interactive = 64 MiB t=3 p=1 (matches min) but the **browser UI never uses it**. `defaultKdfProfile()` (`ui/src/main.ts`) sends **`mobile` (32 MiB)** for browser vaults, `interactive` only for dev/freenet, `test` for mock. `High` is in the TS union and **never sent**. Export also forces Mobile (`export_bundle`). No 500–1000 ms calibration. | 2, 4 | D8 |
| §10 | KDF parameter validation | behavior | missing | Import runs Argon2 with whatever profile the envelope names. No memory/iteration ceiling. `Test` is constructible in the public `KdfProfile` enum (`ui/src/messages.ts`). D12: individual caps **and** `memory_kib * iterations <= 786_432`. | 2, 4 | D12 |
| §11 | Passphrase policy | behavior | contradicts | Floor is **8 characters** in the UI (create + change) and in Rust `change_passphrase` only. **`CreateVault` in Rust does not enforce a minimum** — a crafted CBOR request can create a shorter passphrase. No strength meter. UTF-8 is preserved (no trim/casefold) — that part matches. | 3 | — |
| §12 | MasterEnvelopeV2 | format | missing | `MasterEnvelope` is v1: profile + salt + `SealedBlob` + string vault_id. | 2 | D1, D2 |
| §13 | Framed AAD / transcripts | format | contradicts | `build_aad`: unframed concat `aegis/v1 \|\| kind \|\| vault_id \|\| logical_id`. | 2 | D1 |
| §14 | VaultBlobV2 | format | missing | `SealedBlob { version: 1, kind, nonce, ciphertext }`. No suite, no key_epoch, no binary vault_id. | 2 | — |
| §15 | Fresh 24-byte CSPRNG nonces | behavior | matches | `fill_random` 24 bytes per `seal`. No counter/timestamp nonces. CSPRNG failure is not explicitly fatal beyond panic in getrandom. | 2 | — |
| §16 | Separate audit DEK | format | contradicts | `load_audit` opens with `keys.vault_dek`. | 3 | — |
| §17 | No persistent RootSecret / session key | behavior | contradicts | `SECRET_SESSION = aegis/v1/session`; `persist_session_flag` writes MasterSecret. IndexedDB `export_store` skips it (`browser-wasm`, `file_store.rs`) but the in-memory store still holds it while unlocked. | 3 | — |
| §18 | Zeroization | behavior | partial | `SecretKey: Zeroize + ZeroizeOnDrop`; `DerivedKeys: ZeroizeOnDrop`. Debug is redacted. `Clone` is allowed on `SecretKey`. JS passphrase lifetime not minimized. | 3 | — |
| §19 | Passphrase change = re-wrap same root | behavior | matches | `change_passphrase` re-wraps `self.master`, does not re-encrypt entries. UI does not distinguish this from rotation (rotation missing). | 3 | — |
| §20 | Full cryptographic reset / key_epoch | behavior | missing | No rotate-keys operation. | 6 | D14 |
| §21 | Normal backups MUST NOT contain RootSecret | format | contradicts | `export_bundle` calls `wrap_existing_master` on the live MasterSecret. | 4 | — |
| §22 | BackupPayloadV2 contents | format | contradicts | Export is `ExportBundle { format: 1, envelope, vault }` — envelope *is* the wrapped MasterSecret. | 4 | — |
| §23 | BackupEnvelopeV2 | format | missing | No magic, no independent BackupKey, no container_id. | 4 | D10 |
| §24 | Backup passphrase / KDF strength | behavior | contradicts | UI prompt: “can match your master passphrase”. KDF forced to `KdfProfile::Mobile`. No strength check on export passphrase. | 4 | D8 |
| §25 | Restore creates a NEW cryptographic vault | behavior | contradicts | `import_bundle` installs the backup’s MasterEnvelope (same MasterSecret, same vault_id). | 4 | D4 |
| §26 | Identity-preserving disaster recovery is a separate artifact | behavior | partial | Recovery key exists and wraps MasterSecret (`SECRET_RECOVERY`). Not a distinct file magic; 160-bit not 256-bit. | 5, 9 | D7, D13 |
| §27 | Recovery secret 256-bit CSPRNG + HKDF wrap | format | contradicts | `generate_recovery_key_display` = 20 random bytes (160 bits), Crockford Base32; wrapped via Argon2 like a passphrase, not HKDF. | 9 | D13 |
| §28 | Import must be transactional | behavior | contradicts | `import_bundle`: `if replace { clear_vault_secrets }` **then** decrypt. | 1b | D14 |
| §29 | Atomic browser persistence | behavior | partial | IndexedDB `put` of one key `v1` (`ui/src/browserClient.ts`) is a single-value write, not a multi-key transaction with shadow+commit marker. Native `FileStore::set` is `fs::write` in place, no fsync/rename. | 1b | D14 |
| §30 | Malicious import protection / parser limits | behavior | missing | Sync has `MAX_CIPHERTEXT` 8 MiB / `MAX_REVISIONS` 8. Backup parser has no size/Argon2/entry/string caps. | 4 | D12 |
| §31 | Hybrid sync identity | format | missing | Owner identity = Ed25519 verifying key from `sync_sign_seed`. | 7 | D11 |
| §32 | Hybrid sync signatures (AND, not OR) | format | missing | `sign_revision` / `verify_revision` are Ed25519 only. Worse: **local `sync_vault` never calls `verify_revision`** — it decrypts any blob openable with `vault_dek`. Only the VaultSync *contract* verifies when a VK is present. **D17: defer local-verify hotfix to Phase 7** unless a real VaultSync user exists (then Phase 1d). | 7 | D11, D17 |
| §33 | Sign deterministic transcripts | format | partial | `revision_sign_bytes` is a custom concat (not raw CBOR map) — good instinct, still unframed (device ids, no length prefixes, includes full ciphertext). | 7 | D1 |
| §34 | Separate sync DEK | format | contradicts | `seal_doc_for_sync` uses `keys.vault_dek`. | 3, 7 | — |
| §35 | Sync replay / rollback defense | behavior | partial | Version vectors + content hash exist (`EncryptedRevision`). No `key_epoch`. Counter-monotonicity is CRDT merge, not an explicit reject of `counter <= last`. Local pull does not verify signatures (see §32). | 7 | — |
| §36 | Sync key rotation / transition record | behavior | missing | No epoch, no old-signs-new record. | 6–7 | D9 |
| §37 | Hybrid sharing | format | missing | `share_ecdh_seed` is derived and **never read**. `x25519-dalek` is a workspace dependency with **zero uses** in `.rs` files. No share envelopes. | 8 | D11 |
| §38 | Recipient SharePublicIdentityV2 | format | missing | — | 8 | — |
| §39 | Per-share content key | format | missing | — | 8 | — |
| §40 | Hybrid shared secret combiner | format | missing | — | 8 | D5 |
| §41 | Shares authenticated by hybrid signatures | format | missing | — | 8 | — |
| §42 | Harvest-now-decrypt-later (ML-KEM from first v2 share) | principle | n/a | Sharing not shipped. When it is, hybrid is mandatory (D11). | 8 | — |
| §43 | Downgrade protection | behavior | missing | v2 objects cannot exist yet. v1 has no suite field to bind. | 2, 7 | D11 |
| §44 | Read-only v1 decoder after v2 default | behavior | n/a | v1 *is* the only decoder. Must keep it when v2 ships. | 5 | — |
| §45 | Explicit atomic v1→v2 migration, fresh RootSecret | behavior | missing | No migration path. | 5 | D4, D13, D14 |
| §46 | v1 sync identity transition | behavior | missing | VaultSync optional; Ed25519 identity is live. | 7 | D9 |
| §47 | v1 backup import → new RootSecret | behavior | missing | Import currently *keeps* v1 MasterSecret. | 4–5 | D4 |
| §48 | File magic | format | missing | `ExportBundle.format: 1` inside CBOR; no leading magic. | 2, 4 | D10 |
| §49 | No secret-bearing metadata | behavior | partial | Vault document is encrypted at rest. Sync revisions carry device_id and version vectors in the clear (needed for MVR). Entry names are not on the wire. | 4, 7 | — |
| §50 | Error handling / no oracles | behavior | partial | Decrypt maps to `ErrorCode::AuthFailed`. Unlock errors are not uniformly “incorrect passphrase or corrupted vault.” Logs: `eprintln` in FileStore on write fail. | 3 | — |
| §51 | Security invariants 1–12 | test | missing | None of the 12 are automated. Several are false in v1 (1–2, 6–7, 8–10, 11 audit/sync). 3 (passphrase change keeps root) holds. 12 (fresh nonces) holds. | 1, 4–7 | — |
| §52 | Required cryptographic tests | test | partial | Round-trip, wrong AAD, master wrap, derive purpose-separation for *v1* labels. No modified nonce/ciphertext/kind/vault_id/epoch vectors, no Argon2 limits, no production-rejects-Test. `open()` rebuilds AAD from **`blob.kind`**, not a caller-expected kind, so a kind-mismatch test is not even expressible as an extra check today. `subtle` is a dependency and unused; passphrase-change master compare is `!=` (non-CT). | 1–3 | — |
| §53 | Required backup tests | test | missing | Export/import tests exist as happy-path vault tests; no “backup contains no RootSecret”, no failed-replace leaves bytes unchanged (and today that test would **fail**). | 1, 1b, 4 | — |
| §54 | Required PQ tests | test | missing | Spike round-trip only (`docs/CRYPTO-V2-DECISIONS.md` spike notes). No KATs in-tree. | 7–8 | D16 |
| §55 | Required migration tests | test | missing | No v1 fixtures on disk. | 1, 5 | — |
| §56 | Parser fuzzing | test | missing | No fuzz targets. | 10 | D12 |
| §57 | Dependency/security CI | process | missing | `.github/workflows/pages.yml` builds and deploys. No `cargo test` in CI, no `cargo audit`/`deny`, no JS audit. Lockfiles exist (`Cargo.lock`, `ui/package-lock.json`). | 1c, 10 | D15 |
| §58 | FIPS 203/204 implementations | process | missing | Spike selected RustCrypto `ml-kem` 0.3.2 + `ml-dsa` 0.1.1. | 0, 7–8 | D6, D16 |
| §59 | ML-KEM-768 | format | missing | — | 8 | D6 |
| §60 | ML-DSA-65 + Ed25519 companion | format | missing | — | 7 | D6 |
| §61 | SLH-DSA not mandatory | principle | matches | Not implemented; do not add. | n/a | — |
| §62 | Logging never contains secrets | behavior | partial | Audit events are high-level (`AuditKind` + short detail). `FileStore` eprint paths only. No structured guarantee. | 3 | — |
| §63 | Browser deployment warning / CSP | process | contradicts | `ui/index.html` has **no CSP**. Vite bundles locally (good). Pages workflow installs wasm-bindgen with a non-locked fallback (`cargo install … \|\| cargo install` without `--locked` on retry). | 1c | D15 |
| §64 | Module structure | process | contradicts | Single `common/src/crypto.rs` + `vault.rs`. Do **not** split until D1/D2/D11 are frozen (they are, in DECISIONS). | 2 | — |
| §65 | Distinct secret newtypes | format | contradicts | One `SecretKey([u8; 32])` for master, DEKs, seeds. | 3 | — |
| §66 | Implementation phases | process | n/a | This gap file + DECISIONS are Phase 0. | 0 | — |
| §67 | Highest-priority changes | process | n/a | §67.1 → Phase 1b. §67.2–4 → Phase 4. §67.5 → Phase 2. | 1b–4 | — |
| §68 | Things not to do | forbidden | n/a | Copied as PR checklist in DECISIONS. v1 currently *does* several of these (RootSecret in backups; wipe-then-decrypt; Mobile export KDF). | all | — |
| §69 | Security properties after v2 | principle | n/a | Target properties; see `THREAT_MODEL-V2-DELTA.md`. | 10 | — |
| §70 | Final target architecture | principle | n/a | Diagram of the destination. Storage path is Core, not hybrid (D11). | 2–8 | D11 |
| §71 | Definition of v2 complete | process | missing | None of the completion bullets hold yet. | 10 | — |
| §72 | Security review checkpoint | process | n/a | After implementation, not instead of it. | 10 | — |
| F | Final design rule | principle | contradicts | v1 backup ≡ live identity; replace-import can destroy the live vault; no rotation. | all | — |

## v1 contradictions that are also user-visible bugs

These are the rows where v1 is not merely “not v2 yet”:

1. **Wipe-then-decrypt import** (§28, §51.6–7, §67.1, §68) — Phase 1b.
2. **Export re-wraps live MasterSecret under Mobile KDF** (§21–24, §67.2–4) — Phase 4 (format change).
3. **8-character passphrase floor** (§11) — UI + `change_passphrase` only; `CreateVault` in Rust has no floor.
4. **No CSP** (§63) — Phase 1c.
5. **`Test` KDF is a public enum value** (§10) — wire-reachable; backend never rejects it.
6. **Browser vaults are created with Mobile 32 MiB Argon2** (§9) — the default production path, not just exports.
7. **Local VaultSync pull does not verify Ed25519** (§32) — contract does; `sync_vault` decrypts on DEK alone.

## Counts

Rows = §1–§72 + §2.1–§2.3 + Final design rule (76). The contract itself is 73 items; §2.1–§2.3 are listed separately because they have different v1 statuses.

| v1 status | Count |
|---|---|
| matches | 5 |
| partial | 13 |
| contradicts | 19 |
| missing | 31 |
| n/a | 8 |

## Phase 2 / PR D landed (types only)

`common/src/crypto/` now has the v2 Core format (not wired into `VaultSession::create` / import — that is Phase 5):

| Spec | Implementation |
|---|---|
| §3, §4, D2, D11 | `suite.rs` — `CryptoSuiteId` as explicit u16. Unknown IDs and hybrid IDs on master/vault fail closed. Storage suite is `0x0002` (`AegisV2Core2026`), not hybrid. |
| §7 | `MasterEnvelopeV2.vault_id` / `VaultBlobV2.vault_id` are 16 binary bytes (`serde_bytes`), not hex strings. |
| §8, §10, D8, D12 | `Argon2ParamsV2` serializes algorithm/version/memory/t/p/salt/output_len. `validate` + checked `u64` work factor run before `Params::new` / hasher. v2 generate/import floor 64 MiB. |
| §12 | `MasterEnvelopeV2` |
| §13, D1 | `transcript.rs` length-prefixed AAD; binds version, suite, kind, vault_id, key_epoch. `kind_u16` is `ObjectKind::to_u16` (`0x0001` MasterWrap, `0x0002` VaultBlob, …), not an enum discriminant. |
| §14 | `VaultBlobV2` |
| §48 / D10 | Vault/master file is `"AEGIS_VAULT_V2" \|\| 0x02 \|\| CBOR`. `from_bytes` is the external decoder. |
| §15 | `aead.rs` — fresh 24-byte XChaCha nonce per seal. |
| §43 / D11 | `#[serde(deny_unknown_fields)]` on v2 envelopes; extra ML-KEM fields on a `0x0002` object are rejected. |
| §64 | Split: `v1.rs` + `suite` / `kdf` / `aead` / `transcript` / `envelope_v2` / `secret`. |
| §44 / PR B | Frozen v1 fixtures still decode; v2 parsers reject them. `wrap_root_v2` never emits `SealedBlob.version = 1`. |

Still v1 on the production path: `VaultSession::create` → `wrap_master`. Do not switch that until Phase 5.

## Phase 3 / PR E landed (types + v2 session, not default)

| Spec | Implementation |
|---|---|
| §5, §6, D3 | `hkdf_v2.rs` — HKDF-SHA256, salt = vault_id. RootSecret children do **not** include `recovery-kek`. |
| §27 | `RecoveryKek` from independent `RecoverySecret`. Kit file still Phase 9. |
| §16 | `AuditDek` + `AuditBlobV2`. Audit is not sealed with `VaultDek`. |
| §17 | `VaultSessionV2` is memory-only. No `aegis/v2/session`. RootSecret never written to `SecretStore`. |
| §18, §65 | Distinct zeroizing newtypes; Debug redacted; no Serialize on secrets. |
| §19 | `VaultSessionV2::change_passphrase` re-wraps the same RootSecret. |
| §34 | `SyncDek` + `SyncBlobV2` (local ciphertext). On-wire `AEGIS_SYNC_V2` remains Phase 7. |

`dispatch` / browser WASM still use v1 `VaultSession` (including `SECRET_SESSION` in the in-memory store, skipped on IndexedDB export).

## Phase 4 / PR F landed (v2 backup API, v1 export unchanged)

| Spec | Implementation |
|---|---|
| §21–23, D10 | `BackupKey` + `BackupEnvelopeV2`. File is `"AEGIS_BACKUP_V2" \|\| 0x02 \|\| CBOR`. |
| §22–23 | Payload (encrypted) holds `original_vault_id`. Envelope does not. Isolation asserted on plaintext payload before encrypt. |
| §24, D8 | Backup KDF is `Argon2ParamsV2::generate_v2()` (64 MiB). Mobile/Test cannot generate. |
| §25, D4 | Restore mints new RootSecret + new vault_id; passwords preserved. |
| §30, D12 | Size/KDF/entry caps before Argon2 and before D14 commit. |
| D14 | `VaultSessionV2::restore_backup` authenticates, then `SecretStore::commit`. |
| §11, §24, D18 | Shared `validate_v2_passphrase`: 12-char floor, reject `12345678` / `password` / repeated chars. No composition rules, no trim. |

v1 `.aegis` export still wraps MasterSecret (fixtures remain valid).

## Phase 9 / PR K landed (Recovery Kit productization)

| Spec | Implementation |
|---|---|
| §26, D7, D10 | External kit is `"AEGIS_RECOVERY_V2" \|\| 0x02 \|\| CBOR(RecoveryWrapV2)`. Never inside `.aegis` backups. Distinct from `AEGIS_BACKUP_V2` / `AEGIS_VAULT_V2` / `AEGIS_SYNC_V2`. |
| §27 | `RecoverySecret` is 256-bit CSPRNG (never user-chosen). Display is Crockford Base32 + SHA-256 checksum (`AEGIS2-…`). Hex of 32 bytes remains decode-only. |
| D1 | Recovery wrap AAD is kind `0x000C` (`RecoveryWrap`), Core suite `0x0002`. Binds version, suite, kind, `vault_id`, `key_epoch`. Fresh XChaCha20-Poly1305 nonce per wrap. |
| §25 vs §26 | Backup restore still mints a new RootSecret / vault_id. Recovery Kit import restores the **same** RootSecret, vault_id, and key_epoch. |
| Invariant 10 | RecoverySecret is never written to SecretStore / IndexedDB. Only the wrap (ciphertext) is stored at `aegis/v2/recovery`. |
| D14 | `import_recovery_kit` authenticates the kit **before** any store write, then a single `commit`. Existing vault: exact `vault_id`/`key_epoch` match and recovered RootSecret must open current vault/audit, then re-wrap under a new D18 passphrase. Empty store: kit is identity-only; a v2 backup supplies data (`original_vault_id` must match). Failed import leaves the live vault unchanged. |
| D13 | v1 recovery keys remain unlock/migrate-only. They cannot unlock a v2 vault and v1 generate does not emit a v2 kit. |

## Phase 10 / PR L landed (hardening)

Parser size caps, D14 persist/passphrase-change/sync-buffer commits, CI `cargo audit` / `cargo deny` / `npm audit --omit=dev`, fuzz smoke + `fuzz/` libFuzzer targets. Production docs (`CRYPTO.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`, `VAULTSYNC.md`, README) describe implemented v2. Frozen suite IDs and PQ crate pins were not retargeted.
