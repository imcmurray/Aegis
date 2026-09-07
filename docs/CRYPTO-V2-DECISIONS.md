# Aegis v2 decision log

Frozen choices that [`CRYPTO-V2.md`](./CRYPTO-V2.md) left open. Do not put these back into the spec. Override a row here with a new dated entry; do not silently retarget a released suite ID.

Companion: [`CRYPTO-V2-GAP.md`](./CRYPTO-V2-GAP.md).

Status: **Phase 0 gate re-run 2026-09-06.** Browser Argon2 (including worst-case `256 MiB / t=8 / p=4`) + WASM PQ execution + one official NIST ACVP KAT are recorded below. D1–D17 frozen; D12 includes a combined Argon2 work budget. Production crypto was not changed.

## Suite IDs (D2 + D11)

Nothing is named “hybrid” unless that object requires both a classical and a PQ primitive.

| ID | Name | Algorithms | First used |
|---|---|---|---|
| `0x0001` | `AegisV1Legacy` | Argon2id named profiles, XChaCha20-Poly1305, HKDF-SHA-256, Ed25519. Decoder only after v2 default. | v1 (existing) |
| `0x0002` | `AegisV2Core2026` | Argon2id (serialized params), XChaCha20-Poly1305, HKDF-SHA-256. **No ML-KEM, no ML-DSA.** | Phase 2 — vault, master wrap, backup, audit |
| `0x0003` | `AegisV2SyncHybrid2026` | Ed25519 **and** ML-DSA-65 over the same transcript. | Phase 7 |
| `0x0004` | `AegisV2ShareHybrid2026` | X25519 **and** ML-KEM-768, combiner D5, plus hybrid signatures from `0x0003`. | Phase 8 |

Never reuse an ID. Errata-driven algorithm changes are a **new** ID.

## Decisions

### D1 — Transcript encoding

**Choice:** length-prefixed binary, not ciborium map bytes.

```
"Aegis" || version_u16_le || suite_u16_le || kind_u16_le
        || vault_id_16 || key_epoch_u32_le
        || field_len_u32_le || field_bytes … (repeat)
```

One function per object kind (`build_master_wrap_transcript`, `build_vault_blob_transcript`, `build_sync_signing_transcript`, `build_share_transcript`, …). All implementations of a kind must be byte-for-byte identical.

`kind_u16` is an Aegis-owned permanent ID. Never `enum as u16` / declaration order. Frozen:

| `kind_u16` | Name | First used |
|---|---|---|
| `0x0001` | MasterWrap | Phase 2 |
| `0x0002` | VaultBlob | Phase 2 |
| `0x0003` | AuditBlob | Phase 3 |
| `0x0004` | SyncBlob | Phase 7 |
| `0x0005` | ExportBlob | Phase 4 (backup payload AAD) |
| `0x0006` | BackupWrap | Phase 4 (BackupKey wrap AAD) |

Never reuse an ID. Unknown IDs fail closed.

v1 `revision_sign_bytes` stays for the v1 decoder; it is not a v2 transcript.

### D2 — Core CryptoSuiteId

See table above. `0x0002 = AegisV2Core2026`. Not hybrid.

### D3 — HKDF salt

v1 used `salt = b"aegis/v1"` and labels `aegis/v1/*`. Documented break; do not dual-derive.

**RootSecret children** — `HKDF-SHA256(IKM = RootSecret, salt = vault_id [16 bytes], info = label)`:

```
aegis/v2/vault-dek
aegis/v2/audit-dek
aegis/v2/sync-dek
aegis/v2/search-hmac
aegis/v2/sync-ed25519-seed
aegis/v2/sync-mldsa-seed
aegis/v2/share-x25519-seed
aegis/v2/share-mlkem-seed
```

PQ seeds are derived in Phase 3 so rotation does not change this map later; they are unused until Phases 7–8.

**RecoverySecret child** (§27) — *not* a RootSecret child. `HKDF-SHA256(IKM = RecoverySecret, salt = vault_id, info = "aegis/v2/recovery-kek")`. RecoverySecret is independent 256-bit CSPRNG material. That KEK wraps RootSecret. Kit file format is Phase 9; the derivation must not wait, or the label gets mis-filed again.

**Combiner only** (D5) — not derived from RootSecret or RecoverySecret:

```
aegis/v2/share/hybrid-kek
```

### D4 — vault_id on migration vs restore

- **Live v1 → v2 migration:** keep `vault_id` (devices / sync addressing).
- **Normal backup restore:** mint a new `vault_id` and a new RootSecret (§25).

### D5 — Hybrid KEM combiner

Aegis is not TLS. **Do not claim RFC 10024 / X25519MLKEM768 compliance.**

Follow the conventional secret **ordering** used by X25519MLKEM768:

1. Reject the all-zero X25519 shared secret.
2. `ikm = mlkem_ss (32 bytes) || x25519_ss (32 bytes)`  (ML-KEM first).
3. `transcript_hash = SHA-256(build_share_transcript(...))` — **SHA-256, not SHA-512, not BLAKE3.**
4. `HybridSecret = HKDF-SHA256(IKM = ikm, salt = transcript_hash, info = "aegis/v2/share/hybrid-kek")`.

`build_share_transcript` is the D1 length-prefixed encoding of: protocol domain, sender identity, recipient identity, sender ephemeral key, recipient X25519 key, recipient ML-KEM key, ML-KEM ciphertext, vault/share identifiers (§40). Do not hash raw CBOR maps.

### D6 — PQ crates

Spike (2026-09-06), throwaway `/tmp/aegis-pq-spike`, **not merged**:

| Crate | Version | License | Notes |
|---|---|---|---|
| `ml-kem` | **0.3.2** | MIT OR Apache-2.0 | RustCrypto, FIPS 203 final, `wasm32-unknown-unknown` OK |
| `ml-dsa` | **0.1.1** | MIT OR Apache-2.0 | RustCrypto, FIPS 204 final, README: **unaudited**. MSRV 1.85 (repo rustc 1.97.1) |

Both compiled native and `wasm32-unknown-unknown`. Round-trip sizes match FIPS:

| Object | Spike | FIPS |
|---|---|---|
| ML-KEM-768 encapsulation key | 1184 | 1184 |
| ML-KEM-768 ciphertext | 1088 | 1088 |
| ML-DSA-65 verifying key | 1952 | 1952 |
| ML-DSA-65 signature | 3309 | 3309 |

**WASM integration tax:** these crates pull `getrandom` 0.4, which needs:

```toml
# .cargo/config.toml
[target.wasm32-unknown-unknown]
rustflags = ["--cfg", "getrandom_backend=\"wasm_js\""]
```

and `getrandom` feature `wasm_js`. Current Aegis `common` uses `getrandom` 0.2 with feature `js`. Phase 7 must reconcile this (bump 0.2→0.4 across the workspace, or isolate PQ behind a crate that owns 0.4). Phases 2–6 do not need it.

If that reconciliation fails, Phases 7–8 slip; Phases 2–6 still ship.

`libcrux-ml-kem` 0.0.10 remains an alternative if RustCrypto is blocked; not selected.

### D7 — v1 recovery key is the ancestor of Recovery Kit

Not of normal backup. Distinct file magic `AEGIS_RECOVERY_V2`. Never inside `.aegis` exports. Migration rule is D13.

### D8 — Argon2 generation policy

| Profile | Memory | t | p | Role |
|---|---|---|---|---|
| v2 minimum | 64 MiB | 3 | 1 | Floor for **new** v2 envelopes |
| Preferred | 128 MiB | 3 | 1 | Use when the device can |
| v1 Mobile | 32 MiB | 2 | 1 | Decode-only; never generate |
| `Test` | 8 KiB | 1 | 1 | `cfg(test)` only; impossible in production builds |

Native spike (this machine, 2026-09-06):

| Params | Wall time |
|---|---|
| 64 MiB t=3 p=1 | 176 ms |
| 128 MiB t=3 p=1 | 347 ms |
| 128 MiB t=4 p=2 (v1 High) | 504 ms |
| 256 MiB t=3 p=1 | 704 ms |

Browser WASM (same `argon2` 0.5 crate / `wasm32-unknown-unknown` / wasm-bindgen as the production browser vault; throwaway export because production has no 256 MiB profile and we must not change production crypto). Machine: EndeavourOS, kernel 7.2.2, 31 GiB RAM, 8 cores (`ian-hpprodesk600g3mt`).

| Params | Chromium 151.0.7922.34 | Firefox 151.0 | Native |
|---|---|---|---|
| 64 MiB t=3 p=1 | **189 ms PASS** | **1523 ms PASS** | 176 ms |
| 128 MiB t=3 p=1 | **375 ms PASS** | **3067 ms PASS** | 347 ms |
| 256 MiB t=3 p=1 | **774 ms PASS** | **6316 ms PASS** | 704 ms |
| 256 MiB t=8 p=1 | **2075 ms PASS** | **17222 ms PASS** | 2038 ms |
| 256 MiB t=8 p=4 | **2058 ms PASS** | **16912 ms PASS** | 1866 ms |

No OOM, no tab crash. `p=4` does **not** increase WASM cost (no thread pool); time tracks `memory × iterations`. Independent maxima would allow the last row as a hostile import (~17 s Firefox freeze). D12 therefore adds a combined work budget.

Firefox 64 MiB is already above the spec’s 500–1000 ms calibration window. Spec §9: do **not** drop below the 64 MiB production minimum because Aegis is in a browser. So:

- **New v2 vaults always generate ≥ 64 MiB.** Product blocker if a target browser cannot complete 64 MiB (none of the tested browsers failed).
- **Preferred 128 MiB** only when unlock is comfortable (~≤1 s). That is Chromium-class today, not Firefox-class (3 s). Browser default = 64 MiB; desktop/Chromium may offer 128.
- Import maxima are D12, not D8.

v1 production note: the browser UI currently **generates Mobile 32 MiB** vaults (`defaultKdfProfile()`). v2 must not.

### D9 — VaultSync users

Assume the real install base is **browser vault + `.aegis` export** (README). Keep a v1 Ed25519 decoder and a signed identity-transition record (§46) so optional Freenet mode does not fork.

**Local `verify_revision` omission:** see D17. Not silently left until Phase 7 without a recorded decision.

### D10 — File magic

Leading ASCII, then a version byte, then CBOR. Reject unknown magic before deserialize.

Wire for vault / master:

```
"AEGIS_VAULT_V2" || 0x02 || CBOR(MasterEnvelopeV2 | VaultBlobV2)
```

Wire for normal backup:

```
"AEGIS_BACKUP_V2" || 0x02 || CBOR(BackupEnvelopeV2)
```

External decoder is `from_bytes` (magic + version, then CBOR). Inner `from_cbor` is the body after the prefix is stripped — raw CBOR without magic is not a v2 file.

| Artifact | Magic | Phase |
|---|---|---|
| Vault / master envelope blob | `AEGIS_VAULT_V2` | 2 |
| Normal backup | `AEGIS_BACKUP_V2` | 4 |
| Recovery Kit | `AEGIS_RECOVERY_V2` | 9 |
| Sync revision / state | `AEGIS_SYNC_V2` | 7 |

### D11 — Suite semantics (supersedes CRYPTO-V2 suite-name examples)

**D11 supersedes the suite-name examples in `CRYPTO-V2.md` §§3, 4, 12 and 14.**

Where those sections write `AEGIS_V2_HYBRID_2026` / `AegisV2Hybrid2026` on **vault, master-wrap, or backup** objects, implementation **SHALL** use `AegisV2Core2026` (`0x0002`). Those objects do not use ML-KEM or ML-DSA. The original contract is not edited; this log is the amendment.

Hybrid protocol IDs:

- Sync revisions: `AegisV2SyncHybrid2026` (`0x0003`) — Phase 7.
- Share envelopes: `AegisV2ShareHybrid2026` (`0x0004`) — Phase 8.

A storage/backup/master object that claims `0x0002` and carries ML-KEM/ML-DSA fields is invalid. An object that claims `0x0003` or `0x0004` and is missing either primitive is rejected (§43). Never silently interpret a v2 object as v1.

### D12 — Hostile-resource bounds (frozen 2026-09-06, browser-confirmed)

Generation targets (D8) may be lower. A malicious file must fail closed as DoS, not hang the tab.

Independent Argon2 maxima are **not** sufficient. The combination `256 MiB / t=8 / p=4` is individually legal under those caps and took **~17 s in Firefox** (2058 ms Chromium). That is an attacker-chosen freeze, not the ~6 s stall previously cited from `256 MiB / t=3 / p=1`.

**Combined work budget** (from the browser measurements; time ≈ `memory × iterations` on WASM):

```
memory_kib     <= 262_144          # 256 MiB
iterations     <= 8
parallelism    <= 4
AND
memory_kib * iterations <= 786_432 # 256 MiB × t=3
```

`786_432` is `256 * 1024 * 3`, the largest combination actually timed at ~6 s Firefox / ~0.8 s Chromium with no OOM. Reject **before** allocating Argon2 memory if any clause fails.

**Implementation (Phase 2/4):** compute the work factor with a wide integer and **checked** arithmetic so overflow cannot wrap under the cap:

```
let work = u64::from(memory_kib)
    .checked_mul(u64::from(iterations))
    .ok_or(Error::InvalidKdfParams)?;
if work > MAX_ARGON2_WORK {
    return Err(Error::InvalidKdfParams);
}
```

Do this before allocating the Argon2 buffer or invoking the hasher.

Consequences:

| Combo | `m_kib * t` | Import |
|---|---|---|
| 256 MiB t=3 p≤4 | 786_432 | allow (measured) |
| 256 MiB t=8 p≤4 | 2_097_152 | **reject** (~17 s Firefox) |
| 128 MiB t=6 p≤4 | 786_432 | allow |
| 64 MiB t=8 p≤4 | 524_288 | allow |
| v1 Interactive 64/t=3 | 196_608 | allow |
| v1 High 128/t=4 | 524_288 | allow |
| v1 Mobile 32/t=2 | 65_536 | allow (decode-only) |

`parallelism` stays an independent cap (lane count / implementation safety). On this WASM target `p=4` was slightly *faster* than `p=1`, not a DoS multiplier.

| Resource | Import maximum | Notes |
|---|---|---|
| Argon2 memory | **256 MiB** | Reject before allocate if above. |
| Argon2 iterations | **8** | Not usable at 256 MiB; see work budget. |
| Argon2 parallelism | **4** | |
| Argon2 work | **`memory_kib * iterations <= 786_432`** | Mandatory. Firefox ~6 s at the cap. |
| Argon2 salt | **exactly 16 bytes** | |
| Argon2 output | **exactly 32 bytes** | |
| Total file size | **16 MiB** | Outer container |
| Ciphertext size | **8 MiB** | Matches v1 `VaultSyncState::MAX_CIPHERTEXT` |
| Entries | **50_000** | |
| Folders | **5_000** | |
| Attachments | **not applicable / reserved** | No attachment format in v2 Core. Do **not** encode 8 MiB-each / 32 MiB-total here; that cannot fit in a 16 MiB file / 8 MiB ciphertext. Revisit when an attachment format is specified (new decision, possibly new file-size cap). |
| String length | **8 KiB** | |
| Custom fields / entry | **64** | |
| Nesting depth | **8** | |
| Collection counts (tags, urls, history) | history already capped at 10; urls/tags **64** each | |

v1 envelopes with Mobile (32 MiB) remain decodable. New v2 envelopes must not generate below 64 MiB.

Phase 4 implements these numbers. Do not invent different ones in that PR.

### D13 — Legacy recovery migration

v2 may accept a v1 recovery key **solely** to unlock/migrate a v1 vault.

After a successful migration:

1. Generate a new 256-bit Recovery Kit.
2. Wrap the **new** RootSecret (HKDF `aegis/v2/recovery-kek`).
3. Present the kit once.
4. **Delete** the v1 recovery envelope.

Do not re-wrap the 160-bit secret around RootSecret. Do not leave the v1 recovery envelope as a second unlock path on a v2 vault.

### D14 — Atomic persistence, every backend

“Candidate then commit” applies to **import, v1→v2 migration, and RootSecret rotation**.

`SecretStore` grows an explicit commit API (Phase 1b), used by later phases:

| Backend | Mechanism |
|---|---|
| Browser IndexedDB | Single IDB transaction, or shadow keys `aegis/v2/pending/*` plus a commit marker, then swap the active pointer. Today: one `put` of key `v1` (`ui/src/browserClient.ts`). |
| Native `FileStore` | Stage `*.bin.tmp` + fsync, durably write `_aegis_commit` marker, fsync directory, then rename. Reopen replays the marker. Crash at any boundary recovers to old *or* new, never mixed. |
| Memory / tests | Replace the map in one assignment after the candidate is complete. |
| Freenet | **Not** sequential `set_secret`. Raw `CtxStore::commit` returns `UNSUPPORTED_ATOMIC_COMMIT`. The delegate wraps it in `GenerationStore`: write `aegis/gen/<id>/…`, verify, then a single `aegis/v1/active-gen` pointer switch is the commit point. |

A crash leaves the old valid vault or the new valid vault, never a mixture. Sequential multi-key write is not a commit.

Phase 1b uses this for import only. Phases 5 and 6 must call the same API.

Invariants for later PRs (not new transaction protocols):

- `GenerationStore` candidate generations are immutable once verified.
- The active-generation pointer only ever points at a fully verified generation.
- Recovery/replay is idempotent: reopen twice after a simulated crash yields the same state.
- GC is never required for correctness.
- A malformed commit marker fails closed (does not guess which generation to install).
- Phase 5 migration and Phase 6 RootSecret rotation reuse this D14 machinery.

### D15 — Browser execution security (Phase 1c)

Implemented in PR C2:

- Production HTML gets a strict **meta** CSP (`ui/vite.config.ts` → `ui/dist/index.html` / Pages bundle). Policy includes `default-src 'self'` and `script-src 'self' 'wasm-unsafe-eval'`. No `'unsafe-inline'`, no `'unsafe-eval'`. Vite *dev* omits CSP so HMR works.
- **`frame-ancestors` is not in the meta policy.** CSP Level 3 ignores `frame-ancestors` on a `<meta>` element. GitHub Pages cannot set CSP HTTP headers, so clickjacking protection is **not** an active control on that host. If a reverse proxy/CDN later serves Aegis, add `Content-Security-Policy: …; frame-ancestors 'none'` as a response header.
- `connect-src` is `'self'` plus exact optional-mode origins: `http://127.0.0.1:8787` (dev vault) and `ws://127.0.0.1:7509` (Freenet). Default browser-vault mode does not need those.
- Runtime JS is the Vite bundle from `node_modules` (self-hosted). CI fails if the production HTML has `http(s):` script src.
- `npm ci` only (no `npm install` fallback). `cargo test --workspace --locked` in `.github/workflows/ci.yml` and before Pages deploy.
- `wasm-bindgen-cli` **0.2.126 --locked** with no unpinned fallback, matching `tools/browser-wasm`.

Not in 1c: fuzzing, `cargo deny` full advisory policy, claiming XSS-proof. Those stay Phase 10.

### D16 — PQ conformance and errata

| Standard | Spike implements | Errata watch |
|---|---|---|
| FIPS 203 ML-KEM (2024-08-13) | `ml-kem` 0.3.2, ML-KEM-768 | CSRC planning note **2025-11-17**: errata/potential-updates spreadsheet under FIPS 203 documentation. |
| FIPS 204 ML-DSA (2024-08-13) | `ml-dsa` 0.1.1, ML-DSA-65 | CSRC planning note **2026-07-31**: errata (potential updates) spreadsheet. |

Errata on the standard text do **not** mean the algorithm is unsafe. They mean Aegis pins crate versions, records this table, and does not silently retarget `0x0003`/`0x0004`.

**Official KAT (Phase 0, 2026-09-06):** PASS. One encapsulation vector from NIST ACVP-Server `ML-KEM-encapDecap-FIPS203/internalProjection.json` (algorithm=ML-KEM, mode=encapDecap, revision=FIPS203, vsId=42, **tcId=26**, parameterSet=ML-KEM-768) was run through `ml-kem` 0.3.2 `EncapsulationKey768::new_from_slice` + `encapsulate_deterministic` (`hazmat`). Ciphertext and shared secret matched. The crates.io tarball does **not** ship the ACVP JSON (only the git repo does); that is why the first spike could not `cargo test` the crate’s own `encap-decap.rs`. The crate API *can* consume ACVP fields (`ek`, `m`, `c`, `k`). Full in-tree ACVP/ML-DSA KATs remain Phase 7–8.

**Official ML-DSA-65 KATs (Phase 7, 2026-09-06):** PASS against frozen `ml-dsa` **0.1.1**. NIST ACVP-Server commit `975de31eb83d87039ec88934fdc47d8c312b892d` (2026-08-12, `RELEASE/v1.1.0.43`), revision `FIPS204`, vsId **42**, parameterSet **ML-DSA-65**. Vendored subsets (not a single vector) live in `common/tests/fixtures/acvp-mldsa65/` with SHA-256 recorded in `SHA256SUMS` / `PROVENANCE.md`:

| Mode | Groups | Vectors |
|---|---|---|
| keyGen | tgId 2 | 25 |
| sigGen | tgId 3, 10, 15, 22 | 60 |
| sigVer | tgId 3, 10 (accept + official rejects) | 30 |

Source SHA-256 of the full NIST `internalProjection.json` files and the extraction rules (ML-DSA-65 only; HashML-DSA / externalMu omitted because Aegis uses pure ML-DSA with internally computed μ) are in that provenance file. Suite `0x0003` and the crate pin were **not** retargeted to make vectors pass.

**Official ML-KEM-768 KATs (Phase 8, 2026-09-06):** PASS against frozen `ml-kem` **0.3.2**. Same ACVP-Server commit `975de31eb83d87039ec88934fdc47d8c312b892d`, revision `FIPS203`, vsId **42**, parameterSet **ML-KEM-768**. Vendored in `common/tests/fixtures/acvp-mlkem768/`:

| Mode | Groups | Vectors |
|---|---|---|
| keyGen | tgId 2 | 25 |
| encapDecap | tgId 2 encapsulation AFT (25), tgId 5 decapsulation VAL (10) | 35 |

This supersedes the Phase 0 single-vector gate (encapDecap tcId=26) for ML-KEM-768. Suite `0x0004` and the crate pin were **not** retargeted.

Hybrid KEM combiner tests (D5): all-zero X25519 rejected; swapping ML-KEM/X25519 IKM order changes the secret; changing either component changes the hybrid result.

`ml-dsa` README: never independently audited. Watch RustCrypto advisories (including historical `ml-dsa` timing issues reported against earlier releases). Do not auto-merge crypto major versions.

### D17 — Local VaultSync signature verification (v1)

Gap: `sync_vault` decrypts on `vault_dek` and **never calls `verify_revision`**. Only the contract verifies Ed25519 when a VK is present.

**Decision: defer the local-verify hotfix to Phase 7**, do not add Phase 1d.

Reason: D9 — VaultSync is optional Freenet mode, not the production install base (browser + `.aegis`). A v1 signature-verify change would be a sync-protocol behavior change worth golden fixtures first, and Phase 7 already rewrites revision authentication to hybrid AND.

If that install-base assumption is wrong (a real multi-device VaultSync user exists), **stop and add Phase 1d** before Phase 2: local client must reject unsigned/badly-signed v1 revisions. Record that reversal here; do not “just fix it” inside Phase 7 without fixtures.

### D18 — v2 passphrase policy (frozen 2026-09-06)

Replaces the v1 8-character UI floor for every v2 passphrase-create path. Same function (`validate_v2_passphrase`) for vault create, passphrase change, backup passphrase, and restore’s new-vault passphrase.

- **Minimum:** 12 Unicode scalar values (`chars().count()`), not bytes.
- **Reject** (any one is enough):
  - below the minimum;
  - all characters identical (`aaaaaaaaaaaa`);
  - full-string match against a frozen common-password list (ASCII-case-insensitive *copy* for comparison only);
  - all-digit simple sequences of length ≥ 8 with consecutive ±1 steps (`12345678`, `123456789012`);
  - full-string keyboard / alphabet runs of length ≥ 8 that are a contiguous substring of `qwertyuiop` / `asdfghjkl` / `zxcvbnm` / `abcdefghijklmnopqrstuvwxyz` / `1234567890` or the reverse.
- **Do not** require mixed case, digits, or symbols.
- **Do not** trim, case-fold, or Unicode-normalize the bytes fed to Argon2. Leading/trailing spaces are significant.
- UI may *recommend* 6+ random words or 20+ random characters; that is not an additional reject rule.

Unlock of an existing envelope does not re-apply this policy.

### Phase 2 / PR D (2026-09-06) — Core suite + envelopes

Landed in `common/src/crypto/`. **Not** wired into `VaultSession::create` or import (Phase 5).

- `CryptoSuiteId` serializes as explicit u16 (`0x0001`–`0x0004`). Unknown IDs fail closed. Master wrap and vault blobs `require_v2_core()` (`0x0002` only). No ML-KEM/ML-DSA fields on those objects; `deny_unknown_fields`.
- D10: vault/master wire is `"AEGIS_VAULT_V2" \|\| 0x02 \|\| CBOR`. `from_bytes` rejects missing/wrong magic **before** CBOR. Backup/recovery/sync magics reserved, not used yet.
- `MasterEnvelopeV2`: `format_version=2`, suite `0x0002`, 16-byte `vault_id`, serialized `Argon2ParamsV2`, `key_epoch`, 24-byte `wrap_nonce`, `wrapped_root_secret`.
- `VaultBlobV2`: same header fields + 24-byte nonce + ciphertext.
- D1 `kind_u16` frozen: MasterWrap `0x0001`, VaultBlob `0x0002`, AuditBlob `0x0003`, SyncBlob `0x0004`, ExportBlob `0x0005`. `ObjectKind::to_u16` is an explicit match, not `as u16`.
- D1 transcripts are AAD: `"Aegis" \|\| version_u16_le \|\| suite_u16_le \|\| kind_u16_le \|\| vault_id_16 \|\| key_epoch_u32_le \|\| (field_len_u32_le \|\| field_bytes)*`.
- `Argon2ParamsV2.algorithm`: Aegis wire ID `0x02` = Argon2id (`ARGON2_ALG_ARGON2ID`). Mapped to the crate via `match`, not a discriminant cast. Unknown algorithm/version fail closed.
- `RootSecret` is `Zeroize + ZeroizeOnDrop` (Debug redacted).
- D12: `argon2_work_factor` is `u64::checked_mul` **before** `Params::new` / Argon2 allocate. Caps: 256 MiB, t≤8, p≤4, work ≤ 786_432. v2 generate/import reject < 64 MiB. `Test` params cannot pass `KdfContext::V2Generate` / `V2Import`.
- v2 AEAD is `crypto/aead.rs` (raw nonce + ciphertext), not v1 `SealedBlob { version: 1, … }`.
- Frozen v1 fixtures still decode on the v1 path; v2 parsers reject them.

### Phase 3 / PR E (2026-09-06) — RootSecret hierarchy + memory-only session

Landed beside v1. **`VaultSession::create` / unlock / import still v1** (Phase 5).

- HKDF-SHA256(IKM = RootSecret, salt = 16-byte `vault_id`, info = label). Does not dual-derive with `aegis/v1/*`.
- Root-derived labels (frozen): `vault-dek`, `audit-dek`, `sync-dek`, `search-hmac`, `sync-ed25519-seed`, `sync-mldsa-seed`, `share-x25519-seed`, `share-mlkem-seed` (64-byte `d||z`). **Not** `recovery-kek`.
- `RecoveryKek` = HKDF-SHA256(IKM = **RecoverySecret**, salt = vault_id, info = `aegis/v2/recovery-kek`). RecoverySecret is independent CSPRNG material (§27). Kit file remains Phase 9.
- `aegis/v2/share/hybrid-kek` is the D5 combiner info label only — not a RootSecret or RecoverySecret child.
- Distinct newtypes: `VaultDek`, `AuditDek`, `SyncDek`, `SearchHmacKey`, `SyncEd25519Seed`, `SyncMldsaSeed`, `ShareX25519Seed`, `ShareMlkemSeed`, `RecoverySecret`, `RecoveryKek`, `WrapKek`. No `Clone` / `Serialize` / `Display`. `Zeroize` + `ZeroizeOnDrop`. Debug redacted.
- `AuditBlobV2` / `SyncBlobV2` sealed under their own DEKs and D1 kinds `0x0003` / `0x0004`. Vault DEK cannot open audit or sync.
- `VaultSessionV2` (`common/src/session_v2.rs`): RootSecret only in RAM. Store keys `aegis/v2/{envelope,vault,audit}`. **No `aegis/v2/session`.** Passphrase change re-wraps the same RootSecret (vault blob unchanged).
- UI: password fields are read and cleared before the request is sent to WASM (`takePassword`).
- PQ crates are still not linked; only seed material is derived.

### Phase 4 / PR F (2026-09-06) — independent backup + safe restore

v2-only API on `VaultSessionV2`. **v1 `export_bundle` / `import_bundle` unchanged** (still re-wraps live MasterSecret). Dispatch/UI still v1 until Phase 5.

- `BackupKey` is independent 256-bit CSPRNG. Backup passphrase → Argon2id (`≥ 64 MiB`) → `BackupWrapKek` wraps **BackupKey only**.
- Payload is `BackupPayloadV2` (document + optional audit + **encrypted** `original_vault_id`). No RootSecret, DEKs, or identity seeds.
- Wire: `"AEGIS_BACKUP_V2" \|\| 0x02 \|\| CBOR(BackupEnvelopeV2)`. Public fields: suite, `container_id`, KDF, wrap/payload nonces + ciphertext. `original_vault_id` is **not** on the envelope.
- D1: wrap kind `0x0006` BackupWrap; payload kind `0x0005` ExportBlob. AAD binds version/suite/kind/`container_id`/canonical KDF params — not `original_vault_id`.
- Isolation is checked on **serialized plaintext** BackupPayloadV2 before encryption (plus `deny_unknown_fields`). Ciphertext scans are not the proof.
- Backup passphrase uses D18 (`validate_v2_passphrase`), same as vault create/change/restore.
- D12: file ≤ 16 MiB and magic before CBOR; KDF validated before Argon2; ciphertext ≤ 8 MiB; entry/folder/string caps.
- Restore authenticates fully, then D14 `commit`. Mints **new** RootSecret and **new** vault_id. Backup passphrase is not reused as the vault passphrase.
- Cracked backup cannot unwrap the live master envelope or yield live DEKs.

Phase 5 is v1→v2 migration and default-create v2. Do not start it until this PR is signed off.

### Phase 9 / PR K (2026-09-06) — Recovery Kit productization

Landed. Identity-preserving disaster recovery is a separate artifact from normal backups.

- External file: `"AEGIS_RECOVERY_V2" \|\| 0x02 \|\| CBOR(RecoveryWrapV2)`. Body is Core suite `0x0002` only: `format_version`, `crypto_suite`, `object_kind` `0x000C`, `vault_id`, `key_epoch`, 24-byte nonce, wrapped RootSecret. No vault document, no RecoverySecret.
- D1 AAD: `build_recovery_wrap_transcript` — version, Core suite, kind RecoveryWrap, vault_id, key_epoch. Tampering any of those, or the ciphertext/nonce, fails closed.
- `RecoverySecret` is independent 256-bit CSPRNG. HKDF `aegis/v2/recovery-kek` is unchanged (D3). Display is Crockford Base32 with a 10-bit SHA-256 checksum and `AEGIS2-` prefix. Entropy is not reduced. v1 `AEGIS-` 160-bit keys are rejected on the v2 path (D13).
- Generate stores only the wrap at `aegis/v2/recovery` and returns the kit file + one-time secret. Regeneration overwrites the wrap (previous secret/kit retired). Re-export returns the current kit without minting a new secret.
- Import authenticates fully, then D14 `commit`. Two workflows:
  - **Existing v2 vault (lost passphrase):** kit + RecoverySecret + new D18 passphrase. Requires `kit.vault_id == local.vault_id` and `kit.key_epoch == local.key_epoch`. Recovered RootSecret must open current vault/audit. Re-wraps the **same** RootSecret under a fresh Argon2 salt. Old passphrase is not required. Stale or future-epoch kits are rejected. Empty-install limitation: no retained newer epoch exists to compare against.
  - **Empty store (disaster recovery):** kit is identity only. Requires a v2 `AEGIS_BACKUP_V2` for data, `backup.original_vault_id == kit.vault_id`, then re-encrypts the backup document under kit-derived keys and wraps the kit RootSecret. Ordinary backup restore without a kit still mints a new identity.
- UI warns that kit + secret = control of the vault identity, and that the two must be stored separately. `.aegis-recovery` vs `.aegis`. The Recovery Kit is never presented as a complete empty-install backup.

Phase 10 is security hardening / review. Do not start it until this PR is signed off.

### Phase 10 / PR L (2026-09-06) — hardening, not a new suite

- Parser size caps on MasterEnvelopeV2 / VaultBlobV2 / AuditBlobV2 / SyncBlobV2 (`MAX_VAULT_FILE` 16 MiB) and share/v1 CBOR before deserialize. Recovery Kit and backups already capped.
- `persist` and `change_passphrase` now D14-commit vault+audit / envelope+audit together. Sync buffer persist uses `SecretStore::commit`.
- Fuzz: CI smoke in `common/tests/phase10.rs`. Longer `cargo +nightly fuzz run` targets live in `fuzz/` (not a workspace member).
- Dependency policy: `deny.toml`. `ml-dsa 0.1.1` / `ml-kem 0.3.2` / Core AEAD-KDF crates not retargeted. `RUSTSEC-2025-0141` (unmaintained bincode via freenet-stdlib) ignored with reason. Production `npm audit --omit=dev` is clean; `nanoid` GHSA is Vite-dev-only.

## Spike notes (2026-09-06)

Throwaway crate at `/tmp/aegis-pq-spike` (not in this repo). Production Aegis crypto was not modified.

### Native

- ML-KEM-768 encaps/decaps + ML-DSA-65 sign/verify: **5 ms**.
- Argon2: see D8 native column.

### WASM *execution* (not compile-only)

wasm-bindgen 0.2.127, `--target web`, `aegis_pq_spike_bg.wasm` 629 KiB (Argon2 + PQ, `lto=true` `opt-level=z`). Instantiated in a JS page; functions called from the page.

| Runtime | PQ ML-KEM-768 encap/decap | PQ ML-DSA-65 sign/verify | sizes |
|---|---|---|---|
| Chromium 151.0.7922.34 | **PASS** (36 ms) | **PASS** | ek=1184 ct=1088 vk=1952 sig=3309 |
| Firefox 151.0 (Playwright build) | **PASS** (96 ms) | **PASS** | same |

System Firefox **155.0** is installed but Playwright cannot drive it (juggler protocol). Firefox numbers are from Playwright’s Firefox 151.0, still a Gecko/Firefox WASM runtime.

### Browser Argon2 (actual WASM, both browsers)

See D8 table. All **ten** cells PASS (previous six plus 256 MiB t=8 p=1 and t=8 p=4). No OOM. Firefox at independent-max `256/t=8/p=4` is **~17 s** — that combination is now **rejected** by the D12 work budget (`memory_kib * iterations <= 786_432`).

Harness: same `argon2` 0.5 crate and `wasm32-unknown-unknown` as `aegis-browser-wasm`. Production vault WASM was not used because it has no 256 MiB profile and Phase 0 forbids production crypto changes.

### Official KAT

See D16. **PASS** ACVP ML-KEM-768 encapsulation tcId=26.

### Size note (compile artifact)

Earlier cdylib without wasm-bindgen JS glue was 290 KiB with an exported round-trip. The wasm-bindgen web build used for browser execution is 629 KiB because it also contains Argon2. Expect on the order of **+200–300 KiB** PQ-only when linked into the browser vault, before wasm-opt.

## PR checklist from spec §68

Copy onto every crypto PR. v1 currently violates several of these; v2 PRs must not.

- [ ] Do not replace XChaCha20 with homemade encryption
- [ ] Do not encrypt the vault directly with the passphrase
- [ ] Do not reuse the backup password as a vault password automatically
- [ ] Do not put RootSecret in normal backups
- [ ] Do not reuse v1 MasterSecret when migrating to v2
- [ ] Do not use one key for vault + audit + sync
- [ ] Do not silently fall back from v2 to v1
- [ ] Do not treat ML-KEM as authentication
- [ ] Do not accept either signature in hybrid mode (AND, not OR)
- [ ] Do not use ordinary CBOR map serialization as an undefined signature transcript
- [ ] Do not persist RootSecret to IndexedDB
- [ ] Do not delete an existing vault before a replacement is fully authenticated
- [ ] Do not accept unbounded KDF parameters from imported files
- [ ] Do not accept Argon2 params that pass individual caps but fail `memory_kib * iterations <= 786_432` (D12)
- [ ] Do not hand-implement ML-KEM or ML-DSA
- [ ] Do not weaken Argon2 simply for portable exports
- [ ] Do not label a storage suite “hybrid”
- [ ] Do not carry the v1 160-bit recovery wrapping onto a v2 vault
- [ ] Do not claim RFC 10024 or FIPS compliance the code has not earned
- [ ] Do not silently retarget a released suite ID when NIST publishes errata
