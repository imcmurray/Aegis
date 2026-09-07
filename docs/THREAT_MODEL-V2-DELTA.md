# Threat-model delta: v1 → v2

This is **not** the v2 threat model. [`THREAT_MODEL.md`](./THREAT_MODEL.md) stays the v1 document until Phase 10 rewrites it against the implemented code (§71). This file maps spec §69 onto what the current product actually guarantees.

Contract: [`CRYPTO-V2.md`](./CRYPTO-V2.md). Gaps: [`CRYPTO-V2-GAP.md`](./CRYPTO-V2-GAP.md).

## §69 properties vs v1

| After v2 (spec §69) | v1 today | Residual until |
|---|---|---|
| Stolen **locked local vault** ⇒ offline attack on the passphrase through Argon2id | **Holds weakly.** The default **browser** path creates vaults with **Mobile 32 MiB / t=2**, not Interactive 64 MiB. `Test` is a public enum and wire-reachable. No CSP, so a hostile origin that can run in the unlocked tab bypasses this entirely | Phase 1c (CSP), Phase 2 (serialized params, Test impossible, no Mobile generation) |
| Stolen **normal `.aegis` backup** ⇒ offline attack on **that backup only**; does not reveal live RootSecret | **False.** Export re-wraps the live MasterSecret (`export_bundle`). Cracking the export passphrase yields the same secret as the live vault | Phase 4 |
| Cracking an **old normal backup** does not expose future vault keys | **False**, same reason: backup ≡ identity. Rotation does not exist | Phase 4 + Phase 6 |
| Breaking **X25519** in a quantum future does not reveal shared keys while ML-KEM remains secure | **n/a** — sharing not shipped. v1 only derives an X25519 seed | Phase 8 |
| Breaking **Ed25519** does not allow forged v2 sync revisions while ML-DSA remains secure | **False** for any VaultSync user: revisions are Ed25519-only. Local `sync_vault` does not even call `verify_revision` — it decrypts on `vault_dek` alone; only the contract verifies. **Deferred to Phase 7 by D17** (VaultSync is optional; add Phase 1d if that is wrong) | Phase 7 (or 1d) |
| Changing the **master passphrase** does not re-encrypt every password | **Holds** (`change_passphrase` re-wraps MasterSecret) | keep |
| **Full cryptographic rotation** can invalidate previously compromised root material | **Missing** | Phase 6 |

## Additional v1 residuals the spec calls out

| Residual | Spec | Today |
|---|---|---|
| Wipe-then-decrypt replace-import can destroy the live vault on a bad file | §28, §51.6–7 | `import_bundle` clears secrets first |
| Unlocked MasterSecret lives in `aegis/v1/session` | §17 | Skipped on IndexedDB export; still in the WASM/delegate store while unlocked |
| Audit log uses the vault DEK | §16 | `load_audit` |
| Export KDF is Mobile (32 MiB) | §9, §24 | `KdfProfile::Mobile` in `export_bundle` |
| Passphrase floor is 8 characters | §11 | UI + `change_passphrase` |
| No Content-Security-Policy | §63 | `ui/index.html` |
| Harvest-now on future X25519-only shares | §42 | Do not ship v2 sharing without ML-KEM (D11) |
| Native file store is in-place `fs::write` | §29 / D14 | crash mid-write can truncate a `.bin` |

## Adversaries already in THREAT_MODEL.md

Keep the v1 table. v2 is meant to shrink these rows, not add new ones:

- **Network observer / contract host** — still ciphertext-only; v2 adds hybrid signatures so an Ed25519 break is not enough to forge revisions.
- **Stolen locked device** — still passphrase + Argon2id; v2 raises the floor (no Mobile generation, serialized params, Test impossible).
- **Stolen unlocked device / memory dump** — still **No**. v2 does not claim otherwise.
- **Malicious Aegis UI update / XSS while unlocked** — still the binding constraint on a browser password manager. Phase 1c (CSP, no remote JS) is mitigation, not elimination. Spec §63 is explicit.
- **Long-term harvest (crypto break)** — v1 listed this as residual with “plan crypto-agility.” v2 *is* that plan: Core suite ID + hybrid sync/share IDs, no silent downgrade.

## What this delta is not

- Not a claim that Aegis is post-quantum-ready. PQ is Phases 7–8, after Core storage.
- Not a substitute for the §72 review of the *resulting* code.
