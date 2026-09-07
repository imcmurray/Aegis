# Official FIPS 204 / ACVP ML-DSA-65 vectors (Phase 7 / D16)

These files are **not** homemade KATs. They are the ML-DSA-65 test groups
extracted from NIST's ACVP-Server `internalProjection.json` sample sets — the
same ground-truth files NIST's reference validator uses.

## Source

| Field | Value |
|---|---|
| Origin | https://github.com/usnistgov/ACVP-Server |
| Commit | `975de31eb83d87039ec88934fdc47d8c312b892d` (master, 2026-08-12, `RELEASE/v1.1.0.43` including hotfix patches) |
| Standard | FIPS 204 (2024-08-13), parameter set **ML-DSA-65** |
| ACVP revision | `FIPS204` |
| vsId (all three files) | 42 |
| Implementation under test | RustCrypto `ml-dsa` **0.1.1** (workspace pin; not retargeted) |
| Captured | 2026-09-06 |

## Source files (full NIST projections)

| ACVP set | Path in ACVP-Server | SHA-256 of downloaded file |
|---|---|---|
| ML-DSA / keyGen / FIPS204 | `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json` | `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf` |
| ML-DSA / sigGen / FIPS204 | `gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json` | `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22` |
| ML-DSA / sigVer / FIPS204 | `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json` | `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437` |

## Vendored subsets (this directory)

Only `parameterSet == "ML-DSA-65"` groups are stored. HashML-DSA
(`preHash == "preHash"`) and precomputed-μ (`externalMu == true`) groups are
omitted: Aegis uses pure ML-DSA-65 (FIPS 204 Algorithms 1–3 / 6–8) via
`ml-dsa` 0.1.1, which is the production signing path (empty context, μ
computed internally). The omitted groups remain in the upstream files above.

| File | Groups | Vectors | SHA-256 |
|---|---|---|---|
| `keyGen-FIPS204-ML-DSA-65.json` | tgId 2 (AFT) | 25 | `9056b8a46c04a289033bb7cb2b4d04d6dcb00d995b9412af81918763887967ae` |
| `sigGen-FIPS204-ML-DSA-65.json` | tgId 3, 10, 15, 22 | 60 | `0dc4991d1f003ffecba9cc5b102b7f13caf335c7a7a7d69c52a9c7f51aedd2a9` |
| `sigVer-FIPS204-ML-DSA-65.json` | tgId 3, 10 | 30 | `e2705a370599fc7e5ec5b00aeab3332cece98b5c9273a20139be89ef5d25acfd` |

sigGen groups: deterministic external/pure, deterministic internal, randomized
external/pure, randomized internal. sigVer groups include both valid signatures
and official reject reasons (modified message / commitment / hint / z).

## D16 errata note (unchanged)

FIPS 204 ML-DSA (2024-08-13), crate `ml-dsa` 0.1.1, ML-DSA-65.
CSRC planning note **2026-07-31**: errata (potential updates) spreadsheet.
Errata on the standard text do **not** retarget suite `0x0003` or this crate pin.

Suite ID `AegisV2SyncHybrid2026` / `0x0003` is unchanged.
