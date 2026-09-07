# Official FIPS 203 / ACVP ML-KEM-768 vectors (Phase 8 / D16)

These files are **not** homemade KATs. They are the ML-KEM-768 test groups
extracted from NIST's ACVP-Server `internalProjection.json` sample sets.

## Source

| Field | Value |
|---|---|
| Origin | https://github.com/usnistgov/ACVP-Server |
| Commit | `975de31eb83d87039ec88934fdc47d8c312b892d` (master, 2026-08-12, `RELEASE/v1.1.0.43` including hotfix patches) |
| Standard | FIPS 203 (2024-08-13), parameter set **ML-KEM-768** |
| ACVP revision | `FIPS203` |
| vsId | 42 |
| Implementation under test | RustCrypto `ml-kem` **0.3.2** (workspace pin; not retargeted) |
| Captured | 2026-09-06 |

## Source files (full NIST projections)

| ACVP set | Path in ACVP-Server | SHA-256 of downloaded file |
|---|---|---|
| ML-KEM / keyGen / FIPS203 | `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` |
| ML-KEM / encapDecap / FIPS203 | `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json` | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |

Phase 0 ran a single vector from the encapDecap file (vsId=42, **tcId=26**, ML-KEM-768). Phase 8 vendors the ML-KEM-768 **sets**.

## Vendored subsets

| File | Groups | Vectors | SHA-256 |
|---|---|---|---|
| `keyGen-FIPS203-ML-KEM-768.json` | tgId 2 (AFT) | 25 | `77c000296333f29488104f9868b49e20a076d61d3f730fba7f32d9fe9d5635fc` |
| `encapDecap-FIPS203-ML-KEM-768.json` | tgId 2 encapsulation AFT (25), tgId 5 decapsulation VAL (10) | 35 | `d74d717eb475d1363d9176576fcef1d41fe59e55ed1e7689c346ef9f5d82dea1` |

Key-check VAL groups (`decapsulationKeyCheck` / `encapsulationKeyCheck`) are omitted; they are format checks, not encap/decap KATs. 512/1024 parameter sets are omitted because Aegis uses ML-KEM-768 only.

## D16 errata note (unchanged)

FIPS 203 ML-KEM (2024-08-13), crate `ml-kem` 0.3.2, ML-KEM-768.
CSRC planning note **2025-11-17**: errata/potential-updates spreadsheet.
Errata on the standard text do **not** retarget suite `0x0004` or this crate pin.
