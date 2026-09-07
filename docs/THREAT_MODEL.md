# Aegis Threat Model

## Assets

| Asset | Sensitivity |
|--------|-------------|
| Entry secrets (passwords, TOTP seeds, notes, attachments) | Critical |
| Vault DEK / RootSecret | Critical |
| Master passphrase | Critical |
| Metadata (site names, URLs, folder structure) | High |
| Local audit log | Medium |
| Freenet signing identity | Medium (linkability) |

## Adversaries

| Adversary | Protected? | Notes |
|-----------|------------|--------|
| Network observer / malicious peer | **Yes** (content) | Sees ciphertext + coarse metadata (size, timing). |
| Peer hosting contract state | **Yes** | Untrusted; validates signatures only. |
| Compromised non-rooted device (other origins) | **Mostly** | Shell isolates app iframe; Core holds secrets. Passphrase typed into Aegis UI can be stolen *in that tab* while unlocked. |
| Malicious Aegis UI update | **Partial** | Delegate can require consent for export/bulk ops. Hostile UI can still request individual decrypts while unlocked. |
| Stolen locked device | **Yes** | At-rest AEAD; offline strength = passphrase entropy + Argon2id (≥ 64 MiB on new v2 envelopes). |
| Stolen unlocked device / memory dump | **No** | Classic password-manager limit. |
| Malicious share recipient | **Scoped** | Sees only shared items. |
| Coercion / duress | **No** | Out of scope for MVP. |
| Long-term harvest (crypto break) | **Reduced** | Core 0x0002 stays classical AEAD. Sync forgeries require breaking Ed25519 **and** ML-DSA-65. Share confidentiality requires breaking X25519 **and** ML-KEM-768 (D5). Historical encrypted artifacts do not automatically become the live identity (normal backups mint a new RootSecret). |

## Explicit non-goals

- TEE / enclave resistance against a fully rooted OS dumping Core memory
- Global traffic-analysis resistance beyond Freenet’s own properties
- Unlinkability if the user reuses the same Freenet identity across public apps
- “Forgot passphrase” cloud recovery. Offline Recovery Kit + RecoverySecret is the supported path; the kit is not a password backup.

## Trust boundaries

```
┌─ Untrusted network ──────────────────────────────┐
│  VaultSync / Share contracts (ciphertext only)   │
└──────────────────────────────────────────────────┘
┌─ Local Freenet Core ─────────────────────────────┐
│  Vault Delegate secret store (encrypted at rest) │
│  Unlocked session: DEK available to delegate     │
└──────────────────────────────────────────────────┘
┌─ Browser shell (trusted) ────────────────────────┐
│  RequestUserInput overlays                       │
└──────────────────────────────────────────────────┘
┌─ App iframe (less trusted) ──────────────────────┐
│  UI — display only; no long-lived DEK            │
└──────────────────────────────────────────────────┘
```

## Multi-device sync risks

- Sync ciphertext is **public and durable** for anyone who learns the contract address.
- Mitigations: strong passphrase, non-enumerable contract addressing (derive from secret-linked material), no plaintext metadata on the wire.
- Residual metadata: device count (version-vector width), write frequency.

## Sharing risks (phase 3)

- Revocation cannot erase already-downloaded ciphertext.
- Prefer read-only shares first; key rotation on revoke for future versions of the item.
- Expiry is policy enforced client-side (and optionally recorded in signed share packages).

## Logging policy

- No passwords, passphrases, DEKs, RootSecret, or RecoverySecret in logs, panics, or contract error strings.
- Audit events store action + entry id only — never secret field values.

## v2 properties (implemented)

These hold in the current code. They are not a claim of absolute security.

| Property | Status |
|----------|--------|
| Stolen **normal backup** does not reveal live RootSecret | BackupKey is independent; restore mints a new identity |
| Stolen **Recovery Kit** without RecoverySecret does not unwrap RootSecret | HKDF wrap; secret is never persisted |
| Valid-but-stale Recovery Kit cannot roll back a newer local epoch | Exact `vault_id` + `key_epoch` match on existing vaults |
| Empty-install kit-only restore cannot invent vault data | Kit has no VaultDocument; backup required for data |
| Passphrase change ≠ rotation | Re-wrap vs new RootSecret + epoch |
| Hybrid sync | Ed25519 AND ML-DSA-65; authorized identity before attribution |
| Hybrid share | X25519 AND ML-KEM-768; expected sender required; epoch-bound |
| Malformed v2 is not retried as v1 | Magic/suite fail closed |
| Failed import/recovery/rotation | Authenticate first, D14 commit; old state unchanged |
| Browser v2 session | No RootSecret in IndexedDB |

**Accepted architectural limits**

- Unlocked process memory can be dumped.
- CSP on GitHub Pages is a meta policy: `frame-ancestors` is not an active control there.
- Local sync rollback detection needs a retained newer counter; a coherent older snapshot can still verify.
- Empty-install recovery cannot detect that a kit is stale relative to some unseen later rotation.
- v1 `SecretKey` still implements `Clone` on the legacy path.
