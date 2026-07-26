# Aegis Threat Model

## Assets

| Asset | Sensitivity |
|--------|-------------|
| Entry secrets (passwords, TOTP seeds, notes, attachments) | Critical |
| Vault DEK / MasterSecret | Critical |
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
| Stolen locked device | **Yes** | At-rest AEAD; offline strength = passphrase entropy + Argon2id. |
| Stolen unlocked device / memory dump | **No** | Classic password-manager limit. |
| Malicious share recipient | **Scoped** | Sees only shared items. |
| Coercion / duress | **No** | Out of scope for MVP. |
| Long-term harvest (crypto break) | **Residual** | Version envelopes; plan crypto-agility. |

## Explicit non-goals

- TEE / enclave resistance against a fully rooted OS dumping Core memory
- Global traffic-analysis resistance beyond Freenet’s own properties
- Unlinkability if the user reuses the same Freenet identity across public apps
- “Forgot passphrase” cloud recovery without a recovery key

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

- No passwords, passphrases, DEKs, or MasterSecrets in logs, panics, or contract error strings.
- Audit events store action + entry id only — never secret field values.
