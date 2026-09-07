<!--
Provenance (not part of the security contract):
  Origin: https://gitlab.themcmurrays.us/-/snippets/187
  Git:    ssh://git@gitlab.themcmurrays.us:2222/snippets/187.git
  Commit: 246fe6c816a429ee6edbb4514e3f84c43ec9ecfe (snippet repo; file empty.txt is a stub)
  Captured: 2026-09-06 from the snippet *description* on gitlab.themcmurrays.us
  Do not edit this document to "improve" the architecture. Amendments belong in
  docs/CRYPTO-V2-DECISIONS.md. Classification vs v1 is docs/CRYPTO-V2-GAP.md.
-->

# Aegis v2 Cryptographic Architecture

**Status:** Design specification\
**Target:** Aegis v2\
**Repository:** `imcmurray/Aegis`\
**Purpose:** Security redesign, post-quantum readiness, secure backup/import, crypto agility, key rotation\
**Audience:** Claude Code / Aegis developers / future security reviewers

---

# 1. Objective

Aegis v2 must preserve the strengths of the current Aegis design while correcting weaknesses discovered during security review and preparing the application for long-term post-quantum use.

Aegis v2 must provide:

* strong client-side encryption;
* protection against offline attacks against stolen vault files;
* cryptographic separation between live vaults and backups;
* authenticated and transactional imports;
* post-quantum-resistant sync and sharing;
* crypto agility;
* safe passphrase changes;
* explicit cryptographic key rotation;
* backward-compatible migration from Aegis v1;
* strong domain separation between every cryptographic use;
* no persistence of unlocked root key material;
* protection against algorithm downgrade;
* clear security boundaries that are easy to audit.

Aegis v2 should be designed for confidentiality measured in decades.

It should be described as **post-quantum-ready**, not "quantum proof."

---

# 2. Security philosophy

The cryptographic architecture should follow these rules.

## 2.1 Never invent cryptography

Use established, maintained implementations of standardized or widely reviewed algorithms.

Do not implement:

* Argon2;
* XChaCha20;
* Poly1305;
* HKDF;
* ML-KEM;
* ML-DSA;
* Ed25519;
* X25519

manually.

Use established Rust libraries with good maintenance, WASM compatibility, constant-time implementations where applicable, and active security review.

---

## 2.2 Symmetric cryptography remains the foundation

Aegis v2 should retain:

**XChaCha20-Poly1305 with 256-bit keys**

for vault encryption, backup encryption, audit encryption, sync encryption and share payload encryption.

There is no need to replace XChaCha20 simply because Aegis is becoming post-quantum-ready.

---

## 2.3 Use hybrid public-key cryptography during the PQ transition

Aegis v2 should use:

### Key establishment

**X25519 + ML-KEM-768**

### Digital signatures

**Ed25519 + ML-DSA-65**

The two signature algorithms must both validate for an Aegis v2 hybrid signature to be considered valid.

The hybrid key agreement must combine both independent shared secrets through HKDF.

This means Aegis is not dependent upon either the classical or PQ primitive alone.

---

# 3. Aegis v2 baseline crypto suite

Create a fixed, allow-listed crypto suite.

Conceptually:

`AEGIS_V2_HYBRID_2026

Passphrase KDF:
    Argon2id v=19

Root wrapping:
    XChaCha20-Poly1305

Key derivation:
    HKDF-SHA-256

Vault encryption:
    XChaCha20-Poly1305

Audit encryption:
    XChaCha20-Poly1305

Sync encryption:
    XChaCha20-Poly1305

Classical signature:
    Ed25519

Post-quantum signature:
    ML-DSA-65

Classical key agreement:
    X25519

Post-quantum KEM:
    ML-KEM-768
`

Assign this suite a permanent numeric identifier, for example:

`CryptoSuiteId = 0x0002
`

Do not rely on Rust enum serialization order as an externally stable algorithm identifier.

Explicit numeric IDs must be stable forever once released.

---

# 4. Crypto agility

Aegis must not scatter assumptions such as:

`if version == 2 then use XChaCha
`

throughout the codebase.

Create a well-defined cryptographic abstraction such as:

`CryptoSuite
CryptoSuiteId
EnvelopeVersion
`

However:

**Do not allow arbitrary mix-and-match algorithms supplied by an untrusted vault file.**

For example, an attacker must not be able to construct:

`AEAD = weak_algorithm
KDF = weak_algorithm
signature = none
`

Aegis should recognize only explicitly approved combinations:

`AegisV1Legacy
AegisV2Hybrid2026
FutureAegisV3
`

Unsupported suites must fail closed.

---

# 5. Core key hierarchy

The master passphrase must NEVER directly encrypt vault contents.

Create a random 256-bit root secret:

`RootSecret = CSPRNG(32 bytes)
`

This replaces the conceptual role of the current v1 `MasterSecret`.

The hierarchy becomes:

`                 MASTER PASSPHRASE
                        │
                     Argon2id
                        │
                        ▼
                       KEK
                        │
           XChaCha20-Poly1305 unwrap
                        │
                        ▼
                   RootSecret
                    256 bits
                        │
                  HKDF-SHA256
                        │
       ┌────────────────┼───────────────────┐
       │                │                   │
       ▼                ▼                   ▼
    Vault DEK       Audit DEK           Sync DEK
       │
       ├── Search HMAC key
       │
       ├── Ed25519 sync seed
       │
       ├── ML-DSA sync seed
       │
       ├── X25519 share seed
       │
       └── ML-KEM share seed/material
`

The passphrase-derived KEK exists solely to wrap `RootSecret`.

The KEK must never:

* encrypt entries;
* sign sync revisions;
* derive sharing keys;
* be persisted;
* leave the cryptographic runtime.

---

# 6. Domain-separated HKDF hierarchy

All operational keys derived from `RootSecret` must use unique domain-separated labels.

Suggested labels:

`aegis/v2/vault-dek
aegis/v2/audit-dek
aegis/v2/sync-dek
aegis/v2/search-hmac
aegis/v2/sync-ed25519-seed
aegis/v2/sync-mldsa-seed
aegis/v2/share-x25519-seed
aegis/v2/share-mlkem-seed
`

Include `vault_id` as part of the HKDF context.

Conceptually:

`HKDF(
    RootSecret,
    salt = vault_id,
    info = "aegis/v2/vault-dek"
)
`

Different cryptographic purposes must NEVER reuse the same derived key.

The ML-KEM derivation may require more seed material than 32 bytes. Generate the amount required by the selected implementation using its own HKDF label.

---

# 7. Vault identifiers

Generate `vault_id` from a CSPRNG.

Prefer an actual 128-bit binary UUID rather than using string concatenation internally.

Human-readable UUID rendering is fine for UI and logs.

Cryptographic code should operate on the fixed binary representation.

This prevents ambiguity in authenticated data.

---

# 8. Passphrase KDF

Aegis v2 must continue using:

**Argon2id version 19**

but must stop storing only a named profile such as:

`Mobile
Interactive
High
`

The actual parameters must be serialized.

Example:

`Argon2Params {
    algorithm: argon2id,
    version: 19,
    memory_kib: 131072,
    iterations: 3,
    parallelism: 1,
    salt: [16 random bytes],
    output_len: 32
}
`

Named profiles may still exist in the UI, but the envelope must contain resolved parameters.

---

# 9. Recommended Argon2 policy

Use the device's available resources rather than deliberately weakening browser vaults.

## Baseline v2 minimum

Recommended baseline:

`memory = 64 MiB
iterations = 3
parallelism = 1
`

## Preferred desktop/browser configuration

Attempt:

`memory = 128 MiB
iterations = 3
parallelism = 1
`

when the device can execute it comfortably.

Aegis may calibrate during vault creation to target approximately:

`500–1000 ms
`

of unlock work on the user's device.

Do not reduce below the supported production minimum merely because Aegis is running in a browser.

---

# 10. KDF parameter validation

Never blindly allocate memory according to KDF values supplied by an imported file.

Validate before running Argon2.

For example:

`production minimum memory: 64 MiB
maximum accepted memory: implementation-defined safe ceiling
iterations: bounded
parallelism: bounded
salt length: exactly expected size
output length: exactly 32 bytes
`

Legacy Aegis v1 import may accept old v1 parameters such as 32 MiB.

New Aegis v2 vaults must not generate legacy-strength envelopes.

The `Test` KDF must be impossible to select in production builds.

---

# 11. Passphrase policy

Replace the current eight-character minimum.

Aegis should encourage:

`6+ random words
`

or:

`20+ cryptographically random characters
`

At a minimum, reject obviously inadequate passphrases.

Recommended UI:

`Weak
Fair
Strong
Very Strong
`

with local strength estimation.

Do not impose arbitrary composition rules such as:

`must contain one capital
must contain one symbol
`

Entropy matters more.

Aegis must:

* support long passphrases;
* preserve exact UTF-8 input;
* never silently trim whitespace;
* never silently change case;
* avoid hidden Unicode normalization that could make a passphrase different on another client.

---

# 12. Master envelope v2

Define a new master envelope.

Conceptually:

`MasterEnvelopeV2 {
    format_version: 2,
    crypto_suite: AEGIS_V2_HYBRID_2026,

    vault_id: [u8; 16],

    kdf: Argon2Params,

    wrap_nonce: [u8; 24],

    wrapped_root_secret: bytes,

    created_at: u64
}
`

`wrapped_root_secret` is:

`XChaCha20-Poly1305(
    key = KEK,
    nonce = random 24 bytes,
    plaintext = RootSecret,
    aad = master-envelope transcript
)
`

---

# 13. Authenticated-data encoding

Do not continue the v1 approach of simply concatenating:

`domain || kind || vault_id || logical_id
`

without explicit framing.

Use an unambiguous deterministic transcript.

For example:

`"Aegis" ||
version_u16 ||
suite_u16 ||
kind_u16 ||
vault_id_16 ||
key_epoch_u32 ||
logical_id_length_u32 ||
logical_id
`

Every variable-length field must be length-prefixed.

Alternatively, use a formally defined deterministic encoding.

Do not depend on ordinary CBOR map ordering for cryptographic signatures unless canonical CBOR is explicitly guaranteed.

---

# 14. VaultBlobV2

Conceptually:

`VaultBlobV2 {
    version: 2,
    crypto_suite: AEGIS_V2_HYBRID_2026,
    vault_id: [u8; 16],
    key_epoch: u32,
    nonce: [u8; 24],
    ciphertext: bytes
}
`

Encryption:

`VaultDEK =
    HKDF(RootSecret, vault_id, "aegis/v2/vault-dek")

ciphertext =
    XChaCha20Poly1305(
        VaultDEK,
        random_nonce,
        serialized VaultDocumentV2,
        authenticated_header
    )
`

The authentication tag generated by the AEAD is mandatory.

---

# 15. Nonce requirements

Every XChaCha20-Poly1305 encryption operation must receive a fresh:

`24-byte cryptographically random nonce
`

from the platform CSPRNG.

Never:

* use counters as XChaCha nonces unless carefully specified;
* derive nonces from timestamps;
* derive nonces from entry IDs;
* reuse a nonce with the same key.

CSPRNG failures must be fatal.

---

# 16. Separate audit key

Do not encrypt the audit log with the same key as the vault document.

Derive:

`aegis/v2/audit-dek
`

and encrypt audit state independently.

This gives cleaner cryptographic separation and simplifies future storage changes.

---

# 17. Session key handling

Aegis v2 should eliminate persistent storage of anything equivalent to:

`aegis/v1/session
`

The `RootSecret` must exist only inside the unlocked in-memory vault session.

It must not be written to:

* IndexedDB;
* localStorage;
* sessionStorage;
* Freenet contract state;
* browser persistence snapshots;
* logs;
* crash reports.

Refreshing or closing the application should normally require another unlock.

If Aegis later supports persistent biometric unlock, it must use a separate OS/WebAuthn-backed design.

Do not implement "remember me" by saving `RootSecret` in IndexedDB.

---

# 18. Zeroization

Secret Rust types should implement zeroization-on-drop where practical.

This includes:

* RootSecret;
* KEK;
* VaultDEK;
* AuditDEK;
* SyncDEK;
* sharing secrets;
* seed material;
* temporary decrypted backup keys.

Avoid:

`Debug
Display
Serialize
Clone
`

on secret-bearing types unless absolutely required.

`Debug` output must always redact secret material.

JavaScript passphrases cannot be reliably zeroized, so minimize their lifetime.

The UI should:

1. collect the passphrase;
2. pass it to WASM immediately;
3. clear the visible field;
4. avoid retaining it in React/JS application state.

---

# 19. Passphrase change

Changing the master passphrase should remain inexpensive.

Process:

`old passphrase
      ↓
Argon2id
      ↓
old KEK
      ↓
unwrap RootSecret
      ↓
generate new salt
      ↓
Argon2id(new passphrase)
      ↓
new KEK
      ↓
wrap SAME RootSecret
`

This operation does not re-encrypt the vault.

This is a **passphrase re-wrap**, not a cryptographic reset.

The UI should clearly distinguish the two.

---

# 20. Full cryptographic reset

Add a separate operation:

**Rotate Vault Cryptographic Keys**

This is for suspected key compromise.

It must:

 1. generate a new random `RootSecret`;
 2. derive all new operational keys;
 3. decrypt the current vault;
 4. re-encrypt it under the new VaultDEK;
 5. re-encrypt the audit log;
 6. generate new sync identities;
 7. generate new sharing identities;
 8. increment `key_epoch`;
 9. invalidate or supersede old sync credentials;
10. handle existing shared items according to explicit rotation rules;
11. atomically commit the new state.

Conceptually:

`RootSecret epoch 1
        │
        X COMPROMISED
        │
        ▼

CSPRNG
   │
   ▼
RootSecret epoch 2
        │
        ├── new VaultDEK
        ├── new AuditDEK
        ├── new SyncDEK
        ├── new Ed25519 identity
        ├── new ML-DSA identity
        ├── new X25519 identity
        └── new ML-KEM identity
`

Old `RootSecret` must not decrypt the new vault.

---

# 21. Normal encrypted backups

This is one of the most important v2 changes.

**Normal backups MUST NOT contain RootSecret.**

Do not re-wrap the live RootSecret under an export passphrase.

Instead:

`                   CSPRNG
                     │
                     ▼
                BackupKey
                 256 bits
                     │
                     ▼
          XChaCha20-Poly1305
                     │
                     ▼
          encrypted vault snapshot


Backup Passphrase
        │
     Argon2id
        │
        ▼
   BackupWrapKEK
        │
        ▼
  wrap BackupKey only
`

A stolen backup that is eventually cracked therefore reveals only that backup's data.

It must not reveal the live vault's root identity.

---

# 22. BackupPayloadV2

The encrypted backup payload may contain:

`BackupPayloadV2 {
    snapshot_version,
    original_vault_id,
    exported_at,
    VaultDocumentV2,
    optional_audit,
    application_metadata
}
`

It must NOT contain:

`RootSecret
VaultDEK
AuditDEK
SyncDEK
Ed25519 private seed
ML-DSA private key/seed
X25519 private seed
ML-KEM private key/seed
recovery secret
KEK
`

---

# 23. BackupEnvelopeV2

Conceptually:

`BackupEnvelopeV2 {
    magic,
    format_version: 2,
    crypto_suite,
    container_id: random 128 bits,

    kdf: Argon2Params,

    key_wrap_nonce: [u8; 24],
    wrapped_backup_key: bytes,

    payload_nonce: [u8; 24],
    encrypted_payload: bytes
}
`

Only information strictly necessary to derive the backup wrapping key should remain outside encrypted payload.

---

# 24. Backup passphrase requirements

Backups must not accept any arbitrary non-empty password.

Apply the same strength requirements as the vault passphrase.

Aegis should strongly recommend generating a backup passphrase.

The backup KDF must not be deliberately downgraded to the old v1 Mobile profile.

Use at least the normal v2 baseline.

---

# 25. Backup restore semantics

Restoring a normal backup must create a NEW cryptographic vault.

Process:

`backup passphrase
       ↓
derive BackupWrapKEK
       ↓
unwrap BackupKey
       ↓
decrypt backup snapshot
       ↓
validate
       ↓
generate NEW RootSecret
       ↓
generate NEW vault identity
       ↓
derive NEW operational keys
       ↓
encrypt imported document
`

By default this means:

`new RootSecret
new sync identity
new sharing identity
new key epoch
`

The imported passwords are the same.

The cryptographic identity is not.

This is deliberate.

---

# 26. Identity-preserving disaster recovery

Normal backups should not preserve the live cryptographic identity.

If Aegis needs full identity disaster recovery, create a separate artifact:

`Aegis Recovery Kit
`

possibly:

`.aegis-recovery
`

This may contain encrypted root or identity recovery material.

It must be clearly distinct from a normal backup.

The Recovery Kit must be protected by a **random high-entropy recovery secret generated by Aegis**, not a casually chosen password.

Display a prominent warning:

`Anyone with this Recovery Kit AND its recovery secret can assume control
of this vault identity.

Store them separately.
`

---

# 27. Recovery secret

Generate at least:

`256 bits
`

of CSPRNG entropy.

Render it in a checksummed human-friendly format.

Do not ask the user to invent it.

Because this secret already contains high entropy, it does not require Argon2 to compensate for weak human selection.

A recovery wrapping key may be derived with HKDF:

`RecoveryKEK =
    HKDF(
        RecoverySecret,
        vault_id,
        "aegis/v2/recovery-kek"
    )
`

and used to wrap `RootSecret`.

---

# 28. Import must be transactional

The v1 destructive-import behavior must not exist in v2.

The following sequence is forbidden:

`delete current vault
       ↓
try decrypt backup
`

Instead:

`read candidate file
       ↓
validate outer structure
       ↓
validate safe parameter bounds
       ↓
derive key
       ↓
authenticate wrapped key
       ↓
decrypt payload
       ↓
authenticate payload
       ↓
deserialize
       ↓
validate all internal objects
       ↓
construct candidate new vault
       ↓
verify candidate can reopen
       ↓
ATOMIC COMMIT
       ↓
remove previous vault
`

Until the final commit, the original vault must remain untouched.

---

# 29. Atomic browser persistence

For IndexedDB, use either:

* a genuine atomic transaction; or
* shadow keys plus a commit marker.

Conceptually:

`aegis/v2/pending/*
`

then:

`validate pending state
swap active pointer
delete old state
`

A browser crash at any point must leave either:

* the old valid vault; or
* the new valid vault.

Never an empty vault.

---

# 30. Malicious import protection

Treat backup files as untrusted attacker input.

Before allocation or deserialization, enforce limits on:

* total file size;
* ciphertext size;
* Argon2 parameters;
* number of entries;
* number of folders;
* attachment size;
* string lengths;
* custom fields;
* nesting depth;
* collection counts.

Fuzz the backup parser.

Malformed backups must fail cleanly without panic.

---

# 31. Post-quantum VaultSync identity

Replace the single Ed25519 owner identity with:

`HybridSyncIdentityV2 {
    ed25519_public_key,
    ml_dsa_65_public_key
}
`

Secret material is derived from RootSecret using separate HKDF labels.

---

# 32. Hybrid sync signatures

Every sync revision must be signed independently by both algorithms.

Conceptually:

`transcript =
    DOMAIN ||
    suite ||
    vault_id ||
    device_id ||
    key_epoch ||
    revision_counter ||
    parent_revision_hash ||
    ciphertext_hash ||
    metadata
`

Then:

`ed_signature  = Ed25519.sign(transcript)
pq_signature  = ML-DSA-65.sign(transcript)
`

Verification:

`Ed25519 VALID
       AND
ML-DSA-65 VALID
       │
       ▼
accept revision
`

Never use:

`Ed25519 OR ML-DSA
`

for v2 verification.

That would permit downgrade attacks.

---

# 33. Sign deterministic transcripts, not arbitrary serialized maps

Create a single function responsible for building sync signing transcripts.

For example:

`build_sync_signing_transcript(...)
`

All implementations must produce byte-for-byte identical output.

Avoid signing whatever CBOR bytes happened to be generated by a serializer.

---

# 34. Sync encryption

Derive a separate:

`aegis/v2/sync-dek
`

Sync payloads remain encrypted with XChaCha20-Poly1305.

A sync object should conceptually contain:

`EncryptedRevisionV2 {
    header,
    nonce,
    ciphertext,
    ed25519_signature,
    ml_dsa_signature
}
`

The authenticated/signed header should contain all security-relevant metadata.

---

# 35. Sync replay and rollback defense

Every device should maintain a monotonic revision counter.

Every signed revision should include:

`vault_id
device_id
key_epoch
counter
parent revision/hash
`

Aegis must reject:

`counter <= previously accepted counter
`

for the same device and epoch unless operating in an explicit recovery workflow.

Use parent hashes or revision hashes to detect history substitution.

Untrusted network storage must not be able to silently roll the vault back without detection when a device retains newer state.

---

# 36. Sync key rotation

When full cryptographic rotation occurs:

`key_epoch++
`

New sync keys are generated.

Where practical, publish a signed transition:

`OldHybridIdentity
       signs
       ↓
NewHybridIdentity + new epoch
`

and:

`NewHybridIdentity
       signs
       ↓
Old identity + transition
`

This creates an auditable continuity record.

Once devices accept the new epoch, revisions signed only by the old identity should be rejected.

---

# 37. Hybrid sharing architecture

For sharing, use:

`X25519 + ML-KEM-768
`

Do not merely replace X25519 with ML-KEM.

Use a hybrid construction.

---

# 38. Recipient sharing identity

Each recipient exposes:

`SharePublicIdentityV2 {
    x25519_public_key,
    ml_kem_768_public_key,
    signing_identity
}
`

The public identity itself must be authenticated by the user's hybrid signing identity.

---

# 39. Creating a share

Generate a random per-share or per-item content key:

`ShareContentKey = CSPRNG(32 bytes)
`

Encrypt the shared secret under:

`XChaCha20-Poly1305(ShareContentKey)
`

Then protect `ShareContentKey` using the recipient's hybrid key establishment.

---

# 40. Hybrid shared secret

Conceptually:

`classical_secret =
    X25519(sender_ephemeral_private, recipient_public)

pq_ciphertext,
pq_secret =
    ML-KEM-768.Encapsulate(recipient_mlkem_public)
`

Reject invalid X25519 results such as the all-zero shared secret.

Combine:

`transcript_hash =
    HASH(
       protocol domain,
       sender identity,
       recipient identity,
       sender ephemeral key,
       recipient X25519 key,
       recipient ML-KEM key,
       ML-KEM ciphertext,
       vault/share identifiers
    )
`

Then:

`HybridSecret =
    HKDF-SHA256(
        IKM = classical_secret || pq_secret,
        salt = transcript_hash,
        info = "aegis/v2/share/hybrid-kek"
    )
`

Use that result to wrap `ShareContentKey`.

---

# 41. Authentication of shares

ML-KEM and X25519 establish secrets.

They do not by themselves prove who sent the share.

Every share offer must also carry an authenticated hybrid signature from the sender:

`Ed25519 + ML-DSA-65
`

over the complete share transcript.

This prevents key-substitution and impersonation attacks.

---

# 42. Harvest-now-decrypt-later protection

The hybrid sharing construction is specifically intended to prevent an attacker from recording encrypted sharing traffic today and later decrypting it after obtaining a cryptographically relevant quantum computer.

The ML-KEM component must be present from the first Aegis v2 sharing release.

---

# 43. Algorithm downgrade protection

Every encrypted or signed object must include:

`format_version
crypto_suite
object_kind
key_epoch
`

inside its authenticated transcript.

If an object says:

`Aegis v2
`

but lacks its required ML-KEM or ML-DSA component, reject it.

Never silently interpret it as v1.

---

# 44. Legacy v1 compatibility

Aegis v2 should retain a **read-only v1 decoder**.

It may:

`unlock v1
import v1
migrate v1
`

It must not create new:

`v1 vaults
v1 exports
v1 sync revisions
`

after v2 becomes the default.

---

# 45. V1 → V2 migration

Migration must be explicit and atomic.

Process:

`unlock Aegis v1
       ↓
authenticate v1 MasterEnvelope
       ↓
decrypt v1 vault
       ↓
validate VaultDocument
       ↓
generate fresh v2 RootSecret
       ↓
generate fresh v2 vault_id if appropriate
       ↓
derive v2 keys
       ↓
create v2 envelope
       ↓
encrypt VaultDocumentV2
       ↓
verify new vault can reopen
       ↓
atomic commit
`

**Do not reuse the v1 MasterSecret as the v2 RootSecret.**

Migration is the ideal time to leave old cryptographic key material behind.

---

# 46. Existing v1 sync identity

If v1 VaultSync has already been deployed, migration may optionally produce a transition record:

`old Ed25519 identity
        ↓ signs
new hybrid identity
`

The v2 identity must thereafter require both:

`Ed25519
AND
ML-DSA-65
`

Do not permit the v1 Ed25519 key to continue authorizing ordinary v2 revisions indefinitely.

---

# 47. Existing v1 backup files

Aegis v2 may import v1 backups.

However:

1. decrypt the entire v1 backup first;
2. authenticate it;
3. validate it;
4. extract only the vault data;
5. discard the recovered v1 MasterSecret after migration;
6. generate a brand-new v2 RootSecret.

Never install the v1 MasterSecret directly into the new v2 vault.

---

# 48. File magic and format identification

Add an unambiguous file marker before serialized backup data.

Conceptually:

`AEGIS
02
BACKUP
`

or another stable binary format.

This permits safe version detection without optimistic deserialization.

Different artifact types should be distinguishable:

`AEGIS_VAULT_V2
AEGIS_BACKUP_V2
AEGIS_RECOVERY_V2
AEGIS_SYNC_V2
`

---

# 49. No secret-bearing metadata

Locked vault storage and network sync must not expose:

* usernames;
* site names;
* URLs;
* folder names;
* notes;
* TOTP labels;
* attachment names

unless explicitly required by a feature.

Prefer encrypting metadata.

Only protocol metadata necessary to locate, synchronize or decrypt objects should remain visible.

---

# 50. Error handling

Avoid giving attackers unnecessary oracle information.

For example, opening a vault may return:

`Unable to unlock vault: incorrect passphrase or corrupted vault.
`

Internally, logs may distinguish structural errors where safe, but logs must never contain secret data.

Cryptographic authentication failure must always fail closed.

---

# 51. Security invariants

The following statements should become documented invariants and preferably automated tests.

### Invariant 1

Possession of a normal backup and its password must not reveal the live vault `RootSecret`.

### Invariant 2

Possession of a normal backup's `BackupKey` must not decrypt the live vault.

### Invariant 3

Changing a master passphrase does not change RootSecret.

### Invariant 4

Full cryptographic rotation does change RootSecret.

### Invariant 5

The old RootSecret cannot decrypt a vault after successful full rotation.

### Invariant 6

Failed import must leave the existing vault unchanged.

### Invariant 7

Malformed backup files must never cause existing vault data to be deleted.

### Invariant 8

A v2 sync revision missing either hybrid signature must be rejected.

### Invariant 9

An object claiming v2 cannot downgrade itself to v1 algorithms.

### Invariant 10

RootSecret must never appear in persistent browser storage.

### Invariant 11

Every cryptographic purpose has a unique HKDF domain label.

### Invariant 12

Every AEAD encryption uses a fresh random nonce.

---

# 52. Required cryptographic tests

Add test vectors and tests for:

## AEAD

* encrypt/decrypt round trip;
* wrong key fails;
* modified ciphertext fails;
* modified nonce fails;
* modified AAD fails;
* wrong object kind fails;
* wrong vault ID fails;
* wrong key epoch fails.

## Argon2

* known parameter vector;
* wrong password fails;
* modified salt fails;
* parameter limits enforced;
* production rejects Test KDF.

## HKDF

Test every v2 label.

Verify:

`VaultDEK != AuditDEK
VaultDEK != SyncDEK
EdSeed != MLDSASeed
X25519Seed != MLKEMSeed
`

---

# 53. Required backup tests

Tests must prove:

`exported backup contains no RootSecret
`

and no derived operational keys.

Test:

* correct backup password succeeds;
* incorrect backup password fails;
* modified wrapped key fails;
* modified payload fails;
* corrupt CBOR fails;
* excessive KDF values rejected;
* excessive lengths rejected.

Most importantly:

`failed replace-import
`

must leave every original persistent vault byte unchanged.

---

# 54. Required PQ tests

For ML-KEM:

* encapsulate/decapsulate round-trip;
* modified KEM ciphertext does not yield accepted share;
* wrong recipient key fails;
* hybrid key differs when either component changes.

For hybrid signatures:

`valid Ed25519 + valid ML-DSA       => ACCEPT
valid Ed25519 + invalid ML-DSA     => REJECT
invalid Ed25519 + valid ML-DSA     => REJECT
missing Ed25519                    => REJECT
missing ML-DSA                     => REJECT
both invalid                       => REJECT
`

---

# 55. Required migration tests

Create v1 fixtures permanently.

Test:

`v1 vault
    ↓ migrate
v2 vault
`

and verify:

* all entries preserved;
* folders preserved;
* TOTP preserved;
* password history preserved;
* new RootSecret differs from v1 MasterSecret;
* v2 vault has new ciphertext;
* v2 sync identities differ;
* v1 RootSecret/MasterSecret cannot unlock v2;
* migration interruption leaves v1 usable.

---

# 56. Parser fuzzing

Fuzz:

`MasterEnvelopeV2 parser
VaultBlobV2 parser
BackupEnvelopeV2 parser
RecoveryKit parser
SyncRevisionV2 parser
ShareEnvelopeV2 parser
v1 compatibility parser
`

No random input should cause:

* panic;
* excessive uncontrolled allocation;
* stack exhaustion;
* partial vault deletion;
* undefined state.

---

# 57. Dependency/security CI

Add security checks to CI.

At minimum:

`cargo test --workspace
cargo audit
cargo deny
`

and equivalent checks for JavaScript dependencies.

Pin lockfiles.

Review cryptographic dependency upgrades carefully.

Do not automatically merge crypto-library major-version changes without review.

---

# 58. PQ implementation requirement

Use maintained implementations conforming to:

`FIPS 203 — ML-KEM
FIPS 204 — ML-DSA
`

Track NIST errata and upstream implementation security notices.

Do not implement Kyber/Dilithium-era draft formats unless required only for compatibility with some external system.

Aegis v2 should use the standardized ML-KEM and ML-DSA definitions.

---

# 59. ML-KEM parameter choice

Use:

`ML-KEM-768
`

as the initial Aegis v2 default.

This provides a strong security/performance balance without the larger keys and ciphertexts of ML-KEM-1024.

The algorithm ID must remain explicit so a future Aegis suite can migrate to another parameter set or algorithm.

---

# 60. ML-DSA parameter choice

Use:

`ML-DSA-65
`

as the initial Aegis v2 signature algorithm.

The hybrid companion is:

`Ed25519
`

Future Aegis versions may introduce ML-DSA-87 or another standardized algorithm through a new suite ID.

Do not silently change the algorithm underneath an existing suite ID.

---

# 61. SLH-DSA

Do not make SLH-DSA mandatory for Aegis v2.

Its larger signatures make it less attractive for normal Aegis sync traffic.

However, maintain crypto agility so it could become part of a future suite if lattice-based signature assumptions materially change.

---

# 62. Logging

Never log:

`passphrases
KEKs
RootSecret
DEKs
private signing keys
KEM private keys
TOTP secrets
passwords
recovery secrets
decrypted backup contents
`

Audit logs should use high-level events only:

`vault unlocked
backup exported
passphrase changed
crypto keys rotated
recovery kit generated
sync identity rotated
backup imported
`

---

# 63. Browser deployment warning

Cryptographically strong vault storage cannot protect a user if malicious JavaScript executes while the vault is unlocked.

Aegis should therefore maintain:

* strict CSP;
* no unnecessary third-party scripts;
* pinned dependencies;
* self-hosted application assets;
* minimal runtime dependencies;
* release integrity processes.

This is distinct from cryptographic file security but must remain part of the threat model.

---

# 64. Recommended implementation structure

Suggested modules:

`common/src/crypto/
    mod.rs
    suite.rs
    secret.rs
    kdf.rs
    hkdf.rs
    aead.rs
    transcript.rs
    classical.rs
    pq.rs
    hybrid.rs

common/src/vault/
    envelope_v1.rs
    envelope_v2.rs
    keys.rs
    session.rs
    rotation.rs
    migration.rs

common/src/backup/
    format_v1.rs
    format_v2.rs
    export.rs
    import.rs
    recovery.rs

common/src/sync/
    v1.rs
    v2.rs
    signature.rs
    replay.rs

common/src/share/
    identity.rs
    hybrid_kem.rs
    envelope.rs
`

Exact paths may differ, but avoid keeping all cryptographic behavior in a single large `crypto.rs` or `vault.rs`.

---

# 65. Secret types

Prefer distinct newtypes instead of generic byte arrays.

For example:

`RootSecret
PassphraseKek
VaultDek
AuditDek
SyncDek
BackupKey
RecoverySecret
HybridShareSecret
`

This prevents accidentally passing:

`VaultDEK
`

where:

`BackupKey
`

was expected.

Make misuse difficult at compile time.

---

# 66. Implementation phases

Claude Code should implement Aegis v2 in controlled stages.

## Phase 1 — Tests around existing v1

Before modifying crypto:

* add regression fixtures;
* add export tests;
* add destructive-import regression test;
* add v1 migration fixtures.

Do not remove v1 code yet.

---

## Phase 2 — v2 envelope and suite infrastructure

Implement:

`CryptoSuiteId
MasterEnvelopeV2
VaultBlobV2
structured AAD/transcripts
explicit Argon2 parameters
`

Add tests.

No PQ sync required yet.

---

## Phase 3 — v2 RootSecret hierarchy

Implement:

`RootSecret
HKDF labels
VaultDEK
AuditDEK
SyncDEK
`

Move unlocked RootSecret to memory-only state.

---

## Phase 4 — secure v2 backup/import

This should be treated as a high-priority security fix.

Implement:

`independent BackupKey
strong backup KDF
BackupEnvelopeV2
transactional import
`

Remove live RootSecret from normal exports.

---

## Phase 5 — v1 → v2 migration

Implement read-only v1 migration.

New installations should create only v2 vaults.

---

## Phase 6 — full key rotation

Add explicit:

`Rotate Vault Cryptographic Keys
`

and key epochs.

---

## Phase 7 — PQ VaultSync

Implement:

`Ed25519 + ML-DSA-65
`

hybrid signatures and replay protection.

---

## Phase 8 — PQ sharing

Implement:

`X25519 + ML-KEM-768
`

hybrid key establishment.

---

## Phase 9 — Recovery Kit

Add identity-preserving disaster recovery as a separate, deliberately dangerous artifact protected by generated high-entropy recovery material.

---

## Phase 10 — security hardening

Add:

* fuzzing;
* dependency audit;
* parser limits;
* downgrade tests;
* documentation;
* threat-model updates.

---

# 67. Highest-priority changes

If implementation must be split across multiple releases, perform these first:

### Critical

1. Fix destructive replace-import.
2. Stop normal exports from containing/re-wrapping the live MasterSecret.
3. Require strong export passphrases.
4. Stop defaulting exports to the weaker Mobile KDF.
5. Introduce v2 versioned cryptographic envelopes.

### High

 6. Generate fresh RootSecret during v1 migration.
 7. Add explicit KDF parameters.
 8. Remove persistent session RootSecret storage.
 9. Add full root-key rotation.
10. Separate vault/audit/sync keys.

### PQ

11. Hybrid ML-DSA-65 + Ed25519 sync signatures.
12. Hybrid ML-KEM-768 + X25519 sharing.
13. Algorithm downgrade protection.
14. PQ migration tests.

---

# 68. Things Claude Code must NOT do

Do not:

* replace XChaCha20 with homemade encryption;
* encrypt the vault directly with the passphrase;
* reuse the backup password as a vault password automatically;
* put RootSecret in normal backups;
* reuse v1 MasterSecret when migrating to v2;
* use one key for vault + audit + sync;
* silently fall back from v2 to v1;
* treat ML-KEM as authentication;
* accept either signature in hybrid mode;
* use ordinary CBOR map serialization as an undefined signature transcript;
* persist RootSecret to IndexedDB;
* delete an existing vault before a replacement is fully authenticated;
* accept unbounded KDF parameters from imported files;
* hand-implement ML-KEM or ML-DSA;
* weaken Argon2 simply for portable exports.

---

# 69. Security properties after v2

With this architecture, stealing:

`local encrypted vault
`

requires attacking the user's passphrase through Argon2id.

Stealing:

`normal .aegis backup
`

allows an offline attack only against that backup and cannot reveal the live RootSecret.

Cracking:

`old normal backup
`

does not expose future vault encryption keys.

Breaking:

`X25519
`

in a quantum future does not reveal shared keys while ML-KEM remains secure.

Breaking:

`Ed25519
`

does not allow forged v2 sync revisions while ML-DSA remains secure.

Changing:

`master passphrase
`

does not require re-encrypting every password.

Performing:

`full cryptographic rotation
`

can invalidate previously compromised root key material.

---

# 70. Final target architecture

`                         USER PASSPHRASE
                               │
                           Argon2id
                               │
                               ▼
                              KEK
                               │
                        authenticated wrap
                               │
                               ▼
                         ┌────────────┐
                         │ RootSecret │
                         │  256 bits  │
                         └─────┬──────┘
                               │
                          HKDF-SHA256
                               │
        ┌──────────────────────┼─────────────────────────┐
        │                      │                         │
        ▼                      ▼                         ▼
    Vault DEK              Sync Keys                 Share Keys
        │                      │                         │
 XChaCha20-P1305       ┌───────┴────────┐       ┌────────┴────────┐
        │              │                │       │                 │
        ▼          Ed25519          ML-DSA-65 X25519         ML-KEM-768
 Encrypted Vault          │                │       │                 │
                          └───────┬────────┘       └────────┬────────┘
                                  │                         │
                                  ▼                         ▼
                         HYBRID SIGNATURE          HYBRID KEY EXCHANGE
                         both must verify          secrets combined HKDF


                  NORMAL ENCRYPTED BACKUP

                       Backup Passphrase
                              │
                           Argon2id
                              │
                              ▼
                         BackupWrapKEK
                              │
                              ▼
                          BackupKey
                         random 256-bit
                              │
                     XChaCha20-Poly1305
                              │
                              ▼
                       Vault Data Snapshot

                 NO RootSecret in normal backup
`

---

# 71. Definition of "Aegis v2 complete"

Aegis v2 cryptographic work should not be considered complete until:

* v2 vault creation works;
* v2 unlock works;
* v2 passphrase changes work;
* normal backup cannot expose RootSecret;
* failed imports cannot damage existing vaults;
* v1 migration works atomically;
* RootSecret is memory-only while unlocked;
* full key rotation works;
* sync requires hybrid signatures;
* sharing uses hybrid PQ key establishment;
* downgrade attacks are tested;
* parser limits exist;
* fuzz tests exist;
* dependency security checks run in CI;
* `CRYPTO.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`, and `VAULTSYNC.md` describe v2 accurately.

---

# 72. Security review checkpoint

After Claude Code completes the above implementation, do **not** immediately assume Aegis is secure merely because the design was implemented.

Perform a second review of the actual resulting code looking specifically for:

* key lifetime;
* key serialization;
* accidental copies of secret material;
* nonce generation;
* KDF parameter handling;
* AAD construction;
* hybrid KEM composition;
* hybrid signature verification;
* downgrade behavior;
* import transactions;
* browser persistence;
* WASM/JavaScript boundaries;
* sync replay;
* dependency choices.

Then run an adversarial/red-team review against the implementation.

The architecture is the security contract.

The code must be verified against it.

---

# Final design rule

Aegis v2 should follow one central principle:

> **A compromise of one historical encrypted artifact should expose the smallest possible amount of information and should never automatically become a permanent compromise of the user's live vault identity.**

That principle governs the separation between:

* passphrase and RootSecret;
* RootSecret and backup keys;
* vault and audit keys;
* classical and post-quantum keys;
* normal backups and Recovery Kits;
* passphrase changes and full cryptographic rotation.

This is the foundation of Aegis v2.
