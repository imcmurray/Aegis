# Pinned vault-sync contract

`aegis_vault_sync.wasm` here is the **released** VaultSync contract. A Freenet
contract's address is `blake3(code_hash ‖ params)`, so every user's sync
contract is tied to this exact binary (code hash
`7cFetG8bR6BLUcXxKDnuAVLkrTMvAWwLV7duz7vzRth`, first shipped in ce99f94).

The contract links shared `aegis-common` code, so unrelated common changes
(new modules, enum variants, dependency bumps) can change the compiled WASM and
silently move every vault to a new, empty sync contract. To prevent that,
`scripts/build-wasm.sh` stages THIS file, not the fresh build, and warns when
the fresh build differs.

Changing the sync contract is a deliberate release step: it needs a migration
plan for existing contracts (as delegates have D20), then replace this file and
the hash above in one commit.
