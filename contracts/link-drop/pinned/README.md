# Pinned link-drop contract

`aegis_link_drop.wasm` here is the **released** link-drop contract (D21), code
hash `7NMwr14MSTivJ4e968vCXed5BZA2iKpqnXheaMoy36d1`, first shipped in 2.0.0-rc.3.

Both devices derive the link contract's address from the link code AND this
code hash. If the two computers ran builds with different link-drop WASM, the
new device would look at a different address and report "link not found".
The contract links shared `aegis-common` code, so unrelated changes can alter
the compiled WASM; `scripts/build-wasm.sh` therefore stages THIS file and warns
when a fresh build differs. Same rule as `contracts/vault-sync/pinned/`.
