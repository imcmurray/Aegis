#!/usr/bin/env bash
# Build Freenet WASM artifacts and stage them for the UI (public/).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Building vault-sync contract…"
cargo build --release --target wasm32-unknown-unknown \
  -p aegis-vault-sync --features freenet-main-contract

echo "==> Building link-drop contract…"
cargo build --release --target wasm32-unknown-unknown \
  -p aegis-link-drop --features freenet-main-contract

echo "==> Building vault-delegate…"
cargo build --release --target wasm32-unknown-unknown \
  -p aegis-vault-delegate --features freenet-main-delegate

OUT="$ROOT/target/wasm32-unknown-unknown/release"

# Freenet WASM may import only freenet_* host modules (no wasm-bindgen / env).
# Check before building the browser crate and before staging anything.
echo "==> Checking Freenet WASM imports…"
python3 "$ROOT/scripts/check-wasm-imports.py" \
  "$OUT/aegis_vault_sync.wasm" \
  "$OUT/aegis_link_drop.wasm" \
  "$OUT/aegis_vault_delegate.wasm"

echo "==> Building browser vault WASM (no Freenet)…"
# RUSTFLAGS is scoped to this one command: it replaces .cargo/config.toml's
# Freenet `custom` getrandom backend with the browser `wasm_js` one.
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  cargo build --release --target wasm32-unknown-unknown \
  -p aegis-browser-wasm

UI_PUBLIC="$ROOT/ui/public"
mkdir -p "$UI_PUBLIC" "$UI_PUBLIC/browser-wasm"

cp -f "$OUT/aegis_vault_delegate.wasm" "$UI_PUBLIC/aegis_vault_delegate.wasm"
# The VaultSync contract is PINNED (contracts/vault-sync/pinned/README.md): its
# code hash is part of every user's sync-contract address, so stage the released
# binary, never an incidental rebuild.
PINNED_SYNC="$ROOT/contracts/vault-sync/pinned/aegis_vault_sync.wasm"
if ! cmp -s "$OUT/aegis_vault_sync.wasm" "$PINNED_SYNC"; then
  echo "warning: the fresh vault-sync build differs from the pinned release contract." >&2
  echo "  Staging the PINNED contract so existing sync contracts keep their address." >&2
  echo "  To ship a new sync contract on purpose, see contracts/vault-sync/pinned/README.md." >&2
fi
cp -f "$PINNED_SYNC" "$UI_PUBLIC/aegis_vault_sync.wasm"
cp -f "$OUT/aegis_link_drop.wasm" "$UI_PUBLIC/aegis_link_drop.wasm"

if command -v wasm-bindgen >/dev/null 2>&1; then
  wasm-bindgen --target web --out-dir "$UI_PUBLIC/browser-wasm" \
    "$OUT/aegis_browser_wasm.wasm"
else
  echo "warning: wasm-bindgen not on PATH — browser mode will fail until installed" >&2
  echo "  cargo install wasm-bindgen-cli --version 0.2.126 --locked" >&2
fi

# Write blake3 + base58 of WASM for Freenet registration / VaultSync instance ids.
cargo run -q -p aegis-wasm-hash -- \
  "$UI_PUBLIC/aegis_vault_delegate.wasm" \
  > "$UI_PUBLIC/aegis_vault_delegate.hash.json"
cargo run -q -p aegis-wasm-hash -- \
  "$UI_PUBLIC/aegis_vault_sync.wasm" \
  > "$UI_PUBLIC/aegis_vault_sync.hash.json"
cargo run -q -p aegis-wasm-hash -- \
  "$UI_PUBLIC/aegis_link_drop.wasm" \
  > "$UI_PUBLIC/aegis_link_drop.hash.json"

# Delegate history manifest (D20): older delegates the UI may find a vault in.
cp -f "$ROOT/delegates/vault-delegate/history.json" \
  "$UI_PUBLIC/aegis_vault_delegate.history.json"

echo "==> Staged:"
ls -la "$UI_PUBLIC"/*.wasm "$UI_PUBLIC"/*.hash.json "$UI_PUBLIC"/*.history.json 2>/dev/null || true
ls -la "$UI_PUBLIC/browser-wasm" 2>/dev/null || true
echo "Done."
echo "  Browser (default):  cd ui && npm run dev   →  http://localhost:5173/"
echo "  Freenet:            freenet local + ?mode=freenet&register=1"
