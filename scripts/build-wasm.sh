#!/usr/bin/env bash
# Build Freenet WASM artifacts and stage them for the UI (public/).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Building vault-sync contract…"
cargo build --release --target wasm32-unknown-unknown \
  -p aegis-vault-sync --features freenet-main-contract

echo "==> Building vault-delegate…"
cargo build --release --target wasm32-unknown-unknown \
  -p aegis-vault-delegate --features freenet-main-delegate

OUT="$ROOT/target/wasm32-unknown-unknown/release"

# Freenet WASM may import only freenet_* host modules (no wasm-bindgen / env).
# Check before building the browser crate and before staging anything.
echo "==> Checking Freenet WASM imports…"
python3 "$ROOT/scripts/check-wasm-imports.py" \
  "$OUT/aegis_vault_sync.wasm" \
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
cp -f "$OUT/aegis_vault_sync.wasm" "$UI_PUBLIC/aegis_vault_sync.wasm"

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

# Delegate history manifest (D20): older delegates the UI may find a vault in.
cp -f "$ROOT/delegates/vault-delegate/history.json" \
  "$UI_PUBLIC/aegis_vault_delegate.history.json"

echo "==> Staged:"
ls -la "$UI_PUBLIC"/*.wasm "$UI_PUBLIC"/*.hash.json "$UI_PUBLIC"/*.history.json 2>/dev/null || true
ls -la "$UI_PUBLIC/browser-wasm" 2>/dev/null || true
echo "Done."
echo "  Browser (default):  cd ui && npm run dev   →  http://localhost:5173/"
echo "  Freenet:            freenet local + ?mode=freenet&register=1"
