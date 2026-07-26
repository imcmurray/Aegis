#!/usr/bin/env bash
# Build a River-style release bundle: WASM + static UI for Freenet packaging.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${AEGIS_RELEASE_DIR:-$ROOT/dist/freenet-release}"
rm -rf "$OUT"
mkdir -p "$OUT"/{wasm,ui,docs}

echo "==> 1/4 WASM (browser + Freenet delegate/contract)"
bash "$ROOT/scripts/build-wasm.sh"

if [[ ! -f "$ROOT/ui/public/browser-wasm/aegis_browser_wasm.js" ]]; then
  echo "error: browser-wasm missing after build-wasm.sh (install wasm-bindgen-cli)" >&2
  exit 1
fi

echo "==> 2/4 UI production build"
(cd "$ROOT/ui" && npm ci 2>/dev/null || npm install)
(cd "$ROOT/ui" && npm run build)

echo "==> 3/4 Stage artifacts"
cp -f "$ROOT/ui/public/aegis_vault_delegate.wasm" "$OUT/wasm/"
cp -f "$ROOT/ui/public/aegis_vault_sync.wasm" "$OUT/wasm/"
cp -f "$ROOT/ui/public/aegis_vault_delegate.hash.json" "$OUT/wasm/"
cargo run -q -p aegis-wasm-hash -- \
  "$OUT/wasm/aegis_vault_sync.wasm" \
  > "$OUT/wasm/aegis_vault_sync.hash.json"

# Vite already copies public/ into dist/; ensure browser-wasm + freenet wasm present
cp -a "$ROOT/ui/dist/." "$OUT/ui/"
cp -f "$OUT/wasm/"* "$OUT/ui/" 2>/dev/null || true
mkdir -p "$OUT/ui/browser-wasm"
cp -a "$ROOT/ui/public/browser-wasm/." "$OUT/ui/browser-wasm/"
touch "$OUT/ui/.nojekyll"

cp -f "$ROOT/docs/ACCESS.md" "$OUT/docs/" 2>/dev/null || true
cp -f "$ROOT/docs/MODES.md" "$OUT/docs/" 2>/dev/null || true
cp -f "$ROOT/docs/FREENET.md" "$OUT/docs/"
cp -f "$ROOT/docs/PUBLISH.md" "$OUT/docs/" 2>/dev/null || true
cp -f "$ROOT/docs/ACCESS.md" "$OUT/ui/ACCESS.md" 2>/dev/null || true
cp -f "$ROOT/README.md" "$OUT/"

cat > "$OUT/MANIFEST.json" <<EOF
{
  "app": "Aegis",
  "version": "0.1.0",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "default_mode": "browser",
  "components": {
    "ui": "ui/",
    "browser_wasm": "ui/browser-wasm/",
    "vault_delegate_wasm": "wasm/aegis_vault_delegate.wasm",
    "vault_sync_wasm": "wasm/aegis_vault_sync.wasm"
  },
  "access": [
    "Serve ui/ on any static host (GitHub Pages) — mode=browser by default",
    "Optional Freenet: freenet local + ?mode=freenet&register=1",
    "See docs/ACCESS.md"
  ]
}
EOF

echo "==> 4/4 Bundle summary"
find "$OUT" -type f | sort | sed "s|^|  |"
test -f "$OUT/ui/browser-wasm/aegis_browser_wasm_bg.wasm" || {
  echo "error: browser wasm not in release UI" >&2
  exit 1
}
echo
echo "Release staged at: $OUT"
echo "  Public (no Freenet):  npx --yes serve '$OUT/ui' -l 4173"
echo "  GitHub Pages:         ./scripts/deploy-github-pages.sh  (or push → Actions)"
echo "  Freenet container:    ./scripts/publish-freenet.sh"
