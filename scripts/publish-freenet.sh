#!/usr/bin/env bash
# Publish Aegis UI (web container) + optionally the vault-delegate to a local Freenet peer.
#
# Prerequisites:
#   - freenet local   (ws://127.0.0.1:7509)
#   - fdev on PATH
#   - ./scripts/package-release.sh already run (or we run it)
#
# Usage:
#   ./scripts/publish-freenet.sh              # package + website publish
#   ./scripts/publish-freenet.sh --skip-build # use existing dist/freenet-release
#   WEBSITE_KEY=aegis-prod ./scripts/publish-freenet.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${WS_API_PORT:-${AEGIS_FREENET_PORT:-7509}}"
ADDR="${AEGIS_FREENET_ADDR:-127.0.0.1}"
WEBSITE_KEY="${WEBSITE_KEY:-aegis}"
RELEASE="${AEGIS_RELEASE_DIR:-$ROOT/dist/freenet-release}"
SKIP_BUILD=0
PUBLISH_DELEGATE=1

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    --no-delegate) PUBLISH_DELEGATE=0 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# //' | sed 's/^#//'
      exit 0
      ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: '$1' not found on PATH" >&2
    exit 1
  }
}

need fdev
need freenet || true

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  bash "$ROOT/scripts/package-release.sh"
fi

if [[ ! -f "$RELEASE/ui/index.html" ]]; then
  echo "error: missing $RELEASE/ui/index.html — run package-release.sh first" >&2
  exit 1
fi

# Probe peer
if ! (echo >/dev/tcp/"$ADDR"/"$PORT") 2>/dev/null; then
  echo "error: Freenet peer not reachable at $ADDR:$PORT"
  echo "  start one with:  freenet local"
  exit 1
fi

echo "==> Website signing key: $WEBSITE_KEY"
if ! fdev website list 2>/dev/null | grep -q "$WEBSITE_KEY"; then
  echo "    creating key (fdev website init $WEBSITE_KEY)…"
  fdev website init "$WEBSITE_KEY"
fi

# The Freenet copy of the UI gets its own CSP (node script hashes, below), so
# it must not share a directory with the GitHub Pages build.
FREENET_UI="$RELEASE/ui-freenet"
rm -rf "$FREENET_UI"
cp -a "$RELEASE/ui" "$FREENET_UI"

publish_site() {
  # Prefer update if already published once; fall back to publish
  local out rc
  set +e
  out=$(fdev -p "$PORT" -a "$ADDR" website update --key "$WEBSITE_KEY" "$FREENET_UI" 2>&1)
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "    update failed (first publish?) — trying publish…" >&2
    echo "$out" | tail -5 >&2
    set +e
    out=$(fdev -p "$PORT" -a "$ADDR" website publish --key "$WEBSITE_KEY" "$FREENET_UI" 2>&1)
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      echo "$out" >&2
      echo "error: website publish failed" >&2
      exit 1
    fi
  fi
  echo "$out"
}

echo "==> Publishing UI web container from $FREENET_UI"
WEB_OUT=$(publish_site)
echo "$WEB_OUT" | tail -20

# Capture Freenet web URL for later (key toml only stores signing keys)
WEB_URL=$(echo "$WEB_OUT" | grep -oE 'http://[^[:space:]]+/v1/contract/web/[^[:space:]]+' | head -1 || true)
if [[ -n "$WEB_URL" ]]; then
  # fdev prints a :7509 URL whatever port it used; point it at the node we published to.
  WEB_URL="http://$ADDR:$PORT/v1/contract/web/$(echo "$WEB_URL" | sed -E 's#.*/v1/contract/web/([^/]+).*#\1#')/"
  echo "$WEB_URL" > "$RELEASE/website-url.txt"
  echo "    saved $RELEASE/website-url.txt"
fi

# Freenet serves the container in a sandboxed iframe and injects inline scripts
# (its WebSocket bridge among them). Aegis's CSP blocks inline scripts, so allow
# exactly the node's scripts by sha256, then republish. Rerun this script after
# upgrading the node: a changed shim means new hashes.
if [[ -n "$WEB_URL" ]]; then
  echo "==> Allowing the node's injected scripts in the CSP (by hash)"
  set +e
  python3 -I "$ROOT/scripts/freenet-csp-hashes.py" "${WEB_URL}?__sandbox=1" "$FREENET_UI/index.html"
  CSP_RC=$?
  set -e
  case $CSP_RC in
    0) echo "    republishing with the updated CSP…"; publish_site | tail -5 ;;
    3) ;;
    *) echo "error: could not read the node's injected scripts" >&2; exit 1 ;;
  esac
else
  echo "warning: no web URL found; the CSP was not adjusted, and Aegis will show 'Bridge blocked'" >&2
fi

# --- Delegate: prefer browser RegisterDelegate (raw WASM hits fdev version errors) ---
if [[ "$PUBLISH_DELEGATE" -eq 1 ]]; then
  echo "==> Vault-delegate"
  echo "    Skip CLI publish (fdev rejects unpackaged WASM: 'unsupported incremental API version')."
  echo "    Register from the UI instead (recommended): open the web URL with &register=1"
fi

# --- VaultSync template contract (empty MVR; real instances use per-owner params) ---
if [[ "$PUBLISH_DELEGATE" -eq 1 ]]; then
  SYNC_WASM="$RELEASE/wasm/aegis_vault_sync.wasm"
  if [[ -f "$SYNC_WASM" ]]; then
    echo "==> Publishing vault-sync contract (empty VaultSyncState)"
    EMPTY_STATE=$(mktemp)
    # ciborium encoding of VaultSyncState { revisions: [] }
    # hex: a1 69 "revisions" 80  (NOT bare empty map a0 — missing field `revisions`)
    printf '\xa1\x69revisions\x80' > "$EMPTY_STATE"
    set +e
    SYNC_OUT=$(fdev -p "$PORT" -a "$ADDR" publish --code "$SYNC_WASM" contract --state "$EMPTY_STATE" 2>&1)
    SYNC_RC=$?
    set -e
    echo "$SYNC_OUT" | tail -25
    rm -f "$EMPTY_STATE"
    if [[ $SYNC_RC -ne 0 ]]; then
      echo "    warning: template VaultSync put failed (non-fatal; per-vault Put comes from Sync later)"
    else
      echo "    note: this is a template only; live vaults need params.owner_verifying_key from SyncWithRemote"
    fi
  fi
fi

if [[ -z "${WEB_URL:-}" && -f "$RELEASE/website-url.txt" ]]; then
  WEB_URL=$(cat "$RELEASE/website-url.txt")
fi

echo
echo "Done."
if [[ -n "${WEB_URL:-}" ]]; then
  echo "  • Web container:  ${WEB_URL}"
  echo "  • First visit:    ${WEB_URL}?register=1"
  echo "  • After register: ${WEB_URL}"
  echo "  • (saved in $RELEASE/website-url.txt — back up ~/.config/freenet/website-keys/${WEBSITE_KEY}.toml)"
else
  echo "  • Open the website URL printed above during publish"
  echo "  • Append ?register=1 once to register the vault-delegate"
fi
echo "  • Alternate static serve:  npx --yes serve '$RELEASE/ui' -l 5173"
echo "      then http://localhost:5173/?mode=freenet&register=1"
echo "  • See docs/PUBLISH.md"
