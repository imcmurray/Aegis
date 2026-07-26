#!/usr/bin/env bash
# Build the public static site and print how to put it on GitHub Pages.
# Preferred path: push to main and let .github/workflows/pages.yml deploy.
#
# Manual alternative (needs git remote + gh or manual upload):
#   ./scripts/deploy-github-pages.sh
#   # then: Settings → Pages → Deploy from branch gh-pages / or use Actions
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

bash "$ROOT/scripts/package-release.sh"

UI="$ROOT/dist/freenet-release/ui"
touch "$UI/.nojekyll"
cp -f "$ROOT/docs/ACCESS.md" "$UI/ACCESS.md" 2>/dev/null || true

echo
echo "═══════════════════════════════════════════════════════════"
echo "  Public site ready: $UI"
echo "═══════════════════════════════════════════════════════════"
echo
echo "Option A — GitHub Actions (recommended)"
echo "  1. Create a GitHub repo and push this project (main branch)"
echo "  2. Settings → Pages → Source: GitHub Actions"
echo "  3. Push triggers .github/workflows/pages.yml"
echo "  4. Site: https://<you>.github.io/<repo>/"
echo
echo "Option B — Manual gh-pages branch"
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "  git checkout --orphan gh-pages"
  echo "  # copy $UI contents, commit, push -u origin gh-pages"
  echo "  # Settings → Pages → Deploy from branch gh-pages / (root)"
else
  echo "  (init git first, then create orphan gh-pages with contents of dist/freenet-release/ui)"
fi
echo
echo "Option C — Any static host"
echo "  Upload the contents of: $UI"
echo "  Open the hosted URL (mode=browser by default)"
echo
echo "Local smoke test:"
echo "  npx --yes serve '$UI' -l 4173"
echo "  open http://127.0.0.1:4173/"
echo
