#!/usr/bin/env python3
"""Allow a Freenet node's injected inline scripts in Aegis's CSP, by hash.

Freenet 0.2.16x serves a web container in a sandboxed iframe and injects inline
<script> blocks into the page (a WebSocket shim that relays through the parent
shell, plus clipboard/title helpers). Aegis's production CSP is
`script-src 'self' 'wasm-unsafe-eval'`, which blocks them. Without the shim the
app cannot reach the node, so it reports "Peer offline".

Instead of opening 'unsafe-inline', this reads the exact scripts the node
injects and adds their sha256 hashes to script-src in every Freenet HTML page
(the vault and welcome.html). Aegis ships no inline scripts of its own, so
every inline script in a served page belongs to the node. The hash list is the
node's, not the page's: a new page still needs those same hashes.

Usage:
  freenet-csp-hashes.py <sandbox-url> <page.html> [page.html ...]
      Fetch <sandbox-url> (the container URL with ?__sandbox=1), then rewrite
      each page's CSP meta so script-src lists exactly those hashes.
      Exit 0 = at least one file changed, 3 = already up to date, 1 = error.
"""
import base64
import hashlib
import re
import sys
import urllib.request

INLINE_SCRIPT = re.compile(r"<script>(.*?)</script>", re.S)
META_CSP = re.compile(r'(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(")')


def node_script_hashes(url: str) -> list[str]:
    if not url.startswith(("http://127.0.0.1:", "http://localhost:", "http://[::1]:")):
        raise SystemExit(f"refusing non-loopback URL: {url}")
    with urllib.request.urlopen(url, timeout=15) as r:
        html = r.read().decode("utf-8")
    hashes = []
    for m in INLINE_SCRIPT.finditer(html):
        digest = hashlib.sha256(m.group(1).encode("utf-8")).digest()
        h = "'sha256-" + base64.b64encode(digest).decode() + "'"
        if h not in hashes:
            hashes.append(h)
    return hashes


def patch_csp(csp: str, hashes: list[str]) -> str:
    out = []
    found = False
    for d in [d.strip() for d in csp.split(";") if d.strip()]:
        parts = d.split()
        if parts[0] == "script-src":
            found = True
            kept = [p for p in parts[1:] if not p.startswith("'sha256-")]
            d = " ".join(["script-src", *kept, *hashes])
        out.append(d)
    if not found:
        raise SystemExit("index.html CSP has no script-src directive")
    return "; ".join(out)


def apply_hashes(path: str, hashes: list[str]) -> int:
    """Rewrite one page. 0 = changed, 3 = already current, 1 = no CSP meta."""
    with open(path, encoding="utf-8") as fh:
        html = fh.read()
    m = META_CSP.search(html)
    if not m:
        print(f"{path}: no CSP meta tag", file=sys.stderr)
        return 1
    new_csp = patch_csp(m.group(2), hashes)
    if new_csp == m.group(2):
        print(f"{path}: CSP already allows the node's {len(hashes)} injected scripts")
        return 3
    html = html[: m.start(2)] + new_csp + html[m.end(2) :]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"{path}: CSP script-src now allows the node's {len(hashes)} injected scripts")
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 1
    url, paths = sys.argv[1], sys.argv[2:]
    hashes = node_script_hashes(url)
    if not hashes:
        print("node injected no inline scripts; CSP left unchanged")
        return 3
    changed = False
    for path in paths:
        rc = apply_hashes(path, hashes)
        if rc == 1:
            return 1
        if rc == 0:
            changed = True
    if changed:
        for h in hashes:
            print(f"  {h}")
        return 0
    return 3


if __name__ == "__main__":
    sys.exit(main())
