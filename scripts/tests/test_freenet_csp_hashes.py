"""Freenet CSP hash stamping covers every HTML page, not only the vault."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "freenet_csp_hashes", ROOT / "freenet-csp-hashes.py"
)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

CSP = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'"
)
HASH = "'sha256-abc'"


def page(title: str) -> str:
    return (
        "<!DOCTYPE html><html><head>"
        '<meta charset="UTF-8" />'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}" />'
        f"<title>{title}</title></head><body></body></html>\n"
    )


class ApplyHashes(unittest.TestCase):
    def test_stamps_each_page_and_leaves_a_current_page_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "index.html"
            welcome = Path(tmp) / "welcome.html"
            vault.write_text(page("vault"), encoding="utf-8")
            welcome.write_text(page("welcome"), encoding="utf-8")

            self.assertEqual(MOD.apply_hashes(str(vault), [HASH]), 0)
            self.assertEqual(MOD.apply_hashes(str(welcome), [HASH]), 0)
            self.assertIn(HASH, vault.read_text(encoding="utf-8"))
            self.assertIn(HASH, welcome.read_text(encoding="utf-8"))
            self.assertEqual(MOD.apply_hashes(str(welcome), [HASH]), 3)

    def test_refuses_a_page_with_no_csp(self):
        with tempfile.TemporaryDirectory() as tmp:
            bare = Path(tmp) / "bare.html"
            bare.write_text("<html><body></body></html>", encoding="utf-8")
            self.assertEqual(MOD.apply_hashes(str(bare), [HASH]), 1)


if __name__ == "__main__":
    unittest.main()
