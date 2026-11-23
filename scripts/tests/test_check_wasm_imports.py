import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "check-wasm-imports.py")
_spec = importlib.util.spec_from_file_location("check_wasm_imports", SCRIPT)
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)

HEADER = b"\0asm\x01\0\0\0"


def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def name(s):
    raw = s.encode() if isinstance(s, str) else s
    return leb(len(raw)) + raw


def section(sec_id, body):
    return bytes([sec_id]) + leb(len(body)) + body


def func_import(mod, field):
    return name(mod) + name(field) + b"\x00" + leb(0)


def table_import(mod, field):
    return name(mod) + name(field) + b"\x01" + b"\x70" + b"\x01" + leb(1) + leb(2)


def memory_import(mod, field):
    return name(mod) + name(field) + b"\x02" + b"\x00" + leb(1)


def global_import(mod, field):
    return name(mod) + name(field) + b"\x03" + b"\x7f" + b"\x00"


def module(*entries):
    body = leb(len(entries)) + b"".join(entries)
    return HEADER + section(2, body)


class ListImportsTest(unittest.TestCase):
    def test_no_imports(self):
        self.assertEqual(checker.list_imports(HEADER), [])

    def test_func_import(self):
        self.assertEqual(
            checker.list_imports(module(func_import("freenet_rand", "x"))),
            [("freenet_rand", "x", 0)],
        )

    def test_mixed_descriptors_then_func(self):
        data = module(
            table_import("a", "t"),
            memory_import("b", "m"),
            global_import("c", "g"),
            func_import("d", "f"),
        )
        self.assertEqual(
            checker.list_imports(data),
            [("a", "t", 1), ("b", "m", 2), ("c", "g", 3), ("d", "f", 0)],
        )

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            checker.list_imports(b"\x00bad\x01\0\0\0")

    def test_bad_version(self):
        with self.assertRaises(ValueError):
            checker.list_imports(b"\0asm\x02\0\0\0")

    def test_short(self):
        with self.assertRaises(ValueError):
            checker.list_imports(b"")
        with self.assertRaises(ValueError):
            checker.list_imports(b"\0asm")

    def test_truncated_section(self):
        data = module(func_import("a", "b"))
        with self.assertRaises(ValueError):
            checker.list_imports(data[:-2])

    def test_unknown_kind(self):
        bad = name("a") + name("b") + b"\x09"
        with self.assertRaises(ValueError):
            checker.list_imports(module(bad))

    def test_non_utf8_name(self):
        bad = name(b"\xff\xfe") + name("b") + b"\x00" + leb(0)
        with self.assertRaises(ValueError):
            checker.list_imports(module(bad))


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, fname, data):
        path = os.path.join(self.tmp.name, fname)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-I", SCRIPT, *args], capture_output=True, text=True
        )

    def test_empty_module_ok(self):
        r = self.run_cli(self.write("a.wasm", HEADER))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_freenet_import_ok_and_listed(self):
        p = self.write("a.wasm", module(func_import("freenet_rand", "x")))
        r = self.run_cli(p)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("freenet_rand::x", r.stdout)

    def test_wbindgen_import_fails(self):
        p = self.write(
            "a.wasm", module(func_import("__wbindgen_placeholder__", "__wbindgen_describe"))
        )
        r = self.run_cli(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("__wbindgen_placeholder__", r.stderr)

    def test_env_import_fails(self):
        r = self.run_cli(self.write("a.wasm", module(func_import("env", "foo"))))
        self.assertEqual(r.returncode, 1)

    def test_custom_prefix(self):
        p = self.write("a.wasm", module(func_import("env_a", "b")))
        self.assertEqual(self.run_cli("--prefix", "env_", p).returncode, 0)

    def test_wbindgen_in_custom_section_fails(self):
        custom = section(0, name("note") + b"__wbindgen")
        p = self.write("a.wasm", HEADER + custom)
        r = self.run_cli(p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("__wbindgen", r.stderr)

    def test_invalid_inputs_exit_2(self):
        self.assertEqual(self.run_cli(self.write("m.wasm", b"\x00bad\x01\0\0\0")).returncode, 2)
        self.assertEqual(self.run_cli(self.write("v.wasm", b"\0asm\x02\0\0\0")).returncode, 2)
        trunc = module(func_import("a", "b"))[:-2]
        self.assertEqual(self.run_cli(self.write("t.wasm", trunc)).returncode, 2)
        self.assertEqual(self.run_cli(self.write("e.wasm", b"")).returncode, 2)

    def test_no_args_exit_2(self):
        self.assertEqual(self.run_cli().returncode, 2)

    def test_missing_file_exit_2(self):
        r = self.run_cli(os.path.join(self.tmp.name, "nope.wasm"))
        self.assertEqual(r.returncode, 2)

    def test_two_files_one_bad(self):
        good = self.write("good.wasm", module(func_import("freenet_rand", "x")))
        bad = self.write("bad.wasm", module(func_import("env", "foo")))
        r = self.run_cli(good, bad)
        self.assertEqual(r.returncode, 1)
        self.assertIn("bad.wasm", r.stderr)
        self.assertNotIn("good.wasm", r.stderr)


    def test_all_violations_reported_across_files(self):
        b1 = self.write("bad1.wasm", module(func_import("env", "one"), func_import("env", "two")))
        b2 = self.write("bad2.wasm", module(func_import("js", "three")))
        r = self.run_cli(b1, b2)
        self.assertEqual(r.returncode, 1)
        for needle in ("bad1.wasm", "bad2.wasm", "env::one", "env::two", "js::three"):
            self.assertIn(needle, r.stderr)

    def test_non_utf8_name_exit_2(self):
        bad = name(b"\xff\xfe") + name("b") + b"\x00" + leb(0)
        self.assertEqual(self.run_cli(self.write("u.wasm", module(bad))).returncode, 2)

    def test_short_file_exit_2(self):
        self.assertEqual(self.run_cli(self.write("s.wasm", b"\0asm\x01")).returncode, 2)

    def test_zero_imports_section_ok(self):
        self.assertEqual(self.run_cli(self.write("z.wasm", module())).returncode, 0)

    def test_following_func_checked_after_other_descriptors(self):
        data = module(table_import("freenet_a", "t"), memory_import("freenet_b", "m"),
                      global_import("freenet_c", "g"), func_import("env", "bad"))
        r = self.run_cli(self.write("d.wasm", data))
        self.assertEqual(r.returncode, 1)
        self.assertIn("env::bad", r.stderr)


class RepoConfigTest(unittest.TestCase):
    ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

    def read(self, rel):
        with open(os.path.join(self.ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_cargo_config_defaults_to_custom_backend(self):  # criterion 9
        cfg = self.read(".cargo/config.toml")
        code = "\n".join(
            line for line in cfg.splitlines() if not line.strip().startswith("#")
        )
        self.assertNotIn("wasm_js", code)
        self.assertIn('getrandom_backend=\\"custom\\"', cfg)

    def test_ci_workflow_has_import_check(self):  # criterion 13
        ci = self.read(".github/workflows/ci.yml")
        self.assertIn("scripts/check-wasm-imports.py", ci)
        self.assertIn("unittest discover", ci)
        self.assertIn("wasm_js", ci)

    def test_makefile_tasks(self):  # criterion 14
        mk = self.read("Makefile.toml")
        self.assertIn("[tasks.build-browser]", mk)
        self.assertIn("[tasks.check-wasm-imports]", mk)

    def test_changelog_unreleased_first(self):  # criterion 17
        heads = [l for l in self.read("CHANGELOG.md").splitlines() if l.startswith("## ")]
        self.assertEqual(heads[0], "## [Unreleased]")


if __name__ == "__main__":
    unittest.main()
