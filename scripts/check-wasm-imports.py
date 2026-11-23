#!/usr/bin/env python3
"""Fail if a Freenet contract/delegate WASM imports non-`freenet_*` modules.

Usage: check-wasm-imports.py [--prefix PREFIX] WASM_FILE [WASM_FILE ...]

Exit 0: all import modules start with PREFIX and no file contains `__wbindgen`.
Exit 1: violation(s). Exit 2: usage error, unreadable file, or invalid WASM.
"""
import argparse
import sys

DEFAULT_PREFIX = "freenet_"
WBINDGEN = b"__wbindgen"


class _Reader:
    def __init__(self, data, pos=0, end=None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    def byte(self):
        if self.pos >= self.end:
            raise ValueError("truncated: unexpected end of data")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def leb(self):
        result = 0
        shift = 0
        while True:
            b = self.byte()
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                break
            shift += 7
            if shift >= 35:
                raise ValueError("malformed LEB128 (too long for u32)")
        if result > 0xFFFFFFFF:
            raise ValueError("malformed LEB128 (exceeds u32)")
        return result

    def name(self):
        n = self.leb()
        if self.pos + n > self.end:
            raise ValueError("truncated: name extends past end of section")
        raw = self.data[self.pos:self.pos + n]
        self.pos += n
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("non-UTF-8 name: %s" % e)

    def limits(self):
        flags = self.byte()
        self.leb()
        if flags & 1:
            self.leb()


def list_imports(data):
    """Return [(module, field, kind), ...] in file order; ValueError if malformed."""
    if len(data) < 8:
        raise ValueError("file shorter than 8 bytes")
    if data[:4] != b"\0asm":
        raise ValueError("bad magic")
    if data[4:8] != b"\x01\0\0\0":
        raise ValueError("unsupported WASM version")
    imports = []
    r = _Reader(data, 8)
    while r.pos < len(data):
        sec_id = r.byte()
        size = r.leb()
        end = r.pos + size
        if end > len(data):
            raise ValueError("truncated section %d" % sec_id)
        if sec_id == 2:
            s = _Reader(data, r.pos, end)
            count = s.leb()
            for _ in range(count):
                module = s.name()
                field = s.name()
                kind = s.byte()
                if kind == 0:
                    s.leb()
                elif kind == 1:
                    s.byte()
                    s.limits()
                elif kind == 2:
                    s.limits()
                elif kind == 3:
                    s.byte()
                    s.byte()
                elif kind == 4:
                    s.byte()
                    s.leb()
                else:
                    raise ValueError("unknown import kind %d" % kind)
                imports.append((module, field, kind))
            if s.pos != end:
                raise ValueError("import section has trailing bytes")
        r.pos = end
    return imports


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--prefix", default=DEFAULT_PREFIX)
    ap.add_argument("files", nargs="*", metavar="WASM_FILE")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if not args.files:
        print("error: no WASM files given", file=sys.stderr)
        return 2

    failed = False
    for path in args.files:
        try:
            with open(path, "rb") as f:
                data = f.read()
            imports = list_imports(data)
        except (OSError, ValueError) as e:
            print("error: %s: %s" % (path, e), file=sys.stderr)
            return 2
        print(path)
        for module, field, _kind in imports:
            print("  %s::%s" % (module, field))
        for module, field, _kind in imports:
            if not module.startswith(args.prefix):
                print("%s: %s::%s" % (path, module, field), file=sys.stderr)
                failed = True
        if WBINDGEN in data:
            print("%s: contains `__wbindgen` bytes" % path, file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
