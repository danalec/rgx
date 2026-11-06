#!/usr/bin/env python3
"""Give every internal path dependency the `version` requirement that
`cargo publish` demands.

    python scripts/add-publish-versions.py

A path dependency without a version is publishable as a path and not as a
crate: cargo refuses the whole workspace with "all dependencies must have a
`version` requirement specified when publishing". The version has to be the
one the dependency carries, so the two are read from the manifests rather
than typed here.
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A dependency line: name = { path = "...", ... } -- the tail may be empty.
DEP = re.compile(
    r'^(?P<indent>\s*)(?P<name>[A-Za-z0-9_-]+) = \{ path = "(?P<path>[^"]+)"(?P<rest>[^}]*)\}\s*$'
)


def versions() -> dict[str, str]:
    """The version of every package in the workspace, by package name."""
    out: dict[str, str] = {}
    for manifest in [os.path.join(ROOT, "Cargo.toml")] + [
        os.path.join(ROOT, "crates", d, "Cargo.toml")
        for d in sorted(os.listdir(os.path.join(ROOT, "crates")))
    ]:
        if not os.path.exists(manifest):
            continue
        text = open(manifest, encoding="utf-8").read()
        name = re.search(r'^\s*name = "([^"]+)"', text, re.M)
        version = re.search(r'^\s*version = "([^"]+)"', text, re.M)
        if name and version:
            out[name.group(1)] = version.group(1)
    return out


def main() -> int:
    known = versions()
    changed = 0
    for manifest in [os.path.join(ROOT, "Cargo.toml")] + [
        os.path.join(ROOT, "crates", d, "Cargo.toml")
        for d in sorted(os.listdir(os.path.join(ROOT, "crates")))
    ]:
        if not os.path.exists(manifest):
            continue
        with open(manifest, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-8")
        lines = text.splitlines(keepends=True)
        out: list[str] = []
        touched = False
        for line in lines:
            m = DEP.match(line.rstrip("\r\n"))
            if m:
                name = m.group("name")
                if name in known:
                    want = known[name]
                    rest = m.group("rest")
                    have = re.search(r'version = "([^"]+)"', rest)
                    if have and have.group(1) == want:
                        # Already the version the dependency carries.
                        out.append(line)
                        continue
                    newline = "\r\n" if line.endswith("\r\n") else "\n"
                    if have:
                        rest = rest.replace(have.group(0), f'version = "{want}"')
                    else:
                        rest = f', version = "{want}"' + rest
                    line = (
                        f'{m.group("indent")}{name} = {{ path = "{m.group("path")}"'
                        f'{rest} }}{newline}'
                    )
                    touched = True
                    continue
            out.append(line)
        if touched:
            with open(manifest, "wb") as fh:
                fh.write("".join(out).encode("utf-8"))
            rel = os.path.relpath(manifest, ROOT)
            print(f"version added: {rel}")
            changed += 1
    print(f"\n{changed} manifests carry the version requirement now")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
