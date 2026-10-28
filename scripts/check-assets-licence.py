#!/usr/bin/env python3
"""Audit the licence documents inside every release asset in .dist/.

Every asset has to carry the tree's Apache-2.0 text, the corrected COPYING
and the NOTICE -- and none of them may carry the LICENSE-MIT the tree
shipped before the licence was one.

    python scripts/check-assets-licence.py [dist-dir]

Exit code 0 when every asset passes, 1 otherwise. The names are the ones
the packages use: the doc set is the same everywhere, only the path inside
the container differs.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
import zipfile

# The documents every asset has to carry, and the ones it must not.
REQUIRED = ("COPYING", "LICENSE-APACHE", "NOTICE", "README.md")
FORBIDDEN = ("LICENSE-MIT",)

# What the corrected COPYING says, and what the one it replaces said. The
# second check is what tells the two apart: the asset carrying the old
# COPYING has four exceptions in it, the new one has none.
COPYING_MARKERS = ("Apache License, Version 2.0", "under nothing else")
COPYING_REPLACED = ("Four files are the exception",)
NOTICE_MARKERS = ("under no other license", "learned from")


def docs_from_zip(path: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            base = os.path.basename(name)
            if base in REQUIRED or base in FORBIDDEN:
                out[base] = z.read(name)
    return out


def docs_from_tar(path: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with tarfile.open(path) as t:
        for m in t.getmembers():
            base = os.path.basename(m.name)
            if base in REQUIRED or base in FORBIDDEN:
                f = t.extractfile(m)
                if f is not None:
                    out[base] = f.read()
    return out


def docs_from_deb(path: str) -> dict[str, bytes]:
    """A .deb is an ar archive whose data member is a tar."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    off = 8
    data = b""
    while off + 60 <= len(blob):
        header = blob[off : off + 60]
        name = header[0:16].decode("ascii", "replace").strip()
        size = int(header[48:58].decode("ascii", "replace").strip())
        body = blob[off + 60 : off + 60 + size]
        if name.startswith("data.tar"):
            data = body
            break
        off += 60 + size + (size % 2)
    if not data:
        raise ValueError("no data member")
    mode = "r:*"
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as t:
        out: dict[str, bytes] = {}
        for m in t.getmembers():
            base = os.path.basename(m.name)
            if base in REQUIRED or base in FORBIDDEN:
                f = t.extractfile(m)
                if f is not None:
                    out[base] = f.read()
    return out


def docs_from_bsdtar(path: str) -> dict[str, bytes]:
    """The rpm and the pacman package: libarchive reads both."""
    out: dict[str, bytes] = {}
    listing = subprocess.run(
        ["tar", "-tf", path], capture_output=True, check=True, text=True
    ).stdout.splitlines()
    for name in listing:
        base = os.path.basename(name)
        if base not in REQUIRED and base not in FORBIDDEN:
            continue
        body = subprocess.run(
            ["tar", "-xOf", path, name], capture_output=True, check=True
        ).stdout
        out[base] = body
    return out


def docs_from_apk(path: str) -> dict[str, bytes]:
    """An apk is concatenated gzip members whose payload is a tar.

    The apk v2 format writes its tar headers with a checksum of its own,
    so neither tarfile nor bsdtar will open the payload ("bad checksum").
    The header layout is the ordinary one, so the blocks are walked here:
    the name sits in the first hundred bytes, the size in octal at 124,
    and the content is padded to a multiple of 512.
    """
    import zlib

    out: dict[str, bytes] = {}
    with open(path, "rb") as fh:
        blob = fh.read()
    pos = 0
    while pos < len(blob):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        payload = d.decompress(blob[pos:])
        if d.unused_data:
            pos = len(blob) - len(d.unused_data)
        else:
            pos = len(blob)
        off = 0
        while off + 512 <= len(payload):
            header = payload[off : off + 512]
            if header.strip(b"\0") == b"":
                break
            name = header[0:100].split(b"\0", 1)[0].decode("utf-8", "replace")
            size_field = header[124:136].split(b"\0", 1)[0].strip()
            try:
                size = int(size_field, 8) if size_field else 0
            except ValueError:
                size = 0
            kind = header[156:157]
            body = payload[off + 512 : off + 512 + size]
            off += 512 + ((size + 511) // 512) * 512
            if kind in (b"x", b"g", b"L"):
                # A pax extended header: the entry that follows is the file.
                continue
            base = os.path.basename(name)
            if base in REQUIRED or base in FORBIDDEN:
                out[base] = body
    return out


def read_docs(path: str) -> dict[str, bytes]:
    name = os.path.basename(path)
    if name.endswith(".zip"):
        return docs_from_zip(path)
    if name.endswith(".deb"):
        return docs_from_deb(path)
    if name.endswith(".apk"):
        return docs_from_apk(path)
    if name.endswith(".rpm") or name.endswith(".pkg.tar.zst"):
        return docs_from_bsdtar(path)
    if name.endswith(".tar.gz"):
        return docs_from_tar(path)
    raise ValueError(f"unknown asset format: {name}")


def audit(path: str) -> list[str]:
    """The problems of one asset; empty means it passes."""
    problems: list[str] = []
    try:
        docs = read_docs(path)
    except Exception as exc:  # noqa: BLE001 - the report is the point
        return [f"cannot read the asset: {exc}"]

    for wanted in REQUIRED:
        if wanted not in docs:
            problems.append(f"missing {wanted}")
    for unwanted in FORBIDDEN:
        if unwanted in docs:
            problems.append(f"carries {unwanted}, which the tree no longer offers")

    copying = docs.get("COPYING", b"").decode("utf-8", "replace")
    for marker in COPYING_MARKERS:
        if marker not in copying:
            problems.append(f"COPYING does not say {marker!r}")
    for old in COPYING_REPLACED:
        if old in copying:
            problems.append(f"COPYING still says {old!r}: it is the one before the fix")

    notice = docs.get("NOTICE", b"").decode("utf-8", "replace")
    for marker in NOTICE_MARKERS:
        if marker not in notice:
            problems.append(f"NOTICE does not say {marker!r}")
    return problems


def main() -> int:
    dist = sys.argv[1] if len(sys.argv) > 1 else ".dist"
    assets = sorted(
        f
        for f in os.listdir(dist)
        if f.endswith((".zip", ".tar.gz", ".deb", ".rpm", ".apk", ".pkg.tar.zst"))
    )
    if not assets:
        print(f"no release assets in {dist}/")
        return 1
    failures = 0
    for asset in assets:
        problems = audit(os.path.join(dist, asset))
        if problems:
            failures += 1
            print(f"FAIL {asset}")
            for p in problems:
                print(f"       - {p}")
        else:
            print(f"ok   {asset}")
    print(f"\n{len(assets) - failures}/{len(assets)} assets carry the tree's licence")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
