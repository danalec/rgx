#!/usr/bin/env python3
"""Give every publishable package the keywords and categories crates.io
shows on its landing page.

    python scripts/add-crates-metadata.py

Without them a crate lands with an empty keyword list and no category,
which is the difference between a page a reader can find and a page nobody
lands on. The category slugs are the ones crates.io publishes; a slug it
does not know makes the upload fail, so the list is checked against the
registry before anything is written.
"""

from __future__ import annotations

import json
import os
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# package name -> (keywords, categories)
META: dict[str, tuple[list[str], list[str]]] = {
    "rgx": (
        ["search", "grep", "ripgrep", "grep-like", "text-search"],
        ["command-line-utilities", "text-processing"],
    ),
    "rgx-core": (
        ["search", "regex", "engine", "ripgrep"],
        ["text-processing", "command-line-utilities"],
    ),
    "rar-codec": (
        ["rar", "codec", "archive", "compression"],
        ["encoding", "compression"],
    ),
    "rgx-adapters-archive": (
        ["archive", "zip", "tar", "7z", "rar"],
        ["encoding", "filesystem"],
    ),
    "rgx-adapters-docs": (
        ["markdown", "latex", "docbook", "markup"],
        ["parser-implementations", "text-processing"],
    ),
    "rgx-adapters-inspect": (
        ["forensics", "carving", "strings", "metadata"],
        ["parser-implementations", "filesystem"],
    ),
    "rgx-adapters-llm": (
        ["gguf", "safetensors", "npy", "protobuf"],
        ["parser-implementations", "science"],
    ),
    "rgx-adapters-mail": (
        ["email", "mbox", "eml", "pst"],
        ["parser-implementations", "encoding"],
    ),
    "rgx-adapters-media": (
        ["exif", "jpeg", "png", "tiff", "font"],
        ["parser-implementations", "multimedia"],
    ),
    "rgx-adapters-office": (
        ["docx", "xlsx", "pptx", "rtf", "visio"],
        ["parser-implementations", "encoding"],
    ),
    "rgx-adapters-pdf": (
        ["pdf", "text-extraction", "document"],
        ["parser-implementations", "text-processing"],
    ),
    "rgx-adapters-tabular": (
        ["sqlite", "netcdf", "hdf5", "dbf", "parquet"],
        ["parser-implementations", "database-implementations"],
    ),
    "rgx-adapters-threed": (
        ["las", "laz", "gltf", "ply", "stl"],
        ["parser-implementations", "encoding"],
    ),
}


def known_categories() -> set[str]:
    req = urllib.request.Request(
        "https://crates.io/api/v1/categories?per_page=100",
        headers={"User-Agent": "rgx-metadata"},
    )
    with urllib.request.urlopen(req, timeout=30) as fh:
        payload = json.load(fh)
    return {c["slug"] for c in payload["categories"]}


def main() -> int:
    try:
        valid = known_categories()
    except Exception as exc:  # noqa: BLE001 - the report is the point
        print(f"cannot read the category list from crates.io: {exc}")
        return 1

    manifests = [os.path.join(ROOT, "Cargo.toml")] + [
        os.path.join(ROOT, "crates", d, "Cargo.toml")
        for d in sorted(os.listdir(os.path.join(ROOT, "crates")))
    ]
    changed = 0
    for manifest in manifests:
        if not os.path.exists(manifest):
            continue
        with open(manifest, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-8")
        if "\nkeywords" in text or "\nkeywords =" in text:
            continue
        name = None
        for line in text.splitlines():
            if line.strip().startswith("name = "):
                name = line.split('"')[1]
                break
        if name not in META:
            continue
        keywords, categories = META[name]
        bad = [c for c in categories if c not in valid]
        if bad:
            print(f"{name}: crates.io does not know {bad}")
            return 1
        # The block goes after `readme`, which is the last metadata line of
        # the package section. Every other line of the file is copied
        # through untouched -- the sections after it are the crate's
        # features, its dependencies and its binaries, and dropping one
        # would take the crate's whole configuration with it.
        lines = text.splitlines(keepends=True)
        out: list[str] = []
        inserted = False
        for line in lines:
            out.append(line)
            if not inserted and line.strip().startswith("readme = "):
                nl = "\r\n" if line.endswith("\r\n") else "\n"
                out.append(f"keywords = {json.dumps(keywords)}{nl}")
                out.append(f"categories = {json.dumps(categories)}{nl}")
                inserted = True
        if not inserted:
            print(f"{name}: no readme line to anchor the metadata on")
            return 1
        with open(manifest, "wb") as fh:
            fh.write("".join(out).encode("utf-8"))
        print(f"metadata added: {name} -> {keywords} / {categories}")
        changed += 1
    print(f"\n{changed} manifests carry keywords and categories now")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
