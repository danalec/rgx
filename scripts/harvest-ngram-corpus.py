#!/usr/bin/env python3
"""Harvest the n-gram benchmark corpus, so both hosts prune over one set of bytes.

Why this exists
---------------
`tesla_valve.rs`'s n-gram tables measured 15,000 `.rs` files taken in
`readdir` order from a live Cargo registry. `readdir` order is not stable
across machines and the registry grows on every fetch, so the two published
runs were over *different files* and their absolute prune rates could not be
compared -- the paper says so and calls for a digest-named corpus "the way
`scripts/make-corpus.py` closed the dashboard corpora". This is that corpus.

Determinism
-----------
The selection rule is content-addressed: hash every `.rs` file under the
source root, sort by digest, take the first N. The same snapshot yields the
same selection on any machine; the manifest names the result so two runs
can prove they measured the same bytes. The corpus digest is the sha256 of
the sorted per-file digests -- the number the tables cite.

Usage
-----
    python scripts/harvest-ngram-corpus.py                        # default: registry -> ~/.rgx-bench/ngram-corpus
    python scripts/harvest-ngram-corpus.py --source DIR --out DIR --files 15000
    python scripts/harvest-ngram-corpus.py --verify DIR           # recompute a corpus digest
    python scripts/harvest-ngram-corpus.py --list-only            # digest and stats, copy nothing

Copy the output directory to the second host as-is; the harness reads it
with `--corpus <dir>` and prints the same digest here and there.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_rs(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith(".rs"):
                out.append(Path(dirpath) / name)
    return out


def corpus_digest(digests: list[str]) -> str:
    """The name of the corpus: sha256 over its sorted per-file digests."""
    h = hashlib.sha256()
    for d in sorted(digests):
        h.update(d.encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    home = Path.home()
    ap.add_argument(
        "--source",
        type=Path,
        default=home / ".cargo" / "registry" / "src",
        help="tree to harvest .rs files from (default: the Cargo registry)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=home / ".rgx-bench" / "ngram-corpus",
        help="corpus directory to write (default: ~/.rgx-bench/ngram-corpus)",
    )
    ap.add_argument("--files", type=int, default=15_000, help="how many files to select")
    ap.add_argument("--verify", type=Path, default=None, help="recompute a corpus digest and exit")
    ap.add_argument("--list-only", action="store_true", help="compute and print, copy nothing")
    ap.add_argument("--force", action="store_true", help="replace an existing corpus directory")
    args = ap.parse_args()

    if args.verify is not None:
        files = sorted(args.verify.glob("*.rs"))
        if not files:
            print(f"no .rs files under {args.verify}", file=sys.stderr)
            return 1
        digests = [sha256_file(p) for p in files]
        total = sum(p.stat().st_size for p in files)
        print(f"files:      {len(files)}")
        print(f"bytes:      {total}")
        print(f"corpus:     sha256:{corpus_digest(digests)}")
        manifest = args.verify / "MANIFEST.json"
        if manifest.is_file():
            named = json.loads(manifest.read_text(encoding="utf-8"))["corpus_sha256"]
            print(f"manifest:   sha256:{named}")
            print("verify:     " + ("OK" if named == corpus_digest(digests) else "MISMATCH"))
        return 0

    if not args.source.is_dir():
        print(f"source not found: {args.source}", file=sys.stderr)
        return 1

    t0 = time.time()
    files = collect_rs(args.source)
    print(f"walked {len(files)} .rs files under {args.source} in {time.time() - t0:.1f}s")

    # Content-addressed selection: the same snapshot selects the same files
    # on any machine, whatever order the filesystem lists them in.
    t1 = time.time()
    digested = [(sha256_file(p), p) for p in files]
    digested.sort(key=lambda t: t[0])
    selected = digested[: args.files]
    print(
        f"hashed and selected {len(selected)} of {len(digested)} "
        f"(lowest content digests) in {time.time() - t1:.1f}s"
    )

    total = sum(p.stat().st_size for _, p in selected)
    digest = corpus_digest([d for d, _ in selected])
    print(f"bytes:      {total}")
    print(f"corpus:     sha256:{digest}")

    if args.list_only:
        return 0

    if args.out.exists():
        if not args.force:
            print(f"refusing to replace {args.out} without --force", file=sys.stderr)
            return 1
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True)

    # Content-addressed names: a file in the corpus says what it is. The
    # registry holds duplicate contents (the same bytes under two crates),
    # and a duplicate digest must not overwrite its twin -- the corpus is
    # 15,000 files, so a second occurrence gets a numbered name.
    seen: dict[str, int] = {}
    for d, p in selected:
        n = seen.get(d, 0)
        seen[d] = n + 1
        name = f"{d}.rs" if n == 0 else f"{d}.{n}.rs"
        shutil.copyfile(p, args.out / name)

    manifest = {
        "source_root": str(args.source),
        "selection": "lowest content sha256 of every .rs under the source root",
        "files": len(selected),
        "bytes": total,
        "corpus_sha256": digest,
        "file_sha256": sorted(d for d, _ in selected),
        "harvested_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    (args.out / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=1) + "\n", encoding="utf-8"
    )
    print(f"corpus written to {args.out}")
    print(f"copy that directory to the second host; the harness takes --corpus {args.out.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
