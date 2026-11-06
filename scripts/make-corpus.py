#!/usr/bin/env python3
"""Generate the benchmark corpora, so a number is reproducible by someone else.

Why this exists
---------------
`crates/rgx-core/examples/status_table.rs` prices the engine against a
corpus it cannot build. It looked for `$HOME/.rgx-bench/big235.rs` and for
a tree under `$HOME/.cargo/registry/src`, and **nothing in this repository
produced either**. A clone could read the published tables and reproduce
none of them.

The many-file corpus is worse than missing, because it is unstable rather
than absent. `~/.cargo/registry/src` is a Cargo registry: it grows every
time anything is fetched and is a different size on every machine. The two
published tables disagree about that tree by exactly 175 files -- 56,407
against 56,232 -- which is the signature of two snapshots of the same
directory taken on different days, not of two measurements. So this script
generates a **fixed** tree instead, and `status_table.rs` points at it.

Determinism
-----------
One seed, one generator, the same bytes on every machine and every run. The
sha256 is printed so a corpus can be named rather than described, and
`--verify` checks an existing one instead of rebuilding it.

Usage
-----
    python scripts/make-corpus.py                       # both, with defaults
    python scripts/make-corpus.py --verify              # check, build nothing
    python scripts/make-corpus.py --tree DIR --files 20000
    python scripts/make-corpus.py --out-dir ~/.rgx-bench --force

The defaults write to `$HOME/.rgx-bench/`, which is where `status_table.rs`
looks when given neither `--big` nor `--tree`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
import time
from pathlib import Path

MASK64 = (1 << 64) - 1
DEFAULT_SEED = 0x5EED_1234_ABCD_0001

# Vocabulary with the shape real source has: identifiers, literals, comments,
# and enough punctuation that the byte-class work in the scanner sees the
# same distribution a real corpus gives it. A corpus of one repeated line
# would make every measurement here meaningless.
WORDS = (
    "fn let mut struct enum impl pub use mod match if else while for loop return "
    "self value key data name type index result option vec string str u8 u32 u64 i32 "
    "usize bool char const static trait where async await dyn ref move clone drop "
    "iter next map filter collect unwrap expect panic Some None Ok Err new default "
    "buffer parser token bytes offset length count total window block chunk"
).split()

LITERALS = ["true", "false", "null", "0", "1", "42", "-1", "3.14", "1e10", "0x1F", "'c'"]

PUNCT = "(){}[],;:.->=+*/&|!?<>#%^~@"


def rwords(rng: random.Random, n: int) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(n))


def a_line(rng: random.Random) -> str:
    """One plausible line of Rust. Shape matters more than sense."""
    r = rng.random()
    if r < 0.30:
        return f"    let {rng.choice(WORDS)} = {rng.choice(LITERALS)};"
    if r < 0.45:
        return f"    // {rwords(rng, rng.randint(3, 9))}"
    if r < 0.60:
        return f"    {rng.choice(WORDS)}({rwords(rng, rng.randint(0, 4))});"
    if r < 0.68:
        return f"    pub fn {rng.choice(WORDS)}_{rng.randint(0, 9999)}() {{ }}"
    if r < 0.70:
        # `fn main` is one of the harness's nine patterns. A generator that
        # omits it produces a corpus on which that row reads 0 == 0, which
        # the gate correctly refuses to publish -- the row was never a
        # measurement, it was a hole in the corpus nobody looked for.
        return "    pub fn main() {"
    if r < 0.73:
        # and `foo.*bar` needs a foo and a bar on one line, which no
        # vocabulary of identifiers produces by accident.
        return f"    let foo{rng.randint(0, 99)} = {rng.randint(0, 99)}; let bar{rng.randint(0, 99)} = foo{rng.randint(0, 99)} + 1;"
    if r < 0.84:
        return ""
    if r < 0.93:
        return f"    /* {rwords(rng, rng.randint(4, 14))} */"
    # A line dense in punctuation and non-ASCII, so the byte-class and UTF-8
    # paths are actually exercised rather than assumed.
    return "    let s = \"café 日本語 \\u{1F3AF} \\t\" + " + str(rng.randint(0, 999))


def gen_file(rng: random.Random, target: int) -> bytes:
    buf = []
    n = 0
    while n < target:
        line = a_line(rng) + "\n"
        buf.append(line)
        n += len(line)
    return "".join(buf).encode("utf-8")


def build_big(path: Path, mb: int, seed: int, force: bool, verify: bool) -> bool:
    """One contiguous file, for the engine with no walk in the way."""
    want = mb * 1024 * 1024
    if path.exists() and not force:
        have = path.stat().st_size
        if abs(have - want) < want * 0.02:
            if verify:
                print(f"  ok   {path} ({have:,} bytes)")
                return True
            print(f"  skip {path} already exists ({have:,} bytes, target ~{want:,}); --force to rebuild")
            return True
    if verify:
        print(f"  FAIL {path}: {path.stat().st_size if path.exists() else 0:,} bytes, expected ~{want:,}")
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    rng = random.Random(seed)
    h = hashlib.sha256()
    tmp = path.with_suffix(path.suffix + ".part")
    with open(tmp, "wb") as f:
        written = 0
        while written < want:
            chunk = gen_file(rng, 1 << 20)
            f.write(chunk)
            h.update(chunk)
            written += len(chunk)
    tmp.replace(path)
    took = time.time() - t0
    print(f"  made {path}  {path.stat().st_size:,} bytes  "
          f"sha256 {h.hexdigest()[:16]}  {took:.1f}s")
    return True


def count_corpus_files(root: Path) -> int:
    """Corpus files only, excluding benchmark artifacts built on top of it.

    A pack store is the thing that made this necessary: `rgx --tv-build`
    writes `.rgx-tv/` INSIDE the corpus directory, and the naive count then
    reports 20,028 files where 20,000 were generated. Building a store over
    a corpus is a normal thing to do; counting it as corpus is not.
    """
    skip = {".rgx-tv"}
    return sum(
        1
        for p in root.rglob("*")
        if p.is_file() and not skip.intersection(p.relative_to(root).parts)
    )


def build_tree(root: Path, files: int, seed: int, force: bool, verify: bool,
               tiny: bool = False) -> bool:
    """A fixed many-file tree.

    A Cargo registry is the wrong corpus for this: it is a different size on
    every machine and on every day, and the published tables disagree by
    exactly the number of files a `cargo fetch` would add. This tree is
    generated, so the file count in the output is a property of the seed and
    not of when the benchmark ran.
    """
    if root.exists() and not force:
        have = count_corpus_files(root)
        if have == files and not verify:
            print(f"  skip {root} already has {have:,} files; --force to rebuild")
            return True
        if have != files and not verify:
            print(f"  warn {root} has {have:,} files, expected {files:,}; --force to rebuild")
            return True
    if verify:
        have = count_corpus_files(root) if root.exists() else 0
        ok = have == files
        print(f"  {'ok  ' if ok else 'FAIL'} {root}: {have:,} files, expected {files:,}")
        return ok

    # --force rebuilds from nothing: the file names carry a global counter
    # (`mod_{made:06d}`), so a rebuild with a different per-directory count
    # leaves the old names behind as orphans rather than overwriting them,
    # and the tree grows by exactly the previous run's leftovers. Only a
    # directory that looks like one this script made is removed -- every
    # top-level entry a `crate_NN` -- so a mistyped --tree cannot cost
    # anyone a real directory.
    if root.exists():
        if not force:
            print(f"  FAIL {root} exists; --force to rebuild")
            return False
        import re as _re, shutil as _shutil
        entries = list(root.iterdir())
        if not all(e.is_dir() and _re.fullmatch(r"crate_\d\d", e.name) for e in entries):
            print(f"  FAIL {root} holds entries this script would not have made; "
                  f"remove it by hand and rerun")
            return False
        _shutil.rmtree(root)

    t0 = time.time()
    # 20 directories, so the walk has somewhere to recurse rather than
    # measuring a flat listing. `files // (files // 20)` computed the
    # *directory count* (20) and used it as the per-directory file count,
    # which built 400 files when 20,000 were asked for -- and --verify had
    # never been run against a completed tree, so nothing caught it.
    # Nesting matters as much as file count. Twenty directories holding a
    # thousand files each make directory enumeration nearly free, and the
    # walk row then measures almost nothing but page cache: on that shape
    # ripgrep's traversal came out at 1.2 us/file against rgx's 2.5, where
    # on a real source tree the two are within 0.7 of each other. The shape
    # below is a source tree's: crates, each with modules, each with sources.
    crates = 24
    modules = 10
    per_dir = (files + crates * modules - 1) // (crates * modules)
    made = 0
    for c in range(crates):
        for m in range(modules):
            sub = root / f"crate_{c:02d}" / f"mod_{m:02d}" / "src"
            sub.mkdir(parents=True, exist_ok=True)
            for _ in range(per_dir):
                if made >= files:
                    break
                rng = random.Random(seed + made)
                # A heavy tail with a small median, like a real tree: most
                # files are a few KB, a few are hundreds.
                if tiny:
                    size = int(1 << rng.randint(5, 8))
                else:
                    size = int(1 << rng.randint(8, 13)) if rng.random() < 0.9 else (1 << rng.randint(14, 19))
                (sub / f"mod_{made:06d}.rs").write_bytes(gen_file(rng, size))
                made += 1
    took = time.time() - t0
    total = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    print(f"  made {root}  {made:,} files  {total / 1e6:.1f} MB  {took:.1f}s")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    home = Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or ".")
    ap.add_argument("--out-dir", type=Path, default=home / ".rgx-bench",
                    help="where the corpora go (default: $HOME/.rgx-bench)")
    ap.add_argument("--big", type=Path, default=None,
                    help="path for the single large file (default: <out-dir>/big235.rs)")
    ap.add_argument("--big-mb", type=int, default=235)
    ap.add_argument("--tree", type=Path, default=None,
                    help="path for the many-file tree (default: <out-dir>/tree)")
    ap.add_argument("--files", type=int, default=20000)
    ap.add_argument("--tiny-files", type=int, default=20000,
                    help="files in the tiny-file corpus (default: same count as --files)")
    ap.add_argument("--tiny", action="store_true",
                    help="also build the tiny-file corpus: many small files, "
                         "which is the shape scripts/bench-small-files.ps1 "
                         "measured before the harness was unified")
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=DEFAULT_SEED)
    ap.add_argument("--force", action="store_true", help="rebuild what already exists")
    ap.add_argument("--verify", action="store_true", help="check, build nothing")
    a = ap.parse_args()

    big = a.big or a.out_dir / "big235.rs"
    tree = a.tree or a.out_dir / "tree"

    print(f"corpora under {a.out_dir}   seed 0x{a.seed:016x}   "
          f"{'verify only' if a.verify else 'build'}")
    ok = build_big(big, a.big_mb, a.seed, a.force, a.verify)
    ok &= build_tree(tree, a.files, a.seed, a.force, a.verify)
    if a.tiny or a.verify:
        tiny = a.tree or (a.out_dir / "tiny")
        ok &= build_tree(tiny, a.tiny_files, a.seed + 1, a.force, a.verify, tiny=True)
    if ok and not a.verify:
        print("\nnow run the harness against them:")
        print(f"  python scripts/make-corpus.py --verify")
        print(f"  cargo bench --release -p rgx-core --example status_table")
        print(f"    --big {big} --tree {tree}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
