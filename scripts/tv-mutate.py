#!/usr/bin/env python3
"""Maintenance-loop measurement: what a corpus with k% mutation costs.

What this fills in: the paper's uses table quotes a broker/consultant filing
row at "1%--2% mutation" and a maintenance loop "that re-packs only dirty
files, with Q > Q* after each rebuild" -- and no run in the paper measures
a mutated corpus. This mutates k% of a corpus's files between refreshes and
times the three numbers the claim is made of:

  T_refresh -- `rgx --tv-build` over the mutated corpus (min of R refreshes,
               each one preceded by a FRESH mutation: a second run over an
               unchanged corpus is a no-op and measures nothing),
  T_direct  -- the direct arm's query time (min of ROUNDS paired rounds),
  T_tv      -- the prepared arm's query time (same protocol),
  Q*        -- T_refresh / (T_direct - T_tv), the queries that pay the
               refresh back. The row's claim is Q > Q*; the number says
               what Q* is under this mutation rate.

The count gate runs first and refuses the row if the two arms disagree.

Usage:
    python scripts/tv-mutate.py --corpus DIR --store DIR --percent 1 \
        [--pattern "fn main"] [--refreshes 3] [--rounds 7] [--threads 10]
"""

from __future__ import annotations

import argparse
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path

def find_rgx():
    """The binary, wherever cargo put it and whatever the host calls it.

    The Windows name first, then the bare one: the Unix host has no
    `.exe`. The same fallback `benchmark/diffrig/fuzz.py` makes.
    """
    root = Path(__file__).resolve().parent.parent
    for profile in ("debug", "release"):
        for name in ("rgx.exe", "rgx"):
            candidate = root / "target" / profile / name
            if candidate.is_file():
                return str(candidate)
    return str(root / "target" / "release" / "rgx")

RGX = find_rgx()
# The TV engine is a flag of the main binary, not a second program.
TV = RGX
if not Path(RGX).is_file():
    raise SystemExit(f"no rgx at {RGX}; build it first: cargo build --release")


def wall_ms(argv: list[str], env: dict[str, str] | None = None) -> float:
    e = dict(os.environ)
    if env:
        e.update(env)
    t = time.perf_counter()
    subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=e, check=True)
    return (time.perf_counter() - t) * 1000.0


def summed_count(argv: list[str]) -> int:
    out = subprocess.run(argv, capture_output=True, check=True).stdout.decode("utf-8", "replace")
    total = 0
    for line in out.splitlines():
        m = re.search(r":(\d+)$", line)
        if m:
            total += int(m.group(1))
    return total


def mutate(corpus: Path, percent: float, seed: int) -> int:
    files = sorted(p for p in corpus.rglob("*") if p.is_file())
    k = max(1, int(len(files) * percent / 100.0))
    rng = random.Random(seed)
    for p in rng.sample(files, k):
        # A content change, not just a touch: the freshness gate watches
        # size and mtime, and a rewritten file is what a filing system
        # actually does between queries.
        body = p.read_bytes()
        p.write_bytes(body + f"\nmutated {seed} {p.name}\n".encode())
    return k


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--store", required=True)
    ap.add_argument("--percent", type=float, required=True)
    ap.add_argument("--pattern", default="fn main")
    ap.add_argument("--refreshes", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=7)
    ap.add_argument("--threads", type=int, default=10)
    a = ap.parse_args()

    corpus, store = Path(a.corpus), Path(a.store)
    base = [RGX, "-j", str(a.threads), "-c", a.pattern, str(corpus)]
    # The prepared arm is the standalone store binary, the same arm the
    # paper's tables name "Rgx-tv"; the main binary's `--engine tv` path
    # carries the direct walk's per-query costs and is not that arm.
    tvq = [TV, "-c", "-j", str(a.threads), a.pattern, "--engine", "tv", "--tv-store", str(store)]

    # The gate: same corpus, same query, two paths, one count.
    c_direct, c_tv = summed_count(base), summed_count(tvq)
    if c_direct != c_tv:
        print(f"GATE FAILED: direct={c_direct} tv={c_tv}")
        return 1

    refresh_ms = []
    for r in range(a.refreshes):
        mutate(corpus, a.percent, seed=0x51A7 + r)
        refresh_ms.append(wall_ms([str(RGX), "--tv-build", str(corpus), "--tv-store", str(store)]))
    t_refresh = min(refresh_ms)

    def best(argv: list[str]) -> float:
        wall_ms(argv)  # untimed warmup: the count pass is never charged
        return min(wall_ms(argv) for _ in range(a.rounds))

    t_direct, t_tv = best(base), best(tvq)
    gain = t_direct - t_tv
    qstar = t_refresh / gain if gain > 0 else float("inf")

    print(f"=== tv-mutate: percent={a.percent} pattern={a.pattern!r} threads={a.threads} ===")
    print(f"counts agree: {c_direct} lines")
    print(f"refreshes ({a.refreshes}x, each after a fresh {a.percent}% mutation): "
          + ", ".join(f"{t:.0f}" for t in refresh_ms) + " ms")
    print(f"T_refresh = {t_refresh:.1f} ms   T_direct = {t_direct:.1f} ms   T_tv = {t_tv:.1f} ms")
    print(f"gain per query = {gain:.1f} ms   Q* = {qstar:.1f} queries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
