#!/usr/bin/env python3
"""Generate a log-partition corpus: the non-code shape, for the uses row.

The paper's uses table quotes a log partition as a candidate workload and
no run in the paper measures one. This generates the shape the row is
about: few, larger files (a partition per day), text, mostly stable with
growth at the tail -- deliberately the OPPOSITE file-size shape from the
many-small-files corpora the headline numbers use, which is what makes it
a boundary probe rather than a repetition.

Deterministic like `make-corpus.py`: one seed, the same bytes on every
machine. Usage:

    python scripts/make-log-corpus.py [--out DIR] [--files 5000]
        [--lines 800] [--seed 0x10C0DE] [--verify]
"""

from __future__ import annotations

import argparse
import hashlib
import random
import sys
from pathlib import Path

LEVELS = ["INFO", "WARN", "ERROR", "DEBUG"]
MSGS = [
    "request completed status=200",
    "cache miss key=users",
    "retry scheduled backoff_ms=250",
    "connection reset by peer",
    "checkpoint written",
    "queue depth=%d",
    "shard rebalanced",
    "timeout waiting for lock",
]


def gen(out: Path, files: int, lines: int, seed: int) -> str:
    out.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    for i in range(files):
        rng = random.Random(seed + i)
        body = []
        for ln in range(lines):
            ts = f"2026-10-{(i % 28) + 1:02d}T{(ln // 3600) % 24:02d}:{(ln // 60) % 60:02d}:{ln % 60:02d}Z"
            msg = rng.choice(MSGS)
            if "%d" in msg:
                msg = msg % rng.randrange(1000)
            body.append(f"{ts} svc{rng.randrange(32):02d} {rng.choice(LEVELS)} {msg}")
        data = ("\n".join(body) + "\n").encode()
        p = out / f"part-{i:05d}.log"
        p.write_bytes(data)
        h.update(data)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path.home() / ".rgx-bench" / "log-corpus"))
    ap.add_argument("--files", type=int, default=5000)
    ap.add_argument("--lines", type=int, default=800)
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0x10C0DE)
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args()
    out = Path(a.out)

    if a.verify:
        total = sum(p.stat().st_size for p in out.glob("*.log"))
        print(f"{sum(1 for _ in out.glob('*.log'))} files, {total} bytes in {out}")
        return 0

    digest = gen(out, a.files, a.lines, a.seed)
    total = sum(p.stat().st_size for p in out.glob("*.log"))
    print(f"generated {a.files} log partitions ({total} bytes) in {out}")
    print(f"sha256(content stream) = {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
