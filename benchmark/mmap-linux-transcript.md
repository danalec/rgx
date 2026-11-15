# mmap vs read path on Linux

The Windows verdict on `RGX_MMAP` was that mapping is **1.51× slower**
(51.2%) than the read path on a 246 MB single file, which is 4× the gap
`src/mmap.rs` cited at the time and the reason the platform default is
"read everywhere but Linux". That verdict was one OS on one machine. This transcript is the same question
on the second OS, on the same large-file-only workload.

**On Linux, mmap wins every row** — the mirror image of Windows.

- date: 2026-10-15
- host: AMD Ryzen 7 255 w/ Radeon 780M, 10 logical CPUs, CachyOS
  (Linux 7.2.7), `rustc 1.98.1`, default portable release build
  (`--release`, no target-cpu) — the second host of
  [`tv-transcript.md`](tv-transcript.md) and
  [`status-linux-ryzen7-255.md`](status-linux-ryzen7-255.md)
- binary: `rgx` at `main` as of 2026-10-15, built on the host in a
  `git worktree` of `~/dev/rgx` (the checkout's own uncommitted work was
  left untouched)
- corpus: `big235.rs` (246,541,116 bytes), the same generator and seed as
  every Windows row (`scripts/make-corpus.py`, seed `0x5eed1234abcd0001`)
- protocol: arms paired inside each round, order rotated, 11 rounds,
  min/median/max, `-c -j1`, count gate before any timing. Harness
  `scripts/mmap-ab.sh` (this transcript's runner, also copied to the host)

| pattern | mmap med (min–max) | read med (min–max) | mmap vs read | count gate |
|---|---:|---:|---:|---|
| `pub fn` | **94** (94–95) | 117 (116–119) | **−19.7%** | ok, 882,393 |
| `e.` | **218** (215–225) | 239 (234–242) | **−8.8%** | ok, 6,927,072 |
| `nonexistent_token_xyz` | **44** (43–45) | 71 (69–72) | **−38.0%** | ok, 0 |

Millisecond wall clock. Every band is tight and every pair is disjoint —
no row is inside a ±2% floor and no row overlaps.

## What this settles

**The platform default is right in both directions.** On Windows the read
path beats mmap by 51% (measured twice) and on Linux
mmap beats the read path by 9–38%; the default ("mapped on Linux, read
elsewhere") is the winning side of both. The asymmetry is the teardown
and page-cache story `optimal-techniques.md` §2 documents from the other
direction: Windows pays `UnmapViewOfFile` per mapping (186 ms of an
in-process row in [`tv-matrix-transcript.md`](tv-matrix-transcript.md)),
where Linux `munmap` is a cheap unmap of clean file pages.

**The magnitude is workload-shaded on Linux too**: the miss pattern
(−38%) benefits most — mmap skips the read syscall entirely — and the
dense-output-free but match-heavy `e.` row least (−8.8%), where the scan
dominates both arms.

## Quoteable

- `RGX_MMAP=1` on Linux, 246 MB single file, `-c -j1`, 11 paired rotated
  rounds (Ryzen 7 255, CachyOS, 2026-10-15): **8.8–38.0% faster than the
  read path** (pub fn −19.7%, e. −8.8%, miss −38.0%). Windows on the same
  corpus: the read path is 51% faster than mmap. Keep the OS name with
  the number.
