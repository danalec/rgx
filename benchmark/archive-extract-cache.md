# `--cache` prices the `archive-extract` row: first-run vs cached-run

**Machine:** AMD Ryzen 9 7950X3D, 64 GB DDR5-6000, Windows 11 Pro 26100,
default portable release build (no `RUSTFLAGS`), the same box as
[`status.md`](status.md).

**Question.** `status.md` §1.3's `archive-extract` row shows rgx at 533.5 ms
against rg's 18.0 ms — asymmetric by design (20 hits vs 9, +11 from inside
RAR / 7z / tar.* / brotli / zstd / lz4 / xz / lzma fixtures). The cost is
adapter extraction, and the extraction cache (`--cache`) is off by default.
Does the cache pay, and when?

**Protocol.** Per AGENTS.md §9 rule 4: minimum of N timed runs per cell,
2 discarded warmups per cell, spawn floor measured with the same method
(`rgx --version`) and reported so it can be subtracted. The count gate runs
before any timing is believed: pattern `RGXFIXTURE` over `crates/` must sum
to 20 match lines in every rgx cell and 9 in every rg cell. One query shape,
one corpus, one machine — this is a local price list, not a fleet claim.

| cell | min | runs | counts | floor-subtracted |
|---|---:|---:|---|---:|
| spawn floor (`rgx --version`) | 4.3 ms | 9 | — | — |
| rgx first-run, **no cache** | 537.6 ms | 5 | 20 | 533.3 ms |
| rgx first-run, **cache write** | 1057.1 ms | 5 (wiped each) | 20 | 1052.8 ms |
| rgx **cached-run** | 65.8 ms | 9 | 20 | 61.4 ms |
| rg (archives as binary) | 25.9 ms | 9 | 9 | 21.6 ms |

Warm cache stats on the cached cell: `163 hits, 0 misses, 0 stored, 0 errors`.

## What the numbers say

1. **The cache works.** first-run-with-store → cached is **16.1x**
   (17.1x floor-subtracted), and no-cache first-run → cached is **8.2x**.
   Counts are identical across all three rgx cells (20/20/20) — the cache
   changes what it costs to get the answer, never the answer.
2. **Storing is not free: the first run pays 2.0x.** 1057 ms with
   `--cache` against 537.6 ms without. Filling the cache costs ~520 ms on
   this corpus (163 extracted outputs written and keyed). A one-shot search
   over an archive-heavy tree should stay on the default (**off**); the
   existing default is correct, not an oversight.
3. **Break-even is the third query.** `1057 + 66·(N−1) < 538·N` holds for
   N ≥ 3. For a session that searches the same tree a few times — iterating,
   `--serve`, the gate loops — the cache turns the row from 538 ms into a
   66 ms query from the third run on.
4. **The standing cost of the feature on a cached run is 40 ms.** 66 ms
   against rg's 26 ms, and rgx is returning 20 hits to rg's 9. After the
   first extraction, reading inside archives costs about the floor plus
   60 ms here; the remaining gap is search over extracted text, which is
   ordinary engine work.

## How to read `status.md`'s `archive-extract` row after this

The 533.5 ms figure is a **no-cache first-run** — correct as published, and
matched here to 1.3% by a differently-implemented harness (537.6 ms). Any
future table that varies adapter behaviour should either keep `--cache` off
for both sides or report both cells; mixing them compares different work.

## What this does not claim

Single corpus (`crates/` with its testdata fixtures), single pattern
(`RGXFIXTURE`, deliberately archive-dense), one machine, minimum-of-N not a
distribution. The floor here is 4.3 ms (min of 9 single runs), lower than
the ~16 ms/iter loop average `status.md` quotes — the two are different
statistics of the same cost, and both are reported so neither has to be
trusted alone. Page-cache state of the corpus is shared across the cold
runs (the min of 5 therefore prices extraction, not disk); the cache
directory is wiped per cold run and untouched for the warm cell.
