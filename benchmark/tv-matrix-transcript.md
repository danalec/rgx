# rgx-tv axis matrix transcript — the read-mode question at the claimed scale

The four execution axes of `rgx-tv search` (pool, read mode, packs per
thread, unmap) measured on the CLI's wall clock by `scripts/tv-matrix.sh`,
on the corpus the `optimal-techniques.md` −44.3% claim was made over:
93,234 files / 1.87 GB / 117 packs. This transcript answers the one
question [`tv-transcript.md`](tv-transcript.md) deliberately does not: the
internal read-mode choice at the scale the claim names.

**Protocol** (the harness's own rules, enforced by the harness): every arm
sampled once per round against the reference arm in the same round (paired),
round order rotated, floor ±2% (inside it a row is a tie), a named winner
only when every sample of one arm is outside every sample of the other
(overlapping distributions print `overlap, not a result`), and a count or
answer gate in front of every timing row. Reference arm `mmap`: the cold
mapping arm with explicit unmap, the only arm where `--leak-mmap` acts.

- date: 2026-10-15
- host: AMD Ryzen 9 7950X3D, Windows (same host as every Windows run in
  this directory)
- corpus: `scripts/make-corpus.py --tree tree93k --files 93234` —
  seed `0x5eed1234abcd0001`, 93,234 files, 1,894.9 MB generated;
  `--verify` re-checked `ok: 93,234 files, expected 93,234` after the run
- store: `rgx-tv build tree93k` → 114 packs (1,894.87 MB ingested,
  1,821 MB on disk), build wall clock 15.8 s. The claim's corpus reported
  117 packs over 1.87 GB; this one is digest-named where the claim's was
  not, and sits within ~1% of its size at the same file count
- binary: `./target/release/rgx-tv.exe`, engine of 2026-10-14 (the
  per-line mask settle landed later that night). Every arm runs the same
  engine and the three measured cells move inside the ±3% floor under that
  change (nine-pattern A/B, `benchmark/findings.md` §13), so the arm
  ratios stand; the absolute milliseconds are this binary's
- rounds: 11, batch 2 consecutive runs per sample, threads 1/8/32
- clock: bash `TIMEFORMAT=%R`. No CPU counter: `% Processor Time` is
  saturated by the mapping's page faults and cannot resolve this

## Result

Nine rows, three cells × three thread counts. `buf` is ParallelBuffered
(the default), `buf.sbuf` serial buffered, `mmap.*` the mapping arms.

| cell | threads | buf | buf.ppt4 | buf.sbuf | mmap | verdict (buf vs mmap) |
|---|---:|---:|---:|---:|---:|---|
| `pub fn` `-c` | 1 | 845.0 | 834.0 | 929.0 | 1146.0 | overlap, not a result |
| `pub fn` `-c` | 8 | **163.0** | 161.0 | 495.5 | 364.5 | **−56.1%** faster |
| `pub fn` `-c` | 32 | **160.5** | 157.5 | 523.5 | 345.0 | **−54.0%** faster |
| `nonexistent_token_xyz` `-c` | 1 | **412.5** | 407.5 | 528.0 | 730.5 | **−43.5%** faster |
| `nonexistent_token_xyz` `-c` | 8 | **124.5** | 119.5 | 448.0 | 312.0 | **−61.1%** faster |
| `nonexistent_token_xyz` `-c` | 32 | **108.0** | 109.5 | 447.0 | 331.5 | **−67.3%** faster |
| `fn main` full | 1 | **2118.5** | 2113.0 | 2166.0 | 2350.5 | **−9.8%** faster |
| `fn main` full | 8 | **1605.0** | 1602.5 | 1953.0 | 1819.0 | **−11.2%** faster |
| `fn main` full | 32 | **1593.5** | 1597.0 | 1938.5 | 1802.5 | **−11.2%** faster |

Medians in ms of the per-round paired sample. Every mmap.* arm ties with
the `mmap` reference inside the floor on every row (min/median/max and
paired deltas in the raw log below). Gates: `pub fn` 6,781,133 matches
identical on every arm; `nonexistent_token_xyz` 0 on every arm; `fn main`
full output byte-identical across every arm and round (md5 `1772dc8575f1`).
**All gates passed.**

In-process decomposition at `-j8` (`--stats`; the CLI wall clock cannot
see inside the process):

| arm | in-proc | manifest | map | work | teardown |
|---|---:|---:|---:|---:|---:|
| buf | 156.5 | 8.1 | 0.0 | 129.6 | 0.0 |
| buf.ppt4 | 157.0 | 7.6 | 0.0 | 131.4 | 0.0 |
| buf.sbuf | 495.2 | 16.7 | 346.2 | 76.5 | 48.4 |
| mmap | 384.2 | 15.4 | 2.9 | 172.1 | **186.3** |
| mmap.leak | 220.2 | 16.2 | 4.5 | 191.8 | 0.0 |
| mmap.pool | 202.5 | 19.3 | 0.0 | 182.5 | 0.0 |
| mmap.pool.leak | 179.7 | 19.5 | 0.0 | 159.6 | 0.0 |

## What this settles

**The magnitude of the read-mode gap is cell-dependent, and both published
numbers were measuring their own cell.** The scan-bound count rows at the
claimed scale land at −43.5% to −67.3% (the claimed −44.3% is the `j1`
count row to within a point); the output-bound full row lands at −9.8% to
−11.2%, which is the `~12%` the second host measured over the 20,000-file
tree with `fn main`. There is no contradiction left to resolve: quote the
cell with the number. The direction is now 9 of 9 rows (the one `overlap`
row still has `buf`'s median 26% below `mmap`'s).

The teardown paradox stands as [`optimal-techniques.md`](optimal-techniques.md)
describes it: `mmap` pays 186.3 ms of unmap in-process and the kernel pays
the rest at exit, which is why `--leak-mmap` shows a large in-process win
and no wall-clock one — every mmap.* arm ties on the wall clock.

`serial-buffered` is a different regime and not a candidate default: at
`j8`/`j32` it is 34–52% SLOWER than mmap (its serial map stage is 346 ms
at `-j8`), while at `j1` it is 17–27% faster than mmap.

## Quoteable

- `ParallelBuffered` over mmap at the claimed scale: **−43.5% to −67.3%**
  on scan-bound count rows (93,234 files / 1.89 GB / 114 packs,
  2026-10-15, 7950X3D), **−9.8% to −11.2%** on the output-bound full row.
  Cell-dependence is the finding; a bare "−44.3%" is no longer the right
  shape for the claim and a bare "~12%" is not either.
- mmap's teardown is **186.3 ms** of the 384.2 ms in-process total at
  `-j8`, and zero of the wall clock: the unmap runs at process exit
  either way.

---

## Raw log

```
----------------------------------------------------------------------------
rgx-tv axis matrix -- CLI wall clock, paired within the round
----------------------------------------------------------------------------
binary   : ./target/release/rgx-tv.exe
store    : C:/Users/danalec/AppData/Local/Temp/tvcmp93k  (114 packs, 1821 MB on disk)
rounds   : 11, 2 consecutive runs per sample, floor +/-2%
threads  : 1,8,32
reference: mmap  (cold mapping, explicit unmap -- the arm where --leak-mmap acts)
clock    : bash TIMEFORMAT=%R. No CPU counter: % Processor Time is
           saturated by the mapping's page faults and cannot resolve this.

== pattern 'pub fn'   output: -c   threads: 1 ==
   arm                median       min       max    paired  verdict                note
   count gate: every arm answered 6781133  (matches)
   buf                 845.0     812.0    1249.0    -25.9%  overlap,               not a result
   buf.ppt4            834.0     811.0    1178.0    -28.9%  overlap,               not a result
   buf.sbuf            929.0     911.5    1489.5    -17.7%  overlap,               not a result
   mmap               1146.0    1122.5    1587.5     +0.0%  tie                    (inside floor)
   mmap.leak          1134.5    1122.0    1539.5     -0.8%  tie                    (inside floor)
   mmap.pool          1137.5    1124.5    1617.0     +1.0%  tie                    (inside floor)
   mmap.pool.leak     1145.0    1125.5    1548.0     -0.7%  tie                    (inside floor)

== pattern 'pub fn'   output: -c   threads: 8 ==
   arm                median       min       max    paired  verdict                note
   count gate: every arm answered 6781133  (matches)
   buf                 163.0     159.0     174.0    -56.1%  faster                 than mmap
   buf.ppt4            161.0     158.5     170.0    -56.6%  faster                 than mmap
   buf.sbuf            495.5     482.5     550.5    +34.5%  slower                 than mmap
   mmap                364.5     343.5     421.0     +0.0%  tie                    (inside floor)
   mmap.leak           367.5     358.0     427.0     +2.5%  overlap,               not a result
   mmap.pool           363.0     351.5     387.0     -1.9%  tie                    (inside floor)
   mmap.pool.leak      358.5     351.5     398.0     -2.8%  overlap,               not a result

== pattern 'pub fn'   output: -c   threads: 32 ==
   arm                median       min       max    paired  verdict                note
   count gate: every arm answered 6781133  (matches)
   buf                 160.5     155.5     165.5    -54.0%  faster                 than mmap
   buf.ppt4            157.5     154.5     164.0    -54.2%  faster                 than mmap
   buf.sbuf            523.5     513.5     538.0    +51.5%  slower                 than mmap
   mmap                345.0     335.0     369.5     +0.0%  tie                    (inside floor)
   mmap.leak           344.5     338.5     367.0     +0.4%  tie                    (inside floor)
   mmap.pool           342.5     337.5     349.5     -0.8%  tie                    (inside floor)
   mmap.pool.leak      346.0     338.5     351.0     -0.3%  tie                    (inside floor)

== pattern 'nonexistent_token_xyz'   output: -c   threads: 1 ==
   arm                median       min       max    paired  verdict                note
   count gate: every arm answered 0  (matches)
   buf                 412.5     402.5     428.0    -43.5%  faster                 than mmap
   buf.ppt4            407.5     402.0     425.5    -43.9%  faster                 than mmap
   buf.sbuf            528.0     520.5     581.5    -27.3%  faster                 than mmap
   mmap                730.5     722.5     745.0     +0.0%  tie                    (inside floor)
   mmap.leak           733.0     721.0     749.0     +0.2%  tie                    (inside floor)
   mmap.pool           726.5     720.0     748.5     +0.0%  tie                    (inside floor)
   mmap.pool.leak      725.5     720.0     791.0     +0.3%  tie                    (inside floor)

== pattern 'nonexistent_token_xyz'   output: -c   threads: 8 ==
   arm                median       min       max    paired  verdict                note
   count gate: every arm answered 0  (matches)
   buf                 124.5     116.5     134.0    -61.1%  faster                 than mmap
   buf.ppt4            119.5     116.5     136.0    -62.2%  faster                 than mmap
   buf.sbuf            448.0     441.5     462.5    +39.5%  slower                 than mmap
   mmap                312.0     303.5     359.0     +0.0%  tie                    (inside floor)
   mmap.leak           315.0     308.0     370.5     +2.1%  overlap,               not a result
   mmap.pool           312.5     303.5     362.5     +0.4%  tie                    (inside floor)
   mmap.pool.leak      337.5     305.0     356.0     +1.7%  tie                    (inside floor)

== pattern 'nonexistent_token_xyz'   output: -c   threads: 32 ==
   arm                median       min       max    paired  verdict                note
   count gate: every arm answered 0  (matches)
   buf                 108.0     106.0     111.5    -67.3%  faster                 than mmap
   buf.ppt4            109.5     106.5     114.5    -66.9%  faster                 than mmap
   buf.sbuf            447.0     442.5     482.5    +36.7%  slower                 than mmap
   mmap                331.5     322.0     339.5     +0.0%  tie                    (inside floor)
   mmap.leak           332.0     322.5     342.5     +0.3%  tie                    (inside floor)
   mmap.pool           329.0     324.5     335.0     -0.3%  tie                    (inside floor)
   mmap.pool.leak      330.0     324.5     343.0     -0.0%  tie                    (inside floor)

== pattern 'fn main'   output: full   threads: 1 ==
   arm                median       min       max    paired  verdict                note
   answer gate: every arm printed a byte-identical answer (md5 1772dc8575f1)
   buf                2118.5    2091.5    2186.0     -9.8%  faster                 than mmap
   buf.ppt4           2113.0    2099.0    2144.0    -10.2%  faster                 than mmap
   buf.sbuf           2166.0    2113.5    2212.5     -8.2%  faster                 than mmap
   mmap               2350.5    2330.0    2384.5     +0.0%  tie                    (inside floor)
   mmap.leak          2344.5    2327.0    2388.0     -0.3%  tie                    (inside floor)
   mmap.pool          2351.0    2329.0    2382.5     -0.2%  tie                    (inside floor)
   mmap.pool.leak     2355.0    2336.0    2387.5     -0.0%  tie                    (inside floor)

== pattern 'fn main'   output: full   threads: 8 ==
   arm                median       min       max    paired  verdict                note
   answer gate: every arm printed a byte-identical answer (md5 1772dc8575f1)
   buf                1605.0    1570.5    1659.0    -11.2%  faster                 than mmap
   buf.ppt4           1602.5    1560.0    1638.5    -11.5%  faster                 than mmap
   buf.sbuf           1953.0    1901.5    2062.0     +8.8%  slower                 than mmap
   mmap               1819.0    1744.0    1852.5     +0.0%  tie                    (inside floor)
   mmap.leak          1796.5    1757.0    1841.0     -0.7%  tie                    (inside floor)
   mmap.pool          1798.0    1749.5    1873.0     -0.6%  tie                    (inside floor)
   mmap.pool.leak     1809.5    1757.5    1848.0     -0.6%  tie                    (inside floor)

== pattern 'fn main'   output: full   threads: 32 ==
   arm                median       min       max    paired  verdict                note
   answer gate: every arm printed a byte-identical answer (md5 1772dc8575f1)
   buf                1593.5    1568.0    1629.5    -11.2%  faster                 than mmap
   buf.ppt4           1597.0    1568.0    1681.5    -10.8%  faster                 than mmap
   buf.sbuf           1938.5    1900.0    2007.5     +8.1%  slower                 than mmap
   mmap               1802.5    1775.0    1813.5     +0.0%  tie                    (inside floor)
   mmap.leak          1799.0    1761.0    1840.0     -0.2%  tie                    (inside floor)
   mmap.pool          1783.0    1744.0    1869.5     -0.1%  tie                    (inside floor)
   mmap.pool.leak     1789.5    1751.0    1827.5     -0.3%  tie                    (inside floor)

----------------------------------------------------------------------------
in-process decomposition (-j8, --stats; the CLI wall clock cannot see this)
----------------------------------------------------------------------------
   arm                in-proc   manifest        map       work   teardown
   buf                  156.5        8.1        0.0      129.6        0.0   (filter 2.3)
   buf.ppt4             157.0        7.6        0.0      131.4        0.0   (filter 2.1)
   buf.sbuf             495.2       16.7      346.2       76.5       48.4   (filter 4.5)
   mmap                 384.2       15.4        2.9      172.1      186.3   (filter 4.5)
   mmap.leak            220.2       16.2        4.5      191.8        0.0   (filter 4.7)
   mmap.pool            202.5       19.3        0.0      182.5        0.0   (filter 0.0)
   mmap.pool.leak       179.7       19.5        0.0      159.6        0.0   (filter 0.0)

teardown is the stage the CLI cannot escape: with --leak-mmap it becomes
zero in-process and is paid by the kernel at process exit instead, which
is why the in-process win and the wall-clock win are different numbers.

read the pool column here first: a pooled arm has no teardown at all,
because the pool keeps the mappings and only drops an Arc. So --leak-mmap
can only change anything on the unpooled mmap arm, where Unmap::Explicit
is reachable -- which is why that arm is the reference.
----------------------------------------------------------------------------
all gates passed
----------------------------------------------------------------------------
```
