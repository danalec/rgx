# rgx: Status & Benchmark Dashboard

Measured numbers, generated corpora, one command, and a count gate that can
refuse to print a speed. The three corpora are in §1; the listing in §2; the
bench-side gates in §3; the rest is cross-referenced.

- **Machine:** AMD Ryzen 9 7950X3D (16C/32T, 128 MB 3D V-Cache), 64 GB
  DDR5-6000 CL30, Kingston FURY Renegade G5 4 TB PCIe 5.0 NVMe,
  Windows 11 Pro build 26100, `rustc 1.98.1`. This run is the **default
  portable release build** — a plain `cargo build --release`, no `RUSTFLAGS`,
  no `-C target-cpu`. The `znver4` variant was not built or measured for this
  table, so this file makes no claim about it.
- **Reference:** `ripgrep 15.0.0` (rev 3a612f88b8).
- **Harness:** `cargo run --release -p rgx-core --example status_table`
  (`scripts/bench-status.sh` wraps it) — 7 timed rounds per cell, 2 discarded
  warmups, minimum reported, ±3% floor, `-c` count gate in front of every
  timing line, engines interleaved inside every round with the order
  alternating. **All 22 rows passed the gate**; see §3.
- **Corpora, named by digest.** `scripts/make-corpus.py` generates them, and
  the harness prints the sha256 of every corpus it measures. This is not
  decoration: the previous version of this file promised a fingerprint and did
  not deliver one, and the cost is in §5.
  - one file: `big235.rs`, 246,541,116 bytes,
    `9c38d37f2f578287cb9c7731b0dabeafe38e2d629b04cbbbc3d14596de6c0ab8`
  - many files: the **generated** tree, 20,028 files,
    `ee6d1254e3099175ce0053590541dc03ee6c89f8f3ec496695bf2aa009bbba3a`
    (a tree is digested from its sorted path/size listing; hashing 20k files'
    contents would cost more than every timed round combined)
  - this repository, `5629cb5273d80d1e5d2d44b7e968d1686456ec883dc289d3347672c8aa71240c`
    (the working tree, so this digest moves with the tree; `big235.rs` and the
    generated tree did **not** move and §1.1–§1.2 are directly comparable to
    the previous snap)
- **Headline summary:** [`../README.md`](../README.md) §"Evaluation".
  **Findings:** [`findings.md`](findings.md).
  **How to re-run:** [`README.md`](README.md).
  **Pack-store techniques:** [`optimal-techniques.md`](optimal-techniques.md).
  **Extraction cache pricing** (first-run vs cached-run on the
  `archive-extract` row): [`archive-extract-cache.md`](archive-extract-cache.md).

**The §1.2 corpus changed identity.** The previous table priced the walk on a
cargo registry (101,619 files). The harness now points at the fixed generated
tree above, because `~/.cargo/registry/src` grows on every fetch and is a
different directory on every machine. **No row in §1.2 is comparable to the
previous table's** — same label, different corpus. §1.1 and §1.3 are the same
corpora as before and are directly comparable; the digests confirm it.

---

## Recent changes

- **`--sort path` streams in path order** — the walker emits in
  order, the printer streams, peak memory flat in the match count. Engine
  impact: none, proved with `--rgx-base`. [`findings.md`](findings.md) §2.
- **Lazy newline bitmaps and batched pair scanning** — the change
  that produced the nine rows of §1.1.
- **Per-file engine overhead killed** — `ByteRegex` once per query, not per
  file; matcher and sink built once per worker.
- **`memchr` vendored into `rgx-core`** — the last external
  runtime byte-scanning dependency is gone.
- **`Inspect` stopped claiming `.o`** — 126,145 calls / 641 ms → 193 calls /
  27 ms on a tree of plain source; `RGX_CLAIM_EXT=inspect:o` restores it.
- **Adapter budget scaled by nesting depth** — a 4 MiB zip of zips no longer
  reaches 4 TiB of expansion; the total over a tree is a geometric series
  under twice the process budget.
- **Access violation on unclaimed binaries over 16 MiB fixed** — the reader
  path indexed a terminator map through a raw pointer.
- **A narrow alternation branch no longer vanishes at end of haystack.**

---

## 1. Three corpora, three questions

### 1.1 One file — the engine alone, no walk
`big235.rs`, 246,541,116 bytes, `-j1`, thread-matched, no filter.

| pattern | lines rgx / rg | rgx | ripgrep | ratio | verdict |
|---|---:|---:|---:|---:|---|
| `e` | 6,941,931 / 6,941,931 | 144.5 ms | 308.7 ms | **2.14x** | rgx **+113.6%** |
| `e.` | 6,927,072 / 6,927,072 | 276.4 ms | 387.0 ms | **1.40x** | rgx **+40.0%** |
| `foo.*bar` | 264,029 / 264,029 | 82.1 ms | 117.2 ms | **1.43x** | rgx **+42.8%** |
| `pub fn` | 882,393 / 882,393 | 98.3 ms | 130.9 ms | **1.33x** | rgx **+33.1%** |
| `e[0-9]` | 240,786 / 240,786 | 79.4 ms | 117.5 ms | **1.48x** | rgx **+48.0%** |
| `(pub\|fn) [a-z]+` | 1,236,465 / 1,236,465 | 144.8 ms | 200.9 ms | **1.39x** | rgx **+38.8%** |
| `a\|b\|c` | 6,019,540 / 6,019,540 | 161.0 ms | 299.0 ms | **1.86x** | rgx **+85.7%** |
| `fn main` | 175,860 / 175,860 | 66.9 ms | 106.5 ms | **1.59x** | rgx **+59.1%** |
| `let mut` | 39,795 / 39,795 | 63.7 ms | 100.5 ms | **1.58x** | rgx **+57.9%** |

All nine gates PASS and **all nine rows separate** (`sep=yes`, no overlap).
rgx is ahead on every row, from +33.1% to +113.6%.

The previous table had this section the other way up: ripgrep ahead on four
rows (`foo.*bar` −22.1%, `pub fn` −27.5%, `fn main` −24.5%, `e[0-9]` −16.8%),
rgx ahead on two, three ties or overlaps. The four rows ripgrep won were
**two-byte literals**, where ripgrep's packed prefilter led on this corpus;
`Lazy newline bitmaps and batched pair scanning` is the change that reversed
them. Ripgrep's own column moved very
little across the three snaps of this table (`e` 301.4 → 305.8 → 308.7 ms),
so this is rgx's column moving, not the reference's.

Absolute milliseconds drift between sessions of this harness — the
`--rgx-base` runs in §"Recent changes" show both binaries moving together by
up to ~25% — so the ratios are the claim and the milliseconds are the
machine. This snap's ratios match the previous one's to within a point or
two on every row, which is what a stable measurement looks like.

### 1.2 Many files — mostly walk
The generated tree, 20,028 files, `-j32`, `-g '*.rs'`.
**Not comparable to the previous table** — see the corpus note at the top.

| pattern | lines rgx / rg | rgx | ripgrep | ratio | verdict |
|---|---:|---:|---:|---:|---|
| `e` | 11,764,155 / 11,764,155 | 117.6 ms | 126.2 ms | **1.07x** | rgx **+7.3%** |
| `e.` | 11,739,023 / 11,739,023 | 119.9 ms | 130.2 ms | **1.09x** | rgx **+8.6%** |
| `foo.*bar` | 447,725 / 447,725 | 115.4 ms | 117.3 ms | 1.02x | tie (inside ±3%) |
| `pub fn` | 1,492,934 / 1,492,934 | 112.9 ms | 120.0 ms | **1.06x** | rgx **+6.2%** |
| `e[0-9]` | 406,122 / 406,122 | 113.8 ms | 120.3 ms | **1.06x** | rgx **+5.7%** |
| `(pub\|fn) [a-z]+` | 2,091,372 / 2,091,372 | 115.5 ms | 123.4 ms | **1.07x** | rgx **+6.8%** |
| `a\|b\|c` | 10,201,075 / 10,201,075 | 119.5 ms | 126.2 ms | 1.06x | **overlap, not a result** (+5.6%) |
| `fn main` | 297,851 / 297,851 | 116.8 ms | 122.0 ms | 1.05x | **overlap, not a result** (+4.5%) |
| `let mut` | 67,616 / 67,616 | 112.3 ms | 121.4 ms | 1.08x | **overlap, not a result** (+8.1%) |
| `walk (--files)` | 20,000 / 20,000 | 14.3 ms | 23.0 ms | **1.61x** | rgx **+60.7%** |

This is the shape the §1.1 result says nothing about, and it is worth saying
plainly: **on a walk-dominated corpus the two tools are close.** Every search
row is a tie, an overlap, or a single-digit separation, while `rgx` owns the
only row that isolates the walker — `--files` at **+60.7%**. A per-pattern
speedup in the engine does not survive contact with directory traversal,
which is the measurement `AGENTS.md`'s read-floor paragraph argues from.
**No row in this table is a ripgrep win** — the worst case is a tie — and
this snap has five of nine search rows separating in rgx's favour where the
previous snap had two.

### 1.3 This repository
`crates/` + `src/`, `-j32`, pattern `fn main`, plus the asymmetric
archive row.

| row | lines rgx / rg | rgx | ripgrep | ratio | verdict |
|---|---:|---:|---:|---:|---|
| `crates` | 47 / 47 | 17.1 ms | 16.8 ms | 0.98x | tie (inside ±3%) |
| `src` | 3 / 3 | 10.0 ms | 12.9 ms | **1.29x** | rgx **+28.5%** |
| `archive-extract` | 20 / 9 (+11 in archives) | 526.8 ms | 17.7 ms | n/a | rgx **+11 hits (+122% more)** |

Both engine rows are per-walker fixed cost, not search: 47 and 3 lines cannot
measure a matcher. The value of this section is the asymmetric row — rgx reads
inside RAR / 7z / tar.* / brotli / zstd / lz4 / xz / lzma fixtures and returns
20 paths where ripgrep returns 9. The gate flips to `rgx >= rg` for that row
and the verdict names the surplus rather than a speedup ratio. Note what the
timing says while the gate does not: rgx spends 527 ms doing work ripgrep does
not attempt, and the honest reading is a cost, not a 30x slowdown.

**What the `crates` row is actually made of.** "Per-walker fixed cost" says
where the time is not spent; it does not say where it is. Measured
afterwards, with `scripts/walk_patterns.rs` against the same tree: the walk
is 85.7% of the run, and **`--no-ignore` takes it from 10.55 ms to 3.54 ms —
7.01 ms of a 12.43 ms run is `.gitignore` matching, against 0.88 ms for read
plus engine combined.** The mechanism is the COMPILE of the rule set, once per `.gitignore`, at
~58 us per pattern - not a per-entry match: the per-entry term an earlier
fit carried was refuted by the entries sweep (4.55 to 7.86 ms from 1 to 1024
entries at 65 patterns, where a per-(entry x pattern) cost would move 16x).
It is gated on the presence of a `.git`: a tree without one has its `.gitignore`
compiled and never consulted. Full working, the ruled-out explanations, and
three unbuilt fixes: [`findings.md`](findings.md) §1.

That is the answer to "why does this row not move": not that the walk is
irreducible, but that it is mostly pattern matching and the engine is the
smaller half by 8x.

---

## 2. The listing

`walk (--files)`, 20,000 paths on both engines, **14.3 ms against 23.0 ms**,
1.61x, the only row in this file that isolates the walker. The previous
version of this section printed no time because the two walkers disagreed on
which files exist; that is fixed in §4 and the row is measured now.

---

## 3. Bench-side gates

| check | result |
|---|---|
| Count gate on every timing row | **22 of 22 rows matched; 0 withheld** |
| Rows printed without a count agreement | **0** |
| Corpus digests in the header | 3 of 3 |
| `no_std` core build | `cargo build -p rgx-core --no-default-features --features tv-runtime` compiles clean |

The harness exits non-zero if any row fails its gate, so a script cannot read
this report as clean when it is not. The wider release gate (workspace build,
tests, clippy) lives in `.github/workflows/ci.yml` and in `AGENTS.md`; this
file is the bench subset.

---

## 4. The four rows that used to print no time

The previous table withheld `walk (--files)`, `e`, `e.` and `a|b|c` because
rgx's walker listed five files ripgrep's did not on the cargo registry, and
those five accounted for every line delta that failed the gate.

**Re-measured:** both walkers now return 95,762 paths there, no path unique
to rgx. The divergence does not reproduce — but the registry is not the
directory it was, so **this is not recorded as fixed**. What is established is
that the two walkers produce the same set on that tree today, and that the
generated tree supplies a corpus whose counts agree, which is what the gate
needs. The four rows carry numbers now.

One side finding: **rgx prints `/` where ripgrep prints `\` on Windows.** The
test suite normalises both sides before comparing (`tests/walk_diff.rs:143,191`;
`tests/cli.rs:729,768,900,2211`), so the difference is invisible to it by
construction. Whether rgx should match ripgrep's bytes or keep its normalised
form is an open decision. *Can `rgx --files` ever disagree with `rg --files`*
is still an open property question for `tests/walk_diff.rs`.

---

## 5. Why two previous tables were scrapped

**The first: a regenerated corpus.** A table reported `pub fn` at 80.8 ms and
rgx ahead 1.29×; a re-run at the same path reported 169.9 ms and rgx behind
0.72×. Not a regression — `big235.rs` had been regenerated with a different
token mix (`fn main` 3,561 → 175,860 matches, 49×). The code was byte-identical
and the machine idle. **A corpus that is only described cannot be told from
another corpus at the same path** — hence the digest the harness now prints.

**The second: a perf commit that did not re-snapshot the table.** The table
predecessor was written before the lazy-newline-bitmap work and left
untouched through it, which rewrote the whole hot path and took all nine
§1.1 rows. The commit subject claimed the win; the published table still
showed four rows lost.

Two rules follow:

- **A commit that touches the engine re-runs the table, or says its published
  table is now stale.** A subject line is not a measurement.
- **The corpus digest is the contract, not the path.** §1.2 changed corpus in
  a previous run and every one of its rows was incomparable to its
  predecessor — stated at the top of this file rather than discovered by a
  reader who diffs two tables with the same row labels.

---

## What this file does NOT cover

- **Pack-store speedups** — benchmarked separately in `optimal-techniques.md`
  and the preprint; mixing the build cost into a per-query ratio measures the
  build, and the harness would refuse.
- **The `znver4` build.** Not built or measured for this table. The previous
  version claimed portable and `znver4` separate by under 1.5% per row; that
  claim was measured for *that* table and is not carried forward as a fact
  about this one.
- **Absolute numbers as claims about other machines.** Every figure here is
  this machine on this corpus at these digests. The ratios are the portable
  part; the milliseconds are not. **A second host is now on file** —
  [`status-linux-ryzen7-255.md`](status-linux-ryzen7-255.md), same corpora,
  same gate — and it shows the engine-alone edge is *not* portable: rgx
  leads on the two single-byte shapes and loses the six multi-byte/class
  shapes there, against a clean 9-of-9 lead here. Quote §1.1 with this
  host's name or do not quote it.
- **`benchmark/optimal-techniques.md`.** Hand-written, and its original −44.3%
  mean cited an unpinned 93,234-file / 1.87 GB / 117-pack corpus. **The harness
  it names does exist** (`scripts/tv-matrix.sh`), and a digest-pinned 9-cell
  rerun on 93,234 files (`seed 0x5eed1234abcd0001`, 1.89 GB, 114 packs) is now
  filed in [`tv-matrix-transcript.md`](tv-matrix-transcript.md) and analysed in
  [`findings.md`](findings.md) §14: `ParallelBuffered` vs `mmap` is
  cell-dependent — −43.5% to −67.3% on scan-bound count rows (8 of 9 cells
  separate; `pub fn -c` at `-j1` overlaps at −25.9% median) and −9.8% to −11.2%
  on the output-bound full-output row (`fn main` full), reconciling the older
  −44.3% figure with the second host's ≈12% on the 20,000-file tree.