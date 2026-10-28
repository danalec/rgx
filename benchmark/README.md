# rgx: Benchmark Suite

One harness, generated corpora, one table. The table lives in
[`status.md`](status.md) and is not repeated here, because a number that
exists in two files is a number that will exist in two versions.

| Path | What it is |
| :--- | :--- |
| [`status.md`](status.md) | The measured tables, the gate results, and what the numbers do not claim. **Windows 7950X3D.** |
| [`status-linux-ryzen7-255.md`](status-linux-ryzen7-255.md) | The same gated dashboard on a **second host** (Linux, Ryzen 7 255). Where the two hosts agree and where they do not. |
| [`tv-transcript.md`](tv-transcript.md) | A/B/C of ripgrep vs rgx (filesystem) vs rgx-tv (pack store) over a 20,028-file tree — runs on **both hosts**. |
| [`tv-matrix-transcript.md`](tv-matrix-transcript.md) | 9-cell read-mode (`mmap` / `Buffered` / `ParallelBuffered`) × thread matrix on the digest-pinned 93,234-file corpus (`0x5eed1234abcd0001`). |
| [`findings.md`](findings.md) | Measurements and defects that shaped the code: walk cost, `--sort path`, `--files` path-as-regex, the prefilter pair, line-walk bookkeeping, read-mode cell-dependence (§14), Unicode case folding (§15). |
| [`optimal-techniques.md`](optimal-techniques.md) | The engineering behind the pack store's streaming. Its single −44.3% headline is superseded by the cell-dependent matrix in [`tv-matrix-transcript.md`](tv-matrix-transcript.md) and [`findings.md`](findings.md) §14 (−43.5% to −67.3% on scan-bound count rows, −9.8% to −11.2% on output-bound full output, matching the second host's ≈12% on the 20,000-file tree). |
| [`diffrig/`](diffrig/) | Byte-for-byte differential harness against `rg`: `cmp.sh` for one case, `fuzz.py` for a pattern × flag matrix, `conpty.py` for Windows console output. |

**Two hosts are on file, not one.** The Windows 7950X3D dashboard is
[`status.md`](status.md) and remains the quoted source of the paper's
engine-alone figures. The Linux Ryzen 7 255 dashboard is
[`status-linux-ryzen7-255.md`](status-linux-ryzen7-255.md) and is the check
on whether those figures travel. They do not: the sign of the engine-alone
edge flips on six of nine pattern shapes. Pack-store ratios travel in
direction (the store is faster than both direct paths, exact count parity)
but not in headline magnitude. **Never quote a millisecond without its host,
and never quote a ratio without both.**

---

## Running it

```bash
# 1. build the corpora (once; --verify checks an existing one)
python scripts/make-corpus.py --tiny

# 2. build the binaries and print both tables, gated
bash scripts/bench-status.sh
```

Nothing is written into the repository: the transcript goes to the system
temp directory and the path is printed, so a run can be pasted into
`status.md` or filed without dirtying the tree.

The corpora are generated rather than found, because the directory the
previous tables used — `~/.cargo/registry/src` — grows on every `cargo fetch`
and is a different size on every machine. One seed, one generator, the same
bytes everywhere.

### Asking it something else

```bash
# one extra row, through the same count gate as the nine
cargo run --release -p rgx-core --example status_table -- --pattern 'impl Trait'

# a different corpus
cargo run --release -p rgx-core --example status_table -- --tree ~/.rgx-bench/tiny

# a build of rgx before the change, timed in the same process and the same rounds
cargo run --release -p rgx-core --example status_table -- --rgx-base ./rgx-before.exe
```

An ad-hoc pattern goes through the gate like any other. On a corpus that does
not contain it the row is refused with `GATE FAIL, timing withheld`.

### Walk attribution

```bash
rustc -O --edition 2021 -o walk_patterns scripts/walk_patterns.rs
./walk_patterns
```

Splits a walk into traversal, ignore matching, and everything above it, by
varying one input at a time. Writes nothing into the repository.

### Pack-store A/B

Build a store, then measure the three engines on the same corpus:

```powershell
cargo build --release -p rgx-core --bin rgx-tv --features tv-runtime
.\target\release\rgx-tv.exe build <tree> --store <dir>
# then a paired count-gated A/B/C over the same corpus (see tv-transcript.md)
```

### Differential parity

```bash
cd benchmark/diffrig
bash cmp.sh "fn main" ../../src/main.rs     # one query, byte for byte
python fuzz.py                               # pattern × flag matrix
```

The three scripts resolve their own binaries: `RGX` is derived from the
script's location and `rg` takes an `RG` environment override, then `PATH`.

---

## Elsewhere

- **Paper:** the [`rgx-paper`](https://github.com/danalec/rgx-paper)
  repository — source of the preprint, hosted on Zenodo as
  [10.5281/zenodo.23453407](https://doi.org/10.5281/zenodo.23453407).
  Re-render with `cd ../rgx-paper && pdflatex diodic-search.tex` ×3.
- **Guide and usage:** [`../README.md`](../README.md)
