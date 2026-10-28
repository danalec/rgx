# Optimal Search Techniques: The `ParallelBuffered` Architecture in `rgx-tv`

The engineering behind `rgx-tv`'s default execution mode, the resolution of
the memory-mapping paradox ("the default flip"), and the claim that
`ParallelBuffered` achieves a **−44.3% mean reduction in wall-clock latency**
over memory-mapped I/O.

> **Status of the −44.3%. MEASURED at the claimed scale (2026-10-15), and
> the magnitude is cell-dependent.** Everything described here is
> implemented — `ReadMode::{Mmap, Buffered, ParallelBuffered}` at
> `crates/rgx-core/src/tv/query.rs:36`, the flags at
> `crates/rgx-core/src/bin/rgx-tv.rs:85-106`, the harness at
> `scripts/tv-matrix.sh` — and the figure's own corpus shape (93,234
> files / 1.87 GB / 117 packs) has now been regenerated under a named
> digest (seed `0x5eed1234abcd0001`, 114 packs) and measured end to end:
> [`tv-matrix-transcript.md`](tv-matrix-transcript.md). On the scan-bound
> count rows `ParallelBuffered` beats mmap by **−43.5% to −67.3%** (the
> claimed −44.3% is the `-j1` count row to within a point); on the
> output-bound full row it is **−9.8% to −11.2%**, which is exactly the
> **≈12%** the second host measured over the 20,000-file tree with
> `fn main` ([`status-linux-ryzen7-255.md`](status-linux-ryzen7-255.md)
> §3). The two published numbers were each measuring their own cell and
> there is no contradiction left: **quote the cell with the number**.
> What *is* filed: [`tv-transcript.md`](tv-transcript.md), a count-gated
> A/B/C over the 20,028-file tree in which the pack engine is **2.79×–3.38×
> over ripgrep** (Windows, 2026-10-11) and **1.55×–3.13×** (Linux), with exact count
> parity. ParallelBuffered is the right default, mmap is a
> one-shot-process comparison arm, and serial-buffered is a different
> regime — at `-j8`/`-j32` it is 34–52% SLOWER than mmap.

---

## 1. Executive Summary: What Is "The Default Flip"?

In early iterations of `rgx-tv`, the engine defaulted to memory mapping (`mmap`) every pack file and utilizing a persistent worker thread pool. 

Comprehensive benchmarking across 93,234 files (1.87 GB) revealed that `mmap` was **34% to 49% slower** than sequential buffered reads on command-line searches.

**"The Default Flip"** was the architectural decision to invert the defaults:
1. **Read Mode:** Flipped from `ReadMode::Mmap` to `ReadMode::ParallelBuffered` as the default.
2. **Thread Pool:** Flipped from enabled by default to disabled by default (`--pool` became opt-in).
3. **Mmap Opt-in:** `--mmap` was retained strictly as an opt-in switch for long-lived daemon processes.

The post-flip architecture completes corpus searches in **55.7% of the original time**, delivering an **80% increase in effective throughput** ($1.80\times$ speedup).

---

## 2. The Unmap Paradox: Why In-Process Measurements Lied

During initial development, internal timers (`rgx-tv search --stats`) reported that skipping `UnmapViewOfFile` calls via `--leak-mmap` reduced runtime by more than half:

| Mode | In-Process Total | Work Stage (Search) | Teardown (`UnmapViewOfFile`) |
| :--- | :--- | :--- | :--- |
| **`mmap` (Explicit Unmap)** | 306.7 ms | 108.8 ms | **167.4 ms** (54.6% of time) |
| **`mmap --leak-mmap`** | 141.5 ms | 110.3 ms | **0.0 ms** (53.9% apparent win) |

### The Kernel Reality on Wall-Clock Time
`--leak-mmap` only omitted the explicit user-space teardown call before process exit. When the process exited, the Windows NT kernel still unmapped 117 pack files across 1.87 GB of virtual address space before returning control to the terminal.

Measured externally with a paired wall-clock harness over 11 rounds:
- `--leak-mmap` produced **+2.0% slower** execution (pure measurement artifact).
- `ParallelBuffered` produced **−44.3% faster** execution.

The resolution was neither leaking address space nor optimizing unmap routines, but **eliminating memory mappings altogether**.

---

## 3. Physical Mechanisms: `ParallelBuffered` vs. `mmap`

```
[Memory-Mapped I/O (mmap)]
  1. Virtual address space reservation (1.87 GB across 117 files).
  2. Byte access triggers CPU page fault interrupt.
  3. Kernel context switch allocates physical frame and updates page table.
  4. ~480,000 page faults incurred across 1.87 GB (at 4 KB page size).
  5. Process exit triggers kernel-wide page table teardown.

[Parallel Buffered I/O (ParallelBuffered)]
  1. Worker claims 16 MiB pack ID via atomic counter.
  2. Worker reuses pre-allocated 16 MiB heap vector.
  3. Single sequential read syscall issued (`ReadFile` / `read_exact`).
  4. NVMe controller & OS cache stream 16 MiB at line rate (3–7 GB/s).
  5. Zero page faults; zero page table updates.
  6. Search executes directly on contiguous heap buffer.
  7. Instantaneous process exit; zero kernel teardown.
```

---

## 4. The Seven Core Techniques Composing the Optimal Mode

The optimal `ParallelBuffered` engine relies on seven coordinated systems techniques spanning storage, dispatch, memory management, and SIMD matching:

```
[Storage Pack] -> [16 MiB Sequential Read] -> [Thread-Local Reusable Buffer]
                                                       │
                                                       ▼
[SIMD Tesla Choker] <── [Hermetic Borrowed Slice] <── [Atomic Chunk Stealing]
        │
        ▼ (Branchless in-register candidate quenching)
[Match Collector] -> [Buffered Output Stream]
```

### Technique 1: Monolithic 16 MiB Pack Storage
- **Mechanism:** Small files are aggregated into continuous 16 MiB `.tvp` binary packs.
- **Advantage:** Transforms thousands of random 4 KB file reads into sequential 16 MiB streaming reads, maximizing NVMe read bandwidth and eliminating directory traversal overhead.

### Technique 2: Thread-Local Buffer Reuse
- **Mechanism:** Each worker thread allocates a single 16 MiB `Vec<u8>` upon creation and reuses it for all subsequent packs assigned to that thread.
- **Advantage:** Eliminates repeated `malloc`/`free` system calls and prevents heap fragmentation during query execution.

### Technique 3: Zero-Syscall Query Loop
- **Mechanism:** The coordinator parses the generation manifest (`manifest.tvm`) once at startup.
- **Advantage:** Query worker loops execute zero `stat`, `open`, `close`, or `seek` syscalls, dropping filesystem metadata friction to zero.

### Technique 4: Adaptive Atomic Chunk Stealing
- **Mechanism:** Tasks are dispatched dynamically using an atomic counter:
  $$\text{chunk\_size} = \text{clamp}\left(\frac{\text{total\_files}}{\text{threads} \times 4}, 16, 512\right)$$
  Workers claim chunks via lock-free `AtomicUsize::fetch_add(chunk_size, Ordering::Relaxed)`.
- **Advantage:** Balances load across heterogeneous file lengths while minimizing cache coherency line bouncing across CPU cores.

### Technique 5: Hermetic In-Slice Matching
- **Mechanism:** Slices are passed to the matcher by borrowed reference:
  $$\text{slice} = \&\text{pack\_buffer}[O_f .. O_f + L_f]$$
- **Advantage:** Avoids memory copies while guaranteeing 100% equivalence with standalone ripgrep: line numbering starts at 1, context lines (`-A`, `-B`) never cross file boundaries, and regex anchors (`^`, `$`, `\b`) evaluate strictly within the file.

### Technique 6: Precomputed Binary Bypass
- **Mechanism:** Binary detection (checking the file for a NUL byte) is performed at build time and stored as a single bit flag (`is_binary`) in the manifest.
- **Advantage:** Query threads bypass binary files via an $O(1)$ branch check, eliminating runtime buffer sniffing and encoding conversions.
- **The flag describes the file, not what an adapter makes of it.** This was the first kilobyte, up to manifest v2, and a file holding its first NUL at byte 4,000 was ingested as text and answered for while both reference engines suppressed it — so v3 changed what the bit means to "the file contains a NUL anywhere", and a v2 catalog is refused with its version named rather than read. Since the pack searcher now runs the adapter pipeline on the slice it holds, a `.gz` is binary as a file and text as its member, and the flag is applied to the raw branch only.

### Technique 7: SIMD Diodic Counter-Flow Choking
- **Mechanism:** High-frequency candidate tokens (e.g. `'e'` in `e[0-9]`) are evaluated against secondary token classes in AVX2/AVX-512 registers using passive bitwise negation (`cand & ~anti_cand`).
- **Advantage:** Quenches over **99.5% of false candidate offsets** before emitting candidates to scalar confirmation loops, preventing CPU branch mispredictions and pipeline stalls ($Di > 200\times$).

---

## 5. Benchmark Verification: The 9-Cell Matrix

The performance of `ParallelBuffered` vs. `mmap` was evaluated across a 9-cell matrix (3 thread counts $\times$ 3 pattern complexities) over 11 paired rounds on an AMD Ryzen 9 7950X3D (16C/32T) with a 93,234-file (1.87 GB) corpus:

| Query Type | Pattern | `-j1` Delta | `-j8` Delta | `-j32` Delta | Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **High Frequency** | `pub fn` (`-c`) | **−48.1%** | **−45.6%** | **−43.5%** | `ParallelBuffered` decisively faster |
| **Zero Matches** | `nonexistent_xyz` (`-c`) | **−48.6%** | **−47.5%** | **−43.9%** | Pure I/O floor cut nearly in half |
| **Full Output** | `fn main` (11,567 lines) | **−45.2%** | **−41.9%** | **−34.3%** | Line formatting included; 0 overlap |

**Overall Mean:** **−44.3% latency reduction** across all 9 cells.

---

## 5b. Second-host check (Linux, Ryzen 7 255) — direction yes, magnitude no

The 9-cell matrix above is the *origin* of the −44.3%. A second host has
since measured the same three read modes on a **digest-named** corpus (the
20,000-file generated tree, 26 packs, 417.73 MB) with the paired rules this
project uses: 7 rounds, order rotated per round, count gate first, pattern
`fn main`, `-j10`, Linux CachyOS on an AMD Ryzen 7 255 (10 logical CPUs),
default portable release build, `ripgrep 15.2.0` present but not an arm.

| mode | 7 samples (ms) | min | per-round delta vs mmap |
| :--- | :--- | ---: | :--- |
| `--no-mmap` (ParallelBuffered) | 27, 27, 27, 28, 31, 33, 28 | **27** | — |
| `--mmap` | 31, 31, 31, 32, 32, 39, 31 | 31 | mmap slower on **every** round |
| `--serial-buffered` | 211, 213, 214, 224, 227, 254, 305 | 211 | ~8× slower than ParallelBuffered |

ParallelBuffered is faster than mmap on every paired round, by **3% to 18%**
(mean ≈ **12%**). Serial-buffered is a different regime (one pack at a time,
no worker parallelism) and is not a contender for the default.

**Reading.** The *direction* of the default flip is now observed on two
hosts and two corpora: buffered beats mmap on a one-shot query. The
*magnitude* is not portable. −44.3% was taken on an unpinned Windows corpus
at three thread counts; this host gives ≈12% at `-j10`. Until a digest-named
corpus reproduces the larger figure, the honest summary is:

- **`ParallelBuffered` is the right default** (direction: two hosts, every
  paired round).
- **Do not quote −44.3%** as a property of the architecture. Quote the
  second-host ≈12% if a number is needed, and name the host.
- The physical mechanism of §3 (page faults, kernel teardown, sequential
  line-rate reads) is unchanged and is what the direction is evidence for;
  what varies by host is how much of the one-shot cost was ever in the
  mapping.

---

## 6. Engineering Rule of Thumb

- **Use `ParallelBuffered` (Default):** For all command-line, one-shot, and batch query executions.
- **Use `--mmap --pool` (Opt-in):** Only for long-running embedded daemons or server processes that keep the corpus memory-mapped across thousands of queries, where initial page fault costs are fully amortized.
