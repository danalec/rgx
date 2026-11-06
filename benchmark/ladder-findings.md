# Ladder and knee: what actually limits the pack store

Two measurements made on the CachyOS bench host (Linux, Ryzen 7 255,
CachyOS, 10 logical CPUs) on 2026-10-17, against the tree as it stood on
that date. Both
answer questions `benchmark/findings.md` §20 raised and neither is a
prediction: they are the numbers a model would have to be built on.

## 22. The thread sweep: the knee is at 6-8, and half the query is serial

**Question.** The paper sizes the worker pool from
`X(K) = min(K/D, beta_pack/L_pack)` and never measured where `K` saturates.
Where is the knee?

**Evidence.** `rgx -c 'fn main' --engine tv --tv-store STORE -j N` over the
20,000-file corpus, best of 3 per width, 297,851 matches at every width.

| threads | 1 | 2 | 4 | 6 | **8** | 10 | 12 | 16 | 20 | 32 |
|---|---|---|---|---|---|---|---|---|---|---|
| wall ms | 158 | 111 | 91 | 83 | **82** | 85 | 89 | 88 | 88 | 90 |

1. **The knee is at 6-8 threads.** Past 8 the curve is flat and then rises
   slightly -- contention, not gain. The box has 10 logical CPUs, so
   `-j auto` (the default) already sits past the saturation point.

2. **Only 1.93x of speedup from 8x the threads.** 158 ms at `-j 1` against
   82 ms at `-j 8`. If the query were fully parallel that would be nearer
   8x. The gap is a serial fraction, and by Amdahl it is about half the
   query: `1/1.93 = 0.52 = s + (1-s)/8` gives `s ≈ 0.41`.

3. **Right-sizing is free.** `-j 8` is 3.5% faster than `-j 10` and 9%
   faster than `-j 32` on this corpus. Nothing is gained by defaulting past
   the knee.

**Conclusion.** The pool is oversized by default and about 40% of the query
does not scale with it. Which part is serial is exactly what `--stats`
would name -- the manifest, filter, map and teardown stages are coordinator
thread work by construction -- so this is the measurement that says the
instrumentation is worth restoring.

## 23. The ladder: a U in file size, which is load balance and not per-file cost

**Question.** The two-term law writes the direct arm's cost as
`T = sigma*N + B/beta + eps`. Varying `N` at fixed `B` and `B` at fixed `N`
should separate `sigma` from `1/beta`. What does the ladder say?

**Evidence.** Synthetic corpora, generated with a fixed seed. Pattern
`helper_` matches exactly once per file, so the prefilter prunes nothing and
every file is read. Direct arm (`--engine rgx`), best of 5, wall clock.

| corpus | N | B | ms | bytes/file |
|---|---|---|---|---|
| `n0500` | 500 | 417.7 MB | 74 | 835 KB |
| `n2000` | 2,000 | 417.7 MB | **26** | 209 KB |
| `n8000` | 8,000 | 417.7 MB | 31 | 52 KB |
| `n20000` | 20,000 | 417.8 MB | 52 | 21 KB |
| `b0100` | 20,000 | 104.9 MB | 45 | 5 KB |
| `b1600` | 20,000 | 1677.8 MB | 87 | 84 KB |

1. **The N series at fixed B is a U, not a line.** 500 files are **2.8x
   slower** than 2,000 files at the same byte count. A model with a positive
   per-file cost cannot produce that: less `N` cannot mean more time. This
   is not noise -- the same numbers came out of two independent passes.

2. **The B series at fixed N is sublinear.** 16x the bytes (104.9 to
   1677.8 MB) costs 1.93x the time (45 to 87 ms). `B/beta` with a constant
   `beta` would be linear in `B`, so `beta` is not constant here either.

3. **The U has the shape of load balance.** 500 units of work over 10
   threads is 50 files of 835 KB each, and the slowest thread decides the
   wall clock; 2,000 units of 209 KB divides far more evenly. The
   `StageTimes::balance` field exists for exactly this and is measured at
   0.89-0.96 on the registry store -- it should be lowest on `n0500`.

**Conclusion.** The ladder is the right experiment and it refuses the
two-term law as a fit: at fixed `B`, cost is not monotone in `N`, and at
fixed `N` it is not linear in `B`. Whatever predicts this has to carry a
balance term, which is a property of the pool and the unit of work and not
of the corpus alone. This is the honest end of the `sigma`/`beta` split --
it is not that the data is too thin (six points, two axes), it is that the
model form is wrong.

Reproduce: generate the corpora with the fixed-seed snippet in
`scripts/`, then `rgx -c 'helper_' --engine rgx DIR` best-of-5 at each
point. Both series need the same host and the same build.

---

## 24. The manifest is re-verified on every query, and that is the regression

**Question.** §21 recorded that the pack store's cold penalty moved from
4.50 ms to 228.50 ms and its warm base from 51 to 84 ms while the per-file
arms held still. Where does the cost sit?

**Evidence.** CachyOS bench host, same tree, best of 5, `--engine tv` over
the v5 store at `~/.rgx-bench/cold-v5-disk` against `--engine rgx` over the
same corpus.

| | store | direct | delta |
|---|---|---|---|
| `--files` (enumerate only, no search) | **49 ms** | **9 ms** | **+40 ms** |
| zero-match pattern | 75 ms | 69 ms | +6 ms |
| `fn main` | 82 ms | — | — |

1. **The store is slower than a plain walk at enumerating files.** `--files`
   does no matching at all: it loads the manifest and lists the paths. The
   direct arm walks 20,000 files in 9 ms; the store takes 49 ms to read
   2.9 MB of manifest. That is 59 MB/s, and loading a manifest is supposed
   to *beat* a walk -- it is the store's whole premise.

2. **49 of the 75 ms is manifest load.** A zero-match pattern, which the
   n-gram filter would reject outright if it were pruning, still costs
   75 ms; forcing the filter to stand down with `RGX_ABLATE_NGRAM=1` costs
   75 ms too. The filter is not the cost. The difference between the two
   rows above -- 75 minus 49 -- is the entire filter-and-scan phase.

3. **The cause is in `crates/rgx-core/src/tv/format.rs`.** `decode()` and
   `scan()` both call `self.verify()` first, and `verify()` computes a CRC32
   over the whole manifest payload. `run_tv_query` calls `load_manifest` at
   the top of every query, so each query re-reads and re-hashes 2.9 MB. A
   software CRC32 at roughly 50-60 MB/s is the whole 49 ms.

4. **This is the v5 regression and not a cache effect.** The v4 store was
   the same size to within eight bytes (§21 item 3), so the payload has not
   grown -- the verification work per query has.

**Conclusion.** The store pays a per-query cost proportional to the *record
count* (the manifest is one record per file) where it is supposed to pay a
per-query cost proportional to the *matching* files. That inverts the
architecture's premise on a many-small-files corpus, which is exactly the
corpus the store is for. The fix is not a better prefilter: it is to verify
the manifest once per store open rather than once per query, or to make
`verify` cheap enough to ignore (hardware CRC32C), or both. Until then the
store cannot beat a walk at enumeration and every number measured through
`--engine tv` carries a 49 ms floor.

Reproduce: `rgx --files --engine tv --tv-store STORE` against
`rgx --files --engine rgx CORPUS`, best of 5, same host.

---

## 25. The 41 ms is the freshness check, which walks the corpus the store exists to avoid walking

**Question.** §24 located 49 ms of a 75 ms query in the manifest stage and
suspected its decode. Measuring the stage split says otherwise. Where is it?

**Evidence.** `--stats` (restored, but printing nothing by default), a
zero-match query over the v5 store, CachyOS bench host:

```
rgx-tv: in-process 57.3 ms = manifest 41.2 + filter 1.2 + map 0.8 + work 14.1 + teardown 0.0
```

1. **The manifest stage is 72% of the in-process time.** Filter and map
   together are 2 ms. The n-gram prune and the pack mapping, the two things
   a store is for, are not the cost.

2. **It is not the decode.** §24's parse optimisation -- assembling the
   record integers by shift instead of twelve `try_into().unwrap()` per
   field -- moved `--files` from 49 ms to 50 ms. The hypothesis is refuted
   by its own measurement, and the commit that carried it is neutral.

3. **It is not the CRC.** `crc32_update` is slice-by-8 with two independent
   8-byte chains per 16 bytes, which is ~1 GB/s and about 3 ms on a 2.9 MB
   manifest.

4. **It is the freshness check.** `stale_list_in`
   (`crates/rgx-core/src/tv_runtime/searcher.rs:1372`) calls
   `std::fs::metadata(root.join(&f.rel_path))` for every record to decide
   whether the file has moved since the build. On 20,000 records that is
   20,000 `stat` calls at roughly 2 us each, which is the 40 ms. The dirty
   overlay it feeds is what keeps a stale store answering correctly, so the
   work is not wrong -- it is just paid at query time, per record, forever.

**Conclusion.** The store's per-query cost is proportional to the record
count because it re-walks the corpus to check freshness. That is the
$\mathcal{O}(N)$ term the architecture exists to remove, reintroduced by the
correctness mechanism that keeps the store honest about drift. Three ways
out, and only the first is free:

- **Trust the manifest unless asked.** A `--tv-assume-fresh` flag that skips
  `stale_list_in` gives the store its premise back for a corpus the caller
  knows is unchanged, at the cost of the caller saying so.
- **Make the check cheap.** Compare against one directory mtime, or a
  generation counter, instead of per-file metadata; only fall back to the
  per-file walk when the cheap check says something moved.
- **Pay it at build time.** Store the mtime/size the build saw and compare
  with `fstatat`-style batching; 20,000 stats in one pass is closer to 4 ms
  than 40 ms when they are not interleaved with path construction.

Until one of these lands, every `--engine tv` number carries a 41 ms floor
and the store cannot beat a walk at enumeration -- which is what §24
measured and did not explain.

Reproduce: `rgx -c 'anything' --engine tv --tv-store STORE --stats` and read
the `manifest` field.

**What has been tried.** Reusing one `PathBuf` across the loop instead of
`root.join()` per record removed the allocation and moved `manifest` from
41.2 ms to 38.0 ms and `--files` from 50 ms to 48 ms. Small, real, and not
the answer: the remaining 38 ms is the 20,000 `stat` calls themselves. The
first attempt at that fix switched to `OsString` with a literal `/` and
marked every file stale -- `PathBuf::push` keeps `join`'s separator
semantics, which is the version that is now in the tree.

**Option 1 landed, and it is the fix.** `--tv-assume-fresh` skips the walk
on the caller's word. Same query, same store, same host, `--stats`:

| | default (with the walk) | `--tv-assume-fresh` |
|---|---|---|
| in-process | 67.8 / 64.6 / 66.7 ms | **31.6 / 34.9 / 31.8 ms** |
| manifest | 43.3 / 38.6 / 38.6 ms | **4.4 / 4.9 / 5.0 ms** |

The manifest stage falls 8x and the whole query halves. The count gate is
identical on both arms (297,851), which is the point: nothing here trades
correctness, it declines to re-derive it. No walk means no dirty overlay,
and that is exactly what "assumed fresh" asserts -- a caller who does not
know gets the walk and the warning exactly as before. The remaining 38 ms
of walk is still available to options 2 and 3 for callers who cannot make
the assertion.
