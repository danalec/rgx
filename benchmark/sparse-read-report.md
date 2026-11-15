# Direction 1.2: extent-coalesced sparse `.tvp` reads with an n-gram pre-plan

Scope: make the 512-bit filter's separation visible as **bytes not read**, and
give the read plan one filter rule instead of two. The measured outcome is
`benchmark/findings.md` §22; this file is the record of what changed and why.

## What changed

| File | Change |
|---|---|
| `crates/rgx-core/src/ngram.rs` | The one record-level predicate `may_reject(ngram, covered, query)` and the two coverage answers it is fed: `covered_raw_bytes` (a search over the record's own bytes) and `covered_pipeline_units` (a search over the adapter pipeline's units, as `run_tv_query` runs). |
| `crates/rgx-core/src/tv/plan.rs` | `prune_by_ngram` — the pre-plan filter, the same rule asked over the plan's records before any byte is planned — and the gap rule in `cut_units` with `MAX_EXTENT_GAP = 64 KiB`. |
| `crates/rgx-core/src/tv/query.rs` | `SearchConfig::ngram_query`: the planner's copy of the query signature, derived at the search entry alongside the engine so the pre-plan and the per-file filters can never stand in different states. |
| `crates/rgx-core/src/tv_runtime/searcher.rs` | `raw_decode` runs the pre-plan and reports its rejects into `SearchStats::total_files_pruned` (one count, whichever point answered); both per-file filter sites call `may_reject`; `WorkerOut` carries `bytes_read`/`units_read`. |
| `crates/rgx-core/src/lib.rs` | `ablate_extents()` / `set_ablate_extents()` (`RGX_ABLATE_EXTENTS`), in the `ablate_mask`/`ablate_ngram` house style. |
| `src/main.rs` | The `run_tv_query` filter site calls the shared predicate (`covered_pipeline_units` + `may_reject`); behaviour identical, rule text no longer duplicated. |

## The rule, in one place

```rust
may_reject(ngram: &[u64; 8], covered: bool, query: &NgramSig512) -> bool
    = covered && !NgramSig512::from_words(*ngram).contains_query(query)
```

`covered` is each site's answer to "does the stored signature cover the bytes
this search will actually see?":

- raw-bytes search (the library's pack search): `rollup_ok || !sig_covers_adapter`
  — any signature the format writes covers the record's own bytes; a rollup
  under a foreign extraction fingerprint is stood down conservatively.
- pipeline search (`run_tv_query`): `!claimed || (sig_covers_adapter && rollup_ok)`
  — a claimed file is searched as the pipeline's units, covered only by a
  rollup the query's extraction context vouches for.

Every existing stand-down stays where it stands: the query-level ones
(`-v`/`--files-without-match`, forced `-E`, folded literal, no required
4-gram, `RGX_ABLATE_NGRAM`) at signature construction, the dirty-file
overlay's `dirty_now.is_none()` at the `run_tv_query` site, and the all-zero
signature inside `contains_query`. FNR=0 is preserved by construction: doubt
never reaches `may_reject`, and `may_reject` only rejects on a proven subset.

## The gap rule

`cut_units` already cut at file boundaries and at `UNIT_BYTES`. It now also
ends a unit at a hole of `MAX_EXTENT_GAP` (64 KiB) or more between one file's
end and the next file's start. A hole is bytes of records the plan dropped —
the pre-plan filter's rejects. Below the threshold the bytes are read with
their neighbours (one extent per surviving file would cost more in claims and
syscalls than the skip saves on a sequentially-read pack); at the threshold
the unit ends and the hole is never paid for. Every file sits whole inside
exactly one unit — the boundary invariant — so the cut can lose bytes of a
hole and never bytes of a file.

On the mmap path the same plan changes page touches rather than syscalls: a
pruned record's pages are never faulted, which was already true per-file and
is now decided before the worker loop.

## Ablation switch

`RGX_ABLATE_EXTENTS=1` stands the pre-plan filter **and** the gap rule down:
`prune_by_ngram` returns its input untouched and `cut_units` spans every hole
at any size, so the plan reads exactly what the plan always read. Contract,
same as `RGX_ABLATE_MASK`: cost may change, answers never do.

## Tests and their teeth

| Test | Asserts | Regression it catches |
|---|---|---|
| `a_gap_at_the_threshold_ends_the_unit_and_one_under_it_does_not` | 2 units at gap == `MAX_EXTENT_GAP`, 1 unit at `MAX_EXTENT_GAP − 1` | An off-by-one in the threshold either reads a hole it promised to skip or skips bytes between neighbours it promised to read. |
| `a_chain_of_small_gaps_collapses_into_one_unit` | 3 files, 2 small holes → 1 unit `(0, 320)` | Over-eager splitting that turns the plan into one extent per file (claims and syscalls exploding). |
| `every_file_sits_whole_inside_exactly_one_unit` | Coverage invariant over a mixed layout; no unit spans the big hole | Any cut that loses a file's bytes or double-claims a file: FNR and double-counting in one property. |
| `the_pre_plan_filter_leaves_holes_the_cut_never_reads` | 1 of 3 rejected → 2 units, **200 bytes read** out of 70,200 | The sparse read not being sparse: if the plan still spans the reject, the read is 70,200 and the assert fires. |
| `a_small_hole_is_read_rather_than_issued_around` | 1 KiB hole → 1 unit | A threshold applied in the wrong direction (splitting on every reject). |
| `a_rollup_under_a_foreign_fingerprint_is_never_rejected` | rollup record survives `rollup_ok = false`, falls with `true`; plain record falls both times | The FNR hole of v5: pruning a rollup the query cannot vouch for loses the units it never covered. |
| `the_ablation_rejects_nothing` | 1 rejected → 0 rejected under `set_ablate_extents(true)`, all survive | An ablation that changes answers instead of cost. |
| `the_extent_ablation_changes_the_plan_and_never_the_answer` (searcher) | `search_store` matches and `total_files_pruned` byte-identical with the ablation on/off; `pruned >= 1` fixture teeth | End-to-end divergence between the two arms, and a vacuous fixture the filter ignores. |

`total_files_pruned` is one count across the pre-plan and the per-file
filters: the same rule asked twice must report once, and a caller must not
care which point answered.

## `RGX_EXTENT_STATS`

`RGX_EXTENT_STATS=1` prints one stderr line at the end of the buffered search:

```
rgx-extents: read <bytes_read> bytes in <units_read> units (store payload <payload> bytes, <packs> packs)
```

Under `RGX_ABLATE_EXTENTS=1` the two sides of the fraction are equal — the
control arm of the follow-up A/B.

## Deliberate follow-ups

- **The 7-round rotated A/B is a separate phase** (count gate + ±3% CLI
  floor, per `AGENTS.md` §9). Nothing here claims a speedup number.
- The mmap path (`run_tv_query`, the `rgx` CLI) keeps its per-file filter and
  gains only the shared rule text; its bytes-not-read story is page faults,
  not syscalls, and the pre-plan's marginal win there is iteration count.
- `read_mode` selection is untouched; `ParallelBuffered` remains the default
  and the path the gap rule pays off on.
- The gap threshold is a named constant, not a tuned one: 64 KiB is argued
  in its comment (four pages, under one NVMe request). If the A/B shows the
  threshold mattering on the bench corpora, tuning it is one constant and
  one re-run.
