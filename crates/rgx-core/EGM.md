# rgx-core

## Overview
The engine crate of the `rgx` workspace. Every `rgx` adapter is written against the `Adapter` trait defined in `src/`, and `process()` is what turns a file into searchable units: it owns adapter resolution, recursion, depth limits, member caps and bail semantics, so those live in one place rather than once per adapter. The byte searches, the JSON arena and the pack store are here too.

The crate is `#![no_std]` + `alloc`; the `std` feature decides what else it may use, and what it turns on is the typed error chain, the profiler map, the `f64` JSON parser and the memory-mapping module. An embedder that wants to search its own files without the standard library can have the engine and the same vector kernels the full build uses — the CPU probe that picks the kernel is this crate's own, so the `no_std` build reaches the same AVX2 path the `std` build does.

The manifest is the crate's feature contract. `default` carries `std`, `sha256-hw`, the compression codecs and the ZIP reader (`zip`); the pack store (`tv`, `tv-runtime`) is *not* in `default`, because a binary that reads no pack store should not link its format tables. The `[[bin]]` `rgx-tv` carries `required-features = ["tv-runtime"]` for the same reason.

The published crate ships `/src/**`, the manifest, the README, the licence and the notice. The test corpus under `testdata/` is the repository's and not the crate's: a user of the crate has no use for it, and the examples are one-off diagnostics rather than API demos.

## Subdirectories & Boundaries
- `src`: [src](./src/EGM.md) — the crate root: the `Adapter` trait, the `Outcome`/`Ctx`/`Registry` pipeline, the search engines (regex, searcher, scan, VM) and the format subsystems (compression, JSON, crypto, memory mapping, pack store). Public symbols: `Adapter`, `Outcome`, `Ctx`, `FactsSink`, `Found`, `Registry`, `PathCandidates`, `Reach`, `Policy`, `process`, `normalize_encoding`, `Error`, `Result`, `Field`, `NoStdFloat`, `parse_decimal`.
- `examples`: [examples](./examples/EGM.md) — twenty-two one-off diagnostics that turn a claim about the engine into a measured number. Public symbols: one `main` per example; `anchor_probe`, `casefold_cost`, `confirm_profile`, `cost_sensitivity`, `dense_ablate`, `dense_pieces`, `density_probe`, `diodicity`, `json_accept`, `json_bench`, `json_dump`, `json_intern_bench`, `json_probe`, `memchr_bench`, `ngram_occ`, `pipeline_profile`, `scan_floor`, `sha256_bench`, `status_table`, `straight_probe`, `thread_curve`, `vm_probe`.
- `fuzz`: [fuzz](./fuzz/EGM.md) — the coverage-guided fuzzing package, its own workspace, with the seed corpus and the one target that drives the whole adapter registry.
