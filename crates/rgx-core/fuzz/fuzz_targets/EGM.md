# fuzz_targets

## Overview
The coverage-guided fuzz target for the adapter pipeline. libFuzzer steers arbitrary bytes through every registered adapter by rotating the claimed extension — the first byte of the input picks it — so the deep parser states that the deterministic mutator cannot reach are explored.

The failure modes under test are panics, index-out-of-bounds and hangs: `process` must never propagate them. The target drives the *full* registry, not a subset, because the fuzzer is the only thing in the tree that pushes bytes no fixture ever produces through the parsers.

## Interface
- `fn adapters() -> Vec<Box<dyn rgx_core::Adapter>>` — every adapter the target drives, in one list: the ten families' `adapters()` functions — archive, office, threed, llm, media, tabular, docs, mail, inspect and pdf.
- `fn parts() -> (&'static rgx_core::Registry, &'static [&'static str])` — the registry and the extension list, built once in a `OnceLock` out of that one adapter list: the extensions are collected from the adapters themselves, sorted and deduped.
- `fn registry() -> &'static rgx_core::Registry` and `fn extensions() -> &'static [&'static str]` — the two halves of `parts`, handed out.
- `fuzz_target!(|data: &[u8]| { ... })` — the target itself: byte 0 selects the extension, the rest is the payload, and the whole `data[1..]` goes through `rgx_core::process` with `max_depth: 4`, `max_members: 256` and `max_file_size: 1 << 20`.
- The Cargo target is declared as `[[bin]] name = "process"`, `path = "fuzz_targets/process.rs"`, with `test = false`, `doc = false` and `bench = false`.

## Invariants
- **Every adapter the registry can reach by extension is driven, by construction.** The extension list is derived from the same adapter list the registry is built from, so there is no second copy to drift: the two hand-written lists that used to sit beside each other named 206 extensions while the registry reached 443, and the fuzzer is the only thing in the tree that drives the parsers with bytes no fixture ever produces.
- The first byte of the input selects the extension and the *rest* is the payload; the payload never includes the selector.
- An empty input returns immediately — there is nothing to drive the parsers with.
- The output is touched with `std::hint::black_box(out.len())` so the unit extraction is not dead-stripped and the coverage the target is there to collect is actually collected.
- The target must never panic, index out of bounds or hang; the pipeline's depth, member and size limits are what keep a hostile input from becoming an unbounded walk.
- The target is built with `cargo +nightly fuzz run process -- -max_total_time=300`, which needs a nightly toolchain; the crate itself is `publish = false` and carries its own `[workspace]` so it is not part of the main build.

## Side Effects
- Writes crash artefacts and the corpus under the fuzz target's own `target/` directory and `corpus/` directory, which is why `**/fuzz/corpus/**` is marked `-text` in the root `.gitattributes`: the seeds are byte-for-byte inputs to a decompressor, and a CRLF rewrite would change the offsets the parsers are tested against.
- Reads and writes the corpus directory the fuzzer is pointed at; it touches nothing else in the repository.
- The `OnceLock` registry and extension list are built on the first call and kept for the life of the process.

## Verification
- Run: `cargo test --release --locked --workspace`
- Fuzz: `cargo +nightly fuzz run process -- -max_total_time=300`
