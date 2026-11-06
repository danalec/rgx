# rgx-adapters-archive examples

## Overview

Two one-off diagnostics, not API demos and not harnesses with a gate — the
crate's gated benches live in `benchmark/`. `crc32_bench_7z.rs` times the
7z slice-by-8 CRC-32 fold against the byte-at-a-time definition it is checked
against, over the payload sizes the 7z reader actually hashes (the fixture
`sevenz_multifolder.7z` is 24 KB on disk and expands to 107 MB, so the
per-member CRC runs over 107 MB — that is the row the fold has to move).
`decomp_bench.rs` measures decode throughput of the in-house codecs on real
corpora, minimum of N rounds, and for `.zst` times the libzstd reference in
the same process so the ratio is the honest headroom.

Neither example is published with the crate: the `Cargo.toml`'s `include` list
carries only `/src/**`, `/Cargo.toml`, `/README.md`, `/LICENSE-APACHE` and
`/NOTICE`. Both are declared as `[[example]]` targets with `required-features`
(`sevenz` for the CRC bench, `decompress` + `sevenz` for the decode bench),
because they reach into the codecs the adapter registry does not expose — a
bench that went through the registry would measure the pipeline instead of the
decoder.

## Interface
- `crc32_bench_7z.rs` — a `cargo run --release -p rgx-adapters-archive --example crc32_bench_7z` binary. It imports `rgx_adapters_archive::sevenz::crc32::crc32` and exports no library symbol.
- `decomp_bench.rs` — a `cargo run --release -p rgx-adapters-archive --example decomp_bench -- <file>... [--rounds N] [--check <plain>] [--dump <path>]` binary. It imports `rgx_adapters_archive::brotli::BrotliDecoder`, `rgx_adapters_archive::lz4::Lz4Decoder` and `rgx_adapters_archive::sevenz::SevenzArchive`, and exports no library symbol. Its own usage line names only `--rounds` and `--check`, but `--dump <path>` is accepted too and writes each decoded output to that path.
- `fn crc32_slow(data: &[u8]) -> u32` — the unoptimised CRC-32 definition, mirroring `sevenz/crc32.rs`'s own `crc32_slow`, the oracle the unit tests hold the optimised fold against.
- `fn bench(data: &[u8], label: &str)` — warms both folds, then takes the best of three rounds for each and asserts the two agree.

## Invariants
- The two CRC-32 implementations must agree; the bench asserts it on every round and fails the run if they disagree, because a fast bench that measures the wrong answer is not a measurement.
- `decomp_bench` runs its `--check` comparison *before* printing any timing: a decode that does not reproduce the plain file byte-for-byte is a failure, not a fast row.
- The decode bench decodes with an unlimited byte budget (`u64::MAX`), so the number it reports is throughput and not a truncation artefact.
- The round count is clamped to a minimum of three (`--rounds` below three is raised), because a minimum-of-N measurement needs at least three samples.
- The CRC bench takes the *minimum* of three timed rounds for each arm, so the number reported is the machine's floor rather than its noise.

## Side Effects
- Both read files from disk: `decomp_bench` reads the files named on the command line and, with `--check`, the plain file to compare against.
- `decomp_bench` allocates the decoded output of each input, which for the 7z fixture is the full 107 MB expansion.
- Neither spawns a process, takes a lock or opens a socket. `decomp_bench` writes a file when `--dump <path>` is given: the decoded output of each input goes to that path.
- Both print their measurements to stdout; `decomp_bench` prints one row per input (compressed size, decoded size, minimum ms, MB/s) and exits with status 2 when no input file was given.

## Verification
- Run: `cargo test --release --locked --workspace`
