# rar-codec examples

## Overview

One diagnostic binary, not an API demo. `crc32_bench_rar.rs` times the shipped
slice-by-8 CRC-32 fold against the byte-at-a-time definition it is checked
against, over the payload sizes `Archive::extract` actually hashes. It is not
a harness with a gate: the tree carries no `benches/` directory and no
`[[bench]]` section, and `benchmark/` holds the engine's own measurement
harnesses, none of them about this crate's CRC-32. It exists to answer one
question on the machine being worked on: did the fold pay for itself.

The example is not published with the crate: the `Cargo.toml`'s `include` list
carries only `/src/**`, `/Cargo.toml`, `/README.md`, `/LICENSE-APACHE` and
`/NOTICE`, so this file exists only inside the repository.

## Interface
- `crc32_bench_rar.rs` — a `cargo run --release -p rar-codec --example crc32_bench_rar` binary. It exports no library symbol; `fn main()` is the whole entry point.
- `fn crc32_slow(data: &[u8]) -> u32` — the unoptimised definition, mirroring `crc32.rs`'s own `crc32_slow`, which is the oracle the crate's unit tests hold `rar_codec::crc32` against.
- `fn fill(n: usize) -> Vec<u8>` — deterministic filler (xorshift over a fixed seed, no RNG), so both arms see identical bytes and the comparison does not measure data layout.
- `fn time_ms<F: FnMut() -> u32>(rounds: usize, f: F) -> f64` — runs `f` `rounds` times after one discarded warmup round, and keeps the accumulator live through `std::hint::black_box` so nothing folds the calls away.

## Invariants
- The two CRC-32 implementations must agree on every input. The example prints both timings but never compares the two values, so the equality is enforced by the crate's unit tests rather than here.
- The filler is seeded from a fixed constant, so the bytes are identical on every run and on every machine; the measurement compares two algorithms, not two data sets.
- Exactly one warmup round is discarded before the timed rounds, so the first measured round does not pay the page-fault cost.
- The measured sizes are 4 KiB, 64 KiB, 1 MiB and 8 MiB, and the round count drops as the size grows -- 2000 rounds for the two sizes up to 64 KiB, 200 for the megabyte and 30 for the eight -- so the run stays bounded.

## Side Effects
- Reads no files, writes no files, spawns no processes, takes no locks and opens no sockets.
- Allocates the filler buffer once per size (up to 8 MiB) and holds it for the duration of that size's measurement.
- Prints a table of bytes / slow ms / fast ms / speedup / MB/s to stdout.

## Verification
- Run: `cargo test --release --locked --workspace`
