# bin

## Overview
The `rgx-tv` command-line program: the front end of the pack store. It parses the arguments, calls into `rgx_core::tv_runtime::*`, and prints what the runtime hands back. It owns the argument grammar and the value parsers — `walk_filters`, `split_bundled`, `parse_threads`, `pin_threads`, `parse_lines`, `parse_claims` — and the output formatting (`print_stages`); the decisions live in `crate::tv` and the filesystem in `crate::tv_runtime`.

The Cargo manifest declares it as a `[[bin]]` named `rgx-tv` with `required-features = ["tv-runtime"]`: a build without the pack store does not carry this program at all.

Four subcommands: `build` ingests a directory tree into aggregated packs, `search` searches the packs while preserving file boundaries, `update` publishes a new generation incrementally, and `inspect` verifies the packs' CRC32 checksums and reports the store's statistics.

## Interface
- `fn main()` — the entry point; parses `std::env::args`, dispatches on the subcommand and exits with a status.
- `fn parse_size(s: &str) -> Result<u64, String>` — the `-M` / `--max-filesize` parser, with ripgrep's suffixes: a bare number is bytes, and so is an explicit `b`, `k`/`kb`/`kib` are 1024, `m`/`mb`/`mib` are 1024^2, `g`/`gb`/`gib` are 1024^3. The number is parsed as an `f64`, so a fractional size such as `1.5m` is accepted.
- `fn print_usage()` — the usage text on stderr.
- The options the program accepts: `--store <dir>` (required), `--pack-size-mb <N>`, `--max-depth <N>`, `-g`/`--glob <PATTERN>` (repeatable, gitignore-style), `--hidden`, `-L`/`--follow`, `--no-ignore`, `-j`/`--threads <N>`, `-c`/`--count`, `-n`/`--line-number`, `-A`/`--after-context`, `-B`/`--before-context`, `-C`/`--context`, `-a`/`--text`, `--engine <which>`, `-M`/`--max-filesize N`, `--validate`, `--mmap`, `--no-mmap`, `--serial-buffered`, `--packs-per-thread <N>`, `--pool` (the flag the runtime asks for explicitly), `--no-pool`, `--leak-mmap`, `--stats`, `-h`/`--help`, and `--compact` for `update`.
- Imported from the runtime: `build_store`, `inspect_store`, `search_store`, `search_store_pooled`, `update_store`, `BuildConfig`, `EngineMode`, `MappedStore`, `PoolLimits`, `ReadMode`, `SearchConfig`, `Unmap`.

## Invariants
- `--store <dir>` is required: there is no default store location.
- `-j` pins the thread count. The default is three quarters of the physical cores, opened up to every logical processor when the pack's own timings say the scan, not the copy, is the expensive half.
- `--engine` takes `auto` (the default) or `rgx`; both resolve to the in-house engine, `EngineMode::pick` having one answer left. The retired names `grep` and `both` still parse, resolve to the in-house engine and say so on stderr; there is no cross-check engine and no divergence report.
- `-n`/`--line-number` defaults to true in this program, unlike the engine's own `Config`.
- The program is a thin shell: every flag maps onto a `SearchConfig` or a `BuildConfig` field, and the answers that need a filesystem or a clock are the runtime's to give.
- Usage and argument errors go to stderr and the process exits nonzero; a search that finds nothing prints nothing and exits 0, and only an `Err` from the runtime exits 1 — there is no separate status for "no match", the way ripgrep has one.

## Side Effects
- Reads and writes the store directory through the runtime: pack files, the manifest, and the temporary file the atomic publish renames over the old manifest.
- Spawns worker threads for the search and joins them before returning.
- Reads the corpus tree on `build` and `update`, including `.gitignore`, `.ignore` and the parents' unless `--no-ignore` is given.
- Writes to stdout (the matches) and to stderr (usage, diagnostics and the notice that a retired `--engine` name is gone).

## Verification
- Run: `cargo test --release --locked --workspace`
