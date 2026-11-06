# scripts

## Overview

`scripts/` holds the project's own operational tooling: the gate that decides
whether a tree may be committed, the release pipeline that builds and publishes
the binaries, the generators that write the tables and fixtures the Rust crates
carry, the guards that keep the vendoring rules true, and the harnesses that
measure the engine against `rg` and against itself.

Every file here is a standalone command-line program — a `bash` script, a
PowerShell script, a Python script, or a single-file Rust program compiled with
`rustc`. Nothing in `crates/` compiles against anything in this directory; the
coupling runs one way and it runs by *name*. A generator writes a file into
`crates/` (`charset_table.rs`, `charset_mb_table.rs`, `charset_state_table.rs`,
`casefold_table.rs`, `brotli/tables.rs`), and the crate's own module header
names the script that wrote it so a reader knows the file is generated and what
regenerates it.

The directory is also where the platform twins live. Where a job has to run on
both Windows and Linux, the two files are `.sh` and `.ps1`, and they are held to
the same behaviour: the same inputs, the same output, the same exit code. The
full list of the pairs is in `AGENTS.md` §1.1. The pairs here are
`gate-and-count`, `commit-block`, `stamp-count`, `compare-rg`, `detect-ccd`,
`fetch-legacy-corpus`, `bench-linkers`, `check-vendoring`, `check-drift`,
`apply-vendored-edits`, `harvest-golden`, `smoke-serve`, `build-release`,
`publish-release`, `publish-cratesio` and `publish-homebrew`.

Two data files live here as well. `vendored-sources.tsv` is the ledger of the
upstream specification each vendored file was written from — tab-separated as
`rgx_path`, `upstream_source`, `upstream_commit`, `note` — and it is what
`check-drift` reads. `bench-results/` holds committed CSV transcripts of the
linker and small-file benchmarks; the harness that wrote them,
`scripts/bench.ps1`, is no longer in the tree.

## Interface

### The gate and the test count

- `bash scripts/gate-and-count.sh [--skip-tests]` · `powershell -File scripts/gate-and-count.ps1 [-SkipTests]` — runs `cargo fmt --all -- --check`, then `cargo clippy --release --locked --workspace --all-targets -- -D warnings`, then `cargo test --release --locked --workspace --no-fail-fast`; logs land in `target/gate/` and the run prints the line `COUNT: passed=… failed=… ignored=… suites=…`.
- `bash scripts/stamp-count.sh --agents AGENTS.md --workflow .github/workflows/ci.yml …` · `scripts/stamp-count.ps1 -Agents AGENTS.md -Workflow .github/workflows/ci.yml -Passed N -Ignored N` — writes the measured count into the working notes and into the workflow.
- `python3 scripts/suite-counts.py [path/to/test.log]` — the per-suite counts of a gate log; defaults to `target/gate/test.log`.
- `bash scripts/commit-block.sh --message <file> --files <a> <b> … [--patches <file>] [--note <text>] [--no-count]` · `scripts/commit-block.ps1 -Message <file> -Files <a> <b> …` — stages one block, stashes the others, runs the gate on that tree, stamps the count and commits.

### The vendoring guards

- `bash scripts/check-vendoring.sh` · `scripts/check-vendoring.ps1` — the four rules: no upstream reference in any manifest, no `[patch]` in `.cargo/config.toml`, a provenance header on every vendored tree, and no unlisted external crate. Exits 1 on any violation.
- `bash scripts/check-drift.sh --upstream <dir> [--pin] [--for <file>]` · `scripts/check-drift.ps1` — compares each vendored file against the upstream commit it was pinned to.
- `bash scripts/apply-vendored-edits.sh --files a.rs,b.rs [--whatif] [--alloc-to-std]` · `scripts/apply-vendored-edits.ps1 -Files a.rs,b.rs [-WhatIf] [-AllocToStd]` — re-applies the copy-time transforms after a re-copy from upstream.
- `scripts/vendored-sources.tsv` — the ledger the two guards share; a ledger that exists in two places with two wordings is a ledger that will say two different things.

### The release pipeline

- `bash scripts/build-release.sh [--skip-tests] [--version <v>]` · `scripts/build-release.ps1` — the shippable pair (portable x86-64 and znver4) into `.dist/local/`, each tarball packing `rgx` + `README.md` + `COPYING` + `LICENSE-APACHE` + `NOTICE`.
- `bash scripts/build-linux.sh <git-url> <ref> <out-dir>` — every Linux artifact, built entirely in Docker: the gnu and musl tarballs, the znver4 tarball, and the deb/rpm/apk/pacman packages.
- `bash scripts/package-linux.sh <src-dir> <gnu-bin> <musl-bin> <znver4-bin> <version> <out-dir>` — turns already-built Linux binaries into release artifacts, each install-verified in a container of its own distro.
- `bash scripts/release-all.sh [--skip-tests] [--dry-run] [--no-commit]` — the whole release in one command: gate → Windows zips → Linux over ssh → publish.
- `bash scripts/release-linux.sh [ref]` — pushes the ref (default `main`) to the forgejo, builds on the docker host with `build-linux.sh`, and copies the verified artifacts back to `.dist/`. The host comes from `RGX_RELEASE_HOST` and the forgejo from `RGX_FORGEJO_URL` and `RGX_FORGEJO_REPO`; the script needs only git, ssh and scp.
- `bash scripts/publish-release.sh [--skip-tests] [--dry-run] [--version <v>]` · `scripts/publish-release.ps1` — tags `rgx-v<version>`, pushes, and creates or updates the forgejo release with the assets.
- `bash scripts/publish-cratesio.sh [--publish] [--allow-existing]` · `scripts/publish-cratesio.ps1 [-AllowExisting] [-Attempts N] [-WaitSeconds N]` — publishes every workspace package to crates.io in dependency-graph order; the root package is `rgx-search` there, and the binary it installs is `rgx`.
- `bash scripts/publish-homebrew.sh [--version 0.1.0] [--dry-run]` · `scripts/publish-homebrew.ps1` — opens the homebrew-core pull request with the formula this repository carries.
- `bash scripts/push-github.sh [--push] [--public] [--flat]` — mirrors the release to GitHub; dry-run by default, and the Forgejo push happens first.
- `bash scripts/rewrite-digests.sh [tag]` — rewrites the digests and the version that `install.ps1` and `install.sh` pin, from the artifacts in `.dist/`.
- `python3 scripts/check-assets-licence.py [dist-dir]` — audits the licence documents inside every asset in `.dist/`; exits 1 when one fails.
- `python3 scripts/add-crates-metadata.py` — gives every publishable package its crates.io keywords and categories, checking the category slugs against the registry before writing.
- `python3 scripts/add-publish-versions.py` — adds the `version` requirement `cargo publish` demands to every internal path dependency, read from the manifests rather than typed.
- `python3 scripts/bump-version.py <version> [--check]` — sets the `version` of every published crate, the requirement of each dependency on one of our crates, and the `rgx-v<version>` tag in `install.sh`/`install.ps1` to one number; `--check` reports without writing, and the default refreshes `Cargo.lock` with `cargo update --workspace --offline`.
- `python3 scripts/sync-licence.py [--check]` — puts the tree's `LICENSE-APACHE` and `NOTICE` into every crate; `--check` reports, the default writes.

### Generators, corpora and fixtures

- `python3 scripts/make-corpus.py [--tiny] …` — the benchmark corpora, so a number is reproducible by someone else; `--verify` checks an existing one.
- `python3 scripts/make-log-corpus.py` — the log-partition corpus, the non-code shape.
- `python3 scripts/make-golden.py` — writes `tests/golden/` from source so the golden suite is never vacuous.
- `python3 scripts/make-pdf-fixtures.py` — writes the generated half of `crates/rgx-adapters-pdf/fixtures/`.
- `python3 scripts/gen_charset_tables.py` · `gen_charset_mb_tables.py` · `gen_charset_state_tables.py` · `gen_casefold_table.py` — write `crates/rgx-core/src/charset_table.rs`, the multi-byte tables, `charset_state_table.rs` and `casefold_table.rs`.
- `python3 scripts/gen-brotli-tables.py` — regenerates `crates/rgx-adapters-archive/src/brotli/tables.rs` from the RFC 7932 text.
- `python3 scripts/gen_xz_fixtures.py` — re-encodes the two xz fixtures under `crates/rgx-core/src/compress/xz/testdata` so the streams carry the current plaintext label.
- `python3 scripts/gen_zarr_fixtures.py` — the Zarr fixtures under `crates/rgx-adapters-tabular/testdata/zarr`, and the check that they are what they claim to be.
- `bash scripts/fetch-legacy-corpus.sh` · `scripts/fetch-legacy-corpus.ps1` — the legacy-format corpus, idempotent, into `tests/fixtures/legacy-formats/` only.
- `bash scripts/harvest-golden.sh [--out-dir /tmp/golden] [--pdf-dir ~/Documents]` · `scripts/harvest-golden.ps1` — real-world golden samples from this machine.
- `python3 scripts/harvest-ngram-corpus.py` — the n-gram benchmark corpus, so both hosts prune over one set of bytes.

### Measurement harnesses

- `bash scripts/bench-status.sh [options]` — the two tables of `benchmark/status.md`, from one command; every option is the harness's own.
- `bash scripts/bench-linkers.sh [--cpu znver4]` · `scripts/bench-linkers.ps1` — the system linker against `lld` and `lld-znver4`.
- `bash scripts/compare-rg.sh [--corpus crates]` · `scripts/compare-rg.ps1` — parity of rgx against ripgrep on a real corpus, flag by flag.
- `bash scripts/detect-ccd.sh [--cores-only]` · `scripts/detect-ccd.ps1` — CPU topology, for the thread sweeps.
- `bash scripts/diodicity.sh [--corpus <dir>] [--store <dir>]` — the multiplier the engine is spared; a ratio of 1.0 is a pipe, not a valve.
- `bash scripts/adapter-subset.sh [--corpus <dir>] [--probe <str>] [--jobs N]` — superset or subset, per adapter.
- `bash scripts/engine-sweep.sh --store <dir> [--rounds N]` — which engine is faster for which pattern, on one store. `--store` is required; without it the script exits 1.
- `bash scripts/mmap-ab.sh` — mmap against read on a large-file-only workload.
- `bash scripts/tv-matrix.sh [--store DIR] [--rounds N] [--batch N] [--threads 1,8,32] [--cells "pat|flag,…"] [--ref <arm>] [--arms <subset>] [--rm-store]` — the four independent axes of `rgx-tv search`.
- `bash scripts/tv-threads.sh --store <dir> [--pattern 'pub fn'] [--rounds N] [--arms 8,12,16,32] [--ref 32] [--mode <mode>] [--pool]` · `tv-ugrep.sh --store STORE --root CORPUS` · `tv-vs-rg.sh --store <dir> --root <corpus>` · `tv-usecase.sh [--corpus <dir>] [--keep] [--quick] [--no-gate]` · `tv-ablate.sh --store STORE --root CORPUS` — the thread sweep, the ugrep arm, the rg arm, the use-case row and the ablation.
- `bash scripts/tv-cold.sh --store STORE --root CORPUS [--pattern P] [--samples 5] [--threads N] [--sudo-password PW]` — the cold-cache protocol, on a host that has `drop_caches`.
- `python3 scripts/tv-parity.py` · `tv-diff-lines.py` · `tv-mutate.py --corpus DIR --store DIR --percent 1 [--pattern "fn main"] [--refreshes 3] [--rounds 7] [--threads 10]` — pack against direct parity, the line-level diff, and the mutation loop.
- `python3 scripts/bench-json-print.py [dense|wide] [rounds]` · `scripts/axis-diff.py --root DIR --store DIR [--pattern P] [--vs rg|direct]` — `--json` against the text path, and the per-file count comparison between two search axes.
- `rustc -O --edition 2021 -o walk_patterns scripts/walk_patterns.rs` · `walk_phase.rs` — single-file Rust probes that split a walk into its phases.

### Smaller tools

- `bash scripts/smoke-serve.sh <dir>` · `scripts/smoke-serve.ps1 <dir>` — ask the `--serve` mode the same question two ways.
- `python3 scripts/split-shared-docs.py <file> <block>=<kw1>|<kw2> … [--marker <block>:<text>] [--out <directory>]` — cut the diff of a shared document into per-block patches.
- `python3 scripts/map-floats.py` — map float placement from a LaTeX `.aux` file.

## Invariants

- A `.sh`/`.ps1` twin pair must behave identically: the same inputs, the same output, the same exit code. A pair that drifts is a bug in one of them.
- The gate is the authority on the test count, and the count is measured on the tree the commit carries — the caller stashes the later blocks before calling and pops the stash after.
- `check-vendoring` exits 1 on any of its four violations, and the list of known-remaining external crates is the ledger of what is left to remove: a newly added crate fails the check.
- A release never publishes an artifact whose digest is not pinned, and a pin that cannot be written is an error rather than a stale pin left in place.
- **The count gate stands in front of every timing.** An arm whose count
  disagrees with the other arm prints no timing at all: `bench-linkers.sh`
  and `tv-threads.sh` withhold the row. `tv-matrix.sh` is the exception —
  it sets a failure flag, prints its rows anyway, and ends with the line
  that says the table is not quotable.
- **The floor here is a percentage band.** The spawn floor measured first
  and subtracted from both sides is `benchmark/extent-ab.sh`'s protocol,
  not one of this directory's: `tv-matrix.sh` and `tv-threads.sh` use
  ±2%, the `bench-status.sh` harness ±3% for the CLI and ±2% for the
  in-process number, and `walk_phase.rs` prints the spawn floor as a third
  arm without subtracting it. Inside the band the verdict is a tie, and a
  winner is named only when every sample of one arm sits below every
  sample of the other.
- A generator writes its output where the crate's module header says it lives, and the header names the script that regenerates it.
- Scripts resolve the repository root from their own location rather than encoding a home directory. `mmap-ab.sh` is the exception: it is an ad-hoc local probe with absolute `$HOME` paths.
- A script that fetches from the network writes only inside the directory it names — `fetch-legacy-corpus.sh` writes only inside `tests/fixtures/legacy-formats/`.
- Nothing is written into the repository by a measurement run: the transcript goes to the system temp directory and the path is printed, so a run can be pasted into a transcript without dirtying the tree.

## Side Effects

- Writes into `target/gate/` (`fmt.log`, `clippy.log`, `test.log`) and into `target/` generally, through `cargo`.
- Writes generated Rust into `crates/`: the charset tables, the state tables, the casefold table and the brotli tables.
- Writes fixtures into `crates/rgx-adapters-pdf/fixtures/`, the Zarr and xz fixtures, `tests/golden/`, and the downloaded legacy corpus into `tests/fixtures/legacy-formats/`.
- Writes release artifacts into `.dist/` and `.dist/local/`, and rewrites the pinned digests in `install.ps1` and `install.sh`.
- Writes transcripts into the system temp directory.
- Writes `LICENSE-APACHE` and `NOTICE` into every crate under `crates/`.
- Spawns `cargo`, `git`, `docker`, `ssh`, `scp`, `sudo`, `curl`, `gh`, `perl`, `python3` and the `rgx`/`rgx-tv` binaries. No script here spawns `rustc`: `walk_patterns.rs` is compiled by hand, with the command in its own header.
- Reaches the network: the crates.io registry, GitHub, the forgejo instance, homebrew-core, `www.unicode.org`, `www.rfc-editor.org`, and the two public corpus hosts.
- Leaves no Python bytecode cache behind: every script here imports the standard library only and none imports a sibling module, so a run writes no `__pycache__/` and no `*.pyc` (both patterns are gitignored anyway).

## Verification

- Run: `cargo test --release --locked --workspace`
- The scripts that gate the tree are themselves the check: `bash scripts/gate-and-count.sh` and `bash scripts/check-vendoring.sh`.
