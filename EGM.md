# rgx Blueprint

## System Overview

`rgx` is a line-oriented search tool that reads **inside** files: PDFs,
office documents, archives, 3D models, LLM checkpoints, databases,
e-mail and media metadata. It keeps ripgrep's interface -- the same
flags, the same exit codes (0/1/2) -- so it drops into any `rg`
workflow unchanged, and the difference from a plain `rg` is that every
adapter runs in the search process: a byte slice in, searchable text
out, with no subprocess per file and no IPC.

The tree is a workspace of twelve libraries and two binaries. The first
(`src/`) owns the command-line grammar, the walk, the sinks and the
protocol modes; the engine (`crates/rgx-core`) owns the adapter
contract, the byte-search kernels, the JSON arena and the pack store;
the adapter families own the formats. The second is `rgx-tv`, the pack
store's own CLI: a bin target of `crates/rgx-core` rather than a package
of its own, so `cargo build --release --workspace` links it and a build
of the root package alone does not. `scripts/` holds the gate and
the release pipeline, `benchmark/` the measurements and the harnesses
that produced them, and `Formula/` the Homebrew formula.

## Local Interface & Invariants

The root holds two pieces of code of its own besides the binary package:
`install.sh`, the Linux/FreeBSD installer, and `install.ps1`, its Windows
twin. The two are held to the same behaviour: download a release archive,
verify its SHA256 against a digest pinned in the script, unpack `rgx` into
an install directory and prepend that directory to the user's PATH.

- `bash install.sh [--channel gnu|musl|znver4|freebsd] [--install-dir DIR]
  [--base-url URL] [--version TAG] [--skip-checksum]` -- downloads the
  release tarball of the channel, verifies its SHA256 against the digest
  pinned in the script, unpacks `rgx` into the install directory
  (`$HOME/.local/bin` by default) and prepends that directory to the
  user's PATH. An unknown option or an unknown channel is refused with exit
  status 2 (`install.sh`, `case "$1"` / `case "$channel"`).
- `powershell -File install.ps1 [-Channel x64|znver4] [-InstallDir DIR]
  [-BaseUrl URL] [-Version TAG] [-SkipChecksum]` -- the Windows twin.
  `-Channel` is constrained by `ValidateSet`, `-Version` defaults to the
  pinned `rgx-v0.1.10`, and `-SkipChecksum` is the one switch that can
  install an artifact the script cannot vouch for (`install.ps1`, `param`
  block).
- The digest of each channel's asset is pinned in the script -- four
  uppercase-hex SHA256 values in `install.sh` (`EXPECTED`), two in
  `install.ps1` (`$expected`) -- and `scripts/release-all.sh` rewrites
  those pins from the artifacts it has just built and refuses to finish
  when the rewrite did not move. A hand-maintained table is a table that is
  wrong the day after the release.
- The channels are the four Unix artifacts the release carries: the glibc
  build, the static musl build, the Zen-4 tuned one and the FreeBSD build.
  `gnu` is the default everywhere except on a FreeBSD host, where
  `uname -s` selects `freebsd` (`install.sh`, `channel`). The Zen-4 build
  runs only on a Zen-4 CPU; the generic one runs anywhere.
- Verification is enforced unless `--skip-checksum` / `-SkipChecksum` is
  given: the digest is computed with `sha256sum`, `sha256 -q` or
  `shasum -a 256` on Unix and with `Get-FileHash -Algorithm SHA256` on
  Windows, and a mismatch is refused before anything is unpacked.

## Subdirectories & System Boundaries

- `src`: [src](./src/EGM.md) — `src/` is the root binary package of the rgx workspace — the `rgx` command itself. The crate is published as `rgx-search` because `rgx` is taken on crates.io; the binary it installs is `rgx`.

- `crates`: [crates](./crates/EGM.md) — `crates/` holds the workspace's twelve libraries: the engine, the RAR codec, and the ten adapter families that turn a file into searchable text.

- `scripts`: [scripts](./scripts/EGM.md) — `scripts/` holds the project's own operational tooling: the gate that decides whether a tree may be committed, the release pipeline that builds and publishes the binaries, the generators that write the tables and fixtures the Rust crates carry, the guards that keep the vendoring rules true, and the harnesses that measure the engine against `rg` and against itself.

- `benchmark`: [benchmark](./benchmark/EGM.md) — `benchmark/` holds the measurements that shaped the code and the harnesses that produce them.

- `Formula`: [Formula](./Formula/EGM.md) — `Formula/` holds the Homebrew formula that installs the project on macOS. The formula is `rgx.rb`, a single Ruby file that `brew` reads: it names the release archive to download for each architecture, the digest of that archive, and the binary to install out of it.

## Global Invariants

- The exit codes are ripgrep's: 0 for a match, 1 for no match, 2 for an error. A file an adapter cannot read is not an error of the search.
- An adapter is a synchronous function over a byte slice: no async, no streams, no subprocess in the core model, and it never recurses itself. `rgx_core::process` owns the depth limits, the member caps and the bail semantics, so they live in one place.
- A member's path is `<the container's path>!<the member's name>`. The `!` is the member separator, and the path is logical rather than a path on disk, so a member's own name can hold a `/`.
- A hard failure renders a searchable `[rgx: adapter 'x' failed: ...]` note beside the file's own bytes, never as a replacement of them.
- A decline and a failure are not the same answer. A decline is silent and continues the chain; a failure mints a note that only becomes a unit if nothing later answers.
- A file's own bytes stay searchable. A decoder that finds nothing is not an empty decode, and a format the adapter declines falls back to the raw bytes rather than vanishing.
- The engine is `no_std` plus `alloc`. The `std` feature turns on the typed error chain, the profiler map and the `f64` JSON parser, and nothing else that matters; the vector kernels are chosen at runtime by the crate's own CPU probe, so the two configurations reach the same kernel on the same machine.
- Every crate of the workspace is a path dependency inside this tree. The external crates are not nothing: `scripts/check-vendoring.sh` enumerates the ones the tree still reaches for, refuses any external crate that is not on the list, and prints what each of them is to be replaced by.
- `rgx --version` lists the formats the build carries, read from the `format-*` features themselves, so the list cannot drift away from the binary.
- The gate is the same everywhere: `cargo fmt --all -- --check`, `cargo clippy --release --workspace --all-targets -- -D warnings` and `cargo test --release --locked --workspace`. The workflow runs the test line without `--no-fail-fast`; the local gate scripts add it, so one failing suite does not hide the rest.

## Global Side Effects

- Reads the corpus, the `.rgxrc` file, the git ignore files, and the bytes of every file it searches.
- Writes the token index (`.rgx-idx.ugi`), the facts index (`.rgx-facts.jsonl`), the cache entries and the pack store under the target directory. A cache entry is written to a temporary and renamed into place.
- Deletes cache entries on `--cache-clear` and `--cache-prune`.
- Spawns the external picker on `--pick` -- the first of `fzf`, `sk`, `peco`, `fz` found on `PATH` -- and, through the docs family, the office binary (`soffice` or `libreoffice`), `tesseract` and a rasteriser (`pdftoppm` or `pdftocairo`), but only when their binary is on `PATH` *and* a matching file was found.
- Consumes stdin in `--serve` and `--mcp` mode, one JSON document per line.
- Writes the matches to stdout, and the diagnostics, the warnings, the `--explain-engine` rationale and the engine tally to stderr.

## System Verification

- Run: `cargo test --release --locked --workspace`
