# AGENTS.md — working notes for rgx

`rgx` is a line-oriented search tool that reads **inside** files: PDFs, Office
documents, archives, 3D models, LLM checkpoints, databases, e-mail, media
metadata. It keeps ripgrep's interface — same flags, same exit codes
(0/1/2) — so it drops into any `rg` workflow unchanged.

The difference from `ripgrep-all`: **every adapter runs in the search
process.** Byte slice in, searchable text out. No subprocess per file, no IPC,
no mandatory cache.

Rust, edition 2021, `rustc`/`cargo` 1.98.1. Licensed under Apache-2.0 only.
**All prose in this repository is English.**

## Setup commands

Quick reference; §1 carries the reasoning behind each line and the full gate.

- Install deps: `cargo build` (Windows needs `winget install LLVM.LLVM` — the repo links with `lld-link`)
- Start dev:    `cargo run --release -- <pattern> <path>`
- Build:        `cargo build --release`
- Test:         `cargo test --release --locked --workspace`
- Lint:         `cargo fmt --all -- --check` and `cargo clippy --release --workspace --all-targets -- -D warnings`

`src/` holds the binary (`main.rs` ~5.4k lines: `Args`, the `app()` grammar,
sinks, walk driver, adapter dispatch, `--serve`, output formatting) plus
`engine.rs`, `walk.rs`, `detector.rs`, `cache.rs`, `mmap.rs`, `pick.rs`, `rc.rs`
(the `.rgxrc` loader) and the vendored parser in `cli/`. `crates/` holds
`rgx-core` (the engine, the `Adapter` trait, the token index and the TV pack
format), `rar-codec`, and ten `rgx-adapters-*` families — see `crates/` for the
per-family line and `benchmark/` for findings.

## The Elephant & Goldfish Model

The EGM skills run here: `egm-brainstorm` writes a concepts brief,
`egm-draft` turns the brief into a design document, `egm-review` puts that
document in front of a Goldfish, `egm-resolve` applies what is worth
applying, and `egm-drift-report` checks a document against the code it
describes. The artifacts of that loop -- the brief, the draft, the review
report -- go into one folder, and so do the design documents themselves.
Neither is source, and neither is history:

EGM artifact directory: .egm

Both folders are in `.gitignore` (`.egm/` and `docs/designs/`): the
Elephant's output is a working document, and a working document that is
committed becomes a second source of truth to keep in step with the code.
What belongs in the tree is what the code says about itself -- the module
headers, these notes, the `MANUAL.md` -- and that is where the conclusion
of a design goes once it is a decision about the code.

`egm-bootstrap` is the exception, and it is a dangerous one here: it
**writes** the `README.md` of every directory it walks, and this
repository's READMEs are written by hand -- the root one is the front door
of the project, and `tests/crate_readmes.rs` holds every adapter crate's
claims against its own registry. Run it with a `target_filename` of
`EGM.md`, or not at all.

---

## 1. Build and test

```bash
winget install LLVM.LLVM        # one-time on Windows: the repo's linker
cargo build --release           # everything
cargo build --no-default-features                     # engine-only
cargo build --release --features adapters-archive      # one family
```

`.cargo/config.toml` points `x86_64-pc-windows-msvc` at `lld-link` and
deliberately carries **no** `-C target-cpu`; the znver4 build is a release-script
variant only.

The gate, exactly as `.github/workflows/ci.yml` runs it:

```bash
cargo fmt --all -- --check
cargo clippy --release --workspace --all-targets -- -D warnings
cargo test --release --locked --workspace
```

Plus the follow-on jobs that must pass on every push:

```bash
cargo build --release --no-default-features
cargo test --release --locked -p rgx-core --no-default-features --lib
cargo build --release --locked -p rgx-core --no-default-features --target x86_64-unknown-none
cargo test --release --locked --workspace --features mimalloc
```

**The `no_std` configuration is now gated, and it is gated four ways.** The
build alone was never a gate: it proved the tree compiles, not that the tree
is `no_std`, and not that the configuration an embedder gets is the one the
tests ran in. So the job also runs `rgx-core`'s own suite with `std` off,
builds the engine for `x86_64-unknown-none` -- a target with no operating
system under it and therefore no `std` to link -- and builds the `sha256-hw`
combination with `std` off, because a feature of its own can put `std` back
into a build that asks not to have it (§12). A dependency that reaches
for `std`, directly or through a feature someone forgot was on, fails there
and nowhere else. That target is what caught the `regex` dev-dependency
(§12): its `std` feature turns on `memchr/std`, and Cargo unifies features
across the whole graph, dev-dependencies included, so the `no_std` *test*
build was a `std` build wearing a `no_std` name.

**The gate was run off Windows too.** The `no_std` port was verified on
FreeBSD 15.1 — the machine this repository uses for the Unix paths — with the
whole gate (`fmt`, `clippy -D warnings` and the workspace suite) and the three
`no_std` steps with it, on the tree a Unix runner checks out: the index blob
verbatim, `git checkout-index -a -f` with `core.autocrlf=false`, and the proof
that it is in that state is `git diff --name-only` naming the changes and
nothing else (§12). The `macos-15` job of the matrix is aarch64, and its
compile was reproduced locally rather than assumed:
`cargo clippy --release --workspace --all-targets --target aarch64-unknown-linux-gnu -- -D warnings`,
with `zig cc` standing in for the cross C compiler that `libsqlite3-sys` and
`zstd-sys` need. Two things about that check are worth writing down. The `cc`
crate takes the compiler from `CC_<target>` but does not pass arguments
through, and it adds its own `--target=<rust triple>`, which `zig` does not
parse — so the wrapper rewrites the flag. And the FreeBSD box's `pkg` build of
rust ships only `wasm32-unknown-unknown` and `x86_64-unknown-freebsd`: the
bare-metal target is not among them, so the proof of `no_std` needs a `rustup`
on that box, exactly as the CI installs one.

**The gate was run on Linux too.** The `no_std` port was verified on a
Linux/glibc box on a tree that is *provably* the working tree: a `git clone`
checks out the blobs, and the blobs hold LF, and the working-tree changes
arrive as a patch that `git` itself writes with LF. There is no line-ending
normalisation script to get wrong this time, and the proof is that every
modified file is sha256-identical to the Windows one once the carriage
returns are taken out of it, and every binary fixture is sha256-identical to
its blob. The legacy corpus is not in the repository -- a `.gitignore` keeps
it out of every clone -- so `scripts/fetch-legacy-corpus.sh` has to run before
the tests: fourteen of them fail without it, and they fail loudly rather than
skipping (§12).

**The Linux gate needs a PowerShell on the box.** `tests/count_note.rs`
runs the Windows twin of `scripts/stamp-count.ps1` over the same notes
the shell twin writes, because the pair is the thing under test: the two
have to write the same bytes, and a note that lands in a different place
on each of them is a note that is wrong in one of them. The GitHub
runners carry `pwsh` on the three platforms, so the CI never sees this,
and a Linux box without it fails seven tests that are about the pair and
not about the box -- a panic from `tests/count_note.rs`, seven of them,
and a count that is seven short. The PowerShell 7 tarball installs per
user without root: unpack it under `~/.local/pwsh` and put a `pwsh`
symlink in a directory the PATH of a non-interactive shell already has
-- `~/.local/bin` is in `.bashrc` and `.zshrc` and is not in it, and
`~/.cargo/bin` is.

**The aarch64 job was run, not only compiled.** The matrix's `macos-15` runner is
aarch64, and a cross-built aarch64 Linux is the closest thing to it that this
workstation can produce. The whole workspace's test binaries are built with
`cargo zigbuild --release --locked --workspace --target aarch64-unknown-linux-musl --tests`
and run under `qemu-aarch64` through the kernel's `binfmt_misc`, which makes the
emulated process the real one. Three things about that run are worth writing
down, because none of them is visible in the compile. `cargo-zigbuild` rather
than `cargo build`: rustc asks the linker for `-Wl,--fix-cortex-a53-843419`, an
lld relaxation fix-up that zig's lld does not know, and the link dies on a flag
that only exists to relax Cortex-A53 branch offsets. `env!("CARGO_MANIFEST_DIR")`
and `env!("CARGO_BIN_EXE_rgx")` are baked with the *build* machine's paths, and a
Windows path is one relative path component on Linux -- the backslashes are
ordinary characters -- so the tree has to be reachable under those literal names,
and the run has to start from the directory that holds them. And `Command::new`
with such a name is a PATH lookup rather than a path, so the work directory also
has to be on the PATH; without it every test that spawns the binary fails with
"No such file or directory", which reads like a missing build and is not one.

**`--workspace` on the test line is load-bearing.** Without it cargo builds
only the root package — `workspace_default_members` is just that one — so the
other 12 crates are compiled by clippy and never run.

Feature names mirror crate names; all ten `adapters-*` are in `default`.
`rgx-core`'s `std` feature turns on the typed error chain, the profiler map
and the `f64::from_str` JSON parser, and nothing else that matters: the
vector kernels are chosen at *runtime* by the crate's own CPU probe
(`crates/rgx-core/src/detect.rs`), so the `std` and the `no_std` build reach
the same kernel on the same machine (§5, §12). **`mimalloc` is OFF by
default** — the median gain is small and the variance is large on the bench
machine — opt in with `--features mimalloc`.

### 1.1 The platform pairs

Every script that does a job on Windows has a `.sh` twin that does the same
job on Linux, and the two are held to the same behaviour: the same inputs,
the same output, the same exit code. The Linux script is the one the CI's
Linux runs and the one the box runs; the PowerShell one is the same step on
Windows. A pair that drifts is a bug in one of them, and the table below is
the list to keep in step.

| script | what it does |
|---|---|
| `scripts/gate-and-count.sh`, `scripts/gate-and-count.ps1` | `fmt`, `clippy` and `test` over the workspace, and the line `COUNT: passed=… failed=… ignored=… suites=…` |
| `scripts/commit-block.sh`, `scripts/commit-block.ps1` | the commit of one block: the files and the hunks are staged, the other blocks are stashed, the gate runs on that tree, the count goes into the notes, and the commit is made |
| `scripts/stamp-count.sh`, `scripts/stamp-count.ps1` | the count of the tests, and the note that says what it was taken after, in the working notes and in the workflow |
| `scripts/compare-rg.sh`, `scripts/compare-rg.ps1` | rgx against ripgrep over a pattern corpus, flag by flag |
| `scripts/detect-ccd.sh`, `scripts/detect-ccd.ps1` | the CCD detector, over a corpus of images |
| `scripts/fetch-legacy-corpus.sh`, `scripts/fetch-legacy-corpus.ps1` | the legacy corpus, fetched once and reused |
| `scripts/bench-linkers.sh`, `scripts/bench-linkers.ps1` | the linker bench |
| `scripts/check-vendoring.sh`, `scripts/check-vendoring.ps1` | the four vendoring rules: no upstream in a manifest, no `[patch]`, a provenance header on every vendored tree, and no unlisted external crate |
| `scripts/check-drift.sh`, `scripts/check-drift.ps1` | each vendored file against the upstream commit it was pinned to |
| `scripts/apply-vendored-edits.sh`, `scripts/apply-vendored-edits.ps1` | the copy-time transforms, re-applied after a re-copy from upstream |
| `scripts/harvest-golden.sh`, `scripts/harvest-golden.ps1` | the real-world golden samples, harvested from the machine |
| `scripts/smoke-serve.sh`, `scripts/smoke-serve.ps1` | the `--serve` mode, asked the same question two ways |
| `scripts/build-release.sh`, `scripts/build-release.ps1` | the local release build: the gate, then the portable and the znver4 artifacts |
| `scripts/publish-release.sh`, `scripts/publish-release.ps1` | the release pipeline: build, tag, publish, upload the assets |
| `scripts/publish-cratesio.sh`, `scripts/publish-cratesio.ps1` | every package of the workspace to crates.io, in the order the dependency graph asks for, at the version of the root |
| `scripts/publish-homebrew.sh`, `scripts/publish-homebrew.ps1` | the homebrew-core pull request: a branch, a commit and the pull request |
| `install.sh`, `install.ps1` | the installer: download, verify, unpack, put it on the PATH |
| `benchmark/extent-ab.sh`, `benchmark/extent-ab.ps1` | the extent-sparse A/B, with the count gate in front of every timing |

Two of the pairs carry a difference that is not a port detail but the shape
of the platform, and both say so in their own header: the winget manifests
are the Windows package manager's, so `publish-release.sh` leaves them to
`publish-release.ps1`; and the golden samples come from the machine's own
files, so `harvest-golden.sh` takes them from the Linux equivalents of the
places the Windows script takes them from.

---

## 2. Architecture — do not break

**The adapter contract** (`crates/rgx-core/src/lib.rs`):

```rust
pub trait Adapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn extensions(&self) -> &'static [&'static str];
    fn available(&self) -> bool { true }          // false when a binary is missing
    fn reach(&self) -> Reach { Reach::Reveal }
    fn reach_needs_bytes(&self) -> bool { false }
    fn reach_for(&self, data: &[u8]) -> Reach { self.reach() }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome>;
}

pub enum Outcome {
    Text(Vec<u8>),                     // searchable text
    Members(Vec<(String, Vec<u8>)>),   // recursed by the pipeline, not by you
    Bail(String),                      // "not my file" — try the next adapter
}
```

- Adapters are **sync functions over byte slices**. No async, no streams, no
  subprocess in the core model. The only external tools are in
  `rgx-adapters-docs`, and spawn only when their binary is on `PATH` *and* a
  matching file is found.
- Adapters **never recurse themselves**. `rgx_core::process` owns depth
  limits, member caps and bail semantics so they live in one place.
- **A member's path is `<the container's path>!<the member's name>`.** The `!`
  is the member separator, and the path is logical rather than a path on
  disk: a member's own name can hold a `/` (`docs/report.pdf`), so a
  slash-joined path cannot say where the member lives. `basename_of` and
  `ext_of` cut at the `!` too, which is what lets the **member's** extension
  decide the adapter. §12 has what forgets this, and how quietly it forgets.
- `Registry` indexes by extension, so resolution is O(candidates for this
  extension).
- A hard failure renders a searchable `[rgx: adapter 'x' failed: …]` note
  **beside** the file's own bytes, never as a replacement. (Lesson of
  ripgrep-all issue #151.)
- **`Outcome::Bail` and `Err` are not interchangeable.** Every extractor
  declines with `decline!`, and `decline!` arrives at `process` as an `Err`
  marked `Link::Decline` — so the two arms must differ, or a file an adapter
  merely found nothing in loses its bytes. They differ in exactly three ways,
  and all three are load-bearing: **`Err` holds its note and continues the
  chain** (it is a claim about one adapter, not about the corpus), while a
  decline is silent and also continues. The note becomes a unit only if
  nothing later answers, so a note dropped because a later adapter *did*
  answer is correct. And **neither arm may stop the chain**: that is what let
  the media crate's single-page TIFF reader refuse a two-page file "so the
  chain walker could answer it" and thereby shadow the very reader it was
  deferring to.
- **A header reader says what it did not read.** The JPEG XL adapter
  cannot report the dimensions: they live in the codestream's size header,
  which is entropy-coded, and a reader that invented them would be worse
  than one that says nothing. So the file says `dimensions: not read (the
  codestream's size header is entropy-coded)` — the same rule the flat
  files follow, where a rendering is only worth writing when it makes a
  match the file's own bytes cannot make. A picture's pixels are never
  decoded: the header is the payload, and what the header does not say is
  not in the answer.
- **`decline!` versus `bail!` is a judgement about the file, not about the
  parse.** `decline!("not an OLE Compound File (bad magic)")` is this adapter
  stepping aside from a file that is some other format — an ordinary event
  that must not put a line in the corpus that is not in the file, and must
  not mint a note. `bail!("CFB: FAT sector 3 truncated")` is a file that *is*
  a Compound File and could not be decoded, which is exactly what a note is
  for. Roughly 40 sites are declines (magic and version checks); the rest are
  failures. `Error::is_decline()` looks for the marker in the whole chain,
  not only the head, because `.context()` puts the new message on the head
  and pushes the old one down — a decline that has been given context is
  still a decline.
- **`process` returns `true` only when the sole unit it appended is the file's
  own bytes.** An adapter that reported a failure produced a record, so the
  return is `false` and the caller searches the units — reading it off "is
  the last unit raw?" instead would make every note a silent downgrade.
  **The skip note counts.** A file whose claimant needs an external tool that
  is not on PATH gets `[rgx: adapter 'x' skipped: its external tool is not on
  PATH]` beside its bytes, so it has two units and the return is `false`. It
  used to be `true`, and every caller reads `true` as "the units are the
  file's own bytes, search it raw instead" — so the note was built, appended
  and dropped on the floor, and `rgx` on a `.pub` file with no `soffice` said
  nothing about the tool. A note nobody can see is a note that was not
  written.
- **A decoder that finds nothing is not an empty decode.** `GzipReader`
  walks `while pos < len && is_gzip(rest)`, so non-gzip bytes return `Ok`
  carrying *nothing* rather than an error, and `Members([(inner, [])])` then
  hands the pipeline an empty member: the file vanishes with no match and no
  reason. `Decompress` therefore checks each suffix's magic at the adapter
  boundary and `bail!`s — that is the "not my file" answer, and it is what
  lets the raw bytes stay searchable. Brotli is the one exception RFC 7932
  excuses: it has no magic to check.
- **`Registry::may_claim` says *may*, not *does*** — an adapter whose answer
  depends on the bytes cannot be answered before the read, and answering "no"
  would be the subset property on `.pem`.
- **A key is proved before it is used.** The PDF standard security handler
  (`crates/rgx-adapters-pdf/src/security.rs`) derives a file key and then
  *checks it against the file's `/U` entry* before decrypting anything. A
  document whose `/U` does not reproduce is declined, not decrypted: a wrong
  key yields bytes that pass every structural check and read as text, so
  nothing downstream could tell a page of mojibake from a page of prose. This
  is why `PdfError::Security` exists next to `Outcome::Bail` — a refused
  password is an answer, not a gap.
- **The key derivation, the fax and the JBIG2 decoders each have rules
  where the obvious reading is wrong.** Three of them, and each cost a wrong
  answer that looked like a corrupt file rather than like a bug: RC4 mixes
  the object number like AES does (only the AES revisions mixing is the
  common claim, and it is false); AES-128 appends the literal `sAlT` to the
  *running* hash, not to its output; and `/V` 5 uses the file key as is.
  Each was settled by measurement against libqpdf 12.4.2. A CCITT scan and a
  JBIG2 page are both *programs* — against the previous row, and against a
  template and a dictionary of glyphs — so a wrong decode is not garbage but
  a plausible page, shifted or with the wrong marks on it, which OCRs to
  noise rather than failing loudly. The detail, and the rules each standard
  hides, are in
  [`crates/rgx-adapters-pdf/README.md`](crates/rgx-adapters-pdf/README.md).
- **A dump is a container, and the names inside it are not the framing.** A
  `pg_dump -Fc` custom archive is a header, a table of contents and one
  compressed block per table, and the rows sit inside a stream `rg` cannot
  see past; `crates/rgx-adapters-archive/src/pgdump.rs` reads it. Three
  things in it are load-bearing, and each is where the obvious reading is
  wrong:
  - **The integers are sign-magnitude, not two's complement.** `WriteInt`
    writes a sign byte and then the magnitude, little-endian, a byte at a
    time, so `-1` is `01 01 00 00 00`. A reader that decodes them as
    two's complement reads a length of 3 as -1 and stops, and the archive
    looks fine right up to the second entry.
  - **The name of the compression is not its framing.** PostgreSQL calls it
    "gzip", and `compress_gzip.c` calls `deflateInit` with the default
    window — which is zlib (RFC 1950), not gzip (RFC 1952). A reader that
    reaches for a gzip decoder and falls back to the raw bytes on failure
    finds nothing and says nothing.
  - **The archive version gates the fields.** The header grew a byte at a
    time over fifteen releases and the table of contents grew with it: the
    relation kind only exists from 1.16, the table access method only from
    1.14, the namespace only from 1.6, the dependency list only from 1.5.
    Reading a 1.15 archive as a 1.16 one puts every entry a field out of
    place.
  The corpus is what `pg_dump` itself wrote — one archive per compression
  algorithm it offers — and the expected rows are the ones `pg_restore -a`
  prints, taken from that output rather than retyped. The *other* dump
  formats are decided against rather than implemented: a plain dump is SQL
  that `rg` already reads, and a directory dump is a directory of per-table
  gzip files that the decompress adapter already opens, with only the
  schema left in a `toc.dat` this reader declines by name.
- **A LASzip time sequence is chosen by a symbol, and the reference's loop is
  bounded by a decoder that throws.** The GPS time item lives in one of four
  sequences and the `multi` symbol says which; a value of three or more means
  "the time continues in another sequence", so the reference's reader loops and
  switches. What bounds the reference's loop is its arithmetic decoder: it
  throws when the chunk's bytes run out. A decoder that does not throw can
  decode a symbol without reading a byte at all, and then the loop is bounded
  by nothing — the reader in `crates/rgx-adapters-threed/src/lib.rs` followed
  one file's sequence switch 367 million times and took nearly three seconds,
  which is what the fuzz kit's watchdog calls a hang. The loop is bounded here
  (64 switches, and a point's time needs one), and a file that needs more is
  refused with the reason. The corpus is the LASzip-generated cloud with round
  39 of the mutator applied to it, and the regression test pins the refusal.
  Two more bounds belong to the same reader, and both are the file's own: the
  chunk table cannot declare more chunks than the file has points or bytes,
  and a chunk whose compressed bytes run out stops the point loop where it
  runs out rather than after the hundred thousand points the ceiling allows.
- **A MOBI's fixed fields are addressed from the start of record 0, not from
  the `MOBI` magic.** The PalmDOC header is 16 bytes, the `MOBI` magic sits at
  record-0 `0x10`, and the fields the reader wants — Full Name Offset (`0x54`),
  Full Name Length (`0x58`), EXTH flags (`0x80`) — are **record-0** addresses
  (MobileRead's MOBI table; KindleUnpack's `mobi_header.py` reads them out of
  `self.header`, which is record 0). The Full Name Offset's *value* is an
  offset into record 0 as well. Counting those fields from the magic instead
  lands 16 bytes late: the "offset" read is the Output Language field, the
  "length" read is the Locale field, and the EXTH flags read falls in the 32
  unknown bytes after the real ones — so bit `0x40` is clear, the EXTH block
  is never opened, and a valid book yields no title and no author at all. The
  symptom is a *missing* answer, which is the one failure the adapter's own
  test could not see while the fixture encoded the same drift. The test now
  plants a decoy at record-0 `0x64`, which is where the wrong base would look.
- **A declared encoding is a fact about the bytes, not a hint.** A MIME part's
  `charset=`, an HTML `<meta charset>`, an XHTML prolog, an RFC 2047 header
  and the 8-bit text of a Word, Excel or RTF file all say what their bytes
  are. A reader that ignores the declaration does not read the bytes
  differently — it *replaces* every byte above 0x7F with U+FFFD, and the
  character is gone from the answer, so a search for it cannot find it even
  though the byte is still on the disk. `rgx-core::charset` is where this is
  decided: a named encoding is honoured, and the fallback is the one that
  cannot lose a byte (valid UTF-8 as it is, anything else as Latin-1). The
  single-byte tables are generated by `scripts/gen_charset_tables.py` from
  the reference implementation, because a hand-typed 128-entry table is a
  transcription error waiting to happen. The multi-byte CJK encodings are the
  known exception: they are read as Latin-1, which is mojibake but never a
  lost byte.
- **An mbox is split over bytes, not over a decoded string.** The split used
  to read the whole file as UTF-8 first, so every byte above 0x7F in every
  message was U+FFFD *before* a single message was separated — and no
  per-message charset could recover it, because the bytes were already gone.
  A `Reveal` adapter's output is the only view of the file there is, so a
  loss at the split is a loss in the corpus.
- **A file may open with a user block.** HDF5 lets the writer keep the first
  bytes for itself, and the library finds the superblock by looking for the
  signature at the powers of two from 512 up. MATLAB's v7.3 `.mat` is exactly
  that -- 512 bytes of `MATLAB 7.3 MAT-file, Platform: ...` and then the
  HDF5 file -- so a reader that looks for the signature at offset 0 refuses
  every real v7.3 file, and the `.mat` falls to the v5 reader, which finds
  the `IM` endian marker at byte 126 and walks HDF5 bytes as v5 tags. The
  magic decides which family a file belongs to; the extension only decides
  who is asked first, and the reader that does not own the file has to
  decline it rather than answer it.
- **A netCDF-4 file keeps its names in a fractal heap, and the heap is not
  the only place.** Reading them means four structures in order, and a
  split moves the separator record up into the internal node, so the tree
  holds *more* records than its leaves and a walk that reads only the
  leaves comes up short. A small group has no heap at all, a small object
  header keeps its other messages in **continuation chunks** (`OCHK`), and a
  datatype the file shares with other objects is a pointer to the object
  header that holds it -- so a reader that follows only one of those places
  finds no names, or no type, and falls back to the printable strings it
  can see, which are fragments of the header and not names. The reader is
  `crates/rgx-adapters-tabular/src/hdf5.rs`, its oracle is the `ncdump`
  reference output the netCDF library itself ships for the fixture, and
  the detail is in
  [`crates/rgx-adapters-tabular/README.md`](crates/rgx-adapters-tabular/README.md).
- **A netCDF-4 file's attributes are in the object header, and they are
  the file's own words.** The reader reports them: the file's own
  attributes and the ones of every member, each with the value the
  attribute's own datatype gives it -- a number as a number, a string as
  a string, and the bytes of a value that is neither as hex, because a
  number that is not a number is a lie. An attribute may hold several
  elements, and each one is decoded on its own; the traps are the
  attribute's **version 3** header, which puts a character set between
  the header and the name, and the **null dataspace** (`H5S_NULL`), which
  says the value has no elements at all and writes no bytes for it --
  an empty string attribute is exactly that. The oracle is the same
  `ncdump` output the names are checked against: it lists the thirteen
  attributes of the file the reader reads, and the test compares them
  one by one.
- **A type names its members, and the reader names them too.** A
  netCDF-4 file can store an *enumeration* -- a set of names with the
  values they stand for -- and a *compound* -- a set of names with the
  types they hold. The datatype message of the file says both: the
  members of an enumeration are the names, then the values, each the
  size of the base type; the members of a compound are the names, then
  the offset of each one inside the record, then the member's own
  datatype message. The reader reports them as `member: <path>: <name>
  = <value>`, and a type the file stores twice -- once as a committed
  type, once inside the variable that uses it -- is listed once. The
  oracle for the compound is the same `ncdump` output: it declares the
  type and its members inside the braces. The enumeration has no
  `ncdump` reference in the netCDF library, so its oracle is the source
  that wrote the file, `nc_test4/tst_enums.c`.
- **A netCDF classic file's values are in its data section, and a record
  variable's are not where its own block would be.** The reader reports the
  values, one line per element, with the index that locates it:
  `value time[17] = 17`. The trap is the record: a record variable -- one
  whose first dimension is the record dimension, the one the header stores
  as length zero -- is not a block of its own. A record holds one element of
  *every* record variable, in the order the file lists them, and each of
  them is padded to four bytes, so the distance between two records is the
  size of a whole record, and the size of a record is the sum of what each
  record variable needs. The file says both: the offset of every record
  variable (`begin`), and the size of one record of it (`vsize`). The
  oracle is the file's own header -- and it checks out: the last record of
  the `nctest` file ends at its last byte. The other oracle is the `ncdump`
  reference the netCDF library ships for the 360-day fixture: it renders
  the variable with the units and the calendar the file itself declares, so
  the value at index i is the date i days after 1900-01-01 in a 360-day
  calendar, and the test reads those dates out of it and checks them
  against the ones the reader gives.
- **The data of a dataset is not where the layout message says it is, in
  every version of the message.** The class of the layout message says
  whether the data is in the message itself (compact), in one block at an
  address (contiguous) or in chunks — and the class sits in a different
  byte depending on the version: the first two versions put it after the
  dimensionality, the third and the fourth put it right after the
  version. Reading it in the wrong place gives a class that does not
  exist (255, 124, 169), and the data of the dataset is never found. The
  values of a netCDF-4 file are read now, one line per element with the
  index that locates it, and the `ncdump` reference the netCDF library
  ships for the fixture lists them: the same 1,171 values, in the same
  order, and the compound of the small file as `{x: 1, y: -2}`, the
  oracle's own `{1, -2}`. What is not read: the data of a dataset that is
  in chunks — the chunks are indexed by a tree this reader does not walk
  — and the reader says so, dataset by dataset.
- **The chunks of a chunked dataset are indexed by a v1 B-tree, and the
  key of a chunk says three things at once.** The node of the tree holds
  its children in the order of their keys, and the key of a chunk is the
  size of its data on the disk, the mask of the filters that were
  applied to it, and the offset of the chunk in each of the dataset's
  dimensions — an offset that has to start on a chunk boundary, or the
  tree is corrupt. The mask is a mask of **IDs**, not of names: a bit set
  means a filter was applied, and this reader does not undo the filters.
  The values of the record variables of the netCDF-4 file are read now,
  and the `ncdump` reference lists the same 1,403 values, in the same
  order.
- **A version 1 object header counts the messages of the whole object,
  and keeps only some of them.** The header says how many messages the
  object has and how many bytes of them are in the header itself; the
  rest are in the blocks that a header continuation message names, and
  such a block has no signature. A reader that takes the header's count
  as the number of messages in its own bytes reads a group as an object
  with no layout and no type. The **symbol table** of an old-style group
  is read now — the tree that indexes the nodes of the table, the local
  heap that holds the names, and the node itself — and the MATLAB v7.3
  file, which used to report the internals of the file (`TREE`, `HEAP`,
  `SNOD`), reports its variables.
- **The mask of a chunk says the filters that were EXCLUDED from it.**
  A bit that is clear is a filter that was applied to the chunk, and a
  bit that is set is one that was skipped. Reading it the other way
  round says a chunk has no filters at all, and the reader then hands
  out the compressed bytes of a deflated chunk as if they were the
  values. The pipeline of the dataset says which filters they are, and
  the reader undoes the two it can -- the shuffle, and the Fletcher-32,
  whose checksum is the file's own oracle for the bytes -- and refuses
  the deflate, naming the filter.
- **The flags of a CDF-3 descriptor use the low bits, and the size of a
  record is the size of the whole record.** The first bit of the flags
  says whether the records vary, the second whether the data is padded
  and the third whether it is compressed -- not the top three, which is
  where the reference reader looks. The size a record carries is the
  size of the whole thing, the eight bytes of the size included, and the
  data of a block starts eight bytes into it. The blocks of a variable
  are indexed by a chain of index records, and the number of records is
  the one the descriptor says: the block says how many records it has,
  and that number is not always the one that counts.
- **The checksum of a sorted table's block is over the bytes as they are
  in the file, so it is checked before the Snappy decoder sees them.** The
  reason it was not checked is gone: the claim that a block which fails
  its CRC cannot be told apart from a decoder that disagrees was wrong,
  because the CRC covers the block's data and the type byte, and neither
  is touched by the decoder. A block that fails now ends the walk of that
  table where it happened and says so.
- **A block container is not a filesystem.** VHD, VHDX, QCOW2, VMDK, VDI,
  EROFS, APFS and HFS+ wrap a block device, and reading one means mounting
  it — an adapter is a pure function over a byte slice, so there is no
  mount, no loop device and no privileges. Those adapters report the
  container's own metadata (geometry, UUID, backing chain, features, and
  for the filesystems with a readable catalogue, the names) and say nothing
  about the payload. ISO 9660 and SquashFS are different: they carry a
  catalogue and their files come out as real members. The line between the
  two is the answer each format can honestly give, and `tests/images.rs`
  holds it down end to end — including that a `.vhd`'s own bytes are *not*
  searched.

**Reach and Policy** — a decompressing adapter makes rgx a *superset* of
ripgrep; a *transforming* one (html, md, rtf, tex) makes it a *subset*,
because flattening deletes bytes ripgrep would have matched.

- `Reach::Reveal` — not searchable as it stands; the adapter surfaces new
  bytes. The default.
- `Reach::Render` — searchable as it stands; the rendering is lossy.
- `reach_needs_bytes()` — true when the answer depends on the bytes (`.pem`
  vs `.der` are one adapter and not the same question). Only such an adapter
  pays a read to find out, which is what keeps `.html` and `.md` off the
  adapter path.
- `Policy::Source` (default) — search the file's own bytes; a `Render`
  adapter does not get the file. The only view under which rgx stays a
  superset of ripgrep. `Policy::Render` / `Policy::Both` opt back in.
- A `Reveal` adapter's `Text` is **not** a view of the same lines as the
  file, so `Policy::Both` deliberately does not union the container's own
  bytes there.

**A rendering of a text format is worth writing when it makes a match the
file's own bytes cannot make.** The flat files of the sequencing family
(FASTA, FASTQ, VCF, GFF/GTF, PDB, mmCIF — `crates/rgx-adapters-inspect/src/flatfiles.rs`)
are the case: a FASTA's sequence is written 60 columns wide, so a motif
across the wrap is two lines and `rg` cannot match it; a VCF's columns are
tab-separated, so `chr1 11869` is a pattern the file does not contain. The
rendering joins the first and puts the second side by side, and under
`Policy::Source` — the default — the file's own bytes are still the answer
and none of this is consulted. What is *not* worth writing is a rendering
that only re-orders what `rg` already sees, which is why `.m3u`, `.pls` and
`.xmp` are still left to `rg`.

**The text CAD formats are rendered for the same reason, and the decision to
claim them was made by measurement, not by argument.** DXF, IFC/STEP, IGES,
the ASCII ACIS `.sat` and STL (`crates/rgx-adapters-inspect/src/cad_dxf.rs`,
`cad_step.rs`, `cad_iges.rs`, `cad_sat.rs`, `cad_stl.rs`) are plain text `rg`
reads perfectly, and `cad.rs` used to say they were *not* claimed on
purpose — the argument being that a renderer which drops what the file
carries is a subset of ripgrep. That argument is true of the markup family
and false of a renderer that only *joins* what the file already says, and a
CAD entity is exactly that:

- a DXF's group codes put the entity's name on one line, its layer on
  another and its coordinates on three more;
- a STEP instance is one very long line whose entity, attributes and name
  are separated by a comma and a space;
- an IGES entity's name lives in the directory section and its parameters
  hundreds of lines away, and the only thing that says which belongs to
  which is a pointer counted in delimiter characters;
- an ACIS record is a run of tokens on one line, and a pointer in it is an
  *index* into the list of records;
- an STL facet's three vertices are three lines.

So the rendering puts the name beside the values, and the pattern it holds
is one the file's own bytes do not contain: `entity: LINE on layer LAYER1`,
`#7: IFCWALL(`, `entity: 110 (Line)`, `entity: transform (id 1)`,
`vertices: 0.0, 0.0, 0.0 | 10.0, 0.0, 0.0 | 0.0, 10.0, 0.0`. Under
`Policy::Source` none of it is consulted and the file's own bytes remain the
answer — which is the half of the claim that `tests/cad_formats.rs` pins
down, because a rendering adapter can break the superset property without
failing anything.

**Two adapters may claim one extension.** `.stl` is claimed twice: the
`threed` crate answers the *binary* form (a `Reveal`, because ripgrep
cannot read a binary mesh) and the `inspect` crate answers the *ASCII* form
(a `Render`). The order in the registry decides which is asked first, and a
`bail!` does not end the chain — it is a note, held until nothing later
answers — so the ASCII form reaches the reader that can render it.

**The plotter drawing is rendered for the same reason, and `.plt` is a shared
extension.** An HP-GL file (`crates/rgx-adapters-inspect/src/cad_plt.rs`) is
plain text `rg` already reads, and the drawing is not in it: the file holds the
path the pen took, split across commands, with the pen state carrying the rest
of the meaning. So it is a `Render`, and the pattern it holds —
`polyline (0,11181) (230,11507)` — is one the file's own bytes do not contain.

`.plt` is also what a gnuplot script is called, and the two are nothing alike.
The reader therefore **declines** a file whose stream is not a run of plotter
commands, and a gnuplot script falls through to the raw search and is found
there, in its own words. A claimed extension is not a promise that the file is
of that format; it is a promise that the file will be read correctly *if* it
is.

**The three binary formats are revealed, and the specification is not the last
word.** The CGM, the CALS Raster and the JEDMICS C4
(`crates/rgx-adapters-inspect/src/cad_cgm.rs`, `cad_cals.rs`, `cad_c4.rs`) are
binary: `rg` reads none of them, so the adapter's answer is the answer, and
the reach is `Reveal`. What the answer carries is what the file holds as
numbers — a polyline's points, a page's size, a tile count.

A specification leaves silences and a corpus fills them. The CGM's own text
(ISO 8509-3) does not say that the metafile element's first byte is the
*name's length in characters*, that the integer precision counts bits, or that
a string is prefixed with its length; the 353 real files of the W3C/OASIS
WebCGM 2.1 test suite say all three, and the reader follows the corpus. Where
the corpus and the specification disagree, the corpus wins **and the
disagreement is written down**; where neither settles it, the reader says it
did not read it — the five files of that corpus that write their text in the
two-byte character set are named, not guessed at.

That corpus grants no right to make derivatives, so not one file of it is in
this repository: the fixture is built byte by byte, and the reader was checked
against the corpus from outside the tree (the walk lands on the end of 353 of
353 files, and the element sequence matches an independent reader on 353 of
353).

**A header that lies about itself is declined, not believed.** The C4's data
offset has to match its own tile index, and its index offset has to be 128; a
file whose header says otherwise is declined and the raw bytes are searched
instead. The CALS's type 2 files — several pages and a tile index rather than
one T.6 stream — are reported as what their header says and are not decoded
into pages that were never read.

The policy is applied inside `process`, not in the registry: an adapter that
answers from the bytes cannot be answered without them.

**A magic number is what the container is, and a claim the reader cannot
honour is removed.** The camera RAW reader walks a TIFF IFD chain, and its
extension list named CR2, DNG, NEF, ARW, ORF, PEF, SRW and RW2. Checked
against real files, two of those did not work: a Panasonic RW2 starts with
`49 49 55 00` — 0x55 where a TIFF has 0x2A — and an Olympus ORF with
`IIRO`, and neither is a TIFF byte-order mark, so the reader declined both
and the file fell back to the raw search without a word. The RW2 is a TIFF
in everything but the magic number, so the reader now accepts 0x55 and
**names the container it read** (`TIFF (RW2 …)`); the ORF is not a TIFF at
all, so it is no longer claimed. A claim is a promise that the file will be
read correctly *if* it is of that format, and a promise the reader cannot
keep is worse than no promise: the file answers with a page chain it does
not have.

**The check asks which adapter answered, never whether there was a hit.** A
format that quietly fell back to the raw search still finds the occasional
ASCII run in a header, so `tests/raster_formats.rs` asks for the adapter by
name. That is how the RW2 was found: it matched no pattern, so a
hit-based test would have called it a pass.

**The memo has two layers, and the second one is what makes the first
worth having.** The alias (path + size + mtime) is derived from what the
walk already stat'd, so a hit costs no read at all; the content entry (the
SHA-256 of the bytes) holds the extraction, with the unit paths stored
relative to the file so one entry serves every file with those bytes. A
content entry is only ever served for the same **name**: the extension
picks the parser and a report that names the file names the file. The
policy is in both keys, because under `Source` the adapter is not
consulted at all and under `Render` its answer *is* the answer.

**A parallel walk extracts the same content once.** The walk is parallel,
so two copies of the same file can reach the extraction at the same time.
`Cache::extract_once` is the single-flight: the second thread waits for
the first and then finds what it stored. Without it, the content layer
only helps across runs, and a corpus of copies pays for every copy.

**Engine dispatch** (`src/engine.rs`, `src/detector.rs`):

- **There is one engine.** `Mode` has a single variant, `Rgx`. The
  `grep-searcher`/`grep-regex` deps and the dual-sink `Both` mode are gone.
  `engine.rs`'s module header is current — read it before assuming anything
  about engine parity claims.
- The engine is byte-mode: no Unicode semantics at match time, no capture
  groups in the scanner (they exist in `vm.rs` for `-r`), a smaller pattern
  language than `grep-regex`. **Case folding is resolved at parse time**
  (`unicode_case.rs`, the generated simple-folding table): `(?i)` turns each
  character into the byte alternation of its whole case class, mixed UTF-8
  widths included — `-i kelvin` reaches U+212A and `(?i)ß` reaches `ẞ`. A
  caseless literal whose fold leaves ASCII gets no literal prefilter
  (`literal::extract` declines it — `k` and `s` are the ASCII letters that
  do); the match side is still bytes. The remaining Unicode gaps are the
  class shapes (`[é]` in a mixed class over-matches — the three ignored
  tests in `regex.rs`) and full case mapping (`ß` ≠ `SS`).
- `--engine auto` (default) picks from pattern and corpus; `--explain-engine`
  prints the reasoning. **`auto`/`tv`/`rgx` are the only accepted values** —
  `--engine grep` and `--engine both` fail argument validation.
  `EngineChoice` (`src/detector.rs:17`) has exactly two variants,
  `TeslaValve` and `RgxDirect`.
- **`RGX_ENGINE` accepts retired names and says so.** `RGX_ENGINE=grep`
  reaches `Mode::from_env`, which returns `Mode::Rgx` for everything; it now
  prints one stderr line naming the retired engine and carries on. An ambient
  variable must not fail a search that would otherwise succeed, and a silent
  one must not be able to lie.

**How a file is routed** (`Registry` in `crates/rgx-core/src/lib.rs`): the
name comes first. A path's extension keys resolve to the adapters that
claim them, and a dotted declaration (`scan.ocr.jpg`) is offered to the
adapter that declared `ocr.jpg` before the one that declared `jpg`. Only
when the name is silent does the content get a say: an adapter may declare
a **magic prefix** (`Adapter::magic`), and the registry consults it after
the extension keys run out, on the bytes in hand. The order is not
negotiable — the name is the stronger claim, and a magic is a claim about
the content — and the magic phase runs *last* in the same chain, so an
adapter that claims both a name and a magic still runs once.

The cost lands on the caller, and it is the only way to reach a format that
names nothing: the walker probes the files no adapter claims by name
(one short read) and asks `Registry::claims_magic` before deciding the
file is raw. A borg segment is `data/0/2` — no extension, no dot — so
without that probe the format is unreachable, and the honest alternative
would be to claim an extension nobody owns.

**Measured**: the probe is inside the noise. A/B on the cargo registry
(153,936 files, every one of them unclaimed by an adapter, so every one
of them pays the probe), interleaved passes, the minimum of five rounds:
**15,717 ms with the probe, 16,016 ms without** — 1.86% *apart*, which
is inside the ±3% floor the harness itself refuses to call a result. So
the reach costs nothing measurable, and the alternative — claiming an
extension for a format whose files have none — is not on the table.

**Walking** (`src/walk.rs`): git's ignore semantics, decision for decision, as
implemented by the `ignore` crate — a **dev-dependency only**, held as the
oracle in `tests/walk_diff.rs`. Nothing in any binary links it. The oracle
normalises: `tests/walk_diff.rs` applies `.replace('\\', "/")` to **both**
engines' paths, so the suite cannot see that rgx prints `/` where ripgrep
prints `\` on Windows.

**Pack-store format** (`crates/rgx-core/src/tv/format.rs`):
`PACK_MAGIC = b"RGXTVP01"`, `MANIFEST_MAGIC = b"RGXTVM01"`,
`FORMAT_VERSION = 1`, `MANIFEST_VERSION = 5` (v3 redefined a file record's
`is_binary` flag; v4 added the per-file `ngram` signature; v5 added the
head's `extract_fp` and the `SIG_COVERS_ADAPTER` flag bit, and an older
store is refused with its version named), `DEFAULT_PACK_SIZE = 16 MiB`. The
manifest is published atomically via write-and-rename. Each file is searched
in an isolated `pack[offset..offset+len]` slice, which guarantees no
cross-file match bleed, isolated 1-based line numbering, and exact
`^`/`$`/`\b` anchors.

**Pack search runs the adapter registry on the same bytes the direct path
reads**, so the two answers agree by construction rather than by
coordination: the store holds the corpus verbatim, and `run_tv_query` hands
each file's slice to the same `process` the direct path runs — a `.gz`
member and a `.docx` paragraph included. The rule under it is that
**entering the pack engine may never change what a query means**; the
detector promoting over a store is only sound while that holds, and the
admission check that used to guard it (`adapter_claimed_files`) is gone
because its reason is. `DetectionResult::explicit` carries "the caller named
the engine" — do not re-parse flags in `main.rs` to recover it, or the
precedence rules get duplicated.

**The detector's promotion is freshness-gated through the dirty-file
overlay.** A store whose manifest the filesystem disagrees with - a file
gone, resized, or re-dated (`tv_runtime::stale_files`/`stale_in`/
`stale_list_in`) - is still promoted: `run_tv_query` re-reads every
disagreeing record off disk and answers those files from the bytes there
(`is_empty`/`is_binary` re-derived with the build's own rules), so drift
costs reads and never correctness. The n-gram filter stands down on a dirty
file - its stored signature covers bytes that no longer exist, and pruning
on that is how a filter loses a match to an edit - and a file gone from
disk contributes nothing. A **member record** (the `container!member`
names `--tv-pre-extract` writes) has no path of its own: it hangs off its
owner container and is stale exactly when the owner is (`owner_rel` finds
the owner by prefix; the row's mtime is the owner's), a fresh one is
answered from the pack, and a changed one is answered from the owner's
current extraction (`extract_owner_units`, keyed by `member_rel` so the
names agree by construction). Judged by its own name, every member of every
pre-extract store read as gone-on-disk and the overlay dropped the
container's whole answer - the regression the owner rule exists to keep
out. `--explain-engine` names the count and the mechanism; explicit `--tv`
warns aloud; `--tv-build` repairs. What neither the gate nor the overlay can
see is a file *added* after the build - that needs the walk the store
exists to avoid - so the promotion reason names the snapshot and the
boundary is documented rather than pretended away.

**The n-gram filter** (`crates/rgx-core/src/ngram.rs`) rejects a file before
its bytes are read. A file's `FileRecord::ngram` is `build_stored_sig512`:
the signature of the text the *searcher* will see, so a BOM-marked file is
signed as its decoded form (`search_slice` decodes UTF-16 before matching).
Under manifest v5 a build with an extractor signs the **rollup**: the OR
over the raw text and every unit/error note `process` can hand the searcher,
and a record carrying `FileLoc::SIG_COVERS_ADAPTER` (flags bit 8) promises
exactly that. The head's `extract_fp` fingerprints the extraction context
(`Ctx`, member budget, policy, adapter chain with versions - see
`extract_fingerprint` in `src/main.rs`); a query may only trust rollups
when its own fingerprint matches, or the units it would extract could
differ from the ones the signature covers. External tool versions behind
`rgx-adapters-docs` are invisible to the fingerprint - the same boundary
`--cache`'s key names. The query side is
`query_sig512(pattern, case_insensitive)`, built from `required::anywhere` -
the literal **every** match must contain - never from the pattern's
spelling, which is not required of a match (`abcd|efgh` matches a file
holding one branch; `abcd*` matches `abc`). The filter stands down (`None`
means "search every file", **never** "search none") for a folded literal, a
pattern with no required four-byte literal, a forced `-E` decode,
`-v`/`--files-without-match` (a "match" is a line the pattern does NOT
cover), and - per file - an adapter-claimed extension whose record lacks
`SIG_COVERS_ADAPTER` or whose `extract_fp` does not match the query's. An
all-zero signature is "unknown" and never rejects. `RGX_NGRAM_STATS=1`
prints what it pruned.

### 2.1 The structured filter (`--filter`)

`crates/rgx-core/src/filter.rs` holds the grammar; `filetype.rs` holds the
tables that turn an extension into a MIME type and a language. The facts a
predicate matches on are **named**: `path`, `ext`, `format`, `mime`, `lang`
from the name of the file, and whatever the adapters report through
`Adapter::facts`.

**The rule that is easy to get wrong: which side of a predicate is compared.**
A predicate whose path is the fact's *name* compares the fact's *value*; a
predicate whose path is the fact's *namespace* compares the fact's *name*.
`author:"Jane Doe"` therefore asks who wrote it, and `exif:gps` asks whether
an EXIF fact called `gps` exists at all. That second shape is the one the
user-facing examples use (`exif:gps`, `archive:entry`, `tensor:name`,
`table:column`), and it is why **a fact nobody reports is false** and not an
error - a file that is not a photo does not have GPS.

**The rule that is easier to get wrong: which entity is filtered.** The unit
that gets searched is the entity the filter is evaluated on. A file no
adapter claims is searched raw, and the raw path is filtered on the facts the
name gives - the walker has to ask, because the raw path never goes through
`rgx_core::process`. A member of a container is filtered on its own facts
*plus* the container's: `container` and `archive.entry` are pushed down
`process_scoped`'s `inherited` slice. A container itself produces no unit, so
`--filter ext:zip` finds nothing - the thing searched is
`bundle.zip!script.py`, and that is a `.py`.

**A fact that is always present is a lie.** `has.attachments` is reported
*only* when the message has attachments, and `exif.gps` only when the file
has coordinates: with the namespace rule, the predicate asks about the fact's
existence, so a fact that is always there makes the predicate always true.
Report the absence.

**The cost is the adapter's, and it is paid only on demand.** `facts()` is
called after `extract()`, only when a filter is in play, and an adapter that
has to parse the file again to answer pays for a second parse (the PDF's
`/Info` dictionary is the case that shows it). The reason the facts do not
travel inside `Outcome` is that 280-odd call sites build one; changing its
shape for two of them is not a trade worth making. `Ctx::wants_filter()` is
the gate: a run without `--filter` must not assemble a single fact.

**The cache is keyed by the filter's text.** `src/cache.rs` puts
`Ctx.filter`'s text in the key and `extract_fingerprint` names it too: two
filters over the same file are two extractions, and a cache that handed the
second one the first one's units would answer a question nobody asked.

**A dispatch with a branch per target has to have no dead branch on any of
them.** The searcher has three paths -- AVX2 on x86_64, NEON on aarch64, and
the scalar one everywhere else -- and the code that picks between them was
written with an early `return` in the vector blocks, which is the fastest
shape there is on x86_64. On aarch64 the scalar line after it is
*unreachable*, and the gate's `-D warnings` makes that an error; and once
that line is compiled out, the vector block is the last statement of the
function, so its `return` becomes an unneeded one, and the vector path's
tables become code nobody calls. The shape that holds on every target is
the one where each path is a tail expression and the others are compiled
out. The scalar path stays compiled everywhere, because it is the oracle the
tests hold the vector path to -- so where nothing but the tests call it, it
carries `#[allow(dead_code)]` rather than a `cfg` that would take the oracle
with it.

**An arm64 build can be checked from a Windows box, but only with the test
targets built.** The gate that decides these things is `cargo clippy --target
aarch64-unknown-linux-gnu`, and the `target_arch` gates are the same on every
operating system, so the arm64 lints are visible with nothing but the target's
standard library installed (`rustup target add aarch64-unknown-linux-gnu`). What
that target does not see is the operating system's own files -- `memmap2/platform/
macos.rs` is compiled by `cargo clippy --target aarch64-apple-darwin` and by
nothing else, and its `std::isize::MAX` was the only deprecated constant in the
tree, because the file is the only place the platform's own API is called.

**A cross-target check that does not build the test targets does not check the
tests.** The command above builds the library and stops: the `#[cfg(test)]` code
-- where the oracles live, and where the AVX2 and PCLMULQDQ paths are held
against them -- is not compiled at all. So a cross check that reported the
arm64 build clean was clean about a build the CI never runs, because the CI's
clippy line is `cargo clippy --release --workspace --all-targets -- -D
warnings`. The arm64 job of the macOS matrix failed with eleven errors, and
every one of them was in test code: an import of the scalar oracle that only
the x86_64 test uses, a helper that pads a needle list for the vector kernels,
and three tests that call `avx2::scan_avx2` or `classify16_avx2` -- names that
do not exist on a target without AVX2. The lesson underneath is the one the
gate itself teaches: **a check that does not build what the gate builds is not
the gate.** Run the cross check with `--all-targets` and with the same flags as
the CI line, or it is not checking the same thing.

**A crate with a C dependency cannot be cross-checked from Windows at all.** The
`cc` crate cannot target Mach-O, so a workspace-wide
`cargo clippy --target aarch64-apple-darwin` dies in `zstd-sys`'s build script
with `unrecognized command-line option '-arch'` and the Rust code behind it is
never compiled. The way round it is one crate at a time: a crate whose
dependencies are pure Rust checks in full, and the crates a C dependency blocks
are named as such rather than left silently unchecked. Either way the crates
blocked here are the CI's to answer -- the runner *is* an arm64 machine, and a
green matrix is the only claim worth making.

---

## 3. Adding an adapter family

Exactly four places, per the README:

1. the workspace `members` list in the root `Cargo.toml` (12 crates today),
2. the optional dependency **and** its feature, added to `default`,
3. `fn registry()` in `src/main.rs`, `#[cfg(feature = …)]`-gating
   `v.extend(rgx_adapters_X::adapters())`,
4. the license/legal files, if a new third-party dependency enters.

Each adapter crate exposes `pub fn adapters() -> Vec<Box<dyn Adapter>>`.
**Registration order is meaningful**: first matching available adapter wins.

An adapter is also a **Cargo feature**: see §3.1. Adding an adapter without
adding its feature leaves the format out of every narrow build, which is
exactly what the feature exists to prevent.

**An adapter that reads other files is not memoised, and must not be.**
`src/cache.rs` keeps an allow-list, `MEMOISABLE`, of the adapters whose
answer is a function of the bytes they were handed. An adapter that reads
the environment, spawns a tool, or opens a neighbouring file is not on that
list and is re-extracted every run — the key cannot see those change. The
Zarr is the first adapter in the tree that opens a neighbouring file (the
chunks beside a `.zarray`), so it is deliberately absent from the list.

### 3.1 One Cargo feature per format

Every adapter sits behind a Cargo feature, so a build can carry only the
formats it names. Three layers, and the root package is where the user
touches it:

1. **L1 — the adapter crate** declares one feature per adapter, named after
   the format it answers (`zip`, `grib`, `zarr`). The crate's `default`
   lists every one of them, so the default build of the crate is unchanged.
   A family that needs another family says so in the feature
   (`sevenz = ["std", "ar"]`), and a dependency only one family uses becomes
   `optional = true` and is switched off with it.
2. **L2 — the root package** re-exports one feature per format as
   `format-<name>`, where `<name>` is the string the adapter itself reports
   (`Adapter::name`) — the same string `--json` prints in the `format` field
   and `--explain-engine` names. `format-zip = ["dep:rgx-adapters-archive",
   "rgx-adapters-archive/zip"]`. The crate-level knob `adapters-archive`
   stays and still means "every format that crate knows" — and it is the
   **list** of that crate's `format-*` features, not the crate's own
   `default`, so that one format never drags in the other twenty-two.
   The registry in `src/main.rs` is gated on the same `format-*` features,
   one `any(...)` per crate: the crate is compiled when a format names it,
   and its adapters are registered when any of its formats is on. The two
   can never drift apart.
3. **L3 — `rgx-core`** puts its codecs behind features too, so a format that
   needs the gzip decoder does not drag the zstd one into the binary.

The rules that are easy to get wrong:

- **The order of `adapters()` is meaningful** and the gating must not change
  it: first matching adapter wins, and a file that two adapters claim
  reaches the same one it reached before.
- A helper used by more than one family is gated with
  `#[cfg(any(feature = "a", feature = "b"))]`, and one used by a single
  family with that family's feature. A helper left unused is a `-D warnings`
  failure, so the compiler is the check.
- A test belongs to the family it exercises. The default build's test count
  must not change: the narrow build is the one that loses tests, on purpose.
- Two clippy lints answer every gating change, and both reject the spelling
  that looks natural: `non_minimal_cfg` refuses an `any(...)` with a single
  condition (write `#[cfg(feature = "x")]`), and `vec_init_then_push`
  refuses a list built with one push per feature — which is the only way to
  build a list out of individually `#[cfg]`-ed entries, so that one carries
  an `#[allow]` and the reason next to it.
- The binary **reports what it has**: `rgx --version` lists the formats the
  build carries, read from the `format-*` features themselves, so the list
  cannot drift away from the binary.
- A crate whose `std` feature is off compiles with no format at all. That is
  the honest shape of a no-std build here: every format needs the
  filesystem, the environment and the producer budget, so "no std" means "no
  adapters".

Why the layer exists, in numbers: the full binary is 9 340 416 B; a build
with three formats (zip, pdf, grib) is 4 014 592 B, and the engine alone is
3 516 416 B — 57 % and 62 % smaller. The build clock moves from 31 s to 29 s — a cold
build, each configuration in a target directory of its own, on this
machine — and that is the dependency graph answering, not the codecs: the
lever is **the size of the binary and the dependency surface**. Do not sell
it as a faster build.

---

## 4. CLI surface

The `app()` grammar in `src/main.rs` is canonical — every flag below is one
`Arg::new(...)` line there. Change both together. **rg parity is a feature;
do not rename a flag to something rg would not recognise.**

Flags an agent is likely to get wrong:

| Flag | Source |
|---|---|
| `--threads` / `-j` | `Args::threads` |
| `--column` / `--vimgrep` | `Args::column` |
| `-0` / `--null` | `Args::null_data` |
| `--heading` / `--no-heading` | `Args::heading` |
| `--sort path` / `--sortr path` | `Args::sort` |
| `--color when` | `Args::color` |
| `-E` / `--encoding` | `Args::encoding` |
| `-M` / `--max-filesize` | `Args::max_filesize` |
| `--cache` / `--cache=DIR` | `Args::cache` |
| `--cache-prune` / `--cache-clear` | `Args::cache_prune` / `_clear` |
| `--chunk[=BYTES]` | `Args::chunk` |
| `--filter <EXPR>` | `Args::filter` |
| `--hidden` / `--no-hidden` | `Args::no_hidden` |
| `--serve` | `fn serve` |
| `--pick` | `Args::pick` |
| `--completions SHELL` | `Args::completions` |
| `--explain-engine` | `Args::explain_engine` |
| `--engine auto\|tv\|rgx`, `--tv`, `--tv-store DIR`, `--tv-build`, `--tv-pre-extract`, `--tv-verify PATTERN` | `Args::engine` and the `tv` family |
| `--index-build DIR`, `--index DIR`, `--index-store DIR` | `Args::index` family |
| `--facts-build DIR`, `--facts-index DIR`, `--facts-export FILE`, `--facts-store PATH` | `Args::facts` family |
| `--mcp` | `Args::mcp` |

The effect of each flag is in [MANUAL.md §12](MANUAL.md#12-flag-reference),
with ripgrep's own behaviour beside it; what is here is where the flag is
defined, which is the half a reader of the manual cannot get.

Type filters: `-t/--type`, `-T/--type-not`, `--type-add 'web:html,css'`,
`--type-clear`, `--type-list`. `--type-add` filters the *walk*; it does not
decide which adapter claims a file — that is `RGX_CLAIM_EXT` (see §8).

**A type is a set of patterns, a file matches every type it satisfies, and
the last flag that matches decides.** That is ripgrep's rule, and the crate
ripgrep filters types with — `ignore::types::Types` — is the oracle the
filter is held against (`the_type_filter_agrees_with_the_ignore_crate` in
`src/walk.rs`). The parser keeps the order for it: the per-argument map
cannot answer it, so `ArgMatches::order` records the occurrences as they
were written.

**A type name the table does not have is refused, not ignored.** rg answers
`rg: unrecognized file type: X` and exits 2; rgx answers `rgx: unrecognized
file type: X` and exits 2, and `--serve` answers the query with that error in
the frame. A filter that matches nothing is indistinguishable from a search
that found nothing, and the second is the wrong answer to give: the user
asked for `rust` and got silence, which reads as "there is no Rust here"
instead of "there is no type called `rust`". The table the check reads is the
one the flags describe — the defaults, then `--type-clear`, then `--type-add`
— so a type added on the same command line is a type rgx knows, and a type
`--type-clear` wiped is a type rgx refuses.

The table is rgx's own, `rgx --type-list` prints it, and the rules are in
[MANUAL.md §12](MANUAL.md#file-types).

`--glob`/`-g` is repeatable and gitignore-style: a leading `!` excludes, and
the match is against the path as the walker reports it. There is no `--iglob`.
Flags taking paths accept `-` for stdin. **`--file` is not accepted**,
matching rg.

**An agent debugging "why does rgx ignore my flag" should check for a
`.rgxrc` first.** The search order, and the rule that the file's lines are
prepended to argv so the CLI wins, are in
[MANUAL.md §7](MANUAL.md#7-configuration); the reader is `src/rc.rs`.

**`--serve` protocol** (`fn serve` in `src/main.rs`): one JSON argv-array per
line on stdin, answered on stdout framed by `{"rgx":"ready",...}` /
`{"rgx":"end",...}` sentinels with a per-process `tag` and a `seq`. The
registry and page cache survive between queries. The JSON reader is the
in-house `rgx_core::djson`, not `serde_json`.

**Token index** (`crates/rgx-core/src/index.rs`, `index_io.rs`): an inverted
`token -> Vec<(file_id, line)>` map, serialized as `.rgx-idx.ugi` with magic
`RGXIDX\0`. **The on-disk format is rgx's own** — the `--index` flag names are
ugrep-compatible, the file is not, and nothing else loads it. A token hit is a
*candidate*; the engine still confirms on the re-scanned slice.

**Facts index** (`crates/rgx-core/src/facts_index.rs`): a JSON Lines file, one
object per path — `{path, size, mtime, facts}` — written by `--facts-build`
and read by `--facts-index`. **JSON Lines on purpose:** an index nobody can
read is an index nobody will inspect, and `rg`, `jq` and a person can read
this one. The query language over it is `rgx_core::filter` — the same
`--filter` the walk takes, so there is one query language, not two. A record
whose file has changed is reported as stale on stderr and is **not** answered.
The facts are collected through `Ctx::facts_sink` (`Option<Arc<dyn FactsSink>>`),
and `facts_sink` is deliberately **not** part of the cache key: it decides
where the facts are *written*, not what the extraction *is*. What the index
holds and how to query it are in
[README.md](README.md#the-facts-index).

**MCP** (`crates/rgx-core/src/mcp.rs`): JSON-RPC 2.0, newline-delimited, on
stdio. `PROTOCOL_VERSION` is `2025-03-26` and `SUPPORTED_PROTOCOL_VERSIONS`
also lists `2024-11-05`; the client's version is echoed when the server
speaks it. The methods are `initialize`, `tools/list`, `tools/call` and
`ping`; `notifications/initialized` is a notification and is answered with
nothing. `McpServer` holds an `Arc<Registry>` — `Registry` is not
`Clone`. `--mcp` refuses `--serve`, a pattern and a path of its own. The
tools and the protocol are in [README.md](README.md#the-mcp-server).

---

## 5. Conventions

Formatting is stock `cargo fmt`; there is no `rustfmt.toml`, `clippy.toml` or
`rust-toolchain.toml`, and both tools run at defaults.

Comment style: **contracts over narrative.** A comment earns its place by
saying what would break if the line changed — which invariant, which
measurement, which past failure it prevents. How a bug was found belongs in
`benchmark/` or the commit message, not above the function.

**Licensing is per file, and the tree is the authority.** Every tracked `.rs`
file carries an `SPDX-License-Identifier` header on its first line, and
`tests/cli.rs::every_file_carries_its_spdx_header` reads the file list out of
git and fails on the first file that carries a licence this repository does
not offer, or none at all. So a new source file is one edit — the header —
and there is one header, the one the whole tree carries. "The licence is one
licence" (§11)
has the licence itself, and the reason there is one.

- Format strings and `anyhow!` use inline captures where they read better.
- Errors flow through `rgx_core::{Result, Context, bail!, anyhow!}`. This is
  an in-house replacement for `anyhow`; **do not add the `anyhow` crate** to
  any library or binary. It is `no_std`-compatible and deliberately does not
  implement `std::error::Error`.
- **The tree is `no_std` where it can be, and the port is closed.**
  `rgx-core` is `#![no_std]` + `alloc`, and its `std` feature turns on the
  typed error chain, the profiler map and the `f64::from_str` JSON parser,
  and nothing else that matters. The vector kernels of `scan.rs` and of
  `searcher.rs` are **not** behind `feature = "std"` any more: they are
  chosen at runtime by the crate's own CPU probe, so the `std` build and the
  `no_std` build reach the same kernel on the same machine, and the numbers
  the two produce are comparable. A new `std` call in a library crate is a
  step backwards.
- **The CPU probe is the crate's own, and it is shared.**
  `crates/rgx-core/src/detect.rs` answers "may this CPU run AVX2?" with
  CPUID and XGETBV written out by hand, and caches each answer in an
  `AtomicU8`. `std::is_x86_feature_detected!` is the obvious way to ask and
  it is the wrong one twice over: it lives in `std`, and it is a question
  asked on the hot path, once per scan per buffer, where a question that
  costs a hundred cycles is a question worth caching. The JSON scanner
  carried a copy of this probe before the module existed, for the same
  reason; two copies of one question are two answers waiting to drift. The
  test at the bottom of the module compares every answer with the standard
  library's, on the machine the test runs on.
- **The probe answers for the SHA-256 hardware path too, and that is why the
  `sha256-hw` feature is not a `std` feature.** `crates/rgx-core/src/sha256_hw.rs`
  used to ask `std::arch::is_x86_feature_detected!("sha")` -- and the macro lives
  in `std`, while the feature does not require `std`. So the two things the crate
  claims were independent were not: `--no-default-features --features sha256-hw`
  did not compile at all, and the hardware path could never light up in an
  embedder's build, which is the build the feature exists for. The probe now
  reads `CPUID.(EAX=7, ECX=0):EBX[29]` (SHA) and `CPUID.(EAX=1):ECX[19]`
  (SSE4.1) the way it reads the rest, and the CI's `no_std` job builds the
  combination both for the host and for `x86_64-unknown-none`. The lesson is the
  general one: a feature that names a *hardware* path has to detect the hardware
  with something that does not live in `std`, or the build that wants the
  hardware is the build that cannot be `no_std`.
- **The JSON arena's string shadow is this crate's own hash table.**
  `crates/rgx-core/src/djson/intern.rs` is the shadow of the arena's string
  table: open addressing with linear probing, the key's hash stored beside
  the key's *index*, and the arena's own string table as the key storage.
  Three things came out of writing it. The `alloc` crate has **no `HashMap`
  at all** -- `std::collections::HashMap` is the only one, and it is `std` --
  so the `BTreeMap` this shadow used to be in the `no_std` build was a tree
  of *byte* comparisons, and a lookup compared the key's bytes at every
  level. A slot that holds the index of the key does not hold a second copy
  of it, so the `std` build stopped paying one `String` allocation per
  distinct key. And the hash travels with the entry, so growing the table
  re-hashes nothing.
  The **hash is the one thing the two configurations do not share**, and
  the difference is a capability rather than a choice: with `std` it is the
  standard library's SipHash-1-3, seeded from the operating system, so a
  document cannot be crafted to make its keys collide; without `std` there
  is no entropy to seed with -- `core` has no random number generator and
  the `libc` a syscall would need comes in with the `std` feature -- so it
  is a fixed-seed hash of this crate's own, and the fast one. The trade is
  written down in both directions: the `std` build is the one most users
  run, and it keeps the flood-resistant hash; the `no_std` build is the one
  that may read a document an attacker wrote, and it does not.
  Measured on the same machine, on the same 20 000-key document
  (`crates/rgx-core/examples/json_intern_bench.rs`): the `std` build went
  from 4.1 ms to 3.2 ms and the `no_std` build from 6.6 ms to 3.1 ms, and
  the `no_std` build is now the faster of the two.
- **The `no_std` decimal parser counts its digits instead of dividing.**
  `crates/rgx-core/src/numparse.rs` holds the accumulator a JSON number is
  read into, and the overflow check it used to make was a 128-bit division
  *per digit* -- `(u128::MAX - d) / 10`. That check was the parser's whole
  cost: 25 ns a number against the standard library's 8.5. It was also not
  needed. A `u64` holds 19 decimal digits and a `u128` holds 39, so the
  accumulator cannot overflow before the 38th digit, and the check is a
  *counter*. The answers are still the standard library's, bit for bit (the
  test holds them), and the parser is now 12 ns a number -- which is what
  closed the last place where the `no_std` build was the slower one.
- Byte scanning is the external `memchr` 2.x crate, declared in
  `crates/rgx-core/Cargo.toml` and re-exported through
  `crates/rgx-core/src/memchr.rs` so every call site keeps the
  `rgx_core::memchr::*` path it used when the in-house module still
  existed. `default-features = false` is what keeps `rgx-core`
  `no_std + alloc`. This is a re-export, NOT a vendored tree --
  `check-vendoring.ps1` still lists `memchr` among the external crates to
  remove.
- **The upstream crate cannot dispatch on AVX2 without `std`, so this crate
  does the dispatch itself.** `memchr` decides at runtime whether it may use
  AVX2, and it can only ask the question through
  `std::is_x86_feature_detected!`; without `std` it answers "no" to every
  build, and the `no_std` configuration fell back to SSE2 on every byte
  scan -- the same search over the same bytes was 37% slower in the build
  that is supposed to be the embedder's build. The upstream crate does
  publish the AVX2 searchers themselves, behind an `unsafe` constructor
  whose contract is exactly the question `crate::detect` answers, and
  `crates/rgx-core/src/memchr/dispatch.rs` is that dispatch.
- **The substring search is this crate's own, for the same reason.** The
  upstream packed-pair kernel is unreachable without `std`, and the
  constructor that skips the check is private;
  `crates/rgx-core/src/memchr/memmem.rs` is a facade over
  `crate::scan::pair_find` and `pair_rfind` with the upstream's own answers
  (empty needle -> `Some(0)`, `rfind` -> `Some(haystack.len())`, matches
  that do not overlap), and two differential tests hold it to them.
- **`rgx-adapters-docs` is `std` by necessity, not by omission.** It spawns
  the office binary (`soffice` or `libreoffice`), `tesseract` and a
  rasteriser (`pdftoppm` or `pdftocairo`), reads `PATH`, and writes
  temporary files: there is no `no_std` form of any of that. The crate says
  so in its own manifest and keeps no `std` feature to declare. It is the
  one crate in the tree that is not ported, and it is not going to be.
- Commit messages are lowercase descriptive sentences, no `feat:`/`fix:`
  prefix, no body boilerplate. They name the defect and the evidence, e.g.
  `--max-filesize with a space was the one spelling that did nothing`.

- **The worktree is a CRLF tree, and rustfmt does not keep it that way.**
  `core.autocrlf=true` gives every tracked file CRLF line endings in the
  worktree, and that is the convention the tree is edited in. `rustfmt`
  writes **LF** when it rewrites a file -- even a CRLF one -- while
  `cargo fmt --all -- --check` compares the *text* and stays green on
  either. So a format run quietly leaves the files it touched as the only
  LF ones in the tree, and neither the gate nor `git diff` (which
  normalises through `core.autocrlf`) sees it: the drift is only in the
  bytes. The files rustfmt rewrote are converted back to CRLF after the
  format run, and the proof is the byte count -- `CRLF=n, bare-LF=0` --
  and not the format check, which cannot tell the difference.
- **A script resolves the binary it runs, and it takes the name the host
  has.** The Windows name first, then the bare one: a Unix host has no
  `rgx.exe` and a Windows host has no bare `rgx`, so a script that writes
  one of the two names down cannot run on the other host. The house idiom
  is in `benchmark/diffrig/fuzz.py` and `scripts/bench-status.sh`: try the
  `.exe`, try the bare name, and refuse with a message that says what to
  build. And the TV engine is a flag of the main binary (`--engine tv`),
  not a second program -- so the TV arm of a harness runs the same file as
  the rgx arm, and a script that points the two at different names is
  pointing one of them at a file that is not there.

---

## 6. Testing
**2,632 tests pass, 0 fail, 8 ignored** across 52 test binaries plus 12 doctest
targets, from `cargo test --release --locked --workspace --no-fail-fast`
(the count is the one of the platform the gate ran on: the four tests of
the madvise advice are `#[cfg(unix)]` and the hidden-attribute test of
`tests/walk_diff.rs` is `#[cfg(windows)]`, so Linux, macOS and FreeBSD hold
three tests more -- 2635 -- and the CI runs the gate on all three)
(re-snapped 2026-10-28, after the name of a temporary directory learned to live in one file landed: the one new test is the audit that keeps the name of a temporary directory in one file: the rule that a test's own directory is named after a counter and not after the clock lived in nineteen files, and the copies drifted -- the one that was carried last does not compile, and the rest made the directory with `create_dir_all`, which reuses a directory that is already there, silently, so a directory left behind by a killed run was adopted as if it were fresh. The rule now lives in `tests/common/mod.rs`, and a second copy of it is a defect the audit names. The count before that, 2,631, was after the brew formula learned to be the release it names landed: the one new test is the brew formula against the release it names: the version, the two URLs and the two digests have to name one release, and a digest of sixty-four zeros is a placeholder and not a digest. The corrections are the formula's own claim, which said that no release had been published yet and that the digests below were placeholders -- both halves of it false, because the digests were the digests of the published 0.1.0 archives and the release was published -- and the rewrite of the formula in the release script, which had no guard and could half-apply: a formula whose version moved and whose URLs did not installs the release before this one, and one whose digest did not move refuses its own archive with "SHA256 mismatch" at the user's machine and not here. The rewrite now refuses a rewrite that did not move, and the digests it reads go through one helper, because MSYS2's sha256sum puts a backslash in front of the digest of a file whose path has a backslash in it -- and a backslash in a regular expression is an invalid back reference. The release section of the notes was corrected with it: it said the version was frozen at 0.1.0 until the maintainer launches, and the maintainer launched -- the version is 0.1.1 and the registry and the release carry the tree the loop produced -- and it counted the matrix of the release workflow at ten entries when the workflow has nine. The count before that, 2,630, was after the packages were carrying the contracts into the registry, and the include list negates them now: the two new tests are the packages against what they would carry: cargo's own list of the files, and the rule that says the contracts are not among them. The corrections are the thirteen include lists, which covered `/src/**` whole and so covered every contract under it -- and cargo cannot be told otherwise with an `exclude`, because it ignores the exclude list when an include list is there -- and the dry run of the publish script, which said it had published nothing when it had published nothing. The count before that, 2,628, was after the registry carried the tree of the release and the tree has moved since -- ten crates of the thirteen and the root package with them -- so the version moved a patch and the thirteen packages are the ones the code is now, and the dry run of the publish script says what it did: the two new tests are the manual against the external tools the tree spawns: every binary the code can reach for has to be named in the manual, and the picker's row has to name its candidates in the code's order. The corrections are the manual's summary, which named two of the office tools, the section on the adapters, which left out the office binary's second name, the flag table, which said the picker's default was the first of two candidates when the code has four, and the notes of the project, which said the same two tools. The root contract's three claims were corrected as well: the workspace builds two binaries and not one, the root holds the installers beside the binary package and not one piece of code of its own, and the inventory of the spawned binaries names the rasteriser and the office binary's second name. The count before that, 2,626, was after the thirteen contracts the first pass left unread were read against the tree again, and the manual learned to answer the binary: the three new tests are the manual against the binary: every flag the `--help` prints has to be in the manual, every flag the manual's tables name has to exist in the binary, and a flag the manual mentions beside a table has to exist or the line has to say that it is not accepted. The corrections are the manual's `--adapter-view=source`, which the binary refuses and which the environment variable `RGX_ADAPTER_VIEW` replaces, the `--stats` flag the manual promised and never named, the count note's resolver of the bash that reads the scripts, which knew one installation's path and now derives the one the git on the PATH belongs to, the RAR example's own doc comment, which pointed at a gated bench the tree does not have, and the seven contracts the reader found false: the two that said the workspace has no external dependency, the root one that named a gate line the workflow does not run, the example's own contract, the on-demand one that did not say one of its twelve tests needs the `std` feature, the pack store's, which promised a file-level lock the store does not take, and the two of the 3D family, which named three of the five ASCII forms the readers bail on. The count before that, 2,623, was after the completion audit of the drift review, and the corrections it found landed: the two new tests are the axis harness refusing a store that is not there -- so the store it measures is the store the caller named and not one it built itself -- and the script that holds the class down, which asks every script that names the binary to name it the way the host names it. The corrections are the LZ4 bullet that still claimed the frame was not read, the tv module that called a binary target a crate, the nine scripts that named the binary the way one host names it, the diodicity harness that reported a missing binary as a measurement, the Windows fetch of the legacy corpus that did not make the .wk2 copy its bash twin makes, the panic sweep that carried a second hand-written list of extensions, the contracts of the memmap2 tree that still said no capability check was made, and the extent-ab twin that tested existence where its shell twin tests a file. The count before that, 2,618, was after the missing-tool note reached the corpus, the unit path learned the file's own binary rule, the fuzz target stopped carrying a hand-written list of extensions and the tree's own headers stopped claiming what the code does not do landed: the three new tests are the truncated extraction cached under rgx_max_members served unchanged by a run without it, the named binary file searched as text with the NUL reported rather than obeyed, and the named binary file listed as a miss the way rg lists it. The count before that, 2,615, was after the corrections another agent landed without a commit, the offsets of the whole match, the only-matching output of the standard input, the size limit of the chunk mode, and the documentation review that removed the duplicated prose landed: the eleven new tests are the rock-ridge entry shorter than its own fields not being taken for a name, the pax record whose length lies ending the walk instead of panicking, the DICOM element whose long VR header ends the file stopping there, the record that names one fact twice being refused, the namespace predicate matching the name exactly, the namespace not ending a name in the middle, the truncated tie rounding up when the dropped digit is not zero, the multiline only-matching printing each line's part, the stdin only-matching printing the matches, the cleared type being refused by its alias too, and the chunk mode respecting the size limit. The count before that, 2,604, was after the audit's six findings - the hash that belongs to the table and not to the thread, the float that is whole in both configurations, the number past the top of the range, and the table's collision, load-factor and growth tests landed: the six new tests are the table finding every key where it was put, the table refusing a key that was never put, the table against the standard library's map, two keys under one hash staying two entries, the table surviving every growth, and the hash's low bits carrying the keys into different buckets. The count before that, 2,592, was after the CPU probe became the crate's own and the byte dispatch and the substring search followed it landed: the twelve new tests are the probe against the standard library's
answer, the probe's cache answering the same thing twice, the byte dispatch
against the upstream crate's answers, the iterator walked from both ends, the
substring search's answers against the upstream crate's, the pair scanner
against the upstream crate's, and the six doctests of the substring facade.
The count before that, 2,580, was after the LZMA model, the watchdog and the
vector path learned their limits landed: the four new tests are the one row of the literal table per context, the
header with the worst properties byte that is an error and not a bomb, the
properties outside the specification that are refused, and the round that
hangs and takes the process down with it. The count before that, 2,576, was
after the count learned to write its thousands on every machine landed: the
seven new tests are the two twins over the same files writing the same
bytes, the note landing in the newest clause while the older clauses keep
their story, the carriage returns of a Windows checkout surviving the
stamp, the workflow saying the same count as the notes, a note with a colon
refused instead of placed, a count of seven digits written with its
thousands, and the notes of the repository stamped the same way by both
twins)
(re-snapped 2026-10-23, after the cache comparison learned to ask the tree:
the three new tests are the probe that says whether the fixture can be
read, the answer that is not retried, and the retry that is bounded)
(re-snapped 2026-10-22 once more, after the Ogg comment headers and the ASF
family: the six new tests are the three that read the Ogg comment under each
codec's own header name, the one that reads an Opus file through the header
it actually carries, the one that reads an Ogg Theora file and holds the
claim on it, the one that holds the claim on a `.wma` and reads it, and the
two that read a legacy Word document through a compound file built for the
test and hold the claim on the template beside it. The count before that,
2,552, was after the licence and the LASzip GPS time
fix: the three new tests are the two that hold the licence of every crate in
the tree, and the one that pins the refusal of a `.laz` whose GPS time coding
never settles. The count before that, 2,549, was after the PDF pages that are
drawn were rasterised: the eight new tests are the tool's own page against the adapter's, the
dimensions of the page it wrote, the tool that is not installed, the tool that
fails, and the pages of a document that has an image of its own. The count
before that, 2,541, was after the CRAM fqzcomp codec landed: the ten new
tests are the eight frames of the reference implementation, one for each shape
the codec writes, the frame the reader refuses, and the block of the container
that carries one of them. The count before that, 2,531, was after the CRAM name
tokeniser landed: the twenty
new tests are the five frames of the reference implementation, one for each
shape the codec writes, the sixteen checks of the token types, and the block
of the container that carries one of them. The count before that, 2,511, was
after the CRAM rANS Nx16 codec landed: the twelve
new tests are the nine frames of the reference implementation, one for each
flag the specification gives the codec, the seven-bit integer, the frame the
reader refuses, and the block of the container that carries one of them.
The count before that, 2,499, was after the CRAM adaptive arithmetic landed: the
thirteen new tests are the twelve frames of the reference implementation, one
for each flag the specification gives the codec, and the block of the
container that carries one of them. The count before that, 2,486, was after
GRIB's template 5.53 landed: the two new
tests are the bi-Fourier field of the limited area models, in the two
truncations ecCodes writes, and the test that refused the template was
replaced by the ones that read it. The count before that, 2,484, was after
the encodings that declare themselves landed:
ISO-2022-JP, UTF-7 and the EBCDIC code pages other than 037, whose twelve
new tests are the tables of the reference implementation, the designations
of RFC 1468, the `+<base64>-` form of RFC 2152 and the failures of both.
The count before that, 2,472, was after the streaming shape of the netCDF
classic
model landed: the two new tests are the file that says it holds no records and
the file whose records are counted from its own length, and the test that
refused the shape was replaced by the ones that read it. The count before that,
2,470, was after the CRAM rANS codec landed: the seven new
tests are the three frames of the reference implementation, the frequency
table of the specification's own example, the ITF-8 integer, the frame this
reader refuses, and the container block that carries one of them. The count
before that, 2,462, was after the Zarr v3 layout landed: the new test
is the layout, and the sixteen before it are the LZ4 block, the blosc frame,
the split block and the shuffle. The count before that, 2,363, was after
the GRIB2 complex packing landed: the
four new tests are the packing itself, the message that holds two fields, the
second order of the spatial differencing and the bit map. The count before
that, 2,359, was after the facts index, the MCP server and the three
formats landed: the index has its own end-to-end target, the server has
another, and the netCDF-4 names come out of a fractal heap -- and of the
group's own object header, which is where a small netCDF-4 file keeps them.
The attributes of a netCDF-4 file are read too, and the same `ncdump`
oracle lists them. The members of a type are read as well: the names and
the values of an enumeration, and the names and the types of a compound.
The values of a netCDF classic file are read too, one line per element
with the index that locates it, against the `ncdump` oracle the netCDF
library ships for the 360-day fixture. The v3 Lotus sheet is read now
too, and its oracle is the corpus's own pair: `example.wk1` and
`example.wk3` are the same sheet in two layouts, so every cell the v3
reader prints has to be the v2 reader's cell, at the same address, with
the same words. The deflate filter of an HDF5 chunk is undone too, and
its oracle is the producer's own generator: the HDF5 library's
`test/gen_deflate.c` writes the fixture, and the value it writes at
(i, j) is `j % 5`. The v4 Lotus sheet is read as a document of tables,
and its oracle is the corpus's own trio: `example.wk1`, `example.wk3`
and `example.wk4` are the same sheet in three layouts. The Millennium
sheet is read now too, and its oracle is the corpus's own pair:
`example.123` and `example.wk1` are the same sheet in two layouts).
The GRIB2 complex packing is read now too -- the groups the field is split
into, the reference value of each group, and the spatial differencing of
the first and the second order -- and its oracle is NOAA's own g2c library,
the one NCEP writes those files with: every value the reader prints was
compared with what that library reads out of the same bytes, over all 307
messages of the producer's file, field by field, and over a WRF file that
uses the second order of the differencing. The **blosc** codec of the Zarr
arrays is read too, and its oracle is the pair that writes those frames:
c-blosc itself and `numcodecs`, the codec library `zarr-python` sits on.
Two rules the re-snapshot rests on. The gate runs on the tree the commit
carries: the hunks of the shared documents are staged before the gate and
not after it, or the tree the gate measures is not the tree the commit
holds -- and the test that compares a crate README's claim table with the
crate's registry then fails on a tree that was never going to be committed.
And each block's commit carries the text of that block: the sentence that
says a format is read belongs to the commit that reads it, and the
sentence that says it is refused belongs to the commit before, because
that is what is still true there.

Per suite:
`rgx-core` 902 (+6 ignored) · `rgx-adapters-archive` 281 (+1 ignored) ·
`rgx-adapters-inspect` 341 · `tabular` 246 · root `src/main.rs` 109 ·
`media` 104 · `pdf` 98 · `tests/cli.rs` 77 ·
`rar-codec` 68 unit + 24 integration (compressed 8, multivolume 5, roundtrip 8,
winrar_oracle 3) · `office` 55 · `mail` 37 · `threed` 32 · `llm` 28 ·
`walk_diff` 14 · `tests/cache.rs` 16 · `tests/mcp.rs` 12 ·
`tests/crate_readmes.rs` 10 · `tests/crate_licence.rs` 2 ·
`tests/facts_index.rs` 7 ·
`pick` 8 · `legacy_formats` 14 ·
`tv_overlay` 5 · `inspect_formats` 5 ·
`tests/graphics_formats.rs` 4 · `tests/hidden_files.rs` 4 ·
`tests/images.rs` 4 · `sigroll` 4 · `tests/zarr.rs` 4 ·
`docs` 11 · `ablation` 3 · `cad_formats` 3 · `cjk_encodings` 3 ·
`jbig2_fixtures` 3 · `fax_fixtures` 3 ·
`error_chain` 2 · `office_lock_files` 2 · `raster_formats` 2 · `rgx_tv` 2 ·
`scientific_formats` 2 · `golden` 1 · `panic_sweep` 1 ·
doc-tests 8 (rgx-core 5, rar-codec 2, archive 1; one `rgx-core` doctest is
ignored). **Re-snap from a real run**
— this snapshot rots, and it had rotted in three places before it was
checked against one, and a fourth (`tabular` listed twice, 88 and 74) was
still there until this merge. It rotted again in four more — `media`,
`office` and `threed` behind the tree and `crate_licence` missing from the
list — until the run of 2026-10-23. The same counts appear in the comment
block under `ci.yml`'s test step, so one run re-snaps both.

`tests/golden.rs` is **opt-in and vacuous unless `tests/golden/` exists**
(gitignored; harvest with `scripts/harvest-golden.ps1` on Windows or
`scripts/harvest-golden.sh` on Linux, which takes the same kinds of sample
from the Linux equivalents of the places the Windows script takes them from).
The Linux harvester verifies each sample against the pattern before it
records it, so a manifest never names a sample the tool cannot find.

Integration tests in `tests/` run the real binary via
`env!("CARGO_BIN_EXE_rgx")` against fixture trees built at runtime in a
`std::env::temp_dir()` path. **The name of that path carries a counter and
not the clock**, and the rule behind it lives in one place:
`tests/common/mod.rs` owns it, and every test file asks it for a directory
rather than building one. The rule used to live in nineteen files and the
copies drifted -- one of them did not compile, and the rest made the
directory with `create_dir_all`, which reuses a directory that is already
there, silently, so a directory left behind by a killed run was adopted as
if it were fresh. A second copy of the rule is now an audit that fails:
`tests/cli.rs::one_file_owns_the_name_of_a_temporary_directory`. No
network, no external tools.

| File | Holds down |
|---|---|
| `tests/cli.rs` | end-to-end flags, output shape, exit codes |
| `tests/images.rs` | a hit *inside* an ISO, and the metadata-only answer for a `.vhd` |
| `tests/walk_diff.rs` | the in-house walker against `ignore` as oracle |
| `tests/error_chain.rs` | the adapter-failure note and the alternate `Display` |
| `tests/pick.rs` | `--pick`, with a stub `fzf` |
| `tests/cache.rs` | the `--cache` memo and its key |
| `tests/common/mod.rs` | the name of a test's temporary directory |

Unit tests live in the crates. Three things inside `rgx-core`:

- **`differential.rs` is GONE**, with the `grep-searcher` dev-dependency it
  needed. It held the searcher against `grep-searcher` over a pattern ×
  haystack × flag matrix. What it left is an engine whose only oracle is its
  own two paths — slice and reader can only contradict each other, so a
  defect that makes both wrong the same way is invisible. Every real bug in
  this area since came from comparing against `rg` at the CLI.
- **`searcher/oracle.rs` is the replacement**, on the `regex` crate that was
  already a dev-dependency: a pattern × haystack matrix (≥200 checked cells
  enforced in the test so it cannot silently degenerate), zero disagreements,
  comparing *which lines matched* rather than byte offsets (line splitting is
  rgx's own job, and re-testing the tokenizer would bury what can drift).
  `.unicode(false)` puts it in byte mode; haystacks are ASCII because that is
  where the two are *specified* to agree. Lookaround patterns are the cells it
  deliberately skips, listed so the refusal boundary stays exercised. It drives
  both `search_slice` and `search_reader` (at five chunk sizes) over the same
  matrix, and what it still cannot catch is a defect that reproduces in rgx
  *and* in its own offset-to-line mapping.
- `searcher/tests.rs` (87) and `regex/tests.rs` (34). With the differential
  gone, `searcher/tests.rs` states the line contract directly rather than
  comparing against a hand-written expectation; a change there deserves the
  same scepticism as a change to the searcher.

Conventions: descriptive snake_case names that state the property
(`a_7z_lzma1_stream_with_no_end_marker_still_decodes`), a `//!` header saying
what the test is for, scratch directories that clean up after themselves.

**A test that exercises only the shapes the code already handles is not a
test.** Two shipped anyway, both found by running the tool rather than the
suite: the brotli corpus passed while the decoder failed on the repository's
own `testdata/brotli_big_q*.br`, because every vector was small and the
fixtures were not in them; and `every_reference_brotli_stream_through_the_adapter`
calls `Decompress.extract()` directly, bypassing the Registry and the CLI, so
it cannot observe that a decoder is unreachable. When adding a case, add the
one that was missing, and prefer one that goes through the path a user does.

**A comparison between two runs has to know which of the two lost the
answer.** `tests/cache.rs` compares a run that answers from the memo with a
run that re-reads the files, and the two do not meet the same things: the
second one meets the filesystem. On the Windows runner the second one
answered *nothing* once in thirteen runs — the 45 lines of the fixture
became 0 — and the assertion could not say why, because rgx walks past a
path it cannot read and says nothing about it (the `fs::read` that fails is
a `WalkState::Continue`, `src/main.rs`), so "the machine lost the file" and
"the cache lost the answer" look the same from the outside. Three things
follow. A scratch directory's name carries a **counter** and not the clock:
the old name was the process id and the wall clock in nanoseconds, and two
tests inside the same 100-nanosecond tick got the same path, so the first
one to finish deleted the tree the second one was searching. A short
answer is **retried, a bounded number of times**, and the tree is asked
before the failure is named: the test reads the fixture itself, and a tree
the test can read and a run that still answers short is rgx losing the
answer. And the assertion states the number of lines the fixture answers,
because an empty answer on both sides is equal to an empty answer on one
side, and the comparison would pass on a cache that answers nothing at all.

Fuzzing, two independent mechanisms:

- `rgx-core::fuzzkit` — deterministic, dependency-free, runs inside ordinary
  `cargo test` on stable:
  ```rust
  #[cfg(test)]
  mod fuzz {
      use super::*;
      #[test]
      fn never_panics_on_arbitrary_bytes() {
          let corpus: Vec<(&str, Vec<u8>)> = vec![("valid", fixture_bytes())];
          rgx_core::fuzzkit::assert_never_panics(corpus, 2000, "myadapter", |data| {
              let _ = MyAdapter.extract(data, "fuzz.bin"); // Err/Bail fine, panic = fail
          });
      }
  }
  ```
- `crates/rgx-core/fuzz/` — a `cargo-fuzz`/libFuzzer target `process` that
  drives the **full registry**. Needs nightly + clang:
  `cargo +nightly fuzz run process` — run it from `crates/rgx-core`, not the
  repo root, or cargo-fuzz looks for `./fuzz` and fails.
  **On Windows it cannot link**: the nightly toolchain here ships no
  `librustc-nightly_rt.asan.a` for `x86_64-pc-windows-msvc`. The stable
  replacement that runs as ordinary `cargo test` is
  **`tests/panic_sweep.rs`** — every real corpus fixture offered to all 163
  claimed extensions (cross-feeding one format's bytes into every other
  parser) plus two mutations each, inside `catch_unwind` so one run reports
  every finding instead of the first. 10,758 inputs, 1.3 s. It found the
  `.img` panic on its first run.

---

## 7. Security

- **Decompression bombs.** `crates/rgx-core/src/compress/cap.rs` defines
  `OutputCap`/`Bounded`; every bounded decode counts bytes *as emitted* and
  reports a short read as `capped` rather than returning a truncated payload
  that looks whole. Decoding first and measuring afterwards costs exactly what
  the bomb was built to cost.
- **Member budgets live on the producer side**, not in the pipeline:
  `crates/rgx-adapters-archive/src/budget.rs` exposes `budget()` /
  `set_budget()` / `reset_budget()`, read through `MemberSink`.
  `Adapter::extract` never sees a `Ctx`, so the cap has to live where the
  members are built. Defaults come from `Ctx::default()` (`max_depth: 4`,
  `max_members: 4096`, `max_file_size: 1 << 30`); `RGX_MAX_MEMBERS` and
  `RGX_MAX_MEMBER_BYTES` override, `-M/--max-filesize` wins over both. There
  is also a per-member ceiling on entries *examined*, so a zip whose entries
  all fail to decode does not rescan its central directory per entry.
- **Memory mapping is a promise about the file.** `src/mmap.rs` clips every
  slice to a *verified* length (`MappedFile::live_len`): mapping length, any
  caller limit, and the file length as the OS reports it *now*. Truncating a
  mapped file turns a read past EOF into `SIGBUS`/an access violation, not an
  error return, and `memmap2` does not check. Off by default (`RGX_MMAP=1`)
  because it measured ~12% slower end to end on Windows.
- **External tools are opt-in by presence, not by flag.** `rgx-adapters-docs`
  probes `PATH` (memoised per process) and skips the adapter when the binary
  is missing. Bytes go in on stdin and come back on stdout; nothing is passed
  to a shell. `--pick` works the same way and never re-splits user-supplied
  `--fzf-arg` values.
- **The extraction cache is off unless asked for** (`--cache`, default
  `$RGX_CACHE_DIR` or `~/.rgx/cache`) — a wrong default serves stale bytes.
  Its key is a SHA-256 over a length-prefixed preimage of: format tag +
  version, a build stamp of the running executable (length + mtime), the path
  as the walker reported it, size + mtime, the `Ctx`, and the adapter chain
  with declared versions.
- **No tokens in release scripts.** `scripts/release-all.sh` authenticates
  with stored git credentials.

---

## 8. Environment variables

The variables a user sets are in [MANUAL.md §8](MANUAL.md#8-environment-variables).
The ones below are instrumentation and test hooks.

| Variable | Effect |
|---|---|
| `RGX_ZIP_BOMB_BYTES` | test-only: scales the zip-bomb corpus down |
| `RGX_MMAP` | mmap read path for big files: `1` forces on, `0` forces off; unset = platform default (mapped on Linux, read elsewhere — see `src/mmap.rs`) |
| `RGX_PROFILE` | per-adapter timing counters on stderr |
| `RGX_MASK_STATS` | packed-match-mask counters |
| `RGX_NGRAM_STATS` | pack query: print how many files the n-gram filter rejected |
| `RGX_ABLATE_MASK` | ablation instrumentation: decline the compiled mask at pattern compile (cost changes, answers never do) |
| `RGX_ABLATE_NGRAM` | ablation instrumentation: force the n-gram filter's stand-down state (same contract) |
| `RGX_ABLATE_EXTENTS` | ablation instrumentation: stand down the plan-time n-gram filter and the extent gap rule (same contract) |
| `RGX_EXTENT_STATS` | pack query (buffered path): bytes read vs pack payload and unit count |
| `RGX_WALK_STATS` | `read_globs` tally on exit |
| `RGX_RUNS` | read-only tally of in-house-engine runs |
| `RGX_CACHE_DIR` | default `--cache` directory |
| `RGX_BASE` | benchmark harness (`status_table --rgx-base`): second rgx build to A/B in the same process |
| `RGX_VSD_CORPUS` | Visio corpus directory for the `.vsd` test |
| `RGX_CHOSEN` | benchmark example: echo the chosen engine |
| `RGX_STATUS_OUT` | `scripts/bench-status.sh`: redirect the transcript |
| `RGX_ABS` | `scripts/adapter-subset.sh`: repo root override |
| `RGX_PROBE_TRACE` | `scripts/walk_patterns.rs`: adapter-probe trace |
| `RGX_KEEP_WALK_CORPUS` | `tests/walk_diff.rs`: keep the scratch tree |

---

## 9. Benchmarking

`scripts/bench-status.sh` regenerates `benchmark/status.md` from one command:
it builds the release binary and the harness
(`crates/rgx-core/examples/status_table.rs`, where the gate, the interleaving
and the floor live), then runs it. The transcript goes to the system temp dir
and the path is printed, so a run never dirties the tree. `--help` lists every
option; `--rgx-base <path>` A/Bs two builds in one process.

Four rules, and any new benchmark must keep them:

1. **Thread-matched.** `rgx -j N` against `rg -j N`, same N, printed in the
   header. ripgrep caps its own default at `available_parallelism().min(12)`,
   so an uncapped comparison compares thread counts, not code.
2. **A count gate in front of every timing line.** The summed `-c` of rgx
   against ripgrep on the same corpus; the timing is not printed if they
   disagree. A zero, a mismatch, an unparsable count, or two zeros suppresses
   the line.
3. **A verdict that can refuse.** Inside the ±3% CLI floor a row is a tie.
   Outside it, a named winner only if every sample of one engine is below
   every sample of the other. Overlapping distributions print "overlap, not a
   result" rather than a ratio.
4. **The floor, measured, before any ratio is believed.** Spawning a process
   on a developer Windows box costs ~16 ms — a binary whose entire `main` is
   `print!("hi")` measures 16.4 ms/iter and `rgx --version` 17.5 — so every
   rgx number on this machine carries 16 ms that is not rgx. A constant
   offset does not cancel in a ratio; it compresses every ratio toward 1, so a
   walk reading 0.89x may be 1.33x. Measure with `scripts/bench-status.sh`
   (Rust, `Instant`, `Stdio::null`), with `status_table --rgx-base`, or with
   a `for /L` loop inside a `.bat` and the floor subtracted from both sides.
   If a number cannot be reproduced by one of those, it is not a number yet.

### What the measurements say

**Measure where the time goes before changing anything, and believe the
negative result.** On a walk-dominated corpus no engine change pays.

| corpus | shape | result |
|---|---|---|
| one file, 246,541,116 B | engine alone | rgx ahead on all nine patterns, +33.1% to +113.6% |
| generated tree, 20,028 files | walk-dominated | every search row a tie, an overlap or a single-digit separation; `walk (--files)` +60.7% |
| `crates/`, 573 files | walk-dominated | tie; the walk is 85.7% of the run |
| same, `--no-ignore` | — | walk falls 10.55 → 3.54 ms |

The per-row table, with every count, is [`benchmark/status.md`](benchmark/status.md) §1. Do not restate a number from it here: these four rows are the summary, and a summary that drifts from the table it summarises is worse than none.

**Ignore matching is the cost on a walk-dominated corpus**, and the mechanism
is the COMPILE of the rule set, once per `.gitignore`, at ~58 µs per pattern
— not a per-entry match. Holding patterns at 65 and moving entries from 1 to
1024 moves the cost 4.55 → 7.86 ms; a per-(entry × pattern) cost would move
16×. `RGX_WALK_STATS=1` prints the tally. Full working, and the measured-but-unbuilt
per-glob split that would take the `crates` walk from 10.73 to 6.09 ms:
[`benchmark/findings.md`](benchmark/findings.md) §1.

**The fast-shape path for `.gitignore` existed, was correct, and was
unreachable for years**: the builder demanded *every* file glob have a `*.ext`
or `pre*` shape, and this repository's own ignore file was 17 of 35. One
anchored line cost the whole file its fast path.

**Numbers with no harness behind them.** Do not quote them:

| figure | status |
|---|---|
| 25.6% / 29.2% walk share | lived only in a commit message |
| 4806 ms / 3517 ms read floor | same; superseded by the `crates` row above |
| "~13.9 ns" confirm | superseded by the `CONFIRM_NS` table |
| `LIST_CAP = 8` cliff (35.6 → 68.7 ns) | unsourced; `vm.rs` now reports 22 ns |
| per-buffer skip worth 12.1–100% | harness `prefilter_ablate` no longer exists |
| per-candidate jump worth 25.9–56.6% | same |

**Negative results that survived re-measurement**: raising
`MAX_BITMAP_INPUT` was **measured slower** at 256 KiB → 1 MiB (43.8 → 50.1
ms on a 17 MiB file with multi-KB lines), and that verdict was taken against
a `LineBuffer` that never shrank. Re-measured after the drop fix it
reversed: a 64 MiB cap wins 19% on the single-long-line shape and is
indistinguishable elsewhere, and since a fill is bounded by
`LineBuffer::MAX_BUF` (8 MiB) the decline cannot fire at all. **The old
"raise it and you lose" and "the fix is a windowed map" are both
superseded** — see `benchmark/findings.md` §18. Hoisting `fast.plan` out of the
per-line confirm is ~0.4%. The per-file micro-optimisations (double
`stat`+`open` above `BUFFER_PATH_MAX`, three per-worker regex compiles, a
`GetConsoleMode` per matched file) all measured **inside the floor**: every
published row came out "overlap, not a result". Picking a rarer pair for
`pair_offsets` gains nothing on `let mut` — the current pair is already the
best of its 21, `frequency::rarest_pair` is 22% worse, and candidates are
only 12% of that row. Rewriting the pair kernels for throughput gains
nothing either: `pair_offsets` measures **40–46 GB/s** against a 10 GB/s
naive byte walk (`crates/rgx-core/examples/scan_floor.rs`), so the kernel is
7 ms of a 43 ms `search=` and the rest is the line walk. Raising
`LineBuffer::INITIAL_BUF` from 64 KiB to 256 KiB to cut `ReadFile` syscalls
is **slower** — the two bit maps scale with the fill and evict the haystack
from L2 (~50 ms against ~43 on the absent literal,
`benchmark/findings.md` §5). Redundant work is
still worth removing; it is not worth a number.

---

## 10. Release

**The version moves when the maintainer launches, and 0.1.1 is what the
launch carried.** Raising it is the launch decision, never part of a change
— and a bumped version that publishes a release before that decision is
what the freeze is for. The version was frozen at 0.1.0 through the whole
review: every correction of the loop went into the tree under 0.1.0, and
the registry carried the tree of the twenty-third of October while the tree
itself moved on for days. The launch of the twenty-seventh raised it to
0.1.1, and the registry and the GitHub release carry the tree the loop
produced.

The one thing that moves a version is a change that has to reach crates.io.
The crates are published at the version of the root: `publish-cratesio.sh`
reads the version from the root `Cargo.toml` and publishes every package
with it, and a published version cannot be edited — so a crate that carries
a correction under a version the registry already has would never be
published at all. A correction in a crate is therefore a patch of 0.0.1
(0.1.0 became 0.1.1 at the launch), and it waits for the launch that
carries it.

Bump `version` in the root `Cargo.toml`, then:

```bash
bash scripts/release-all.sh     # --dry-run to rehearse, --skip-tests to iterate
```

It gates on the same clippy and `cargo test --release --locked --workspace`
pair, builds the portable and znver4 Windows zips into `.dist/`, builds Linux
artifacts on the docker host via `scripts/build-linux.sh`, then tags and
publishes. The per-platform twins are `powershell -File
scripts/build-release.ps1` (`-SkipTests` to iterate) and `bash
scripts/build-release.sh` (`--skip-tests`), and the publish side is
`scripts/publish-release.ps1` / `scripts/publish-release.sh`. The Linux
build writes to `.dist/local/`, because `.dist/` holds what the release
publishes: the glibc tarball, the musl tarball and the distro packages that
`scripts/build-linux.sh` builds in Docker.

CI releases on `git push origin rgx-v<version>`: a 9-entry matrix
(x86 / znver4 / aarch64 Windows; gnu / musl / znver4 / aarch64 Linux; both
macOS arches), then `scripts/package-linux.sh` builds and install-verifies
deb/rpm/apk/pkg.tar.zst in per-distro containers, then the publish job
attaches everything to the GitHub release. Asset naming is
`rgx-v<version>-<asset>.<zip|tar.gz>`. `RUSTFLAGS` is only ever
`-C target-cpu=znver4`; the linker always comes from `.cargo/config.toml`.
The publish job publishes only when there is no release yet: the release is
normally published by `scripts/push-github.sh`, with the assets the local
pipeline built and install-verified, and the winget manifest names the hash
of that windows zip — a CI publish would replace those assets with ones
nobody verified here, and with a windows zip of another hash, which is a
manifest that installs nothing.

**The Linux binaries are built inside Docker, in the bullseye image, and not
on the runner.** glibc 2.31 is the floor the `.deb` and the release notes
promise, and the runner's own image is newer than that: `ubuntu-24.04`
carries glibc 2.39, and a binary linked against it dies on the first call
that needs the newer symbols — `version 'GLIBC_2.39' not found` — which is
exactly the `debian:bookworm-slim` and `ubuntu:20.04` containers where
`scripts/package-linux.sh` verifies the install. The symptom is a
*packages* job that fails while every *build* job is green: the build is
fine and only the install is not, and nothing warns of the floor before the
binary refuses to start, because fpm's `dir` input writes no `Depends` at
all. The symbols tell the two apart — a bullseye build asks for at most
`GLIBC_2.30`, a trixie or `ubuntu-24.04` build for `GLIBC_2.39` — and so
does the binary itself, which answers `rgx --version` on bookworm and on
ubuntu:20.04 when it was built on bullseye and answers nothing when it was
not. The CI therefore runs the Linux builds in `rust:1.98-slim-bullseye`,
the image `scripts/build-linux.sh` uses, so the two pipelines cannot drift;
each build gets a named volume of its own, because cargo's fingerprint does
not know about the image and a build made elsewhere would be taken for a
fresh one.

Consumers install via `irm https://raw.githubusercontent.com/danalec/rgx/main/install.ps1 | iex`
(SHA-256-verified, `-Channel znver4` for the tuned build) or
`winget install --manifest .winget`. On Linux:
`curl -fsSL https://raw.githubusercontent.com/danalec/rgx/main/install.sh | bash`
(`--channel gnu|musl|znver4`).

**Both installers pin the digests of the assets they may install** — two
Windows zips in `install.ps1`, three Linux tarballs in `install.sh` — and
both refuse a download that does not match. The pins are release data, and
the release owns them: `scripts/rewrite-digests.sh` rewrites all five from
the artifacts that are about to be published, and refuses to finish if the
rewrite did not move, which is what keeps a hand-cut release from shipping
an installer that throws "SHA256 mismatch" at every user.

**The rewriting belongs to every path that publishes, not to the one that
builds.** The pins went stale once because the artifacts were rebuilt
outside the release flow — `scripts/release-linux.sh` and
`scripts/build-release.ps1` rebuild without touching them — and the GitHub
publish path rewrote the winget hash but not the five pins. Nothing turned
red: the winget manifest named the hash of the asset the release carried,
the installers named the hash of an older one, and both were correct about
themselves. So the rewrite is a script of its own, called by
`scripts/release-all.sh` and by `scripts/push-github.sh`, and the GitHub
path commits it before the mirror is built — the mirror carries the pins of
the assets it publishes.

**Homebrew installs from the macOS archive, and the formula's digests are
the digests of the archive that is about to be published.** The CI builds
the macOS archives on its macos runners while the local pipeline builds
the windows ones and the docker host the linux ones, so the release is a
joint act: `scripts/push-github.sh` fetches the macOS archives from the
CI run of the tag, publishes them beside the nine verified assets, and
rewrites `Formula/rgx.rb` — the URLs, the digests and the version — the
way it rewrites the winget hash and the five pins. A machine with no
macOS archive has no digest to write, so the formula is left alone and
the script says so.

**The formula's name is not the crate's name.** On Homebrew it is `rgx`,
because that name is free in homebrew-core; on crates.io it is
`rgx-search`, because that name was taken there. Both install the same
`rgx` binary. The formula is not a tap of our own: homebrew-core is a git
repository like any other, and `scripts/publish-homebrew.sh` (and its
`.ps1` twin) does what a pull request is — a branch, a commit and a
merge — against the fork `danalec/homebrew-core`, after checking that the
release artifact the formula names is actually there. What the CI on that
pull request runs, `brew audit --new --formula` and `brew readall`, needs
a Mac, and the script says so instead of pretending the pull request is
the last step.

**The release carries the assets that were built, and they have to be built
from the tree the release publishes.** Three builders make one release: this
machine builds the windows ones, the docker host the linux ones and the CI
the macOS ones, and each runs at its own moment. Whatever `.dist/` holds
when `scripts/push-github.sh` runs is what the release carries, so a
`.dist/` filled yesterday publishes yesterday's program — and the published
release did exactly that: the nine local assets carried the 22 October tree
while the repository published the 23 October one, and what was missing was
not a rebuild date but the code: the media, office and pdf adapters, the
scan kernels and the dependency versions. The repository showed them and the
binary did not have them. The macOS archives are the exception that proves
the rule: they come from the CI run of the tag, so they are the published
tree by construction, and the formula pins their digests. The bytes are not
reproducible either: the linker stamps the link time into the PE header, so
a rebuild of the same tree is the same size and a different file, and the
only digest that can name an asset is the digest of the file that was
published — which is what the five pins, the winget hash and the formula
carry.

**crates.io publishes new crates on a token bucket: five at once, then one
every ten minutes.** The registry answers the sixth upload with a 429 and
the minute the next one is accepted, and the bucket holds five tokens and
refills one every ten minutes — not a quota that empties once a day. So a
first release of thirteen packages is two hours of uploads, not thirteen of
them, and the script's five-minute wait is what fits that cadence: the
attempt after the window opens is the one that succeeds, and twenty
attempts at five minutes is an hour and a half of tolerance for a gap of
ten minutes.

---

## 11. Vendoring

rgx **never copies a file from any upstream**. Every vendored file is an
**independent reimplementation** — written from understanding the upstream
source, the API contract and the per-platform algorithm.

```bash
powershell -File scripts/check-vendoring.ps1   # exits 1 on any violation
bash scripts/check-vendoring.sh                # the same four rules
```

An independent reimplementation means: read the upstream source or spec to learn
the **API contract** (signatures, return types, `Option<usize>` semantics) and
the **per-platform algorithm** (byte-at-a-time loop, packed-pair SIMD, chunked
iteration, runtime feature detection); then write fresh code. No file-level
copies, no verbatim pastes, no `git show` + `cp`.

Every file under a vendored tree carries a `//!` provenance header naming the
upstream and the commit it was based on, with the words `independent
reimplementation` rather than `verbatim`.
`scripts/vendored-sources.tsv` records the same. **A row with `-` counts as a
failure on purpose** — a manifest that quietly omits a file is worse than one
that admits it has not been looked at.

The check enforces four rules: no upstream reference in any non-comment line
of `Cargo.toml`/`Cargo.lock`/`.cargo/config.toml`; no `[patch]` in
`.cargo/config.toml`; a provenance header on every vendored tree's root module
(the check accepts `vendored from` or `independent reimplementation`, so
legacy trees still pass); and no unlisted crates.io dependency.

**The other half of the rule is `scripts/check-drift.sh`**
(`scripts/check-drift.ps1` on Windows): the check above enforces the *shape*
of the vendoring, and it cannot notice that a file was copied on Monday and
that the upstream changed it on Tuesday. The drift check asks the other
question — has the upstream changed the recorded source since the recorded
pin? — and it compares upstream against upstream, so the copy-time rewrites
never enter into it and there is nothing to normalise. A row pinned with `-`
counts as a failure there too.

`src/cli/` (arg parser and shell completions) is an independent reimplementation
of an upstream hand-rolled CLI parser's contract, rewritten from the rgx
grammar and the tests of the layer. It is the only parser in the build.

### The licence is one licence

The project is **Apache-2.0 only** — not "MIT OR Apache-2.0", not a split
between the pack store and the rest. Every tracked `.rs` file carries an
SPDX header on its first line, and
`tests/cli.rs::every_file_carries_its_spdx_header` reads the file list out of
git and fails on the first file that carries a different licence or none.

A file without a header is a hole in the claim, not a neutral fact: the
licence of a file nobody labelled is whatever the reader guesses, and the
reader who guesses wrong is the one who ships it. There are no exceptions
to the one header: every package in the workspace declares
`license = "Apache-2.0"`, and the audit allows one expression and one only.
The provenance of what is *not* rgx's code — the layouts learned from third-
party implementations, the Rust dependencies, the HPGL-Plotter fixture — is
named in `NOTICE`, which is where a reader looks for it.

### The one exception: `crates/rar-codec/`

A `rustfmt`-ed **port of libarchive's RAR support**
(`archive_read_support_format_rar{5,}.c`, BSD-2-Clause) plus RARLAB's
published RAR technote — **not** an independent reimplementation. Its header
says "Vendored from libarchive" and its rows in
`scripts/vendored-sources.tsv` say **`verbatim`**.
`check-vendoring.ps1` accepts either string in a header, so **the check
passes while the stated rule is broken**. Recorded, not overlooked.

Before re-syncing it: the copy is `rustfmt`-ed from upstream rather than raw
blobs, and the clippy edits in the manifest notes exist only because rgx's
gate is `cargo clippy --workspace --all-targets -- -D warnings`, which
upstream does not run — prefer fixing them upstream; a re-sync means
re-applying them.

**This section describes the crate as it was.** Every module of it has since
been rewritten as an independent reimplementation — `crates/rar-codec/src/lib.rs`
says so, module by module, and each row of `scripts/vendored-sources.tsv`
that is not the manifest says "Written fresh" or "Written from the published
algorithm". The only row still reading `verbatim` is
`crates/rar-codec/Cargo.toml`, and a manifest is not code. No upstream file
remains in the tree; the BSD 2-Clause terms the port inherited are kept on
the record in `NOTICE`, which is what lets the tree be Apache-2.0 today.

Behaviourally, `ppmd7.rs` and `unpack3.rs` are present, so PPMd var-H blocks
decode. What does **not** decode is PPMd *filters*, VM-program filters,
encryption and RAR 7.x (`crates/rar-codec/src/lib.rs`). An unsupported member
is dropped quietly — `rar.rs` is `if let Ok(bytes) = archive.extract(e)` —
and if nothing extracts, the adapter falls back to a names-and-sizes header
listing. `ppmd7.rs` now carries unit tests -- heap floor, range-init
rejection and truncation, plus a never-panics floor over arbitrary bytes.
There is still no decode-against-known-good test: `rar-codec` encodes
store-only, so no PPMd-encoded RAR can be crafted here.

---

## 12. Gotchas

Each has already cost debugging time, so each is an invariant in practice.

- **MessagePack integers are big-endian.** The format stores them in network
  byte order, which is the opposite of every other binary format in this
  crate. A reader that reaches for `from_le_bytes` decodes a file mode of
  16895 as 65345 and a borg timestamp of 1792419512700472100 as
  2633477522910390040, and **nothing crashes**: the numbers are simply other
  numbers, and the paths that come with them are the paths of a different
  archive. The test `msgpack::tests::the_integers_are_in_network_byte_order`
  pins it. The lesson underneath is the one this repo keeps making: the
  format is transcribed from the producer's own source, and the numbers
  are checked against the producer's own output, because a decoder can be
  *nearly* right and still be wrong in a way that produces plausible
  output.
- **A borg entry's `size` counts the whole entry, the CRC included.** The
  entry is `crc(4) | size(4) | tag(1) | id(32) | data`, and `size` is the
  length of all of it — so the reader advances by `size`, not by
  `size + 4`, and the payload runs to `off + size`, not `off + 4 + size`.
  Reading it as "the size counts from the tag" puts the reader four bytes
  off: the CRC of the *second* entry then covers the wrong bytes and the
  segment is refused, or — worse — the first entry's payload is four bytes
  short and the content is truncated. The code was right and the *doc* was
  wrong, and the way it was found was to read borg's own `write_put`
  rather than to reason about it: `size = data_size +
  put_header_fmt.size`, with `put_header_fmt` being `<IIB32s`, 41 bytes.
  What pins it is the real segment: its four entries have to tile the file
  exactly and every CRC has to match, and the fixture's tests do exactly
  that.
- **A member's path is logical, not a path on disk.** A member of a container
  is named `<the container's path>!<the member's name>`
  (`bundle.zip!script.py`, `outer.zip!middle.zip!inner.zip!deep/marker.txt`),
  and the `!` is what separates them. A `/` cannot do that job: a member's
  own name holds one (`docs/report.pdf`), so a slash-joined path says nothing
  about where the member lives - `bundle.zip/docs/report.pdf` reads as a
  directory `bundle.zip` that does not exist. The price is a reservation:
  the `!` ends an extension the way a separator does, so a file called
  `report.txt!draft` is read as the container `report.txt` and the member
  `draft`, and `ext_of` has to reject an extension that carries one. Every
  place that reads a member path back has to know the rule - `basename_of`,
  `ext_of`, the cache's `relative_of` and `restamp`, the index's `owner_rel`
  - and a place that forgets it does not fail loudly. The cache simply stops
  storing: a unit whose path cannot be made relative is dropped, and the
  symptom is `cache: 0 hits, 3 misses, 0 stored` and not an error. The index
  is the same: a member record whose owner cannot be found is a record whose
  answer is thrown away. The separators the index cuts at are written down
  once, in `tv_runtime::builder::MEMBER_SEPARATORS`. The stored form of the
  path changed with the rule, so the cache entry's version went with it
  (3 -> 4): an entry written under the old convention is a miss, never a
  path that names a directory that does not exist.
- **The high half of a CJK encoding is a pair of bytes, not one.** A file
  that declares `charset=Shift_JIS` and is read one byte at a time is not
  read differently — it is read *wrongly*, and the characters a search is
  for are not in the answer: what the answer holds is the Latin-1 mojibake
  of a two-byte sequence. The tables are therefore indexed by the lead
  byte and then by the trail byte, and the forms are tried longest first,
  because GB18030's four-byte form starts with a lead byte the two-byte
  form also uses. The tables come from the reference implementation
  (`scripts/gen_charset_mb_tables.py`), and what the sample pins down is
  the **decoder's** indexing of them: the tables are generated, so they
  cannot be mistyped, but the index that reads them can be. That is not a
  formality — the first version of the generator printed GB18030's
  four-byte ranges in decimal with a `0x` in front, so the table said
  `0x128` where the reference says `0x80`, and every four-byte character
  was wrong by a constant that no round trip of a *fixture* would have
  caught, because the fixture's own bytes were encoded by the same
  reference and the fixture's text is what the table claims.
- **The hidden files are read by default, and the repository's own state never
  is.** ripgrep's `--hidden` is the opposite of rgx's default: rgx reads the
  hidden files (a name starting with `.`, and the hidden attribute on
  Windows) because a format that keeps its own metadata in a dotfile is
  invisible otherwise — a Zarr array's `.zarray`, a `.zattrs`, a
  `.gitignore`. `--no-hidden` is the flag that puts ripgrep's default back.
  A version control system's own state (`.git`, `.hg`, `.svn`, `.jj`) is
  never walked, whatever the flag says: it is metadata *about* the corpus,
  and it is routinely larger than the tree it describes. The rules in it are
  still applied — a `.gitignore` and a `.git/info/exclude` are read and
  honoured — they are just not listed. The rule is
  `rgx_core::walk_policy::is_vcs_dir`, and the three walkers (the binary's,
  the store's, and the `tests/walk_diff.rs` oracle) have to make the same
  call or they disagree on every corpus that has a `.git` in it.
- **A Zarr array is a directory, and the answer is not in the file.** The
  `.zarray` manifest describes the array — the shape, the dtype, the codec —
  and the values live in the chunks beside it, in a format that says nothing
  about what it holds: the same eight bytes are eight `u1`, one `f8` or a
  ten-character string depending on the `dtype` line. So the reader leaves
  the file, decodes the chunks, and keeps the manifest's own bytes at the
  top of its answer, because rgx is a superset of ripgrep and a search for
  a key in the JSON still has to find it. The manifest is a **dotfile**,
  which is why the hidden files are read by default; the whole array
  disappears under `--no-hidden`.
- **A Lotus 1-2-3 v3 cell is not a v1 cell, and its number is not an `f64`.**
  The v3 (`.wk3`) record framing is the v1's -- a u16 opcode, a u16 length,
  the body -- but the body of a cell is the row, a block byte, the column,
  and then a payload the opcode names: `0x0016` a label (a format byte, then
  NUL-terminated text), `0x0017` a number, `0x0018` an integer. The number is
  an **x87 80-bit extended float**, ten bytes, not the v1's `f64`; read as an
  `f64` it comes out as the low eight bytes of the significand and a wrong
  answer. The column is **one byte**, and the byte before it is the *block*
  the cell belongs to: reading the two as one little-endian `u16` and
  dividing by 256 works on the example sheet only because every cell of it
  has block 0, and on a real v4 sheet it puts cells in columns that are not
  columns. What pins the layout is the corpus's own pair -- `example.wk1`
  and `example.wk3` are the same sheet, and every label and every number
  lands on the same address in both, with the same words. The integer cell
  is the one this reader leaves out: its unit is not established (the
  example sheet's twin reads exactly half of it, while the integers of a
  real v4 sheet only make sense as cents), so it is reported as not read
  rather than printed in a unit nobody can vouch for.
- **The Millennium cell record counts the column in 256ths of a
  character, and some of its cells are stored elsewhere.** The `.123`'s
  cell record is the row, the column, and the payload — but the column
  counts 256ths (256, 512, 768), so a reader that takes it for a cell
  count puts every label 256 columns to the right. And the six cells the
  file stores indirectly carry the row and the column with a reference
  to data that lives elsewhere in the file: they are left out and
  counted, because a cell whose data the reader has not found is not a
  cell it can vouch for.
- **A v4 cell's address names the table the cell belongs to.** The v3 and
  the v4 share the cell record — the row, a block byte, the column, and
  the payload — but the v4's sheet is a document of several tables, and
  the same (row, column) holds different cells in different ones: of the
  1 279 distinct (row, column) pairs of `DEMO.WK4`, 591 hold more than
  one cell. An address that does not name the table is an address two
  cells share, and the reader prints `B3R24C27` rather than `R24C27` for
  that reason.
- **An HDF5 deflate filter holds a zlib stream, and the first layout
  messages count an element's size as a dimension.** The deflate filter
  is not a raw DEFLATE stream: `src/H5Zdeflate.c` calls zlib's
  `inflateInit`, which is the RFC 1950 framing, and the file says so --
  every chunk of `deflate.h5` starts with `78 da`. Read as raw DEFLATE,
  the stream dies a few bytes in with "stored block length mismatch".
  And a layout message of the **first two versions** says its
  dimensionality is the rank *plus one*, the last dimension being the
  size of an element: `deflate.h5` says three, with the dimensions 50,
  50 and 4 -- fifty by fifty elements of four bytes, in a dataset of a
  hundred by two hundred. Take those three as the chunk's shape and the
  index of a value grows a third component that is not a coordinate, and
  the values land in the wrong cells; take the last one for what it is
  and they land in the right ones.
- **A GRIB2 message holds fields, and a bit map indexes the points of the
  grid.** The sections 4, 5, 6 and 7 repeat: a message is a sequence of
  fields, and each field has its own data representation section, its own
  bit map and its own data. A reader that keeps the last section 5 and the
  last section 7 decodes the *first* field's values with the *last* field's
  packing, and says nothing about it, because both are well formed. The
  NCEP GFS file has messages with two fields, and the two fields do not
  even have the same number of groups (723 against 730). The bit map is the
  same kind of trap: it indexes the points of the *grid*, so it has to be
  walked over the grid and not over the values -- a reader that walks it
  over the values reads the wrong word for every point after the first one
  that is missing.
- **The complex packing's template is 38 octets, and its fields are not
  where the column headings put them.** Data representation template 5.3
  runs from octet 12 to octet 49, and the reference for the group widths is
  one octet (36), the true length of the last group is four (43 to 46),
  and the number of bits the group reference values are stored in is the
  number of bits the packed values are stored in (20) -- the template has
  no octet of its own for them. Read at the wrong offset the number of
  groups comes out as 730 instead of 723 and the field decodes to nothing
  at all, which is what the reader did until the layout was taken from
  NOAA's g2c library and checked against the bytes that library writes.
- **A reduced grid keeps the shape of the grid in a list of numbers, and where
  that list starts is the length of the grid definition template.** The list
  follows the template and holds the number of points of each row -- or, for
  the third interpretation of code table 3.11, the latitude of each row -- and
  it begins where the template ends, so a reader that reads the list at a
  fixed offset reads the wrong numbers: the list of a 3.0 section starts at
  octet 73, because the template of that number is 58 octets long, while the
  templates of 3.1 and 3.2 are 70 octets and the one of 3.3 is 82, and the
  length of the template is what says where the list is.
  The lengths are NOAA's g2c library's, the library NCEP writes these files
  with: its `src/gridtemplates.c` holds the map of octets of every template
  it knows, and these are the sums of the maps of the latitude/longitude and
  of the Gaussian families, the two families a reduced grid belongs to. The
  number of columns of a reduced grid is not in the template at all: the
  field is missing, all ones, which is how the section says the grid is
  reduced, and the shape of the grid is in the list. What pins it is the
  pair of libraries that write and read these files -- NOAA's g2c and
  ECMWF's ecCodes -- which read the same list out of the same bytes.
- **A Zarr array of the v3 layout is named by a key encoding, and the
  codecs are a pipeline.** The metadata is in one `zarr.json` instead of a
  `.zarray` beside the chunks, the chunks live under `c/` and are named by
  their indices, and the pipeline runs from the array's bytes outwards: the
  `bytes` codec says the byte order the elements are in, and the codecs
  after it are the compressions -- so a decoder undoes them in the other
  order. The v2 layout's manifest is a dotfile and the v3 layout's is not,
  so the two are told apart by their content and not by their name, and
  every JSON file in the tree is handed to the adapter to be declined.
- **A Zarr group's metadata is a flat map of the group's files, and the v3
  transpose codec sits before the bytes codec.** The `.zmetadata` holds
  `<the array's path>/.zarray` for every array of the group, and the chunks
  of an array are in the array's own directory, not beside the `.zmetadata`:
  a reader that looks for them beside the file finds none, and the map has
  to name the groups above an array too, or `zarr-python` will not open it.
  The transpose codec permutes the axes of a chunk's elements and sits
  before the `bytes` codec, because it is an array-to-array codec: the
  pipeline is `[transpose, bytes, zstd]` and not `[bytes, transpose, zstd]`,
  and the stored axis `i` holds the chunk's axis `order[i]` — so a decoder
  that transposes the array instead of the stored layout gets the values
  right and the axes wrong.
- **A FoxPro memo file counts its blocks from the start of the file, and the
  header record is the first of them.** The file is a 512-byte header record
  and then fixed-size blocks, and a block sits at `number * block_size` bytes
  into it, so with the 64-byte blocks Visual FoxPro writes the first memo is
  block 8 and not block 1. A reader that puts the first memo at 512 bytes
  and counts the blocks from there is seven blocks out for every memo, so
  the text it prints is another memo's. The memo field is the other end of
  the same pair of files: four bytes, least significant byte first, while
  the memo file's own header -- the number of the next free block and the
  size of a block -- is most significant byte first, so the two ends are
  read in opposite byte orders. What pins it is the container's own rows: a
  row names the block its text is in, the block holds the name the row gives,
  and the memo file's header says the number of the next free block, which
  is one past the last block the table points at.
- **A blosc frame is a table of block offsets and then the blocks.** The
  header says the codec, whether the bytes are shuffled and the size of one
  element; the table that follows says where each block starts; the blocks
  come last. A decoder that reads the blocks one after another reads the
  table as a block, and the frame decodes to nothing. And the shuffle is the
  block's, not the frame's, and it is the bytes of the *same place* of each
  element that go next to each other — `dest[j * count + i] = src[i *
  typesize + j]` — so a shuffle that is the other way round round-trips into
  itself and still reads as garbage everywhere else. Both were wrong here
  until the frames were checked against c-blosc and `numcodecs`, the two
  implementations that write them.
- **A CRAM container's `length` is the size of its blocks, and a block is its
  header, its data and its CRC32.** The container header carries its own
  size, so the next container is `header size + length` bytes on -- a reader
  that steps `length` bytes from the container's start lands inside the
  header's own blocks, and every container after the first is then read from
  the wrong bytes. And a block occupies its header, its data and, from CRAM
  3 on, its CRC32 -- a reader that steps over the data alone lands inside
  the *next* block's header, and every block after the first is read wrong.
  The block count is not the region's length either: it is only a guide, and
  htsjdk writes a CRAM 3.1 file whose second container declares 28 blocks
  and carries 30, so the region a container covers is bounded by its
  `length`, and a block that will not parse ends the block list rather than
  the walk. What pins it is htsjdk's own file and htsjdk's own container
  reader: `crates/rgx-adapters-inspect/testdata/sample.cram` was written by
  htsjdk 5.0.2, and htsjdk's reader walks the same containers out of it --
  the second one declaring 28 blocks and carrying 30, and holding the eight
  records this reader totals.
- **The Ogg comment block is the same in every codec, and the packet that
  introduces it is not.** Vorbis comments in `\x03vorbis`, Opus in
  `OpusTags`, Theora in `\x81theora`, and the block that follows each one is
  the vendor string and the `key=value` list the Vorbis comment defines. A
  reader that looked for the Vorbis marker alone read a Vorbis stream and
  nothing else: an Opus file has no `\x03vorbis` anywhere in it, so the
  reader came back empty, the adapter declined, and the file fell through
  to the raw search -- where the NUL in the Ogg page header cut the search
  before the comment. The file was in the corpus, the tags were in the
  file, and the answer was not. The lesson is the one this repo keeps
  making: a **claim** that names a format and a **reader** that reads it
  are two things, and a reader that does not know the format's own header
  turns the claim into a promise the search does not keep. The same shape
  appeared in the ASF family, where the claim was missing instead: a
  `.wma` is a `.wmv` under another name, and ASF stores its strings as
  UTF-16, so the title of a `.wma` is not findable in the raw bytes by a
  search for its own text -- only the reader sees it.
- **`--tv-build` is boolean.** The tree comes from the first positional, not
  from a flag value.
- **`--engine grep` / `--engine both` are rejected by the CLI**, not warned
  about. Only `RGX_ENGINE` tolerates retired names, and it says so on stderr.
- **`--rgx-base` is a `status_table` option, not an `rgx` flag.** It lives in
  `crates/rgx-core/examples/status_table.rs` and is rejected as unknown by the
  binary.
- **There is no `scripts/bench.sh`** — an older revision named one.
  `scripts/bench-status.sh` is the gated entry point.
- Several directories under `tests/` (`.rgx-bench`, `.rgx-corpus`, …) and
  `tests/golden/` are gitignored generated corpora, not tests. Do not add
  fixtures there.
- `tests/fixtures/legacy-formats/` is the canonical corpus for the
  legacy-format integration tests (`tests/legacy_formats.rs` — DIF,
  Lotus 1-2-3, Jet/ACE, synthesised WAB). It is gitignored; populate
  it with `scripts/fetch-legacy-corpus.sh` (or `.ps1` on Windows),
  which clones `mdbtools/mdbtestdata` and pulls the sembiance.com
  Lotus/DIF samples into `tests/fixtures/legacy-formats/{mdbtestdata,
  lotus, dif}/`.
  **A missing fixture fails the test, it does not skip.** The suite used to
  `return` early, and libtest counts a bare `return` as `ok` — so a clean
  clone reported `7 passed` with nothing read, which is worse than no test
  because it looks like evidence. It now panics with the command that fixes
  it, the same shape `tests/cli.rs` uses for ripgrep
  (`.expect("ripgrep must be installed: tests/cli.rs is a parity suite")`).
  Verified: with `tests/fixtures/legacy-formats/` renamed away, 7 of the 8
  fail and only `wab_synthesized_minimal_cfb_is_parsed` — the one that
  synthesises its CFB in memory — still passes. `ci.yml` fetches the corpus
  before the test step in both jobs that run tests, so the gate is never
  vacuously green; a fetch failure is tolerated in the fetch step so a
  flaky third-party host does not take the matrix down, and the test step
  then fails naming the script to re-run.
- **A vector path is chosen by the *feature*, and the matrix has no machine
  without it.** The byte scanner has three tiers — AVX-512 (`avx512bw`), AVX2
  and the scalar loop — and the searcher and the JSON scanner add AVX2 of
  their own. Every tier is picked by a runtime probe — the crate's own
  (`crates/rgx-core/src/detect.rs`), which the standard library's macro
  agrees with on the machine the test runs on — so a compiler flag cannot
  take a tier away: `-C target-feature=-avx2` changes what the compiler
  emits, not what the CPU reports. The CI matrix
  (`ubuntu-24.04`, `windows-2022`, `macos-15`) has no x86_64 runner without
  AVX2, so the *fallback* is never taken there, and a test that asks for the
  vector path on the strength of the architecture alone passes on all three
  and fails on the first CPU that does not have the feature — which is what
  `djson/json_scan/tests.rs::the_predicate_on_a_small_document_is_what_it_looks_like`
  did, found on a FreeBSD guest whose CPU has SSE2 and nothing more. The fix
  is the one its two sibling tests in the same file already used: gate the
  assertion on `has_avx2_pclmulqdq()`, the *feature*, and not on
  `target_arch`.
  Which tier each machine actually takes is worth writing down, because one
  of the three is taken by none of them: the Windows workstation (a
  7950X3D) and the FreeBSD guest booted with `--cpu-type EPYC-Genoa` both
  report `avx512bw` and both take the AVX-512 tier; the same guest booted
  without it takes the QEMU baseline `qemu64` — SSE2 only — and takes the
  scalar one; and the tier *between* them, AVX2 without AVX-512, is taken by
  no machine in the lab. **The tier is a property of the CPU, not of the
  build**: the probe is the crate's own and is compiled into both
  configurations, so the `std` build and the `no_std` build take the same
  tier on the same machine, and the two configurations' numbers are
  comparable because they come from the same kernel (§1, §5).
- **The same instructions can be a third apart, and the difference is where
  the linker put them.** The paired-byte scanner's hot path is five
  instructions and a branch; whether they straddle a 64-byte window or sit
  inside one is decided by the address the linker gives the function, and
  the `std` and the `no_std` build differ by a few kilobytes of code and so
  differ in that address. The machine code was byte for byte the same in
  both builds -- the same instructions, the same registers, the same
  offsets -- and the scan measured **103 us in one build and 154 us in the
  other**, reproducibly, across runs and across a change of buffer
  alignment. A build that measures faster is not a build that is right, and
  the fix was not to write better code but to take the kernel whose number
  does not depend on the layout: the AVX-512 one measures 112 us in every
  configuration tried (five, over three feature sets), and it is what the
  forwards scan takes. Rust has no way to pin a function's address --
  `#[repr(align)]` is refused on functions -- so this cannot be settled
  from the source; it has to be settled by measurement, and the measurement
  has to be of the *build*, not of a copy of the kernel somewhere else.
- **A dev-dependency's features reach the library.** Cargo unifies features
  across the whole graph, dev-dependencies included, so a dev-dependency
  that turns on `std` turns it on for the crate under test. `regex` with
  its default features does exactly that: it pulls `memchr/std`, and
  `memchr`'s `std` feature is what lets the upstream crate use AVX2 at all.
  The `no_std` *test* build was therefore a `std` build wearing a `no_std`
  name, and every test it ran was a test of the other configuration. The
  fix is `default-features = false` on the dev-dependency, and the thing
  that notices it is the build for `x86_64-unknown-none`: a target with no
  `std` to link fails where a test never would (§1).
- **A SIMD loop with a call in it is a load-bound loop.** The confirmation
  of a candidate in a byte scanner wants `memcmp`, and `memcmp` is a call,
  and a call inside the loop clobbers every vector register -- so the
  broadcast vectors have to be spilled and reloaded on every block. The
  same kernel measured **167 us with the call in it and 103 us without
  it**. The confirm belongs on the candidate path, which is the rare one,
  and it belongs there as inline code over raw pointers: a bounds check
  costs the same, because the panic path behind it keeps the needle's
  pointer and length alive across the loop and the compiler answers the
  shortage by spilling them and reloading them on every block.
- **A loop that carries two induction variables pays for the second one.**
  The paired-byte scan walks the haystack with one induction variable -- the
  block's own address -- and computes the candidate's offset from it only
  when there is a candidate to confirm. The version that carried the
  block's start as an index *and* the haystack's base as a pointer needed
  one register too many, and the compiler answered the shortage by handing
  the `movemask` result the register the base pointer was in: the block
  copied the base out and back on every iteration. The same scan measured
  **154 us with the index loop and 103 us with the pointer one**, and the
  shape it follows is the upstream crate's own packed-pair kernel.
- **`git check-attr` prints `unset` for `-text`, and not `-text`.** A script
  that decides "is this file binary?" by comparing the attribute's value
  with the literal string `-text` never matches, so it takes every binary
  fixture for text and rewrites the line endings inside it. The corruption
  is silent and it surfaces a long way from its cause: the RAR fixture
  comes back with a member carrying CRLF where the expected bytes carry
  LF, the borg segment reports "an entry has a checksum that does not
  match its bytes", and an XXH32 over 69 998 bytes is 971 747 345 where
  the reference says 1 828 940 130 -- every one of them looking like a
  decoder bug and none of them one. The attribute has three values and
  they print as `set`, `unset` and `unspecified`, and `unset` *is*
  `-text`. The tree a Unix runner checks out is not a Windows tree with
  the line endings stripped: it is the index blob verbatim, and
  `git checkout-index -a -f` with `core.autocrlf=false` is what produces
  it. The proof that a tree is in that state is `git diff --name-only` --
  it must name the changes and nothing else -- and not `git status`, whose
  stat cache can be stale across a copy and says nothing about the bytes.

- **The hash belongs to the table, and not to the thread.** The intern table
  took its hash from a `thread_local!` hasher, so the same text hashed on
  another thread landed in another bucket: the lookup missed, the key was
  interned twice, and the deduplication broke *silently* -- a miss in a
  hash table is not an error, so nothing said so. The two configurations
  disagreed as well, because the `std` build's hasher was seeded per
  process and the `no_std` build's was not. The hasher is now a property
  of the table (`StringIndex::hash_of`): a `RandomState` per table in the
  `std` build -- SipHash-1-3, the operating system's seed, resistant to a
  document crafted to make its keys collide -- and a fixed-seed hash of
  this crate's own in the `no_std` build. The regression test interns the
  same text on two threads and asks for the same index.
- **A float past 2^63 is a whole number, and the two configurations have to
  say so.** `f64::fract` is `std`-only, so the integrality test had a
  `no_std` replacement that read the number as an `i64` -- and the cast
  saturates, so the "fraction" that came out of it was not zero. The
  `std` build said `1.5e19` was a whole number and the `no_std` build said
  it was not: the same input, two answers, and the answer that changed was
  the one that decides whether a JSON number is an integer. The test is one
  function now, with no `cfg` (`is_integral`), and it decides *before* the
  cast: past 2^63 every `f64` is a whole number anyway, because the
  spacing there is two or more.
- **The number past the top of the range is not the number below it.**
  `i64::MAX as f64` is 2^63 and `u64::MAX as f64` is 2^64 -- both round
  *up* -- so a bound written as `<= i64::MAX as f64` admits a number that
  does not fit in an `i64` at all, and the cast then saturates and
  reports `i64::MAX` for it. The crate answered `i64::MAX` for 2^63 and
  `u64::MAX` for 2^64: two numbers the file never held. The bounds are
  exclusive now (`I64_LIMIT`, `U64_LIMIT`), and the answers are written
  down in a table rather than compared against the standard library,
  because Rust has no `f64::as_i64` and no `f64::as_u64` -- the `as` cast
  saturates and says nothing about what it could not represent, so there
  is no oracle to compare against.
- **Every adapter crate turns `std` back on for `rgx-core`.** The ten
  `rgx-adapters-*` crates depend on `rgx-core` with `default-features =
  false, features = ["std", "sha256-hw"]`, and Cargo unifies features
  across the graph, so an embedder that pulls in one adapter gets
  `rgx-core/std` back whatever it asked for. The `no_std` configuration is
  therefore a configuration of the *engine*, not of the tree: the
  guarantee is that the engine embeds without `std`, and the adapters are
  the part that wants the heap, the filesystem and the process API. A
  tree-wide `no_std` -- the adapters included -- is a different piece of
  work, and not this one.
- **`policy()`, `current_depth()` and the typed error chain are the `std`
  half of the API.** Three places where the two configurations are allowed
  to differ, and each of them is a decision rather than an accident:
  `policy()` reads `RGX_ADAPTER_VIEW` only with `std` (without it the
  policy is always `Source`, the conservative end -- the one that cannot
  lose a line `rg` prints); `current_depth()` is 0 without `std`, so the
  `max_depth` ceiling is not enforced there; and the typed error chain
  (`Trait::new` over `StdError`, the blanket `From`, `Context`, `as_std`)
  exists only with `std`, so a `no_std` build keeps the message chain and
  nothing else. A test that asserted the typed chain in the `no_std`
  configuration would be asserting an API that configuration does not
  have.
- **rustfmt writes LF when it rewrites a file, and the check does not
  notice.** The worktree is a CRLF tree (`core.autocrlf=true`), and
  `cargo fmt --all` turned the two files it had something to say about
  into LF. `cargo fmt --all -- --check` stayed green on the CRLF files
  and on the LF ones alike -- the check compares the text, and the line
  ending is not part of it -- and `git diff` did not see it either, because
  `core.autocrlf` normalises the worktree before the comparison. The
  consequence is a file that is the only one in the tree whose lines end
  in LF, and no gate that can tell. The files rustfmt rewrote are
  converted back to CRLF after the format run, and the proof that the tree
  is in that state is the byte count -- `CRLF=n, bare-LF=0` (§5).
- **The delivery script writes LF, and the commit says there is nothing to
  commit.** `scripts/push-github.sh` rewrites the winget manifests, the brew
  formula and the installer pins with the `sed` and the `awk` of MSYS2, and
  those take the carriage return off a CRLF line before the program sees it
  and write LF back. The repository does not notice: `core.autocrlf` puts
  the LF back in the index, the commit has nothing to commit, and `git diff`
  is empty. The worktree does, and the proof is the byte count and not the
  status (§5) -- and the status is the one that lies, because its stat
  cache still holds the size of the file from before the rewrite, so the
  four files show as modified until `git add --` settles them.
  `git update-index --refresh` does not settle them.
- **A number a kernel does not know is an instruction it does know.** The
  `madvise(2)` advice that only Linux has -- `MADV_REMOVE` and the fork,
  the merge and the huge page pair -- are seven numbers Linux owns, and
  the enum in `crates/rgx-core/src/memmap2/advice.rs` keeps one shape on
  every platform so that a caller needs no `cfg` of its own. The numbers
  are therefore on a BSD too, where they mean something else: FreeBSD's
  `MADV_PROTECT` is 10 and Linux's `MADV_DONTFORK` is 10, so handing 10
  over changes the protection of the mapping instead of refusing the
  advice. `advise` turns the seven down before the syscall, and the
  refusal is one rule for the three unix platforms --
  `platform::refuse_unavailable`, over `advice::is_available` -- while
  Linux refuses nothing, because Linux has them. Upstream `memmap2` never
  has the problem: its variants are behind `#[cfg(target_os = "linux")]`,
  so there is no number to hand over. The pin that matters is that the
  seven are Linux's *numbers* and not a range: a range wide enough to hold
  them would also hold a number a BSD kernel has an instruction for.

- **The star chart counts from the day the repository existed, so the
  repository is not to be made again.** `danalec/rgx` on GitHub was created
  on the twenty-eighth of October 2026 at 03:33:27 UTC, and the chart the
  README carries -- `api.star-history.com`, which plots the stargazers of
  a repository against the moment it was created -- takes that creation
  moment as the point the count starts from. A repository that is deleted
  and made again is a new object with a new creation moment: the stars it
  has would be plotted from a later date and the count would begin again
  from zero. So the counters are reset by the recreation and by nothing
  that is done to the commits. The delivery does not do that.
  `scripts/push-github.sh --flat` rewrites `main` with a single commit and
  force-pushes it, which changes the history and leaves the repository
  alone: the mirror was pushed several times on the twenty-eighth, and
  `created_at` stayed at 03:33:27 through every one of them. The mirror may
  therefore be re-pushed as often as the tree asks for it; the repository
  is not to be deleted, recreated or renamed, because a renamed repository
  is a new object too, and a new object counts from zero.

- **The gate answers to the owner and to the collaborators, and to nobody
  else.** The repository on GitHub is public, so the pull requests come from
  strangers, and the gate is four jobs over three operating systems: a
  stranger's pull request would spend the owner's minutes on code the owner
  never asked for. So the four jobs of `.github/workflows/ci.yml` carry a
  condition on `author_association` -- OWNER, MEMBER and COLLABORATOR are
  the ones with a key to the tree -- and the settings of the repository hold
  a pull request from outside for approval
  (`all_external_contributors`), so the gate does not even begin without the
  owner. The two rulesets are the other half of the door: `main` cannot be
  deleted and cannot be force-pushed over, and a tag cannot be created,
  moved or deleted, so a stranger cannot invent a release tag; and the
  owner is in the bypass list of both, because the delivery writes the
  mirror with a force-push and moves the tag with it. The release and the
  fuzz workflows carry no condition and need none: a tag push and a manual
  dispatch are both write access.


---

## 13. Branch, tag and stash policy

- **`main` is the only active branch.** The forgejo remote tracks a single
  `refs/heads/main`; PRs and feature work land as fast-forward commits on it.
- **Historical work is reachable, not active.** Retired work lives under
  `archive/*` tags: `archive/post-sota-final`,
  `archive/baseline-grep-deps-final` (the `rgx-mod` reference build, 163
  commits behind) and `archive/walk-perf`. (`archive/baseline-grep-deps` also
  exists as a local branch.)
- **`dev` is retired, not lost.** It lived in its own worktree (`../rgx-dev`)
  and held the SHA-NI kernel, the unicode case-folding work and smaller
  fixes; **all of it is on `main`** (2026-10-15, after both "blocked on
  nightly" premises turned out false — the fold is parse-time, the SHA-NI
  intrinsics are stable since 1.41). The branch and worktree are deleted
  and the exact state lives in the `archive/dev-final` tag, which the
  history-of-record keeps reachable the way the other `archive/*` tags do.
- **Stashes get dropped at end of session** when their parent branch no longer
  exists. The tag is the recoverable form; the stash is not.
- **A block is one commit, and the machinery of it is versioned.** When
  several blocks touch the same document -- the root `README.md`, the
  `FORMATS.md` of the formats, the tabular crate's `README.md` and its
  `testdata/README.md`, the inspect crate's `testdata/README.md`, the Zarr
  fixtures' `README.md` and the Zarr fixture script -- each block carries
  its own text, and the text of the blocks that come later is not yet in
  the tree. The scripts below cut the
  diff of a shared document into the hunks of each block, gate the tree the
  commit carries and make the commit with the count of that tree:

  | script | what it does |
  |---|---|
  | `scripts/split-shared-docs.py` | the diff of one shared document, cut into the hunks of each block; the cut is by position, and the patches it writes are applied with `git apply --cached --unidiff-zero` |
  | `scripts/gate-and-count.sh`, `scripts/gate-and-count.ps1` | `fmt`, `clippy` and `test` over the workspace, and the line `COUNT: passed=… failed=… ignored=… suites=…` |
  | `scripts/commit-block.sh`, `scripts/commit-block.ps1` | the commit of one block: the files and the hunks are staged, the other blocks are stashed, the gate runs on that tree, the count goes into the notes and into the workflow, and the commit is made |
  | `scripts/stamp-count.sh`, `scripts/stamp-count.ps1` | the count of the tests, and the note that says what it was taken after, written into the notes and into the workflow |
  | `scripts/suite-counts.py` | the counts per suite of a gate's log, which is what the list in §6 has to agree with |

  The count is stamped, and the note that says what it was taken after is
  stamped with it. The history of the counts is a list of clauses in §6, and
  each clause says what a re-snapshot was after; the newest clause is the
  one the stamp rewrites, and the older ones are the history and stay. The
  header of a clause runs from its `(` to the first `:` after the date, and
  the note is written into that header — which is why a note cannot hold a
  colon: it would end the header in the wrong place, and the stamp refuses
  it rather than write a history that cannot be read back.

  The body of the newest clause is written by hand, and the stamp does not
  write it: the stamp rewrites the header and leaves the body, so a body
  that still names the previous snapshot's tests is a clause about the
  wrong count. The body says what the new count came with -- the tests it
  added -- and then the chain back: `The count before that, 2,604, was
  after <the note of the clause before> landed:`, and the body of that
  clause follows it, so the whole history reads as one sentence from the
  newest snapshot to the oldest. The body is written before the stamp
  runs, because the stamp finds the clause by the `(` of its header and
  writes the header the body hangs on.

  The two twins write the same bytes, and that is a contract and not a
  wish: a note that lands in a different place on each of them is a note
  that is wrong in one of them. So the stamp counts the bytes it finds and
  splices the new ones in, and it does not rewrite the file around them —
  a `sed -i` reads the file in text mode on Windows and takes the carriage
  returns of a Windows checkout with it, and the notes of the project are a
  Windows checkout. `tests/count_note.rs` runs the two twins over the same
  files and asks for the same bytes, over the notes of the repository and
  not only over a fixture.

  The Linux scripts are the ones the CI's Linux runs and the ones the box
  runs; the PowerShell ones are the same steps on Windows. The plan of
  which files and which hunks belong to which block is not versioned: it
  belongs to the series it is for.

---

## 14. Findings

Kept out of the code so the contracts above stay short. Each carries its own
measurements, the ruled-out explanations, and the traps.

### 14.1 Where the specifications live

A reader that refuses a format "because the layout is not established here"
is a claim about a document, and the document can be looked up. The map --
the specification of each format, linked, and the implementation that checks
the reading against it, with the verdict each one earned -- is in
[`FORMATS.md`](FORMATS.md#where-the-formats-are-specified), where a reader
can follow the links.

What is here instead is where the corpus comes from: `target/fmt/` holds
NOAA's g2c, ECMWF's ecCodes, htsjdk, htslib, `hts-specs` (with
`CRAMv2.1.pdf` and `CRAMcodecs.pdf`), c-blosc, `cdflib`, the HDF5 sources,
and `target/py/` with zarr-python 3.4.1 and numcodecs.

Two things the research found in **this** codebase, and they are worth
remembering because the format was not where the bug was:

- `crates/rgx-core/src/compress/blosc.rs` mapped the blosc frame's
  **format** codes to c-blosc's **library** codes for 2–5, so a zstd frame
  was called "zlib" and a zlib frame "snappy", and the code `5` does not
  exist in the format at all. The table is in the report's §3.2 and the
  measured frames are in §3.3.
- GRIB 1's spectral packing is **not** the "second-order packing": the
  second-order packing is the grid-point one, by differences within groups,
  and the spectral one is "spherical harmonics-complex packing" (Code
  Table 10, mode 2) — the same bit of the same flag, a completely
  different structure. The subset of the unpacked values is **IBM** float in
  edition 1 and **IEEE** in edition 2, which is the trap that a port falls
  into.

The long reports (the octet tables, the numbers each fixture asserts, the
divergences between a specification and the implementations) are in
`target/fmt/spec-research.md` and `target/fmt/specs/`, which the scratch
area holds and the repository does not version.
| File | What |
|---|---|
| [`benchmark/findings.md`](benchmark/findings.md) | Walk cost attribution, `--sort path`, `--files` path-as-regex, the prefilter pair, line-walk bookkeeping — each with its measurements and the traps |
| [`benchmark/status.md`](benchmark/status.md) | The published tables, the gate results, and two scrapped tables and why |
| [`benchmark/archive-extract-cache.md`](benchmark/archive-extract-cache.md) | First-run vs cached-run on the `archive-extract` row: the cache is 8x on repeat but 2x to fill, break-even at the third query |
