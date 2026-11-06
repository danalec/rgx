# rgx — manual

*Search inside everything.* A ripgrep-compatible search engine with
in-process adapters for PDF, Office documents, archives, 3D models, ML model
files, databases and e-mail, plus a pack store that moves the per-file cost
of a query off the query path once it has been paid at build time.

This file is the task-oriented manual: how to drive rgx.
[`README.md`](README.md) is the entry point — what rgx is and the published
measurements. [`FORMATS.md`](FORMATS.md) says what it reads, format by
format, and what it refuses.

**The flag list is in §12, and the grammar is canonical.** The `app()`
function in `src/main.rs` is the authoritative list, one `Arg::new(...)` line
per flag. rg parity is a feature: a flag is not renamed to something rg
would not recognise. Where this manual and the grammar disagree, the
grammar is right and this manual is wrong.

## Contents

- [1. What it is](#1-what-it-is)
- [2. Build and install](#2-build-and-install)
- [3. Quick start](#3-quick-start)
- [4. Choosing an engine](#4-choosing-an-engine)
- [5. The pack store](#5-the-pack-store)
- [6. Adapters and the extraction cache](#6-adapters-and-the-extraction-cache)
- [7. Configuration](#7-configuration)
- [8. Environment variables](#8-environment-variables)
- [9. Output modes](#9-output-modes)
- [10. The token index](#10-the-token-index)
- [11. Benchmarks](#11-benchmarks)
- [12. Flag reference](#12-flag-reference)
- [13. Troubleshooting](#13-troubleshooting)
- [14. References](#14-references)
- [15. See also](#15-see-also)

---

## 1. What it is

`rgx` answers a regular expression over a corpus. Three things make it more
than a ripgrep clone:

1. **In-process adapters.** A `.pdf`, a `.docx`, a `.zip`, a `.stl`, a
   `.safetensors` are searched as text, without shelling out and without an
   intermediate file. The external tools (`soffice` or `libreoffice`,
   `tesseract`, and a rasteriser -- `pdftoppm` or `pdftocairo` -- for the
   pages of a PDF) are used when they are on `PATH`; when they are not, the
   adapter declines, and a file no adapter claims is searched as its own
   bytes rather than skipped.
2. **The pack store.** Build once, and the per-file walk, `stat` and `open`
   cost moves off the query path and onto the build. Queries read contiguous
   packs instead of walking the tree.
3. **rg parity.** Flags, output shapes and exit codes match ripgrep. A
   script written for `rg` runs against `rgx`.
4. **An engine that does not need the standard library.** `rgx-core` is
   `#![no_std]` + `alloc`. The `std` feature turns on the typed error
   chain, the profiler map and the `f64` JSON parser, and nothing else
   that matters, so a router or a NAS can link the engine and reach the
   same AVX2 kernels the full build uses.

What it reads is listed family by family in
[`FORMATS.md`](FORMATS.md); the adapters that answer are in §6.

---

## 2. Build and install

```sh
cargo build --release          # the `rgx` binary at target/release/rgx
cargo test --workspace         # the suite; CI runs it on three OSes
```

Built and tested with Rust 1.98.1 and the 2021 edition. No manifest
declares a `rust-version`, so nothing turns an older toolchain away at
the door — the gate is what says a toolchain works. Nothing else is
mandatory: the optional external adapters light up when their tools are
present.

On Windows, `install.ps1` copies the binary onto `PATH`.

---

## 3. Quick start

```sh
rgx 'fn main'                      # search here, like rg
rgx -c 'fn main' src/              # counts per file
rgx --files -g '*.rs'              # what would be searched
rgx 'pattern' --json               # machine-readable stream
rgx 'invoice' --filter 'mime:pdf'  # only the PDFs
```

`rgx` takes the same paths `rg` takes: none means the current directory,
and `-` means standard input.

---

## 4. Choosing an engine

`--engine` picks the search path. The default, `auto`, decides per run and
can explain itself.

| Engine | What it is | Use it when |
|---|---|---|
| `auto` (default) | the adaptive detector picks one | you do not want to choose. Add `--explain-engine` to see the decision and its reasoning on stderr |
| `tv` (or `--tv`) | the prepared-pack storage tier | the corpus is large, many-small-files, and queried many times per mutation. This is the storage tier the paper is about |
| `rgx` | the in-process SIMD engine over the tree | you want the engine without any store, or you are measuring it |

The decision `auto` makes is a *detector*, not a law: it reads the corpus
shape and the request and picks. `--explain-engine` prints the choice and
why, which is the first thing to look at when a run is slower than expected.

`grep` and `both` are not accepted values. They named the removed
`grep-searcher` backend; `RGX_ENGINE=grep` prints one stderr line saying so
and runs anyway.

---

## 5. The pack store

The architecture is named **diodic** in the paper: work is asymmetric in one
direction, scoped to one generation of the corpus. This section is its
**storage tier**, which is what the `tv` flags select — `tv` is the code's
name for the tier, not the design's name for it.

The write-up is the preprint [rgx-paper](https://github.com/danalec/rgx-paper),
DOI [10.5281/zenodo.23453407](https://doi.org/10.5281/zenodo.23453407).

Tesla's 1920 valvular conduit is the picture that principle is illustrated
with, and the paper is explicit that the valve is not a model — it predicts
nothing about latency, and where the picture and the code disagree, the code
is the claim.

The store is a directory holding `manifest.tvm` and a number of `.tvp` pack
files. It is build-time cost traded for query-time cost.

**Build.** The corpus is the first positional, the store is `--tv-store`:

```sh
rgx --tv-build --tv-store ./store ./corpus
```

This walks the corpus once, packs file contents contiguously, and writes the
manifest. A rebuild is incremental: changed and added files are re-packed,
deleted ones are dropped.

**Query.**

```sh
rgx -c 'pattern' --engine tv --tv-store ./store
```

With no path argument the store is the corpus and result paths are relative
to it. Pass a path and it is used as the prefix of the reported paths.

**Pre-extract adapter text.** Adapters are expensive on the query path.
`--tv-pre-extract` moves that cost to the build:

```sh
rgx --tv-build --tv-pre-extract --tv-store ./store ./corpus
```

Queries over a pre-extracted store are sub-millisecond because no adapter
runs at query time at all.

**Check which engine is faster for a pattern.**

```sh
rgx --tv-verify 'fn main' --tv-store ./store
```

A/Bs the in-house engine over the store, reports which won, and exits. This
is the cheap way to answer "does this pattern want the store?" for one case.

**What the store is not.** It is not a cache of *answers*: it holds file
content, so a query always re-scans the packed bytes. It does not weaken the
match — the paper's equivalence theorem is that the store answers exactly
what a direct search answers. The benefit is cost, not semantics.

**The tier's flags.** `--tv` selects it: same binary, same `rg` flags, same
exit codes, and the flag only changes where the bytes come from.

| Flag | What it does |
|---|---|
| `--tv` | answer the query from a prepared pack store (shorthand for `--engine tv`) |
| `--tv-build` | build or refresh that store for the tree named by the first positional, then exit |
| `--tv-store DIR` | where the store lives (`.tvp` packs plus `manifest.tvm`) |
| `--tv-pre-extract` | at build time, pull adapter text into the packs once |
| `--tv-assume-fresh` | skip the staleness gate; answer from the store even if it is out of date |
| `--explain-engine` | print why the detector chose the route it chose |

So for the same search, over and over, on a fixed tree:

```sh
rgx --tv-build src/ --tv-store .rgx-tv   # one-time
rgx --tv "fn main" --tv-store .rgx-tv    # every query after it
```

The store holds the corpus verbatim and answers each file from its own
slice, running the *same* adapter registry as the direct path — so a hit
inside a `.gz` member or a `.docx` paragraph comes back identically either
way. `--engine auto` (the default) picks the route and **declines the store
when files changed under it**, rather than answer from stale bytes;
`--explain-engine` names how many are stale.

---

## 6. Adapters and the extraction cache

An adapter extracts searchable text from a format. Registration order
matters — the first adapter that claims a file wins.

| Family | Formats (indicative) |
|---|---|
| PDF | `.pdf` |
| Office | `.docx`, `.xlsx`, `.pptx`, `.odt`, … |
| Archives | `.zip`, `.tar`, `.gz`, `.7z`, `.rar`, … |
| 3D | `.stl`, `.obj`, `.3mf`, … |
| Media | image/audio containers |
| ML models | `.safetensors`, `.gguf`, … |
| Mail | `.mbox`, `.eml` |
| Databases | sqlite and friends |
| Docs | markdown, HTML, source trees |
| Tabular | CSV, TSV, parquet |
| Inspect | container forensics |

Two adapters shell out to tools on `PATH` (`soffice` or `libreoffice`, and
`tesseract`), and the OCR adapter reaches for a third (`pdftoppm` or
`pdftocairo`) when a PDF's pages are drawn and have to be rasterised. If the
tool is absent the adapter declines, and the file falls back to the **raw
bytes** it has on disk: rgx searches what is there rather than skipping the
file. `--max-adapter-depth` (default 4) bounds archive nesting.

Which adapter claims a file is controlled by `RGX_CLAIM_EXT`, not by
`--type-add`: `--type-add` filters the walk, and the two are independent.

**Dotted extensions.** An adapter may declare more than one component, and
the more specific claim wins. `scan.ocr.jpg` is offered to an adapter that
declared `ocr.jpg` before one that declared `jpg`, and if the first declines
with `Outcome::Bail` the second still runs. This is how the `docs` crate
reads text out of a scanned image without every photograph in the tree
paying for OCR:

```sh
rgx 'invoice total' .          # scan.ocr.jpg is OCR'd
rgx 'camera' .                 # plain .jpg is only read for EXIF
```

Note that `-t`/`--type-add` is the walk filter and knows nothing about
adapter claims; `ocr.jpg` is not a type name and does not appear in
`--type-list`.

### The cache

Adapter output is expensive to compute and stable for a given file, so
`--cache` memoises it:

```sh
rgx 'pattern' --cache             # uses $RGX_CACHE_DIR or ~/.rgx/cache
rgx 'pattern' --cache=./mycache   # an explicit directory
rgx --cache-prune --cache-max-age 30    # drop entries older than 30 days
rgx --cache-clear                       # drop everything
```

The cache is **off by default** — a wrong default serves stale bytes. For a
corpus queried repeatedly it is the single biggest lever after the pack
store: on an archive-heavy row it was 8× on a repeat run against 2× to fill,
breaking even at the third query.

`--cache DIR` memoises what the adapters made of a file, so a second search
over the same corpus does not extract it again. It has two layers, and the
reason for two is that they answer different questions:

- an **alias**, keyed by the path, the size and the mtime, points at the
  extraction. It is derived from what the walk already stat'd, so a run that
  hits it does not read the file at all — not even a byte of it.
- a **content entry**, keyed by the SHA-256 of the file's bytes, holds the
  extraction itself, with the unit paths stored relative to the file so one
  entry can serve every file with those bytes.

What that buys, in the order a user meets it:

- **A copy of a file is extracted once.** Two files with the same bytes and
  the same name share one extraction, wherever they live. The walk is
  parallel, so the second copy can arrive while the first is still being
  extracted; it waits for it and finds what it stored.
- **A file that moved is not extracted again.** The alias is keyed by the
  path, so a move misses it — but the bytes are the same, and the content
  entry is not.
- **A touched file is re-read, not re-extracted.** The mtime moved, so the
  alias misses; the bytes did not, so the content entry hits. What changes
  is the work: a hash instead of an extraction.

The name is part of the content key, and the policy is too. The extension
picks the parser (`scan.ocr.jpg` is not `scan.jpg`), and a report that
names the file names the file; and under `RGX_ADAPTER_VIEW=source` the
adapter is not consulted at all, so one file under two policies is two
extractions.

**What it does not survive:** an edit that preserves the size *and* the
mtime — the same hole `make`, `ccache` and `cargo` have, and the same
answer (leave the flag off).

`--cache-clear` empties it and `--cache-prune` drops what has aged out.

---

## 7. Configuration

`.rgxrc` is read **before** argv is parsed, and each non-empty non-comment
line is *prepended* to argv. So CLI flags win over the file.

Search order: `$RGX_CONFIG_PATH` → `./.rgxrc` → `~/.rgxrc` →
`~/.config/rgx/rgxrc`. A missing file is fine; an unreadable one warns.
Lines split on whitespace with shell-style quoting.

If rgx seems to ignore a flag, check for a `.rgxrc` first.

---

## 8. Environment variables

| Variable | Effect |
|---|---|
| `RGX_ENGINE` | `rgx` — ask for the in-house engine by name (prints the `RGX_RUNS` tally). A retired name (`grep`, `both`, `tv`, `tesla`) prints one stderr line saying the engine no longer exists and the run continues; anything else is ignored |
| `RGX_CONFIG_PATH` | override the `.rgxrc` search (§7) |
| `RGX_CLAIM_EXT` | `adapter:ext[,adapter:ext…]` extra registry claims, e.g. `inspect:o`. An environment variable rather than a flag because it is per-invocation policy about what to *read* |
| `RGX_ADAPTER_VIEW` | `source` (default) · `render`/`rendered`/`adapter` · `both`/`union` |
| `RGX_MAX_MEMBERS` | per-archive member count (default 4096) |
| `RGX_MAX_MEMBER_BYTES` | per-archive expanded byte total; accepts `k`/`m`/`g` |
| `RGX_MMAP` | the mmap read path for big files: `1` forces it on, `0` forces it off; unset is the platform default (mapped on Linux, read elsewhere) |
| `RGX_CACHE_DIR` | the default `--cache` directory |
| `RGX_PROFILE` | per-adapter timing counters on stderr |

The rest of the variables in the project's notes (`RGX_ABLATE_*`,
`RGX_*_STATS`, the benchmark harness's own) are instrumentation and harness
plumbing, not part of the interface.

---

## 9. Output modes

| Mode | Flag | Notes |
|---|---|---|
| Normal | — | ripgrep's default shape |
| Counts | `-c` | per-file counts |
| File list | `-l`, `--files-without-match`, `--files` | with `-0` for NUL-terminated |
| JSON | `--json` | `rg --json` compatible stream |
| Serve | `--serve` | a query daemon — see below |
| Picker | `--pick` | pipes to fzf and prints the selection |
| Editor | `--vimgrep`, `--column` | `{path}:{line}:{col}:{text}` |
| Context | `-A`/`-B`/`-C`, `--chunk` | `--chunk` gives an LLM-sized window |

**`--serve`** reads one JSON argv-array per line on stdin and answers on
stdout, framed by `{"rgx":"ready",...}` and `{"rgx":"end",...}` sentinels
with a per-process `tag` and a `seq`. The registry and page cache survive
between queries, which is what makes it fast. The reader is rgx's own
`rgx_core::djson`, not `serde_json`.

**`--pick`** exits 0 on a pick, 1 on nothing or dismissal, 2 when no fzf is
found. `--fzf-binary` and `--fzf-arg` tune it.

---

## 10. The token index

An inverted `token → Vec<(file_id, line)>` map, written as `.rgx-idx.ugi`
with magic `RGXIDX\0`. **The on-disk format is rgx's own** — the flag names
are ugrep-compatible, the file is not, and nothing else loads it.

```sh
rgx --index-build ./corpus                  # writes .rgx-idx.ugi
rgx 'pattern' --index ./corpus              # answer through the index
rgx --index-build ./corpus --index-store ./idx   # somewhere else
```

A token hit is a *candidate*. The engine still confirms on the re-scanned
slice, so the index cannot introduce a false positive.

---

## 11. Benchmarks

`benchmark/` holds the published measurement record; `scripts/` the harness
that produced it.

| Script | What it measures |
|---|---|
| `bench-status.sh` | regenerates `benchmark/status.md` from one command |
| `compare-rg.sh` | parity against ripgrep over 19 flag/mode cases |
| `detect-ccd.sh` | CPU topology, so a thread sweep stays inside one CCD |
| `bench-linkers.sh` | system linker vs lld, with a count gate |
| `tv-cold.sh` | cold against warm page-cache latency, with a MAD pass and the cache-immunity ratio |
| `tv-vs-rg.sh` | the A/B/C protocol: rg, rgx, rgx-tv over one corpus |
| `tv-matrix.sh` | the four orthogonal CLI axes on wall clock |
| `tv-threads.sh` | the thread-count sweep |
| `tv-ablate.sh` | what each tier contributes |
| `tv-usecase.sh` | a use case written to be able to fail |
| `diodicity.sh` | the diodicity check, with the pack store as the negative control |
| `engine-sweep.sh` | `auto` against `rgx` across a pattern grid |

Findings and traps are written up in
[`benchmark/findings.md`](benchmark/findings.md); the published tables are
[`benchmark/status.md`](benchmark/status.md).

Measurement discipline the harness enforces: paired rounds, the minimum
reported (not the mean), a ±3% floor below which nothing is called, and an
exact count gate — a faster time on a smaller result refutes nothing, so a
run whose counts disagree is a **failure**, not a result.

---

## 12. Flag reference

Every flag, what it does, and where it differs from ripgrep.

### Pattern matching

| Flag | Effect | rg parity |
|---|---|---|
| `-i`, `--ignore-case` | case-insensitive match | same |
| `-S`, `--smart-case` | case-insensitive only when the pattern is all lowercase | same |
| `-F`, `--fixed-strings` | treat the pattern as a literal string, not a regex | same |
| `-w`, `--word-regexp` | match only at word boundaries | same |
| `-v`, `--invert-match` | select non-matching lines | same |
| `-U`, `--multiline` | let matches span lines; a match is reported on the line it *ends* on | same |
| `--multiline-dotall` | like `--multiline`, and `.` also matches a newline | same |

### Execution

| Flag | Effect |
|---|---|
| `-j`, `--threads <N\|auto>` | worker count; `auto` uses every available CPU (the default) |

### What to print

| Flag | Effect | rg parity |
|---|---|---|
| `-c`, `--count` | print only the count of matching lines per file | same |
| `-l`, `--files-with-matches` | print only file names with matches | same |
| `--files-without-match` | print only file names **without** matches | no short flag, as in rg 15 |
| `--files` | list the files that would be searched; do not search | same |
| `-o`, `--only-matching` | print only the matched parts of each line | same |
| `-r`, `--replace <TEXT>` | replace each match with TEXT; `$1` and `${name}` work | same |
| `-m`, `--max-count <N>` | stop after N matching lines per file | same |
| `-q`, `--quiet` | exit 0 on the first match, print nothing | same |
| `--json` | machine-readable JSON stream, `rg --json` compatible | same |
| `--serve` | query daemon: one JSON argv-array per line on stdin, answered on stdout | rgx only |
| `-0`, `--null` | NUL-terminate the file list instead of `\n` (for `xargs -0`) | same |

### Context

| Flag | Effect | rg parity |
|---|---|---|
| `-A`, `--after-context <N>` | show N lines after each match | same |
| `-B`, `--before-context <N>` | show N lines before each match | same |
| `-C`, `--context <N>` | show N lines around each match (`-A N -B N`) | same |
| `--chunk[=BYTES]` | emit a paragraph-aware context window as `path:line` plus chunk text, sized for LLM context windows | rgx only |

`--chunk` bare means 2048 bytes.

### Which files to search

| Flag | Effect | rg parity |
|---|---|---|
| `-g`, `--glob <PAT>` | include/exclude by glob, repeatable; a leading `!` excludes | same, but **no `--iglob`** |
| `-t`, `--type <TYPE>` | only search files of TYPE, repeatable | same rule, rgx's own type names |
| `-T`, `--type-not <TYPE>` | exclude files of TYPE, repeatable | same rule, rgx's own type names |
| `--type-add <T:ext,ext>` | add a type to the table, repeatable (`--type-add 'web:html,css'`) | same |
| `--type-clear` | empty the type table before `--type-add` is applied | same |
| `--type-list` | print the registered type table and exit | same |
| `--hidden` | search hidden files | **rgx reads them by default**, so this is accepted and does nothing |
| `--no-hidden` | skip hidden files | rgx only — the flag that puts rg's default back |
| `--no-ignore` | do not respect ignore files | same |
| `-L`, `--follow` | follow symbolic links | same |
| `-a`, `--text` | search binary files as if they were text | same |
| `--max-depth <N>` | maximum directory depth | same |
| `--filter <EXPR>` | keep only the files whose facts satisfy EXPR — see below | rgx only |
| `-M`, `--max-filesize <SZ>` | skip files larger than SZ (e.g. `100M`); default 1G | same, and like rg it is **not** applied to a path named on the command line |

#### File types

A **type** is a set of patterns: the extensions and the bare filenames that
belong to it. A file matches **every** type it satisfies, so `lib.min.js` is
a `.js` file and a `minified` one at the same time.

The flags are read in the order they were written, and **the last one that
matches a file decides**:

| Flags | `lib.min.js` |
|---|---|
| `-t javascript` | kept |
| `-T minified` | dropped |
| `-t javascript -T minified` | dropped — the exclusion is the last word |
| `-T minified -t javascript` | kept — the inclusion is the last word |

With at least one `-t`, a file that matches no type at all is dropped; with
only `-T`, it is kept.

A name the table does not have is refused. `rgx -t nosuchtype` prints
`rgx: unrecognized file type: nosuchtype` and exits 2, the way rg does: a
filter that matches nothing is indistinguishable from a search that found
nothing, and the second is the wrong answer to give.

The table is rgx's own and `rgx --type-list` prints it. The names ripgrep
uses for a type that is here are accepted as aliases — `-t js` is
`-t javascript`, `-t py` is `-t python`, `-t md` is `-t markdown` — so a
flag written out of rg's habit works without a second thought.

`--type-add 'web:html,css,js'` adds a type to the table, `--type-clear`
empties it before the additions are applied, and `--type-list` prints the
names and exits.

The type filter is the **walk** filter. It does not decide which adapter
claims a file — that is `RGX_CLAIM_EXT`, see §6.

#### `--filter <EXPR>`

Keep only the files whose facts satisfy the expression. The grammar, the
rule that the path ends at the **last colon outside quotes**, and the rule
that a predicate compares a fact's name or its namespace are in the
[README](README.md#searching-by-what-a-file-is); the facts each format
gives are in [FORMATS.md](FORMATS.md#the-facts-each-format-gives).

The facts are `path`, `ext`, `format`, `mime` and `lang` (from the name),
plus what the adapters report: a PDF's `author`/`title`/`producer`…, a
message's `mail.from`/`mail.to`/`mail.subject`/`mail.date` and
`has.attachments`, a photo's `exif.make`/`exif.model`/`exif.camera`/`exif.gps`,
a model's `tensor.name`/`tensor.shape`/`tensor.dtype`, a table's
`table.column`, and `container`/`archive.entry` for what a member is inside.
The full catalogue is in
[`FORMATS.md`](FORMATS.md#the-facts-each-format-gives); the idea behind the
filter is in the [README](README.md#searching-by-what-a-file-is).

A file the filter rejects is not in the corpus at all: no unit and no note
about it. The facts are assembled only when a filter is in play, so a run
without `--filter` pays nothing for them.

### Output shape

| Flag | Effect | rg parity |
|---|---|---|
| `--sort path` / `--sortr path` | sort the file list in path order / reverse | same |
| `-I`, `--no-filename` | do not print file names | same |
| `--heading` | print the path once above its matches | same |
| `--no-heading` | print the path before every match line (the default when stdout is not a TTY) | same |
| `-n`, `--line-number` | show line numbers (on by default only when stdout is a terminal) | same |
| `-N`, `--no-line-number` | hide line numbers; **wins** over `--line-number` | rgx differs — rg lets the last of the two win |
| `--column` | print the 1-based byte column of each match | same |
| `--vimgrep` | `{path}:{line}:{col}:{text}`; implies `--column` | same |
| `-E`, `--encoding <ENC>` | decode input as `utf-8`, `utf-16le` or `utf-16be` | same |
| `--color <WHEN>` | `auto` (default) / `always` / `ansi` / `never` | same |

Flags that take a path accept `-` for stdin. **`--file` is not accepted**,
matching rg.

### Adapters and the extraction cache

| Flag | Effect |
|---|---|
| `--max-adapter-depth <N>` | maximum archive nesting depth (default 4) |
| `--cache[=DIR]` | memo of adapter output, keyed by path + mtime + adapter version + config. Bare uses `$RGX_CACHE_DIR`, else `~/.rgx/cache`. **Off by default.** |
| `--cache-clear` | delete the extraction cache and exit |
| `--cache-prune` | drop entries older than `--cache-max-age`, then the oldest until the cache fits its budget, and exit |
| `--cache-max-age <DAYS>` | age threshold for `--cache-prune` (default 30) |

### Interactive

| Flag | Effect |
|---|---|
| `--pick` | pipe results to fzf and print the selection. Exit 0 picked, 1 nothing or dismissed, 2 no fzf |
| `--fzf-binary <PATH>` | picker for `--pick` (default: the first of `fzf`, `sk`, `peco`, `fz` on PATH) |
| `--fzf-arg <ARG>` | one argument passed to the picker, repeatable (`--fzf-arg=--multi`) |

### Shell

| Flag | Effect |
|---|---|
| `--completions <SHELL>` | print a completion script generated from the live grammar |

### Engine, pack store, token index

| Flag | Effect |
|---|---|
| `--engine <auto\|tv\|rgx>` | engine selector. `auto` runs the adaptive detector (the default), `tv` the pack-store storage tier, `rgx` the in-process SIMD engine |
| `--tv` | shorthand for `--engine tv` |
| `--tv-store <DIR>` | the pack store directory; holds `manifest.tvm` and the `.tvp` packs |
| `--tv-build` | **boolean**. Build or update the store in `--tv-store` from the first positional path, then exit |
| `--tv-pre-extract` | pre-extract adapter text during the pack build, for instant queries |
| `--tv-verify <PATTERN>` | A/B the in-house engine over the store on PATTERN, report which is faster, and exit |
| `--index-build <DIR>` | build a token index for DIR and exit (writes `.ugi` into `--index-store`) |
| `--index <DIR>` | answer queries through the index in DIR |
| `--index-store <DIR>` | where `--index-build` writes (default `<root>/.rgx-idx.ugi`) |
| `--explain-engine` | on stderr, why the detector chose the engine it chose |
| `--stats` | on stderr, the in-process stage decomposition of a pack-store query |

`--tv-build` takes the corpus as the **first positional**, so the shape is:

```sh
rgx --tv-build --tv-store STORE CORPUS
```

### The facts index

| Flag | Effect |
|---|---|
| `--facts-build <DIR>` | walk DIR, record what is known about every file, and write the index; then exit |
| `--facts-index <DIR>` | answer a `--filter` against the index in DIR and print the matching paths. Exit 1 when nothing matches |
| `--facts-export <FILE>` | copy the index to FILE, in the same JSON Lines form. Needs `--facts-index` or `--facts-build` |
| `--facts-store <PATH>` | where the index is read from and written to (default `<root>/.rgx-facts.jsonl`) |

The index is described in the [README](README.md#the-facts-index).

### The MCP server

| Flag | Effect |
|---|---|
| `--mcp` | speak the Model Context Protocol (JSON-RPC 2.0, one message per line) on stdin/stdout instead of searching |

The tools and the protocol version are in the
[README](README.md#the-mcp-server).

`--mcp` and `--serve` cannot be combined — both want to own stdin — and
`--mcp` takes no pattern and no path of its own.

---

## 13. Troubleshooting

**"rgx ignores my flag."** Check for a `.rgxrc` — it is prepended to argv,
so a flag there is overridden by the command line, but a flag you expect to
be default may be set in the file.

**"The store is slower than a direct search."** Small corpus, or few queries
per mutation: the build cost is not amortised. `rgx --tv-verify PATTERN
--tv-store S` answers it for one pattern. The break-even query count for the
reference corpus is in `benchmark/findings.md`.

**"A PDF is not searched."** The PDF reader is in-process, so this one means
the file was refused — a truncated xref, an encrypted document whose key does
not reproduce, a format the reader does not own. rgx then searches the file's
own bytes: a declined adapter means the content was not understood, not that
the file is out of the search.

**"The counts differ from rg."** That is a bug, and it is the one the
harness treats as fatal. `scripts/compare-rg.sh` names the failing case, and
`scripts/tv-parity.py` and `scripts/tv-diff-lines.py` narrow it down.

**"A run is much slower than the last one."** Absolute milliseconds are a
property of the host *and* the machine state, not of the code. Check
`benchmark/findings.md` §20: going cold costs the direct paths 30–32% of
their warm latency and the pack store ~9%, so a run made against a cold page
cache is not comparable to a warm one.

**"The cache serves a stale answer."** The cache is keyed by the path, the
size and the mtime, and an edit that preserves the size *and* the mtime is
invisible to it — the same hole `make`, `ccache` and `cargo` have. Run
`--cache-clear`, or leave the cache off.

---

## 14. References

- **ripgrep**, whose flags, output and exit codes rgx reproduces —
  [the user guide](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md)
  and [the repository](https://github.com/BurntSushi/ripgrep).
- **The rgx paper**, the diodic architecture the pack store implements —
  [rgx-paper](https://github.com/danalec/rgx-paper), DOI
  [10.5281/zenodo.23453407](https://doi.org/10.5281/zenodo.23453407).
- **The format specifications** — what each format's bytes are, and the
  oracle that checks the reading against it — in
  [`FORMATS.md`](FORMATS.md#the-facts-each-format-gives) and in the
  project's notes, §14.1.
- **The Model Context Protocol**, the `--mcp` server's wire format —
  [the 2025-03-26 specification](https://modelcontextprotocol.io/specification/2025-03-26).
- **The published measurements** — [`benchmark/status.md`](benchmark/status.md)
  and the ledger of what was tried, [`benchmark/findings.md`](benchmark/findings.md).

---

## 15. See also

- [`README.md`](README.md) — what rgx is, and the measurements.
- [`FORMATS.md`](FORMATS.md) — what it reads, format by format, and what it
  refuses.
- [`AGENTS.md`](AGENTS.md) — the project's own notes: the contracts that
  must not break, the conventions, and where the specifications live.
- [`COPYING`](COPYING) — the licence the whole tree is under, and what it does not cover.

---

## License

`rgx` is Apache-2.0, and nothing else — the pack store, the codecs and every
adapter included. See [`COPYING`](COPYING), `LICENSE-APACHE` and `NOTICE`.
