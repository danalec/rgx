# rgx

`rg` that reads **inside** files — PDFs, Office documents, archives, 3D models,
LLM checkpoints, databases, e-mail, media metadata. Every container format
ripgrep treats as opaque bytes.

Same flags, same `path:line:text` output, same exit codes (0/1/2), so it drops
into a pipeline that already calls `rg` unchanged.

Every adapter runs **in-process** — bytes in, searchable text out.

That is the whole difference from [rga](https://github.com/phiresky/ripgrep-all), which reaches the same
formats by shelling out to a helper per file:
here there is nothing to spawn

## See it work

[![rgx -- a demo on YouTube](https://img.youtube.com/vi/R-td9S8gBn4/hqdefault.jpg)](https://www.youtube.com/watch?v=R-td9S8gBn4)

## rgy or rgx?

**If you just want to find things, use [rgy](https://github.com/danalec/rgy).**
It ships rgx's matching engine inside an indexed search app: your disks are
indexed once, a name query answers from that index, and a content query narrows
with the index before reading the file. Nothing to configure, nothing to
rebuild by hand. Windows, Linux, macOS and FreeBSD.

`rgx` is what sits underneath: a search *engine* and an `rg`-compatible command
line. Take it when you are scripting, dropping it into a pipeline that already
calls `rg`, or choosing the engine and the store yourself.

| | [rgy](https://github.com/danalec/rgy) | `rgx` (this repo) |
|---|---|---|
| Shape | an app — CLI, TUI (`search-ui`) and daemon (`searchd`) | one binary: `rgx PATTERN [PATHS]` |
| Find a **file by name** | yes — fuzzy, ranked, typo-tolerant (`rep`, `^src`, `dat$`, `!tmp`) | no — `--files` lists paths and `-g` filters by glob; rgx searches *contents* |
| Find **text inside a file** | yes — `grep:` / `regex:` / `sym:`, confirmed on rgx's regex engine | yes — the whole `rg` flag surface |
| Read **inside** a PDF / Office doc / archive | not yet — the adapter families are vendored, the search path does not run them | yes — every family in [What it reads](README.md#what-it-reads) |
| Between queries | keeps an index across runs | walks the tree again, every query |
| Indexed when | by default, on first run | opt-in and manual — `--index-build`, or `--tv-build` for the pack store |
| Freshness | `--max-age` / `--reindex` say when the index is rebuilt | always current — it reads the disk as it searches |
| Exit codes | 0 matches · 1 none · 2 error | the same |

rgy's confirmation step *is* rgx's regex engine — `rgx_core::regex::ByteRegex`,
imported verbatim — so plain-text matching runs the same code in both. What is
not in rgy's search path yet is the adapter layer: `grep:` confirms against a
file's own bytes, so a hit *inside* a PDF, an Office document or an archive is
rgx-only today.

## Install

```powershell
irm https://raw.githubusercontent.com/danalec/rgx/main/install.ps1 | iex
```

From crates.io, as a Rust tool:

```sh
cargo install rgx-search   # installs the `rgx` binary
```

Linux tarballs (glibc, static musl, znver4) and `.deb` / `.rpm` / `.apk` /
`.pkg.tar.zst` packages are on the
[release page](https://github.com/danalec/rgx/releases/latest). Winget
manifests are in `.winget/`.

On macOS, from Homebrew — the formula is in `Formula/rgx.rb`, and
`scripts/publish-homebrew.sh` opens the pull request to homebrew-core:

```sh
brew install rgx
```

## Build only what you need

Every format sits behind a Cargo feature, so a build can carry only the ones
you name. The default build carries all of them; a narrow one does not.

```sh
# the engine alone: no adapter crate at all
cargo build --release --no-default-features

# only the formats you asked for
cargo build --release --no-default-features \
  --features format-pdf,format-zip,format-office

# a whole adapter crate at once
cargo build --release --no-default-features --features adapters-archive
```

The feature is named after the string the adapter itself reports — the one
`--json` prints in the `format` field — so `format-zip` is the zip adapter,
`format-grib` is GRIB, `format-stl` is the binary STL and `format-stl-ascii`
is the ASCII renderer.

**The engine is `no_std`.** `rgx-core` is `#![no_std]` + `alloc`, and the
`std` feature turns on the typed error chain, the profiler map and the
`f64` JSON parser — nothing else that matters. So the engine above is the
crate an embedder links: a router or a NAS that wants to search its own
files can take it without the standard library, and still reach the same
AVX2 kernels the full build uses.

`rgx --version` prints the formats the build actually carries, read from the
features themselves, so the list cannot drift away from the binary.

The full binary is 9 340 416 bytes. A build with three formats (zip, pdf,
grib) is 4 014 592 and the engine alone is 3 516 416 — 57 % and 62 % smaller.

## Try it

The first three are searches ripgrep reports as binary:

```sh
rgx "invoice total" ~/Documents        # inside PDFs and .docx
rgx "password" secrets.tar.gz .env.bak # inside archives
rgx "hidden_dim" model.gguf            # inside an LLM checkpoint

rgx "fn main" -t rust --sort path .    # plain source: the flags you already know
```

On a mixed corpus of source plus RAR / 7z / tar / brotli / zstd / lz4 / xz /
lzma fixtures, from one command line:

| | paths returned |
|---|---:|
| **rgx** | **20** |
| ripgrep | 9 |

+122% more hits. ripgrep calls those archives binary and moves on; rgx unpacks
them in-process. Full table and the gate that produced it:
[`benchmark/status.md`](benchmark/status.md).

## What it reads

The families, the formats of each one, what each of them gives and what
each of them refuses are in [**FORMATS.md**](FORMATS.md) -- eighteen
families, from the archive to the e-mail, and the gaps of each.

### Searching by what a file is

A pattern asks a question about the *text*. A filter asks a question about the
*file*, and the file has facts the pattern cannot see: a PDF has an author, a
message has a sender, a photo has coordinates, a model has tensors, an archive
has entries. `--filter` is where they become searchable.

```console
$ rgx 'contrato' --filter 'mime:pdf AND author:"ACME"'
$ rgx 'senha|password' --filter 'mail:from:"admin@example.com"'
$ rgx 'layer.*weight' --filter 'tensor:name AND mime:safetensors'
$ rgx 'GPS' --filter 'exif:gps'
$ rgx 'api_key' --filter 'container:zip AND lang:python'
```

The grammar is predicates over named facts, combined with `AND`, `OR` and
`NOT`, with parentheses:

```text
expr      := or
or        := and ( "OR" and )*
and       := unary ( "AND" unary )*
unary     := "NOT" unary | primary
primary   := "(" expr ")" | predicate
predicate := path [ ":" [ op ] value ]
path      := ident ( (":" | ".") ident )*
op        := "=" | "!=" | "<" | "<=" | ">" | ">="
value     := '"' text '"' | "'" text '"' | bare
```

**Where the path ends.** At the *last* colon outside quotes, so
`mail:from:"admin@example.com"` is the path `mail:from` and the value
`admin@example.com`, and `mime:pdf` is the path `mime` and the value `pdf`.
`:` and `.` are the same separator, so `mail:from` and `mail.from` are one
path.

**What a predicate matches.** A fact has a name and a value. A predicate whose
path is the fact's *name* compares the fact's *value*; a predicate whose path
is the fact's *namespace* compares the fact's *name*. So `author:"Jane Doe"`
asks who wrote it, and `exif:gps` asks whether the file has an EXIF fact
called `gps` at all. That second shape is why a fact nobody reports is
false rather than an error: a file that is not a photo does not have GPS.

The facts each format gives are in
[**FORMATS.md**](FORMATS.md#the-facts-each-format-gives).

**The unit is what is filtered.** A file that no adapter claims is searched
raw, and the raw path is filtered on the facts the name gives. A member of a
container is filtered on its own facts *plus* the container's: a Python file
inside a zip is a Python file (`lang:python`) and it is inside a zip
(`container:zip`), and a filter that asks for both keeps it. A container
itself produces no unit of its own — its members do — so `--filter ext:zip`
finds nothing, because the thing that gets searched is `bundle.zip!script.py`
and that is a `.py`.

**What it costs.** Nothing when there is no filter: the facts are not
assembled, and the adapters are not asked. With a filter, an adapter that has
to parse the file again to answer pays for a second parse — the PDF's
`/Info` dictionary is the case that shows it.

**What it is not.** An index, and a query language over an index. The filter
is applied to what the walk finds, file by file, the same way the pattern is.

### The facts index

A filter asks every file the same question on every run: *what do you know
about this file?* The answers are assembled, tested against the filter, and
thrown away. That is a fine bargain for one search over a corpus that is
still moving, and a bad one for a question asked twice about a corpus that
changes once.

`--facts-build` asks the question once and keeps the answers:

```console
$ rgx --facts-build ~/corpus          # writes ~/corpus/.rgx-facts.jsonl
$ rgx --facts-index ~/corpus --filter 'mime:pdf'
```

The index is **JSON Lines**: one object per path, one line per object.

```console
$ head -1 ~/corpus/.rgx-facts.jsonl
{"path":"/home/me/corpus/a.txt","size":15,"mtime":1700000000,"facts":{"path":"/home/me/corpus/a.txt","format":"raw","ext":"txt","mime":"text/plain"}}
```

It is JSON and not a binary blob for the same reason the token index is
not the only thing rgx ships: **an index nobody can read is an index nobody
will inspect**. `rg` reads this file. So does `jq`, and so does a person
who wants to know what rgx thinks a file is.

**The query language is the filter's.** `--facts-index` takes the same
`--filter` expression the walk takes, and applies it to the facts that were
kept. There is one query language over the facts, not two: a second one
would be a second answer to the same question, and the two would drift.

**What a stale record does.** It does not answer. A record carries the
size and the modification time the file had when the facts were taken, and
a file that no longer has them is a file the index does not know any more.
The record is reported as stale on stderr rather than silently answered:
a filter that matched a file that has since changed is a filter that
answered about a file that is not there.

**What the index is not.** It is not a copy of the corpus. It holds facts
and stamps, not bytes — the bytes are read from the file when a search
runs, and an index that held them would be a second copy of the corpus,
and a stale one.

**Where it lives.** `<root>/.rgx-facts.jsonl` by default.
`--facts-store <PATH>` puts it somewhere else, which is the flag to reach
when the corpus itself is read-only, or when the index is meant to describe
a tree other than the one it is asked about.

**Getting it out.** `--facts-export <FILE>` copies the index to a file, in
the same JSON Lines form it was written in:

```console
$ rgx --facts-index ~/corpus --facts-export ~/facts.jsonl
```

The export is the **whole** index, not a filtered subset: choosing which
records to keep is the reader's job, and the reader already has a way to
choose — `--facts-index` with a `--filter`. What the export does not do is
invent a second format. An export in a format only rgx reads would be a way
to move facts that only rgx could then use, and the index is already a file
that `rg`, `jq` and a person can read.

### The MCP server

`--mcp` puts rgx behind a **Model Context Protocol** server: JSON-RPC 2.0
over stdin and stdout, one message per line, the way an MCP client already
speaks to a tool.

```console
$ rgx --mcp
```

Two tools are exposed:

| tool | what it answers |
|---|---|
| `search` | a **literal**, case-sensitive search over the corpus. The pattern is matched byte for byte, and the path narrows where the search happens. |
| `facts` | what is known about one file: the adapter that claimed it, and, with a `filter` argument, whether that file satisfies a `--filter` expression. |

The protocol version announced at `initialize` is `2025-03-26`, and the
older `2024-11-05` is accepted and echoed back when the client asks for it.
`initialize`, `tools/list`, `tools/call` and `ping` are the methods; a
notification such as `notifications/initialized` is answered with nothing,
because a notification is not a question.

`--mcp` and `--serve` are two doors into the same house: `--serve` speaks
rgx's own line protocol to one client, `--mcp` speaks the protocol an MCP
client already speaks. They cannot be combined — both want to own stdin —
and `--mcp` refuses a pattern or a path of its own, because the requests
arrive on the wire and a second way in would be a second answer to the
same question.

## Speed

Every row below sits behind a match-count gate: a row whose counts disagree
against ripgrep is withheld, not printed with a ratio. Per-row timings, corpus
digests and the ±3% spawn floor are in
[`benchmark/status.md`](benchmark/status.md).

- **One large file, the matcher alone** — **1.33×–2.14×** faster than ripgrep,
  9 of 9 patterns won (246 MB file, `-j1`).
- **A directory walk, 20,028 files** — five of nine patterns ahead, one tie,
  three overlapping, **none a ripgrep win**. The isolated walker is the clearest
  margin: 14.3 ms against 23.0 ms for 20,000 paths.
- **Pack store, same tree built once** — **2.4×–3.1×** over rgx's own direct
  path, **2.8×–3.4×** over ripgrep, paying for itself after ~24 queries.

**And the other half of it:** those are one machine's numbers. The same
byte-identical corpus on a second host (Linux, Ryzen 7 255) puts rgx *behind*
ripgrep on six of the nine patterns
([`benchmark/status-linux-ryzen7-255.md`](benchmark/status-linux-ryzen7-255.md)).
Quote a ratio with its host, or don't quote it.

## The extraction cache

`--cache DIR` memoises what the adapters made of a file, so a second search
over the same corpus does not extract it again: a copy of a file is
extracted once, a file that moved is not extracted again, and a touched file
is re-read rather than re-extracted. How it is keyed, and what it does not
survive, is in the [manual](MANUAL.md#6-adapters-and-the-extraction-cache).

## The storage tier

The architecture is **diodic**: work is asymmetric in one direction and
scoped to one generation of the corpus, so a mutation re-pays the build and
the asymmetry is amortised between one ingestion and many queries. The
`--tv` flags select it, and the tier itself is in the
[manual](MANUAL.md#5-the-pack-store).

## Still ripgrep

The `rg` flag surface works as-is — `-i -S -F -w -v -m -o -r -l -c -q -U
--files --json -g --no-ignore --max-depth -M/--max-filesize -I -A/-B/-C
--files-without-match -a`, plus `-t/--type` and `-T/--type-not`.

**One default differs, on purpose.** rgx reads the hidden files — a name
that starts with a dot, and on Windows the hidden attribute — because a
format that keeps its own metadata in a dotfile is invisible otherwise: a
Zarr array's `.zarray`, a `.zattrs`, a `.gitignore`. `--no-hidden` puts
ripgrep's default back. The one thing never walked, whatever the flag
says, is a version-control system's own state (`.git`, `.hg`, `.svn`,
`.jj`): it is metadata *about* the corpus rather than the corpus, and it
is routinely larger than the tree it describes. The rules in it are still
applied — a `.gitignore` and a `.git/info/exclude` are read and honoured —
they are just not listed.

Four additions are worth knowing:

- **`--chunk[=BYTES]`** — each match as a paragraph-aware window, built for LLM
  context. Bare `--chunk` is 2048 bytes.
- **`--filter <expr>`** — a structured query over what is known about a file:
  its type, its language, the author of a PDF, the sender of a message, the
  tensors of a model, the columns of a table. See
  [Searching by what a file is](README.md#searching-by-what-a-file-is).
- **`--serve`** — a persistent query daemon; the adapter registry and page
  cache survive between queries.
- **`--json`** — machine-readable, naming the adapter that claimed each file and
  the exact submatch spans.
- **`.rgxrc`** — read *before* argv, so a CLI flag always wins. If rgx seems to
  ignore a flag you passed, look here first.

Full reference: [`MANUAL.md`](MANUAL.md).

## Scripts

Three jobs exist in both languages. The `.sh` is the Linux counterpart and
runs the same cases, so a parity failure names the same case on either host.

| job | Windows | Linux / macOS |
|---|---|---|
| parity against ripgrep | `scripts/compare-rg.ps1` | `scripts/compare-rg.sh` |
| linker A/B (system vs lld vs lld-znver4) | `scripts/bench-linkers.ps1` | `scripts/bench-linkers.sh` |
| CPU topology, for the thread sweeps | `scripts/detect-ccd.ps1` | `scripts/detect-ccd.sh` |

**PowerShell** — `scripts/build-release.ps1` (both shippable binaries,
gate included) · `scripts/check-vendoring.ps1` (the guard) ·
`scripts/check-drift.ps1` (vendored code behind upstream) ·
`scripts/apply-vendored-edits.ps1` · `scripts/harvest-golden.ps1` ·
`scripts/publish-release.ps1` · `scripts/smoke-serve.ps1`, plus
`benchmark/extent-ab.ps1`.

**bash** — `scripts/release-all.sh` (the whole release, one command) ·
`scripts/build-linux.sh` and `scripts/package-linux.sh` (every Linux artifact,
each install-verified in a container of its own distro) ·
`scripts/release-linux.sh` (Linux artifacts onto this machine) ·
`scripts/push-github.sh` (mirror the release to GitHub) ·
`scripts/bench-status.sh` (regenerates the tables above) ·
`scripts/adapter-subset.sh` (superset or subset, per adapter) ·
`scripts/diodicity.sh` · `scripts/engine-sweep.sh` · `scripts/mmap-ab.sh`, and
the pack-store harnesses `tv-vs-rg.sh`, `tv-matrix.sh`, `tv-threads.sh`,
`tv-cold.sh`, `tv-ablate.sh`, `tv-ugrep.sh` and `tv-usecase.sh`.

## Reading further

| | |
|---|---|
| [`FORMATS.md`](FORMATS.md) | what each format gives, and what it refuses |
| [`MANUAL.md`](MANUAL.md) | every flag, environment variable and exit code |
| [`benchmark/status.md`](benchmark/status.md) | per-row timings, corpus digests, the gate, both hosts |
| [`benchmark/findings.md`](benchmark/findings.md) | the ledger — what was tried, and what it was worth |
| [`COPYING`](COPYING) | the licence the whole tree is under, and what it does not cover |

## License

**Apache-2.0**, and nothing else — per file: every file in this repository
carries an SPDX header, and a test reads the file list out of git and fails
on the first file that says otherwise. A distributed `rgx` binary is
Apache-2.0 code plus the Rust dependencies it links, each of which carries
its own permissive licence.

The full text is `LICENSE-APACHE`. What is not rgx's code is named in
[`NOTICE`](NOTICE), and the reasoning — why the tree has one licence and
what it does not cover — is in [`COPYING`](COPYING).

## Star history

<a href="https://star-history.com/#danalec/rgx&Date">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=danalec/rgx&type=Date&theme=dark">
<source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=danalec/rgx&type=Date">
<img alt="Star History Chart" src="https://api.star-history.com/svg?repos=danalec/rgx&type=Date">
</picture>
</a>
