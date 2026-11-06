# rgx binary (`rgx-search`)

## Overview

`src/` is the root binary package of the rgx workspace — the `rgx`
command itself. The crate is published as `rgx-search` because `rgx` is
taken on crates.io; the binary it installs is `rgx`.

This directory owns the command-line grammar, the search orchestration
and the output formatting, and it is the only place that decides
whether a file is searched as raw bytes on disk or handed to the
adapter pipeline in `rgx-core`. The modules beside `main.rs` are the
parts of one search run: `walk.rs` finds the files and applies git's
ignore rules, `engine.rs` wraps the in-house byte searcher in a
`grep-searcher`-shaped face, `detector.rs` chooses between the direct
byte engine and the pack store, `cache.rs` memoises adapter output on
disk, `type_db.rs` classifies file types for `-t`/`-T`, `rc.rs` loads
`.rgxrc`, `pick.rs` hands the output to an external picker, and `cli/`
is the argument parser the grammar is written against. `mmap.rs`
decides read-versus-map for a file's bytes, but it is not a module of
the crate root: `engine.rs` declares it, so it lives at
`crate::engine::mmap`.

`main.rs` is the largest file: it holds `Args` (the parsed command
line), `app()` (the grammar table), the sinks that format matches in
text and JSON, the walk driver, the adapter dispatch, the `--serve` and
`--mcp` protocol modes, and the index/facts/pack-store generators that
exit before a search begins.

## Interface

- `fn main()` — the process entry point: runs `run()`, prints the
  engine tally, and exits 2 on an error (`src/main.rs:fn main`).
- `fn run() -> rgx_core::Result<()>` — the top-level dispatch, in
  order: shell completions, `--serve`, `--mcp`, cache clear/prune,
  `--type-list`, pack-store build, `--tv-verify`, token-index build,
  `--index-dir` query, facts-index build/export, then the search itself
  (`src/main.rs:fn run`).
- `struct Args` — the parsed command line: the pattern, the paths, the
  boolean flags, and the index/facts/pack-store options
  (`src/main.rs:struct Args`).
- `fn app() -> cli::App` — the grammar table the parser reads
  (`src/main.rs:fn app`).
- `fn registry() -> rgx_core::Registry` — the adapter registry this
  build carries; one entry per `format-*` feature
  (`src/main.rs:fn registry`).
- `struct Submatch` — one match span inside a line, with its byte
  offsets (`src/main.rs:struct Submatch`).
- `pub(crate) fn compiled_byte_arc(args: &Args) -> Option<Arc<ByteRegex>>`
  — the process-wide memo of the compiled pattern
  (`src/main.rs:fn compiled_byte_arc`).
- `fn unit_searcher(raw: &mut RawState, found: &rgx_core::Found, path_str: &str, named_binary: bool) -> &mut CompatSearcher`
  — the searcher a unit is read with: a unit that IS the file's own
  bytes uses the convert rule (rg's rule for a path the user named)
  when `named_binary` is set and the quit rule otherwise, and every
  other unit uses the text searcher (`src/main.rs:fn unit_searcher`).
- `fn unit_is_binary(args: &Args, bytes: &[u8]) -> bool` — the file's own
  binary rule, sniffed on the unit that IS the file's own bytes; a
  walked binary file is dropped whole and is not counted as a miss
  (`src/main.rs:fn unit_is_binary`).

### `engine.rs`

- `pub enum Mode { Rgx }` — the only engine; `Mode::from_env()` reads
  `RGX_ENGINE`, warns once on stderr when it names a retired engine
  (`grep`, `both`) and returns `Mode::Rgx` either way — the run
  continues.
- `pub struct Searcher` — the searcher the binary drives.
  `Searcher::new(config: Config, byte: Option<Arc<ByteRegex>>, _mode: Mode) -> Searcher`,
  `search_slice<S>(&mut self, hay: &[u8], sink: &mut S) -> Result<bool, io::Error>`,
  `search_path<S>(&mut self, file: std::fs::File, len: u64, sink: &mut S) -> Result<bool, io::Error>`,
  `binary_detection(&self) -> RgxBinaryDetection` (test builds only).
- `pub use rgx_core::searcher::BinaryDetection as RgxBinaryDetection`.
- `pub enum Event { Match(Option<u64>, Vec<u8>), Context(Option<u64>, Vec<u8>), Other(Option<u64>, Vec<u8>), Finish(Option<u64>) }`
  — the reduced form of a reported event; kept for the sink contract,
  with no live reader.
- `pub fn build_byte_regex_flags(pattern: Option<&str>, ignore_case: bool, dot_all: bool) -> Option<ByteRegex>`
  — compile the pattern with the in-house engine, or `None` when it is
  outside the byte-mode subset.
- `pub mod stats` — `RGX_RUNS`, `FALLBACKS`, `DIVERGENCES`,
  `EXPLICIT` (atomics) and `stats::report()`, which prints nothing
  unless `EXPLICIT` is set.

### `walk.rs`

- `pub struct TypeSel { name: String, negate: bool }` — a `-t`/`-T`
  selection, kept in the order the command line gave it.
- `pub struct TypeFilter` — `new(db: TypeDb, selections: Vec<TypeSel>)`,
  `db() -> &TypeDb`, `accepts(&Path) -> bool` (test builds only),
  `classify_verdict(&Path) -> Option<bool>`,
  `accepts_with_bytes(&Path, head: &[u8]) -> bool`.
- `pub struct Override` / `pub struct OverrideBuilder` — the gitignore
  layer: `Override::empty()`, `is_empty()`, `matched(&Path, is_dir: bool) -> Match`;
  `OverrideBuilder::new(path)`, `add(&mut self, glob: &str) -> Result<&mut OverrideBuilder, GlobError>`,
  `build(&self) -> Result<Override, GlobError>`.
- `pub enum Match` — the verdict of an ignore rule; `is_ignore(self) -> bool`.
- `pub struct GlobError` — a glob that would not compile.
- `pub enum WalkState` — what the visitor says about an entry
  (continue, skip the subtree, stop).
- `pub struct DirEntry<'a>` — `path() -> &Path`,
  `file_type() -> Option<FileType>`, `metadata() -> io::Result<&Metadata>`.
- `pub struct Builder` — `new(path)`, `add(path)`, `hidden`, `parents`,
  `git_ignore`, `git_global`, `git_exclude`, `follow_links`,
  `max_depth`, `overrides`, `add_glob`, `threads`, `ordered`,
  `type_filter`, `build_parallel() -> WalkParallel`.
- `pub struct WalkParallel` — `run<F>(&self, mkf: F)` where `F` hands a
  fresh visitor per thread.
- `pub fn print_walk_stats()` — the opt-in walk statistics.

### `detector.rs`

- `pub enum EngineChoice { PackStore, RgxDirect }` — `as_str(&self) -> &'static str`
  (`"tv"` / `"rgx"`).
- `pub struct DetectionResult { engine: EngineChoice, reason: String, store_path: Option<PathBuf>, explicit: bool }`.
- `pub struct AutoDetector` — `detect(args: &Args) -> DetectionResult`,
  `find_store(args: &Args) -> Option<PathBuf>`,
  `is_valid_store(dir: &Path) -> bool`.

### `cache.rs`

- `pub const MAX_BYTES: u64 = 256 << 20` — the byte budget the cache is
  pruned back to.
- `pub struct Cache` — `open(dir: PathBuf) -> Self`,
  `extract_once<F>(&self, key: &str, file_path: &str, extract: F) -> Option<Vec<Found>>`,
  `content(&self, key: &str) -> Option<Vec<Found>>`,
  `alias(&self, key: &str) -> Option<String>`,
  `put_content(&self, key: &str, file_path: &str, founds: &[Found])`,
  `put_alias(&self, key: &str, content_key: &str)`,
  `note_alias_hit()`, `note_content_hit()`, `note_miss()`,
  `Cache::summary() -> String`.
- `pub struct Key<'a>` / `pub struct BuildStamp` — the two key inputs;
  `BuildStamp::derive() -> Option<String>`,
  `derive_content(&self, content: &[u8; 32]) -> Option<String>`,
  `name(&self) -> &str`.
- `pub fn build_stamp() -> Option<BuildStamp>`,
  `pub fn version_of(adapter: &str) -> Option<u32>`,
  `pub fn chain_for(reg: &rgx_core::Registry, path: &str) -> Option<Vec<(&str, u32)>>`,
  `pub fn policy_code() -> u8`,
  `pub fn locate(flag: Option<&str>) -> Result<PathBuf>`,
  `pub fn relative_of(unit_path: &str, file_path: &str) -> Option<String>`,
  `pub fn restamp(unit_path: &str, file_path: &str) -> String`,
  `pub fn content_hash(data: &[u8]) -> [u8; 32]`,
  `pub fn clear(dir: &Path) -> Result<(usize, u64)>`,
  `pub fn prune(dir: &Path, max_age: Duration, max_bytes: u64) -> Result<(usize, u64)>`.

### `mmap.rs`

- The module is `crate::engine::mmap`: `engine.rs` declares it with
  `#[path = "mmap.rs"] pub(crate) mod mmap;` (`src/engine.rs:mod mmap`), so it
  is `pub(crate)` and is not a module of the crate root.
- `pub const MAP_THRESHOLD: u64 = 64 * 1024` — below this, map nothing.
- `pub const AUTO_MMAP_THRESHOLD: u64 = 64 * 1024 * 1024` — the retired
  automatic-promotion threshold, kept with its measurement table.
- `pub fn worth_mapping(len: u64) -> bool`,
  `pub fn should_map(len: u64) -> bool` — the platform-split decision,
  `pub fn enabled_by_env() -> bool` — the `RGX_MMAP` override.
- `pub struct MappedFile` — `map_file(path)`, `map_open_file(&File)`,
  `map_prefix(path, len)`; `len()`, `is_empty()`,
  `live_len(&mut self) -> usize`, `set_limit(&mut self, len: usize)`,
  `as_live_slice(&mut self) -> &[u8]`,
  `read(&mut self, buf: &mut [u8]) -> io::Result<usize>`,
  `consumed(&self) -> usize`.

### `type_db.rs`

- `pub struct TypeEntry { name: String, exts: Vec<String> }`.
- `pub struct TypeDb` — `with_defaults()`, `add(&mut self, name: &str, exts: &[&str])`,
  `clear(&mut self)`, `classify_name(&self, name: &str) -> Option<&str>`,
  `patterns_of(&self, name: &str) -> Option<&[String]>`,
  `type_names(&self) -> Vec<&str>`, `has_type(&self, name: &str) -> bool`,
  `resolve<'a>(&'a self, name: &'a str) -> Option<&'a str>`.

### `rc.rs`

- `pub fn load() -> Vec<String>` — the tokens of the first `.rgxrc`
  found.
- `pub fn merge_into(argv: Vec<String>) -> Vec<String>` — the config
  tokens prepended to the user's argv.

### `pick.rs`

- `pub struct Request<'a> { args: &'a [String], binary: Option<&'a str> }`.
- `pub type Search = Box<dyn FnOnce(&mut (dyn Write + Send + 'static)) -> Result<bool> + Send + 'static>`.
- `pub fn pick(search: Search, req: &Request<'_>) -> Result<i32>` — runs
  the search on its own thread, feeds the picker, and yields the
  process exit status.

### `cli/`

- The argument parser the grammar is written against: [cli](./cli/EGM.md).

## Invariants

- **Exit status.** 0 for a match (or `--list-files`), 1 for no match,
  2 for an error. `main()` prints `Error: {e:?}` and exits 2;
  `Args::parse` exits 2 on a parse error and exits 0 after printing
  help or version.
- **Raw bytes stay raw.** A file an adapter claims is read and
  searched in memory; every other file is searched directly on disk
  (read, or memory-mapped where `mmap.rs` says so). Plain text never
  enters the adapter pipeline.
- **Searcher field order.** In `engine::Searcher`, `searcher` and
  `hybrid` are declared before `byte` and are therefore dropped
  first; that ordering is what keeps the transmuted `'static` borrows
  of the `ByteRegex` valid.
- **A whole-file scan starts at zero.** `FileSource::new` rewinds the
  caller's handle to offset 0 before reading, because the caller may
  already have sniffed the first 64 KiB of the file.
- **One engine, and a refusal is loud.** There is no second engine. A
  pattern outside the in-house byte subset is answered with
  `io::ErrorKind::Unsupported` and counted in
  `engine::stats::FALLBACKS` — never with a silent second opinion.
- **One compiled pattern.** The compiled `ByteRegex` is memoised per
  process and shared behind an `Arc`, so the three searchers a worker
  builds cost one compile, not three.
- **Types decide in command-line order.** A type is a set of patterns,
  a file matches every type whose patterns its name satisfies, and the
  *last* type the user named that matches the file is the one that
  decides. `-t js -T minified` and `-T minified -t js` are different
  queries.
- **The type filter never prunes a directory.** It sees file entries
  only, and is `None` when no `-t`/`-T` was given.
- **The config file loses to the command line.** `.rgxrc` tokens are
  prepended to argv, so a repeated flag is honoured as the later one.
  A missing `.rgxrc` is not an error; a file that exists but cannot
  be read is a warning on stderr.
- **Hidden files are read by default.** A format that keeps its own
  metadata in a dotfile (a Zarr `.zarray`, a `.gitignore`) is invisible
  otherwise; `--no-hidden` puts ripgrep's behaviour back.
- **The cache is off unless asked for.** A wrong default serves stale
  bytes. A key covers the format tag and version, the build stamp of
  the running executable, the file's name, the extraction settings, the
  policy and the adapter chain; the alias layer adds path, size and
  mtime, and the content layer adds the SHA-256 of the bytes. Adapters
  that consult state outside the input bytes and this executable are
  not memoised at all.
- **The protocol modes own stdin.** `--serve` (JSON argv arrays) and
  `--mcp` (JSON-RPC 2.0) read stdin and never exit; neither takes a
  pattern or paths, and neither can be combined with `--pick` or with
  each other.
- **The tally is printed once.** The engine statistics are a property
  of the whole walk, so they are printed inside `run()`, before it
  leaves through `process::exit` — not by whichever worker happened to
  finish last, and not by the tail of `main`, which a search never
  reaches.

## Side Effects

- **Reads** the corpus, the `.rgxrc` file (search order:
  `$RGX_CONFIG_PATH`, `./.rgxrc`, `~/.rgxrc`, `~/.config/rgx/rgxrc`),
  the git ignore files, and the bytes of every file it searches.
- **Writes** the token index (`<root>/.rgx-idx.ugi` by default), the
  facts index (`<root>/.rgx-facts.jsonl`, JSON Lines), a facts export
  file, cache entries under the cache directory (written to a
  temporary and renamed into place), and the pack store under
  `<target>/.rgx-tv` or `--tv-store`.
- **Deletes** cache entries on `--cache-clear` and `--cache-prune`.
- **Spawns** the picker process on `--pick` — the first of `fzf`,
  `sk`, `peco`, `fz` found on `PATH` — and, through the adapter
  crates, `soffice` and `tesseract`, but only when their binary is on
  `PATH` *and* a matching file was found.
- **Consumes stdin** in `--serve` and `--mcp` mode, one JSON document
  per line.
- **Writes stdout** with the matches (text or `--json` form) and
  **stderr** with the diagnostics, the warnings, the `--explain-engine`
  rationale and the engine tally — the tally only when `RGX_ENGINE=rgx`
  named the engine, and only when that run searched or refused a
  pattern.
- **Locks** the cache behind a `Mutex`/`Condvar` and hands work
  between walker threads through a crossbeam deque.

## Verification

- Run: `cargo test --release --locked --workspace`
