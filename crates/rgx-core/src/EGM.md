# src

## Overview
The crate root of `rgx-core`: the adapter contract, the extraction pipeline, and the engines the adapters and the CLI are written against. The crate is `#![no_std]` + `alloc`; the `std` feature gates what genuinely needs it — the typed error chain, the profiler map, the `f64` JSON parser and the memory-mapping module — while the pack store's format half (`tv`), the ZIP reader (`zip`) and the pack store's filesystem half (`tv-runtime`, which turns `std` on as its own dependency) are features of their own.

The design decisions the whole tree rests on are stated here and repeated where they are enforced. Adapters are **sync and work on byte slices**: no async, no streams, no subprocess in the core model; the external tools live in `rgx-adapters-docs` and spawn only when their binary is on `PATH` *and* a matching file is found. Adapters never recurse themselves: archives return `Outcome::Members` and the pipeline recurses uniformly, so depth limits, member caps and bail semantics live in one place. `Outcome::Bail` mirrors rga's bail-out semantics: the file falls back to the next adapter and finally to raw-text search, and an adapter declining a file is never an error.

`process` is where the pipeline lives, and its contract is strict: every outcome puts the file's own bytes somewhere the searcher will read them; a hard failure renders a searchable `[rgx: adapter 'x' failed: …]` note **beside** the file's own bytes, never as a replacement, and a claimant whose external tool is not on `PATH` gets a `[rgx: adapter 'x' skipped: its external tool is not on PATH]` note beside them too; and `process` returns `true` only when the sole unit it appended is the file's own bytes — a note is a record like any other, so the return is `false` and the caller searches the units.

The member separator is `!`: a member's path is `<the container's path>!<the member's name>`, and it is logical rather than a path on disk, because a member's own name can hold a `/` (`docs/report.pdf`). `basename_of` cuts at the `!` too, and `extension_of` reads through it, which is what lets the **member's** extension decide the adapter.

The modules here fall into three groups: the pipeline and its contract (`lib.rs`, `error.rs`, `filter.rs`, `filetype.rs`, `facts_index.rs`, `encoding.rs`, `charset.rs`, `detect.rs`, `walk_policy.rs`); the search engines (`regex.rs`, `searcher.rs`, `scan.rs`, `nfa.rs`, `vm.rs`, `matcher.rs`, `fixed.rs`, `literal.rs`, `ngram.rs`, `prefilter.rs`, `required.rs`, `rulebank.rs`, `byteclass.rs`, `unicode_case.rs`, `casefold_table.rs`, `numparse.rs`, `syntax.rs`, `tokenize.rs`, `maskstats.rs`, `frequency.rs`, `hybrid.rs`, `fuzzy.rs`); and the format subsystems (the compression codecs, the JSON suite, the cryptographic primitives, the memory-mapping module, the pack store, the ZIP reader, the compound-file reader, the PNG writer and the Base64 codec). Four more stand beside them: the SHA-256 implementation and its hardware path (`sha256.rs`, `sha256_hw.rs`), the token index (`index.rs`, `index_io.rs`), the MCP server (`mcp.rs`) and the deterministic structural fuzzer (`fuzzkit.rs`).

## Interface
- The adapter contract:
  - `pub trait Adapter: Send + Sync` — `name()`, `extensions()`, `available()`, `reach()`, `reach_needs_bytes()`, `reach_for(data)`, `magic()`, `facts(data, path)`, `extract(data, path) -> Result<Outcome>`.
  - `pub enum Outcome { Text(Vec<u8>), Members(Vec<(String, Vec<u8>)>), Bail(String) }`.
  - `pub struct Ctx` — `max_depth`, `max_members`, `max_file_size`, `filter`, `facts_sink`; `passes(&[Field])`, `wants_filter()`, `wants_facts()`.
  - `pub trait FactsSink: Send + Sync` — `record(&self, path: &str, facts: Vec<Field>)`.
  - `pub struct Found` — `path`, `bytes`, `via`.
- The registry:
  - `pub struct Registry` — `new(adapters)`, `with_extra_claims(adapters, extra_claims)`, `chain()`, `candidates(ext)`, `may_claim(ext)`, `unavailable_claimants(ext)`, `candidates_for_path(path)`, `candidates_for_path_bytes(path, head)`, `has_magic_claimants()`, `claims_magic(head)`, `may_claim_for_path(path)`, `unavailable_claimants_for_path(path)`.
  - `pub struct PathCandidates<'a>` — the iterator over the candidates for one path.
  - `pub fn extension_candidates(path: &str) -> ExtensionCandidates<'_>`, `pub struct ExtensionCandidates<'a>`, `pub fn extension_of(path: &str) -> Cow<'_, str>`.
- The policy and the ablations:
  - `pub enum Reach { Reveal, Render }`, `pub enum Policy { Source, Render, Both }`, `pub const POLICY_ENV: &str = "RGX_ADAPTER_VIEW"`, `pub fn policy() -> Policy`, `pub fn set_policy(p: Policy)`.
  - `pub fn ablate_mask() -> bool`, `set_ablate_mask(on)`, `ablate_ngram() -> bool`, `ablate_extents() -> bool`, `set_ablate_extents(on)`.
- The pipeline:
  - `pub fn process(reg: &Registry, path: &str, data: &[u8], depth: usize, ctx: &Ctx, out: &mut Vec<Found>) -> bool`.
  - `pub fn normalize_encoding(bytes: Vec<u8>) -> Vec<u8>`.
  - `pub fn current_depth() -> usize`; `pub struct DepthGuard` — `enter(depth)` — the guard is `std`-gated, so it exists only in the `std` configuration.
- The crate's own support:
  - `pub use error::{Context, Error, Result}`, `pub use filter::Field`.
  - `pub trait NoStdFloat` — `parse(s: &str) -> Result<Self, ()>`; `pub fn parse_decimal(s: &str) -> Result<f64, ()>`.
  - `pub fn profile_enabled() -> bool`, `profile_init()` — the flag is a core atomic and survives without `std`; `profile_add(name, ns)`, `profile_dump() -> Vec<(&'static str, u64, u64)>` — the map's two ends are `std`-gated.
  - `pub use alloc::format` — `#[doc(hidden)]`, so a `no_std` caller can use the `anyhow!`-style macros.
- Children:
  - `bin`: [bin](./bin/EGM.md) — the `rgx-tv` command-line program. A binary crate: it exports no public symbol, and `main`, `parse_size` and `print_usage` are private functions of it.
  - `compress`: [compress](./compress/EGM.md) — the in-house compression codecs. Public symbols: `OutputCap`, `Bounded`, `UNLIMITED`, `CompressError`, `CompressResult`, `crc32`, `crc32_update`, `Crc32Calculator`, `Lz77Encoder`, `Lz77Decoder`, `Lz77Token`, `Match`, `HuffmanNode`, `HuffmanDecoder`, `BitReader`, `BitWriter`, `build_huffman_tree`, `build_canonical_codes`, `package_merge_lengths`, `DeflateEncoder`, `DeflateDecoder`, `ZlibEncoder`, `ZlibDecoder`, `GzipReader`, `GzipWriter`, `GzipHeader`, `GzipMember`, `GzipError`, `Bwt`, `MtfEncoder`, `Rle`, `Bzip2Encoder`, `Bzip2Decoder`, `LzmaDecoder`, `LzmaProps`, `LzmaLevel`, `ZstdDecoder`, `SnappyDecoder`, `Lz4Decoder`, `BloscDecoder`, `BloscCodec`, `Codec`.
  - `crypt`: [crypt](./crypt/EGM.md) — the cryptographic primitives the PDF handler needs. Public symbols: `Md5`, `hash`, `rc4`, `rc4_in_place`, `Aes`, `AesError`, `cbc_encrypt_padded`, `cbc_encrypt_nopad`, `cbc_decrypt_padded`, `cbc_decrypt_nopad`, `Sha384`, `Sha512`, `hash384`, `hash512`.
  - `djson`: [djson](./djson/EGM.md) — the JSON value, parser, serializer and streaming layer. Public symbols: `parse`, `to_string`, `to_string_pretty`, `Arena`, `Value`, `Number`, `RawValue`, `JsonError`, `ErrorCategory`, `JsonResult`, `StreamParser`, `NdJsonIter`, `ndjson`, `from_reader`, `escape_json_string`, `write_escaped`.
  - `memchr`: [memchr](./memchr/EGM.md) — the byte searches, dispatched by the crate's own CPU probe. Public symbols: `memchr`, `memrchr`, `memchr2`, `memrchr2`, `memchr3`, `memrchr3`, `memchr_iter`, `memrchr_iter`, `memchr2_iter`, `memrchr2_iter`, `memchr3_iter`, `memrchr3_iter`, `Memchr`, `Memchr2`, `Memchr3`, `memmem::find`, `memmem::rfind`, `memmem::find_iter`, `memmem::rfind_iter`, `memmem::Finder`, `memmem::FinderRev`, `memmem::FinderBuilder`, `memmem::Matcher`, `memmem::FindIter`, `memmem::FindRevIter`.
  - `memmap2`: [memmap2](./memmap2/EGM.md) — the memory-mapping module. Public symbols: `Mmap`, `MmapMut`, `MmapOptions`, `Advice`, `UncheckedAdvice`, `MmapAsRawDesc`, `MmapRawDescriptor`.
  - `regex`: [regex](./regex/EGM.md) — the byte-mode regex engine's differential suite. Public symbols: the `fast` and `text` helpers and the ranged-anchor, plan, syntax and replacement tests.
  - `searcher`: [searcher](./searcher/EGM.md) — the searcher's line-contract suite and its differential oracle. Public symbols: the `Recorded`, `Typed` and `LineNumbers` sinks, the `cfg_line_numbers`, `split_lines`, `oracle_lines`, `rgx_lines`, `rgx_lines_reader`, `oracle_accepts`, `compare` and the multi-line differential helpers.
  - `tv`: [tv](./tv/EGM.md) — the pack store's format and plan. Public symbols: `PackHeader`, `PackRecord`, `FileLoc`, `FileRecord`, `Manifest`, `ManifestHead`, `RawManifest`, `PACK_MAGIC`, `MANIFEST_MAGIC`, `FORMAT_VERSION`, `MANIFEST_VERSION`, `DEFAULT_PACK_SIZE`, `PackPlan`, `Unit`, `UNIT_BYTES`, `MAX_EXTENT_GAP`, `cut_units`, `kept`, `kept_loc`, `kept_flags`, `narrow`, `split_locs`, `split_owned`, `merge_buckets`, `prune_by_ngram`, `EngineMode`, `ReadMode`, `Unmap`, `SearchConfig`, `SearchMatch`, `line_anchored`.
  - `tv_runtime`: [tv_runtime](./tv_runtime/EGM.md) — the pack store's filesystem half. Public symbols: `BuildConfig`, `BuildStats`, `PreExtractor`, `UnitSigner`, `StoreAction`, `build_store`, `build_store_with_extractor`, `build_or_update_store_with_extractor`, `walk_root`, `member_rel`, `MEMBER_SEPARATORS`, `compact_store`, `compact_store_if_worth_it`, `CompactStats`, `inspect_store`, `StoreReport`, `load_manifest`, `load_raw_manifest`, `publish_atomic`, `read_pack_header`, `now_secs`, `to_io`, `Engine`, `Crew`, `StageTimes`, `SearchStats`, `WorkerOut`, `default_threads`, `threads_for`, `smt_level`, `stale_files`, `stale_in`, `stale_list_in`, `owner_rel`, `search_store`, `search_store_pooled`, `MappedStore`, `PoolLimits`, `PoolStats`, `PoolCounters`, `StoreSnapshot`, `ManifestKey`, `DEFAULT_MAX_MAPPED_BYTES`, `update_store`, `update_store_with`, `UpdateStats`.

## Invariants
- **A decline is not a failure.** `Outcome::Bail` and `Err` are not interchangeable. `Err` holds its note and continues the chain; a decline is silent and also continues. Neither arm may stop the chain — that is what let the media crate's single-page TIFF reader refuse a two-page file "so the chain walker could answer it" and thereby shadow the very reader it was deferring to.
- **A note never replaces the file's bytes.** A hard failure renders a searchable `[rgx: adapter 'x' failed: …]` note beside the file's own bytes, and a note filed under `raw` would report "no adapter ran" about a file an adapter did run on and fail on.
- **The single unit is the whole rule.** `process` returns `true` only when the sole unit it appended is the file's own bytes; an adapter that reported a failure, or one whose external tool is not on `PATH`, produced a record, so the return is `false` and the caller searches the units.
- `Outcome::Members` is recursed by the pipeline, not by the adapter; the depth limit, the member cap and the bail semantics live in `process` alone.
- The `!` member separator is honoured by `basename_of`, and `extension_of` reads through it, so the **member's** extension decides the adapter — reading the container's extension would route every member of a zip back to the zip reader and the recursion would never reach the file inside.
- A repeated extension inside one adapter's own list is collapsed by `Registry::new`, because the index pushes that adapter once per literal and the duplicate made an expensive adapter run twice over the whole file.
- Extension resolution is most-specific-first: `a.b.c.jpg` is offered as `b.c.jpg`, `c.jpg`, `jpg`, so a dotted claim runs before the plain one and a bail still falls through to it.
- A magic-prefix claim is a candidate only when no adapter claimed the file by name, and only when the bytes in hand start with the prefix — a magic is a claim about content and cannot outrank a claim about the name.
- `Policy::Source` is the default and the only policy under which rgx stays a superset of ripgrep on a `Reach::Render` format; under it a `Render` adapter does not get the file at all unless it says `reach_needs_bytes()`.
- The filter is the last word on the file: a file it rejects is not in the corpus, and neither is a note about it.
- The facts sink is not part of the cache key: the sink decides where the facts are *written*, not what the extraction *is*.
- The crate is `no_std` + `alloc`; `std` is linked for the test harness only, and the library's own code cannot use it in that configuration.

## Side Effects
- `process` mutates the caller's `out: &mut Vec<Found>` — it appends the searchable units it produced, and it is the only place the pipeline writes anything.
- The pipeline reads process-global switches: `policy()` reads `RGX_ADAPTER_VIEW` once and caches it; `ablate_mask()`, `ablate_ngram()` and `ablate_extents()` read their environment variables and their process-global overrides.
- `profile_init`, `profile_add` and `profile_dump` mutate a process-global profiler map when the `std` feature is on; the profiler's flag is a core atomic and survives without `std`.
- `DepthGuard::enter` publishes the current nesting depth in a thread-local so the adapters below — which have no depth parameter — can build their work budget; dropping the guard restores it.
- `FactsSink::record` is called through a shared `Arc<dyn FactsSink>`, so the implementor owns the interior mutability (a `Mutex` around a `Vec` is the obvious one) and the pipeline's threads write into it.
- No subprocess, no async and no streaming in the core model; the only external tools are in `rgx-adapters-docs`, and they spawn only when their binary is on `PATH` and a matching file is found.

## Verification
- Run: `cargo test --release --locked --workspace`
