# tv_runtime

## Overview
The `std`-bound half of the pack store: the filesystem surface of the format tables, the inspector, the builder, the searcher and the store itself. Everything in this module is gated on the `tv-runtime` feature so the `no_std` build of `rgx-core` does not link `std` for it.

The codec, query vocabulary and planner stay under `crate::tv` (the `tv` feature, `no_std` + `alloc`); this module is `std` + `alloc`. The CLI lives at `crates/rgx-core/src/bin/rgx-tv.rs` and uses this module's items through `rgx_core::tv_runtime::*`.

The division is by capability, not by convenience. The store's decisions — what a file is, which packs it lives in, how a pack is cut into claimable pieces — need no operating system; the answers that do need one — how many threads to start, where a pack file is, what time it is — are here.

## Interface
- `pub mod builder` — ingestion.
  - `pub struct BuildConfig` — `fingerprint() -> u64`.
  - `pub struct BuildStats`.
  - `pub fn walk_root(root: &Path, store: &Path, config: &BuildConfig) -> io::Result<Walk>`.
  - `pub type PreExtractor = dyn Fn(&str, &[u8]) -> Option<Vec<(String, Vec<u8>)>> + Send + Sync`.
  - `pub type UnitSigner = dyn Fn(&str, &[u8]) -> Vec<Vec<u8>> + Send + Sync`.
  - `pub const MEMBER_SEPARATORS: [char; 3]` — `['/', '#', '!']`.
  - `pub fn member_rel(rel_path: &str, member_name: &str) -> String`.
  - `pub fn build_store(...)`, `pub fn build_store_with_extractor(...)`, `pub fn build_or_update_store_with_extractor(...)`.
  - `pub enum StoreAction`.
- `pub mod compact` — `pub struct CompactStats` (`reclaimed()`, `waste_ratio()`), `pub fn compact_store(store_dir: &Path, min_waste: f64) -> io::Result<Option<CompactStats>>`, `pub fn compact_store_if_worth_it(store_dir: &Path) -> io::Result<Option<CompactStats>>`.
- `pub mod format` — the `std` shell over `crate::tv::format`: `pub fn now_secs() -> u64`, `load_manifest(store_dir)`, `load_raw_manifest(store_dir)`, `publish_atomic(manifest, store_dir)`, `read_pack_header(f: &mut File)`, `to_io(e: crate::Error) -> io::Error`.
- `pub mod inspect` — `pub struct StoreReport`, `pub fn inspect_store(store_dir: &Path) -> io::Result<StoreReport>`.
- `pub mod searcher` — the query engine.
  - `pub enum Engine` — `new(pattern: &str, mode: EngineMode) -> io::Result<Engine>`, `new_for_test(pattern)`, `new_for_test_mode(pattern, mode)`, `starts_inhouse() -> bool`.
  - `pub struct Crew` — `new(started, cap, inhouse_on)`, `maybe_pick_engine(...)`, `maybe_widen(...)`, `take_extra() -> Vec<JoinHandle<io::Result<WorkerOut>>>`.
  - `pub struct StageTimes`, `pub struct SearchStats`, `pub struct WorkerOut` (`empty()`).
  - `pub fn default_threads() -> usize`, `pub fn threads_for(logical: usize, per_core: Option<usize>) -> usize`, `pub fn smt_level(ecx: u32, ebx: u32) -> Option<usize>`.
  - `pub fn stale_files(store_dir: &Path) -> io::Result<(usize, usize)>`, `stale_in(&Manifest) -> (usize, usize)`, `stale_list_in(&Manifest) -> (usize, Vec<usize>)`.
  - `pub fn owner_rel(root: &Path, rel_path: &str) -> Option<String>`.
  - `pub fn search_store(...)`, `pub fn search_store_pooled(...)`.
- `pub mod store` — the warm mapping pool.
  - `pub const DEFAULT_MAX_MAPPED_BYTES: u64`.
  - `pub struct PoolLimits`, `pub struct ManifestKey`, `pub struct StoreSnapshot` (`touch()`, `cold_packs() -> Vec<u32>`), `pub struct PoolCounters`, `pub struct PoolStats`.
  - `pub struct MappedStore` — `open(dir: &Path, limits: PoolLimits)`, `limits()`, `dir()`, `enabled()`, `warm()`, `snapshot()`, `stats()`.
- `pub mod update` — `pub struct UpdateStats`, `pub fn update_store(...)`, `pub fn update_store_with(...)`.
- Re-exports at the module root: `build_or_update_store_with_extractor`, `build_store`, `build_store_with_extractor`, `member_rel`, `walk_root`, `BuildConfig`, `BuildStats`, `PreExtractor`, `StoreAction`, `UnitSigner`; `compact_store`, `compact_store_if_worth_it`, `CompactStats`; `load_manifest`, `load_raw_manifest`, `now_secs`, `publish_atomic`, `read_pack_header`, `FileLoc`, `FileRecord`, `Manifest`, `ManifestHead`, `PackHeader`, `PackRecord`, `RawManifest`, `DEFAULT_PACK_SIZE`, `FORMAT_VERSION`, `MANIFEST_MAGIC`, `MANIFEST_VERSION`, `PACK_MAGIC`; `inspect_store`, `StoreReport`; `default_threads`, `owner_rel`, `search_store`, `search_store_pooled`, `smt_level`, `stale_files`, `stale_in`, `stale_list_in`, `threads_for`, `Engine`, `SearchStats`, `StageTimes`; `MappedStore`, `PoolCounters`, `PoolLimits`, `PoolStats`, `StoreSnapshot`, `DEFAULT_MAX_MAPPED_BYTES`; `update_store`, `update_store_with`, `UpdateStats`; plus `EngineMode`, `ReadMode`, `SearchConfig`, `Unmap` re-exported from `crate::tv::query`.

## Invariants
- **File boundaries are strict.** For each file in the manifest the matcher is given exclusively its isolated slice, `&pack[offset .. offset + length]`. Zero matches can cross a file boundary, context lines cannot bleed into adjacent files, line numbers are 1-based and local to the individual file, and anchors (`^`, `$`, `\b`, `\A`, `\z`) match relative to the file's own boundaries.
- `publish_atomic` is write-and-rename: a reader sees the whole old catalog or the whole new one, never a mixture.
- Compaction's order is what makes it safe: write the new packs (unreferenced, so a crash there is inert), publish the manifest atomically so it names only the new packs, then delete the superseded pack files. A crash before the last step leaves orphan files that nothing references — the safe direction to fail in, since a dangling reference would break every query.
- `update_store` is append-only: a modified file gets a tombstone on its old record and a fresh record pointing into a new pack, and nothing ever removes a pack file. That is why compaction exists.
- An `update` has to reproduce the build's walk configuration exactly. The store's corpus fingerprint records it, and an update without the same flags is refused rather than allowed to delete the rest.
- `MappedStore` holds the parsed manifest, the filtered file indexes and the pack mappings alive across calls; a pooled search takes one read lock, bumps an LRU tick and never unmaps anything. The pool is for an embedder that queries one store many times in one process — for a single-shot query it is dead weight, which is why the CLI asks for it explicitly (`--pool`).
- The pool is bounded: `PoolLimits` caps the mapped bytes, and `DEFAULT_MAX_MAPPED_BYTES` is the default ceiling.
- `ReadMode::Mmap` maps every pack in the coordinator; `ReadMode::Buffered` reads every pack into RAM on the coordinator's own thread; `ReadMode::ParallelBuffered` has the coordinator read nothing and lets each worker read its own range.

## Side Effects
- Reads and writes the store directory: pack files (`*.tvp`), the manifest (`manifest.tvm`) and the temporary files the atomic publish writes and renames.
- Deletes superseded pack files during compaction.
- Spawns worker threads for the search; `Crew::take_extra` hands back their join handles.
- Maps pack files into memory through `crate::memmap2` and unmaps them when the pool drops — or deliberately not, under `Unmap::Leak`.
- Takes locks: the pool's read lock on the snapshot, and the mutexes that guard the pool's own bookkeeping. There is no file-level lock — nothing in the store takes one on the files, so the coordination is in-process only.
- Reads the wall clock (`now_secs`) and the filesystem's own metadata; `walk_root` uses the `ignore` crate, so it reads `.gitignore`, `.ignore` and the parents'.
- Leaves behind: a new manifest generation and the pack files the generation names; compaction leaves orphan pack files when it is interrupted before its delete step.

## Verification
- Run: `cargo test --release --locked --workspace`
