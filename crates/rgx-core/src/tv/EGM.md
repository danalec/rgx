# tv

## Overview
The Tesla Valve pack store, as a format and a plan. `rgx-tv` is the binary target of `rgx-core`; the half that owns the filesystem, the threads and the wall clock is the `rgx_core::tv_runtime` module behind the `tv-runtime` feature. This module is the part of it that owns the *decisions* — the on-disk codec, the query vocabulary, and the planner that turns a manifest into claimable units. Everything here is `no_std` + `alloc`, behind the `tv` feature, because a decision does not need a filesystem and a plan does not need a thread.

The split is not cosmetic. The two halves live in the same crate under different features — `tv` for the decisions and `tv-runtime` for the filesystem — so a build that wants the format alone never links the thread pool with it. And the format being here is what makes the on-disk layout a property of the store rather than of whichever process happens to be reading it this time.

The codec is bytes in and bytes out: `PackHeader::decode` takes the 32 bytes at the front of a pack, `Manifest::encode` produces a whole manifest, `RawManifest::from_bytes` takes one back. Opening, publishing and the wall clock belong to `crate::tv_runtime`, which is `std` and owns the filesystem. The reader/writer split is the reason `RawManifest` exists: reading the catalog whole and decoding it later is what lets pack reads start while the coordinator is still turning file records into a plan.

## Interface
- `pub mod format` — the on-disk codec.
  - `pub const PACK_MAGIC: &[u8; 8]`, `MANIFEST_MAGIC: &[u8; 8]`, `FORMAT_VERSION: u32`, `MANIFEST_VERSION: u32`, `DEFAULT_PACK_SIZE: u64`.
  - `pub struct PackHeader` — `SIZE: usize = 32`, `new(pack_id, file_count, content_len, content_crc32)`, `extend(&self, buf: &mut Vec<u8>)`, `decode(b: &[u8]) -> Result<Self>`.
  - `pub struct PackRecord`, `pub struct FileLoc` (with `FLAG_EMPTY`, `FLAG_DELETED`, `FLAG_BINARY`, `SIG_COVERS_ADAPTER`, `is_empty()`, `is_deleted()`, `is_binary()`, `sig_covers_adapter()`), `pub struct FileRecord`.
  - `pub struct RawManifest` — `from_bytes(bytes: Vec<u8>) -> Result<Self>`, `head() -> Result<ManifestHead>`, `scan() -> Result<(ManifestHead, Vec<FileLoc>)>`, `path_of(&self, loc: &FileLoc) -> Result<String>`, `verify(&self) -> Result<()>`, `decode(&self) -> Result<Manifest>`.
  - `pub struct ManifestHead`, `pub struct Manifest` — `new_at(root_path, generation, timestamp_secs)`, `with_corpus_at(...)`, `encode(&self) -> Vec<u8>`.
- `pub mod plan` — the planner; reads no byte.
  - `pub struct PackPlan` — `build(...)`.
  - `pub struct Unit`, `pub const UNIT_BYTES: u32 = 1 << 20`, `pub const MAX_EXTENT_GAP: u32 = 64 * 1024`.
  - `pub fn merge_buckets<K: Ord>(...)`, `split_owned(...)`, `kept(&FileRecord, &SearchConfig) -> bool`, `kept_loc(&FileLoc, &SearchConfig) -> bool`, `kept_flags(is_deleted, is_binary, length, &SearchConfig) -> bool`, `narrow(&[u32], &Manifest, &SearchConfig) -> Vec<u32>`, `split_locs(&[FileLoc], &SearchConfig) -> (Vec<u32>, Vec<u32>)`, `prune_by_ngram(...)`, `cut_units(&[u32], &[u32], &[FileLoc]) -> Vec<Unit>`.
- `pub mod query` — the vocabulary of one query.
  - `pub enum EngineMode` — `pick(_pattern: &str) -> EngineMode`.
  - `pub enum ReadMode`, `pub enum Unmap { Explicit, Leak }`.
  - `pub fn line_anchored(pattern: &str) -> bool`.
  - `pub struct SearchConfig`, `pub struct SearchMatch`.
- Re-exports at the module root: `FileLoc`, `FileRecord`, `Manifest`, `ManifestHead`, `PackHeader`, `PackRecord`, `RawManifest`, `DEFAULT_PACK_SIZE`, `FORMAT_VERSION`, `MANIFEST_MAGIC`, `MANIFEST_VERSION`, `PACK_MAGIC`; `cut_units`, `kept`, `kept_flags`, `kept_loc`, `merge_buckets`, `narrow`, `split_locs`, `split_owned`, `PackPlan`, `Unit`, `UNIT_BYTES`; `EngineMode`, `ReadMode`, `SearchConfig`, `SearchMatch`, `Unmap`.

## Invariants
- The planner reads no byte: it turns a decoded manifest and a `SearchConfig` into a table of units that workers claim.
- `kept_flags` is the single place a file can be dropped, so a decoded record and a locator cannot disagree about whether it is searched.
- `cut_units` enforces the boundary invariant the pack design states: a unit never spans a file boundary.
- Every mode keys its result buckets by the claim itself and concatenates them in that order, so two runs of the same query on the same store print the same bytes in the same order.
- `PackHeader` is exactly 32 bytes at the front of a pack; the payload's integrity is a CRC32 over the pack's content.
- A pack's magic, the manifest's magic, `FORMAT_VERSION` and `MANIFEST_VERSION` are part of the format: a reader that does not recognise them refuses the file rather than guessing.
- `Unmap::Leak` is for one-shot CLIs only: it never drops the mappings, so every query leaks a full set of them until the process exits.
- The format is `no_std` + `alloc`: nothing here opens a file, reads a clock or starts a thread.

## Side Effects
- None. Every item here is a pure function over byte slices, decoded records and configurations; the crate allocates its own buffers and drops them on return.
- No file, socket, clock, lock or process is touched. The filesystem half of the store lives in `crate::tv_runtime`.

## Verification
- Run: `cargo test --release --locked --workspace`
