// SPDX-License-Identifier: Apache-2.0

//! The `std`-bound half of the pack store: the filesystem surface of the
//! format tables, the inspector, the builder, the searcher and the store
//! itself. Everything in this module is gated on the `tv-runtime` feature
//! so the `no_std` build of `rgx-core` does not link `std` for it.
//!
//! The codec, query vocabulary and planner stay under [`super::tv`] (the
//! `tv` feature). They are `no_std + alloc`; this module is `std` +
//! `alloc`. The CLI lives at `crates/rgx-core/src/bin/rgx-tv.rs` and uses
//! this module's items through `rgx_core::tv_runtime::*`.

pub mod builder;
pub mod compact;
pub mod format;
pub mod inspect;
pub mod searcher;
pub mod store;
pub mod update;

pub use builder::{
    build_or_update_store_with_extractor, build_store, build_store_with_extractor, member_rel,
    walk_root, BuildConfig, BuildStats, PreExtractor, StoreAction, UnitSigner,
};
pub use compact::{compact_store, compact_store_if_worth_it, CompactStats};
pub use format::{
    load_manifest, load_raw_manifest, now_secs, publish_atomic, read_pack_header, FileLoc,
    FileRecord, Manifest, ManifestHead, PackHeader, PackRecord, RawManifest, DEFAULT_PACK_SIZE,
    FORMAT_VERSION, MANIFEST_MAGIC, MANIFEST_VERSION, PACK_MAGIC,
};
pub use inspect::{inspect_store, StoreReport};
pub use searcher::{
    default_threads, owner_rel, search_store, search_store_pooled, smt_level, stale_files,
    stale_in, stale_list_in, threads_for, Engine, SearchStats, StageTimes,
};
pub use store::{
    MappedStore, PoolCounters, PoolLimits, PoolStats, StoreSnapshot, DEFAULT_MAX_MAPPED_BYTES,
};
pub use update::{update_store, update_store_with, UpdateStats};
// The query vocabulary (`EngineMode`, `ReadMode`, `SearchConfig`, `Unmap`)
// lives under `crate::tv::query` (the `tv` feature, no_std + alloc).
// Re-export it here so callers of the runtime see one module.
pub use crate::tv::query::{EngineMode, ReadMode, SearchConfig, Unmap};
// `store` is not re-exported at the module root on purpose: a future
// build that does not want a thread pool should be able to take the
// inspector without taking `MappedStore`'s worker types. Re-export
// happens at the `rgx-tv` crate root, where the whole runtime is
// imported together.
