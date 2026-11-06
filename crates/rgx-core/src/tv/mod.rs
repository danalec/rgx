// SPDX-License-Identifier: Apache-2.0

//! The Tesla Valve pack store, as a format and a plan.
//!
//! `rgx-tv` is the `std` half of this crate — the binary that owns the
//! filesystem, the threads and the wall clock; this module is the part behind
//! it that owns the *decisions* — the on-disk codec, the query vocabulary,
//! and the planner that turns a manifest into claimable units. Everything
//! here is `no_std` + `alloc`, behind the `tv` feature, because a decision
//! does not need a filesystem and a plan does not need a thread.
//!
//! The split is not cosmetic. The decision half is in `rgx-core`, so `rgx`
//! links it without taking the thread pool with it, and `rgx-tv` is a
//! separate binary that drives it. And the format being here is what makes
//! the on-disk layout a property of the store rather than a property of
//! whichever process happens to be reading it this time.

pub mod format;
pub mod plan;
pub mod query;

pub use format::{
    FileLoc, FileRecord, Manifest, ManifestHead, PackHeader, PackRecord, RawManifest,
    DEFAULT_PACK_SIZE, FORMAT_VERSION, MANIFEST_MAGIC, MANIFEST_VERSION, PACK_MAGIC,
};
pub use plan::{
    cut_units, kept, kept_flags, kept_loc, merge_buckets, narrow, split_locs, split_owned,
    PackPlan, Unit, UNIT_BYTES,
};
pub use query::{EngineMode, ReadMode, SearchConfig, SearchMatch, Unmap};
