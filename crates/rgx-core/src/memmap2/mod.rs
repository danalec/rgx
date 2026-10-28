// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of `memmap2-rs` upstream commit f16835d (v0.9.0).
//! Written from the upstream source to understand the public API; no verbatim copies.
//!
//! Upstream: `RazrFalcon/memmap2-rs`, Copyright 2015 Dan Burkert and
//! 2020 Yevhenii Reizner. Upstream's work is used here under Apache-2.0, the
//! option it offered, and no upstream source file is in this tree. The
//! provenance is recorded in `NOTICE` and in `scripts/vendored-sources.tsv`.

#![allow(clippy::all)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::len_without_is_empty)]
#![allow(dead_code)]
#![allow(unexpected_cfgs)]

mod advice;
mod error;
mod mmap;
mod mmap_mut;
mod options;
mod platform;

#[cfg(unix)]
pub use self::advice::{Advice, UncheckedAdvice};
pub use self::mmap::Mmap;
pub use self::mmap_mut::MmapMut;
pub use self::options::MmapOptions;
pub use self::platform::{MmapAsRawDesc, MmapRawDescriptor};
