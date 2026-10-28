// SPDX-License-Identifier: Apache-2.0

//! The byte searches, dispatched by this crate's own CPU probe.
//!
//! ## Why this module exists
//!
//! `rgx-core` is `#![no_std]` + `alloc`, and the upstream `memchr` crate
//! decides at *runtime* whether it may use AVX2 -- but it can only ask the
//! question through `std::is_x86_feature_detected!`, and that macro lives in
//! `std`. So the upstream crate answers "no" to every `no_std` build, and the
//! `no_std` configuration of this crate fell back to SSE2 on every byte
//! scan: the same search over the same bytes was 37% slower in the build
//! that is supposed to be the embedder's build.
//!
//! The upstream crate does publish the AVX2 searchers themselves --
//! `memchr::arch::x86_64::avx2::memchr::{One, Two, Three}` -- behind an
//! `unsafe` constructor whose contract is exactly the question this crate
//! already answers: *may this CPU run the AVX2 instructions?* The answer
//! comes from [`crate::detect`], which is written out by hand (CPUID and
//! XGETBV, no `std`) and cached.
//!
//! ## What this buys
//!
//! The two configurations now take the *same* path. There is no
//! `feature = "std"` anywhere in the dispatch: a build with `std` and a
//! build without it ask the same probe and reach the same kernel, so the
//! numbers the two builds produce are comparable. The upstream crate's own
//! dispatch is still what runs when this CPU has no AVX2 -- there it picks
//! SSE2, and on aarch64 it picks NEON, both of which are decisions the
//! upstream crate makes at compile time and that need no probe.
//!
//! ## What is re-exported
//!
//! Everything else the upstream crate offers is re-exported unchanged, so
//! every call site keeps the `rgx_core::memchr::*` path it has used since
//! the in-house module was deleted.
//!
//! The substring search is the one exception: [`memmem`] is this crate's
//! own, because the upstream crate's packed-pair kernel cannot be reached
//! without `std` -- see that module's own documentation for the whole of
//! it.
//!
//! `memmem::find_iter` yields the *start* of each match, and the matches
//! do not overlap. A caller that wants the overlapping ones has to step
//! one byte on, which is what `crate::regex`'s `sub_offsets` does.

pub use ::memchr::*;

pub mod memmem;

mod dispatch;

pub use dispatch::{
    memchr, memchr2, memchr2_iter, memchr3, memchr3_iter, memchr_iter, memrchr, memrchr2,
    memrchr2_iter, memrchr3, memrchr3_iter, memrchr_iter, Memchr, Memchr2, Memchr3,
};
