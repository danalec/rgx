// SPDX-License-Identifier: Apache-2.0

//! # LZ4 codec
//!
//! Independent reimplementation of the published LZ4 block and frame
//! formats, plus the deprecated legacy container `lz4 -l` emits. The
//! encoder and decoder surface was shaped from the API contract of
//! `lib/lz4.c` (`https://lz4.org`); the byte layout every function
//! reads and writes is the published specification. rgx only decodes,
//! so the encoder half (`Lz4Encoder`, `encode_block_graph` and the
//! graph-theoretic match finder it pulls in) is carried along unused.
//!
//! The frame walk reads a block's size from bits 0..30 of its header
//! (bit 31 marks a stored block) and terminates on the zero end mark,
//! not on a flag in the header. Dependent blocks decode into the
//! frame's running output so a match can resolve against the previous
//! block's bytes. The legacy container is a bare sequence of
//! length-prefixed blocks with no frame header and no block checksums,
//! so it shares only the block compressor with the frame reader; its
//! stream ends where the frame's does not, on a zero block size or on a
//! size past the ceiling, and not on an end mark. Dictionary-compressed
//! frames (`lz4 -D`) that match across the dictionary are still
//! rejected.
//!
//! The blanket allow below matches `sevenz`/`tar`: rgx never encodes,
//! so the encoder half and its match finder are carried along unused,
//! and silencing that per-item would be something a re-vendor had to
//! replay. `unreachable_patterns` is deliberately NOT allowed: a
//! shadowed match arm in a parser is a real defect, not vendoring
//! noise.
#![allow(
    dead_code,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_assignments,
    // `lz4::lz4` keeps the codec next to the match-finder and error
    // modules it is written alongside.
    clippy::module_inception
)]

pub mod error;
pub mod graph_optimize;
pub mod lz4;

pub use lz4::{Lz4Decoder, Lz4Encoder};
