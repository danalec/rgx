// SPDX-License-Identifier: Apache-2.0

//! In-process 7z container support, vendored from the 7-Zip project
//! (`https://7-zip.org/sdk.html`,
//! `CPP/7zip/{Archive/7z,Compress}/*`)
//! with only mechanical adjustments: fixture paths, the `graph_optimize`
//! import narrowed to the `graph_mode` selection enum, and the `std` /
//! `isa-huffman` cfg feature names declared in this crate's Cargo.toml so
//! the copied `cfg(feature = ...)` attributes stay byte-identical to the
//! upstream sources. `isa-huffman` reaches [`isa_icf`], a wrapper over this
//! crate's own encoder rather than Intel ISA-L — real ISA-L is an Intel library
//! this crate does not depend on, and linking it would make every build here
//! non-portable.
//!
//! Decoder semantics are format-faithful: signature header CRC, raw and
//! encoded headers, bind-pair coder chains (Copy, LZMA1, LZMA2, Deflate,
//! BZip2, Delta, x86 BCJ), UTF-16 file table, sub-streams, and per-entry
//! CRC verification. AES/PPMd/BCJ2 report an honest `Unsupported`.

pub mod bwt;
pub mod bzip2;
pub mod crc32;
pub mod deflate;
pub mod error;
pub mod graph_mode;
pub mod huffman;
#[cfg(feature = "isa-huffman")]
pub mod isa_huffman;
#[cfg(feature = "isa-huffman")]
pub mod isa_icf;
pub mod lz77;
pub mod lzma;
// `sevenz::sevenz` mirrors the vendored upstream layout (scripts/vendored-sources.tsv).
#[allow(clippy::module_inception)]
pub mod sevenz;

#[cfg(test)]
pub(crate) use sevenz::take_folder_decodes;
pub use sevenz::{SevenzArchive, SevenzFile};
