// SPDX-License-Identifier: Apache-2.0

//! rar-codec: pure-Rust RAR container codec.
//!
//! # Provenance
//!
//! This crate was originally a `rustfmt`-ed port of libarchive's RAR support
//! (`archive_read_support_format_rar{5,}.c`, BSD-2-Clause), and every module
//! has since been rewritten as an independent reimplementation in this
//! repository's sense (`AGENTS.md` §11): the API contract and the algorithm
//! are learned from the upstream source, from RARLAB's published RAR 5.0
//! archive format specification (`https://www.rarlab.com/technote.htm`), and
//! — for the decompression algorithms the technote does not cover — from
//! understanding of the algorithm itself. Then the code is written fresh: no
//! file-level copies, no verbatim pastes.
//!
//! **Modules rewritten** (Apache-2.0, SPDX headers; per-module rows in
//! `scripts/vendored-sources.tsv`): `error`, `vint`, `crc32`, `bitreader`,
//! `huffman`, `read`, `write`, `unpack`, `unpack3`, `ppmd7`. `crc32` keeps
//! the byte-at-a-time definition in-file as the oracle its slice-by-8 fold
//! is tested against. `huffman` caps its primary table at 12 bits with an
//! overflow list for long codes and one peek per symbol, and treats an
//! all-zero length array as a legal empty table (RAR 5.0 sends unused
//! sub-tables that way). `unpack3` and `ppmd7` are the decompression half
//! RARLAB's spec does not cover: rewritten from algorithm understanding and
//! verified end-to-end against goldens extracted by the genuine UnRAR —
//! RAR4 store/normal/best members and PPMd var-H members decode
//! byte-identical. No public algorithm specification exists for that half;
//! LOC PRONOM fmt/411 records the format's transparency as low.
//!
//! **Verification**: `tests/winrar_oracle.rs` compares extraction against
//! SHA-256 goldens produced by genuine `Rar.exe`/`UnRAR.exe` (gated on
//! `RGX_WINRAR_ORACLE` / `RGX_WINRAR_ORACLE_RAR4` / `RGX_UNRAR`; the two
//! matrices cover RAR5 and RAR4 methods, PPMd, solid groups, path
//! encodings, encryption refusal and edge-case sizes) plus a reverse check
//! that genuine UnRAR reads what [`ArchiveBuilder`] writes. The integration
//! tests in `tests/` are the behavioral oracle, written for this crate
//! against the fixtures in `testdata/`; no upstream file remains in the
//! tree, and the BSD 2-Clause terms the original port inherited are kept on
//! the record in the repository's `NOTICE`.
//!
//! Zero dependencies, `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`.
//!
//! ## Decode
//!
//! Walks the full header structure of RAR4 and RAR5 archives. Extraction
//! supports stored entries, the RAR5 LZ77/Huffman method (version 0,
//! including solid archives and the delta, E8/E8E9 and ARM filters), and
//! the RAR4 LZ77/Huffman method (0x31..=0x35, including solid archives,
//! the standard E8/E8E9, delta, RGB and audio VM filters, and PPMd var-H
//! blocks inside the packed stream), all with CRC-32 verification. RAR5
//! multivolume archives reassemble across volumes via
//! [`Archive::open_multi`]. Encrypted payloads, PPMd filters, arbitrary
//! RAR VM program filters and the RAR 7.x compression algorithm
//! (version 1) are not implemented: the version is read and stored,
//! never consulted, and such a member is handed to the RAR5 decoder.
//!
//! ## Encode
//!
//! Writes valid RAR5 archives using the store method. The RAR5 container
//! layout is publicly documented by RARLAB; writing store-only archives
//! needs no proprietary algorithm.
//!
//! ```
//! use rar_codec::ArchiveBuilder;
//!
//! let mut w = ArchiveBuilder::new();
//! w.add_stored("hello.txt", b"hi there").unwrap();
//! let bytes = w.finish();
//!
//! let arc = rar_codec::Archive::open(&bytes).unwrap();
//! assert_eq!(arc.entries().len(), 1);
//! assert_eq!(arc.entries()[0].name, "hello.txt");
//! assert_eq!(arc.extract(&arc.entries()[0]).unwrap(), b"hi there");
//! ```

#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "std"))]
extern crate std;

extern crate alloc;

mod bitreader;
mod crc32;
mod error;
mod huffman;
mod ppmd7;
mod read;
mod unpack;
mod unpack3;
pub mod vint;
mod write;

pub use crc32::{crc32, update};
pub use error::{Error, Result};
pub use read::{Archive, Entry, EntryKind, Format, METHOD_STORE};
pub use write::ArchiveBuilder;
