// SPDX-License-Identifier: Apache-2.0

//! In-house compression codecs.
//!
//! **Provenance.** The codec modules here are independent reimplementations
//! of the published formats, written from those specifications rather than
//! translated from any implementation's source:
//!
//! - `crc32` / `xz::crc64` — the IEEE 802.3 / FIPS CRC-32 and the XZ
//!   CRC-64, both specified by their polynomial and bit-at-a-time
//!   recurrence.
//! - `lz77`, `huffman`, `deflate` — RFC 1951 (DEFLATE), with RFC 1950
//!   (zlib) and RFC 1952 (gzip) framing in `zlib` and `gzip`.
//! - `bwt`, `bzip2` — the bzip2 algorithm: RLE, Burrows-Wheeler,
//!   move-to-front, Huffman, and the block framing the format defines.
//! - `lzma` — the LZMA algorithm as published in the LZMA specification
//!   (range coding, Markov probability models, the literal/match state
//!   machine), plus the LZMA2 chunk framing.
//! - `xz` — the XZ container format specification (stream header, blocks,
//!   index, footer, check types) over the LZMA2 decoder.
//! - `zstd` — RFC 8878, decoding only.
//! - `snappy` — Google's Snappy format, decoding only: the preamble and the
//!   literal/copy element stream. It is here because LevelDB and RocksDB
//!   compress their blocks with it, and without it their `.ldb`/`.sst` files
//!   are compressed noise to a search tool.
//! - `lz4` — the LZ4 block format, decoding only. The `.lz4` file wrapper is
//!   not read *here*; the archive crate's own decoder reads it, and it
//!   replaced `lz4_flex` for the search path.
//! - `blosc` — the frame of c-blosc, decoding only: the header, the table of
//!   block offsets, the blocks and the byte shuffle. It is here because the
//!   chunks zarr-python writes by default are blosc frames.
//!
//! `error` and `cap` are rgx's own: the error vocabulary the decoders fail
//! with, and the ceiling on how many bytes one decode may emit. The cap is
//! a bomb guard, counted as bytes are emitted — decoding first and
//! measuring afterwards costs exactly what a compression bomb was built to
//! cost.
//!
//! The `.lz4` file wrapper is not read here: this module reads the block
//! format, because the blosc frame is made of blocks. The frame itself is
//! read by the archive crate's own decoder, which replaced `lz4_flex` for
//! the search path; `lz4_flex` stays in the tree for the extraction cache
//! alone.

#[cfg(feature = "blosc")]
pub mod blosc;
#[cfg(feature = "bwt")]
pub mod bwt;
#[cfg(feature = "bzip2")]
pub mod bzip2;
pub mod cap;
pub mod crc32;
#[cfg(feature = "deflate")]
pub mod deflate;
pub mod error;
#[cfg(feature = "gzip")]
pub mod gzip;
#[cfg(feature = "huffman")]
pub mod huffman;
#[cfg(feature = "lz4")]
pub mod lz4;
#[cfg(feature = "lz77")]
pub mod lz77;
#[cfg(feature = "lzma")]
pub mod lzma;
#[cfg(feature = "snappy")]
pub mod snappy;
#[cfg(feature = "xz")]
pub mod xz;
#[cfg(feature = "zlib")]
pub mod zlib;
#[cfg(feature = "zstd")]
pub mod zstd;

#[cfg(feature = "blosc")]
pub use blosc::{BloscDecoder, Codec as BloscCodec};
#[cfg(feature = "bzip2")]
pub use bzip2::Bzip2Decoder;
pub use cap::{Bounded, OutputCap, UNLIMITED};
#[cfg(feature = "deflate")]
pub use deflate::DeflateDecoder;
#[cfg(feature = "gzip")]
pub use gzip::{GzipError, GzipReader, GzipResult, GzipWriter};
#[cfg(feature = "lz4")]
pub use lz4::Lz4Decoder;
#[cfg(feature = "snappy")]
pub use snappy::SnappyDecoder;
#[cfg(feature = "xz")]
pub use xz::XzReader;
#[cfg(feature = "zlib")]
pub use zlib::{ZlibDecoder, ZlibEncoder};
#[cfg(feature = "zstd")]
pub use zstd::ZstdDecoder;
