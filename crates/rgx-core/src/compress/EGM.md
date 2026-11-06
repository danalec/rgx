# compress

## Overview
The in-house compression codecs. Every module here is an independent reimplementation of a published format, written from that specification rather than translated from any implementation's source: `crc32` and `xz::crc64` are the IEEE 802.3 / FIPS CRC-32 and the XZ CRC-64, both specified by polynomial and bit-at-a-time recurrence and both evaluated through a 256-entry table that folds eight bytes per step; `lz77`, `huffman` and `deflate` are RFC 1951 (DEFLATE), with RFC 1950 (zlib) and RFC 1952 (gzip) framing in `zlib` and `gzip`; `bwt` and `bzip2` are the bzip2 algorithm (RLE, Burrows-Wheeler, move-to-front, Huffman, block framing); `lzma` is the LZMA algorithm as published in the LZMA specification plus the LZMA2 chunk framing; `xz` is the XZ container over the LZMA2 decoder; `zstd` is RFC 8878, decoding only; `snappy` is Google's Snappy format, decoding only; `lz4` is the LZ4 block format, decoding only; `blosc` is the c-blosc frame, decoding only.

`error` and `cap` are rgx's own: the error vocabulary the decoders fail with, and the ceiling on how many bytes one decode may emit. The cap is a bomb guard, counted as bytes are emitted — decoding first and measuring afterwards costs exactly what a compression bomb was built to cost.

The `.lz4` file wrapper is absent here: this module reads the block format only, because the blosc frame is made of blocks. The frame and the deprecated `lz4 -l` container are read by the archive adapter's own decoder; `lz4_flex` survives only in the `rgx` binary's extraction cache.

Each codec is a Cargo feature, so a binary that reads no zip archive carries no zip codec either. The codec that only exists to serve another codec is not a name of its own: `gzip` needs `deflate`, `deflate` needs `huffman` and `lz77`, `xz` needs `lzma`, and `blosc` pulls in `lz4`, `snappy`, `zlib` and `zstd`.

## Interface
- `pub mod cap` — the bomb guard.
  - `pub const UNLIMITED: u64`
  - `pub struct OutputCap` — `new(limit)`, `unlimited()`, `limit()`, `used()`, `capped()`, `remaining()`, `set_limit(limit)`, `take(n) -> bool`, `fits(n) -> bool`.
  - `pub struct Bounded` — `bytes: Vec<u8>`, `declared: Option<u64>`, `limit: u64`, `capped: bool`; `complete(bytes, declared, limit)`, `stopped(bytes, declared, limit)`.
- `pub mod error` — `pub enum CompressError { InvalidFormat, CorruptedData, UnexpectedEof, BufferTooSmall, InvalidLevel, CrcMismatch, Unsupported, UnsupportedFormat, DecompressionFailed, InternalError }` and `pub type CompressResult<T>`.
- `pub mod crc32` — `pub fn crc32(data: &[u8]) -> u32`, `pub fn crc32_update(crc: u32, data: &[u8]) -> u32`, `pub struct Crc32Calculator`.
- `pub mod lz77` (feature `lz77`) — `pub const DEFAULT_WINDOW_SIZE`, `MIN_MATCH`, `MAX_MATCH`, `MAX_DISTANCE`; `pub struct Match`, `pub struct Lz77Encoder`, `pub enum Lz77Token`, `pub struct Lz77Decoder`.
- `pub mod huffman` (feature `huffman`) — `pub const MAX_DEFLATE_CODE_LEN`, `MAX_BZIP2_CODE_LEN`; `pub struct HuffmanNode`, `build_huffman_tree(freqs)`, `pub struct CodeLength`, `build_canonical_codes(lengths, max_bits)`, `reverse_bits(code, len)`, `pub struct HuffmanDecoder`, `pub struct BitWriter`, `pub struct BitReader<'a>`, `package_merge_lengths(freqs, max_bits)`.
- `pub mod deflate` (feature `deflate`) — `pub enum CompressionLevel`, `pub struct DeflateEncoder`, `pub struct DeflateDecoder` (`decode(data)`, `decode_bounded(data, limit)`).
- `pub mod zlib` (feature `zlib`) — `pub struct ZlibError`, `pub type ZlibResult<T>`, `pub struct ZlibEncoder`, `pub struct ZlibDecoder` (`decode(data)`, `decode_bounded(data, limit)`).
- `pub mod gzip` (feature `gzip`) — `pub enum GzipCompressionMethod`, `GzipFlag`, `GzipOperatingSystem`; `pub struct GzipExtraField`, `GzipHeader`, `GzipMember`, `GzipFile`; `pub enum GzipError`, `pub type GzipResult<T>`; `pub struct GzipReader`, `pub struct GzipWriter`; `GzipReader::decode(data)`, `GzipReader::decode_bounded(data, limit)`.
- `pub mod bwt` (feature `bwt`) — `pub struct Bwt`, `pub struct MtfEncoder`, `pub struct Rle`.
- `pub mod bzip2` (feature `bzip2`) — `pub struct Bzip2Encoder`, `pub struct Bzip2Decoder` (`decode(data)`, `decode_bounded(data, limit)`).
- `pub mod lzma` (feature `lzma`) — `pub struct LzmaProps`, `pub const LZMA_DICT_MIN`, `LZMA_DICT_MAX`; `pub struct LzmaLevel(pub u8)`; `pub struct LzmaDecoder` (`decode(input)`, `decode_bounded(input, limit)`).
- `pub mod zstd` (feature `zstd`) — `pub const MAGIC: u32`; `pub struct ZstdDecoder` (`decode(data)`, `decode_bounded(data, limit)`); `pub fn frame_content_size(data: &[u8]) -> Option<u64>`.
- `pub mod snappy` (feature `snappy`) — `pub struct SnappyDecoder` (`decode(data)`, `decode_bounded(data, limit)`, `decompress(data, cap)`).
- `pub mod lz4` (feature `lz4`) — `pub struct Lz4Decoder` (`decode(data)`, `decode_bounded(data, limit)`, `decompress(data, cap)`).
- `pub mod blosc` (feature `blosc`) — `pub enum Codec`, `pub struct BloscDecoder` (`decode(data)`, `decode_bounded(data, limit)`, `decompress(data, cap)`).
- `pub mod xz` (feature `xz`): [xz](./xz/EGM.md) — the `.xz` container framing and the CRC-64/XZ check type. Public symbols: `pub struct XzReader` (`decompress`, `decompress_bounded`, `decompress_all`); `pub const XZ_MAGIC` and `pub const FOOTER_MAGIC` live in `xz::container`, `pub fn crc64(data: &[u8]) -> u64` in `xz::crc64`, and the module root re-exports only `XzReader`.
- Re-exports at the module root: `BloscDecoder`, `BloscCodec`, `Bzip2Decoder`, `Bounded`, `OutputCap`, `UNLIMITED`, `DeflateDecoder`, `GzipError`, `GzipReader`, `GzipResult`, `GzipWriter`, `Lz4Decoder`, `SnappyDecoder`, `XzReader`, `ZlibDecoder`, `ZlibEncoder`, `ZstdDecoder` — each behind the feature of the module it comes from, and only `Bounded`, `OutputCap` and `UNLIMITED` exist without one.

## Invariants
- A bounded decode counts bytes *as they are emitted*. Decoding first and measuring afterwards costs exactly what a compression bomb was built to cost.
- `OutputCap::take` is all-or-nothing: on failure nothing is counted and `capped()` latches true; `fits` answers the same question without counting.
- `Bounded::bytes` from a capped decode is a prefix of the real payload and is unverified — a decoder that stops early cannot have checked the checksum covering the bytes it did not see.
- `Bounded::declared` is `None` where the format has no declared size, and `Some` otherwise — gzip publishes its ISIZE even though that value is the size modulo 2^32 and is therefore a floor once a member passes 4 GiB.
- Every decoder exposes an unbounded entry point and a bounded one — `decode` / `decode_bounded` in the block and stream codecs, `decompress` / `decompress_bounded` in the XZ reader — and the bounded form is the one the bomb guard applies.
- The three codecs that can share one budget also expose `decompress(data, cap)`, which takes the caller's `OutputCap` directly: `Lz4Decoder`, `SnappyDecoder` and `BloscDecoder`.
- A decoder that finds nothing is not an empty decode: the caller checks the format's magic at the adapter boundary, so a file that is not the format stays searchable as raw bytes.
- Each codec is gated by its own Cargo feature; the dependency graph is what keeps a binary from carrying a codec it never calls.

## Side Effects
- None beyond allocation. Every entry point is a pure function over a byte slice; no file, socket or process is touched, no lock is taken, and no global state is mutated.
- The `Lz77Decoder`, `DeflateDecoder`, `Bzip2Decoder` and `HuffmanDecoder` types carry state across calls and must be reset before reuse, but they own only their own buffers.

## Verification
- Run: `cargo test --release --locked --workspace`
