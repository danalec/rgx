# sevenz

## Overview

In-process 7z container support, vendored from the 7-Zip project
(`CPP/7zip/{Archive/7z,Compress}/*`) with only mechanical adjustments: fixture
paths, the `graph_optimize` import narrowed to the `graph_mode` selection
enum, and the `std` / `isa-huffman` cfg feature names declared in the crate's
`Cargo.toml` so the copied `cfg(feature = ...)` attributes stay byte-identical
to the upstream sources. Decoder semantics are format-faithful: signature
header CRC, raw and encoded headers, bind-pair coder chains (Copy, LZMA1,
LZMA2, Deflate, BZip2, Delta, x86 BCJ), the UTF-16 file table, sub-streams and
per-entry CRC verification. AES/PPMd/BCJ2 report an honest `Unsupported`
rather than silently mis-decoding.

`sevenz.rs` is the container reader: the header walk, the coder-chain
assembly and the folder/sub-stream split. Around it sit the codecs the
chains can name — `lzma.rs` (LZMA1 and LZMA2 range coding), `deflate.rs`
(DEFLATE, RFC 1951, with stored, fixed and dynamic block modes),
`bzip2.rs` (stream-compatible with libbz2), `lz77.rs` (the sliding-window
match finder DEFLATE sits on), `bwt.rs` (the Burrows-Wheeler transform and
its move-to-front and zero-run companions, which bzip2 sits on),
`huffman.rs` (the canonical Huffman codes, the bit reader and the bit writer
both codecs share) and `crc32.rs` (the slice-by-8 fold). `graph_mode.rs` is
rgx's own: the match-finding strategy selection, shared with
`lz4/graph_optimize.rs`. `isa_huffman.rs` and `isa_icf.rs` exist only to
satisfy the imports of the vendored sources behind the `isa-huffman` feature —
and the "ISA-L" behind that name is a wrapper over this tree's own DEFLATE
encoder, not Intel's library.

## Interface
- `pub use sevenz::{SevenzArchive, SevenzFile}` — the container. `SevenzArchive::parse(data: &'a [u8]) -> CompressResult<Self>` on `SevenzArchive<'a>`, which borrows the caller's buffer, `files(&self) -> &[SevenzFile]`, `folder_count(&self) -> usize`, `stream_of(&self, index: usize) -> Option<(usize, usize)>`, `folder_output(&self, folder_idx: usize) -> CompressResult<Vec<u8>>`, `folder_unpack_size(&self, folder_idx: usize) -> CompressResult<u64>`, `substream_bytes(&self, folder_idx: usize, sub_idx: usize, folder_out: &[u8]) -> CompressResult<Vec<u8>>`, `extract(&self, index: usize) -> CompressResult<Vec<u8>>`, `index_of_name(&self, name: &str) -> Option<usize>`. `SevenzFile` carries `name: String` (UTF-16 decoded, `/`-separated), `is_directory: bool`, `size: u64` and `crc32: Option<u32>`.
- `pub mod bwt` — `pub struct Bwt` (`new`, `transform`, `inverse`), `pub struct MtfEncoder` (`new`, `encode`, `decode`, `reset`), `pub struct Rle` (`encode`, `decode`).
- `pub mod bzip2` — `pub struct Bzip2Encoder` (`new`, `with_block_size`, `encode`), `pub struct Bzip2Decoder` (`new`, `decode`).
- `pub mod crc32` — `pub fn crc32(data: &[u8]) -> u32`, `pub fn crc32_update(crc: u32, data: &[u8]) -> u32`, `pub struct Crc32Calculator` (`new`, `update`, `finish`, `reset`, `current`).
- `pub mod deflate` — `pub enum CompressionLevel`, `pub struct DeflateEncoder` (`with_isal`, `encode_fast`, `encode`), `pub struct DeflateDecoder` (`decode`).
- `pub mod error` — `pub enum CompressError` (`InvalidFormat`, `CorruptedData`, `UnexpectedEof`, `BufferTooSmall`, `InvalidLevel`, `CrcMismatch { expected, actual }`, `Unsupported`, `UnsupportedFormat(String)`, `DecompressionFailed(String)`, `InternalError`) and `pub type CompressResult<T>`.
- `pub mod graph_mode` — `pub enum GraphMode { Standard, Paley }`.
- `pub mod huffman` — `pub const MAX_DEFLATE_CODE_LEN: usize = 15`, `pub const MAX_BZIP2_CODE_LEN: usize = 20`, `pub struct HuffmanNode` (`leaf`, `internal`, `is_leaf`), `pub fn build_huffman_tree(freqs: &[u64]) -> Option<Box<HuffmanNode>>`, `pub struct CodeLength`, `pub fn build_canonical_codes(lengths: &[u8], max_bits: usize) -> Vec<CodeLength>`, `pub fn reverse_bits(code: u32, len: u8) -> u32`, `pub struct HuffmanDecoder` (`from_lengths`, `decode`, `table_bits`), `pub struct BitWriter` (`new`, `write_bits`, `write_bits_msb`, `finish`, `bit_position`), `pub struct BitReader<'a>` (`new`, `read_bits`, `peek_bits`, `skip_bits`, `read_bits_msb`, `read_bits_msb_64`, `align`, `has_more`, `remaining_bytes`, `remaining_bits`), `pub fn package_merge_lengths(freqs: &[u64], max_bits: u8) -> Vec<u8>`.
- `pub mod lz77` — `pub const DEFAULT_WINDOW_SIZE: usize = 32 KiB`, `MIN_MATCH`, `MAX_MATCH: usize = 258`, `MAX_DISTANCE`, `pub struct Match`, `pub struct Lz77Encoder` (`new`, `with_level`, `with_graph_mode`, `compress`), `pub enum Lz77Token`, `pub struct Lz77Decoder` (`new`, `decompress`, `copy_match`, `add_literal`, `output`, `reset`).
- `pub mod lzma` — `pub struct LzmaProps { lc, lp, pb }` (`from_byte`, `to_byte`), `pub const LZMA_DICT_MIN: u32 = 1 << 12`, `pub const LZMA_DICT_MAX: u32 = 1 << 27`, `pub struct LzmaLevel(pub u8)`, `pub struct LzmaEncoder` (`new`, `with_settings`, `with_graph_mode`, `encode`), `pub struct LzmaDecoder` (`decode`, `decode_raw`, `decode_lzma2`).
- `pub mod isa_huffman` (feature `isa-huffman`) — `pub enum CompressionLevel`.
- `pub mod isa_icf` (feature `isa-huffman`) — `pub struct IsalDeflateEncoder` (`with_level`, `encode`).

## Invariants
- The signature header's own CRC is verified before anything else is read, and every entry's CRC is verified against the unpacked payload when the archive records one.
- AES-256, PPMd and non-x86 BCJ filters are refused with `CompressError::Unsupported`. They are not approximated: a wrong decode would be a plausible-looking page rather than a loud failure.
- `isa_huffman::CompressionLevel` and `isa_icf::IsalDeflateEncoder` are stand-ins. The latter wraps this tree's own `DeflateEncoder` and produces byte-identical output to it — `encode_fast` gains correctness and a buildable path, not speed.
- `crc32` and the byte-at-a-time `crc32_slow` beside it must agree at every length. The fold is slice-by-8 because the fixture `sevenz_multifolder.7z` is 24 KB on disk and declares 107 MB across its two folders, so the per-member CRC runs over 107 MB of payload.
- The BWT forward transform sorts cyclic shifts with prefix doubling (the standard O(n log n) suffix-array construction); the inverse is the classic last-column walk over the first-column occurrence map, placing each recovered byte at its final index so no reverse pass is needed.
- bzip2 bit packing is MSB-first within bytes and continuous across block boundaries, matching `bzip2` / libbz2 output byte-for-byte.
- The LZMA encoder and decoder share the same probability-model shapes, so a stream written here is readable by liblzma and vice versa; the fixtures under `testdata/lzma_*` are third-party vectors the tests hold this code against.
- The LZ77 window is 32 KiB per RFC 1951 §3.2.7, a match is at least 3 bytes and at most 258, and the encoder emits a `Lz77Token` stream that the DEFLATE encoder maps to Huffman symbols and extra bits.
- A 7z folder is decoded whole, and the number of folder decodes is counted per thread so the test can pin "one decode per folder, however many files the folder holds" — the thing a per-file extract violates silently, with no wrong answer to catch it.

## Side Effects
- Reads only the byte slice handed in; the tree opens no files, spawns no processes and takes no locks.
- Allocates the unpacked folder output, the header structures and the per-coder state. A folder's whole expansion is materialised before any of its entries can be refused by the pipeline's member budget.
- Nothing is written to disk and no state survives the call.

## Verification
- Run: `cargo test --release --locked --workspace`
