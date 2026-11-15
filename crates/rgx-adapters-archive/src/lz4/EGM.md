# lz4

## Overview

An in-house LZ4 codec, written from the published LZ4 block and frame formats
and from the deprecated legacy container `lz4 -l` emits. The API contract of
`lib/lz4.c` is what the encoder and decoder surface was shaped from; the byte
layout every function reads and writes is the published specification.

`lz4.rs` is the codec: the block format, the frame format and the legacy
container. `error.rs` is the error vocabulary. `graph_optimize.rs` holds the
graph-theoretic hash and chain-walking primitives the encoder uses — a
Paley-inspired quadratic-residue mixer for the hash tables and a
FlipPredictor-style scoring function for chain walking — plus the predictor
and partitioner types that sit on top of them.

rgx only decodes, so the encoder half (`Lz4Encoder`, `encode_block_graph` and
the match finder it pulls in) is carried along unused; the module therefore
allows `dead_code` and the other unused-item lints, the same way the vendored
`sevenz` and `tar` trees do. `unreachable_patterns` is deliberately *not*
allowed: a duplicate or shadowed match arm in a parser is a real defect, not
vendoring noise.

## Interface
- `pub use lz4::{Lz4Decoder, Lz4Encoder}` — re-exported at the module root.
- `pub struct Lz4Decoder` — `new()`, `decode_block(&self, input: &[u8]) -> CompressResult<Vec<u8>>`, `decode_block_bounded(&self, input: &[u8], limit: u64) -> CompressResult<Bounded>`, `decode(&self, input: &[u8]) -> CompressResult<Vec<u8>>` (one frame), `decode_bounded(&self, input: &[u8], limit: u64) -> CompressResult<Bounded>`, `decode_legacy(&self, input: &[u8]) -> CompressResult<Vec<u8>>`, `decode_legacy_bounded(&self, input: &[u8], limit: u64) -> CompressResult<Bounded>`, `decode_auto(&self, input: &[u8]) -> CompressResult<Vec<u8>>`, `decode_auto_bounded(&self, input: &[u8], limit: u64) -> CompressResult<Bounded>`, and the associated `is_legacy(input: &[u8]) -> bool`.
- `pub struct Lz4Encoder` — `new()`, `with_level(level: Lz4Level)`, `with_block_mode(mode: BlockMode)`, `with_checksum(checksum: ContentChecksum)`, `with_graph_mode(mode: GraphMode)`, `encode_block(&self, input: &[u8]) -> Vec<u8>`, `encode(&self, input: &[u8]) -> Vec<u8>`.
- `pub struct Lz4Level(pub u32)`, `pub enum BlockMode`, `pub enum ContentChecksum`, `pub struct Lz4FrameHeader` — the frame-description types.
- `pub const LZ4_MAGIC: u32 = 0x184D_2204` (frame magic), `pub const LZ4_SKIPPABLE_MAGIC: u32 = 0x184D_2A50`, `pub const LZ4_BLOCK_MAX: usize = 4 MiB`, `pub const LZ4_BLOCK_MAX_64KB: usize = 64 KiB`, `pub const LZ4_LEGACY_MAGIC: u32 = 0x184C_2102`, `pub const LZ4_LEGACY_BLOCK_MAX_COMPRESSED: usize = 8 MiB + 8 MiB/255 + 16`.
- `pub mod error` — `pub enum CompressError` (`InvalidFormat`, `CorruptedData`, `UnexpectedEof`, `BufferTooSmall`, `InvalidLevel`, `CrcMismatch { expected, actual }`, `Unsupported`, `UnsupportedFormat(String)`, `DecompressionFailed(String)`, `InternalError`) and `pub type CompressResult<T>`.
- `pub mod graph_optimize` — `pub enum GraphMode { Standard, Paley }`, `pub struct MatchFeatures`, `pub struct MatchPredictor` (`new`, `predict_quality`, `should_skip`, `record_match`, `historical_rate`, `learn`), `pub struct WitnessConfig` (`qr13`, `qr17`, `qr5`), `pub struct OffsetPredictor` (`new`, `record`, `top_offsets`, `paley_intersection`), `pub struct StridePredictor` (`new`, `record`, `try_stride`, `is_active`), `pub struct BlockPartitioner` (`new`, `find_boundaries`), `pub enum DataRegion` (`classify`, `optimal_min_match`).

## Invariants
- The frame walk reads a block's size from bits 0..30 of its header — bit 31 marks a stored block — and terminates on the zero end mark, not on a flag in the header.
- Dependent blocks decode into the frame's running output, so a match can resolve against the previous block's bytes.
- The legacy container is a bare sequence of length-prefixed blocks with no frame header and no block checksums; it shares only the block codec with the frame reader, and its blocks decode into one running buffer so a match can resolve against the previous block's bytes. Its stream ends where the frame's does not: on a zero block size, or on a size past the ceiling, and not on an end mark.
- Dictionary-compressed frames (`lz4 -D`) that match across the dictionary are still rejected.
- A block is a sequence of sequences: a token byte whose high nibble is the literal length and whose low nibble is the match length minus four, either nibble of 15 deferring to a 255-chained extension; then the literal bytes; then, unless this is the block's last sequence, a two-byte little-endian match offset and any match-length extension. The last sequence carries literals only, so a block always ends on its literal run.
- A match copies from `output[-offset]`, a source that overlaps the write cursor whenever the match is longer than its offset. That case is a byte-wise repeat of the `offset` bytes before the match, not one bulk move.
- The frame header checksum is the second byte of XXH32 over the descriptor, optional fields included; a per-block checksum (FLG bit 4) is XXH32 over the block's bytes as stored.
- The mixer constants in `graph_optimize.rs` are pinned: the Paley prime `p ≡ 1 (mod 4)` gives the quadratic-residue step its avalanche, and changing the constants changes every fingerprint the encoder emits.
- `decode_auto` picks the container from its magic, so the two containers stay separate behind one entry point; `is_legacy` is the published predicate for the deprecated one and is what the `Decompress` adapter checks before it hands bytes to the decoder.

## Side Effects
- Reads only the byte slice handed in; the codec opens no files, spawns no processes and takes no locks.
- Allocates the decoded output and the frame's running output buffer. The bounded entry points cap the expansion as they emit, so a bomb costs the budget and no more.
- Nothing is written to disk and no state survives the call.

## Verification
- Run: `cargo test --release --locked --workspace`
