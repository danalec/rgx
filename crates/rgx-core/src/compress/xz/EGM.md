# xz

## Overview
The `.xz` container: stream/block/index framing in `container.rs` and the CRC-64 check type in `crc64.rs`. Both are independent reimplementations of the published format, written from the xz container specification and the CRC-64/XZ parameters rather than from any implementation's source. `container.rs` decodes the LZMA2 payload through `crate::compress::lzma::LzmaDecoder`; `crc64.rs` implements the check type `0x04` (the ECMA-182 polynomial, reflected, `init` and `xorout` all-ones). The container accepts and verifies four check kinds — none `0x00`, CRC-32 `0x01`, CRC-64 `0x04` and SHA-256 `0x0A` — and refuses any other.

The format's own caution governs the decode. Section 3.1.4 says the Block Header and Index fields "may contain (intentionally or unintentionally) invalid information", so the extent of the Compressed Data is walked from the LZMA2 control bytes, a declared Compressed Size is only trusted once it matches that walk (3.1.3), and the Index is checked against what the blocks *really* occupied (4.2/4.3) rather than against what their headers claimed.

## Interface
- `pub mod container` — the framing.
- `pub mod crc64` — the CRC-64 check type.
- `pub struct XzReader` — the container reader.
  - `pub fn decompress(data: &[u8]) -> CompressResult<Vec<u8>>` — decode one `.xz` stream.
  - `pub fn decompress_bounded(data: &[u8], limit: u64) -> CompressResult<Bounded>` — decode one stream without expanding it past `limit` bytes.
  - `pub fn decompress_all(data: &[u8]) -> CompressResult<Vec<u8>>` — decode every stream in a possibly concatenated `.xz` file, honouring Stream Padding (2.2).
- `pub const XZ_MAGIC: [u8; 6]` — the six-byte stream magic (2.1.1.1): `FD 37 7A 58 5A 00`. It lives in `container`, not at the module root.
- `pub const FOOTER_MAGIC: [u8; 2]` — the two-byte stream footer magic (2.1.2): `YZ`. It lives in `container`, not at the module root.
- `pub fn crc64(data: &[u8]) -> u64` — CRC-64/XZ over `data`; `crc64(b"123456789") == 0x995DC9BBDF1939FA`. It lives in `crc64`, not at the module root; the module root re-exports only `XzReader`.

## Invariants
- The length is checked first: a stream shorter than header plus footer is refused as "file is too short to be an XZ stream", and only then is the magic compared — `data[..6] == XZ_MAGIC`, a mismatch refused as "bad magic bytes".
- A block's declared Compressed Size is trusted only after the LZMA2 walk agrees with it; the walk, not the header, decides where the block ends.
- The Index is verified against the extents the blocks really occupied, not against the sizes their headers claimed.
- Stream Padding between concatenated streams must be a multiple of four bytes, or the file is refused — the alignment 2.2 requires and `xz -t` enforces.
- CRC-64/XZ steps against the reflected form `0xC96C5795D7870F42`, derived from the normal form `0x42F0E1EBA9EA3693` rather than typed in, and it must not drift into CRC-64/ECMA-182 proper (`init = 0`, MSB-first, `xorout = 0`) nor into the unnamed un-reflected CRC.
- `decompress_bounded` skips the Index verification when the cap cut the stream short: a partial decode has no business being compared against a full one.
- A block whose optional Uncompressed Size declaration exceeds the cap is refused from the declaration, before its LZMA2 payload is walked.

## Side Effects
- None. Every entry point is a pure function over a byte slice; the crate allocates the output vector and drops it on return.
- Reads no files, spawns no processes, takes no locks and touches no global state.

## Verification
- Run: `cargo test --release --locked --workspace`
