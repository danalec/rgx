# rar-codec src

## Overview

The crate's whole public surface lives here. `lib.rs` is the crate root: it
declares the modules, re-exports the handful of names a caller needs, and
carries the crate's provenance note — the crate began as a `rustfmt`-ed port
of libarchive's RAR support (BSD-2-Clause, recorded in the repository's
`NOTICE`) and every module has since been rewritten as an independent
reimplementation, written from RARLAB's published RAR 5.0 format
specification for the container half and from understanding of the algorithms
for the decompression half, which RARLAB does not document.

The work splits into three layers. The bottom layer is the primitives:
`crc32` (the reflected IEEE 802.3 fold, slice-by-8, with the byte-at-a-time
definition kept beside it as the oracle), `vint` (RAR 5.0's variable-length
integers — the only public module), `bitreader` (an MSB-first bit cursor over
a byte slice) and `huffman` (canonical Huffman decode tables). The middle
layer is the decompressors: `unpack` for the RAR 5.0 LZ77/Huffman method and
its filters, `unpack3` for the RAR 2.9/3.x method with its VM filter
programs, and `ppmd7` for the PPMd var-H model that appears inside RAR 4.x
packed streams. The top layer is the container: `read` walks the RAR4 and
RAR5 header structures and reassembles multivolume sets, and `write` emits
RAR 5.0 store-method archives.

## Interface
- `pub use read::{Archive, Entry, EntryKind, Format, METHOD_STORE}` — the read side. `Archive::open(data: &[u8]) -> Result<Self>` parses one volume strictly (every RAR5 header CRC32 verified), `Archive::open_lenient(data: &[u8]) -> Result<Self>` parses without the header checks — a difference that exists for RAR5 alone, because the RAR 4.x header CRC is read but never enforced, `Archive::open_multi(volumes: &[&[u8]]) -> Result<Self>` takes every volume at once and reassembles members that span them, `Archive::entries(&self) -> &[Entry<'a>]` lists the members in archive order, and `Archive::extract(&self, entry: &Entry<'a>) -> Result<Vec<u8>>` returns one member's unpacked bytes.
- `Archive<'a>` — an opened archive: the public fields `format: Format`, `encrypted: bool`, `multivolume: bool`, `volume_number: Option<u64>`, over the entries, the packed chunks and the solid-group cache.
- `Entry<'a>` — one member, borrowed from the input buffer: `name: Cow<'a, str>`, `kind: EntryKind`, `unpacked_size: u64`, `size_unknown: bool`, `packed_size: u64`, `method: u8`, `compression_version: u8`, `dictionary_size: u64`, `solid: bool`, `host_os: u8`, `crc32: Option<u32>`, `mtime: Option<u32>`, `encrypted: bool`, `split_before: bool`, `split_after: bool`, `data_offset: Option<usize>`.
- `EntryKind` — `File`, `Directory`, `Symlink`, `Hardlink`, `Service`.
- `Format` — `Rar4` (magic `Rar!\x1a\x07\x00`) or `Rar5` (magic `Rar!\x1a\x07\x01\x00`).
- `METHOD_STORE: u8 = 0x30` — the RAR 4.x store method byte. RAR 5.0's equivalent is method 0 in the compression-information field.
- `pub use write::ArchiveBuilder` — the encode side. `ArchiveBuilder::new() -> Self`, `len(&self) -> usize`, `is_empty(&self) -> bool`, `add_stored(&mut self, name: &str, data: &[u8]) -> Result<&mut Self>`, `add_directory(&mut self, name: &str) -> Result<&mut Self>`, `finish(self) -> Vec<u8>`.
- `pub use crc32::{crc32, update}` — `crc32(data: &[u8]) -> u32` for a whole slice; `update(state: u32, data: &[u8]) -> u32` to continue a checksum over more bytes, where `state` is the value *before* the final XOR.
- `pub use error::{Error, Result}` — `Error` is `Truncated`, `BadMagic`, `Malformed(&'static str)`, `BadCrc(&'static str)` or `Unsupported(&'static str)`; `Result<T> = core::result::Result<T, Error>`.
- `pub mod vint` — RAR 5.0 variable-length integers. `MAX_LEN: usize = 10`, `read(data: &[u8]) -> Result<(u64, usize)>`, `read_r(data: &[u8], cursor: &mut usize) -> Result<u64>` (the cursor form a sequential header parser wants), `len(v: u64) -> usize` (always in `1..=10`), `write(out: &mut Vec<u8>, v: u64)`.
- Private modules, reachable only inside the crate: `bitreader` (`BitReader` over a byte slice, `peek16`/`peek32`/`take`/`skip`/`seek_byte_bit`), `huffman` (`DecodeTable::build(bit_length: &[u8], size: usize) -> Result<DecodeTable>`, `DecodeTable::decode(&self, br: &mut BitReader) -> Result<u16>`), `unpack` (`unpack(data: &[u8], unpacked_size: Option<u64>, dict_size: u64) -> Result<Vec<u8>>` and the stateful `Unpacker` with `new`/`begin_member`/`write_stored`/`run`/`finish`), `unpack3` (`unpack(data: &[u8], unp_size: u64) -> Result<Vec<u8>>` and the stateful `Unpacker3` with `new`/`run_member`/`write_stored`), `ppmd7` (`Ppmd7` with `new`/`init_range_rar`/`init_model`/`set_init_esc`/`decode_symbol`), `read`, `write`, `error`, `crc32`.

## Invariants
- The crate is `#![no_std]` + `alloc` and `#![forbid(unsafe_code)]`; nothing here may reach for `std` except under `cfg(any(test, feature = "std"))`.
- A vint is at most 10 bytes and must fit in 64 bits. A payload bit past 63 is refused (`Malformed("vint exceeds 64 bits")`) rather than silently truncated, and a 10th byte that still carries the continuation flag is refused (`Malformed("vint longer than 10 bytes")`).
- `crc32` and the byte-at-a-time `crc32_slow` beside it must agree at every length; an optimisation that cannot pass that test is not an optimisation. `update`'s `state` is the pre-final-XOR value, so the final complement happens once, at the end.
- A Huffman table must be exactly or under-subscribed: the Kraft sum above 1 is refused (`Malformed("huffman code space over-subscribed")`), and no code may exceed 15 bits. An all-zero length array is a *legal* empty table — RAR 5.0 sends unused sub-tables that way — so it builds successfully and fails only when a code is actually drawn from it.
- `BitReader` never panics on a short stream: every byte read is bounds-checked and a run past the end is `Error::Truncated`. `skip` past the end is not an error by itself; the read that needs the bits reports it.
- `Archive::open_multi` requires the volumes in order: a later volume must be the same RAR family and must declare the volume number that matches its position, or the set is refused as malformed.
- A member that spans volumes is extractable only from an archive opened with `open_multi`. Opened over a single volume it is reported with `split_before`/`split_after` and extraction is refused (`Unsupported("member spans volumes")`) — the bytes are not all there, and a short answer would look like a complete one.
- A solid group's members decode through the group cache: the dictionary, the Huffman tables, the distance cache and the last match length persist across the members of the group, so a member can only be decoded by decoding the run that precedes it. A stored member inside a solid group still occupies the dictionary (`write_stored`).
- The RAR5 distance cache is most-recent-first, and the RAR4 cache distinguishes a cache *hit* (rotate the first `k + 1` slots) from a *new* distance (shift all four slots). Getting that wrong corrupts every later cache hit, so the two updates are separate methods.
- A filter's region must complete inside the member that declares it; a filter range out of order or out of bounds is `Malformed`.
- `Unpacker::finish` checks the produced byte count against the declared size when the header gave one, and refuses a member whose filter never completed. `Unpacker3` checks its filters and the member byte count and computes no checksum at all; the member's CRC-32 is verified one level up, in `Archive::extract`.
- `ArchiveBuilder::finish` emits the RAR 5.0 "general archive layout": signature, one main archive header, one file header per queued member followed by its data area, and an end-of-archive header. An empty member name is refused (`Malformed("empty member name")`).

## Side Effects
- Reads only the byte slices handed in; the crate opens no files, spawns no processes, takes no locks and performs no IO of its own.
- Allocates: the LZ window (rounded up to a power of two, at least 64 KiB, and capped at the 4 MiB RAR3 dictionary ceiling on the RAR4 path only — the RAR5 path takes the dictionary size from the header and rounds it up with no upper bound), the Huffman tables, the PPMd context pool, and the decoded output buffers.
- The PPMd model carves its contexts and symbol states from one flat byte pool addressed by `u32` offsets. Reads past the pool yield 0 and writes are dropped — valid streams never reference outside it, and a corrupt stream is caught by the member-size and CRC checks upstream instead of panicking.
- `Archive` caches solid-group decoder state in a `RefCell`, so it is not `Sync`; the cache holds the decoded outputs of the group it is currently decoding.
- Nothing is written to disk and no state survives the process.

## Verification
- Run: `cargo test --release --locked --workspace`
