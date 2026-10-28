# LZ4 test vectors

Third-party vectors for `src/lz4/`. Every `.lz4` file here was written by
the **reference `lz4` CLI** (lz4 v1.10.0 64-bit multithread, by Yann
Collet), not by upstream and not by rgx. They are committed so the test suite
runs with no external tool installed.

A round trip through our own encoder and decoder proves nothing about
interop — that is exactly how the frame decoder shipped broken (see the
note in `src/lz4/mod.rs`). These files are the reason the decoder is
believed to work.

## Payloads

`lz4_*.expected` are the *uncompressed* originals, named after the vector
family they back. All deterministic; no randomness, no timestamps.

| Payload | Bytes | What it is |
| --- | --- | --- |
| `lz4_empty.expected` | 0 | empty input, so the frame is header + end mark only |
| `lz4_tiny.expected` | 2 | `Hi` — one stored (uncompressed) block |
| `lz4_text.expected` | 20692 | 400 lines of English-ish text, compresses ~10:1 |
| `lz4_repeat.expected` | 1600 | `abcdefgh` repeated 200× — long matches |
| `lz4_binary.expected` | 70000 | pseudo-random (seed 12345) — incompressible, so the reference stores it as an *uncompressed* block |
| `lz4_big.expected` | 250000 | 64-byte pattern with a mutation every 4 KB; at `-B4` this is four compressed blocks in one frame |

## Vectors

Reproduce any row with the command in its `lz4` column, run in this
directory. The reference `-f` flag overwrites.

| Vector | Payload | lz4 command | Bytes | Frame feature it pins down |
| --- | --- | --- | --- | --- |
| `lz4_empty_plain` | empty | `lz4 -f -1` | 15 | end mark with no block |
| `lz4_tiny_plain` | tiny | `lz4 -f -1` | 21 | single stored block; block header `0x80000002` |
| `lz4_text_plain` | text | `lz4 -f -1` | 2076 | single compressed block, content checksum on |
| `lz4_text_l9` | text | `lz4 -f -9` | 2009 | level 9 |
| `lz4_text_csize` | text | `lz4 -f -1 --content-size` | 2084 | content size present (FLG bit 3) |
| `lz4_text_nocrc` | text | `lz4 -f -1 --no-frame-crc` | 2072 | content checksum absent (FLG bit 2) |
| `lz4_text_bx` | text | `lz4 -f -1 -BX` | 2080 | per-block checksums (FLG bit 4) |
| `lz4_text_bx_csize` | text | `lz4 -f -9 -BX --content-size` | 2021 | block checksums *and* content size |
| `lz4_text_b4` | text | `lz4 -f -1 -B4` | 2076 | 64 KB blocks |
| `lz4_text_b7` | text | `lz4 -f -1 -B7` | 2076 | 4 MB blocks |
| `lz4_text_bd` | text | `lz4 -f -1 -BD` | 2076 | block dependency flag set (single block) |
| `lz4_text_bd_bx` | text | `lz4 -f -1 -BD -BX` | 2080 | dependency + block checksums |
| `lz4_repeat_plain` | repeat | `lz4 -f -1` | 43 | 2.7% ratio, long matches |
| `lz4_binary_plain` | binary | `lz4 -f -1` | 70019 | stored block: header `0x80011170` |
| `lz4_binary_b4` | binary | `lz4 -f -1 -B4` | 70023 | stored block, 64 KB blocks |
| `lz4_big_plain` | big | `lz4 -f -1 -B4` | 2436 | four compressed blocks in one frame |
| `lz4_big_bx` | big | `lz4 -f -1 -B4 -BX` | 2452 | four blocks + per-block checksums |
| `lz4_big_bd` | big | `lz4 -f -1 -B4 -BD` | 1982 | **dependent blocks**: a match in block N reaches into block N-1 |

## The legacy container

`lz4 -l` (legacy container, magic `0x184C2102`) is **covered**: the
vendored decoder reads it, as a bare run of length-prefixed blocks under
that magic, with no frame header and no checksums. The decoder that
replaced `lz4_flex` is `src/lz4/lz4.rs`, and the legacy reader is
`decode_legacy` in it.

Dictionary frames (`lz4 -D`) are likewise not covered. Frames that do not
match across the dictionary decode fine; those that do are rejected, and
`lz4_flex` rejects them too.
