# rar-codec

## Overview

`rar-codec` is the pure-Rust RAR container codec that `rgx` uses for `.rar`
extraction, kept as its own crate so the container walk and the decompression
algorithms can be exercised on their own instead of through the search
pipeline. The crate has zero dependencies, is `#![no_std]` + `alloc` and
`#![forbid(unsafe_code)]`, and carries a `std` feature that relaxes nothing
critical today and is reserved for future IO adapters.

On the decode side it walks the full header structure of RAR 4.x and RAR 5.0
archives: stored members, the RAR5 LZ77/Huffman method (version 0, including
solid archives and the delta, E8/E8E9 and ARM filters), the RAR 2.9/3.x
LZ77/Huffman method `0x31..=0x35` (including solid archives, the standard
E8/E8E9, delta, RGB and audio VM filter programs, and PPMd var-H blocks inside
the packed stream), and RAR5 multivolume sets reassembled through
`Archive::open_multi`. A member's data CRC-32 is checked at extract time and
the RAR 5.0 header CRC at open time; the RAR 4.x header CRC is read but not
enforced. On the encode side it writes valid RAR 5.0 archives in the store
method, because the container layout is publicly documented by RARLAB and
writing store-only archives needs no proprietary algorithm. Encrypted
payloads, PPMd filters, arbitrary RAR VM program filters and unknown RAR4
compression methods are reported as `Error::Unsupported` rather than guessed
at. The RAR 7.x compression algorithm (version 1) is not one of them: the
version is parsed and stored on the entry and never consulted, so a member
that carries it is handed to the RAR 5.0 decoder and fails there as
`Malformed` or `Truncated` rather than being refused by name.

This directory holds no source files of its own. It groups the crate root
(`Cargo.toml`, `README.md`, `LICENSE-APACHE`, `NOTICE`), the library sources
under `src/`, one diagnostic example under `examples/`, and the crate's own
behavioural corpus under `tests/` and `testdata/` — the integration tests are
the oracle the implementation is written against, and the fixtures they read
(`testdata/rar/`) stay in the repository rather than in the published crate.

## Subdirectories & Boundaries
- src: [link](./src/EGM.md) — the crate's public surface: the RAR4/RAR5 container walk, the two decompressors, the PPMd var-H model, the CRC-32 and the variable-length integer codec.
- examples: [link](./examples/EGM.md) — one-off timing diagnostic that answers whether the CRC-32 slice-by-8 fold paid for itself.
