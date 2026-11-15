# rar-codec

The RAR container codec `rgx` uses for `.rar` extraction, kept as its own
crate so the container and the decompression algorithms can be tested on
their own. Zero dependencies, `#![no_std]` + `alloc`,
`#![forbid(unsafe_code)]`. The RAR4 half, the RAR5 half and the PPMd
decoder were written here from the format and from the algorithm; the
module header records the provenance of each.

## Decode

`Archive::open` walks the full header structure of RAR4 and RAR5
archives. Extraction covers stored entries, the RAR5 LZ77/Huffman method
(version 0, including solid archives and the delta, E8/E8E9 and ARM
filters), and the RAR4 method `0x31..=0x35` — solid archives, the
standard E8/E8E9, delta, RGB and audio VM filters, and PPMd var-H blocks
inside the packed stream — all with CRC-32 verification. RAR5 multivolume
archives reassemble across volumes through `Archive::open_multi`.

Encrypted payloads, PPMd filters, arbitrary RAR VM program filters and the
RAR 7.x compression algorithm (version 1) report as `Error::Unsupported`.

## Encode

`ArchiveBuilder` writes valid RAR5 archives using the store method. The
RAR5 container layout is publicly documented, and writing store-only
archives needs no proprietary algorithm.

## Public surface

`Archive`, `Entry`, `EntryKind`, `Format`, `METHOD_STORE`,
`ArchiveBuilder`, `crc32` and `update`, `Error` and `Result`, and `vint`
for the variable-length integers the RAR5 header format uses.

## Feature flags

`default` is empty. `std` relaxes nothing critical today and is reserved
for future IO adapters.

## Licence

Apache-2.0 only. Every file carries the SPDX header saying so, and
`../../scripts/vendored-sources.tsv` records the module each was written
from. The crate was born as a port of libarchive's RAR support
(BSD-2-Clause); every module has since been rewritten, and the terms that
port inherited are kept on the record in the repository's `NOTICE`.