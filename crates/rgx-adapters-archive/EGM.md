# rgx-adapters-archive

## Overview

`rgx-adapters-archive` is the adapter family that opens archives and
compressed streams so their contents can be searched. Every adapter is a
synchronous function over a byte slice: no subprocess, no mount, no loop
device, no privileges. A member comes back as `rgx_core::Outcome::Members`
and `rgx_core::process` recurses it, so a `.docx` inside a `.zip` inside a
`.tar.gz` is still a `.docx` — the adapters never recurse themselves.

The crate covers the container formats and the single-file decompressors:
zip and the package formats that are zip containers under another extension,
7z, tar (ustar, pax and GNU long names), cpio "newc", Unix `ar` and Debian
packages, git packfiles and git bundles, Subversion dumps, PostgreSQL custom
dump archives, borg repository segments, RAR, SquashFS, ISO 9660, the WIM
metadata header and the block-image containers (VHD, VHDX, QCOW2, VMDK, VDI,
EROFS, APFS/HFS+),
plus the single-file decompressors (gzip, bzip2, xz, legacy `.lzma`, zstd,
LZ4, brotli, zlib and the Unix `compress` LZW refusal). The decompressor
re-matches the expanded stream by extension, so `outer.tar.gz` keeps unpacking
into `outer.tar`.

Registration order is the chain order, and the first matching available
adapter wins. The order is deliberate: the adapters that claim by name come
first, `borg` comes last among those because it is the one format reached by
what a file *is* rather than by what it is called, and the image adapters come
after the real archives because each of them declines on a magic it does not
own. Every adapter declares `Reach::Reveal` — these are containers and
compressed streams, not text ripgrep already reads — except `SvnDump`, which
declares `Reach::Render` and decides from the bytes (`reach_needs_bytes()`),
and none declares `available()`, so there is no external binary in the chain.

This directory holds no source files of its own. It groups the crate root
(`Cargo.toml`, `README.md`, `LICENSE-APACHE`, `NOTICE`), the adapter sources
under `src/`, two one-off diagnostics under `examples/`, and the crate's own
behavioural corpus under `testdata/`.

## Subdirectories & Boundaries
- src: [link](./src/EGM.md) — the adapter registry, the shared producer budget, one module per format family, and the three in-house codec trees (brotli, LZ4, 7z).
- examples: [link](./examples/EGM.md) — one-off timing diagnostics for the 7z CRC-32 fold and for decode throughput of the in-house codecs.
