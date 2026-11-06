# rgx-adapters-pdf

## Overview

The PDF family of `rgx`: an in-process text extractor, fully in-process
(no subprocess, no external tool), and the only adapter in the tree that
carries its own security handler.

The reader's scope is the whole document: classic xref tables, xref streams
(PDF 1.5+), object streams (`ObjStm`), the full filter zoo (Flate, LZW,
ASCII85, ASCIIHex, RunLength, PNG predictors), page-tree walking with
inherited resources, and font-aware text extraction — simple-font encodings
(WinAnsi/MacRoman/Differences) and CID fonts via `ToUnicode` CMaps.

Image XObjects are outside *text* extraction but are reachable through
`all_page_images`: a scanned page has no text layer to extract, so the
picture is the whole content, and handing it to an OCR engine is what makes
a scanned PDF searchable at all. The scans that are not pictures in the
first place — a CCITT fax stream and a JBIG2 page — are decoded here, in
house, before they are handed over.

The crate is `#![no_std]` + `alloc` and holds exactly one adapter, `Pdf`,
behind the single `pdf` feature: `--no-default-features` leaves a crate
with no adapter at all.

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `Pdf` adapter and its `adapters()` factory, the full document parser in
  `pdf_full.rs`, the standard security handler in `security.rs`, the
  ITU-T T.4/T.6 fax decoder in `fax.rs`, and the JBIG2 decoder tree.
  Public symbols: `pub fn adapters()`, `pub struct Pdf`, `pub use
  pdf_full::all_page_images`, `pub mod fax` (`pub struct FaxParams`, `pub fn
  decode_fax`), `pub mod jbig2` (`decode`, `decode_with_size`,
  `Jbig2Image`), and `impl Adapter` for `Pdf`.
- `src/jbig2`: [src/jbig2/EGM.md](./src/jbig2/EGM.md) — the JBIG2
  (ITU-T T.88) decoder: the MQ arithmetic coder, the arithmetic integer
  procedures, the segment and region structures, the generic region, the
  symbol dictionary and the text region, and the bi-level bitmap they all
  draw onto.
