# rgx-adapters-docs

## Overview

The long-tail adapter family of `rgx`: the only family in the tree whose
answers come from **external binaries** rather than from in-process readers.
Two adapters live here — LibreOffice (`soffice`) and Tesseract OCR — and each
one detects its binary on `PATH` inside `available()`, so a machine that has
neither still gets the complete in-process adapter set from the other
families. Nothing is spawned unless a matching file is actually found.

The crate is `std`-only by nature: it spawns processes, so it declares no
`std` feature and is not part of the `no_std` port. Its two adapters are
feature-gated (`soffice`, `ocr`, both on by default), and each feature drags
in exactly the sibling crate it borrows one function from: `soffice` borrows
`rgx_adapters_office::xml_to_text`, `ocr` borrows
`rgx_adapters_pdf::all_page_images`.

Most of what the crate used to claim was moved in-process: `ffmpeg`/`ffprobe`
gave way to the media crate's own `avi`/`asf`/`flv`/`mpeg` readers, and
`antiword` gave way to the office crate's in-process FIB + piece-table reader
for legacy `.doc`. What remains for `soffice` is the single format nothing
else reads well: MS Publisher (`.pub`).

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `adapters()` factory, the `ProcAdapter` subprocess harness with its
  `Prepared` payload split, the `Soffice` converter, the `ocr()` adapter and
  the poppler page-rasterising fallback. Public symbols: `pub fn
  adapters()`, `pub struct Soffice`, and `impl Adapter` for each of the two
  adapters; the `ocr` feature alone carries `pub fn ocr() -> ProcAdapter`,
  `pub struct ProcAdapter` and `pub struct Prepared`, so a build with only
  `soffice` has neither type.
