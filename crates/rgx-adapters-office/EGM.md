# rgx-adapters-office

## Overview

The office / OpenDocument / e-book family of `rgx`, fully in-process: no
external tool is ever spawned for these formats. The container formats are
zips of XML parts, read in-process and rendered to plain text — OOXML
(docx/xlsx/pptx), ODF (odt/ods/odp/odg), EPUB, VSDX, XPS — and the binary
formats have their own readers: the legacy Word FIB + piece table, binary
PowerPoint, binary Excel, binary Visio, RTF, TeX, and the lightweight
markup family (reStructuredText, org-mode, MediaWiki wikitext, Jupyter
notebooks, Textile, troff/groff man pages, Markdown, HTML, Txt2Tags and
FictionBook 2).

The family also owns the formats that are neither zip nor OLE2: AbiWord's
gzipped XML, Hangul Word Processor's raw record stream, and WordPerfect's
compound binary header.

Each adapter sits behind a Cargo feature named after the format it reads
(`office`, `rtf`, `doc`, `ppt`, `xls`, `tex`, `visio`, `markup`, `abiword`,
`hwp`, `wordperfect`), and the default build carries all of them. The
`office` feature pulls in `rgx-adapters-archive`, because a zipped document
is read under the archive crate's shared producer budget.

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `adapters()` factory, the `xml_to_text` pass the tree shares with the
  docs crate, the container readers in `lib.rs` (`Office`, `Doc`, `Rtf`),
  the binary readers (`ppt`, `xls`, `visio`), the markup family in
  `markup.rs`, the TeX detex pass in `tex.rs`, and the non-zip legacy
  formats in `legacy.rs`. Public symbols: `pub fn adapters()`, `pub fn
  xml_to_text(&[u8]) -> String`, `pub struct Office`, `pub struct Doc`,
  `pub struct Rtf`, and `impl Adapter` for each adapter. The readers of
  the private modules — `ppt::Ppt`, `xls::Xls`, `visio::Visio`, `tex::Tex`,
  `markup::Markup`, `legacy::AbiWord`, `legacy::HwpRaw`,
  `legacy::WordPerfect` and the per-module `extract_text` helpers — are
  crate-internal and are not nameable from outside the crate.
