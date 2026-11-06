# rgx-adapters-office/src

## Overview

The implementation of the office family. `lib.rs` holds the crate's shell,
the `adapters()` factory, the `xml_to_text` pass and the three readers that
live there; the other modules hold one format family each.

The shape of the family is a consequence of what each format is. The
container formats (OOXML, ODF, EPUB, VSDX, XPS) are zips of XML parts, read
in-process and rendered to plain text. The binary formats (`.doc`, `.ppt`,
`.xls`, `.vsd`) are OLE compound files, read with the shared CFB reader in
`rgx_core::cfb`. The text formats (RTF, TeX, and the markup family) are
files ripgrep already reads, so their adapters *render* rather than answer.

## Interface

The crate's public surface is the factory, the `xml_to_text` pass and the
three readers that live in `lib.rs`; every other reader below lives in a
private module, so it is crate-internal and no item of it is nameable from
outside the crate.

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes, in feature order: `Office`, `Rtf`, `Doc`, `ppt::Ppt`,
  `xls::Xls`, `tex::Tex`, `visio::Visio`, `markup::Markup`,
  `legacy::AbiWord`, `legacy::HwpRaw`, `legacy::WordPerfect`.
- `pub fn xml_to_text(xml: &[u8]) -> String` (feature `office`) — strip
  tags, newline at paragraph-ish boundaries, unescape entities. Byte-level,
  no XML stack: malformed parts degrade gracefully. Public because it is
  the tree's **only** XML → text pass — the docs crate feeds it the flat
  ODF that `soffice` writes for MS Publisher, whose document type has no
  text export filter to convert into instead.
- `pub struct Office` (feature `office`) — the zip-of-XML containers. `impl
  Adapter`: `name() == "office"`,
  `extensions() == &["docx", "docm", "dotx", "dotm", "xlsx", "xlsm",
  "xltx", "xltm", "pptx", "pptm", "potx", "potm", "ppsx", "odt", "ott",
  "ods", "ots", "odp", "otp", "odg", "odgi", "odi", "otg", "epub", "vsdx",
  "vssx", "vstx", "xps", "oxps"]`.
- `pub struct Doc` (feature `doc`) — legacy Word 97-2003. `impl Adapter`:
  `name() == "doc"`, `extensions() == &["doc", "dot"]`.
- `pub struct Rtf` (feature `rtf`) — `impl Adapter`: `name() == "rtf"`,
  `extensions() == &["rtf"]`.
- `pub struct ppt::Ppt` (feature `ppt`) — crate-internal: `impl Adapter`:
  `name() == "ppt"`, `extensions() == &["ppt", "pot", "pps"]`. The module
  also exposes `pub fn extract_text(data: &[u8]) -> Result<String>`.
- `pub struct xls::Xls` (feature `xls`) — crate-internal: `impl Adapter`:
  `name() == "xls"`, `extensions() == &["xls", "xlt", "xlm"]`. The module
  also exposes `pub fn extract_text(data: &[u8]) -> Result<String>`.
- `pub struct visio::Visio` (feature `visio`) — crate-internal: `impl
  Adapter`: `name() == "visio"`, `extensions() == &["vsd"]`. The module
  also exposes `pub fn extract_text(data: &[u8]) -> Result<String>`.
- `pub struct tex::Tex` (feature `tex`) — crate-internal: `impl Adapter`:
  `name() == "tex"`, `extensions() == &["tex", "latex", "ltx"]`. The module
  also exposes `pub fn extract_text(data: &[u8]) -> Result<String>`.
- `pub struct markup::Markup` (feature `markup`) — crate-internal: the
  lightweight markup family. `impl Adapter`: `name() == "markup"`,
  `extensions()` covering reStructuredText (`rst`), org-mode (`org`),
  MediaWiki wikitext (`mediawiki`, `wiki`), Jupyter notebooks (`ipynb`),
  Textile (`textile`), troff/groff man pages (`man`, and the `1`..`9` man
  sections), Markdown (`md`, `markdown`, `gfm`), HTML (`html`, `htm`,
  `xhtml`), Txt2Tags (`t2t`) and FictionBook 2 (`fb2`).
- `pub struct legacy::AbiWord` (feature `abiword`) — crate-internal: `impl
  Adapter`: `name() == "abiword"`, `extensions() == &["abw"]`.
- `pub struct legacy::HwpRaw` (feature `hwp`) — crate-internal: Hangul
  Word Processor 5.0 raw record stream. `impl Adapter`: `name() ==
  "hwp-raw"`, `extensions() == &["hwd"]`.
- `pub struct legacy::WordPerfect` (feature `wordperfect`) — crate-internal:
  `impl Adapter`: `name() == "wordperfect"`, `extensions() == &["wpd",
  "wps", "wfb"]`.

## Invariants

- **Everything is in-process.** No external tool is spawned for any format
  in this crate; the zip is read in-process and the XML rendered in-process.
- **`Reach` is part of the contract.** The text formats — RTF, TeX and the
  markup family — declare `Reach::Render`: ripgrep already reads them, so
  under the default policy the file's own bytes are the answer and the
  renderer is not consulted, while under `RGX_ADAPTER_VIEW=render` the
  rendering is what gets searched. The binary and container formats keep
  the default `Reach::Reveal`.
- The RTF stripper and the TeX detex pass are a strict subset of the file's
  own bytes *as a search space* — they drop the control words, the
  preamble, the comments and the verbatim environments — which is exactly
  why they are renderings and not answers.
- The TeX pass drops the preamble, the comments and the control words,
  unwraps section titles and skips verbatim environments; math delimiters
  are dropped but their content is kept, because for grep the symbols inside
  math are usually still meaningful.
- The XML → text pass is byte-level with no XML stack, so a malformed part
  degrades gracefully instead of failing the document.
- The `Office` adapter's parts are bounded: at most `MAX_PART` (8 MiB) per
  XML part and at most `MAX_OUT` (16 MiB) of total extracted text; the loop
  stops when the next section would cross the total.
- The zip is read under the archive crate's shared producer budget
  (`budget::MemberSink`), so a document is capped by `-M` /
  `RGX_MAX_MEMBER_BYTES` like every other container, and the truncation note
  reaches the pipeline as an ordinary member instead of being dropped in
  silence.
- The container kind is chosen from the file's **extension**
  (`kind_of`), and an extension with no kind is declined ("unsupported
  office extension") rather than answered.
- The xlsx path is cell-aware: the shared string table is resolved and the
  cells are emitted as `A1: value` lines — the same shape the legacy `.xls`
  reader produces, so the two agree on what a spreadsheet says.
- The `.doc` reader uses the shared CFB reader and the `WordDocument`
  stream; the table stream is chosen from the FIB's `fWhichTblStm` flag
  (`1Table` when set, `0Table` otherwise), and the piece table resolves the
  text. A stream shorter than the FIB, or a `wIdent` that is not `0xA5EC`,
  is refused.
- The `.ppt` reader walks `UserEditAtom` → `PersistDirectoryAtom`(s) →
  persisted record trees and harvests `TextCharsAtom` (UTF-16LE) /
  `TextBytesAtom` (cp1252) / `CStringAtom` leaves. If the edit chain is
  broken (quirky producers, truncated files), a validated linear scan over
  the stream recovers the same atoms at the cost of document order.
- The `.xls` reader walks the `Workbook` stream's record chain: a globals
  substream (BoundSheet8 directory + shared string table) followed by one
  worksheet substream per sheet. Nothing else in the file is decoded.
- The `.vsd` reader walks the `VisioDocument` stream — a forest of
  sub-streams addressed by absolute offset, each holding either a chunk
  sequence or a single blob, optionally compressed with the Visio LZSS
  variant (4096-byte window). Text lives in `VSD_TEXT` (0x0e) chunks: an
  8-byte prefix followed by UTF-16LE (format version 11) or ANSI
  (versions 1-6) characters. Only text is interpreted; geometry, styles
  and stencils are walked past. The grammar was read from LibreOffice's
  `libvisio`; the code here is rgx's own.
- The `.doc` adapter claims `dot` because a Word 97-2003 template is the
  same binary format as the document that gave the format its name — the
  same `WordDocument` stream, the same FIB, the same piece table. A
  template that nothing can read is a document that cannot be found.
- **Claiming an extension is `may`, not `does`.** The `Office` adapter
  claims `odi` and `odgi` in its extension list, but `kind_of` maps
  neither, so such a file is claimed and then declined with "unsupported
  office extension" and its raw bytes stay searchable. The ZIP-based
  members of the "legacy office" family are claimed elsewhere: the
  archive adapter takes `uof`, `uot`, `uos` and `uop`, and the inspect
  crate's compound reader takes `sxw`.
- `.hwp` has two shapes and the two are kept apart: the OLE2 wrapper is
  handled by the compound reader, and the raw record stream — which starts
  with its own signature, the string `HWP Document File` repeated twice
  256 bytes apart — is claimed under its own extension (`hwd`).
- The AbiWord reader handles both shapes: an `.abw` is gzip and is
  decompressed, and the plain-text fallback (an `abw` saved as XML without
  compression) is passed through. Decompressing is what turns a document
  ripgrep skips into one it reads.
- The WordPerfect reader checks the `\xFFWPC` 5.x product code in bytes
  0..4 before it reads anything.

## Side Effects

- None on the filesystem, the network, the clock or the environment: every
  adapter is a pure function over `&[u8]`, and no process is spawned.
- The `office` feature reads the archive crate's **process-wide producer
  budget** (`rgx_adapters_archive::budget`), which the owning binary
  configures from `RGX_MAX_MEMBERS` and `RGX_MAX_MEMBER_BYTES`. The crate
  itself neither writes nor mutates it.

## Verification

- Run: `cargo test --release --locked --workspace`
