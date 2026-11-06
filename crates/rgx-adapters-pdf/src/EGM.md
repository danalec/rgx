# rgx-adapters-pdf/src

## Overview

The implementation of the PDF family. `lib.rs` holds the crate's `no_std`
shell, the `adapters()` factory and the `Pdf` adapter; `pdf_full.rs` holds
the document parser; `security.rs` holds the standard security handler;
`fax.rs` holds the CCITT decoder; `jbig2/` holds the JBIG2 decoder.

The crate's own header states the boundary that shapes everything else:
image XObjects are outside *text* extraction but reachable through
`all_page_images`, because a scanned page has no text layer — the picture
is the whole content, and the scans that are not pictures in the first
place (a CCITT fax stream, a JBIG2 page) are decoded here, in house, before
they are handed over.

## Interface

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes. The crate holds exactly one adapter.
- `pub struct Pdf` (feature `pdf`) — `impl Adapter`: `name() == "pdf"`,
  `extensions() == &["pdf"]`.
- `pub use pdf_full::all_page_images` (feature `pdf`) — the entry point the
  docs crate's OCR adapter uses: every page image of a document, with the
  JPEG bytes, the PNG bytes, the filter name and the dimensions of each.
- `pub mod fax` (feature `pdf`) — the ITU-T T.4 (Group 3) / T.6 (Group 4)
  decoder:
  - `pub struct FaxParams` — `/K` (`k: i64`; 0 is Group 4, -1 is Group 3,
    a positive value is the number of 1D-encoded rows in that many 2D rows
    — mixed coding), `/Columns` (`columns: u32`, pixels per row),
    `/Rows` (`rows: u32`; 0 or absent means "until the data ends"), and the
    remaining decode parameters.
  - `pub fn decode_fax(data: &[u8], p: &FaxParams) -> Option<Vec<u8>>` —
    the decoder. **Every entry point here is total**: a malformed,
    truncated or empty stream answers `None`. Half a scan is not a scan,
    and an OCR engine handed one reports a bad image rather than a bad
    page.
- `pub mod jbig2` (feature `pdf`) — the JBIG2 decoder (ITU-T T.88): the
  bi-level image coding a scanned page usually carries. Its public symbols
  are `pub fn decode(Option<&[u8]>, &[u8]) -> Option<Jbig2Image>`,
  `pub fn decode_with_size(Option<&[u8]>, &[u8], u32, u32) ->
  Option<Jbig2Image>`, `pub struct Jbig2Image` (`width`, `height`,
  `pixels`), `pub const MAX_PIXELS`, the MQ arithmetic coder in
  `pub mod mq` (`Context`, `Decoder`, `decode_bit`, `decode_bit_fixed`,
  `context_table`), the arithmetic integer procedures in `pub mod int`
  (`IntProc`, `Decoded`, `IntegerContexts`, `IaidContexts`,
  `code_length`), the segment headers in `pub mod segment` (the segment
  type constants, `SegmentHeader`, `Segment`, `split`), and the generic
  region in `pub mod generic` (`GenericRegion`, `parse`, `decode`). See
  [jbig2/EGM.md](./jbig2/EGM.md).
- `pdf_full` (private module, feature `pdf`) — the document parser. Its
  public surface inside the crate:
  - `pub enum PdfError` and `pub type PdfResult<T> = Result<T, PdfError>`.
  - `pub struct PdfDocument<'a>` with `pub fn parse(data: &'a [u8]) ->
    PdfResult<Self>`, `pub fn resolve(&self, num: u32) -> Option<PdfObject>`,
    `pub fn deref(&self, obj: &PdfObject) -> Option<PdfObject>`,
    `pub fn is_encrypted_open(&self) -> bool`.
  - `pub struct PdfReader` with `pub fn parse(data: &[u8]) ->
    PdfResult<PdfDocument<'_>>` — the entry point that mirrors the other
    binary-format readers. The page and metadata methods — `page_count`,
    `page_text`, `page_text_with_runs`, `page_images`, `all_images`,
    `extract_text_with_notes` and `metadata` — are methods of
    `PdfDocument`, not of the reader.
  - `pub enum PdfObject` — the object model.
  - `pub struct Extraction` (`text`, `undecodable`, `missing_fonts`,
    `pages`, `runs`) with `is_partial()`, `has_invisible_runs()` and
    `is_entirely_invisible()`. There is no `notes` field and no
    `page_count()` method: the page count is the `pages` field, and the
    document's page count is `PdfDocument::page_count()`.
  - `pub struct FontReport` and `pub struct RunReport`
    (`has_invisible()`, `is_entirely_invisible()`).
  - `pub struct PageImage` and `pub fn all_page_images(data: &[u8]) ->
    Vec<PageImage>`.
  - The filter decoders, all in-tree: `pub fn inflate`,
    `pub fn zlib_decode`, `pub fn png_predictor`, `pub fn lzw_decode`,
    `pub fn ascii85_decode`, `pub fn asciihex_decode`,
    `pub fn runlength_decode`.
  - `pub fn decode_text_string(bytes: &[u8]) -> String` and
    `pub fn decode_text_string_into(bytes: &[u8], out: &mut String)`.
- `security` (private module, feature `pdf`) — the standard security
  handler:
  - `pub enum SecurityError` — `Malformed(&'static str)` (a required
    `/Encrypt` entry is absent or the wrong type; the text says which),
    `PasswordRequired` (the derived key does not reproduce `/U`), and
    `Unsupported(&'static str)` (a scheme this module does not implement,
    named).
  - `pub struct Security` with `pub fn new(encrypt: &[(String, PdfObject)],
    id: &[u8]) -> Result<Security, SecurityError>`, `pub fn decrypt_stream(
    &self, num: u32, gen: u16, data: &[u8]) -> Option<Vec<u8>>` and
    `pub fn decrypt_string(&self, num: u32, gen: u16, data: &[u8]) ->
    Option<Vec<u8>>`.

## Invariants

- The crate is `#![no_std]` + `alloc`: nothing here touches the filesystem,
  the clock, the environment, a socket or a process.
- **A key is proved before it is used.** The standard security handler
  derives a file key and then *checks it against the file's own `/U` entry*
  before decrypting anything. A document whose `/U` does not reproduce is
  declined, not decrypted: a wrong key yields bytes that pass every
  structural check and read as text, so nothing downstream could tell a
  page of mojibake from a page of prose.
- The security handler's scope is the part a byte-slice reader can honestly
  answer: **an empty user password**. That is not a corner case — a file
  printed from a Word export, or written by most scanners, carries
  `/Encrypt` and still opens in any viewer without a prompt.
- What stays out of the handler, and why: a **non-empty user password** (it
  is a secret, and a search tool has no business guessing one or picking
  one up from the environment — the honest answer is a decline, which
  leaves the file's raw bytes searchable); **non-standard handlers**
  (`/Filter` values other than `/Standard` have no published algorithm);
  **public-key handlers** (`/V` 6 with `/Recipients` populated is a
  different scheme); and **revision 5** (deprecated, and — unlike revision
  6 — its `/U` carries no tag that independently confirms a derived key).
- Three rules of the key derivation, each of which the obvious reading
  gets wrong, and each settled by measurement against libqpdf 12.4.2:
  - **RC4 mixes the object number too.** The common claim that "RC4 uses
    the file key unchanged and only AES mixes it in" is false, and following
    it produces a reader that decrypts nothing at revision 2 or 3 — the two
    revisions that are still all over older corpora.
  - **AES-128 appends the literal `sAlT`** to the digest before the second
    hash. It is in the specification, it is in every implementation, and
    nobody remembers it. It is appended to the *running hash*, not to its
    output: feeding the first digest's bytes into a fresh MD5 instead is a
    different computation that produces a different key, and the failure is
    a padding check on the first AES block — indistinguishable, to a
    reader, from a corrupt file.
  - **`/V` 5 uses the file key as is** (Algorithm 1.A), with no object
    number and no second hash. Deriving one for revision 6 breaks the
    newest and most common revision in the wild.
- The cipher comes from `/V`, not from `/R`: a revision 4 and a revision 6
  file differ in how the key is *derived*, while `/V` says what is done
  with it afterwards. `/V` 0 ("not encrypted") and `/V` 3 (an unpublished
  algorithm with no specification to implement) are **declines, not
  errors** — the pipeline wants a bail there, not a note.
- The RC4 key length is taken from the **cipher**, not from `/V`: `/V` 2
  exists precisely to allow a longer RC4 key, and taking the length from
  the version silently truncates every 128-bit RC4 file to five bytes.
  That truncation does not fail visibly — Algorithm 2 still produces a
  key, just the wrong one, and the `/U` proof is the only thing that
  catches it.
- A font whose codes cannot be placed is *reported* via
  `Extraction::undecodable`, never guessed at; `lib.rs` turns that into one
  `[rgx: pdf: …]` line beside the text that did decode.
- **Metadata values are flattened to a single line.** A PDF string may
  contain raw newlines, which would otherwise inject forged lines into the
  corpus — including lines shaped like the "Page N:" markers, which
  downstream tooling parses to attribute a match to a page.
- A document with no page text, no font note and no invisible run **bails**
  ("pdf: no extractable text"), so the pipeline falls through to the
  raw-byte passthrough — which for a scanned or image-only PDF is strictly
  more searchable than the few metadata fields would be, because it reaches
  strings inside every object stream. Returning metadata there would
  *lose* that.
- A document whose whole text layer is invisible is a picture with words
  under it: the pages show no text at all, so the picture is handed over
  for OCR — and the hidden text stays in the text unit, because the OCR of
  the picture is the truth and the hidden text is not.
- All the filter decoders are in-tree; no external compression crate is
  used. LZW is MSB-first with `EarlyChange`; the PNG predictors 10–15 come
  through `/DecodeParms`.
- The fax decoder is a **program**, not a bitmap: a 2D code says "this
  row's changing element sits at the reference line's element `b1`, shifted
  by this much", and the reader has to have tracked the previous row's
  changing elements to place it. Getting the reference line wrong does not
  produce garbage, it produces a plausible image that is shifted, and a
  shifted scan OCRs to noise rather than failing loudly.
- The JBIG2 decoder is in the same family of traps: it is refused rather
  than approximated when the variant is one it does not implement (the
  Huffman variants and the refinement/aggregate symbol dictionary), because
  a dictionary decoded wrongly places the wrong glyphs in the right places,
  which is the worst kind of wrong.

## Side Effects

- None. Everything is a pure function over `&[u8]`: nothing is read from
  disk, no process is spawned, no socket is opened, no clock or environment
  variable is consulted, and no lock is taken.
- One piece of hygiene is part of the contract: `Security` implements no
  `Debug` at all — neither a derive nor a manual impl — so the file key
  cannot reach a log line through it. These values decrypt a document; a
  key in a log line is a key in a log line, whatever the log is for.

## Verification

- Run: `cargo test --release --locked --workspace`
