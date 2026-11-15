# rgx-adapters-pdf/src/jbig2

## Overview

The JBIG2 decoder, in the shape a PDF's `/JBIG2Decode` stream carries it.
JBIG2 (ITU-T T.88) is the bi-level image coding a scanned page usually
carries: a page is a rectangle of black and white pixels, and the file
describes it as a sequence of *segments* — dictionaries of reusable
symbols, regions of pixels, and the page information that says how big the
page is.

A PDF hands over two streams: the image stream itself, and optionally a
globals stream holding the dictionaries the page refers to. The page
information segment is *not* part of a PDF's stream — the size comes from
the image dictionary's `/Width` and `/Height` — so both entry points
exist: `decode` for a stream that carries its own page information, and
`decode_with_size` for one that does not.

The decoder is in-house: the MQ arithmetic coder, the arithmetic integer
procedures, the generic region, the symbol dictionary and the text region
are all implemented here, on top of a one-byte-per-pixel bi-level bitmap.

## Interface

- `pub fn decode(globals: Option<&[u8]>, data: &[u8]) -> Option<Jbig2Image>`
  — decode a stream that carries its own page information. `globals` is the
  optional globals stream (a PDF's `/JBIG2Globals`).
- `pub fn decode_with_size(globals: Option<&[u8]>, data: &[u8], width: u32,
  height: u32) -> Option<Jbig2Image>` — decode a stream whose page size the
  caller knows, as a PDF's `/JBIG2Decode` stream does.
- `pub struct Jbig2Image` — `pub width: u32`, `pub height: u32`,
  `pub pixels: Vec<u8>` (one byte per pixel, row-major: `0` = black,
  `255` = white).
- `pub const MAX_PIXELS: u64 = 64 * 1024 * 1024` — the ceiling on the
  pixels one bitmap may hold.
- `pub mod mq` — the MQ arithmetic decoder (T.88 Annex E):
  - `pub struct Context(pub u8)` — one of the 94 adaptive probability
    states.
  - `pub struct Decoder<'a>` with `pub fn new(data: &'a [u8]) -> Self`,
    `pub fn decode_bit(&mut self, context: &mut Context) -> u8`,
    `pub fn decode_bit_fixed(&mut self, context: &mut Context) -> u8`, and
    `pub fn context_table(len: usize) -> Vec<Context>`.
- `pub mod int` — the arithmetic integer decoding procedures (T.88 Annex A):
  - `pub const CONTEXTS_PER_PROC: usize = 512`,
  - `pub enum IntProc`, `pub enum Decoded`,
  - `pub struct IntegerContexts` with `pub fn reset(&mut self)` and
    `pub fn decode(&mut self, dec: &mut Decoder<'_>, proc: IntProc) ->
    Decoded`,
  - `pub struct IaidContexts` with `pub fn reset_for_bits(&mut self, bits:
    u8)`, `pub fn decode(&mut self, dec: &mut Decoder<'_>, bits: u8) -> u32`,
  - `pub fn code_length(count: usize) -> u8`.
- `pub mod segment` — the segment headers and types (T.88 §7.2 and §7.3):
  - the segment-type constants: `SYMBOL_DICTIONARY` (0),
    `INTERMEDIATE_TEXT_REGION` (4), `IMMEDIATE_TEXT_REGION` (6),
    `IMMEDIATE_LOSSLESS_TEXT_REGION` (7), `PATTERN_DICTIONARY` (16),
    `INTERMEDIATE_HALFTONE_REGION` (20),
    `IMMEDIATE_HALFTONE_REGION` (22),
    `IMMEDIATE_LOSSLESS_HALFTONE_REGION` (23),
    `INTERMEDIATE_GENERIC_REGION` (36), `IMMEDIATE_GENERIC_REGION` (38),
    `IMMEDIATE_LOSSLESS_GENERIC_REGION` (39),
    `INTERMEDIATE_REFINEMENT_REGION` (40),
    `IMMEDIATE_REFINEMENT_REGION` (42),
    `IMMEDIATE_LOSSLESS_REFINEMENT_REGION` (43),
    `PAGE_INFORMATION` (48), `END_OF_PAGE` (49), `END_OF_STRIPE` (50),
    `END_OF_FILE` (51), `PROFILES` (52), `TABLES` (53), `EXTENSION` (62);
  - `pub const UNKNOWN_LENGTH: u32 = 0xFFFF_FFFF`;
  - `pub struct SegmentHeader`, `pub struct Segment<'a>`,
    `pub fn split(data: &[u8]) -> Vec<Segment<'_>>`.
- `pub mod generic` — generic region decoding (T.88 §6.2 and §7.4.6):
  - `pub struct GenericRegion<'a>`,
  - `pub fn parse(data: &[u8], unknown_length: bool) ->
    Option<GenericRegion<'_>>`,
  - `pub fn decode(region: &GenericRegion<'_>) -> Option<Bitmap>`,
  - `pub fn decode_with(...)`.
- Private modules (their types are reachable through the entry points
  above): `bitmap` (`Bitmap`, `new`, `get`, `set`, `copy_row_above`,
  `combine`), `region` (`RegionInfo`, `LENGTH = 17`, `parse`), `symbol`
  (`SymbolDictionary`, `decode`), `text` (`TextRegion`, `decode`).

## Invariants

- **The MQ decoder follows T.88 §E.3.1 exactly.** `C` is a 32-bit register
  whose high half (`Chigh`) carries the comparisons, `A` is the 16-bit
  interval register, `0x8000` is the renormalisation threshold, and
  `INITDEC`, `DECODE`, `RENORMD` and `BYTEIN` follow the flowcharts of
  Figures E.15 to E.20. The probability estimate lives in a 94-state
  machine (T.88 Table E.1).
- The arithmetic integer procedures keep their own bank of 512 adaptive
  probability estimates, because the context is "IAx" followed by the nine
  bits of the procedure's own history register `PREV`. **IAID is the odd
  one out**: it codes a symbol ID as a fixed number of bits walking a
  binary tree, so its context is the tree node itself.
- The generic region's context is the pixel neighbourhood called a
  *template* (T.88 Figures 3 to 6). Four templates exist, of 16, 13, 10
  and 10 pixels. The bits of the context are the template's pixel values
  gathered **in reading order — top row to bottom row, and left to right
  within a row** — with the first gathered pixel as the most significant
  bit. T.88 leaves the order "not standardised", but it fixes the value of
  the context used for the typical-prediction bit (Figures 8 to 11).
- A generic region has two codings: arithmetic (every pixel a binary
  decision under a context taken from the pixels around it) and MMR (the
  region is simply a T.6 Group 4 fax bitmap).
- The segment header is **variable length**: the page association is one
  or four bytes, and the referred-to segment count field is one byte or a
  run of bytes depending on how many segments are referred to. Getting
  that length wrong shifts every later segment, so the parser here reads
  the header as a whole and reports the payload it actually found.
- A stream that holds less than a segment's header says is refused: the
  page it would decode into is a page with its marks missing, which reads
  as if it were whole.
- `MAX_PIXELS` is the same refusal the fax decoder makes for an image the
  container only *claims* is large. A JBIG2 region is decoded a pixel at a
  time, so a header that says "four billion pixels" is not a slow page, it
  is a page that never ends.
- **A variant the decoder does not implement is refused, not approximated.**
  In the symbol dictionary, the Huffman variant (Annex B) and the
  refinement/aggregate variant (`SDREFAGG = 1`) are refused: both change
  what the bytes mean, and a dictionary decoded wrongly places the wrong
  glyphs in the right places, which is the worst kind of wrong. In the text
  region, the Huffman variant (`SBHUFF = 1`) needs the code tables of
  T.88 Annex B and is refused too.
- A symbol dictionary's symbols are grouped into *height classes*:
  symbols of the same height, decoded one after another, with the first
  symbol's width and each following width given as a difference.
- A text region is a list of *symbol instances*, each a symbol ID and a
  position, drawn onto the region's bitmap. The positions are coded as a
  run of strips (rows of text) and, within a strip, a sequence of S
  coordinates that usually differ by a constant.
- Every region segment's data part opens with the same seventeen bytes
  (`RegionInfo::LENGTH`): the size and position of the bitmap it carries,
  and the operator that merges it into the page. The merge operators are
  the external combination operators of T.88 §7.4.1.5 (OR, AND, XOR, XNOR,
  REPLACE).
- The bitmap is one byte per pixel, `1` = black, `0` = white — T.88's
  numbering, used throughout the decoder. The gray-scale conversion the
  PDF path needs happens once, at the boundary (`Jbig2Image::pixels` uses
  `0` = black, `255` = white).

## Side Effects

- None. Every entry point is a pure function over `&[u8]`: nothing is read
  from disk, no process is spawned, no socket is opened, no clock or
  environment variable is consulted, and no lock is taken. The decoder
  allocates through `alloc`.

## Verification

- Run: `cargo test --release --locked --workspace`
