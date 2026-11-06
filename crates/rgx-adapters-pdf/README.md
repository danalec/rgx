# rgx-adapters-pdf

In-process PDF text extraction. One adapter, one extension, and the crate
depends on `rgx-core` alone.

## What it claims

`pdf` claims `pdf`, and declares `Reach::Reveal`: the bytes on disk are
not text ripgrep can read.

## How it works

The reader covers classic xref tables, xref streams (PDF 1.5+), object
streams, the filter zoo (Flate, LZW, ASCII85, ASCIIHex, RunLength, PNG
predictors), page-tree walking with inherited resources, and font-aware
text: simple-font encodings (WinAnsi, MacRoman, Differences) and CID fonts
resolved through `ToUnicode` CMaps.

Document metadata is emitted ahead of the page text, one line per value.
The values are flattened because a PDF string may contain raw newlines,
which would otherwise inject lines shaped like the page markers that
downstream tooling parses to attribute a match to a page.

Three cases bail rather than answer, so the pipeline falls through to the
raw-byte passthrough: an encrypted file whose scheme or password is out of
scope; an unparseable one; and a file with no extractable text and no font
to explain why. That last is the scanned-PDF case, where the raw bytes
reach strings inside every object stream and returning metadata would lose
them.

## Encrypted PDFs

The standard security handler is implemented in `security.rs`, for
revisions 2, 3, 4 and 6: RC4 at 40 and 128 bits, AES-128 and AES-256. The
scope is an **empty user password**, which is what almost every PDF carrying
`/Encrypt` uses — it opens in any viewer without a prompt, because only the
owner password guards it.

Two rules make that scope safe rather than merely convenient:

- **A key is proved before it is used.** The derived key must reproduce the
  `/U` entry (ISO 32000-1 Algorithm 6, or the revision-6 tag). A key that
  does not is discarded and the file is declined, because decrypting with
  it would produce bytes that look like text and are not.
- **A non-empty user password is a refusal, not a failure.** It is a secret.
  The file's own bytes stay searchable, which is the right answer for a
  document nobody can open.

Revision 5 is declined on purpose: its `/U` carries no tag that independently
confirms a derived key. Non-standard handlers (`/Adobe.PubSec`, the Acrobat 3
bullet scheme) and public-key handlers are named and declined.

Three details in the object-key derivation are load-bearing, and each is
where the obvious reading is wrong — see `Security::object_key`:

1. **RC4 mixes the object number too.** The common claim that RC4 uses the
   file key unchanged, and only AES mixes it in, is false. Following it
   decrypts nothing at revision 2 or 3.
2. **AES-128 appends the literal `sAlT`** to the running hash before the
   second digest.
3. **`/V` 5 uses the file key as is** (Algorithm 1.A), with no object number
   and no second hash.

All three were settled by measurement against libqpdf 12.4.2 rather than by
reading the specification, which is wrong about each of them in a way that
produces a working-looking reader.

The MD5, RC4, AES and SHA-384/512 primitives come from `rgx-core::crypt`,
each validated against a published specification vector rather than against
itself.

When a font left text out of the extraction, a `[rgx: pdf: …]` line says
how many fonts, over how many pages, and why — so a partly readable file
is accounted for instead of quietly answering with the part that happened
to decode. No note is emitted when nothing was left out.

## Scanned pages

The crate does not OCR anything itself, but it does hand out the pictures: a
PDF's page images are extracted, and the `docs` adapter gives them to an
external `tesseract`. A `/DCTDecode` image already *is* a JPEG, so it is
passed along as it stands.

**CCITT G3 and G4 are not.** A faxed page is a run-length program against the
previous row, not a picture, so `fax.rs` decodes it: ITU-T T.4 (Group 3) and
T.6 (Group 4) in the shape a PDF's `/CCITTFaxDecode` stream carries them, with
the 2D modes placing each row's changing elements against the previous row's.
The result is wrapped as a PNG by `rgx-core::png` — grey, stored-deflate,
because its job is to be handed to a subprocess and thrown away.

Three rules in that decoder are load-bearing, and each is where the obvious
reading is wrong:

1. **The first `a0` of a line is imaginary** — it sits *before* the first
   picture element, and the first run is coded as `a0a1 - 1` (T.6 §2.2.5.1).
   The arithmetic folds that `-1` in, but the reference lookup still has to see
   the virtual position, or the reference line's element at 0 is not "to the
   right of `a0`" and every vertical on the line is misplaced.
2. **`VR` and `VL` are different code words** — Table 1/T.6 names `VR` the mode
   that puts `a1` to the *right* of `b1` and `VL` the one that puts it to the
   left, and the seven-bit pair shares the prefix `000001`, so the tree splits
   on the seventh bit.
3. **A `b1` that is not detected sits on the line's width** — T.6 §2.2.5.2
   puts it on the imaginary changing element just after the reference line's
   last actual element, which is where a vertical that closes a line gets its
   position from.

A row that cannot be decoded takes the whole image with it: half a scan reads
as a bad image rather than a bad page, and the difference is invisible to
whoever is handed the result.

The corpus is compared byte for byte against the *encoder's* input, not
against a round trip — a decoder that agreed with the encoder it was tested
against would prove that the two share a misreading. `tests/fax_fixtures.rs`
carries five streams produced by libtiff and their bitmaps, and every one of
them is a case the decoder has to be right about.

**JBIG2 is not either.** A JBIG2 page (ITU-T T.88) is a program against a
pixel template and a dictionary of glyphs, not a picture, so `jbig2/`
decodes it: the arithmetic generic regions, the symbol dictionary, and the
text region that places the dictionary's glyphs on the page. The result is
wrapped as a PNG by `rgx-core::png`, like the fax one.

Two rules in that decoder are load-bearing, and each is where the obvious
reading is wrong:

1. **The MQ coder does not advance its state on every symbol.** T.88 §E.3.2
   puts the update of `I(CX)` from the NMPS column *inside* the
   renormalisation discussion; the plain path says only that "if A is not less
   than `0x8000`, then the MPS sense stored at CX is used to set the decoded
   decision D". JPEG 2000's MQ coder — the one most people carry in their
   heads — updates the state there, and getting that wrong does not fail
   loudly: it decodes a page that is blank except at the end.
2. **The context is the template read in reading order** — top row to bottom
   row, and left to right within a row, the first pixel most significant.
   T.88 leaves the order "not standardised", but the value of the context
   used for the typical-prediction bit is fixed (Figures 8 to 11), and it only
   comes out right under reading order: template 0's is `0x9B25`.

A segment whose header declares more data than the stream holds takes the
whole page with it: half a page reads as a page that is missing its marks,
and the difference is invisible to whoever is handed the result.

The variants this decoder does not implement — the Huffman codings
(Annex B) and the refinement/aggregate codings — are refused rather than
approximated, because each of them changes what the bytes mean. The corpus
is again compared byte for byte against the encoder's input;
`tests/jbig2_fixtures.rs` carries the streams and their bitmaps.

**A hidden text layer is not a scan.** The rendering mode IS tracked: the text
state follows the content stream, so text drawn with `3 Tr` is known to be
invisible, and text drawn with `7 Tr` is known to be invisible and clipped. A
document whose text layer is *entirely* invisible and that carries page images
answers with both views: the hidden text stays in a `text.txt` member, and the
page images are handed over as `page-N.ocr.jpg`, which the `docs` adapter
OCRs. The two are not alternatives — the layer is the file's own content and
the picture is the page — so the OCR of the picture is *added* to the layer and
neither replaces the other. A document with both visible and invisible runs
says how many of each it has, and keeps the text. A file named `*.ocr.pdf` is
still routed to the `docs` adapter, and still means "OCR this file's pages".

## Licence

Apache-2.0 only. See [LICENSE-APACHE](https://github.com/danalec/rgx/blob/main/crates/rgx-adapters-pdf/LICENSE-APACHE), and the
repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) for what the licence covers and what
it does not.