// SPDX-License-Identifier: Apache-2.0

//! In-process PDF text extraction — full version, copied from upstream
//! (`io::binary::pdf`, the mother of all libs).
//!
//! Scope: classic xref tables, xref streams (PDF 1.5+), object streams
//! (`ObjStm`), the full filter zoo (Flate, LZW, ASCII85, ASCIIHex,
//! RunLength, PNG predictors), page-tree walking with inherited resources,
//! and font-aware text extraction — simple-font encodings
//! (WinAnsi/MacRoman/Differences) and CID fonts via `ToUnicode` CMaps.
//!
//! Image XObjects are outside *text* extraction, but they are reachable
//! through [`all_page_images`]: a scanned page has no text layer to extract,
//! so the picture is the whole content, and handing it to an OCR engine is
//! what makes a scanned PDF searchable at all. The scans that are not
//! pictures in the first place — a CCITT fax stream ([`fax`]) and a JBIG2
//! page ([`jbig2`]) — are decoded here, in house, before they are handed
//! over.
//!
//! Encrypted PDFs are handled by the standard security handler: the file
//! key is derived and proved against the file's own `/U` entry before
//! anything is decrypted, and a document whose `/U` does not reproduce is
//! declined rather than decrypted — a wrong key yields bytes that pass
//! every structural check and read as text, so nothing downstream could
//! tell a page of mojibake from a page of prose.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::boxed::Box;
#[cfg(feature = "pdf")]
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "pdf")]
use core::fmt::Write as _;
use rgx_core::Adapter;
#[cfg(feature = "pdf")]
use rgx_core::{Field, Outcome, Result};

#[cfg(feature = "pdf")]
pub mod fax;
#[cfg(feature = "pdf")]
pub mod jbig2;
#[cfg(feature = "pdf")]
mod pdf_full;
#[cfg(feature = "pdf")]
mod security;

#[cfg(feature = "pdf")]
pub use pdf_full::all_page_images;

#[cfg(feature = "pdf")]
use pdf_full::PdfReader;

pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        #[cfg(feature = "pdf")]
        Box::new(Pdf),
    ]
}

#[cfg(feature = "pdf")]
pub struct Pdf;

#[cfg(feature = "pdf")]
impl Adapter for Pdf {
    fn name(&self) -> &'static str {
        "pdf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pdf"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        match PdfReader::parse(data) {
            Ok(doc) => {
                let extracted = doc.extract_text_with_notes();
                let font_note = undecodable_note(&extracted);
                // Read the two facts about the rendering modes before the
                // text is moved out of the report.
                let has_invisible = extracted.has_invisible_runs();
                let entirely_invisible = extracted.is_entirely_invisible();
                let text = extracted.text;
                if text.trim().is_empty() && font_note.is_none() && !has_invisible {
                    // No page text, and no font to explain why. Bail, so the
                    // pipeline falls through to the raw-byte passthrough,
                    // which for a scanned or image-only PDF is strictly more
                    // searchable than the few metadata fields would be — it
                    // reaches strings inside every object stream. Returning
                    // metadata here would *lose* that.
                    Ok(Outcome::Bail("pdf: no extractable text".into()))
                } else {
                    // Document metadata is real searchable text, so emit it
                    // ahead of the page text. Values are flattened to a single
                    // line: a PDF string may contain raw newlines, which would
                    // otherwise inject forged lines into the corpus —
                    // including lines shaped like the "Page N:" markers,
                    // which downstream tooling parses to attribute a match to
                    // a page.
                    let pictures = page_pictures(&doc);
                    let mut out = String::new();
                    for (key, value) in doc.metadata() {
                        let flat = flatten_ws(&value);
                        if !flat.is_empty() {
                            let _ = writeln!(out, "{key}: {flat}");
                        }
                    }
                    out.push_str(&text);
                    if let Some(note) = &font_note {
                        out.push_str(note);
                    }
                    if let Some(note) = rendering_note(&extracted.runs, &pictures) {
                        out.push_str(&note);
                    }
                    // A document whose whole text layer is invisible is a
                    // picture with words under it: the pages show no text at
                    // all, and what the reader sees is the picture. So the
                    // picture is handed over for OCR -- and the hidden text
                    // stays in `text.txt`, because the OCR of the picture is
                    // ADDED to the hidden layer and never substituted for
                    // it. A document that lets its own OCR replace its text
                    // layer throws away words the file still holds.
                    if entirely_invisible && pictures.handed_pages > 0 {
                        let mut members = Vec::with_capacity(pictures.members.len() + 1);
                        members.push((String::from("text.txt"), out.into_bytes()));
                        members.extend(pictures.members);
                        return Ok(Outcome::Members(members));
                    }
                    Ok(Outcome::Text(out.into_bytes()))
                }
            }
            Err(pdf_full::PdfError::Encrypted) => Ok(Outcome::Bail("pdf: encrypted".into())),
            Err(_) => Ok(Outcome::Bail("pdf: unparseable".into())),
        }
    }

    /// The document's Info dictionary, as the facts a filter asks about.
    ///
    /// The names are the Info keys lowercased -- `title`, `author`,
    /// `subject`, `keywords`, `creator`, `producer`, `creationdate`,
    /// `moddate`. They are facts about the document itself and not about
    /// one of its parts, so they carry no namespace: `author` is the
    /// author, not `pdf.author`.
    ///
    /// The values are the ones the PDF holds, flattened to a single line.
    /// A PDF string may hold raw newlines, and a value broken across
    /// lines is a value a predicate cannot quote.
    ///
    /// **The cost.** The pipeline asks after `extract`, so the document
    /// is parsed a second time here -- and the parse is the expensive
    /// part of a PDF search. This is the price of not changing the shape
    /// of [`Outcome`] for the hundreds of call sites that build one, and
    /// it is paid only by the runs that ask a filter about a PDF.
    ///
    /// A document with no Info dictionary, or with one that names no
    /// author, reports no such fact. Absence is the honest answer.
    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        let Ok(doc) = PdfReader::parse(data) else {
            // Unparseable, encrypted or not a PDF at all: no facts. The
            // question is asked of a file this adapter could not read,
            // and the honest answer to a question about an unreadable
            // file is that there is nothing to say.
            return Vec::new();
        };
        doc.metadata()
            .into_iter()
            .filter_map(|(key, value)| {
                let value = flatten_ws(&value);
                if value.is_empty() {
                    // An empty value is not a fact: a predicate for it
                    // would match every document that happens to carry
                    // the key.
                    return None;
                }
                Some(Field::new(&key.to_ascii_lowercase(), &value))
            })
            .collect()
    }
}

/// A metadata value with its whitespace flattened to single spaces.
///
/// A PDF string may hold raw newlines and tabs, and a value that breaks
/// across lines is a value a predicate cannot quote -- and, in the
/// searchable text, a line break that would forge a line of its own.
#[cfg(feature = "pdf")]
fn flatten_ws(value: &str) -> String {
    let mut out = String::new();
    for word in value.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// The page images a document carries, and what became of each one.
///
/// A `/DCTDecode` page hands over the JPEG its stored bytes already are --
/// undoing that filter would destroy the image -- and a fax or JBIG2 page
/// hands over the PNG this crate built from the decoded scan. An image in
/// a codec this tree cannot undo is *named* and left out: a wrong picture
/// is worse than a named gap, and the name is what tells the user why
/// their page did not come back.
#[cfg(feature = "pdf")]
struct PagePictures {
    /// `(member name, bytes)` for every image that could be rendered.
    members: Vec<(String, Vec<u8>)>,
    /// The pages whose image could not be rendered, with the reason.
    skipped: Vec<String>,
    /// Pages that carry an image at all.
    pages_with_images: usize,
    /// Pages that had at least one image handed over.
    handed_pages: usize,
}

/// Collect the page images of a document, named for the OCR adapter.
///
/// The name carries the dotted extension the `docs` crate's OCR adapter
/// claims -- `ocr.jpg`, `ocr.png` -- so the member is offered to it before
/// the ordinary `jpg` reader, and a tesseract that is not installed leaves
/// the member to that reader instead of losing it. A second image on the
/// same page gets a number in the middle (`page-1.2.ocr.jpg`), which keeps
/// the claimed extension last: the dotted key is still offered, after the
/// numbered one.
#[cfg(feature = "pdf")]
fn page_pictures(doc: &pdf_full::PdfDocument<'_>) -> PagePictures {
    let mut out = PagePictures {
        members: Vec::new(),
        skipped: Vec::new(),
        pages_with_images: 0,
        handed_pages: 0,
    };
    for idx in 0..doc.page_count() {
        let images = doc.page_images(idx);
        if images.is_empty() {
            continue;
        }
        out.pages_with_images += 1;
        let mut handed = false;
        let mut on_page = 0usize;
        for image in images {
            let filter = image.filter;
            let (bytes, ext) = match (image.jpeg, image.png) {
                (Some(jpeg), _) => (jpeg, "jpg"),
                (None, Some(png)) => (png, "png"),
                (None, None) => {
                    out.skipped.push(if filter.is_empty() {
                        format!(
                            "page {} ({}x{} with no filter) could not be rendered",
                            idx + 1,
                            image.width,
                            image.height
                        )
                    } else {
                        format!(
                            "page {} ({}x{} {}) could not be rendered",
                            idx + 1,
                            image.width,
                            image.height,
                            filter
                        )
                    });
                    continue;
                }
            };
            on_page += 1;
            let name = if on_page == 1 {
                format!("page-{}.ocr.{ext}", idx + 1)
            } else {
                format!("page-{}.{on_page}.ocr.{ext}", idx + 1)
            };
            out.members.push((name, bytes));
            handed = true;
        }
        if handed {
            out.handed_pages += 1;
        }
    }
    out
}

/// One searchable line saying that the document's text was drawn in a
/// rendering mode that puts no ink on the page.
///
/// `3 Tr` and `7 Tr` are the two modes that neither fill nor stroke the
/// glyphs. A producer lays a text layer over a scan with them, so the page
/// reads as a picture while the text is still in the file. The reader
/// reads the text either way, so the note says which it did: a search over
/// a hidden layer that does not say the layer is hidden reads like a search
/// over visible text, and a file that answers identically with `0 Tr` and
/// with `3 Tr` cannot tell the two apart.
///
/// No note is emitted when nothing was drawn invisibly -- the note is only
/// worth anything if it is rare, and a document with no invisible run must
/// not grow a line.
#[cfg(feature = "pdf")]
fn rendering_note(runs: &pdf_full::RunReport, pictures: &PagePictures) -> Option<String> {
    if !runs.has_invisible() {
        return None;
    }
    if runs.is_entirely_invisible() {
        let ocr = if pictures.handed_pages > 0 {
            format!(
                "the page images of {} page(s) were handed over for OCR",
                pictures.handed_pages
            )
        } else if pictures.pages_with_images > 0 {
            format!(
                "the page images of {} page(s) could not be rendered, so none was handed over \
                 for OCR",
                pictures.pages_with_images
            )
        } else {
            String::from("the document carries no page image to hand over for OCR")
        };
        let layer = if runs.invisible_text > 0 {
            "the text above is that hidden layer"
        } else {
            "no part of that hidden layer reached the text above"
        };
        let skipped = if pictures.skipped.is_empty() {
            String::new()
        } else {
            format!("; {}", pictures.skipped.join(", "))
        };
        Some(format!(
            "[rgx: pdf: every text run on {} page(s) was drawn in an invisible rendering mode \
             (3 Tr or 7 Tr); {layer}, and {ocr}{skipped}]\n",
            runs.pages_with_invisible
        ))
    } else {
        let layer = if runs.invisible_text > 0 {
            "the hidden runs are in the text above"
        } else {
            "no part of the hidden runs reached the text above"
        };
        Some(format!(
            "[rgx: pdf: {} of {} text run(s) on {} page(s) were drawn in an invisible rendering \
             mode (3 Tr or 7 Tr); {layer}]\n",
            runs.invisible, runs.total, runs.pages_with_invisible
        ))
    }
}

/// One searchable line saying which fonts left text out of the extraction
/// and why, so a file that is only partly readable is accounted for instead
/// of quietly answering with the part that happened to decode.
///
/// The alternative this replaces read an unmapped code as Latin-1, which for
/// `tesla-valve.pdf`'s Type 3 fonts turned glyph `/a97` into the letter
/// `a` — plausible, and wrong, in general. A wrong line is a wrong search
/// result; a missing line is a visible gap. The same rule is why
/// `rgx_core::process` keeps a file's own bytes beside an adapter failure
/// note rather than in place of it.
///
/// No note is emitted when nothing was left out — the control case (a
/// TrueType subset with a `/ToUnicode` CMap) must not grow a line.
#[cfg(feature = "pdf")]
fn undecodable_note(e: &pdf_full::Extraction) -> Option<String> {
    if !e.is_partial() {
        return None;
    }
    let fonts: usize = e.undecodable.iter().map(|(_, n)| n).sum();
    let reasons = e
        .undecodable
        .iter()
        .map(|(why, _)| *why)
        .collect::<Vec<_>>()
        .join(" / ");
    let tail = if e.missing_fonts > 0 {
        format!(
            "; {} content-stream font name(s) were absent from /Resources",
            e.missing_fonts
        )
    } else {
        String::new()
    };
    Some(format!(
        "[rgx: pdf: {fonts} font(s) over {} page(s) had no decodable character encoding \
         ({reasons}){tail}; their glyphs are absent from the text above]\n",
        e.pages
    ))
}

#[cfg(all(test, feature = "pdf"))]
mod tests {
    //! Fixture tests: what each real and each constructed PDF has to yield.
    //!
    //! The failure these would miss is the silent kind. Every assertion is on
    //! exact characters or on the note, because a reader that answers with the
    //! wrong letter still returns a `String` and still looks like it works.
    //!
    //! `pdflatex-cm.pdf` and `lualatex-truetype.pdf` are real output. They were
    //! built with, and can be rebuilt by:
    //!
    //! ```text
    //! pdflatex  --disable-installer -interaction=nonstopmode cm.tex
    //! lualatex  --disable-installer -interaction=nonstopmode tt.tex
    //! ```
    //!
    //! where `cm.tex` is `\documentclass{article}\pagestyle{empty}\begin{document}
    //! \noindent Valvular calculus, please.\end{document}` (CM Type 1 subsets)
    //! and `tt.tex` is the same with `\usepackage{fontspec}` and
    //! `\setmainfont{Verdana}` over `C:/Windows/Fonts/verdana.ttf` (a Type 0 /
    //! CIDFontType2 TrueType subset). The two date strings and the `/ID` were
    //! then rewritten in place to fixed values of the same length, so a rebuild
    //! is byte-identical. `pdftotext` agrees with every assertion below.
    //!
    //! The other four are written by `scripts/make-pdf-fixtures.py`, because
    //! they are shapes no producer emits: a `/Type1` font that is not embedded
    //! and has nothing but a base encoding to go on, a `/Differences` array of
    //! glyph names that carry no Unicode, and a symbolic font with no encoding
    //! at all.
    use super::*;

    fn extract(data: &[u8]) -> Outcome {
        Pdf.extract(data, "t.pdf").unwrap()
    }

    fn text_of(data: &[u8]) -> String {
        let Outcome::Text(text) = extract(data) else {
            panic!("expected text, got a bail");
        };
        String::from_utf8(text).expect("adapter text is utf-8")
    }

    /// A classic-xref PDF holding the objects it is given, in order.
    struct Mini {
        buf: Vec<u8>,
        offsets: Vec<usize>,
    }

    impl Mini {
        fn new() -> Self {
            Self {
                buf: b"%PDF-1.4\n".to_vec(),
                offsets: Vec::new(),
            }
        }
        fn obj(&mut self, num: u32, body: &str) {
            self.offsets.push(self.buf.len());
            self.buf
                .extend_from_slice(format!("{num} 0 obj\n{body}\nendobj\n").as_bytes());
        }
        fn stream(&mut self, num: u32, data: &[u8]) {
            self.offsets.push(self.buf.len());
            self.buf.extend_from_slice(
                format!("{num} 0 obj\n<< /Length {} >>\nstream\n", data.len()).as_bytes(),
            );
            self.buf.extend_from_slice(data);
            self.buf.extend_from_slice(b"\nendstream\nendobj\n");
        }
        /// A stream whose dictionary says more than its length: an image
        /// XObject needs its filter and its dimensions, and a content
        /// stream needs nothing else.
        fn stream_with_dict(&mut self, num: u32, dict: &str, data: &[u8]) {
            self.offsets.push(self.buf.len());
            self.buf.extend_from_slice(
                format!("{num} 0 obj\n<< {dict} /Length {} >>\nstream\n", data.len()).as_bytes(),
            );
            self.buf.extend_from_slice(data);
            self.buf.extend_from_slice(b"\nendstream\nendobj\n");
        }
        fn finish(self, size: u32) -> Vec<u8> {
            self.finish_with_trailer(size, "")
        }
        /// The same document, with `extra` added to the trailer -- e.g.
        /// `/Info 5 0 R` for a document that carries an Info dictionary.
        fn finish_with_trailer(self, size: u32, extra: &str) -> Vec<u8> {
            let mut out = self.buf;
            let xref = out.len();
            out.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
            out.extend_from_slice(b"0000000000 65535 f \n");
            for off in &self.offsets {
                out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
            }
            let mut trailer = format!("<< /Size {size} /Root 1 0 R ");
            if !extra.is_empty() {
                trailer.push_str(extra);
                trailer.push(' ');
            }
            trailer.push_str(">>");
            out.extend_from_slice(
                format!("trailer\n{trailer}\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
            );
            out
        }
    }

    #[test]
    fn reportlab_real_file() {
        let text = text_of(include_bytes!("../fixtures/reportlab.pdf"));
        assert!(text.contains("Page 1:"), "{text}");
        assert!(text.contains("upstream mother of all libs"), "{text}");
        assert!(text.contains("segunda linha zebrada"), "{text}");
    }

    #[test]
    fn a_fully_decodable_document_grows_no_note() {
        // The note is only worth anything if it is rare. A base-14 Type 1
        // with `/Encoding /WinAnsiEncoding` and no `/ToUnicode` decodes
        // completely, so a `[rgx:` line here would be a lie.
        let text = text_of(include_bytes!("../fixtures/reportlab.pdf"));
        assert!(!text.contains("[rgx:"), "{text}");
    }

    #[test]
    fn a_type1_font_with_a_base_encoding_and_no_tounicode_yields_its_text() {
        let text = text_of(include_bytes!("../fixtures/type1-base-encoding.pdf"));
        assert!(text.contains("Valve the Tesla regulator"), "{text}");
        assert!(!text.contains("[rgx:"), "{text}");
    }

    #[test]
    fn a_differences_array_wins_over_the_base_encoding_beneath_it() {
        // 0x27 is `quoteright` and 0x60 is `quoteleft` under
        // StandardEncoding; 0xB1 and 0xD0 are `endash` and `emdash` and
        // come from the base encoding itself. Latin-1 would answer the
        // first two wrong and drop the last two. `pdftotext` reads this
        // file as U+2019 U+2018 U+2013 U+2014.
        let text = text_of(include_bytes!("../fixtures/type1-differences.pdf"));
        assert!(
            text.contains("Va\u{2019}lve\u{2019}s \u{2018}quoted\u{2018} \u{2013}em\u{2014}dash"),
            "{text:?}"
        );
        assert!(!text.contains('\''), "{text:?}");
        assert!(!text.contains('`'), "{text:?}");
        assert!(!text.contains("[rgx:"), "{text}");
    }

    #[test]
    fn a_pdflatex_document_reads_end_to_end() {
        // The producer of this crate's own flagship document, at 1/400th
        // the size: Type 1 subsets, `/ToUnicode` plus `/Encoding`, and an
        // indirect `/Resources`. Before the indirect-`/Resources` and the
        // `TJ`-array fixes this file extracted to nothing at all.
        let text = text_of(include_bytes!("../fixtures/pdflatex-cm.pdf"));
        assert!(text.contains("Valvular calculus, please."), "{text}");
        assert!(!text.contains("[rgx:"), "{text}");
    }

    #[test]
    fn a_truetype_subset_with_a_tounicode_cmap_reads_without_a_note() {
        // Type 0 / CIDFontType2, so the two-byte path: every code is a CID
        // and only the CMap can place it.
        let text = text_of(include_bytes!("../fixtures/lualatex-truetype.pdf"));
        assert!(text.contains("Valvular calculus, please."), "{text}");
        assert!(!text.contains("[rgx:"), "{text}");
    }

    #[test]
    fn an_opaque_type3_glyph_name_is_reported_rather_than_read_as_a_letter() {
        // The page also has a base-14 font, so the test has to see both
        // halves: the decodable text survives, the note names the gap, and
        // the two opaque codes 0x61/0x62 did not become the letters `a`
        // and `b`. Only the page text is searched for the letters — the
        // note contains the word "absent".
        let text = text_of(include_bytes!("../fixtures/type3-opaque-glyph-names.pdf"));
        let (page, note) = text.split_at(text.find("[rgx:").expect("a note"));
        assert!(page.contains("Valve the Tesla regulator"), "{page:?}");
        // A Latin-1 fallback would have made the two opaque codes the
        // letters `a` and `b`; the codes around them (0x51, 0x52) are not
        // in the font's /Differences at all, so nothing renders for them.
        assert!(!page.contains("QabR"), "{page:?}");
        assert!(!page.contains("ab"), "{page:?}");
        assert!(
            note.starts_with(
                "[rgx: pdf: 1 font(s) over 1 page(s) had no decodable character encoding"
            ),
            "{note}"
        );
        assert!(
            note.contains("/Differences names only glyphs with no Unicode"),
            "{note}"
        );
    }

    #[test]
    fn a_symbolic_font_with_no_encoding_reports_instead_of_bailing_to_raw_bytes() {
        // Every code in this document is undecodable, so the page text is
        // empty. The file must still answer with a searchable note: a
        // `Bail` here would hand the file back as its own compressed
        // bytes, which is the vanishing this crate's contract forbids.
        let text = text_of(include_bytes!("../fixtures/type1-symbolic-no-encoding.pdf"));
        assert!(
            text.contains("symbolic font whose encoding lives in the font program"),
            "{text}"
        );
        assert!(!text.contains("Valve"), "{text}");
    }

    #[test]
    fn a_scanned_pdf_with_no_fonts_at_all_still_bails_to_raw_bytes() {
        // The other half of the rule: with nothing to report, an empty page
        // must still bail, because for an image-only PDF the file's own
        // bytes are more searchable than its metadata would be.
        let mut b = Mini::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << >> /Contents 4 0 R >>",
        );
        b.stream(4, b"q 595 0 0 842 0 0 cm /Im0 Do Q");
        let pdf = b.finish(5);
        assert!(matches!(
            Pdf.extract(&pdf, "scan.pdf").unwrap(),
            Outcome::Bail(_)
        ));
    }

    #[test]
    fn non_pdf_bails() {
        assert!(matches!(
            Pdf.extract(b"not a pdf at all", "t.pdf").unwrap(),
            Outcome::Bail(_)
        ));
        assert!(matches!(
            Pdf.extract(b"", "t.pdf").unwrap(),
            Outcome::Bail(_)
        ));
    }

    #[test]
    fn never_panics_on_mutation() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                (
                    "reportlab",
                    include_bytes!("../fixtures/reportlab.pdf").to_vec(),
                ),
                (
                    "pdflatex",
                    include_bytes!("../fixtures/pdflatex-cm.pdf").to_vec(),
                ),
                (
                    "truetype",
                    include_bytes!("../fixtures/lualatex-truetype.pdf").to_vec(),
                ),
                (
                    "type3",
                    include_bytes!("../fixtures/type3-opaque-glyph-names.pdf").to_vec(),
                ),
                (
                    "invisible-text-over-an-image",
                    pdf_with_text_and_image(&page_content("3"), Some(TINY_JPEG)),
                ),
                (
                    "invisible-text",
                    pdf_with_text_and_image(&page_content("3"), None),
                ),
                (
                    "visible-text-over-an-image",
                    pdf_with_text_and_image(&page_content("0"), Some(TINY_JPEG)),
                ),
                (
                    "mixed-text",
                    pdf_with_text_and_image(
                        "BT /F1 14 Tf 0 Tr 20 100 Td [(Valve)-250(the)]TJ 3 Tr 20 80 Td \
                         (Hidden layer) Tj ET",
                        None,
                    ),
                ),
                ("magic-only", b"%PDF-1.4\n".to_vec()),
                ("empty", vec![]),
            ],
            2000,
            "pdf",
            |data| {
                let _ = Pdf.extract(data, "fuzz.pdf");
            },
        );
    }

    // --- the rendering mode ------------------------------------------------

    // A real 64x32 JPEG, so the page image the adapter hands over is a
    // picture and not a stand-in for one. It was written by ImageMagick:
    //
    //     magick -size 64x32 xc:white -depth 8 -quality 30 tiny.jpg
    //
    // The bytes are the file's, untouched: `/DCTDecode` *is* JPEG, and
    // undoing that filter would destroy the image.
    const TINY_JPEG: &[u8] = &[
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x1b, 0x12, 0x14, 0x17, 0x14,
        0x11, 0x1b, 0x17, 0x16, 0x17, 0x1e, 0x1c, 0x1b, 0x20, 0x28, 0x42, 0x2b, 0x28, 0x25, 0x25,
        0x28, 0x51, 0x3a, 0x3d, 0x30, 0x42, 0x60, 0x55, 0x65, 0x64, 0x5f, 0x55, 0x5d, 0x5b, 0x6a,
        0x78, 0x99, 0x81, 0x6a, 0x71, 0x90, 0x73, 0x5b, 0x5d, 0x85, 0xb5, 0x86, 0x90, 0x9e, 0xa3,
        0xab, 0xad, 0xab, 0x67, 0x80, 0xbc, 0xc9, 0xba, 0xa6, 0xc7, 0x99, 0xa8, 0xab, 0xa4, 0xff,
        0xc0, 0x00, 0x0b, 0x08, 0x00, 0x20, 0x00, 0x40, 0x01, 0x01, 0x11, 0x00, 0xff, 0xc4, 0x00,
        0x15, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00,
        0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0xff, 0xd9,
    ];

    /// The page's text, drawn in the given rendering mode.
    ///
    /// The two fixtures this builds differ in exactly one token, so the
    /// only thing that can tell their answers apart is the mode.
    fn page_content(mode: &str) -> String {
        format!("BT /F1 14 Tf {mode} Tr 20 100 Td (Valve the Tesla regulator) Tj ET")
    }

    /// A one-page PDF whose page draws `content` with a base-14 font and
    /// carries `image` as a `/DCTDecode` image XObject when one is given.
    ///
    /// The text layer and the picture are the two halves of the shape a
    /// producer makes when it lays words over a scan: the words are in
    /// the file, the picture is what the page shows.
    fn pdf_with_text_and_image(content: &str, image: Option<&[u8]>) -> Vec<u8> {
        let mut b = Mini::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        let resources = match image {
            Some(_) => "<< /Font << /F1 5 0 R >> /XObject << /Im0 6 0 R >> >>",
            None => "<< /Font << /F1 5 0 R >> >>",
        };
        b.obj(
            3,
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Resources {resources} \
                 /Contents 4 0 R >>"
            ),
        );
        b.stream(4, content.as_bytes());
        b.obj(
            5,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        );
        if let Some(bytes) = image {
            b.stream_with_dict(
                6,
                "/Type /XObject /Subtype /Image /Width 64 /Height 32 /ColorSpace /DeviceGray \
                 /BitsPerComponent 8 /Filter /DCTDecode",
                bytes,
            );
        }
        b.finish(if image.is_some() { 7 } else { 6 })
    }

    /// One member of a `Members` answer, by name.
    fn member(members: &[(String, Vec<u8>)], name: &str) -> Vec<u8> {
        members
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_else(|| {
                let names: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
                panic!("no member {name:?} in {names:?}");
            })
    }

    #[test]
    fn an_invisible_text_layer_does_not_answer_like_a_visible_one() {
        // The same page, drawn with `0 Tr` and with `3 Tr`. The visible
        // one puts its words on the page; the invisible one puts no ink
        // there at all, so a reader that answers them the same cannot
        // tell a text page from a blank one.
        let visible = text_of(&pdf_with_text_and_image(&page_content("0"), None));
        let invisible = text_of(&pdf_with_text_and_image(&page_content("3"), None));
        assert!(visible.contains("Valve the Tesla regulator"), "{visible}");
        assert!(
            !visible.contains("[rgx:"),
            "a visible page has nothing to report: {visible}"
        );
        // The hidden layer is still in the file, so the words are still
        // read: the note says they are hidden, it does not drop them.
        assert!(
            invisible.contains("Valve the Tesla regulator"),
            "{invisible}"
        );
        assert!(
            invisible.contains("invisible rendering mode"),
            "the note has to name the reason: {invisible}"
        );
        assert_ne!(visible, invisible);
    }

    #[test]
    fn an_invisible_text_layer_over_a_page_image_hands_the_image_over_for_ocr() {
        // The shape a producer makes when it lays words over a scan: the
        // page shows the picture and the words are under it. The picture
        // is what a reader sees, so it is handed over for OCR -- and the
        // hidden words stay in `text.txt`, because the OCR of the picture
        // is added to the hidden layer and never substituted for it.
        let pdf = pdf_with_text_and_image(&page_content("3"), Some(TINY_JPEG));
        let Outcome::Members(members) = extract(&pdf) else {
            panic!("expected members, got a text answer");
        };
        let text = String::from_utf8(member(&members, "text.txt")).expect("utf-8");
        assert!(text.contains("Valve the Tesla regulator"), "{text}");
        assert!(
            text.contains("invisible rendering mode"),
            "the note has to say the layer is hidden: {text}"
        );
        let image = member(&members, "page-1.ocr.jpg");
        assert_eq!(image, TINY_JPEG, "the page image, byte for byte");
    }

    #[test]
    fn a_document_with_no_invisible_run_grows_no_note() {
        // The note is only worth anything if it is rare. A page drawn
        // with `0 Tr` has nothing to report, so it must not grow a line
        // -- and it must not be handed over for OCR either, because its
        // words are on the page where a reader can see them.
        let pdf = pdf_with_text_and_image(&page_content("0"), Some(TINY_JPEG));
        let Outcome::Text(text) = extract(&pdf) else {
            panic!("expected text, got a members answer");
        };
        let text = String::from_utf8(text).expect("utf-8");
        assert!(text.contains("Valve the Tesla regulator"), "{text}");
        assert!(!text.contains("[rgx:"), "{text}");
    }

    #[test]
    fn an_invisible_text_layer_without_a_page_image_keeps_the_text() {
        // There is nothing to hand over, so there is no members answer --
        // but the hidden layer is still the document's text, and it must
        // not be lost on the way to a reader that can see nothing.
        let pdf = pdf_with_text_and_image(&page_content("3"), None);
        let text = text_of(&pdf);
        assert!(text.contains("Valve the Tesla regulator"), "{text}");
        assert!(
            text.contains("invisible rendering mode"),
            "the note has to name the reason: {text}"
        );
        assert!(
            text.contains("no page image"),
            "the note has to say there was nothing to hand over: {text}"
        );
    }

    #[test]
    fn a_page_with_both_visible_and_invisible_text_says_how_much_was_invisible() {
        // One visible run and one invisible one. The visible run is a `TJ`
        // array of three strings and it counts as ONE run: the array is one
        // show operation, and a note that counted its strings would report
        // a number the page does not have. So the note says one of two.
        let content = "BT /F1 14 Tf 0 Tr 20 100 Td [(Valve)-250(the)-250(regulator)]TJ \
                       3 Tr 20 80 Td (Hidden layer) Tj ET";
        let pdf = pdf_with_text_and_image(content, None);
        let text = text_of(&pdf);
        assert!(text.contains("Valve the regulator"), "{text}");
        assert!(text.contains("Hidden layer"), "{text}");
        assert!(
            text.contains(
                "[rgx: pdf: 1 of 2 text run(s) on 1 page(s) were drawn in an invisible rendering \
                 mode (3 Tr or 7 Tr); the hidden runs are in the text above]"
            ),
            "{text}"
        );
    }

    // --- the facts a filter asks about -------------------------------------

    /// A one-page PDF whose trailer points at an Info dictionary holding
    /// `info`.
    fn pdf_with_info(info: &str) -> Vec<u8> {
        let mut b = Mini::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << >> /Contents 4 0 R >>",
        );
        b.stream(4, b"");
        b.obj(5, info);
        b.finish_with_trailer(6, "/Info 5 0 R")
    }

    /// The value a fact carries, by name.
    fn fact_value(facts: &[Field], name: &str) -> Option<String> {
        facts
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.value.clone())
    }

    #[test]
    fn the_info_dictionary_answers_a_filter_about_the_document() {
        let pdf = pdf_with_info("<< /Title (Valvular calculus) /Author (ACME Corp) >>");
        let facts = Pdf.facts(&pdf, "t.pdf");
        assert_eq!(
            fact_value(&facts, "author").as_deref(),
            Some("ACME Corp"),
            "{facts:?}"
        );
        assert_eq!(
            fact_value(&facts, "title").as_deref(),
            Some("Valvular calculus"),
            "{facts:?}"
        );
        // The names are the Info keys, lowercased: these are facts about
        // the document and not about one of its parts, so they carry no
        // namespace -- `author` is the author, not `pdf.author`.
        assert!(facts.iter().all(|f| !f.name.contains('.')), "{facts:?}");
        assert!(fact_value(&facts, "Author").is_none(), "{facts:?}");
    }

    #[test]
    fn a_document_without_an_info_dictionary_reports_no_facts() {
        // Absence is the honest answer, and asking must not panic on a
        // document that has nothing to say.
        let mut b = Mini::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << >> /Contents 4 0 R >>",
        );
        b.stream(4, b"");
        let pdf = b.finish(5);
        let facts = Pdf.facts(&pdf, "t.pdf");
        assert!(facts.is_empty(), "{facts:?}");
    }

    #[test]
    fn an_info_dictionary_that_names_no_author_reports_no_author() {
        // The other half of absence: the keys that are there are
        // reported, and the one that is not stays unsaid.
        let pdf = pdf_with_info("<< /Title (Valvular calculus) >>");
        let facts = Pdf.facts(&pdf, "t.pdf");
        assert_eq!(
            fact_value(&facts, "title").as_deref(),
            Some("Valvular calculus"),
            "{facts:?}"
        );
        assert!(fact_value(&facts, "author").is_none(), "{facts:?}");
    }

    #[test]
    fn a_metadata_value_with_a_newline_comes_back_on_one_line() {
        // A PDF string may hold raw newlines. A value broken across
        // lines is a value a predicate cannot quote, so it comes back
        // flattened -- the same flattening the searchable text gets.
        let pdf = pdf_with_info("<< /Title (Valvular\ncalculus, please.) >>");
        let facts = Pdf.facts(&pdf, "t.pdf");
        let title = fact_value(&facts, "title").expect("a title fact");
        assert_eq!(title, "Valvular calculus, please.");
        assert!(!title.contains('\n'), "{title:?}");
    }

    #[test]
    fn facts_of_a_file_that_is_not_a_pdf_are_empty_and_never_panic() {
        assert!(Pdf.facts(b"not a pdf at all", "t.pdf").is_empty());
        assert!(Pdf.facts(b"", "t.pdf").is_empty());
    }

    #[test]
    fn a_real_document_reports_its_info_dictionary_and_skips_what_is_empty() {
        // A real producer's file. ReportLab writes an empty `/Keywords`,
        // and an empty value is not a fact: a predicate for it would
        // match every document that happens to carry the key.
        let facts = Pdf.facts(include_bytes!("../fixtures/reportlab.pdf"), "reportlab.pdf");
        assert_eq!(
            fact_value(&facts, "author").as_deref(),
            Some("anonymous"),
            "{facts:?}"
        );
        assert_eq!(
            fact_value(&facts, "title").as_deref(),
            Some("untitled"),
            "{facts:?}"
        );
        assert!(fact_value(&facts, "keywords").is_none(), "{facts:?}");
    }
}
