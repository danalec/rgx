// SPDX-License-Identifier: Apache-2.0

//! The JBIG2 decoder against the corpus it has to be right about.
//!
//! The `.jb2` files are the streams a JBIG2 encoder produced, and the
//! `.expected.pbm` files are the bitmaps that went in — the oracle, not a
//! round trip: a decoder that agreed with the encoder it was tested
//! against would prove that the two share a misreading, and this corpus
//! was built by a third-party encoder that is not the oracle.
//!
//! The bitmaps are the two shapes the format has to carry: `jbig2_blocks`
//! is stems, wide blocks and tight combs, the shapes a generic region has
//! to match against a template; `jbig2_text` is a page of rendered text,
//! the shape a symbol dictionary exists for. `jbig2_narrow` is the blocks
//! bitmap again, small enough to sweep exhaustively.
//!
//! One thing about these PBMs is worth stating outright, because the
//! format says the opposite. The PBM standard has a set bit mean black;
//! these files were written by packing a PIL "1" image, where a set bit
//! means *white*, and the corpus' own one-byte-per-pixel bitmaps — the
//! ones the reference decoders were checked against, and the ones every
//! correct decode reproduces exactly — are the expansion of the set bit to
//! `255`. The other reading is their exact complement, so a decoder that
//! came out right would fail this test on every pixel of the page. See
//! `SET_BIT_IS_WHITE`.

#![cfg(feature = "pdf")]

use rgx_adapters_pdf::jbig2::{decode, Jbig2Image};

/// Which way round this corpus' PBM bits are.
///
/// `true` for the corpus that is in the tree: the set bit is the white one.
/// The comment at the top of the file is the long version.
const SET_BIT_IS_WHITE: bool = true;

fn fixture(name: &str, kind: &str) -> Vec<u8> {
    let path = format!(
        "{}/testdata/jbig2/{name}.{kind}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The globals segment a stream refers to, when it has one. The symbol
/// stream needs the dictionary; the generic ones do not have one at all.
fn globals(name: &str) -> Option<Vec<u8>> {
    let path = format!(
        "{}/testdata/jbig2/{name}.globals",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).ok()
}

/// The bitmap a PBM (P4) holds, in the decoder's convention: one byte per
/// pixel, `0` = black, `255` = white.
///
/// The header is `P4`, then the width and the height separated by
/// whitespace, then a single whitespace byte, then the raster: one bit per
/// pixel, each row padded to a whole number of bytes, most significant bit
/// first within the byte.
fn read_pbm(raw: &[u8]) -> (u32, u32, Vec<u8>) {
    assert_eq!(&raw[..2], b"P4", "not a P4 PBM");
    let mut i = 2;
    let mut fields: Vec<u32> = Vec::new();
    while fields.len() < 2 {
        while i < raw.len() && (raw[i] as char).is_whitespace() {
            i += 1;
        }
        if i < raw.len() && raw[i] == b'#' {
            while i < raw.len() && raw[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        while i < raw.len() && !(raw[i] as char).is_whitespace() {
            i += 1;
        }
        let num = std::str::from_utf8(&raw[start..i])
            .unwrap_or_else(|e| panic!("PBM header is not text: {e}"))
            .trim()
            .parse::<u32>()
            .unwrap_or_else(|e| panic!("PBM header field is not a number: {e}"));
        fields.push(num);
    }
    i += 1; // the single whitespace byte that ends the header
    let (w, h) = (fields[0], fields[1]);
    let stride = (w as usize).div_ceil(8);
    let raster = &raw[i..i + stride * h as usize];

    let (black, white) = if SET_BIT_IS_WHITE {
        (0u8, 255u8)
    } else {
        (255u8, 0u8)
    };
    let mut pixels = Vec::with_capacity(w as usize * h as usize);
    for y in 0..h as usize {
        for x in 0..w as usize {
            let bit = (raster[y * stride + (x >> 3)] >> (7 - (x & 7))) & 1;
            pixels.push(if bit == 1 { white } else { black });
        }
    }
    (w, h, pixels)
}

/// Every stream, and the bitmap it has to come back as.
fn corpus() -> Vec<(&'static str, &'static str)> {
    vec![
        ("jbig2_blocks.arith_t0", "jbig2_blocks"),
        ("jbig2_blocks.arith_t1", "jbig2_blocks"),
        ("jbig2_blocks.arith_t2", "jbig2_blocks"),
        ("jbig2_blocks.arith_t3", "jbig2_blocks"),
        ("jbig2_blocks.generic", "jbig2_blocks"),
        ("jbig2_blocks.symbol", "jbig2_blocks"),
        ("jbig2_narrow.arith_t0", "jbig2_narrow"),
        ("jbig2_narrow.arith_t1", "jbig2_narrow"),
        ("jbig2_narrow.arith_t2", "jbig2_narrow"),
        ("jbig2_narrow.arith_t3", "jbig2_narrow"),
        ("jbig2_narrow.generic", "jbig2_narrow"),
        ("jbig2_narrow.symbol", "jbig2_narrow"),
        ("jbig2_text.arith_t0", "jbig2_text"),
        ("jbig2_text.arith_t1", "jbig2_text"),
        ("jbig2_text.arith_t2", "jbig2_text"),
        ("jbig2_text.arith_t3", "jbig2_text"),
        ("jbig2_text.generic", "jbig2_text"),
        ("jbig2_text.symbol", "jbig2_text"),
    ]
}

/// The streams whose truncation is worth sweeping exhaustively: a generic
/// region, and the text region that needs a globals segment to mean
/// anything at all.
fn hostile() -> Vec<&'static str> {
    vec!["jbig2_blocks.arith_t0", "jbig2_text.symbol"]
}

/// How many pixels of `got` are not the expected ones.
fn differing_pixels(got: &Jbig2Image, expected: &[u8]) -> usize {
    got.pixels
        .iter()
        .zip(expected.iter())
        .filter(|(a, b)| a != b)
        .count()
}

#[test]
fn every_fixture_decodes_to_the_bitmap_the_encoder_was_given() {
    for (stream, bitmap) in corpus() {
        let data = fixture(stream, "jb2");
        let g = globals(stream);
        let (w, h, expected) = read_pbm(&fixture(bitmap, "expected.pbm"));

        let got = decode(g.as_deref(), &data).unwrap_or_else(|| panic!("{stream} did not decode"));
        assert_eq!(
            (got.width, got.height),
            (w, h),
            "{stream}: decoded size is not the bitmap's"
        );
        assert_eq!(
            got.pixels.len(),
            expected.len(),
            "{stream}: decoded length is not the bitmap's"
        );
        let differing = differing_pixels(&got, &expected);
        assert_eq!(differing, 0, "{stream}: {differing} pixels differ");
    }
}

#[test]
fn an_empty_or_truncated_stream_is_refused_and_never_panics() {
    for stream in hostile() {
        let data = fixture(stream, "jb2");
        let g = globals(stream);
        let whole = decode(g.as_deref(), &data)
            .unwrap_or_else(|| panic!("{stream}: the whole stream must decode"));

        assert!(
            decode(g.as_deref(), &[]).is_none(),
            "{stream}: an empty stream must be refused"
        );
        assert!(
            decode(None, &[]).is_none(),
            "{stream}: an empty stream must be refused with no globals too"
        );

        // Every prefix of a real stream, truncated: none of them may panic,
        // and none of them may decode into something that disagrees with
        // the page. A prefix that only lost the trailing fill may still
        // decode the whole page — that is the same page, not a different
        // one — so the invariant is agreement with the full decode, not a
        // smaller one. A page that comes back blank, or with the marks
        // missing, is a different page, and handing it over as one is the
        // failure this catches: the data ran out, and the reader that ran
        // out of data must not have a page to hand over.
        for cut in 0..data.len() {
            if let Some(got) = decode(g.as_deref(), &data[..cut]) {
                assert_eq!(
                    got.width, whole.width,
                    "{stream}: a truncated stream must not change the page's width (cut {cut})"
                );
                assert!(
                    got.pixels.len() <= whole.pixels.len(),
                    "{stream}: a truncated stream must not yield more than the whole one (cut {cut})"
                );
                let differing = differing_pixels(&got, &whole.pixels);
                assert_eq!(
                    differing, 0,
                    "{stream}: a truncated stream must not decode into a different page \
                     (cut {cut}, {differing} pixels differ)"
                );
            }
        }
    }
}

#[test]
fn a_truncated_globals_segment_is_refused_and_never_panics() {
    // The dictionary the text region places its symbols from. A dictionary
    // that stops halfway is a dictionary the reader cannot use, and a page
    // assembled from half of it is a different page.
    let stream = "jbig2_text.symbol";
    let data = fixture(stream, "jb2");
    let g = globals(stream).unwrap_or_else(|| panic!("{stream}: the fixture has globals"));
    let whole =
        decode(Some(&g), &data).unwrap_or_else(|| panic!("{stream}: the whole stream must decode"));

    for cut in 0..g.len() {
        if let Some(got) = decode(Some(&g[..cut]), &data) {
            assert_eq!(
                (got.width, got.height),
                (whole.width, whole.height),
                "{stream}: a truncated globals must not change the page's size (cut {cut})"
            );
            let differing = differing_pixels(&got, &whole.pixels);
            assert_eq!(
                differing, 0,
                "{stream}: a truncated globals must not decode into a different page \
                 (cut {cut}, {differing} pixels differ)"
            );
        }
    }
}
