// SPDX-License-Identifier: Apache-2.0

//! The CCITT decoder against the corpus it has to be right about.
//!
//! The `.strip` files are the fax streams libtiff produced, and the
//! `.expected` files are the bitmaps that went in — one byte per pixel,
//! `0` = black. The comparison is byte for byte against the *encoder's*
//! input, not against a round trip: a decoder that agreed with the
//! encoder it was tested against would prove that the two share a
//! misreading, and this session has already produced three cases where a
//! confident reading of a format was simply wrong.
//!
//! The pixels in these fixtures were chosen to force the 2D modes — long
//! stems, wide blocks, tight combs and wide white gaps — so a decoder that
//! handles only the common path fails here rather than in the field.

#![cfg(feature = "pdf")]

use rgx_adapters_pdf::fax::{decode_fax, FaxParams};

fn fixture(name: &str, kind: &str) -> Vec<u8> {
    let path = format!("{}/testdata/{name}.{kind}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Every fixture, with the parameters a PDF's `/CCITTFaxDecode` dictionary
/// would carry for it.
fn corpus() -> Vec<(&'static str, i64, u32, u32)> {
    vec![
        ("fax_g4", 0, 1720, 280),
        ("fax_g4_narrow", 0, 640, 200),
        ("fax_g4_text", 0, 1240, 320),
        ("fax_g3", -1, 800, 200),
        ("fax_g3_text", -1, 1240, 320),
    ]
}

fn params(k: i64, columns: u32, rows: u32) -> FaxParams {
    FaxParams {
        k,
        columns,
        rows,
        black_is_1: false,
        byte_align: false,
    }
}

#[test]
fn every_fixture_decodes_to_the_bitmap_the_encoder_was_given() {
    for (name, k, columns, rows) in corpus() {
        let strip = fixture(name, "strip");
        let expected = fixture(name, "expected");
        let got = decode_fax(&strip, &params(k, columns, rows))
            .unwrap_or_else(|| panic!("{name} did not decode"));
        assert_eq!(got.len(), expected.len(), "{name}: decoded length");
        let differing = got
            .iter()
            .zip(expected.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(differing, 0, "{name}: {differing} pixels differ");
    }
}

#[test]
fn a_stream_that_cannot_fill_its_rows_is_refused_rather_than_half_decoded() {
    // A page that claims more rows than the stream carries has to come back
    // as nothing, or as the rows it really holds — never as a page that
    // stops in the middle. The two cases are told apart by what ended the
    // stream, and the fixtures were measured to differ exactly there: the
    // Group 3 fixture runs out of data with no terminator, while the Group 4
    // one ends with the encoder's own `EOFB`.
    let (name, k, columns, rows) = ("fax_g3", -1, 800, 200);
    let strip = fixture(name, "strip");
    assert!(
        decode_fax(&strip, &params(k, columns, rows + 10)).is_none(),
        "{name}: data that ran out must not be handed over as a page"
    );

    let (name, k, columns, rows) = ("fax_g4", 0, 1720, 280);
    let strip = fixture(name, "strip");
    let whole = decode_fax(&strip, &params(k, columns, rows)).expect("the fixture decodes");
    assert_eq!(whole.len(), columns as usize * rows as usize);
    let over = decode_fax(&strip, &params(k, columns, rows + 10))
        .expect("a block the encoder ended is not a truncation");
    assert_eq!(
        over.len(),
        whole.len(),
        "{name}: the rows the block holds are the answer, and no more"
    );
}

#[test]
fn an_empty_or_truncated_stream_is_refused_and_never_panics() {
    let (name, k, columns, rows) = corpus()[0];
    let strip = fixture(name, "strip");
    let whole = decode_fax(&strip, &params(k, columns, rows))
        .unwrap_or_else(|| panic!("{name}: the whole stream must decode"));

    assert!(decode_fax(&[], &params(k, columns, rows)).is_none());
    // Every prefix of a real stream, truncated: none of them may panic, and
    // none of them may decode into something that disagrees with the page.
    // A prefix that only lost the trailing fill may still decode the whole
    // page — that is the same page, not a different one — so the invariant
    // is agreement with the full decode, not a smaller one.
    for cut in 0..strip.len() {
        if let Some(pixels) = decode_fax(&strip[..cut], &params(k, columns, rows)) {
            assert!(
                pixels.len() <= whole.len(),
                "a truncated stream must not yield more than the whole one"
            );
            assert_eq!(
                pixels,
                whole[..pixels.len()],
                "a truncated stream must not decode into a different page"
            );
        }
    }
}
