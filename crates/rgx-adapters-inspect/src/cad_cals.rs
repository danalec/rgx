// SPDX-License-Identifier: Apache-2.0

//! The **CALS Raster** file (MIL-STD-1840A), read as a rendering.
//!
//! **What a CALS Raster file is.** A 2048-byte ASCII header followed by a
//! raster image. The header holds eleven 128-byte records — `srcdocid`,
//! `dstdocid`, `txtfilid`, `figid`, `srcgph`, `doccls`, `rtype`, `rorient`,
//! `rpelcnt`, `rdensity` and `notes`, in that order — each written as
//! `<identifier>: <value>` and padded with spaces to 128 bytes; the last 640
//! bytes of the header are padding. The image data starts at offset 2048.
//!
//! **Why it is revealed and not rendered.** `rg` cannot read the file. The
//! image data is a compressed raster, and the header is a fixed-column form
//! whose records are padded to 128 bytes, so the value of a record and the
//! next record's identifier sit 100-odd spaces apart. This is
//! [`Reach::Reveal`]: the adapter surfaces bytes the raw searcher cannot
//! reach.
//!
//! **What the rendering is for.** The record and the image are two
//! different things, and a search has to join them: `rpelcnt` says how many
//! pels the image has, `rdensity` says how large they are, and the bytes at
//! offset 2048 are the picture of them. The rendering puts the joined fact
//! on the first line — `cals: type 1, 1728x2200 pels at 200 dpi, ...` — and
//! each record on a line of its own, so "the size of the image and what the
//! file says about it" is one pattern and not two.
//!
//! **What it does not do.** It does not decode the image. The pel count and
//! the density are what the header says, the pixels behind them are not
//! read, and a type 2 file — which holds several pages and a tile index
//! rather than one T.6 stream — is reported as what its header says and
//! nothing more.

use alloc::string::{String, ToString};
use core::fmt::Write as _;
use rgx_core::{decline, Adapter, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost.
const MAX_RENDER: usize = 64 << 20;

/// The header of a CALS Raster file: 2048 bytes of ASCII.
const HEADER_LEN: usize = 2048;

/// A record of the header: 128 bytes.
const RECORD_LEN: usize = 128;

/// The eleven header records, in the order MIL-STD-1840A fixes.
const RECORDS: [&str; 11] = [
    "srcdocid", "dstdocid", "txtfilid", "figid", "srcgph", "doccls", "rtype", "rorient", "rpelcnt",
    "rdensity", "notes",
];

/// The index of `rtype` in [`RECORDS`].
const REC_RTYPE: usize = 6;
/// The index of `rorient` in [`RECORDS`].
const REC_RORIENT: usize = 7;
/// The index of `rpelcnt` in [`RECORDS`].
const REC_RPELCNT: usize = 8;
/// The index of `rdensity` in [`RECORDS`].
const REC_RDENSITY: usize = 9;

/// A CALS Raster file.
pub struct Cals;

impl Adapter for Cals {
    fn name(&self) -> &'static str {
        "cals"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["cal", "ct1", "ct2"]
    }

    /// The image data is compressed raster and the header is a padded
    /// fixed-column form: `rg` reads neither.
    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_cals(data)?.into_bytes()))
    }
}

/// The CALS header: the records as the file wrote them, and the ones the
/// standard gives a meaning to.
struct Header {
    /// The eleven record values, in the standard's order.
    raw: [String; 11],
    /// The raster type: 1 is a single Group 4 image, 2 the multi-page form.
    rtype: u8,
    /// The pels per row, from `rpelcnt`.
    width: u32,
    /// The scan lines, from `rpelcnt`.
    height: u32,
    /// The density in pels per inch, from `rdensity`.
    density: u32,
}

impl Header {
    /// The value of the record at `i`.
    fn record(&self, i: usize) -> &str {
        self.raw.get(i).map(String::as_str).unwrap_or("")
    }
}

/// The CALS Raster rendering: the header's records, and the image they
/// describe.
fn render_cals(data: &[u8]) -> Result<String> {
    let header = parse_header(data)?;

    let summary = format!(
        "cals: type {}, {}x{} pels at {} dpi, orientation {}",
        header.rtype,
        header.width,
        header.height,
        header.density,
        header.record(REC_RORIENT)
    );

    let mut body = String::new();
    // Every record, on a line of its own: the record values are what the
    // header says, and the summary above is what they mean together.
    for (name, value) in RECORDS.iter().zip(header.raw.iter()) {
        let _ = writeln!(body, "{name}: {value}");
    }

    // The image data, which starts where the header ends.
    let image = data.get(HEADER_LEN..).unwrap_or(&[]);
    match header.rtype {
        1 => {
            if image.is_empty() {
                let _ = writeln!(
                    body,
                    "image data: none (the file ends at the {HEADER_LEN}-byte header)"
                );
            } else {
                let _ = writeln!(
                    body,
                    "image data: {} bytes of CCITT Group 4 (T.6) data, {}",
                    image.len(),
                    if has_eofb(image) {
                        "ending in the EOFB"
                    } else {
                        "without the EOFB"
                    }
                );
            }
        }
        _ => {
            // A type 2 file holds a band structure and a tile index, not one
            // T.6 stream: the header is read and the pages are not invented.
            let _ = writeln!(
                body,
                "image data: {} bytes, not decoded (a type 2 file holds a band structure, not a single T.6 stream)",
                image.len()
            );
        }
    }

    Ok(finish(&summary, &body))
}

/// Reads the header: the eleven records, and the three that have a meaning
/// beyond their text.
fn parse_header(data: &[u8]) -> Result<Header> {
    // The first record names the format. A file that does not open with it
    // is some other format, and declining is what lets the next adapter
    // have it.
    match data.get(..RECORD_LEN) {
        Some(head) if head.starts_with(b"srcdocid:") => {}
        Some(_) => decline!("cals: the header does not open with 'srcdocid:'"),
        None => decline!("cals: the file is shorter than one 128-byte header record"),
    }
    // The header is 2048 bytes; a file that stops inside it is truncated.
    if data.len() < HEADER_LEN {
        decline!(
            "cals: the header is {} bytes, not the {HEADER_LEN} the standard fixes",
            data.len()
        );
    }

    let mut raw: [String; 11] = core::array::from_fn(|_| String::new());
    for (i, name) in RECORDS.iter().enumerate() {
        let start = i * RECORD_LEN;
        let Some(record) = data.get(start..start + RECORD_LEN) else {
            decline!("cals: the header ends inside record {i} ('{name}')");
        };
        // The record is `<identifier>: <value>`, padded with spaces.
        let prefix = format!("{name}: ");
        let Some(head) = record.get(..prefix.len()) else {
            decline!("cals: record {i} ('{name}') is too short to hold its identifier");
        };
        if head != prefix.as_bytes() {
            decline!(
                "cals: record {i} does not begin with '{}'",
                prefix.trim_end()
            );
        }
        // The header is 7-bit ASCII; a byte outside it means this is not
        // the record the standard describes.
        let value = &record[prefix.len()..];
        if !value.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            decline!("cals: record {i} ('{name}') is not 7-bit ASCII");
        }
        if let Some(slot) = raw.get_mut(i) {
            *slot = String::from_utf8_lossy(value).trim().to_string();
        }
    }

    // The raster type: 1 is a single Group 4 image, 2 the multi-page form.
    let rtype = match raw[REC_RTYPE].as_str() {
        "1" => 1u8,
        "2" => 2u8,
        other => decline!("cals: the rtype record is '{other}', not 1 or 2"),
    };

    // The pel count: the pels per row and the scan lines.
    let (width, height) = match split_pair(&raw[REC_RPELCNT]) {
        Some(pair) => pair,
        None => decline!(
            "cals: the rpelcnt record is '{}', not two numbers",
            raw[REC_RPELCNT]
        ),
    };

    // The density, in pels per inch.
    let density = match raw[REC_RDENSITY].parse::<u32>() {
        Ok(value) => value,
        Err(_) => decline!(
            "cals: the rdensity record is '{}', not a number",
            raw[REC_RDENSITY]
        ),
    };

    Ok(Header {
        raw,
        rtype,
        width,
        height,
        density,
    })
}

/// Two numbers separated by a comma, as `rpelcnt` writes them.
fn split_pair(text: &str) -> Option<(u32, u32)> {
    let (left, right) = text.split_once(',')?;
    let left = left.trim().parse::<u32>().ok()?;
    let right = right.trim().parse::<u32>().ok()?;
    Some((left, right))
}

/// Whether the stream ends with the 24-bit EOFB.
///
/// The EOFB is the last 24 bits of the *bit* stream and the padding to the
/// byte boundary follows it, so the pattern is looked for at each of the
/// eight places a byte boundary can put it.
fn has_eofb(data: &[u8]) -> bool {
    /// `000000000001000000000001`
    const EOFB: u32 = 0x001_001;
    let Some(tail) = data.get(data.len().saturating_sub(4)..) else {
        return false;
    };
    // The last 32 bits, big-endian. A stream shorter than that leaves the
    // EOFB in the low bits, where it belongs.
    let mut bits: u32 = 0;
    for byte in tail {
        bits = (bits << 8) | u32::from(*byte);
    }
    // The EOFB is the last 24 bits of the *bit* stream and the padding to
    // the byte boundary follows it, so the pattern is looked for at each
    // of the eight places a byte boundary can put it.
    (0..8).any(|pad| (bits >> pad) & 0xFF_FFFF == EOFB)
}

/// Composes a rendering: the summary in front, the records behind it.
///
/// The summary goes first because it is the question the file answers
/// slowest, and the records behind it because they are the question the
/// user is usually asking.
fn finish(summary: &str, body: &str) -> String {
    let mut out = String::with_capacity(body.len() + summary.len() + 64);
    let _ = writeln!(out, "{summary}");
    if body.len() <= MAX_RENDER {
        out.push_str(body);
        return out;
    }
    // Cut on a line boundary: a rendering that stops in the middle of a
    // record is a record that reads as if it were whole.
    let bytes = body.as_bytes();
    let mut cut = MAX_RENDER.min(bytes.len());
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    let cut = body[..cut].rfind('\n').map(|i| i + 1).unwrap_or(cut);
    out.push_str(&body[..cut]);
    let _ = writeln!(
        out,
        "note: the rendering stopped at the {MAX_RENDER}-byte ceiling; the rest of the file is not shown"
    );
    out
}

#[cfg(test)]
mod tests {
    //! The fixture is written by hand to the standard and kept as a file, so
    //! the end-to-end run reads the same bytes the unit tests read.
    //!
    //! The first test is the one that matters: it asserts that the file
    //! itself does **not** contain what the rendering contains, because a
    //! rendering that only re-orders what `rg` already sees would be a
    //! rendering for nothing.

    use super::*;

    const CAL: &[u8] = include_bytes!("../testdata/sample.cal");

    /// The rendering the fixture produces, line for line.
    const EXPECTED: &str = "\
cals: type 1, 1728x2200 pels at 200 dpi, orientation 000,270
srcdocid: SAMPLE DOCUMENT
dstdocid: ACME-001
txtfilid: 003,007
figid: NONE
srcgph: F0814003.007
doccls: Unclass
rtype: 1
rorient: 000,270
rpelcnt: 001728,002200
rdensity: 0200
notes: Fri Aug 14 12:21:43 1991 PDT
image data: 781 bytes of CCITT Group 4 (T.6) data, ending in the EOFB
";

    #[test]
    fn a_cals_renders_what_the_file_does_not() {
        let file = String::from_utf8_lossy(CAL);
        // The header is a padded fixed-column form: the records are there,
        // but the joined fact is not, and the image data is not text.
        assert!(!file.contains("cals: type 1"), "the fixture is a header");
        assert!(!file.contains("image data:"), "the fixture is a header");
        let out = render_cals(CAL).expect("a cals is ours");
        assert!(
            out.contains("cals: type 1, 1728x2200 pels at 200 dpi"),
            "{out}"
        );
        assert!(out.contains("image data: 781 bytes"), "{out}");
    }

    #[test]
    fn the_fixture_renders_as_expected() {
        let out = render_cals(CAL).expect("a cals is ours");
        assert_eq!(out, EXPECTED);
    }

    #[test]
    fn a_file_that_is_not_a_cals_is_declined() {
        let err = render_cals(b"not a cals file at all").expect_err("not a cals");
        assert!(err.is_decline(), "{err}");
        // A file that opens with the right record but whose records are not
        // the standard's is not a CALS file either.
        let mut wrong = CAL.to_vec();
        wrong[RECORD_LEN * 2] = b'X';
        let err = render_cals(&wrong).expect_err("not a cals");
        assert!(err.is_decline(), "{err}");
    }

    #[test]
    fn a_truncated_cals_is_declined_and_not_a_panic() {
        // Every prefix of the file is declined, and none of them panics.
        // The 2048-byte prefix is not one of them: a header with no image
        // data is a header, and the adapter reports it.
        for len in [0usize, 1, 12, 127, 128, 129, 1407, 1408, 2047] {
            let cut = &CAL[..len.min(CAL.len())];
            let err = render_cals(cut).expect_err("truncated");
            assert!(err.is_decline(), "at {len} bytes: {err}");
        }
    }

    #[test]
    fn a_header_without_image_data_reports_the_header_alone() {
        let head = &CAL[..HEADER_LEN];
        let out = render_cals(head).expect("a cals is ours");
        assert!(out.contains("image data: none"), "{out}");
        assert!(
            out.contains("cals: type 1, 1728x2200 pels at 200 dpi"),
            "{out}"
        );
    }

    #[test]
    fn a_type_two_cals_says_it_is_type_two() {
        let mut two = CAL.to_vec();
        // The rtype record is the seventh: its value starts after "rtype: ".
        let at = RECORD_LEN * REC_RTYPE + "rtype: ".len();
        two[at] = b'2';
        let out = render_cals(&two).expect("a cals is ours");
        assert!(
            out.contains("cals: type 2, 1728x2200 pels at 200 dpi"),
            "{out}"
        );
        assert!(out.contains("not decoded"), "{out}");
    }

    #[test]
    fn a_cals_with_a_bad_record_is_declined() {
        // A density that is not a number is not a density.
        let mut bad = CAL.to_vec();
        let at = RECORD_LEN * REC_RDENSITY + "rdensity: ".len();
        bad[at] = b'x';
        let err = render_cals(&bad).expect_err("bad density");
        assert!(err.is_decline(), "{err}");
    }

    #[test]
    fn the_eofb_is_looked_for_in_the_bit_stream() {
        // The EOFB is 24 bits followed by the padding to the byte boundary,
        // so it is not always byte-aligned.
        let aligned = [0x00u8, 0x10, 0x01];
        let shifted = [0x00u8, 0x08, 0x00, 0x80];
        assert!(has_eofb(&aligned));
        assert!(has_eofb(&shifted));
        assert!(!has_eofb(&[0x00, 0x00, 0x00]));
        assert!(!has_eofb(&[]));
    }
}
