// SPDX-License-Identifier: Apache-2.0

//! JBIG2 decoding, in the shape a PDF `/JBIG2Decode` stream carries it.
//!
//! JBIG2 (ITU-T T.88) is the bi-level image coding a scanned page usually
//! carries: a page is a rectangle of black and white pixels, and the file
//! describes it as a sequence of *segments* — dictionaries of reusable
//! symbols, regions of pixels, and the page information that says how big the
//! page is.
//!
//! A PDF hands over two streams: the image stream itself, and optionally a
//! globals stream holding the dictionaries the page refers to. The page
//! information segment is *not* part of a PDF's stream — the size comes from
//! the image dictionary's `/Width` and `/Height` — so both entry points
//! exist: [`decode`] for a stream that carries its own page information, and
//! [`decode_with_size`] for one that does not.
//!
//! ## What is refused
//!
//! Every entry point is total: a malformed, truncated or empty stream answers
//! `None`. A half-decoded page is not a page, and an OCR engine handed one
//! reports a bad image rather than a bad page. A segment type this decoder
//! does not implement is a refusal, not a guess: a plausible-looking but
//! wrong page is worse than no page, because the wrongness is invisible.

extern crate alloc;

mod bitmap;
pub mod generic;
pub mod int;
pub mod mq;
mod region;
pub mod segment;
mod symbol;
mod text;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitmap::Bitmap;
use region::RegionInfo;

/// A decoded bi-level image.
pub struct Jbig2Image {
    pub width: u32,
    pub height: u32,
    /// One byte per pixel, row-major: `0` = black, `255` = white.
    pub pixels: Vec<u8>,
}

/// The eight-byte ID string that opens a JBIG2 file (T.88 §D.4.1).
const FILE_HEADER_ID: [u8; 8] = [0x97, 0x4A, 0x42, 0x32, 0x0D, 0x0A, 0x1A, 0x0A];

/// The ceiling on the pixels one bitmap may hold.
///
/// The same refusal the fax decoder makes for an image the container only
/// *claims* is large. A JBIG2 region is decoded a pixel at a time, so a
/// header that says "four billion pixels" is not a slow page, it is a page
/// that never ends.
pub const MAX_PIXELS: u64 = 64 * 1024 * 1024;

/// The external combination operators of T.88 §7.4.1.5.
const OP_OR: u8 = 0;
const OP_AND: u8 = 1;
const OP_XOR: u8 = 2;
const OP_XNOR: u8 = 3;
const OP_REPLACE: u8 = 4;

/// One segment of a stream, as this decoder needs to see it.
struct SegmentData<'a> {
    number: u32,
    seg_type: u8,
    /// The segments this one refers to (T.88 §7.2.5).
    referred: Vec<u32>,
    /// Whether the data part's length was unknown when it was written.
    unknown_length: bool,
    data: &'a [u8],
}

/// The segments of a stream, in order.
struct Stream<'a> {
    order: Vec<SegmentData<'a>>,
}

/// Decode a JBIG2 stream that carries its own page information.
///
/// `globals` is the optional globals stream — a PDF's `/JBIG2Globals` — and
/// `data` is the page data. Returns `None` when the stream does not decode.
pub fn decode(globals: Option<&[u8]>, data: &[u8]) -> Option<Jbig2Image> {
    let stream = collect(globals, data)?;
    let (width, height) = stream
        .order
        .iter()
        .filter(|s| s.seg_type == segment::PAGE_INFORMATION)
        .find_map(|s| page_size(s.data))?;
    compose(stream, width, height)
}

/// Decode a JBIG2 stream whose page size the caller knows.
///
/// A PDF's `/JBIG2Decode` stream has no page information segment: the size
/// comes from the image dictionary. `width` and `height` are that size.
pub fn decode_with_size(
    globals: Option<&[u8]>,
    data: &[u8],
    width: u32,
    height: u32,
) -> Option<Jbig2Image> {
    if width == 0 || height == 0 {
        return None;
    }
    compose(collect(globals, data)?, width, height)
}

/// Gather the segments of a stream.
///
/// A stream that holds less than a segment's header says is refused here:
/// the page it would decode into is a page with its marks missing, which
/// reads as if it were whole.
fn collect<'a>(globals: Option<&'a [u8]>, data: &'a [u8]) -> Option<Stream<'a>> {
    let mut order = Vec::new();

    // The globals stream holds the dictionaries the page refers to. A PDF's
    // globals stream is a bare sequence of segments; a standalone file's
    // globals would come with a file header, which is skipped the same way.
    if let Some(g) = globals {
        push_segments(strip_file_header(g), &mut order)?;
    }
    push_segments(strip_file_header(data), &mut order)?;

    Some(Stream { order })
}

/// Split a byte string into segments and record them.
fn push_segments<'a>(data: &'a [u8], order: &mut Vec<SegmentData<'a>>) -> Option<()> {
    for seg in segment::split(data) {
        if seg.header.truncated {
            return None;
        }
        order.push(SegmentData {
            number: seg.header.number,
            seg_type: seg.header.seg_type,
            referred: seg.header.referred,
            unknown_length: seg.header.unknown_length,
            data: seg.data,
        });
    }
    Some(())
}

/// Skip a file header, if the stream starts with one (T.88 §D.4).
///
/// A file header is the eight-byte ID, a flags byte and a four-byte page
/// count: thirteen bytes.
fn strip_file_header(data: &[u8]) -> &[u8] {
    if data.len() >= 13 && data[..8] == FILE_HEADER_ID {
        &data[13..]
    } else {
        data
    }
}

/// The page size a page information segment declares (T.88 §7.4.8).
fn page_size(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 8 {
        return None;
    }
    let be = |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    let width = be(0);
    let height = be(4);
    // A height of 0xFFFFFFFF means the page is striped and its height is not
    // known yet (T.88 §7.4.8.2).
    if width == 0 || height == 0 || height == 0xFFFF_FFFF {
        return None;
    }
    Some((width, height))
}

/// The page's default pixel value and default combination operator
/// (T.88 §7.4.8.5).
fn page_defaults(data: &[u8]) -> (u8, u8) {
    let flags = data.get(16).copied().unwrap_or(0);
    let default_pixel = (flags >> 2) & 0x01;
    let default_operator = (flags >> 3) & 0x03;
    (default_pixel, default_operator)
}

/// Combine the regions of a stream into a page (T.88 §8.2).
fn compose(stream: Stream<'_>, width: u32, height: u32) -> Option<Jbig2Image> {
    if (width as u64) * (height as u64) > MAX_PIXELS {
        return None;
    }

    // The symbol dictionaries come first: a text region places the glyphs a
    // dictionary holds, so the dictionary has to exist before the region
    // that refers to it.
    let mut dictionaries: BTreeMap<u32, Vec<Bitmap>> = BTreeMap::new();
    for seg in &stream.order {
        if seg.seg_type != segment::SYMBOL_DICTIONARY {
            continue;
        }
        let mut imported: Vec<Bitmap> = Vec::new();
        for referred in &seg.referred {
            if let Some(symbols) = dictionaries.get(referred) {
                imported.extend(symbols.iter().cloned());
            }
        }
        let dictionary = symbol::decode(seg.data, &imported)?;
        dictionaries.insert(seg.number, dictionary.symbols);
    }

    // The page information segment says what the page starts as: the default
    // pixel value and the default combination operator. It comes before the
    // regions in a well-formed stream, but the page is built from the whole
    // segment list, so the defaults are read first.
    let mut default_pixel = 0u8;
    let mut default_operator = OP_OR;
    for seg in &stream.order {
        if seg.seg_type == segment::PAGE_INFORMATION {
            let (pixel, operator) = page_defaults(seg.data);
            default_pixel = pixel;
            default_operator = operator;
        }
    }

    // The page buffer starts at the page's default pixel value.
    let mut page = Bitmap::new(width, height);
    if default_pixel != 0 {
        for p in page.pixels.iter_mut() {
            *p = 1;
        }
    }
    let mut drew_something = false;

    for seg in &stream.order {
        match seg.seg_type {
            segment::PAGE_INFORMATION => {}
            segment::IMMEDIATE_GENERIC_REGION | segment::IMMEDIATE_LOSSLESS_GENERIC_REGION => {
                let region = generic::parse(seg.data, seg.unknown_length)?;
                let bitmap = generic::decode(&region)?;
                let operator = external_operator(region.info.comb_operator, default_operator);
                draw(&mut page, &bitmap, region.info, operator);
                drew_something = true;
            }
            segment::IMMEDIATE_TEXT_REGION | segment::IMMEDIATE_LOSSLESS_TEXT_REGION => {
                // The region refers to the symbol dictionary it uses.
                let mut symbols: Vec<Bitmap> = Vec::new();
                for referred in &seg.referred {
                    if let Some(dictionary) = dictionaries.get(referred) {
                        symbols.extend(dictionary.iter().cloned());
                    }
                }
                if symbols.is_empty() {
                    return None;
                }
                let region = text::decode(seg.data, &symbols)?;
                let operator = external_operator(region.comb_operator, default_operator);
                let info = RegionInfo {
                    width: region.bitmap.width,
                    height: region.bitmap.height,
                    x: region.x,
                    y: region.y,
                    comb_operator: region.comb_operator,
                };
                draw(&mut page, &region.bitmap, info, operator);
                drew_something = true;
            }
            // An intermediate region goes into an auxiliary buffer that only a
            // later refinement segment can draw. Nothing refines it here, so
            // it contributes nothing to the page and saying so is better than
            // guessing where it would have landed.
            segment::INTERMEDIATE_GENERIC_REGION | segment::INTERMEDIATE_TEXT_REGION => {}
            // A dictionary or a control segment contributes no pixels.
            segment::SYMBOL_DICTIONARY
            | segment::TABLES
            | segment::PROFILES
            | segment::EXTENSION
            | segment::END_OF_PAGE
            | segment::END_OF_STRIPE
            | segment::END_OF_FILE => {}
            // A region type this decoder does not implement would leave a
            // hole in the page, and a page with a hole in it is a page that
            // reads as if it were whole.
            _ => return None,
        }
    }

    // A page with no region at all is the page's default pixel value
    // everywhere, which is a page of nothing. That is a legitimate page (an
    // empty scan), but it is not what a caller asking for an image wants,
    // and it is indistinguishable from a stream that decoded to nothing.
    if !drew_something && default_pixel == 0 {
        return None;
    }

    Some(to_image(page, width, height))
}

/// The operator a region is drawn with.
///
/// T.88 §7.4.8.5: when the page's "combination operator overridden" bit is 0,
/// every direct region segment uses the page's default operator.
fn external_operator(region_operator: u8, default_operator: u8) -> u8 {
    match region_operator {
        OP_REPLACE => OP_REPLACE,
        other => {
            if other == default_operator {
                other
            } else {
                // The region's own operator is only meaningful when the page
                // allows it; the page's default is the safe reading.
                default_operator
            }
        }
    }
}

/// Draw a region's bitmap into the page (T.88 §8.2, step 5a).
fn draw(page: &mut Bitmap, region: &Bitmap, info: RegionInfo, operator: u8) {
    for y in 0..region.height {
        for x in 0..region.width {
            let px = info.x as i64 + x as i64;
            let py = info.y as i64 + y as i64;
            if px < 0 || py < 0 || px >= page.width as i64 || py >= page.height as i64 {
                continue;
            }
            let old = page.get(px, py);
            let new = region.get(x as i64, y as i64);
            let value = match operator {
                OP_OR => old | new,
                OP_AND => old & new,
                OP_XOR => old ^ new,
                OP_XNOR => 1 - (old ^ new),
                _ => new,
            };
            page.set(px, py, value);
        }
    }
}

/// Turn an internal bitmap into the public image.
fn to_image(bitmap: Bitmap, width: u32, height: u32) -> Jbig2Image {
    let mut pixels = Vec::with_capacity(bitmap.pixels.len());
    for v in bitmap.pixels {
        // Internally 1 is black; the public image is gray-scale, where 0 is
        // black and 255 is white.
        pixels.push(if v != 0 { 0 } else { 255 });
    }
    Jbig2Image {
        width,
        height,
        pixels,
    }
}

#[cfg(all(test, feature = "pdf"))]
mod fuzz {
    //! The JBIG2 decoder's mutation floor.
    //!
    //! A JBIG2 stream is bytes this crate did not write: a segment header
    //! with a length in it, a region coded against a template, a dictionary
    //! of glyphs whose sizes are differences. Every one of those is a place
    //! where an index computed from a field can point outside the buffer.
    //!
    //! The corpus is the real streams — a generic region and a text region
    //! with its dictionary — because a decoder that never sees a well-formed
    //! page cannot be shown to survive a malformed one.

    use super::decode;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&'static str, Vec<u8>)> = vec![
            (
                "generic",
                include_bytes!("../../testdata/jbig2/jbig2_text.arith_t0.jb2").to_vec(),
            ),
            (
                "text",
                include_bytes!("../../testdata/jbig2/jbig2_text.symbol.jb2").to_vec(),
            ),
            (
                "globals",
                include_bytes!("../../testdata/jbig2/jbig2_text.symbol.globals").to_vec(),
            ),
            ("zeros", vec![0u8; 512]),
            ("ones", vec![0xff; 512]),
        ];
        let globals = include_bytes!("../../testdata/jbig2/jbig2_text.symbol.globals").to_vec();
        rgx_core::fuzzkit::assert_never_panics(corpus, 200, "jbig2", move |data| {
            let _ = decode(None, data);
            let _ = decode(Some(&globals), data);
        });
    }
}
