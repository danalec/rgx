// SPDX-License-Identifier: Apache-2.0

//! Generic region decoding (ITU-T T.88 §6.2 and §7.4.6).
//!
//! A generic region is a rectangle of pixels coded one pixel at a time. Two
//! codings exist: arithmetic, where every pixel is a binary decision under a
//! context taken from the pixels around it, and MMR, where the region is
//! simply a T.6 (Group 4) fax bitmap.
//!
//! The arithmetic form's context is the pixel neighbourhood called a
//! *template* (T.88 Figures 3 to 6). Four templates exist, of 16, 13, 10 and
//! 10 pixels. The bits of the context are the template's pixel values
//! gathered **in reading order — top row to bottom row, and left to right
//! within a row** — with the first gathered pixel as the most significant
//! bit. T.88 leaves the order "not standardised", but it fixes the value of
//! the context used for the typical-prediction bit (Figures 8 to 11), and
//! those values only come out right under reading order: template 0's
//! `SLTP` context is `0x9B25`, and the pixels of Figure 8 read in order
//! give exactly that.

use super::bitmap::Bitmap;
use super::mq::{context_table, Context, Decoder};
use super::region::RegionInfo;

/// The nominal AT pixel locations of T.88 Table 5.
const NOMINAL_AT: [[(i8, i8); 4]; 4] = [
    [(3, -1), (-3, -1), (2, -2), (-2, -2)],
    [(3, -1), (0, 0), (0, 0), (0, 0)],
    [(2, -1), (0, 0), (0, 0), (0, 0)],
    [(2, -1), (0, 0), (0, 0), (0, 0)],
];

/// The context used for the typical-prediction bit, per template
/// (T.88 Figures 8 to 11).
///
/// These are the template's own context with the pixel values frozen at the
/// ones the figures show — the "reused context".
const SLTP_CONTEXT: [u16; 4] = [0x9B25, 0x0795, 0x00E5, 0x0195];

/// How many contexts a template's pixel context can take.
fn context_count(template: u8) -> usize {
    match template {
        0 => 1 << 16,
        1 => 1 << 13,
        2 | 3 => 1 << 10,
        _ => 1 << 10,
    }
}

/// A parsed generic region segment.
pub struct GenericRegion<'a> {
    pub info: RegionInfo,
    /// Whether the region is MMR (T.6) coded.
    pub mmr: bool,
    /// The template used for arithmetic coding: 0, 1, 2 or 3.
    pub template: u8,
    /// Whether typical prediction (TPGD) is used.
    pub tpgdon: bool,
    /// The adaptive template pixel locations.
    pub at: [(i8, i8); 4],
    /// The coded data.
    pub data: &'a [u8],
}

/// Parse a generic region segment's data part (T.88 §7.4.6.1 to §7.4.6.3).
///
/// `unknown_length` says the segment's length was not known when it was
/// written; the region then says how many rows it really holds at the end
/// of its data, and that is the truth about the region's height.
pub fn parse(data: &[u8], unknown_length: bool) -> Option<GenericRegion<'_>> {
    let mut info = RegionInfo::parse(data)?;
    let mut pos = RegionInfo::LENGTH;
    let flags = *data.get(pos)?;
    pos += 1;
    let mmr = flags & 0x01 != 0;
    let template = (flags >> 1) & 0x03;
    let tpgdon = flags & 0x08 != 0;

    // The AT flags are present only for arithmetic coding, and template 0 has
    // four AT pixels where the others have one (T.88 §7.4.6.3).
    let mut at = NOMINAL_AT[template as usize];
    if !mmr {
        let at_count = if template == 0 { 4 } else { 1 };
        for slot in at.iter_mut().take(at_count) {
            let x = *data.get(pos)? as i8;
            let y = *data.get(pos + 1)? as i8;
            pos += 2;
            *slot = (x, y);
        }
    }

    let coded = data.get(pos..)?;
    if unknown_length {
        if let Some(rows) = trailing_row_count(coded, mmr) {
            info.height = info.height.min(rows);
        }
    }

    Some(GenericRegion {
        info,
        mmr,
        template,
        tpgdon,
        at,
        data: coded,
    })
}

/// The number of rows a region really holds, when its length was unknown.
///
/// T.88 §7.2.7: the data part ends with the two-byte terminator — `0xFF 0xAC`
/// for arithmetic coding, `0x00 0x00` for MMR — followed by a four-byte row
/// count.
fn trailing_row_count(data: &[u8], mmr: bool) -> Option<u32> {
    if data.len() < 6 {
        return None;
    }
    let terminator = if mmr { [0x00, 0x00] } else { [0xFF, 0xAC] };
    let at = data.len() - 6;
    if data[at] != terminator[0] || data[at + 1] != terminator[1] {
        return None;
    }
    let rows = u32::from_be_bytes([data[at + 2], data[at + 3], data[at + 4], data[at + 5]]);
    if rows == 0 {
        return None;
    }
    Some(rows)
}

/// Decode a generic region.
pub fn decode(region: &GenericRegion<'_>) -> Option<Bitmap> {
    let width = region.info.width;
    let height = region.info.height;
    if width == 0 || height == 0 {
        return None;
    }
    if (width as u64) * (height as u64) > super::MAX_PIXELS {
        return None;
    }
    if region.mmr {
        decode_mmr(region.data, width, height)
    } else {
        let mut contexts = context_table(context_count(region.template));
        let mut decoder = Decoder::new(region.data);
        decode_arithmetic(
            &mut decoder,
            &mut contexts,
            width,
            height,
            region.template,
            &region.at,
            region.tpgdon,
        )
    }
}

/// Decode a generic region into an existing decoder and context bank.
///
/// A symbol dictionary codes every one of its symbols out of one arithmetic
/// stream and one context bank (T.88 §6.5.5), so the contexts carry from one
/// symbol to the next; this entry point is how that is expressed.
pub fn decode_with(
    decoder: &mut Decoder<'_>,
    contexts: &mut [Context],
    width: u32,
    height: u32,
    template: u8,
    at: &[(i8, i8); 4],
    tpgdon: bool,
) -> Option<Bitmap> {
    if width == 0 || height == 0 {
        return None;
    }
    if (width as u64) * (height as u64) > super::MAX_PIXELS {
        return None;
    }
    if contexts.len() < context_count(template) {
        return None;
    }
    decode_arithmetic(decoder, contexts, width, height, template, at, tpgdon)
}

/// Decode a generic region coded with MMR (T.88 §6.2.6).
///
/// The region is a T.6 (Group 4) bitmap: "black" pixels are 1 and "white"
/// pixels are 0, and the data part may or may not end with an `EOFB`
/// depending on whether its length was known when it was written.
fn decode_mmr(data: &[u8], width: u32, height: u32) -> Option<Bitmap> {
    if data.is_empty() {
        return None;
    }
    // The fax decoder reads black as 0 bits, so it is asked for the opposite
    // ink convention to get 1 = black out of it.
    let params = super::super::fax::FaxParams {
        k: 0,
        columns: width,
        rows: height,
        black_is_1: true,
        byte_align: false,
    };
    let gray = super::super::fax::decode_fax(data, &params)?;
    if gray.len() < (width as usize) * (height as usize) {
        return None;
    }
    let mut bitmap = Bitmap::new(width, height);
    for (dst, src) in bitmap.pixels.iter_mut().zip(gray.iter()) {
        // The fax decoder paints white as 255 and black as 0.
        *dst = if *src == 0 { 1 } else { 0 };
    }
    Some(bitmap)
}

/// Decode a generic region coded with arithmetic (T.88 §6.2.5).
fn decode_arithmetic(
    decoder: &mut Decoder<'_>,
    contexts: &mut [Context],
    width: u32,
    height: u32,
    template: u8,
    at: &[(i8, i8); 4],
    tpgdon: bool,
) -> Option<Bitmap> {
    let mut bitmap = Bitmap::new(width, height);

    // T.88 §6.2.5.7: LTP starts at 0 and the first row has no row above it,
    // so "the row immediately above" is the all-white row.
    let mut ltp = false;
    for y in 0..height {
        if tpgdon {
            let sltp = decoder.decode_bit(&mut contexts[SLTP_CONTEXT[template as usize] as usize]);
            ltp ^= sltp != 0;
        }
        if ltp {
            if y > 0 {
                bitmap.copy_row_above(y);
            }
            continue;
        }
        for x in 0..width {
            let ctx = pixel_context(template, &bitmap, x as i64, y as i64, at);
            let bit = decoder.decode_bit(&mut contexts[ctx]);
            bitmap.set(x as i64, y as i64, bit);
        }
    }
    Some(bitmap)
}

/// The context of the pixel at `(x, y)`: the template's pixel values read in
/// reading order, most significant bit first.
fn pixel_context(template: u8, bitmap: &Bitmap, x: i64, y: i64, at: &[(i8, i8); 4]) -> usize {
    // The fixed pixels of each template, in reading order, as (dx, dy). The
    // AT pixels take the places marked in T.88 Figures 3 to 6.
    //
    // Reading order means: the row above first (top to bottom), and within a
    // row, left to right. A template's own rows are at dy = 0, -1 and -2.
    let mut ctx: u32 = 0;
    let mut push = |value: u8| {
        ctx = (ctx << 1) | value as u32;
    };
    match template {
        0 => {
            // Figure 3: y = -2 row (A4, -1, 0, 1, A3), y = -1 row
            // (A2, -2, -1, 0, 1, 2, A1), y = 0 row (-4, -3, -2, -1).
            push(at_pixel(bitmap, x, y, at[3]));
            push(bitmap.get(x - 1, y - 2));
            push(bitmap.get(x, y - 2));
            push(bitmap.get(x + 1, y - 2));
            push(at_pixel(bitmap, x, y, at[2]));
            push(at_pixel(bitmap, x, y, at[1]));
            push(bitmap.get(x - 2, y - 1));
            push(bitmap.get(x - 1, y - 1));
            push(bitmap.get(x, y - 1));
            push(bitmap.get(x + 1, y - 1));
            push(bitmap.get(x + 2, y - 1));
            push(at_pixel(bitmap, x, y, at[0]));
            push(bitmap.get(x - 4, y));
            push(bitmap.get(x - 3, y));
            push(bitmap.get(x - 2, y));
            push(bitmap.get(x - 1, y));
        }
        1 => {
            // Figure 4: y = -2 row (-1, 0, 1, 2), y = -1 row (-2, -1, 0, 1,
            // 2, A1), y = 0 row (-3, -2, -1).
            push(bitmap.get(x - 1, y - 2));
            push(bitmap.get(x, y - 2));
            push(bitmap.get(x + 1, y - 2));
            push(bitmap.get(x + 2, y - 2));
            push(bitmap.get(x - 2, y - 1));
            push(bitmap.get(x - 1, y - 1));
            push(bitmap.get(x, y - 1));
            push(bitmap.get(x + 1, y - 1));
            push(bitmap.get(x + 2, y - 1));
            push(at_pixel(bitmap, x, y, at[0]));
            push(bitmap.get(x - 3, y));
            push(bitmap.get(x - 2, y));
            push(bitmap.get(x - 1, y));
        }
        2 => {
            // Figure 5: y = -2 row (-1, 0, 1), y = -1 row (-2, -1, 0, 1, A1),
            // y = 0 row (-2, -1).
            push(bitmap.get(x - 1, y - 2));
            push(bitmap.get(x, y - 2));
            push(bitmap.get(x + 1, y - 2));
            push(bitmap.get(x - 2, y - 1));
            push(bitmap.get(x - 1, y - 1));
            push(bitmap.get(x, y - 1));
            push(bitmap.get(x + 1, y - 1));
            push(at_pixel(bitmap, x, y, at[0]));
            push(bitmap.get(x - 2, y));
            push(bitmap.get(x - 1, y));
        }
        _ => {
            // Figure 6: y = -1 row (-3, -2, -1, 0, 1, A1), y = 0 row
            // (-4, -3, -2, -1).
            push(bitmap.get(x - 3, y - 1));
            push(bitmap.get(x - 2, y - 1));
            push(bitmap.get(x - 1, y - 1));
            push(bitmap.get(x, y - 1));
            push(bitmap.get(x + 1, y - 1));
            push(at_pixel(bitmap, x, y, at[0]));
            push(bitmap.get(x - 4, y));
            push(bitmap.get(x - 3, y));
            push(bitmap.get(x - 2, y));
            push(bitmap.get(x - 1, y));
        }
    }
    ctx as usize
}

/// The value of an AT pixel: the pixel at `(x + dx, y + dy)`.
///
/// An AT pixel in the current row may only look to the left — the pixels to
/// the right have not been decoded yet, and read as 0.
#[inline]
fn at_pixel(bitmap: &Bitmap, x: i64, y: i64, at: (i8, i8)) -> u8 {
    let px = x + at.0 as i64;
    let py = y + at.1 as i64;
    if py == y && px >= x {
        return 0;
    }
    bitmap.get(px, py)
}
