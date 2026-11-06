// SPDX-License-Identifier: Apache-2.0

//! Text region decoding (ITU-T T.88 §6.4 and §7.4.3).
//!
//! A text region is a page of glyphs: a list of *symbol instances*, each a
//! symbol ID and a position, drawn onto the region's bitmap. The positions
//! are coded as a run of strips (rows of text) and, within a strip, a
//! sequence of S coordinates that usually differ by a constant.
//!
//! Only the arithmetic variant is implemented. The Huffman variant
//! (SBHUFF = 1) needs the code tables of T.88 Annex B and is refused.

use super::bitmap::Bitmap;
use super::int::{code_length, Decoded, IaidContexts, IntProc, IntegerContexts};
use super::mq::Decoder;
use super::region::RegionInfo;

/// The ceiling on the pixels one text region may hold.
const MAX_PIXELS: u64 = 64 * 1024 * 1024;

/// The text region's own flags (T.88 §7.4.3.1.1).
struct Flags {
    sbhuff: bool,
    sbrefine: bool,
    log_sb_strips: u8,
    ref_corner: u8,
    transposed: bool,
    sb_comb_op: u8,
    sb_def_pixel: bool,
    sb_ds_offset: i64,
}

/// A decoded text region: the bitmap and where it goes on the page.
pub struct TextRegion {
    pub bitmap: Bitmap,
    pub x: u32,
    pub y: u32,
    /// The external combination operator (T.88 §7.4.1.5).
    pub comb_operator: u8,
}

/// Decode a text region segment.
///
/// `symbols` holds the exported symbols of the symbol dictionary the region
/// refers to.
pub fn decode(payload: &[u8], symbols: &[Bitmap]) -> Option<TextRegion> {
    let info = RegionInfo::parse(payload)?;
    let mut pos = RegionInfo::LENGTH;

    // The text region segment flags (T.88 §7.4.3.1.1).
    if payload.len() < pos + 2 {
        return None;
    }
    let raw = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    pos += 2;
    let flags = Flags {
        sbhuff: raw & 0x0001 != 0,
        sbrefine: raw & 0x0002 != 0,
        log_sb_strips: ((raw >> 2) & 0x03) as u8,
        ref_corner: ((raw >> 4) & 0x03) as u8,
        transposed: raw & 0x0040 != 0,
        sb_comb_op: ((raw >> 7) & 0x03) as u8,
        sb_def_pixel: raw & 0x0200 != 0,
        sb_ds_offset: sign_extend_5((raw >> 10) & 0x1F),
    };

    // The Huffman variant is refused: it needs the code tables of Annex B.
    if flags.sbhuff {
        return None;
    }

    // The refinement AT flags are present when SBREFINE is 1 and the
    // refinement template is 0. A refinement of a symbol instance is itself
    // refused below, so the field is only skipped.
    if flags.sbrefine && raw & 0x8000 == 0 {
        pos += 4;
    }

    // The number of symbol instances (T.88 §7.4.3.1.4).
    if payload.len() < pos + 4 {
        return None;
    }
    let num_instances = u32::from_be_bytes([
        payload[pos],
        payload[pos + 1],
        payload[pos + 2],
        payload[pos + 3],
    ]);
    pos += 4;

    let width = info.width;
    let height = info.height;
    if width == 0 || height == 0 {
        return None;
    }
    if width as u64 * height as u64 > MAX_PIXELS {
        return None;
    }
    if symbols.is_empty() {
        return None;
    }

    let data = payload.get(pos..)?;
    let mut decoder = Decoder::new(data);
    let mut int_ctx = IntegerContexts::default();
    let mut iaid_ctx = IaidContexts::default();
    let code_len = code_length(symbols.len());
    iaid_ctx.reset_for_bits(code_len);

    let mut bitmap = Bitmap::new(width, height);
    if flags.sb_def_pixel {
        for p in bitmap.pixels.iter_mut() {
            *p = 1;
        }
    }

    let sb_strips: i64 = 1i64 << flags.log_sb_strips;

    // The initial strip T (T.88 §6.4.5 step 2): the decoded delta, negated.
    let dt0 = match int_ctx.decode(&mut decoder, IntProc::Iadt) {
        Decoded::Value(v) => v,
        Decoded::Oob => return None,
    };
    let mut strip_t: i64 = dt0.checked_mul(sb_strips)?.checked_neg()?;
    let mut first_s: i64 = 0;
    let mut n_inst: u32 = 0;

    while n_inst < num_instances {
        // The strip's delta T (T.88 §6.4.5 step 3b).
        let dt = match int_ctx.decode(&mut decoder, IntProc::Iadt) {
            Decoded::Value(v) => v,
            Decoded::Oob => return None,
        };
        strip_t = strip_t.checked_add(dt.checked_mul(sb_strips)?)?;

        // The first symbol instance's S coordinate (T.88 §6.4.5 step 3c i).
        let dfs = match int_ctx.decode(&mut decoder, IntProc::Iafs) {
            Decoded::Value(v) => v,
            Decoded::Oob => return None,
        };
        first_s = first_s.checked_add(dfs)?;
        let mut cur_s = first_s;
        let mut first_in_strip = true;

        loop {
            if !first_in_strip {
                // The subsequent symbol instances' S coordinates
                // (T.88 §6.4.5 step 3c ii). An out-of-band value ends the
                // strip.
                match int_ctx.decode(&mut decoder, IntProc::Iads) {
                    Decoded::Oob => break,
                    Decoded::Value(v) => {
                        cur_s = cur_s.checked_add(v)?.checked_add(flags.sb_ds_offset)?;
                    }
                }
            }
            first_in_strip = false;

            if n_inst >= num_instances {
                return None;
            }

            // The symbol instance's T coordinate within the strip
            // (T.88 §6.4.5 step 3c iii).
            let cur_t: i64 = if sb_strips == 1 {
                0
            } else {
                match int_ctx.decode(&mut decoder, IntProc::Iait) {
                    Decoded::Value(v) => v,
                    Decoded::Oob => return None,
                }
            };
            let t_i = strip_t.checked_add(cur_t)?;

            // The symbol ID (T.88 §6.4.5 step 3c iv).
            let id = iaid_ctx.decode(&mut decoder, code_len) as usize;
            let symbol = symbols.get(id)?;

            // A refined symbol instance is refused: the refinement is a
            // whole refinement region, and a refinement decoded wrongly puts
            // a plausible glyph in the wrong place.
            if flags.sbrefine {
                return None;
            }

            place_symbol(
                &mut bitmap,
                symbol,
                flags.ref_corner,
                flags.transposed,
                &mut cur_s,
                t_i,
                flags.sb_comb_op,
            )?;
            n_inst += 1;
        }
    }

    Some(TextRegion {
        bitmap,
        x: info.x,
        y: info.y,
        comb_operator: info.comb_operator,
    })
}

/// Extend a five-bit signed field.
fn sign_extend_5(value: u16) -> i64 {
    let value = value & 0x1F;
    if value & 0x10 != 0 {
        (value as i64) - 32
    } else {
        value as i64
    }
}

/// Place a symbol instance on the region (T.88 §6.4.5 step 3c vi to x).
///
/// The S coordinate is the region's X axis and the T coordinate its Y axis,
/// unless the region is transposed, in which case they swap. The reference
/// corner says which corner of the glyph the position refers to, and the S
/// coordinate advances by the glyph's extent before or after the placement
/// depending on that corner.
fn place_symbol(
    bitmap: &mut Bitmap,
    symbol: &Bitmap,
    ref_corner: u8,
    transposed: bool,
    cur_s: &mut i64,
    t_i: i64,
    op: u8,
) -> Option<()> {
    // REFCORNER: 0 BOTTOMLEFT, 1 TOPLEFT, 2 BOTTOMRIGHT, 3 TOPRIGHT.
    let right = ref_corner == 2 || ref_corner == 3;
    let bottom = ref_corner == 0 || ref_corner == 2;
    let wi = symbol.width as i64;
    let hi = symbol.height as i64;

    if !transposed {
        if right {
            *cur_s = cur_s.checked_add(wi - 1)?;
        }
        let si = *cur_s;
        let x_left = if right { si - (wi - 1) } else { si };
        let y_top = if bottom { t_i - (hi - 1) } else { t_i };
        bitmap.combine(symbol, x_left, y_top, op);
        if !right {
            *cur_s = cur_s.checked_add(wi - 1)?;
        }
    } else {
        if bottom {
            *cur_s = cur_s.checked_add(hi - 1)?;
        }
        let si = *cur_s;
        let x_left = if right { t_i - (wi - 1) } else { t_i };
        let y_top = if bottom { si - (hi - 1) } else { si };
        bitmap.combine(symbol, x_left, y_top, op);
        if !bottom {
            *cur_s = cur_s.checked_add(hi - 1)?;
        }
    }
    Some(())
}
