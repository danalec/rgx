// SPDX-License-Identifier: Apache-2.0

//! Symbol dictionary decoding (ITU-T T.88 §6.5 and §7.4.2).
//!
//! A symbol dictionary is a set of reusable bitmaps — usually the glyphs of
//! a font — that a text region then places. The dictionary's symbols are
//! grouped into *height classes*: symbols of the same height, decoded one
//! after another, with the first symbol's width and each following width
//! given as a difference.
//!
//! Only the arithmetic, directly-coded variant is implemented here. The
//! Huffman variant (Annex B) and the refinement/aggregate variant
//! (SDREFAGG = 1) are refused rather than approximated: both change what
//! the bytes mean, and a dictionary decoded wrongly places the wrong glyphs
//! in the right places, which is the worst kind of wrong.

use alloc::vec;
use alloc::vec::Vec;

use super::bitmap::Bitmap;
use super::generic;
use super::int::{code_length, Decoded, IntProc, IntegerContexts};
use super::mq::{Context, Decoder};

/// The ceiling on the pixels one dictionary may hold, the same refusal the
/// fax decoder makes for an image the container only claims is large.
const MAX_PIXELS: u64 = 64 * 1024 * 1024;

/// The ceiling on the number of symbols in one dictionary.
const MAX_SYMBOLS: usize = 1 << 20;

/// A decoded symbol dictionary.
pub struct SymbolDictionary {
    /// The exported symbols, in export order.
    pub symbols: Vec<Bitmap>,
}

/// The symbol dictionary's own flags (T.88 §7.4.2.1.1).
struct Flags {
    sdhuff: bool,
    sdrefagg: bool,
    sdtemplate: u8,
}

/// Parse a symbol dictionary segment's data part.
fn parse_flags(data: &[u8]) -> Option<(Flags, usize)> {
    if data.len() < 2 {
        return None;
    }
    let flags = u16::from_be_bytes([data[0], data[1]]);
    Some((
        Flags {
            sdhuff: flags & 0x0001 != 0,
            sdrefagg: flags & 0x0002 != 0,
            sdtemplate: ((flags >> 10) & 0x03) as u8,
        },
        2,
    ))
}

/// Decode a symbol dictionary segment.
///
/// `imported` holds the exported symbols of the dictionaries this one refers
/// to; they come before this dictionary's own symbols in the combined symbol
/// space that the export flags select from.
pub fn decode(payload: &[u8], imported: &[Bitmap]) -> Option<SymbolDictionary> {
    let (flags, mut pos) = parse_flags(payload)?;

    // The Huffman variant and the refinement/aggregate variant are refused.
    if flags.sdhuff || flags.sdrefagg {
        return None;
    }

    // The adaptive template pixels (T.88 §7.4.2.1.2): template 0 carries four
    // of them, the others carry one.
    let mut at = [(0i8, 0i8); 4];
    let at_count = if flags.sdtemplate == 0 { 4 } else { 1 };
    for slot in at.iter_mut().take(at_count) {
        let x = *payload.get(pos)? as i8;
        let y = *payload.get(pos + 1)? as i8;
        pos += 2;
        *slot = (x, y);
    }

    // The exported and new symbol counts (T.88 §7.4.2.1.4 and §7.4.2.1.5).
    if payload.len() < pos + 8 {
        return None;
    }
    let num_ex = u32::from_be_bytes([
        payload[pos],
        payload[pos + 1],
        payload[pos + 2],
        payload[pos + 3],
    ]) as usize;
    let num_new = u32::from_be_bytes([
        payload[pos + 4],
        payload[pos + 5],
        payload[pos + 6],
        payload[pos + 7],
    ]) as usize;
    pos += 8;

    let total = imported.len().checked_add(num_new)?;
    if total > MAX_SYMBOLS || num_ex > total {
        return None;
    }

    let data = payload.get(pos..)?;

    // T.88 §6.5.5: the statistics start fresh for each dictionary.
    let mut int_ctx = IntegerContexts::default();
    let mut generic_ctx: Vec<Context> = vec![Context(0); 1 << 16];
    let _ = code_length(total);

    let mut decoder = Decoder::new(data);
    let mut new_symbols: Vec<Bitmap> = Vec::with_capacity(num_new.min(4096));
    let mut total_pixels: u64 = 0;

    // The height class loop (T.88 §6.5.5 step 4).
    let mut hc_height: i64 = 0;
    while new_symbols.len() < num_new {
        let dh = match int_ctx.decode(&mut decoder, IntProc::Iadh) {
            Decoded::Value(v) => v,
            Decoded::Oob => return None,
        };
        hc_height = hc_height.checked_add(dh)?;
        if hc_height <= 0 || hc_height > u32::MAX as i64 {
            return None;
        }

        // The symbols of this height class, terminated by an out-of-band
        // delta width.
        let mut sym_width: i64 = 0;
        loop {
            let dw = match int_ctx.decode(&mut decoder, IntProc::Iadw) {
                Decoded::Oob => break,
                Decoded::Value(v) => v,
            };
            sym_width = sym_width.checked_add(dw)?;
            if sym_width <= 0 || sym_width > u32::MAX as i64 {
                return None;
            }
            if new_symbols.len() >= num_new {
                return None;
            }
            let pixels = (sym_width as u64).checked_mul(hc_height as u64)?;
            total_pixels = total_pixels.checked_add(pixels)?;
            if total_pixels > MAX_PIXELS {
                return None;
            }

            // The symbol's own bitmap is a generic region coded out of the
            // dictionary's arithmetic stream, sharing the generic context
            // bank with the symbols before it.
            let bitmap = generic::decode_with(
                &mut decoder,
                &mut generic_ctx,
                sym_width as u32,
                hc_height as u32,
                flags.sdtemplate,
                &at,
                false,
            )?;
            new_symbols.push(bitmap);
        }
    }

    // The export flags (T.88 §6.5.10): runs of alternating flags over the
    // combined symbol space, starting with "not exported".
    let mut exported: Vec<Bitmap> = Vec::with_capacity(num_ex.min(total));
    let mut index = 0usize;
    let mut ex_flag = false;
    let max_runs = total.saturating_mul(2).saturating_add(4);
    let mut runs = 0usize;
    while index < total {
        runs += 1;
        if runs > max_runs {
            return None;
        }
        let run = match int_ctx.decode(&mut decoder, IntProc::Iaex) {
            Decoded::Value(v) if v >= 0 => v as usize,
            _ => return None,
        };
        if run > total - index {
            return None;
        }
        if ex_flag {
            for j in index..index + run {
                let sym = if j < imported.len() {
                    &imported[j]
                } else {
                    &new_symbols[j - imported.len()]
                };
                exported.push(sym.clone());
            }
        }
        index += run;
        ex_flag = !ex_flag;
    }
    if exported.len() != num_ex {
        return None;
    }

    Some(SymbolDictionary { symbols: exported })
}
