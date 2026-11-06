// SPDX-License-Identifier: Apache-2.0

//! Lotus 1-2-3 spreadsheet (`.wks`, `.wk1`, `.wk2`, `.wk3`, `.wk4`, `.123`).
//!
//! The file is a flat sequence of records, each a **u16 little-endian
//! opcode, a u16 little-endian length in bytes, then that many bytes of
//! body**. The stream starts at offset 0 -- there is no file header ahead of
//! the first record -- and record 0 is the BOF, whose body carries the
//! version code:
//!
//! | version (LE u16) | family | release           |
//! |------------------|--------|-------------------|
//! | `0x0404` / `0x0405` | WKS  | 1-2-3 v1.0      |
//! | `0x0406`          | WK1    | 1-2-3 v2.0       |
//! | `0x1000` / `0x1001` | WK3 | 1-2-3 v3.x      |
//! | `0x1002` / `0x1003` | WK4 | 1-2-3 v4.x      |
//! | `0x1005` / `0x1006` | 123  | 1-2-3 Millennium |
//!
//! A cell record's body is one attributes byte, then **column and row as
//! little-endian u16s, then the payload**:
//!
//! ```text
//! body[0]      attributes
//! body[1..3]   column (LE u16)
//! body[3..5]   row    (LE u16)
//! body[5..]    payload, per opcode
//! ```
//!
//! * opcode `0x000D` integer (`i16 LE`)
//! * opcode `0x000E` number (`f64 LE`)
//! * opcode `0x000F` label (one alignment byte, then NUL-terminated text)
//! * opcode `0x0010` formula (cached `f64 LE` result, then an RPN token
//!   stream we do not decode)
//!
//! The v3 (`.wk3`) and the v4 (`.wk4`) sheets have a cell layout of their
//! own. The framing does not change -- it is still a u16 opcode, a u16
//! length, and the body -- but the body of a cell record is:
//!
//! ```text
//! body[0..2]   row      (LE u16)
//! body[2]      block
//! body[3]      column
//! body[4..]    payload, per opcode
//! ```
//!
//! * opcode `0x0016` label (a format byte, then NUL-terminated text)
//! * opcode `0x0017` number (an x87 80-bit extended float)
//! * opcode `0x0018` integer (a `u16`, whose unit this reader does not
//!   know -- see `walk_record_v3`)
//!
//! The Millennium (`.123`) sheet has a cell layout of its own again: the
//! row, the column in 256ths of a character, and then the payload --
//! `0x0016` a label and `0x0027` a number in the `f64` the v1 uses.
//!
//! What we deliberately skip: range records, formatting, column widths,
//! named views, and the 1-2-3 Millennium password envelope. Those are not
//! what a `rgx` over a `.wk1` is for; the bytes are still in the file and a
//! raw byte search on the same path will find them.
use alloc::string::String;
use core::fmt::Write as _;

use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Result};

/// Cap on cells emitted per file. A real Lotus sheet is bounded by 8192 rows
/// x 256 columns; we leave a margin for any version that stretched it and
/// stop earlier if a corrupt stream emits a runaway counter.
const MAX_CELLS: usize = 200_000;

/// Per-record byte cap. A Lotus record of 64 KiB is already implausible for
/// an opcode that is supposed to be a single cell; if a stream keeps
/// emitting records that long something is wrong, so we truncate and walk on
/// rather than spend the whole input on a single record.
const MAX_RECORD_BYTES: usize = 65_536;

/// Lotus 1-2-3 spreadsheet (`.wks`, `.wk1`, `.wk2`, `.wk3`, `.wk4`, `.123`).
pub struct Lotus;
impl Adapter for Lotus {
    fn name(&self) -> &'static str {
        "lotus123"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["wks", "wk1", "wk2", "wk3", "wk4", "123", "wkb"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 8 {
            decline!("too small for Lotus 1-2-3");
        }
        // Record 0 is the BOF. Its body starts at offset 4 and holds the
        // version code that names the family.
        let version = u16::from_le_bytes([data[4], data[5]]);
        let (family, framing) = match version {
            0x0404..=0x0406 => ("1-2-3 v1/v2 (WKS/WK1)", Framing::V2),
            0x1000 | 0x1001 => ("1-2-3 v3.x (WK3)", Framing::V3),
            0x1002..=0x1004 => ("1-2-3 v4.x (WK4)", Framing::V4),
            0x1005 | 0x1006 => ("1-2-3 Millennium (123)", Framing::Millennium),
            _ => decline!("not a Lotus 1-2-3 file (version {version:#06x})"),
        };

        let mut out = String::new();
        let _ = writeln!(out, "-- lotus 1-2-3 --");
        let _ = writeln!(out, "family: {family}");
        let _ = writeln!(out, "version: {version:#06x}");

        // The record stream starts at 0: the BOF *is* the first record, and
        // reading the version out of its body above is the same read. Starting
        // at 8 instead -- as this did -- lands two records into the stream and
        // then re-frames every record after it as body noise.
        let mut pos = 0usize;
        let mut emitted = 0usize;
        let mut skipped = 0usize;

        while pos + 4 <= data.len() && emitted < MAX_CELLS {
            let step = match framing {
                Framing::V2 => walk_record_v2(data, pos, &mut out, &mut emitted),
                Framing::V3 => walk_record_v3(
                    data,
                    pos,
                    &mut out,
                    &mut emitted,
                    &mut skipped,
                    Address::Plain,
                ),
                Framing::V4 => {
                    // The v4 cell layout is the v3's, but the sheet is split
                    // into tables and the address has to say which one: of
                    // the 1 279 distinct (row, column) pairs of `DEMO.WK4`,
                    // 591 hold more than one cell.
                    walk_record_v3(
                        data,
                        pos,
                        &mut out,
                        &mut emitted,
                        &mut skipped,
                        Address::WithBlock,
                    )
                }
                Framing::Millennium => {
                    walk_record_millennium(data, pos, &mut out, &mut emitted, &mut skipped)
                }
            };
            match step {
                Ok(step) if step > 0 => pos += step,
                // A record we cannot frame ends the walk. Reading past it
                // would print another file's bytes as this one's cells.
                _ => break,
            }
        }
        if skipped > 0 {
            // A cell this reader does not place is a cell it does not
            // report a value for. Saying how many were left out is the
            // difference between a sheet that was read and a sheet that
            // was partly read.
            let _ = writeln!(
                out,
                "not read: {skipped} cells: this reader does not know their value"
            );
        }
        if emitted == 0 {
            // The version above confirmed the format, so a stream that
            // yielded nothing is a failure worth a note rather than a
            // decline: the next adapter would only misreport a Lotus sheet.
            if skipped > 0 {
                bail!("lotus: {family} sheet: no cells extracted: {skipped} cells were not read: this reader does not know their value");
            }
            bail!("lotus: {family} sheet: no cells extracted");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[derive(Copy, Clone)]
enum Framing {
    /// WKS/WK1: u16 opcode, u16 length, and the cell layout proven below.
    V2,
    /// WK3: the same four-byte record header, and a cell layout of its own
    /// that this adapter has verified against a real sheet.
    V3,
    /// WK4: the same four-byte record header, and the same cell layout as
    /// the v3's, over a sheet that is split into tables.
    V4,
    /// 1-2-3 Millennium: u16 opcode, u32 length.
    Millennium,
}

/// Walk one WKS/WK1/WK3/WK4 record. Returns the bytes consumed, or 0 when the
/// cursor cannot advance.
///
/// The four-byte header is not a detail. The reader this replaces took the
/// opcode and the length as one byte each, so it stepped `2 + len` through a
/// stream whose records are `4 + len` long: from the second record on, every
/// "opcode" it read was a body byte and every coordinate it printed was
/// garbage. On `PEYNEVAL.WK1` (155 032 bytes) the four-byte framing walks
/// 8 315 records and lands on the last byte exactly, ending on the `0x0001`
/// EOF record -- which the two-byte framing cannot reach, because it
/// overshoots the file long before the end.
///
/// The column and row are **little-endian**, at `body[1..3]` and `body[3..5]`.
/// The three overlapping readings of this body are settled by the file
/// itself: `body[1..3]` takes exactly 36 distinct values in 0..=35 (the
/// column count the header records declare), `body[3..5]` takes 231 in
/// 0..=230 (the row count), and the header labels `NO`, `DATE`, `X`, `Y`,
/// `SLOP` land on columns 0..4 of row 0 -- the column names in row order.
/// Read little-endian and column-first, the coordinates are the addresses the
/// sheet was written with; the alternatives are not merely different, they
/// are out of the sheet's own declared range.
fn walk_record_v2(data: &[u8], pos: usize, out: &mut String, emitted: &mut usize) -> Result<usize> {
    if pos + 4 > data.len() {
        return Ok(0);
    }
    let opcode = u16::from_le_bytes([data[pos], data[pos + 1]]);
    let payload_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
    let total = 4usize.saturating_add(payload_len);
    if payload_len > MAX_RECORD_BYTES || pos.saturating_add(total) > data.len() {
        // Truncated record: stop the walk rather than read past the buffer.
        return Ok(0);
    }
    let body = &data[pos + 4..pos + total];
    // Attributes, column, row, payload. Five bytes of fixed preamble.
    if body.len() < 5 {
        return Ok(total);
    }
    let col = u16::from_le_bytes([body[1], body[2]]);
    let row = u16::from_le_bytes([body[3], body[4]]);
    let payload = &body[5..];
    match opcode {
        0x000D if payload.len() >= 2 => {
            let n = i16::from_le_bytes([payload[0], payload[1]]);
            let _ = writeln!(out, "R{row}C{col}\t{n}");
            *emitted += 1;
        }
        0x000E if payload.len() >= 8 => {
            let f = f64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
            let _ = writeln!(out, "R{row}C{col}\t{f}");
            *emitted += 1;
        }
        0x000F => {
            // payload[0] is the alignment byte: 0x27 in every one of the 885
            // labels in PEYNEVAL.WK1, so it is a constant of the record and
            // not part of the text.
            let text = if payload.is_empty() {
                &[][..]
            } else {
                &payload[1..]
            };
            let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
            if end > 0 {
                let label = String::from_utf8_lossy(&text[..end]);
                let _ = writeln!(out, "R{row}C{col}\t{label}");
                *emitted += 1;
            }
        }
        0x0010 if payload.len() >= 8 => {
            // The cached result the sheet stores for the formula; the RPN
            // token stream behind it is not decoded.
            let f = f64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
            let _ = writeln!(out, "R{row}C{col}\t{f} [formula]");
            *emitted += 1;
        }
        _ => {}
    }
    Ok(total)
}

/// How a cell's address is written.
#[derive(Copy, Clone)]
enum Address {
    /// `R{row}C{col}`: the v3 sheet is one table, and the block byte of
    /// every cell of it is zero.
    Plain,
    /// `B{block}R{row}C{col}`: the v4 sheet is split into tables, and the
    /// same (row, column) holds different cells in different ones.
    WithBlock,
}

/// Walk one WK3 (1-2-3 v3) or WK4 (1-2-3 v4) record.
///
/// The framing is the v1's: a u16 opcode, a u16 length, and the body. The
/// cell layout is the v3's own: the row, a block byte, the column, and
/// then the payload the opcode names.
///
/// The addresses are settled by the same sheet in the old layout. The
/// corpus holds `example.wk1` and `example.wk3`, which are the same
/// sheet, and every label and every number lands on the same address in
/// both files, with the same words -- the two differ only where the sheet
/// names itself ("WK1 test file" against "WK3 test file") and in the
/// integer column, which the v3 file stores in a unit this reader does
/// not know.
fn walk_record_v3(
    data: &[u8],
    pos: usize,
    out: &mut String,
    emitted: &mut usize,
    skipped: &mut usize,
    address: Address,
) -> Result<usize> {
    if pos + 4 > data.len() {
        return Ok(0);
    }
    let opcode = u16::from_le_bytes([data[pos], data[pos + 1]]);
    let payload_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
    let total = 4usize.saturating_add(payload_len);
    if payload_len > MAX_RECORD_BYTES || pos.saturating_add(total) > data.len() {
        // Truncated record: stop the walk rather than read past the buffer.
        return Ok(0);
    }
    let body = &data[pos + 4..pos + total];
    if !matches!(opcode, 0x0016..=0x001A) {
        // Not a cell: the stream also carries the sheet's own setup
        // records -- the ranges, the fonts, the column widths -- and
        // those are walked over, not counted as cells left out.
        return Ok(total);
    }
    // The row, the block, the column. Four bytes of fixed preamble.
    if body.len() < 4 {
        return Ok(total);
    }
    let row = u16::from_le_bytes([body[0], body[1]]) as usize;
    let block = body[2];
    let col = body[3] as usize;
    if matches!(address, Address::Plain) && block != 0 {
        // A v3 sheet with more than one block: the block says which table
        // the cell belongs to, and this reader does not lay those out,
        // so the cell is not placed at an address it cannot vouch for.
        *skipped += 1;
        return Ok(total);
    }
    match opcode {
        0x0016 if body.len() >= 5 => {
            // The byte after the column says how the cell is displayed,
            // not what it holds: every text cell of the corpus holds text
            // after it, whatever the byte says.
            let text = &body[5..];
            let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
            if end > 0 {
                let label = String::from_utf8_lossy(&text[..end]);
                match address {
                    Address::Plain => {
                        let _ = writeln!(out, "R{row}C{col}\t{label}");
                    }
                    Address::WithBlock => {
                        let _ = writeln!(out, "B{block}R{row}C{col}\t{label}");
                    }
                }
                *emitted += 1;
            }
        }
        0x0017 if body.len() >= 14 => {
            // A number, in the x87's own 80-bit format.
            let value = f64_from_extended(&body[4..14]);
            match address {
                Address::Plain => {
                    let _ = writeln!(out, "R{row}C{col}\t{value}");
                }
                Address::WithBlock => {
                    let _ = writeln!(out, "B{block}R{row}C{col}\t{value}");
                }
            }
            *emitted += 1;
        }
        0x0019 | 0x001A => {
            // The v4's formula records: the token stream of the formula,
            // and the result it was last evaluated to. The result does not
            // say whether it holds a number or a string, and the tokens
            // that would say are not decoded, so the cell is not placed.
            *skipped += 1;
        }
        0x0018 => {
            // An integer cell: a `u16` whose unit is not established. The
            // example sheet's twin in the old layout reads exactly half of
            // it, and the sheet's own arithmetic agrees with the twin; the
            // integers of a real v4 sheet, on the other hand, only make
            // sense as cents. Two corpus files, two units, so this reader
            // does not know what the number means and does not place the
            // cell: a cell read with the wrong unit is a wrong cell.
            *skipped += 1;
        }
        _ => {}
    }
    Ok(total)
}

/// Decode the x87 80-bit extended float a v3 number cell carries.
///
/// The value is a 64-bit significand and a 15-bit exponent, the layout
/// the x87 FPU registers use. The corpus holds the same sheet in the old
/// layout, where the number is an `f64`, and the two agree to the last
/// bit the `f64` can hold: the v3 file simply keeps the number in more
/// bits than the reader prints.
fn f64_from_extended(bytes: &[u8]) -> f64 {
    if bytes.len() < 10 {
        return 0.0;
    }
    let significand = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let se = u16::from_le_bytes([bytes[8], bytes[9]]);
    let sign = if se & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = (se & 0x7fff) as i32;
    if exponent == 0x7fff {
        // The significand tells an infinity from a NaN.
        return if significand == 0 {
            sign * f64::INFINITY
        } else {
            f64::NAN
        };
    }
    if significand == 0 {
        return 0.0 * sign;
    }
    // The value is the significand times 2^(exponent - 16383 - 63).
    let scale = exponent - 16383 - 63;
    let mut bits = (significand as f64).to_bits();
    let biased = ((bits >> 52) & 0x7ff) as i32 + scale;
    if biased > 0 && biased < 0x7ff {
        // The ordinary case: the scale moves the exponent and touches
        // nothing else, so the result is the correctly rounded value.
        bits = (bits & 0x800f_ffff_ffff_ffff) | ((biased as u64) << 52);
        return f64::from_bits(bits);
    }
    // Too small or too large for a normal `f64`: scale it in steps.
    let mut value = significand as f64;
    let mut steps = scale;
    while steps > 0 {
        value *= 2.0;
        steps -= 1;
    }
    while steps < 0 && value != 0.0 {
        value *= 0.5;
        steps += 1;
    }
    sign * value
}

/// Walk one Millennium (`.123`) record.
///
/// The framing is the v3's -- a u16 opcode, a u16 length, and the body --
/// but the cell records are the format's own: the row, the column in
/// 256ths of a character, and the payload.
///
/// The oracle is the corpus's own pair: `example.123` and `example.wk1` are
/// the same sheet, and every cell of one is the same cell of the other, at
/// the same address, with the same word.
fn walk_record_millennium(
    data: &[u8],
    pos: usize,
    out: &mut String,
    emitted: &mut usize,
    skipped: &mut usize,
) -> Result<usize> {
    if pos + 4 > data.len() {
        return Ok(0);
    }
    let opcode = u16::from_le_bytes([data[pos], data[pos + 1]]);
    let payload_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
    let total = 4usize.saturating_add(payload_len);
    if payload_len > MAX_RECORD_BYTES || pos.saturating_add(total) > data.len() {
        // Truncated record: stop the walk rather than read past the buffer.
        return Ok(0);
    }
    let body = &data[pos + 4..pos + total];
    if !matches!(opcode, 0x0016 | 0x0025 | 0x0027) {
        // Not a cell: the file's own workspace records -- the object tree,
        // the ranges, the formats -- are walked over.
        return Ok(total);
    }
    // The row and the column. The column counts 256ths of a character.
    if body.len() < 4 {
        return Ok(total);
    }
    let row = u16::from_le_bytes([body[0], body[1]]) as usize;
    let col = u16::from_le_bytes([body[2], body[3]]) as usize / 256;
    match opcode {
        0x0016 if body.len() >= 5 => {
            // The byte after the column says how the cell is displayed, not
            // what it holds: every text cell of the corpus holds text
            // after it, whatever the byte says.
            let text = &body[5..];
            let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
            if end > 0 {
                let label = String::from_utf8_lossy(&text[..end]);
                let _ = writeln!(out, "R{row}C{col}\t{label}");
                *emitted += 1;
            }
        }
        0x0027 if body.len() >= 12 => {
            // A number, in the `f64` the v1's numbers use.
            let value = f64::from_le_bytes(body[4..12].try_into().unwrap_or([0u8; 8]));
            let _ = writeln!(out, "R{row}C{col}\t{value}");
            *emitted += 1;
        }
        0x0025 => {
            // An indirect cell: the row and the column are here, but the
            // data is somewhere else in the file, and this reader does not
            // follow the reference -- so the cell is left out rather than
            // placed at an address with nothing behind it.
            *skipped += 1;
        }
        _ => {}
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    fn text_of(data: &[u8]) -> String {
        match Lotus.extract(data, "a.wk1").unwrap() {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("expected Outcome::Text"),
        }
    }

    /// The BOF: opcode 0x0000, length 2, version as LE u16.
    fn bof(version: u16) -> Vec<u8> {
        let mut buf = vec![0x00, 0x00, 0x02, 0x00];
        buf.extend_from_slice(&version.to_le_bytes());
        buf
    }

    /// A cell record under the framing the file actually uses: u16 opcode,
    /// u16 byte length, then attributes, column, row, payload.
    fn cell(opcode: u16, col: u16, row: u16, payload: &[u8]) -> Vec<u8> {
        let body_len = 5 + payload.len();
        let mut rec = Vec::with_capacity(4 + body_len);
        rec.extend_from_slice(&opcode.to_le_bytes());
        rec.extend_from_slice(&(body_len as u16).to_le_bytes());
        rec.push(0x80); // attributes
        rec.extend_from_slice(&col.to_le_bytes());
        rec.extend_from_slice(&row.to_le_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    #[test]
    fn wk1_integer_cell_is_emitted() {
        let mut buf = bof(0x0406);
        buf.extend_from_slice(&cell(0x000D, 0, 0, &42i16.to_le_bytes()));
        let out = text_of(&buf);
        assert!(out.contains("family: 1-2-3 v1/v2"), "{out}");
        assert!(out.contains("R0C0\t42"), "{out}");
    }

    #[test]
    fn number_cell_is_emitted_as_f64() {
        let mut buf = bof(0x0406);
        buf.extend_from_slice(&cell(0x000E, 2, 1, &1.5f64.to_le_bytes()));
        let out = text_of(&buf);
        assert!(out.contains("R1C2\t1.5"), "{out}");
    }

    #[test]
    fn label_cell_is_emitted_as_string() {
        // payload[0] is the alignment byte; the text is NUL-terminated.
        let mut label = vec![0x27u8];
        label.extend_from_slice(b"hello\0");
        let mut buf = bof(0x0406);
        buf.extend_from_slice(&cell(0x000F, 0, 5, &label));
        let out = text_of(&buf);
        assert!(out.contains("R5C0\thello"), "{out}");
    }

    #[test]
    fn wks_v1_is_also_parsed() {
        let mut buf = bof(0x0404);
        buf.extend_from_slice(&cell(0x000D, 9, 7, &9i16.to_le_bytes()));
        let out = text_of(&buf);
        assert!(out.contains("family: 1-2-3 v1/v2"), "{out}");
        assert!(out.contains("R7C9\t9"), "{out}");
    }

    /// The regression the four-byte framing exists for: a run of records
    /// whose lengths are odd makes a `2 + len` reader land two bytes early on
    /// record 1 and never recover, so only the first cell ever prints.
    #[test]
    fn a_run_of_records_is_walked_to_the_end_of_the_stream() {
        let mut buf = bof(0x0406);
        buf.extend_from_slice(&cell(0x000D, 0, 0, &1i16.to_le_bytes())); // 7-byte body
        buf.extend_from_slice(&cell(0x000D, 1, 0, &2i16.to_le_bytes()));
        buf.extend_from_slice(&cell(0x000D, 2, 0, &3i16.to_le_bytes()));
        buf.extend_from_slice(&cell(0x000D, 3, 0, &4i16.to_le_bytes()));
        let out = text_of(&buf);
        for (row, col, val) in [(0u16, 0u16, 1), (0, 1, 2), (0, 2, 3), (0, 3, 4)] {
            assert!(
                out.contains(&format!("R{row}C{col}\t{val}")),
                "missing R{row}C{col}={val} in {out}"
            );
        }
    }

    #[test]
    fn a_formula_reports_its_cached_result() {
        let mut buf = bof(0x0406);
        let mut payload = 0.5f64.to_le_bytes().to_vec();
        payload.extend_from_slice(&[0x1b, 0x00, 0x01]); // RPN tail we do not decode
        buf.extend_from_slice(&cell(0x0010, 30, 1, &payload));
        let out = text_of(&buf);
        assert!(out.contains("R1C30\t0.5 [formula]"), "{out}");
    }

    /// A record whose declared length runs past the end of the buffer must
    /// stop the walk, not read the next file's bytes as cells.
    #[test]
    fn a_truncated_record_stops_the_walk() {
        let mut buf = bof(0x0406);
        buf.extend_from_slice(&cell(0x000D, 0, 0, &7i16.to_le_bytes()));
        // A record that claims 400 bytes with 4 to give.
        buf.extend_from_slice(&0x000Du16.to_le_bytes());
        buf.extend_from_slice(&400u16.to_le_bytes());
        buf.extend_from_slice(b"\x80\x00\x00\x00\x00");
        let out = text_of(&buf);
        assert!(out.contains("R0C0\t7"), "{out}");
        assert_eq!(
            out.lines().filter(|l| l.starts_with('R')).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn a_sheet_with_no_cells_fails_loudly() {
        // The version is confirmed, so an empty stream is a failure worth a
        // note -- the next adapter would only misreport a Lotus sheet.
        assert!(Lotus.extract(&bof(0x0404), "a.wk1").is_err());
    }

    #[test]
    fn rejects_unknown_magic() {
        let buf = vec![0x99, 0x99, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00];
        assert!(Lotus.extract(&buf, "a.wk1").is_err());
    }

    /// A four-byte-framed record: u16 opcode, u16 length, and the body.
    fn record(opcode: u16, body: &[u8]) -> Vec<u8> {
        let mut rec = Vec::with_capacity(4 + body.len());
        rec.extend_from_slice(&opcode.to_le_bytes());
        rec.extend_from_slice(&(body.len() as u16).to_le_bytes());
        rec.extend_from_slice(body);
        rec
    }

    /// A WK3 cell record: u16 opcode, u16 length, then the row (u16 LE),
    /// the block, the column, and the payload.
    fn cell_v3(opcode: u16, row: u16, col: u8, payload: &[u8]) -> Vec<u8> {
        let body_len = 4 + payload.len();
        let mut rec = Vec::with_capacity(4 + body_len);
        rec.extend_from_slice(&opcode.to_le_bytes());
        rec.extend_from_slice(&(body_len as u16).to_le_bytes());
        rec.extend_from_slice(&row.to_le_bytes());
        rec.push(0); // block
        rec.push(col);
        rec.extend_from_slice(payload);
        rec
    }

    /// The x87 80-bit encoding of 1.0: the significand 0x8000000000000000
    /// and the exponent 0x3fff. These are the bytes `example.wk3` holds
    /// for the version number of the sheet.
    const EXTENDED_ONE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f];
    /// The x87 80-bit encoding of 5.0: the significand 0xa000000000000000
    /// and the exponent 0x4001.
    const EXTENDED_FIVE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0xa0, 0x01, 0x40];

    #[test]
    fn wk3_label_cell_is_emitted() {
        let mut buf = bof(0x1000);
        let mut payload = vec![0x27u8]; // the format byte
        payload.extend_from_slice(b"WK3 test file\0");
        buf.extend_from_slice(&cell_v3(0x0016, 0, 0, &payload));
        let out = text_of(&buf);
        assert!(out.contains("family: 1-2-3 v3.x (WK3)"), "{out}");
        assert!(out.contains("R0C0\tWK3 test file"), "{out}");
    }

    #[test]
    fn wk3_number_cell_is_emitted() {
        let mut buf = bof(0x1000);
        buf.extend_from_slice(&cell_v3(0x0017, 12, 1, &EXTENDED_FIVE));
        let out = text_of(&buf);
        assert!(out.contains("R12C1\t5"), "{out}");
    }

    /// The integer cell carries a number in a unit this reader does not
    /// know, so the cell is left out and the count of what was left out
    /// is said. Printing 84 where the sheet shows 42 would be a wrong
    /// cell, not a partial answer.
    #[test]
    fn wk3_integer_cell_is_not_placed_but_is_reported() {
        let mut buf = bof(0x1000);
        buf.extend_from_slice(&cell_v3(0x0016, 11, 5, b"\x27total\0"));
        buf.extend_from_slice(&cell_v3(0x0018, 12, 5, &84u16.to_le_bytes()));
        let out = text_of(&buf);
        assert!(out.contains("R11C5\ttotal"), "{out}");
        assert!(!out.contains("R12C5"), "{out}");
        assert!(out.contains("not read: 1 cells"), "{out}");
    }

    /// A cell of a second block cannot be placed at an address this
    /// reader cannot vouch for.
    #[test]
    fn wk3_cell_of_another_block_is_not_placed() {
        let mut buf = bof(0x1000);
        buf.extend_from_slice(&cell_v3(0x0016, 0, 0, b"\x27WK3 test file\0"));
        let mut rec = cell_v3(0x0016, 3, 2, b"\x27hello\0");
        rec[6] = 1; // the block byte
        buf.extend_from_slice(&rec);
        let out = text_of(&buf);
        assert!(out.contains("R0C0\tWK3 test file"), "{out}");
        assert!(!out.contains("R3C2"), "{out}");
        assert!(out.contains("not read: 1 cells"), "{out}");
    }

    /// The Millennium sheet's cell record is the row, the column in 256ths
    /// of a character, and the payload.
    #[test]
    fn wk123_label_cell_is_emitted() {
        let mut buf = bof(0x1005);
        let mut body = Vec::new();
        body.extend_from_slice(&2u16.to_le_bytes()); // the row
        body.extend_from_slice(&256u16.to_le_bytes()); // the column, in 256ths
        body.push(0x27); // the format byte
        body.extend_from_slice(b"hello\0");
        buf.extend_from_slice(&record(0x0016, &body));
        let out = text_of(&buf);
        assert!(out.contains("family: 1-2-3 Millennium (123)"), "{out}");
        assert!(out.contains("R2C1\thello"), "{out}");
    }

    /// A v4 sheet is split into tables, and the address says which one the
    /// cell belongs to: the same (row, column) holds different cells in
    /// different tables.
    #[test]
    fn wk4_cell_names_the_table_it_belongs_to() {
        let mut buf = bof(0x1002);
        let mut rec = cell_v3(0x0016, 2, 1, b"\x27hello\0");
        rec[6] = 3; // the block byte
        buf.extend_from_slice(&rec);
        let out = text_of(&buf);
        assert!(out.contains("family: 1-2-3 v4.x (WK4)"), "{out}");
        assert!(out.contains("B3R2C1\thello"), "{out}");
    }

    #[test]
    fn the_extended_float_decodes() {
        assert_eq!(f64_from_extended(&EXTENDED_ONE), 1.0);
        assert_eq!(f64_from_extended(&EXTENDED_FIVE), 5.0);
        assert_eq!(f64_from_extended(&[0u8; 10]), 0.0);
        // 1.5: the significand 0xc000000000000000, the exponent 0x3fff.
        assert_eq!(
            f64_from_extended(&[0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0x3f]),
            1.5
        );
    }
}
