// SPDX-License-Identifier: Apache-2.0

//! Legacy binary `.xls` (BIFF5/8): the `Workbook` stream inside the CFB
//! container holds a globals substream (BoundSheet8 directory + shared
//! string table) followed by one worksheet substream per sheet. We walk
//! the record chain and emit resolved cells (`A1: value`), the same shape
//! the xlsx path produces. Nothing else in the file is decoded.
//!
//! A reduced port of the XLS reader of the `io` project by Dan Gohman,
//! whose work is used here under Apache-2.0: the typed cell grid and the
//! shared string table per sheet are the shape it walks, and it flattens
//! them to text. See `NOTICE`.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use rgx_core::{decline, Context, Result};
use rgx_core::{Adapter, Outcome};

#[cfg(test)]
#[allow(unused_imports)]
use alloc::string::ToString;
#[cfg(test)]
#[allow(unused_imports)]
use core::iter;

const MAX_OUT: usize = 16 << 20;

const REC_BOF: u16 = 0x0809;
const REC_EOF: u16 = 0x000A;
const REC_SST: u16 = 0x00FC;
const REC_CONTINUE: u16 = 0x003C;
const REC_BOUNDSHEET: u16 = 0x0085;
const REC_LABELSST: u16 = 0x00FD;
const REC_LABEL: u16 = 0x0204;
const REC_RK: u16 = 0x027E;
const REC_MULRK: u16 = 0x00BD;
const REC_NUMBER: u16 = 0x0203;
const REC_FORMULA: u16 = 0x0006;
const REC_STRING: u16 = 0x0207; // string result of a formula
const REC_BOOLERR: u16 = 0x0205;

/// Bounds-checked little-endian readers over a record payload.
fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}
fn f64_at(b: &[u8], i: usize) -> Option<f64> {
    Some(f64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

/// Sequential reader across one or more record payloads (SST + CONTINUEs).
/// At a buffer boundary *inside* a string's character data, BIFF starts the
/// CONTINUE payload with a fresh option-flags byte — the caller handles that
/// via `read_char_flags` when it runs out of chars mid-string.
struct ChainReader<'a> {
    bufs: &'a [&'a [u8]],
    bi: usize,
    pos: usize,
}

impl<'a> ChainReader<'a> {
    fn new(bufs: &'a [&'a [u8]]) -> Self {
        ChainReader {
            bufs,
            bi: 0,
            pos: 0,
        }
    }
    fn exhausted(&self) -> bool {
        self.bi >= self.bufs.len()
    }
    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.bufs.get(self.bi)?.get(self.pos)?;
        self.pos += 1;
        if self.pos >= self.bufs[self.bi].len() {
            self.bi += 1;
            self.pos = 0;
        }
        Some(b)
    }
    fn read_u16(&mut self) -> Option<u16> {
        let lo = self.read_u8()? as u16;
        let hi = self.read_u8()? as u16;
        Some(lo | (hi << 8))
    }
    fn read_u32(&mut self) -> Option<u32> {
        let lo = self.read_u16()? as u32;
        let hi = self.read_u16()? as u32;
        Some(lo | (hi << 16))
    }
    /// Read up to `want` characters with the given byte-width; returns the
    /// decoded string, chars actually read, and whether a buffer boundary
    /// was crossed (caller must then read a fresh flags byte).
    fn read_chars(&mut self, want: usize, wide: bool) -> (String, usize, bool) {
        let mut out = String::new();
        let mut got = 0usize;
        while got < want && !self.exhausted() {
            let buf = self.bufs[self.bi];
            let avail = buf.len() - self.pos;
            let unit = if wide { 2 } else { 1 };
            let take = (want - got).min(avail / unit);
            if take == 0 {
                // not enough bytes left for one char in this buffer
                if avail == 0 {
                    self.bi += 1;
                    self.pos = 0;
                    continue;
                }
                break; // dangling half-char: stop, caller gives up on us
            }
            let bytes = &buf[self.pos..self.pos + take * unit];
            if wide {
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                out.push_str(&String::from_utf16_lossy(&units));
            } else {
                // A narrow BIFF8 string is the compressed Unicode form:
                // a byte below 0x80 is ASCII and a byte above it is
                // Latin-1. It is not UTF-8, and reading it as such replaced
                // the accented characters with U+FFFD.
                out.push_str(
                    &String::from_utf8(rgx_core::charset::decode(rgx_core::charset::LATIN1, bytes))
                        .unwrap_or_default(),
                );
            }
            self.pos += take * unit;
            got += take;
            if self.pos >= buf.len() && got < want {
                self.bi += 1;
                self.pos = 0;
                // boundary crossed mid-string: next byte is a new flags byte
                return (out, got, true);
            }
        }
        (out, got, false)
    }
    fn skip(&mut self, mut n: usize) {
        while n > 0 && !self.exhausted() {
            let avail = self.bufs[self.bi].len() - self.pos;
            let take = n.min(avail);
            self.pos += take;
            n -= take;
            if self.pos >= self.bufs[self.bi].len() {
                self.bi += 1;
                self.pos = 0;
            }
        }
    }
}

/// Parse the SST record plus its CONTINUE chain into shared strings.
fn parse_sst(bufs: &[&[u8]]) -> Vec<String> {
    let mut r = ChainReader::new(bufs);
    let Some(_total) = r.read_u32() else {
        return Vec::new();
    };
    let Some(unique) = r.read_u32() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(unique.min(1 << 20) as usize);
    for _ in 0..unique {
        let Some(cch) = r.read_u16() else { break };
        let Some(flags) = r.read_u8() else { break };
        let mut wide = flags & 0x01 != 0;
        let rich = flags & 0x08 != 0;
        let ext = flags & 0x04 != 0;
        let c_run = if rich {
            r.read_u16().unwrap_or(0) as usize
        } else {
            0
        };
        let cb_ext = if ext {
            r.read_u32().unwrap_or(0) as usize
        } else {
            0
        };
        let mut s = String::with_capacity(cch as usize);
        let mut remaining = cch as usize;
        while remaining > 0 {
            let (part, got, crossed) = r.read_chars(remaining, wide);
            s.push_str(&part);
            remaining -= got;
            if remaining == 0 {
                break;
            }
            if crossed {
                // CONTINUE payload starts with a fresh flags byte
                match r.read_u8() {
                    Some(f) => wide = f & 0x01 != 0,
                    None => break,
                }
            } else {
                // ran out of buffers entirely
                break;
            }
        }
        // formatting runs (4 bytes each) + ext data follow the chars
        r.skip(c_run.saturating_mul(4).saturating_add(cb_ext));
        out.push(s);
        if r.exhausted() && out.len() as u32 >= unique {
            break;
        }
    }
    out
}

/// RK: 30 payload bits with fX100 (÷100) and fInt flags in the low bits.
fn decode_rk(raw: u32) -> Option<f64> {
    let mult100 = raw & 0x01 != 0;
    let is_int = raw & 0x02 != 0;
    let mut v = if is_int {
        // signed 30-bit integer in the high bits
        let bits = (raw >> 2) as i32;
        let sign_extended = if bits & 0x2000_0000 != 0 {
            bits | !0x3FFF_FFFF
        } else {
            bits
        };
        sign_extended as f64
    } else {
        // top 30 bits of an IEEE-754 double (low 34 bits zero)
        let hi = raw & 0xFFFF_FFFC;
        f64::from_bits((hi as u64) << 32)
    };
    if mult100 {
        v /= 100.0;
    }
    Some(v)
}

fn col_letters(mut col: u16) -> String {
    let mut s = Vec::new();
    loop {
        let r = (col % 26) as u8;
        s.push(b'A' + r);
        if col < 26 {
            break;
        }
        col = col / 26 - 1;
    }
    s.reverse();
    String::from_utf8(s).unwrap_or_default()
}

fn num_fmt(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

pub fn extract_text(data: &[u8]) -> Result<String> {
    use rgx_core::cfb::Cfb;
    let cfb = Cfb::parse(data)?;
    let wb = cfb
        .stream("Workbook")
        .or_else(|| cfb.stream("Book"))
        .decline_context("no Workbook stream")?;
    if wb.len() < 4 || u16_at(&wb, 0) != Some(REC_BOF) {
        decline!("Workbook stream does not start with BOF");
    }

    // Pass 1: directory (BoundSheet8) + shared strings (SST + CONTINUE).
    let mut sheets: Vec<(u32, String)> = Vec::new(); // (stream offset, name)
    let mut sst: Vec<String> = Vec::new();
    let mut p = 0usize;
    while p + 4 <= wb.len() {
        let ty = u16_at(&wb, p).unwrap();
        let len = u16_at(&wb, p + 2).unwrap_or(0) as usize;
        let body = p + 4;
        let end = body.saturating_add(len).min(wb.len());
        match ty {
            REC_BOUNDSHEET => {
                if let (Some(off), Some(cch)) =
                    (u32_at(&wb, body), u16_at(&wb, body + 6).map(|v| v as usize))
                {
                    let grbit = wb.get(body + 7).copied().unwrap_or(0);
                    let start = body + 8;
                    let name = if grbit & 0x01 != 0 {
                        let units: Vec<u16> = wb
                            .get(
                                start..start + cch.saturating_mul(2).min(end.saturating_sub(start)),
                            )
                            .unwrap_or(&[])
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&units)
                    } else {
                        // The narrow form of a BIFF8 string is Latin-1.
                        String::from_utf8(rgx_core::charset::decode(
                            rgx_core::charset::LATIN1,
                            wb.get(start..start + cch.min(end.saturating_sub(start)))
                                .unwrap_or(&[]),
                        ))
                        .unwrap_or_default()
                    };
                    sheets.push((off, name));
                }
            }
            REC_SST => {
                // gather the CONTINUE chain
                let mut bufs: Vec<&[u8]> = vec![&wb[body..end]];
                let mut q = end;
                while q + 4 <= wb.len() && u16_at(&wb, q) == Some(REC_CONTINUE) {
                    let clen = u16_at(&wb, q + 2).unwrap_or(0) as usize;
                    let cbody = q + 4;
                    let cend = cbody.saturating_add(clen).min(wb.len());
                    bufs.push(&wb[cbody..cend]);
                    q = cend;
                }
                sst = parse_sst(&bufs);
            }
            _ => {}
        }
        p = end.max(p + 4);
        if ty == REC_EOF {
            break; // end of the globals substream; sheets follow separately
        }
    }

    if sheets.is_empty() {
        decline!("no BoundSheet8 records (not a BIFF workbook?)");
    }

    // Pass 2: worksheet substreams → cells. A sheet's records live at the
    // BoundSheet offset and start with a BOF of type 0x0010.
    let mut out = String::new();
    for (off, name) in &sheets {
        if out.len() > MAX_OUT {
            break;
        }
        let start = *off as usize;
        if start + 4 > wb.len() || u16_at(&wb, start) != Some(REC_BOF) {
            continue; // chartsheets / macrosheets: nothing greppable
        }
        let mut p = start;
        let mut pending_str: Option<(u16, u16)> = None;
        let mut any_cell = false;
        let _ = writeln!(out, "=== {name} ===");
        use core::fmt::Write as _;
        // Stream cells directly into `out` as the BIFF records are
        // encountered. The previous shape buffered them in a
        // `Vec<Cell>` and re-walked the vector at the end, cloning
        // every shared-string cell from the SST (`sst.get(...).cloned()`)
        // along the way. A 50 000-cell worksheet was 50 000 heap
        // strings and a 50 000-element Vec, then 50 000 throwaway
        // `format!` strings. The new path is zero-allocations per
        // cell: a `&str` from the SST borrowed directly, the col
        // computed inline, and the line written through `write!`.
        while p + 4 <= wb.len() {
            let ty = u16_at(&wb, p).unwrap();
            let len = u16_at(&wb, p + 2).unwrap_or(0) as usize;
            let body = p + 4;
            let end = body.saturating_add(len).min(wb.len());
            let b = &wb[body..end];
            match ty {
                REC_BOF => {
                    if p != start {
                        break; // next substream begins
                    }
                    if u16_at(b, 2) != Some(0x0010) {
                        break; // not a worksheet substream (e.g. chart)
                    }
                }
                REC_LABELSST => {
                    if let (Some(r), Some(c), Some(ix)) = (u16_at(b, 0), u16_at(b, 2), u32_at(b, 6))
                    {
                        if let Some(v) = sst.get(ix as usize) {
                            if !v.is_empty() {
                                let _ = writeln!(out, "{}{}: {}", col_letters(c), r + 1, v);
                                any_cell = true;
                            }
                        }
                    }
                }
                REC_LABEL => {
                    // BIFF5: cch + cp1252 bytes; BIFF8: cch + grbit + chars
                    if let (Some(r), Some(c), Some(cch)) =
                        (u16_at(b, 0), u16_at(b, 2), u16_at(b, 6).map(|v| v as usize))
                    {
                        let avail = b.len().saturating_sub(8);
                        let v = if avail >= cch && avail < cch + 1 {
                            // BIFF5 strings are cp1252, and the format says
                            // so in the record itself. Reading them as UTF-8
                            // does not read them differently -- it replaces
                            // every byte above 0x7F with U+FFFD, and the
                            // character is gone.
                            Cow::Owned(
                                String::from_utf8(rgx_core::charset::decode(
                                    rgx_core::charset::WINDOWS_1252,
                                    &b[8..8 + cch],
                                ))
                                .unwrap_or_default(),
                            )
                        } else {
                            match b.get(8) {
                                Some(&grbit) => {
                                    let wide = grbit & 0x01 != 0;
                                    let unit = if wide { 2 } else { 1 };
                                    let n = cch.saturating_mul(unit).min(b.len().saturating_sub(9));
                                    let bytes = &b[9..9 + n];
                                    if wide {
                                        let units: Vec<u16> = bytes
                                            .as_chunks::<2>()
                                            .0
                                            .iter()
                                            .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                                            .collect();
                                        Cow::Owned(String::from_utf16_lossy(&units))
                                    } else {
                                        // BIFF8's compressed Unicode form: a
                                        // byte below 0x80 is ASCII and a byte
                                        // above it is Latin-1. The string is
                                        // not UTF-8, and reading it as such
                                        // dropped the whole cell.
                                        Cow::Owned(
                                            String::from_utf8(rgx_core::charset::decode(
                                                rgx_core::charset::LATIN1,
                                                bytes,
                                            ))
                                            .unwrap_or_default(),
                                        )
                                    }
                                }
                                None => Cow::Borrowed(""),
                            }
                        };
                        if !v.is_empty() {
                            let _ = writeln!(out, "{}{}: {}", col_letters(c), r + 1, v);
                            any_cell = true;
                        }
                    }
                }
                REC_NUMBER => {
                    if let (Some(r), Some(c), Some(v)) = (u16_at(b, 0), u16_at(b, 2), f64_at(b, 6))
                    {
                        let _ = writeln!(out, "{}{}: {}", col_letters(c), r + 1, num_fmt(v));
                        any_cell = true;
                    }
                }
                REC_RK => {
                    if let (Some(r), Some(c), Some(rk)) = (u16_at(b, 0), u16_at(b, 2), u32_at(b, 6))
                    {
                        if let Some(v) = decode_rk(rk) {
                            let _ = writeln!(out, "{}{}: {}", col_letters(c), r + 1, num_fmt(v));
                            any_cell = true;
                        }
                    }
                }
                REC_MULRK => {
                    if let (Some(r), Some(col_first)) = (u16_at(b, 0), u16_at(b, 2)) {
                        // row(2) + colFirst(2) + n*(ixfe(2) + rk(4)) + colLast(2):
                        // 6 bytes of overhead around the n six-byte pairs.
                        // The column is NOT in the record: ixfe's low 14 bits
                        // are the extended-formatting (XF) index, not a column
                        // number, and rgx does not use formatting. The column
                        // of entry k is colFirst + k, which is what Excel
                        // writes contiguously.
                        let n = b.len().saturating_sub(6) / 6;
                        for k in 0..n {
                            let base = 4 + k * 6;
                            if let Some(rk) = u32_at(b, base + 2) {
                                if let Some(v) = decode_rk(rk) {
                                    // saturating: a corrupt record can declare
                                    // colFirst near u16::MAX with enough
                                    // entries that `col_first + k` overflows
                                    let col = col_first.saturating_add(k as u16);
                                    let _ = writeln!(
                                        out,
                                        "{}{}: {}",
                                        col_letters(col),
                                        r + 1,
                                        num_fmt(v)
                                    );
                                    any_cell = true;
                                }
                            }
                        }
                    }
                }
                REC_FORMULA => {
                    if let (Some(r), Some(c)) = (u16_at(b, 0), u16_at(b, 2)) {
                        if let Some(res) = b.get(6..14) {
                            if res[6..8] == [0xFF, 0xFF] {
                                match res[0] {
                                    0 => pending_str = Some((r, c)), // STRING record follows
                                    1 => {
                                        let s = if res[2] != 0 { "TRUE" } else { "FALSE" };
                                        let _ = writeln!(out, "{}{}: {}", col_letters(c), r + 1, s);
                                        any_cell = true;
                                    }
                                    _ => {} // error / empty: skip
                                }
                            } else if let Some(v) = f64_at(b, 6) {
                                let _ =
                                    writeln!(out, "{}{}: {}", col_letters(c), r + 1, num_fmt(v));
                                any_cell = true;
                            }
                        }
                    }
                }
                REC_STRING => {
                    if let Some((r, c)) = pending_str.take() {
                        // XLUnicodeString: cch u16, grbit u8, chars
                        if let Some(cch) = u16_at(b, 0).map(|v| v as usize) {
                            let wide = b.get(2).is_some_and(|f| f & 0x01 != 0);
                            let unit = if wide { 2 } else { 1 };
                            let n = cch.saturating_mul(unit).min(b.len().saturating_sub(3));
                            let bytes = &b[3..3 + n];
                            let v = if wide {
                                let units: Vec<u16> = bytes
                                    .as_chunks::<2>()
                                    .0
                                    .iter()
                                    .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                                    .collect();
                                Cow::Owned(String::from_utf16_lossy(&units))
                            } else {
                                Cow::Borrowed(core::str::from_utf8(bytes).unwrap_or(""))
                            };
                            if !v.is_empty() {
                                let _ = writeln!(out, "{}{}: {}", col_letters(c), r + 1, v);
                                any_cell = true;
                            }
                        }
                    }
                }
                REC_BOOLERR => {
                    if let (Some(r), Some(c), Some(v)) = (u16_at(b, 0), u16_at(b, 2), b.get(6)) {
                        let is_err = b.get(7).is_some_and(|e| *e != 0);
                        if !is_err {
                            let s = if *v != 0 { "TRUE" } else { "FALSE" };
                            let _ = writeln!(out, "{}{}: {}", col_letters(c), r + 1, s);
                            any_cell = true;
                        }
                    }
                }
                REC_EOF => break,
                _ => {}
            }
            p = end.max(p + 4);
        }
        // If this worksheet was empty (e.g. a chart sheet left over
        // from the BOF skip), trim the header we wrote so the
        // final check still catches a no-cells workbook.
        if !any_cell {
            // Pop the "=== {name} ===\n" line. The output had exactly
            // that suffix; truncating to its length is safe because
            // no other text was written.
            let header = format!("=== {name} ===\n");
            let new_len = out.len().saturating_sub(header.len());
            out.truncate(new_len);
        }
    }
    if out.trim().is_empty() {
        decline!("no cells in workbook");
    }
    Ok(out)
}

pub struct Xls;
impl Adapter for Xls {
    fn name(&self) -> &'static str {
        "xls"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["xls", "xlt", "xlm"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(extract_text(data)?.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal CFB image with regular-sector streams only (every stream
    /// padded to ≥4096 bytes so the mini stream is never needed).
    fn cfb_image(streams: &[(&str, &[u8])]) -> Vec<u8> {
        const SS: usize = 512;
        let mut sectors: Vec<Vec<u8>> = Vec::new();
        let mut entries: Vec<(String, usize, u64)> = Vec::new();
        for (name, data) in streams {
            let start = sectors.len();
            let mut padded = data.to_vec();
            padded.resize(data.len().div_ceil(SS) * SS, 0);
            for chunk in padded.chunks(SS) {
                sectors.push(chunk.to_vec());
            }
            entries.push((name.to_string(), start, data.len() as u64));
        }
        let dir_sector = sectors.len();
        sectors.push(vec![0xFF; SS]);
        let fat_sector = sectors.len();
        sectors.push(vec![0; SS]);

        let mut fat = vec![0xFFFFFFFFu32; SS / 4];
        let mark_chain = |start: usize, count: usize, fat: &mut Vec<u32>| {
            for k in 0..count {
                fat[start + k] = if k + 1 < count {
                    (start + k + 1) as u32
                } else {
                    0xFFFFFFFE
                };
            }
        };
        for (_, start, size) in &entries {
            mark_chain(*start, (*size as usize).div_ceil(SS), &mut fat);
        }
        fat[dir_sector] = 0xFFFFFFFE;
        sectors[fat_sector] = fat.iter().flat_map(|v| v.to_le_bytes()).collect();

        let mut dir = vec![0u8; SS];
        let write_entry =
            |buf: &mut [u8], idx: usize, name: &str, ty: u8, start: u32, size: u64| {
                let e = &mut buf[idx * 128..idx * 128 + 128];
                let wide: Vec<u16> = name.encode_utf16().chain(iter::once(0)).collect();
                for (i, u) in wide.iter().enumerate() {
                    e[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
                }
                e[64] = (wide.len() * 2) as u8;
                e[66] = ty;
                e[68..72].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
                e[72..76].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
                e[116..120].copy_from_slice(&start.to_le_bytes());
                e[120..128].copy_from_slice(&size.to_le_bytes());
            };
        write_entry(&mut dir, 0, "Root Entry", 5, 0xFFFFFFFE, 0);
        for (i, (name, start, size)) in entries.iter().enumerate() {
            write_entry(&mut dir, i + 1, name, 2, *start as u32, *size);
        }
        sectors[dir_sector] = dir;

        let total = sectors.len();
        let mut img = Vec::with_capacity(512 + total * SS);
        let mut hdr = vec![0u8; 512];
        hdr[0..8].copy_from_slice(&0xD0CF11E0A1B11AE1u64.to_be_bytes());
        hdr[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
        hdr[26..28].copy_from_slice(&0x0003u16.to_le_bytes());
        hdr[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        hdr[30..32].copy_from_slice(&9u16.to_le_bytes());
        hdr[32..34].copy_from_slice(&6u16.to_le_bytes());
        hdr[44..48].copy_from_slice(&(fat_sector as u32).to_le_bytes());
        hdr[48..52].copy_from_slice(&(dir_sector as u32).to_le_bytes());
        hdr[56..60].copy_from_slice(&4096u32.to_le_bytes());
        hdr[60..64].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes());
        hdr[68..72].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes());
        hdr[76..80].copy_from_slice(&(fat_sector as u32).to_le_bytes());
        for k in 1..109 {
            hdr[76 + k * 4..80 + k * 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        }
        img.extend_from_slice(&hdr);
        for s in &sectors {
            img.extend_from_slice(s);
        }
        img
    }

    fn rec(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + payload.len());
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn bof(dt: u16) -> Vec<u8> {
        rec(REC_BOF, &{
            let mut b = Vec::new();
            b.extend_from_slice(&0x0600u16.to_le_bytes()); // BIFF8
            b.extend_from_slice(&dt.to_le_bytes());
            b
        })
    }

    fn boundsheet(offset: u32, name: &str) -> Vec<u8> {
        rec(REC_BOUNDSHEET, &{
            let mut b = Vec::new();
            b.extend_from_slice(&offset.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes()); // hsState/hsType
            b.push(name.len() as u8);
            b.push(0u8); // compressed
            b.extend_from_slice(name.as_bytes());
            b
        })
    }

    /// XLUnicodeString with the high-byte flag.
    fn sst_entry(s: &str, wide: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(s.chars().count() as u16).to_le_bytes());
        b.push(wide as u8);
        if wide {
            for u in s.encode_utf16() {
                b.extend_from_slice(&u.to_le_bytes());
            }
        } else {
            b.extend_from_slice(s.as_bytes());
        }
        b
    }

    fn labelsst(row: u16, col: u16, isst: u32) -> Vec<u8> {
        rec(REC_LABELSST, &{
            let mut b = Vec::new();
            b.extend_from_slice(&row.to_le_bytes());
            b.extend_from_slice(&col.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes()); // ixfe
            b.extend_from_slice(&isst.to_le_bytes());
            b
        })
    }

    fn number(row: u16, col: u16, v: f64) -> Vec<u8> {
        rec(REC_NUMBER, &{
            let mut b = Vec::new();
            b.extend_from_slice(&row.to_le_bytes());
            b.extend_from_slice(&col.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&v.to_le_bytes());
            b
        })
    }

    fn rk(row: u16, col: u16, raw: u32) -> Vec<u8> {
        rec(REC_RK, &{
            let mut b = Vec::new();
            b.extend_from_slice(&row.to_le_bytes());
            b.extend_from_slice(&col.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&raw.to_le_bytes());
            b
        })
    }

    /// Synthetic BIFF8 workbook with one sheet holding every record kind
    /// we decode.
    pub(super) fn sample_xls() -> Vec<u8> {
        let sst_payload = {
            let mut b = Vec::new();
            b.extend_from_slice(&3u32.to_le_bytes()); // total
            b.extend_from_slice(&3u32.to_le_bytes()); // unique
            b.extend_from_slice(&sst_entry("grid_3", false));
            b.extend_from_slice(&sst_entry("ZIRCALOY", false));
            b.extend_from_slice(&sst_entry("fórmula Σ", true));
            b
        };
        let globals = [
            bof(0x0005),
            boundsheet(0, "Data"), // patched below
            rec(REC_SST, &sst_payload),
            rec(REC_EOF, &[]),
        ]
        .concat();

        let sheet = [
            bof(0x0010),
            labelsst(0, 0, 0),
            labelsst(0, 1, 1),
            labelsst(0, 2, 2),
            number(1, 0, 42.0),
            rk(1, 1, (7 << 2) | 0x02),   // int 7
            rk(1, 2, (314 << 2) | 0x03), // 314 ÷ 100 = 3.14
            rec(REC_MULRK, &{
                let mut b = Vec::new();
                b.extend_from_slice(&2u16.to_le_bytes()); // row
                b.extend_from_slice(&0u16.to_le_bytes()); // colFirst
                for (i, v) in [(1u32, (10u32 << 2) | 0x02), (1, (20 << 2) | 0x02)] {
                    let _ = i;
                    b.extend_from_slice(&0u16.to_le_bytes()); // ixfe
                    b.extend_from_slice(&v.to_le_bytes());
                }
                b.extend_from_slice(&1u16.to_le_bytes()); // colLast
                b
            }),
            rec(REC_FORMULA, &{
                let mut b = Vec::new();
                b.extend_from_slice(&3u16.to_le_bytes());
                b.extend_from_slice(&0u16.to_le_bytes());
                b.extend_from_slice(&0u16.to_le_bytes());
                b.extend_from_slice(&123.5f64.to_le_bytes());
                b
            }),
            rec(REC_BOOLERR, &{
                let mut b = Vec::new();
                b.extend_from_slice(&4u16.to_le_bytes());
                b.extend_from_slice(&0u16.to_le_bytes());
                b.extend_from_slice(&0u16.to_le_bytes());
                b.push(1); // TRUE
                b.push(0); // not an error
                b
            }),
            rec(REC_EOF, &[]),
        ]
        .concat();

        let sheet_off = globals.len() as u32;
        // patch the BoundSheet offset (bytes 4+4 in globals)
        let mut g = globals;
        g[12..16].copy_from_slice(&sheet_off.to_le_bytes()); // BoundSheet payload

        let wb = [g, sheet].concat();
        let mut pad = wb;
        pad.resize(4096, 0);
        cfb_image(&[("Workbook", &pad)])
    }

    #[test]
    fn decodes_all_cell_kinds() {
        let text = extract_text(&sample_xls()).unwrap();
        assert!(text.contains("=== Data ==="), "{text}");
        assert!(text.contains("A1: grid_3"), "{text}");
        assert!(text.contains("B1: ZIRCALOY"), "{text}");
        assert!(text.contains("C1: fórmula Σ"), "{text}");
        assert!(text.contains("A2: 42"), "{text}");
        assert!(text.contains("B2: 7"), "{text}");
        assert!(text.contains("C2: 3.14"), "{text}");
        assert!(text.contains("A3: 10"), "{text}");
        assert!(text.contains("B3: 20"), "{text}");
        assert!(text.contains("A4: 123.5"), "{text}");
        assert!(text.contains("A5: TRUE"), "{text}");
    }

    #[test]
    fn sst_continuation_resets_wide_flag() {
        // "AB" split across SST→CONTINUE: first buffer holds 'A' (compressed),
        // CONTINUE payload starts with flags=1 then UTF-16 'B'.
        let mut sst_part = Vec::new();
        sst_part.extend_from_slice(&1u32.to_le_bytes()); // total
        sst_part.extend_from_slice(&1u32.to_le_bytes()); // unique
        sst_part.extend_from_slice(&2u16.to_le_bytes()); // cch
        sst_part.push(0u8); // flags: compressed
        sst_part.push(b'A');
        let mut cont = Vec::new();
        cont.push(1u8); // flags: wide
        cont.extend_from_slice(&('B' as u16).to_le_bytes());

        let globals = [
            bof(0x0005),
            boundsheet(0, "S"),
            rec(REC_SST, &sst_part),
            rec(REC_CONTINUE, &cont),
            rec(REC_EOF, &[]),
        ]
        .concat();
        let sheet = [bof(0x0010), labelsst(0, 0, 0), rec(REC_EOF, &[])].concat();
        let sheet_off = globals.len() as u32;
        let mut g = globals;
        g[12..16].copy_from_slice(&sheet_off.to_le_bytes()); // BoundSheet payload
        let wb = [g, sheet].concat();
        let mut pad = wb;
        pad.resize(4096, 0);
        let text = extract_text(&cfb_image(&[("Workbook", &pad)])).unwrap();
        assert!(text.contains("A1: AB"), "{text}");
    }

    #[test]
    fn rejects_non_xls() {
        assert!(extract_text(b"not an xls at all").is_err());
    }

    #[test]
    fn rejects_cfb_without_workbook() {
        let img = cfb_image(&[("Random Stream", &vec![0u8; 4096])]);
        assert!(extract_text(&img).is_err());
    }

    #[test]
    fn never_panics_on_mutation() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![("sample", sample_xls()), ("empty", vec![])],
            2000,
            "xls",
            |data| {
                let _ = extract_text(data);
            },
        );
    }
}
