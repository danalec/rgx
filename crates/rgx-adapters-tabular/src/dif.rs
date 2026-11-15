// SPDX-License-Identifier: Apache-2.0

//! DIF (Data Interchange Format) -- the VisiCalc spreadsheet interchange
//! format that survived into Lotus 1-2-3 and Excel.
//!
//! Plain text. Sections are keyword lines that name what follows:
//!
//! ```text
//! TABLE
//! 0,1
//! "<title>"
//! VECTORS
//! 0,N
//! ""
//! <type-token>          # NUMBER or STRING, repeated N times
//! TUPLES
//! 0,N
//! ""
//! <type-token>          # same tokens, but one per ROW rather than per
//!                       # column; the values themselves are in DATA
//! DATA
//! 0,0
//! "<value>"             # a logical row is one or more cell values...
//! -1,0                  # ...closed by a sentinel pair (-1,0) or ""
//! -1,0
//! EOT
//! ```
//!
//! Two sentinels close a row: a `""` line, or a `-1,0` pair. Writers disagree
//! on which to emit and Excel mixes both, so the parser walks until either
//! appears. A numeric first token with `0,0` opens the data section; the
//! `-1,0` at end-of-row carries `-1` as the column to mean "this row has no
//! value in column N+1" and writers fill the gap by emitting `-1` repeatedly.
//!
//! Cell values are emitted as `C<col>\t<value>`; the parser is lossy about
//! column letters and preserves order. Number cells pass through `f64` so a
//! spreadsheet literal like `1.5e3` reads back the same way.
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Reach, Result};

/// Cap on rows. A workbook with millions of rows fits; an unknown sender with
/// no row sentinel will not bound itself, so we do.
const MAX_ROWS: usize = 200_000;
/// Cap on cells per row. The format allows N-of-them declarations in VECTARS;
/// a degenerate one can claim a million columns and exhaust memory.
const MAX_COLS: usize = 16_384;

/// DIF: Data Interchange Format, the VisiCalc/Lotus/Excel text interchange.
pub struct Dif;
impl Adapter for Dif {
    fn name(&self) -> &'static str {
        "dif"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dif"]
    }
    /// DIF is plain text, so ripgrep already reads it — and this rendering is
    /// lossy about it: the `TABLE`/`VECTORS`/`TUPLES`/`DATA` section keywords
    /// and the column-type tokens are consumed rather than emitted, so a
    /// pattern that occurs only in one of them is a line `rg` prints and this
    /// rendering does not.
    ///
    /// `Render` is therefore the honest answer, and under the default
    /// `Policy::Source` it is the one that keeps the file's own bytes in the
    /// corpus. Left as the default `Reveal`, the file's bytes were dropped in
    /// favour of the rendering, and rgx became a strict subset of ripgrep on
    /// every `.dif`.
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // DIF is plain ASCII text. `from_utf8_lossy` keeps the layout and
        // marks the undecodable bytes; a strict UTF-8 read would reject
        // every file written by a non-UTF-8 codepage, which is most of them.
        let text = String::from_utf8_lossy(data);
        let mut out = String::new();
        let mut emitted = 0usize;

        let mut section = Section::Header;
        let mut col_types: Vec<DifType> = Vec::new();
        let mut row_types: Vec<DifType> = Vec::new();
        let mut col_index: u32 = 0;
        let mut row_buf: Vec<String> = Vec::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim_end_matches('\r').trim();
            if line.is_empty() {
                continue;
            }
            // Section keywords come on a line by themselves. A file that
            // happens to start with the word `TABLE` is not DIF, but a
            // spreadsheet cell whose first column is the literal string
            // `TABLE` would also be on a line by itself when written by a
            // generator -- the cost of being too eager is the same as the
            // cost of being too lazy, so we trust the keyword.
            match line {
                "TABLE" => {
                    section = Section::Header;
                    continue;
                }
                "VECTORS" => {
                    section = Section::Vectors;
                    continue;
                }
                "TUPLES" => {
                    // The block is structurally identical to VECTORS but
                    // describes the *rows* rather than the columns. Types
                    // are declared twice because the original VisiCalc was a
                    // row-streaming format and needed both shapes to lay out
                    // a 2D sheet; the values section is where the data lives.
                    section = Section::Tuples;
                    row_types.clear();
                    continue;
                }
                "DATA" => {
                    // closing any open row
                    flush_row(&mut row_buf, &mut col_index, &mut out, &mut emitted)?;
                    section = Section::Data;
                    continue;
                }
                "EOT" | "EOD" => {
                    // `EOD` is what some writers close with instead. Without
                    // it the keyword fell through to the DATA arm, where it
                    // parsed as a harmless `0,0` pair and the loop ran to EOF
                    // with the last row still buffered -- a silently dropped
                    // row, which is the failure this whole format is prone
                    // to.
                    flush_row(&mut row_buf, &mut col_index, &mut out, &mut emitted)?;
                    break;
                }
                _ => {}
            }

            match section {
                Section::Header => {
                    // The TABLE block has up to two lines: `0,1` (count) and
                    // a quoted title. Either may be absent, but the count
                    // line, when present, has to look like one. A bare
                    // quoted title opens the door for writers that skip the
                    // count. Some writers (Lotus-derived) pad the count
                    // with spaces ("0 , 1"); we accept any whitespace
                    // between the digits and the comma.
                    if is_count_line(line) {
                        // count line: ok
                    } else if line.starts_with('"') && line.ends_with('"') {
                        // title line: ok
                    } else {
                        decline!("dif: header line {line:?} unexpected (lineno {lineno})");
                    }
                }
                Section::Vectors => {
                    // The vectors block is the column count then a single
                    // `""` then one type token per column. The count line is
                    // `<num-cols>,<num-rows>`; we read num-cols from the
                    // first integer. A `0,<n>` line is acceptable but
                    // redundant, so we accept both orderings.
                    if col_types.is_empty() {
                        let (a, b) = split_pair(line);
                        let cols = a.max(b);
                        if cols == 0 || cols as usize > MAX_COLS {
                            bail!("dif: VECTORS declares {cols} columns");
                        }
                        col_types = vec![DifType::Number; cols as usize];
                        col_index = 0;
                    } else if line == "\"\"" {
                        // empty marker before the type tokens: skip
                    } else if let Some(t) = DifType::from_token(line) {
                        if (col_index as usize) < col_types.len() {
                            col_types[col_index as usize] = t;
                        }
                        col_index += 1;
                    } else {
                        bail!("dif: VECTORS type token {line:?} unknown (lineno {lineno})");
                    }
                }
                Section::Tuples => {
                    // TUPLES mirrors VECTORS with one type per *row* rather
                    // than one per column. The cell values live in DATA; a
                    // row type says how to interpret them, and this adapter
                    // prints cell values as text either way, so the tokens
                    // are counted and dropped.
                    //
                    // This block is not optional in the format -- a writer
                    // that emits it is normal, and before this arm existed
                    // the `TUPLES` keyword fell through to the VECTORS arm,
                    // where an unrecognised token bailed and the whole file
                    // was refused.
                    if row_types.is_empty() && is_pair_line(line) {
                        let (a, b) = split_pair(line);
                        let rows = a.max(b);
                        if rows == 0 || rows as usize > MAX_COLS {
                            bail!("dif: TUPLES declares {rows} rows");
                        }
                        row_types = vec![DifType::Number; rows as usize];
                    } else if line == "\"\"" {
                        // the empty marker that opens the type list
                    } else if is_tuples_token(line) {
                        // a row-type token: counted, not used
                    } else {
                        bail!("dif: TUPLES line {line:?} unexpected (lineno {lineno})");
                    }
                }
                Section::Data => {
                    // A pair `<col-index>,<row-index>` opens the row's first
                    // cell, or `-1,<row>` after a sentinel. A line of `""`
                    // also closes a row. Anything quoted is a string cell;
                    // anything else is a number (or `-1` sentinel).
                    if line == "\"\"" {
                        flush_row(&mut row_buf, &mut col_index, &mut out, &mut emitted)?;
                        continue;
                    }
                    if is_sentinel(line) {
                        flush_row(&mut row_buf, &mut col_index, &mut out, &mut emitted)?;
                        continue;
                    }
                    if line.starts_with('"') && line.ends_with('"') && line.len() >= 2 {
                        // String cell value; the indices that precede it
                        // (e.g. `0,5`) are read on the cell line itself or
                        // on the line before, depending on writer. Many
                        // writers emit a pair line *then* the value line,
                        // so we cannot rely on a fixed alternation.
                        let v = unquote(line);
                        row_buf.push(v.to_string());
                        col_index += 1;
                    } else if let Some((a, b)) = parse_pair(line) {
                        // Pair line. If both are non-negative and a fits
                        // in the column count, treat `a` as the column and
                        // the next quoted/numeric line as the value. If
                        // only `b` looks like a row index, this is the
                        // row's first cell with implicit column 0.
                        if a == -1 || b == -1 {
                            flush_row(&mut row_buf, &mut col_index, &mut out, &mut emitted)?;
                        } else if a >= 0 && (a as usize) < col_types.len().max(1) {
                            col_index = a as u32;
                            // wait for the value on the next line
                        } else if b == 0 {
                            // `0,0` after DATA is the pair line that opens
                            // the first cell; ignore and continue.
                        } else {
                            bail!("dif: pair {line:?} out of range (lineno {lineno})");
                        }
                    } else if let Ok(n) = line.parse::<f64>() {
                        // Numeric cell value.
                        let mut s = String::new();
                        let _ = write!(s, "{n}");
                        row_buf.push(s);
                        col_index += 1;
                    } else {
                        // A bare token in DATA is the format's own content, not
                        // a framing error: `BOT` opens the data block and
                        // `EOD` closes it (HDINFO.DIF has 225 of each), and a
                        // writer may also emit an unquoted label. Refusing
                        // here discarded the whole sheet -- the cells already
                        // parsed and all -- over a token we can print, which
                        // is how a search for `Heads` came back empty on a
                        // file that plainly contains it. Keep the token as
                        // the cell's text and let the next line carry the
                        // value.
                        row_buf.push(line.to_string());
                        col_index += 1;
                    }
                    if row_buf.len() >= MAX_COLS {
                        flush_row(&mut row_buf, &mut col_index, &mut out, &mut emitted)?;
                    }
                    if emitted >= MAX_ROWS {
                        break;
                    }
                }
            }
        }
        if emitted == 0 {
            bail!("dif: no rows emitted");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[derive(Clone, Copy)]
enum DifType {
    Number,
    String,
}

impl DifType {
    fn from_token(s: &str) -> Option<Self> {
        match s {
            "NUMBER" => Some(DifType::Number),
            "STRING" => Some(DifType::String),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Header,
    Vectors,
    Tuples,
    Data,
}

/// Row-type tokens DIF allows in TUPLES, including the boolean pair the
/// VECTORS block does not use. They are consumed and dropped, so this is
/// about accepting what writers emit rather than interpreting it — and it
/// is what keeps the arm from swallowing the DATA block that follows.
fn is_tuples_token(s: &str) -> bool {
    matches!(s, "NUMBER" | "STRING" | "BUTT" | "BSTR")
}

/// A line that really is `<int>` or `<int>,<int>`.
///
/// `parse_pair` cannot answer this: it defaults an unparsable field to 0 and
/// always returns `Some`, so using it as the "is this a count line" test
/// would make every word a count.
fn is_pair_line(line: &str) -> bool {
    let mut parts = line.splitn(2, ',');
    let a = parts.next();
    let b = parts.next();
    match (a, b) {
        (Some(a), Some(b)) => a.trim().parse::<i64>().is_ok() && b.trim().parse::<i64>().is_ok(),
        (Some(a), None) => a.trim().parse::<i64>().is_ok(),
        _ => false,
    }
}

fn flush_row(
    row_buf: &mut Vec<String>,
    col_index: &mut u32,
    out: &mut String,
    emitted: &mut usize,
) -> Result<()> {
    // DIF's logical row is N cells closed by a sentinel line, so each cell
    // is its own emitted line (rgx treats one line as one match candidate).
    // A row of three cells produces three lines: `C0\tv0`, `C1\tv1`,
    // `C2\tv2`. An empty buffer is a no-op, which is what the bare `-1,0`
    // before any DATA writes needs to do.
    for (i, v) in row_buf.iter().enumerate() {
        let _ = writeln!(out, "C{}\t{}", i, v);
        *emitted += 1;
    }
    row_buf.clear();
    *col_index = 0;
    Ok(())
}

fn is_sentinel(line: &str) -> bool {
    // `-1` alone, `-1,0`, `0,-1`, and `-1,-1` all close a row in the writers
    // that mix them.
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() == 1 {
        return parts[0].trim() == "-1";
    }
    if parts.len() == 2 {
        let a = parts[0].trim().parse::<i64>().unwrap_or(0);
        let b = parts[1].trim().parse::<i64>().unwrap_or(0);
        return a == -1 || b == -1;
    }
    false
}

/// `None` when the line is not a `a,b` pair of two integers.
///
/// This returned `Some` unconditionally, through `split_pair`'s
/// `unwrap_or(0)`. The DATA arm above therefore matched *every* line, the
/// numeric arm below it was dead code, and a bare value like `42` was read as
/// the pair `42,0` -- which takes the `b == 0` branch and drops the cell. A
/// sheet of numbers lost every value with no note: same bytes named `.txt`
/// matched, named `.dif` did not.
fn parse_pair(line: &str) -> Option<(i64, i64)> {
    let (a, b) = line.split_once(',')?;
    Some((a.trim().parse::<i64>().ok()?, b.trim().parse::<i64>().ok()?))
}

fn split_pair(line: &str) -> (i64, i64) {
    let mut it = line.split(',');
    let a = it
        .next()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0);
    let b = it
        .next()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0);
    (a, b)
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    match s.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(inner) => inner,
        None => s,
    }
}

/// True when `line` is a TABLE-count line: two integers separated by a
/// comma, with optional whitespace (e.g. `0,1`, `0 , 1`, `0  ,  1`).
fn is_count_line(line: &str) -> bool {
    let mut parts = line.split(',');
    let a = parts.next().unwrap_or("").trim();
    let b = parts.next().unwrap_or("").trim();
    if parts.next().is_some() {
        return false;
    }
    !a.is_empty()
        && !b.is_empty()
        && a.bytes().all(|b| b.is_ascii_digit())
        && b.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(data: &[u8]) -> String {
        match Dif.extract(data, "a.dif").unwrap() {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("expected Outcome::Text"),
        }
    }

    #[test]
    fn minimal_two_by_two() {
        // DIF row layout: a `0,0` pair opens a cell in the same row, `-1,0`
        // closes the row. So a 2x2 grid pairs `0,0` between same-row cells
        // and `-1,0` between rows.
        let body = "TABLE\n0,1\n\"tiny\"\nVECTORS\n0,2\n\"\"\nNUMBER\nNUMBER\nDATA\n0,0\n\"1\"\n0,0\n\"2\"\n-1,0\n0,0\n\"3\"\n0,0\n\"4\"\n-1,0\nEOT\n";
        let out = text_of(body.as_bytes());
        assert!(out.contains("C0\t1"), "{out}");
        assert!(out.contains("C1\t2"));
        assert!(out.contains("C0\t3"));
        assert!(out.contains("C1\t4"));
    }

    #[test]
    fn strings_with_quotes_and_spaces() {
        let body = "TABLE\n0,1\n\"\"\nVECTORS\n0,1\n\"\"\nSTRING\nDATA\n0,0\n\"hello; world\"\n-1,0\nEOT\n";
        let out = text_of(body.as_bytes());
        assert!(out.contains("hello; world"), "{out}");
    }

    #[test]
    fn empty_sentinel_closes_row() {
        // Some writers use `""` instead of `-1,0` to close a row.
        let body = "TABLE\n0,1\n\"\"\nVECTORS\n0,2\n\"\"\nNUMBER\nNUMBER\nDATA\n0,0\n\"10\"\n0,0\n\"20\"\n\"\"\n0,0\n\"30\"\n0,0\n\"40\"\n\"\"\nEOT\n";
        let out = text_of(body.as_bytes());
        assert!(out.contains("C0\t10"), "{out}");
        assert!(out.contains("C1\t40"), "{out}");
    }

    #[test]
    fn rejects_a_file_that_is_not_dif() {
        // No `TABLE` keyword: the header section never advances.
        let r = Dif.extract(b"hello world\n", "a.dif");
        assert!(r.is_err(), "expected bail");
    }

    #[test]
    fn a_tuples_block_is_read_rather_than_refused() {
        // TUPLES sits between VECTORS and DATA in the format, and a writer
        // that emits it is ordinary. Before this arm existed the keyword fell
        // through to the VECTORS arm, whose unknown-token branch bailed --
        // so a perfectly good DIF file was refused whole.
        let body = "TABLE\n0,1\n\"with tuples\"\nVECTORS\n0,2\n\"\"\nNUMBER\nSTRING\n\
TUPLES\n0,2\n\"\"\nNUMBER\nSTRING\nDATA\n0,0\n\"7\"\n0,0\n\"seven\"\n-1,0\nEOT\n";
        let out = text_of(body.as_bytes());
        assert!(out.contains("C0\t7"), "{out}");
        assert!(out.contains("C1\tseven"), "{out}");
    }

    #[test]
    fn tuples_accepts_the_boolean_row_types() {
        // BUTT/BSTR are row types DIF defines; the VECTORS block does not use
        // them, so the token list here is its own.
        let body = "TABLE\n0,1\n\"b\"\nVECTORS\n0,1\n\"\"\nNUMBER\n\
TUPLES\n0,2\n\"\"\nBUTT\nNUMBER\nDATA\n0,0\n\"1\"\n-1,0\n0,0\n\"2\"\n-1,0\nEOT\n";
        let out = text_of(body.as_bytes());
        assert!(out.contains("C0\t1"), "{out}");
        assert!(out.contains("C0\t2"), "{out}");
    }

    #[test]
    fn eod_closes_the_file_and_the_last_row_with_it() {
        // `EOD` used to fall through to the DATA arm and parse as a `0,0`
        // pair, so the loop ran to EOF with the final row still buffered.
        // The sentinel under test is the missing last row.
        let eod = "TABLE\n0,1\n\"\"\nVECTORS\n0,2\n\"\"\nNUMBER\nNUMBER\n\
DATA\n0,0\n\"10\"\n0,0\n\"20\"\n-1,0\n0,0\n\"30\"\n0,0\n\"40\"\nEOD\n";
        let out = text_of(eod.as_bytes());
        assert!(
            out.contains("C0\t30"),
            "the last row must not be dropped: {out}"
        );
        assert!(out.contains("C1\t40"), "{out}");

        let eot = eod.replace("EOD", "EOT");
        assert_eq!(text_of(eot.as_bytes()), out, "both terminators agree");
    }

    #[test]
    fn a_tuples_block_still_refuses_a_line_it_cannot_place() {
        // Consuming the block must not turn it into a hole that swallows
        // anything: an unplaceable line inside TUPLES is still a bail.
        let body = "TABLE\n0,1\n\"\"\nVECTORS\n0,1\n\"\"\nNUMBER\n\
TUPLES\n0,1\n\"\"\nwhat is this\nDATA\n0,0\n\"1\"\n-1,0\nEOT\n";
        assert!(Dif.extract(body.as_bytes(), "a.dif").is_err());
    }
}
