// SPDX-License-Identifier: Apache-2.0

//! SYLK (`.slk`) — Microsoft's SYMBOLic Link spreadsheet interchange format.
//!
//! Plain text, which is why it is worth reading at all: every other
//! spreadsheet container rgx claims is a binary container that has to be
//! walked before one character of the sheet is visible, and this one is
//! already the sheet.
//!
//! The shape, as published with the format:
//!
//! * the first non-empty line is `ID;P` -- record type `ID`, then field `P`,
//!   joined by the format's own `;` delimiter. Nothing here is `ID=P`: that
//!   spelling is the plausible-looking wrong one, and a parser that asked for
//!   it would reject every real file while every test still passed.
//! * everything after it is a stream of records, one per line, `;`-separated,
//!   and a record ends at a line holding exactly `E`;
//! * `C;X<col>;Y<row>;K<value>` is a cell, with `X` a 1-based column *letter*
//!   (`A`..`Z`, then `AA`..) and `Y` a 1-based row number. The `X` and `Y`
//!   tokens may appear in either order, which is why the parser reads the
//!   fields by their first letter rather than by position;
//! * `B`/`I`/`U`/`S`/`F` are formatting attributes that precede the cell they
//!   apply to, and several record kinds exist that carry nothing searchable.
//!
//! The payload extracted is the cell values as `R<row>C<col>\t<value>`.
//! Formatting attributes are deliberately dropped: they are not what a grep
//! for a value in a spreadsheet is looking for, and emitting one line per
//! bold cell would cost a search hit per row for no answer.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::{decline, Result};
use rgx_core::{Adapter, Outcome, Reach};

/// Cap on emitted cells. A sheet can address a million cells of which three
/// are written; `D` format records and `E` terminators are cheap to send in
/// bulk and a generator can produce them without bound, so the walk stops
/// rather than filling memory with an empty grid.
const MAX_CELLS: usize = 200_000;

/// Microsoft's SYMBOLic Link spreadsheet.
pub struct Slk;
impl Adapter for Slk {
    fn name(&self) -> &'static str {
        "slk"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["slk"]
    }
    /// SYLK is plain text, so ripgrep already reads it — and this rendering is
    /// lossy about it: the formatting records (`P;FORMAT`, `B`, `I`, `U`, `S`,
    /// `F`) are deliberately dropped, so a pattern that occurs only in one of
    /// them is a line `rg` prints and this rendering does not. An empty field
    /// drops the whole cell too.
    ///
    /// `Render` is therefore the honest answer, and under the default
    /// `Policy::Source` it is the one that keeps the file's own bytes in the
    /// corpus. Left as the default `Reveal`, the file's bytes were dropped in
    /// favour of the rendering, and rgx became a strict subset of ripgrep on
    /// every `.slk`.
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // SYLK is an 8-bit text format written in whatever ANSI codepage the
        // author's machine had, so a strict UTF-8 read would reject files
        // that are perfectly readable; the lossy path keeps the layout and
        // marks the undecodable bytes rather than dropping the sheet.
        let text = String::from_utf8_lossy(data);
        let mut lines = text.lines();

        // The header is the only structural claim that distinguishes this
        // format from an arbitrary text file the caller happened to name
        // `.slk`, so it is what "not my file" turns on.
        let header = lines
            .find(|l| !l.trim().is_empty())
            .map(str::trim)
            .unwrap_or("");
        if !header.starts_with("ID;P") {
            decline!("not a SYLK file (header is {header:?})");
        }

        let mut out = String::new();
        let mut emitted = 0usize;
        for line in lines {
            let line = line.trim_end_matches('\r').trim();
            match line.as_bytes().first() {
                // A record terminator, and the blank lines writers put
                // between records. Nothing is carried across the boundary:
                // the attributes before it described the cells it closed.
                None | Some(b'E') => continue,
                Some(b'C') => {
                    let Some((row, col, value)) = parse_cell(line) else {
                        continue;
                    };
                    if value.is_empty() {
                        continue;
                    }
                    let _ = writeln!(out, "R{row}C{col}\t{value}");
                    emitted += 1;
                    if emitted >= MAX_CELLS {
                        break;
                    }
                }
                // B/I/U/S/F and every other record kind: formatting and
                // window state. Not searchable content -- see the module note.
                _ => continue,
            }
        }

        if emitted == 0 {
            // An empty grid and an unreadable one must not look the same:
            // this bails so the pipeline can try the next adapter and, at
            // the end, search the bytes raw rather than report success.
            return Ok(Outcome::Bail("slk: no non-empty cells".into()));
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// `(row, col, value)` for a `C;...` record, or `None` when the record does
/// not name both coordinates.
///
/// The `X`/`Y` order is not fixed across writers, so the fields are matched
/// by their leading letter rather than read positionally.
fn parse_cell(line: &str) -> Option<(u32, u32, &str)> {
    let mut row: Option<u32> = None;
    let mut col: Option<u32> = None;
    let mut value: Option<&str> = None;

    for field in split_fields(line) {
        let mut chars = field.chars();
        // An empty field is legal SYLK -- a skipped column is written as a bare
        // `;`. `chars.next()?` returned from the whole function, discarding the
        // fields already parsed and with them the cell's value, so one stray
        // separator silently deleted a column. Skip the field instead.
        let Some(tag) = chars.next() else { continue };
        match tag {
            'X' => col = col_of(chars.as_str()),
            'Y' => row = chars.as_str().parse().ok(),
            'K' => value = Some(unquote(chars.as_str())),
            _ => {}
        }
    }
    Some((row?, col?, value.unwrap_or("")))
}

/// Splits on `;` outside double quotes.
///
/// A quoted cell value may contain `;` (`K"a;b"`), so splitting the whole
/// line naively cuts a cell in half and turns the tail into what looks like
/// a new field. The quotes toggle; the byte offsets used for slicing are
/// always a `;`, which is ASCII, so every slice lands on a char boundary.
fn split_fields(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    for (i, &b) in line.as_bytes().iter().enumerate() {
        match b {
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                out.push(&line[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&line[start..]);
    out
}

/// 1-based column index from an `X` token.
///
/// The token is **either** decimal (`X27`) **or** letters (`XAA`), and
/// writers disagree: Excel emits the number, other producers emit the
/// letter. Accepting only one of them silently drops every cell of the
/// files that speak the other, so both are taken and the digits win when
/// present. The letter form is bijective base-26 — `A`=1 … `Z`=26, `AA`=27,
/// `AZ`=52, `BA`=53. Bijective rather than plain base-26 because the format
/// has no zero digit: counting `A`..`Z` as 0..25 would land `Z` and `AA` on
/// the same index and shift every column after it.
fn col_of(token: &str) -> Option<u32> {
    if token.is_empty() {
        return None;
    }
    if token.bytes().all(|b| b.is_ascii_digit()) {
        return token.parse().ok();
    }
    let mut n: u32 = 0;
    for b in token.bytes() {
        let up = b.to_ascii_uppercase();
        if !up.is_ascii_alphabetic() {
            return None;
        }
        n = n.checked_mul(26)?.checked_add((up - b'A' + 1) as u32)?;
    }
    Some(n)
}

/// Strips one layer of surrounding double quotes and trims the `~` escape
/// Excel writes for a leading quote inside a quoted value.
fn unquote(v: &str) -> &str {
    let v = v.trim();
    match v.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(inner) => inner.strip_prefix('~').unwrap_or(inner),
        None => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn text_of(data: &[u8]) -> String {
        match Slk.extract(data, "a.slk").unwrap() {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("expected Outcome::Text"),
        }
    }

    #[test]
    fn a_two_by_two_sheet_renders_every_cell() {
        let data = b"ID;P\nC;Y1;X1;K\"name\"\nE\nC;Y1;X2;K\"qty\"\nE\nC;Y2;X1;K\"bolt\"\nE\nC;Y2;X2;K42\nE\n";
        assert_eq!(
            text_of(data),
            "R1C1\tname\nR1C2\tqty\nR2C1\tbolt\nR2C2\t42\n"
        );
    }

    #[test]
    fn the_x_and_y_tokens_may_arrive_in_either_order() {
        let a = text_of(b"ID;P\nC;Y2;X3;K\"a\"\nE\n");
        let b = text_of(b"ID;P\nC;X3;Y2;K\"a\"\nE\n");
        assert_eq!(
            a, b,
            "a writer that swapped the tokens must not lose the cell"
        );
        assert_eq!(a, "R2C3\ta\n");
    }

    #[test]
    fn columns_past_z_are_not_off_by_one() {
        // A..Z is 1..26 and AA must be 27, not 1 again.
        assert_eq!(text_of(b"ID;P\nC;XZ;Y1;K\"z\"\nE\n"), "R1C26\tz\n");
        assert_eq!(text_of(b"ID;P\nC;XAA;Y1;K\"aa\"\nE\n"), "R1C27\taa\n");
        assert_eq!(col_of("AZ"), Some(52));
        assert_eq!(col_of("BA"), Some(53));
    }

    #[test]
    fn a_column_token_may_be_written_as_a_number_or_as_letters() {
        // Excel writes the index; other producers write the letter. Same
        // cell either way, so neither spelling may be dropped.
        let by_number = text_of(b"ID;P\nC;X27;Y1;K\"v\"\nE\n");
        let by_letter = text_of(b"ID;P\nC;XAA;Y1;K\"v\"\nE\n");
        assert_eq!(by_number, "R1C27\tv\n");
        assert_eq!(by_letter, by_number);
    }

    #[test]
    fn a_quoted_value_containing_a_semicolon_stays_one_cell() {
        let got = text_of(b"ID;P\nC;Y1;X1;K\"a;b\"\nE\n");
        assert_eq!(got, "R1C1\ta;b\n");
        // The tail after the quoted `;` must not have been read as fields.
        assert!(!got.contains("b\t"), "the value leaked into a second field");
    }

    #[test]
    fn an_empty_cell_is_not_a_row_of_text() {
        let got = text_of(b"ID;P\nC;Y1;X1;K\nE\nC;Y1;X2;K\"\"\nE\nC;Y1;X3;K\"kept\"\nE\n");
        assert_eq!(got, "R1C3\tkept\n");
    }

    #[test]
    fn formatting_records_are_not_searchable_content() {
        let got = text_of(b"ID;P\nB\nI\nF\"Arial\"\nC;Y1;X1;K\"bold\"\nE\n");
        assert_eq!(got, "R1C1\tbold\n", "B/I/F leaked into the payload");
    }

    #[test]
    fn a_file_without_the_header_is_not_ours() {
        let err = Slk.extract(b"C;Y1;X1;K\"a\"\nE\n", "a.slk");
        assert!(err.is_err(), "a bare cell stream must not be accepted");
    }

    #[test]
    fn the_header_is_the_semicolon_record_and_not_the_equals_spelling() {
        // `Record = RecordType *(";" Field) LF` -- a real file starts `ID;P`.
        assert_eq!(text_of(b"ID;P\nC;Y1;X1;K\"a\"\nE\n"), "R1C1\ta\n");
        assert!(
            Slk.extract(b"ID=P\nC;Y1;X1;K\"a\"\nE\n", "a.slk").is_err(),
            "`ID=P` is not a SYLK header and must not be accepted"
        );
    }

    #[test]
    fn a_grid_with_nothing_in_it_bails_rather_than_returning_empty() {
        let out = Slk.extract(b"ID;P\nC;Y1;X1;K\nE\n", "a.slk").unwrap();
        assert!(
            matches!(out, Outcome::Bail(_)),
            "empty must fall through, not report success"
        );
    }

    #[test]
    fn an_unterminated_final_record_is_still_read() {
        // Writers do not always emit the last `E`.
        assert_eq!(text_of(b"ID;P\nC;Y1;X1;K\"tail\""), "R1C1\ttail\n");
    }

    #[test]
    fn crlf_line_endings_do_not_leak_into_values() {
        let got = text_of(b"ID;P\r\nC;Y1;X1;K\"a\"\r\nE\r\n");
        assert_eq!(got, "R1C1\ta\n");
    }

    #[test]
    fn a_record_naming_one_coordinate_only_is_skipped_not_guessed() {
        let got = text_of(b"ID;P\nC;X1;K\"orphan\"\nE\nC;Y1;X1;K\"real\"\nE\n");
        assert_eq!(got, "R1C1\treal\n");
    }
}
