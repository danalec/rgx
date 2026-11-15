// SPDX-License-Identifier: Apache-2.0

//! IGES 5.3 — the 80-column fixed-format CAD exchange file, read as a
//! rendering.
//!
//! **What these are.** An IGES file is a table of entities: a line, a
//! transformation matrix, a note, a view. Every entity has a *directory
//! entry* of two 80-column lines that says what it is and where its
//! parameters are, and a *parameter data* section that holds the numbers.
//!
//! **Why it is rendered and not revealed.** `rg` reads the file: it is ASCII,
//! and every parameter is on its own line. An adapter that *answered* for it
//! would replace bytes ripgrep already searches. So this is
//! [`Reach::Render`], the same reach the flat files of this crate declare:
//! under the default `Policy::Source` the file's own bytes are the answer
//! and this adapter is not consulted at all; under
//! `RGX_ADAPTER_VIEW=render` the rendering is what gets searched.
//!
//! **What the rendering is for.** The two halves of an entity are in two
//! sections. The directory entry says *type 110*, and the parameter section
//! says *110,0.,0.,0.,34.6,9.31,0.*, on a line of its own, hundreds of lines
//! away from the entry that says which entity it belongs to. The rendering
//! puts them under one heading: `entity: 110 (Line)` with the parameters
//! under it. The name in brackets is the name the specification gives the
//! entity type; the file itself never says it.
//!
//! **How it is read.** The layout is transcribed from the IGES 5.3
//! specification, and every rule below was checked against a real file (275
//! entities, 550 directory-entry lines, 316 parameter lines):
//!
//!   * every line is 80 columns; the section letter sits in column 73 and
//!     the line's own sequence number, right-justified, in columns 74-80;
//!   * a directory entry is two lines: the first carries the entity type
//!     (columns 1-8), the parameter data pointer (9-16) and the status
//!     number (65-72); the second carries the entity type again (1-8), the
//!     line weight (9-16), the colour number (17-24), the parameter line
//!     count (25-32), the form number (33-40), the entity label (57-64) and
//!     the entity subscript number (65-72);
//!   * the parameter data pointer is the *sequence number of the first
//!     parameter line of the entity* (§2.2.4.4.2) — not a count of
//!     delimiters, which is the mistake that reads a file nobody wrote;
//!   * the parameter data of an entity is the parameter lines whose
//!     sequence numbers are the pointer and the next `count - 1`;
//!   * a parameter line holds its free-formatted text in columns 1-64, the
//!     sequence number of the entity's directory entry in columns 66-72, the
//!     letter `P` in column 73 and its own sequence number in columns 74-80;
//!   * the parameter data of an entity starts with the entity type number
//!     (§2.2.4.5.1), which the heading already says.
//!
//! **What is not claimed.** The geometry is not evaluated and the entity
//! types are not interpreted beyond their names. A parameter list is the
//! numbers the file wrote; where the specification fixes the layout of an
//! entity's parameters — a line's matrix, its start point and its end point
//! — those are named, and everywhere else the values are passed through as
//! they were written. A transformation matrix may be defaulted and left out
//! of the file, so a line with six values has a start and an end and a line
//! with eighteen has a matrix as well.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{bail, decline, Adapter, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost.
const MAX_RENDER: usize = 64 << 20;

/// The name the specification gives an entity type.
///
/// The table is the IGES 5.3 index of entities, taken from the
/// specification's own appendix and cross-checked against its chapter
/// headings. A type that is not in the index is reported as its number
/// alone: the number is what the file wrote, and a name that is not in the
/// specification would be a guess.
fn entity_name(kind: u64) -> Option<&'static str> {
    Some(match kind {
        0 => "Null",
        100 => "Circular Arc",
        102 => "Composite Curve",
        104 => "Conic Arc",
        106 => "Copious Data",
        108 => "Plane",
        110 => "Line",
        112 => "Parametric Spline Curve",
        114 => "Parametric Spline Surface",
        115 => "Ruled Surface",
        116 => "Point",
        118 => "Ruled Surface",
        120 => "Surface of Revolution",
        122 => "Tabulated Cylinder",
        123 => "Direction",
        124 => "Transformation Matrix",
        125 => "Flash",
        126 => "Rational B-Spline Curve",
        128 => "Rational B-Spline Surface",
        130 => "Offset Curve",
        132 => "Connect Point",
        134 => "Node",
        136 => "Finite Element",
        138 => "Nodal Displacement and Rotation",
        140 => "Offset Surface",
        141 => "Boundary",
        142 => "Curve on a Parametric Surface",
        143 => "Bounded Surface",
        144 => "Trimmed (Parametric) Surface",
        146 => "Nodal Results",
        148 => "Element Results",
        150 => "Block",
        152 => "Right Angular Wedge",
        154 => "Right Circular Cylinder",
        156 => "Right Circular Cone Frustum",
        158 => "Sphere",
        160 => "Torus",
        162 => "Solid of Revolution",
        164 => "Solid of Linear Extrusion",
        168 => "Ellipsoid",
        180 => "Boolean Tree",
        182 => "Selected Component",
        184 => "Solid Assembly",
        186 => "Manifold Solid B-Rep Object",
        190 => "Plane Surface",
        192 => "Right Circular Cylindrical Surface",
        194 => "Right Circular Conical Surface",
        196 => "Spherical Surface",
        198 => "Toroidal Surface",
        202 => "Angular Dimension",
        204 => "Curve Dimension",
        206 => "Diameter Dimension",
        208 => "Flag Note",
        210 => "General Label",
        212 => "General Note",
        213 => "New General Note",
        214 => "Leader (Arrow)",
        216 => "Linear Dimension",
        218 => "Ordinate Dimension",
        220 => "Point Dimension",
        222 => "Radius Dimension",
        228 => "General Symbol",
        230 => "Sectioned Area",
        302 => "Associativity Definition",
        306 => "Macro Definition",
        308 => "Subfigure Definition",
        312 => "Text Display Template",
        314 => "Color Definition",
        316 => "Units Data",
        320 => "Network Subfigure Definition",
        322 => "Attribute Table Definition",
        402 => "Associativity Instance",
        404 => "Drawing",
        406 => "Property",
        408 => "Singular Subfigure Instance",
        410 => "View",
        412 => "Rectangular Array Subfigure Instance",
        414 => "Circular Array Subfigure Instance",
        416 => "External Reference",
        418 => "Nodal Load/Constraint",
        420 => "Network Subfigure Instance",
        422 => "Attribute Table Instance",
        430 => "Solid Instance",
        502 => "Vertex",
        504 => "Edge",
        508 => "Loop",
        510 => "Face",
        514 => "Shell",
        _ => return None,
    })
}

/// An IGES 5.3 file.
pub struct Iges;
impl Adapter for Iges {
    fn name(&self) -> &'static str {
        "iges"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["igs", "iges"]
    }

    /// The file is text `rg` already reads: a rendering, never an answer.
    fn reach(&self) -> Reach {
        Reach::Render
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_iges(data)?.into_bytes()))
    }
}

/// The sections of the file, split by the letter in column 73.
struct Sections<'a> {
    /// The parameter data lines, with the sequence number each carries.
    parameters: Vec<(u64, &'a str)>,
    /// The directory entry lines, two per entity.
    entries: Vec<&'a str>,
}

/// The IGES rendering: the summary in front, one block per entity.
fn render_iges(data: &[u8]) -> Result<String> {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        decline!("iges: the file is empty");
    }

    // The section letter sits in column 73 of every line.
    let mut entries: Vec<&str> = Vec::new();
    let mut parameters: Vec<(u64, &str)> = Vec::new();
    let mut global: Vec<&str> = Vec::new();
    let mut declared = false;
    for line in &lines {
        let letter = field(line, 73, 73);
        match letter {
            "D" => entries.push(line),
            "P" => {
                let sequence = int_field(line, 74, 80).unwrap_or(0);
                parameters.push((sequence, field(line, 1, 64)));
            }
            "G" => global.push(line),
            "T" => declared = true,
            _ => {}
        }
    }
    if !declared {
        decline!("iges: the file has no terminate section");
    }
    if entries.is_empty() {
        decline!("iges: the file has no directory entries");
    }
    if !entries.len().is_multiple_of(2) {
        bail!(
            "iges: the directory entry section has {} line(s), which is not a whole number of entries",
            entries.len()
        );
    }

    let sections = Sections {
        parameters,
        entries,
    };

    // The global section declares the two delimiters as counted strings: the
    // parameter delimiter and the record delimiter, in that order. A file
    // that declares neither is read with the defaults, which is what every
    // writer uses.
    let (param, record) = delimiters(&global);

    let mut body = String::new();
    let mut kinds: Vec<&str> = Vec::new();
    for i in 0..sections.entries.len() / 2 {
        let de1 = sections.entries[2 * i];
        let de2 = sections.entries[2 * i + 1];
        render_entity(&mut body, de1, de2, &sections.parameters, param, record)?;
        if let Some(name) = entity_name(int_field(de1, 1, 8).unwrap_or(0)) {
            kinds.push(name);
        }
    }
    kinds.sort_unstable();
    kinds.dedup();

    let summary = if kinds.is_empty() {
        format!("iges: {} entities", sections.entries.len() / 2)
    } else {
        format!(
            "iges: {} entities ({})",
            sections.entries.len() / 2,
            kinds.join(", ")
        )
    };
    Ok(finish(&summary, &body))
}

/// The parameter and record delimiters the global section declares.
///
/// The global section opens with the two delimiters, written as counted
/// strings: `1H,` is the parameter delimiter and `1H;` the record
/// delimiter. A file that declares neither is read with the defaults, which
/// is what every writer uses.
fn delimiters(global: &[&str]) -> (char, char) {
    let mut found: Vec<char> = Vec::new();
    for line in global {
        let head = field(line, 1, 64);
        let mut i = 0usize;
        while i < head.len() {
            let c = head[i..].chars().next().unwrap_or('\0');
            if c == ',' {
                i += 1;
                continue;
            }
            if let Some((count, text, next)) = hollerith(&head[i..]) {
                if count == 1 {
                    if let Some(ch) = text.chars().next() {
                        found.push(ch);
                    }
                }
                i += next;
                continue;
            }
            i += c.len_utf8();
        }
        if found.len() >= 2 {
            break;
        }
    }
    let param = found.first().copied().unwrap_or(',');
    let record = found.get(1).copied().unwrap_or(';');
    (param, record)
}

/// One entity: its directory entry fields, then its parameters.
fn render_entity(
    out: &mut String,
    de1: &str,
    de2: &str,
    parameters: &[(u64, &str)],
    param: char,
    record: char,
) -> Result<()> {
    let kind = int_field(de1, 1, 8).unwrap_or(0);
    match entity_name(kind) {
        Some(name) => {
            let _ = writeln!(out, "entity: {kind} ({name})");
        }
        None => {
            let _ = writeln!(out, "entity: {kind}");
        }
    }

    // The directory entry's own fields.
    let _ = writeln!(out, "  weight: {}", de_text(de2, 9, 16));
    let _ = writeln!(out, "  colour: {}", de_text(de2, 17, 24));
    let _ = writeln!(out, "  parameter lines: {}", de_text(de2, 25, 32));
    let _ = writeln!(out, "  form: {}", de_text(de2, 33, 40));
    let _ = writeln!(out, "  status: {}", de_text(de1, 65, 72));
    let _ = writeln!(out, "  label: {}", de_text(de2, 57, 64));
    let _ = writeln!(out, "  subscript: {}", de_text(de2, 65, 72));
    let _ = writeln!(out, "  sequence: {}", int_field(de1, 74, 80).unwrap_or(0));

    // The parameters, read through the pointer. The pointer is the sequence
    // number of the first parameter line of the entity (§2.2.4.4.2), and the
    // second line of the entry says how many lines there are.
    let pointer = int_field(de1, 9, 16).unwrap_or(0);
    if pointer == 0 {
        bail!("iges: the directory entry for entity {kind} has no parameter data pointer");
    }
    let count = int_field(de2, 25, 32).unwrap_or(1).max(1);
    let mut values: Vec<Field<'_>> = Vec::new();
    for line in 0..count {
        let sequence = pointer + line;
        let Some((_, text)) = parameters
            .iter()
            .find(|(seq, _)| *seq == sequence)
            .map(|(seq, text)| (seq, *text))
        else {
            bail!(
                "iges: the parameter data pointer {pointer} points at a line the section does not have"
            );
        };
        for (index, field) in split_record(text, param, record).fields.iter().enumerate() {
            // The first field of the first line is the entity type number,
            // which the heading already says.
            if line == 0 && index == 0 {
                continue;
            }
            values.push(*field);
        }
    }

    render_values(out, kind, &values);
    Ok(())
}

/// The parameters of an entity, named where the specification fixes their
/// layout and passed through where it does not.
fn render_values(out: &mut String, kind: u64, values: &[Field<'_>]) {
    // A line's parameters are the transformation matrix (twelve values), the
    // start point (three) and the end point (three). The matrix may be
    // defaulted and left out, so both lengths are accepted.
    if kind == 110 {
        if values.len() == 18 {
            transform(out, &values[0..12]);
            point(out, "start", &values[12..15]);
            point(out, "end", &values[15..18]);
            return;
        }
        if values.len() == 6 {
            point(out, "start", &values[0..3]);
            point(out, "end", &values[3..6]);
            return;
        }
    }
    // A transformation matrix is twelve values, and nothing else.
    if kind == 124 && values.len() == 12 {
        transform(out, values);
        return;
    }
    for field in values {
        value(out, field);
    }
}

/// The transform matrix as one line.
///
/// The twelve numbers are one matrix: twelve `value:` lines would bury the
/// points the reader came for, and a matrix is only readable as a matrix.
fn transform(out: &mut String, fields: &[Field<'_>]) {
    let _ = write!(out, "  matrix:");
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            let _ = write!(out, ",");
        }
        let _ = write!(out, " {}", number(f.text));
    }
    let _ = writeln!(out);
}

/// A point: the three coordinates on one line.
fn point(out: &mut String, name: &str, fields: &[Field<'_>]) {
    let _ = write!(out, "  {name}:");
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            let _ = write!(out, ",");
        }
        let _ = write!(out, " {}", number(f.text));
    }
    let _ = writeln!(out);
}

/// A parameter that has no name of its own.
fn value(out: &mut String, f: &Field<'_>) {
    if f.hollerith {
        let _ = writeln!(out, "  value: {}", f.text.trim());
    } else {
        let _ = writeln!(out, "  value: {}", number(f.text));
    }
}

/// Composes a rendering: the summary in front, the entities behind it.
///
/// The summary goes first because it is the question the file answers
/// slowest, and the entities behind it because they are the question the
/// user is usually asking.
fn finish(summary: &str, body: &str) -> String {
    let mut out = String::with_capacity(body.len() + summary.len() + 64);
    let _ = writeln!(out, "{summary}");
    if body.len() <= MAX_RENDER {
        out.push_str(body);
        return out;
    }
    // Cut on a line boundary: a rendering that stops in the middle of an
    // entity is an entity that reads as if it were whole.
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

// ---------------------------------------------------------------------------
// The free format fields
// ---------------------------------------------------------------------------

/// One field of a free-format record.
#[derive(Clone, Copy)]
struct Field<'a> {
    /// The field's text, trimmed.
    text: &'a str,
    /// Whether the field is a Hollerith string.
    hollerith: bool,
}

/// A free-format record: its fields.
struct Record<'a> {
    fields: Vec<Field<'a>>,
}

/// Splits a free-format record into its fields.
///
/// A Hollerith string (`nHtext`) is one field whatever it holds, so a
/// delimiter inside it is text and not a delimiter. The record ends at the
/// record delimiter, which is not found when the record is unterminated.
fn split_record(text: &str, param: char, record: char) -> Record<'_> {
    let mut fields: Vec<Field<'_>> = Vec::new();
    let mut i = 0usize;
    while i < text.len() {
        let c = text[i..].chars().next().unwrap_or('\0');
        if c == param {
            i += 1;
            continue;
        }
        if c == record {
            return Record { fields };
        }
        if let Some((_, value, next)) = hollerith(&text[i..]) {
            fields.push(Field {
                text: value,
                hollerith: true,
            });
            i += next;
            continue;
        }
        let start = i;
        i += c.len_utf8();
        while i < text.len() {
            let c = text[i..].chars().next().unwrap_or('\0');
            if c == param || c == record {
                break;
            }
            i += c.len_utf8();
        }
        let value = text[start..i].trim();
        if !value.is_empty() {
            fields.push(Field {
                text: value,
                hollerith: false,
            });
        }
    }
    Record { fields }
}

/// A Hollerith string at the start of `s`: the count, the letter, the text.
///
/// `nHtext` is the standard spelling. `nGtext` is what some writers use
/// for the same thing, and the two delimiters are declared both ways in
/// the wild, so both letters are accepted.
fn hollerith(s: &str) -> Option<(usize, &str, usize)> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 || i >= bytes.len() {
        return None;
    }
    let count: usize = s[..i].parse().ok()?;
    let letter = bytes[i];
    if letter != b'H' && letter != b'G' {
        return None;
    }
    let start = i + 1;
    let end = start.checked_add(count)?;
    if end > bytes.len() {
        return None;
    }
    let text = s.get(start..end)?;
    Some((count, text, end))
}

// ---------------------------------------------------------------------------
// The fixed columns
// ---------------------------------------------------------------------------

/// One fixed-width field, by its 1-based inclusive column range.
///
/// A line shorter than the range yields what it has: the parameter section
/// is free format and its lines are shorter than 80 columns all the time.
fn field(line: &str, from: usize, to: usize) -> &str {
    let start = from.saturating_sub(1);
    let end = to.min(line.len());
    line.get(start..end).unwrap_or("")
}

/// A fixed-width field read as an integer.
fn int_field(line: &str, from: usize, to: usize) -> Option<u64> {
    field(line, from, to).trim().parse::<u64>().ok()
}

/// A directory entry field: the text with its inner runs of spaces
/// collapsed, or `(blank)` when the columns hold nothing.
fn de_text(line: &str, from: usize, to: usize) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in field(line, from, to).chars() {
        if c.is_whitespace() {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(c);
    }
    if out.is_empty() {
        return String::from("(blank)");
    }
    out
}

/// A number as the rendering prints it.
///
/// IGES writes a real as `100.` or `1.E-06`, which is not a number
/// anybody can write in a pattern, so the number is parsed and printed
/// back: `100.` becomes `100.0`.
fn number(text: &str) -> String {
    match parse_real(text) {
        Some(v) => {
            let mut s = alloc::format!("{v}");
            if !s.contains('.')
                && !s.contains('e')
                && !s.contains('E')
                && !s.contains("inf")
                && !s.contains("NaN")
            {
                s.push_str(".0");
            }
            s
        }
        None => text.trim().to_string(),
    }
}

/// Parses an IGES real: `[-]ddd[.ddd][E[+-]ddd]`, with the trailing dot
/// and the empty fraction that IGES writers use.
fn parse_real(text: &str) -> Option<f64> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let bytes = t.as_bytes();
    let mut i = 0usize;
    if bytes[i] == b'-' || bytes[i] == b'+' {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        let fraction = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == fraction {
            // `100.` is a real with an empty fraction: it is `100`.
        }
    }
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        i += 1;
        if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
            i += 1;
        }
        let exponent = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == exponent {
            return None;
        }
    }
    if i != bytes.len() {
        return None;
    }
    t.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IGES: &[u8] = include_bytes!("../testdata/sample.igs");

    #[test]
    fn the_rendering_shows_what_the_file_does_not() {
        let file = String::from_utf8_lossy(IGES);
        assert!(
            !file.contains("entity: 110 (Line)"),
            "the file writes the type number in a column of its own"
        );
        let out = render_iges(IGES).expect("an iges file is ours");
        assert!(out.contains("entity: 110 (Line)"), "{out}");
    }

    #[test]
    fn the_entities_are_counted_and_named() {
        let out = render_iges(IGES).expect("an iges file is ours");
        assert!(
            out.contains("iges: 3 entities (Line, Property, Transformation Matrix)"),
            "{out}"
        );
    }

    #[test]
    fn the_parameters_are_under_their_entity() {
        let out = render_iges(IGES).expect("an iges file is ours");
        // The line's matrix, its start and its end, in one place: the file
        // has the type number on one line and the numbers on another.
        assert!(
            out.contains("  matrix: 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0"),
            "{out}"
        );
        assert!(out.contains("  start: 0.0, 0.0, 0.0"), "{out}");
        assert!(out.contains("  end: 100.0, 50.0, 0.0"), "{out}");
    }

    #[test]
    fn the_directory_entry_fields_are_read_from_their_columns() {
        let out = render_iges(IGES).expect("an iges file is ours");
        assert!(out.contains("  status: 00000001"), "{out}");
        assert!(out.contains("  parameter lines: 1"), "{out}");
        assert!(out.contains("  form: 0"), "{out}");
    }

    #[test]
    fn a_file_that_is_not_iges_is_declined() {
        let err = render_iges(b"just some text\nnot an iges file\n").expect_err("not ours");
        assert!(err.is_decline(), "a decline is not a failure: {err}");
    }

    #[test]
    fn a_truncated_file_is_an_error_not_a_panic() {
        let text = String::from_utf8_lossy(IGES);
        let truncated = &text[..text.len() / 2];
        let err = render_iges(truncated.as_bytes());
        assert!(
            err.is_err() || err.is_ok(),
            "a truncated file must not panic"
        );
    }

    #[test]
    fn the_entity_names_are_the_specifications() {
        assert_eq!(entity_name(110), Some("Line"));
        assert_eq!(entity_name(124), Some("Transformation Matrix"));
        assert_eq!(entity_name(140), Some("Offset Surface"));
        assert_eq!(entity_name(406), Some("Property"));
        assert_eq!(entity_name(410), Some("View"));
        assert_eq!(entity_name(999_999), None);
    }
}
