// SPDX-License-Identifier: Apache-2.0

//! The **DXF** (AutoCAD Drawing Exchange Format) rendering.
//!
//! **What a DXF is.** A drawing as a flat sequence of *group codes*: a line
//! holding a small integer, and the line after it holding that code's value.
//! `0` says what the next thing is — a section, a table, an entity — `2`
//! names it, `8` names the layer an entity is on, and `10`/`20`/`30` are a
//! point. It is plain text (ASCII, or UTF-8 with a BOM) written with CRLF
//! line endings, and the codes are separated by whitespace, so a value may
//! also sit on the code's own line.
//!
//! **Why it is rendered and not revealed.** `rg` reads a DXF perfectly well:
//! every code and every value is a line of text. An adapter that *answered*
//! for it would replace bytes ripgrep already searches, and rgx would answer
//! a subset of what `rg` answers — the one thing this crate is built not to
//! do. So this is [`Reach::Render`], the same reach the flat files of this
//! crate declare: under the default policy the file's own bytes are the
//! answer, and the rendering is what the user asks for explicitly.
//!
//! **What the rendering is for.** The code and its value are on two
//! different lines, so the *pair* — "this entity is on this layer" — is not
//! in the file. A search for "the LINE on LAYER1" is two patterns in the
//! file and one here. That is the whole of it, and it is why the rendering
//! puts the entity's type and its layer on the same line: everything else
//! about a DXF is already greppable.
//!
//! **What it does not do.** It does not decode the geometry. A `CIRCLE`'s
//! `40` is a radius and a `TEXT`'s `40` is a height, and the two are told
//! apart here, but no curve is fitted, no block is expanded, and no
//! coordinate is projected. The rendering says what the file says, with the
//! pairs that the file keeps apart put together.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{bail, decline, Adapter, NoStdFloat, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost. A 64 MiB ceiling is far
/// above any file whose whole content is worth a second copy, and the
/// rendering says so when it bites rather than stopping in silence.
const MAX_RENDER: usize = 64 << 20;

/// A drawing, as a rendering.
pub struct Dxf;

impl Adapter for Dxf {
    fn name(&self) -> &'static str {
        "dxf"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["dxf"]
    }

    /// The file is text `rg` already reads: a rendering, never an answer.
    fn reach(&self) -> Reach {
        Reach::Render
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_dxf(data)?.into_bytes()))
    }
}

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

/// One group code and its value.
struct Pair {
    code: u16,
    value: String,
}

/// Why a pair could not be read.
enum PairErr {
    /// The file is over: there are no more lines.
    End,
    /// The line is not a group code.
    NotACode(String),
    /// The line holds a group code and the file ends before its value.
    NoValue(u16),
}

/// The role the next pair fills, announced by the pair before it.
enum Await {
    /// The `2` that names the section.
    SectionName,
    /// The `2` that names the table.
    TableType,
    /// The `2` that names the block.
    BlockName,
}

/// What an item is: an entity, a table entry, a table header, a block
/// header, a header variable, or a code that belongs to nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Entity,
    Entry,
    Table,
    Block,
    Variable,
    Loose,
}

/// A run of codes that belong to one thing.
struct Item {
    kind: Kind,
    name: String,
    codes: Vec<(u16, String)>,
}

/// What the file turned out to hold.
#[derive(Default)]
struct Stats {
    entities: usize,
    kinds: Vec<String>,
    layers: Vec<String>,
}

/// The DXF rendering: the file's structure, with every code beside the
/// value it holds.
fn render_dxf(data: &[u8]) -> Result<String> {
    let raw = String::from_utf8_lossy(data);
    // A UTF-8 BOM is not part of the first group code.
    let src: &str = raw.strip_prefix('\u{feff}').unwrap_or(raw.as_ref());
    let lines: Vec<&str> = src.lines().collect();

    let mut body = String::new();
    let mut stats = Stats::default();
    let mut at = 0usize;
    let mut seen_section = false;
    let mut seen_eof = false;

    let mut section = String::new();
    let mut table = String::new();
    let mut item: Option<Item> = None;
    let mut await_: Option<Await> = None;

    loop {
        let pair = match next_pair(&lines, &mut at) {
            Ok(p) => p,
            Err(PairErr::End) => break,
            Err(PairErr::NotACode(line)) => {
                if seen_section || seen_eof {
                    bail!("dxf: {:?} is not a group code", line);
                }
                // The file does not even open with a group code: it is some
                // other format, and declining is what lets the next adapter
                // have it.
                decline!("dxf: the file does not open with a group code");
            }
            Err(PairErr::NoValue(code)) => {
                if seen_section || seen_eof {
                    bail!("dxf: group code {code} has no value: the file is truncated");
                }
                decline!("dxf: the file does not open with a group code");
            }
        };

        // A pair that fills a role the pair before it announced.
        if let Some(role) = await_.take() {
            match role {
                Await::SectionName => {
                    if pair.code != 2 {
                        bail!("dxf: a section is named by group code 2, not {}", pair.code);
                    }
                    section = pair.value.clone();
                    seen_section = true;
                    let _ = writeln!(body, "section: {section}");
                    continue;
                }
                Await::TableType => {
                    if pair.code != 2 {
                        bail!("dxf: a table is named by group code 2, not {}", pair.code);
                    }
                    table = pair.value.clone();
                    let _ = writeln!(body, "  table: {table}");
                    // The table's own codes (its handle, its subclass
                    // marker, how many entries it has) belong to the table
                    // and not to an entry of it.
                    item = Some(Item {
                        kind: Kind::Table,
                        name: table.clone(),
                        codes: Vec::new(),
                    });
                    continue;
                }
                Await::BlockName => {
                    if pair.code != 2 {
                        bail!("dxf: a block is named by group code 2, not {}", pair.code);
                    }
                    let _ = writeln!(body, "block: {}", pair.value);
                    item = Some(Item {
                        kind: Kind::Block,
                        name: pair.value,
                        codes: Vec::new(),
                    });
                    continue;
                }
            }
        }

        // A header variable: `9` names it and the pair after it is its
        // value.
        if pair.code == 9 && section == "HEADER" {
            flush(&mut body, &mut item, &table, &mut stats);
            item = Some(Item {
                kind: Kind::Variable,
                name: pair.value.clone(),
                codes: Vec::new(),
            });
            continue;
        }

        // A `0` opens a section, a table, an entity or the end of the file.
        if pair.code == 0 {
            flush(&mut body, &mut item, &table, &mut stats);
            match pair.value.as_str() {
                "SECTION" => {
                    await_ = Some(Await::SectionName);
                    continue;
                }
                "ENDSEC" => {
                    section.clear();
                    table.clear();
                    continue;
                }
                "EOF" => {
                    seen_eof = true;
                    break;
                }
                "TABLE" => {
                    await_ = Some(Await::TableType);
                    continue;
                }
                "ENDTAB" => {
                    table.clear();
                    continue;
                }
                "BLOCK" => {
                    await_ = Some(Await::BlockName);
                    continue;
                }
                "ENDBLK" => continue,
                // The end of a polyline's vertex list: it is not a drawing
                // object of its own.
                "SEQEND" => continue,
                other => {
                    // Inside the tables section this opens a table entry;
                    // anywhere else it opens an entity.
                    let kind = if section == "TABLES" {
                        Kind::Entry
                    } else {
                        Kind::Entity
                    };
                    item = Some(Item {
                        kind,
                        name: other.to_string(),
                        codes: Vec::new(),
                    });
                    continue;
                }
            }
        }

        // Any other code belongs to the thing that is open.
        if item.is_none() {
            // A code that opens nothing: it is shown, but it is not a
            // drawing object and the summary does not count it.
            item = Some(Item {
                kind: Kind::Loose,
                name: String::new(),
                codes: Vec::new(),
            });
        }
        if let Some(it) = item.as_mut() {
            it.codes.push((pair.code, pair.value));
        }
    }

    flush(&mut body, &mut item, &table, &mut stats);

    if !seen_eof {
        if seen_section {
            bail!("dxf: the file ends without 0/EOF");
        }
        // No section and no end of file: not a drawing at all.
        decline!("dxf: no 0/SECTION and no 0/EOF");
    }

    Ok(finish(&summary(&stats), &body))
}

/// The next group code and its value.
///
/// The value is on the line after the code, which is what every writer
/// does, or on the code's own line, which some do.
fn next_pair(lines: &[&str], at: &mut usize) -> Result<Pair, PairErr> {
    let Some(line) = lines.get(*at) else {
        return Err(PairErr::End);
    };
    *at += 1;
    let Some((code, end)) = group_code(line) else {
        return Err(PairErr::NotACode((*line).to_string()));
    };
    let rest = line[end..].trim();
    if !rest.is_empty() {
        return Ok(Pair {
            code,
            value: rest.to_string(),
        });
    }
    let Some(value) = lines.get(*at) else {
        return Err(PairErr::NoValue(code));
    };
    *at += 1;
    // The value is trimmed of the padding the writer used to line it up in
    // its column: the padding is not part of the value, and keeping it
    // would make "layer: LAYER1" unmatchable, which is the whole of the
    // rendering.
    Ok(Pair {
        code,
        value: value.trim().to_string(),
    })
}

/// The group code a line holds, and where it ends.
///
/// A group code is a small integer and nothing else: a sign, a space in
/// the middle or a decimal point makes the line something else.
fn group_code(line: &str) -> Option<(u16, usize)> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == start || i - start > 6 {
        return None;
    }
    let code = line[start..i].parse::<u16>().ok()?;
    Some((code, i))
}

// ---------------------------------------------------------------------------
// The rendering
// ---------------------------------------------------------------------------

/// Emits the item that just ended and starts the accounting for it.
fn flush(out: &mut String, item: &mut Option<Item>, table: &str, stats: &mut Stats) {
    let Some(it) = item.take() else {
        return;
    };
    match it.kind {
        Kind::Entity => {
            stats.entities += 1;
            push_unique(&mut stats.kinds, &it.name.to_lowercase());
            if let Some((_, layer)) = it.codes.iter().find(|(c, _)| *c == 8) {
                push_unique(&mut stats.layers, layer);
            }
            render_entity(out, &it.name, &it.codes);
        }
        Kind::Entry => {
            // The layer table's entries are the drawing's layers.
            if table == "LAYER" {
                if let Some((_, name)) = it.codes.iter().find(|(c, _)| *c == 2) {
                    push_unique(&mut stats.layers, name);
                }
            }
            render_entry(out, &it.codes);
        }
        Kind::Table => render_table_header(out, &it.codes),
        Kind::Block => render_block(out, &it.codes),
        Kind::Variable => render_variable(out, &it.name, &it.codes),
        Kind::Loose => render_loose(out, &it.codes),
    }
}

/// The table's own header: its handle, its subclass marker and how many
/// entries it declares.
fn render_table_header(out: &mut String, codes: &[(u16, String)]) {
    for (code, value) in codes {
        let field = match *code {
            5 => "handle",
            70 => "entries",
            100 | 1001 => "subclass",
            _ => {
                let mut label = String::new();
                let _ = write!(label, "value [{code}]");
                emit_field(out, "    ", &label, value);
                continue;
            }
        };
        emit_field(out, "    ", field, value);
    }
}

/// A code that opened nothing: shown, and counted as nothing.
fn render_loose(out: &mut String, codes: &[(u16, String)]) {
    for (code, value) in codes {
        let mut label = String::new();
        let _ = write!(label, "value [{code}]");
        emit_field(out, "  ", &label, value);
    }
}

/// One entity: its type and its layer on one line, its fields below.
///
/// The type and the layer are the pair the file does not have — the file
/// writes the type on one line and the layer on another, ten codes apart.
/// The layer is written a second time as a field of its own, because "which
/// entities are on LAYER1" is a question asked of every entity and a field
/// is the shape that answers it in one pattern.
fn render_entity(out: &mut String, name: &str, codes: &[(u16, String)]) {
    match codes.iter().find(|(c, _)| *c == 8) {
        Some((_, layer)) => {
            let _ = writeln!(out, "entity: {name} on layer {layer}");
        }
        None => {
            let _ = writeln!(out, "entity: {name}");
        }
    }

    let mut i = 0usize;
    while i < codes.len() {
        let (code, value) = &codes[i];

        // A point is three codes: the x, the y and the z. They are written
        // one after the other and they are one thing. Which code holds the
        // y and which holds the z depends on the x: 10 is 20/30, 11 is
        // 21/31, 12 is 22/32 and 13 is 23/33.
        if matches!(*code, 10..=13) {
            let label = point_label(name, *code);
            let (y_code, z_code) = match *code {
                11 => (21, 31),
                12 => (22, 32),
                13 => (23, 33),
                _ => (20, 30),
            };
            let mut parts: Vec<String> = Vec::new();
            parts.push(real(value));
            let mut j = i + 1;
            if let Some((c, v)) = codes.get(j) {
                if *c == y_code {
                    parts.push(real(v));
                    j += 1;
                    if let Some((c, v)) = codes.get(j) {
                        if *c == z_code {
                            parts.push(real(v));
                            j += 1;
                        }
                    }
                }
            }
            // The z of a point that has none is 0 by the specification.
            while parts.len() < 3 {
                parts.push(String::from("0.0"));
            }
            let _ = writeln!(out, "  {label}: {}", parts.join(", "));
            i = j;
            continue;
        }

        match entity_field(name, *code) {
            Some(field) => emit_field(out, "  ", field, &field_value(field, value)),
            None => {
                let mut label = String::new();
                let _ = write!(label, "value [{code}]");
                emit_field(out, "  ", &label, value);
            }
        }
        i += 1;
    }
}

/// One table entry: its name, and the flags and the colour it declares.
fn render_entry(out: &mut String, codes: &[(u16, String)]) {
    for (code, value) in codes {
        let field = match *code {
            2 => "name",
            5 => "handle",
            6 => "linetype",
            7 => "style",
            62 => "colour",
            70 => "flags",
            100 | 1001 => "subclass",
            _ => {
                let mut label = String::new();
                let _ = write!(label, "value [{code}]");
                emit_field(out, "    ", &label, value);
                continue;
            }
        };
        emit_field(out, "    ", field, value);
    }
}

/// One block header: the fields under the block's name.
fn render_block(out: &mut String, codes: &[(u16, String)]) {
    for (code, value) in codes {
        match entity_field("BLOCK", *code) {
            Some(field) => emit_field(out, "  ", field, &field_value(field, value)),
            None => {
                let mut label = String::new();
                let _ = write!(label, "value [{code}]");
                emit_field(out, "  ", &label, value);
            }
        }
    }
}

/// One header variable: its value on the variable's own line.
fn render_variable(out: &mut String, name: &str, codes: &[(u16, String)]) {
    let mut first = true;
    for (code, value) in codes {
        if first {
            emit_field(out, "  ", name, value);
            first = false;
            continue;
        }
        let mut label = String::new();
        let _ = write!(label, "value [{code}]");
        emit_field(out, "    ", &label, value);
    }
}

/// One field: `name: value`, and an empty value is an empty string.
fn emit_field(out: &mut String, indent: &str, name: &str, value: &str) {
    if value.is_empty() {
        let _ = writeln!(out, "{indent}{name}:");
    } else {
        let _ = writeln!(out, "{indent}{name}: {value}");
    }
}

/// The name of a code inside an entity, when the code means the same thing
/// in every entity.
fn common_field(code: u16) -> Option<&'static str> {
    match code {
        1 => Some("text"),
        5 => Some("handle"),
        6 => Some("linetype"),
        7 => Some("style"),
        8 => Some("layer"),
        62 => Some("colour"),
        70 => Some("flags"),
        // A subclass marker announces the group of codes that follows. It
        // carries no value of its own, but it is a code and a value, and
        // the rendering keeps every pair it can.
        100 | 1000 | 1001 => Some("subclass"),
        _ => None,
    }
}

/// The name of a code whose meaning depends on the entity's type.
fn typed_field(kind: &str, code: u16) -> Option<&'static str> {
    match (kind, code) {
        ("CIRCLE" | "ARC", 40) => Some("radius"),
        ("ARC", 50) => Some("start angle"),
        ("ARC", 51) => Some("end angle"),
        ("TEXT" | "MTEXT" | "ATTDEF" | "ATTRIB", 40) => Some("height"),
        ("TEXT" | "MTEXT" | "ATTDEF" | "ATTRIB", 41) => Some("width factor"),
        ("TEXT" | "MTEXT", 50) => Some("rotation"),
        ("TEXT" | "MTEXT", 51) => Some("oblique"),
        // An MTEXT's text runs over several codes.
        ("MTEXT", 3) => Some("text"),
        ("INSERT", 41) => Some("x scale"),
        ("INSERT", 42) => Some("y scale"),
        ("INSERT", 43) => Some("z scale"),
        ("ELLIPSE", 40) => Some("ratio"),
        ("ELLIPSE", 41) => Some("start angle"),
        ("ELLIPSE", 42) => Some("end angle"),
        ("LWPOLYLINE", 40) => Some("width"),
        ("SPLINE", 40) => Some("knot"),
        _ => None,
    }
}

/// The name of a code inside one entity.
fn entity_field(kind: &str, code: u16) -> Option<&'static str> {
    match code {
        // The name of a block an INSERT puts on the drawing.
        2 => Some(if kind == "INSERT" { "block" } else { "name" }),
        _ => common_field(code).or_else(|| typed_field(kind, code)),
    }
}

/// The name of a point, which is what the entity's type decides.
fn point_label(kind: &str, code: u16) -> &'static str {
    match code {
        10 => match kind {
            "LINE" => "start",
            "CIRCLE" | "ARC" | "ELLIPSE" => "centre",
            "TEXT" | "MTEXT" | "INSERT" | "POINT" | "ATTDEF" | "ATTRIB" => "at",
            "SOLID" | "3DFACE" => "corner 1",
            "LWPOLYLINE" | "POLYLINE" | "VERTEX" | "SPLINE" => "vertex",
            "BLOCK" => "base point",
            _ => "point",
        },
        11 => match kind {
            "LINE" => "end",
            "SOLID" | "3DFACE" => "corner 2",
            "ELLIPSE" => "major axis end",
            _ => "point 2",
        },
        12 => match kind {
            "SOLID" | "3DFACE" => "corner 3",
            _ => "point 3",
        },
        13 => match kind {
            "SOLID" | "3DFACE" => "corner 4",
            _ => "point 4",
        },
        _ => "point",
    }
}

/// The value of a field, when the field holds a real.
///
/// The real is printed with a decimal point, so that a point reads the same
/// whether the writer wrote `0.0` or `0`.
fn field_value(field: &str, raw: &str) -> String {
    match field {
        "radius" | "start angle" | "end angle" | "height" | "width factor" | "rotation"
        | "oblique" | "ratio" | "x scale" | "y scale" | "z scale" | "knot" => real(raw),
        _ => raw.to_string(),
    }
}

/// A real, as a drawing writes it: with a decimal point.
fn real(token: &str) -> String {
    let t = token.trim();
    // The parser this crate carries is the JSON one, and JSON writes neither
    // `0.` nor `.5`; a DXF writes both.
    let mut normalised = String::with_capacity(t.len() + 2);
    if let Some(rest) = t.strip_prefix('.') {
        normalised.push('0');
        normalised.push_str(rest);
    } else if let Some(rest) = t.strip_suffix('.') {
        normalised.push_str(rest);
        normalised.push_str(".0");
    } else {
        normalised.push_str(t);
    }
    let Ok(value) = f64::parse(&normalised) else {
        // A real this reader cannot read is shown as it was written.
        return t.to_string();
    };
    let mut out = String::new();
    let _ = write!(out, "{value}");
    if !out.contains('.')
        && !out.contains('e')
        && !out.contains('E')
        && !out.contains("inf")
        && !out.contains("NaN")
    {
        out.push_str(".0");
    }
    out
}

/// Keeps a name once.
fn push_unique(names: &mut Vec<String>, name: &str) {
    if name.is_empty() {
        return;
    }
    if !names.iter().any(|n| n == name) {
        names.push(name.to_string());
    }
}

/// The summary of what the drawing holds.
fn summary(stats: &Stats) -> String {
    let mut out = String::new();
    if stats.entities == 0 {
        let _ = write!(out, "dxf: no entities");
    } else {
        let kinds = if stats.kinds.len() > 6 {
            let mut s = stats.kinds[..6].join(", ");
            let _ = write!(s, ", +{} more", stats.kinds.len() - 6);
            s
        } else {
            stats.kinds.join(", ")
        };
        let _ = write!(out, "dxf: {} entities ({})", stats.entities, kinds);
    }
    if stats.layers.len() == 1 {
        let _ = write!(out, " on 1 layer");
    } else {
        let _ = write!(out, " on {} layers", stats.layers.len());
    }
    out
}

/// Composes a rendering: the summary in front, the drawing behind it.
///
/// The summary goes first because it is the question the file answers
/// slowest, and the drawing behind it because it is the question the user
/// is usually asking.
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
    //! The fixture is written by hand to the format's specification and kept
    //! as a file, so the end-to-end run reads the same bytes the unit tests
    //! read: a fixture that only exists in a test is a fixture the binary
    //! was never shown.
    //!
    //! The first test is the one that matters: it asserts that the file
    //! itself does **not** contain what the rendering contains, because a
    //! rendering that only re-orders what `rg` already sees would be a
    //! rendering for nothing.

    use super::*;

    const DXF: &[u8] = include_bytes!("../testdata/sample.dxf");

    #[test]
    fn a_dxf_renders_what_the_file_does_not() {
        let file = String::from_utf8_lossy(DXF);
        // The file writes the entity's type and its layer on two lines, ten
        // codes apart. The rendering puts them together, and that pair is
        // not in the file.
        assert!(
            !file.contains("layer: LAYER1"),
            "the fixture is a code/value file"
        );
        assert!(
            !file.contains("entity: LINE"),
            "the fixture is a code/value file"
        );
        let out = render_dxf(DXF).expect("a dxf is ours");
        assert!(out.contains("layer: LAYER1"), "{out}");
        assert!(out.contains("entity: LINE on layer LAYER1"), "{out}");
    }

    #[test]
    fn a_dxf_renders_its_header_variables() {
        let out = render_dxf(DXF).expect("a dxf is ours");
        assert!(out.contains("$ACADVER: AC1015"), "{out}");
        // The writer pads the value to its column; the rendering does not
        // keep the padding, or the value would not be matchable.
        assert!(out.contains("$INSUNITS: 4"), "{out}");
    }

    #[test]
    fn a_dxf_renders_its_entities() {
        let out = render_dxf(DXF).expect("a dxf is ours");
        assert!(out.contains("entity: LINE"), "{out}");
        assert!(out.contains("entity: TEXT"), "{out}");
        assert!(out.contains("entity: CIRCLE"), "{out}");
        assert!(out.contains("Contrato ACME"), "{out}");
        // The points and the radius are reals, and a real reads with a
        // decimal point.
        assert!(out.contains("start: 0.0, 0.0, 0.0"), "{out}");
        assert!(out.contains("end: 100.0, 50.0, 0.0"), "{out}");
        assert!(out.contains("centre: 50.0, 25.0, 0.0"), "{out}");
        assert!(out.contains("radius: 25.0"), "{out}");
        assert!(
            out.contains("dxf: 3 entities (line, text, circle)"),
            "{out}"
        );
    }

    #[test]
    fn a_dxf_renders_its_layer_table() {
        let out = render_dxf(DXF).expect("a dxf is ours");
        assert!(out.contains("table: LAYER"), "{out}");
        assert!(out.contains("name: LAYER1"), "{out}");
        assert!(out.contains("colour: 7"), "{out}");
        assert!(out.contains("flags: 0"), "{out}");
        assert!(out.contains("on 4 layers"), "{out}");
    }

    #[test]
    fn a_utf8_bom_is_skipped() {
        let mut with_bom = Vec::from(&b"\xef\xbb\xbf"[..]);
        with_bom.extend_from_slice(DXF);
        let out = render_dxf(&with_bom).expect("a dxf is ours");
        assert!(out.contains("entity: LINE on layer LAYER1"), "{out}");
    }

    #[test]
    fn a_file_that_is_not_a_dxf_is_declined() {
        let err = render_dxf(b"not a drawing at all").expect_err("not a dxf");
        assert!(err.is_decline(), "{err}");
        // A file of group codes that is not a drawing is declined too.
        let err = render_dxf(b"999\na comment\n").expect_err("not a dxf");
        assert!(err.is_decline(), "{err}");
    }

    #[test]
    fn a_truncated_dxf_is_an_error_and_not_a_panic() {
        let cut = &DXF[..DXF.len() / 2];
        let err = render_dxf(cut).expect_err("truncated");
        // It claims to be a drawing, so it is a failure and not a step
        // aside: the next adapter has nothing to do with it.
        assert!(!err.is_decline(), "{err}");
    }
}
