// SPDX-License-Identifier: Apache-2.0
//
// The record layout below was learned from ezdxf's implementation, which is
// the description of the format that exists; the code here is rgx's own.
// The provenance is recorded in `NOTICE`.

//! ACIS `.sat` — the text container of an ACIS B-rep model, read as a
//! rendering.
//!
//! **What these are.** An ACIS model is a set of entities — a body, the
//! shells under it, their faces, the edges and vertices under those — and a
//! `.sat` file is that model written as text. The same model in a binary
//! container is a `.sab`, and the `.sab` adapter in `cad.rs` reads that one.
//!
//! **Why it is rendered and not revealed.** `rg` reads the file: it is ASCII,
//! and every entity is a run of tokens on one line. An adapter that
//! *answered* for it would replace bytes ripgrep already searches, and rgx
//! would answer a subset of what `rg` answers. This is therefore
//! [`Reach::Render`], the same reach the flat files of this crate declare:
//! under the default `Policy::Source` the file's own bytes are the answer and
//! this adapter is not consulted at all; under `RGX_ADAPTER_VIEW=render` the
//! rendering is what gets searched.
//!
//! **What the rendering is for.** The pairing. A record is
//! `body $-1 2 $0 #` — the entity's name, the pointer to the entity that
//! owns it, its own id, its data, and the `#` that ends it — and a pointer
//! is an *index* into the list of records, so the file says "entity zero"
//! where a reader says "the transform". The rendering names each entity,
//! gives it its id, and says which entity a pointer reaches.
//!
//! **How it is read.** The layout follows the writer side of the
//! reference implementation (ezdxf: `src/ezdxf/acis/sat.py`,
//! `src/ezdxf/acis/hdr.py` and `src/ezdxf/acis/const.py`), not a
//! description of it:
//!
//!   * the header is three lines — four integers; three length-prefixed
//!     strings; the unit and the two tolerances;
//!   * a record is the entity's name, the pointer to its owner, its id (from
//!     version 700 up), its data tokens, and `#`;
//!   * a data token is a pointer (`$N`), a number, a boolean (`forward`,
//!     `reversed`, ...), an interval (`F` for finite, `I` for infinite) or a
//!     string (`@<len>` followed by the text);
//!   * the file ends with `End-of-ACIS-data` or `End-of-ASM-data`, or opens
//!     its history block with `Begin-of-ACIS-History-data`.
//!
//! **What is not claimed.** The geometry is not evaluated. A `point`'s three
//! numbers are the numbers the file wrote; a `transform`'s twelve are the
//! matrix the file wrote. This is a view of the file's own statements and
//! not a kernel, and it says so rather than pretending to be one.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::mem;
use rgx_core::{bail, decline, Adapter, NoStdFloat, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost.
const MAX_RENDER: usize = 64 << 20;

/// The marker that ends the entity data.
const END_OF_ACIS_DATA: &str = "End-of-ACIS-data";
/// The marker an ASM-headed file ends with.
const END_OF_ASM_DATA: &str = "End-of-ASM-data";
/// The marker that opens the history block, which is not the model.
const BEGIN_OF_HISTORY: &str = "Begin-of-ACIS-History-data";

/// An ACIS `.sat` file.
pub struct AcisSat;
impl Adapter for AcisSat {
    fn name(&self) -> &'static str {
        "acis-sat"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["sat"]
    }
    /// The file is text `rg` already reads: a rendering, never an answer.
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_sat(data)?.into_bytes()))
    }
}

/// One entity of the model, as the file wrote it.
struct Entity {
    /// The entity's type: `body`, `transform`, `point`, ...
    name: String,
    /// The entity's own id, or -1 when the file's version carries none.
    id: i64,
    /// The pointer to the entity that owns this one, as the file wrote it.
    owner: String,
    /// The data tokens, verbatim.
    data: Vec<String>,
}

/// The SAT rendering: the summary in front, one block per entity.
fn render_sat(data: &[u8]) -> Result<String> {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<&str> = text.lines().collect();

    // The claim: the file opens with the ACIS version number. A file that
    // does not is another format's, and saying so is what lets the next
    // adapter have it.
    let head: Vec<&str> = lines
        .first()
        .map(|l| l.split_whitespace().collect())
        .unwrap_or_default();
    let version: i64 = match head.first().and_then(|t| t.parse::<i64>().ok()) {
        Some(v) => v,
        None => decline!("acis-sat: the file does not open with an ACIS version number"),
    };
    if lines.len() < 3 {
        bail!(
            "acis-sat: the header is truncated: {} line(s) where 3 are written",
            lines.len()
        );
    }

    let entities = parse_entities(&lines[3..], version)?;

    // The end of the model. Everything past it is not the model: the history
    // block, which is a record of what the kernel did, not of what the
    // drawing is.
    let mut body_text = String::new();
    let mut ended = false;
    let mut history = false;
    for line in &lines[3..] {
        if line.starts_with(END_OF_ACIS_DATA) || line.starts_with(END_OF_ASM_DATA) {
            ended = true;
            break;
        }
        if line.starts_with(BEGIN_OF_HISTORY) {
            ended = true;
            history = true;
            break;
        }
        body_text.push_str(line);
        body_text.push(' ');
    }
    if !ended {
        bail!("acis-sat: the file ends without its end-of-data marker");
    }

    let mut body = String::new();
    let strings = header_strings(lines[1]);
    let claim = |i: usize| head.get(i).copied().unwrap_or("?");
    let _ = writeln!(
        body,
        "  product: {}",
        strings.first().map(String::as_str).unwrap_or("")
    );
    let _ = writeln!(
        body,
        "  acis version: {}",
        strings.get(1).map(String::as_str).unwrap_or("")
    );
    let _ = writeln!(
        body,
        "  created: {}",
        strings.get(2).map(String::as_str).unwrap_or("")
    );
    let units: Vec<&str> = lines[2].split_whitespace().collect();
    let _ = writeln!(
        body,
        "  units: {} mm",
        units.first().map(|t| real(t)).unwrap_or_default()
    );
    // The tolerances keep the file's own notation: `9.9999999999999995e-007`
    // is a value the shortest round-trip decimal does not shorten, and
    // rewriting it as a twenty-four-digit decimal would be noise.
    let _ = writeln!(body, "  tolerances: {}", units[1..].join(", "));
    let _ = writeln!(
        body,
        "  file header: version {}, records {}, entities {}, flags {}",
        version,
        claim(1),
        claim(2),
        claim(3)
    );
    if history {
        let _ = writeln!(
            body,
            "  note: the file carries a history block after the model; it is not read"
        );
    }

    for entity in &entities {
        let id = if entity.id >= 0 {
            format!(" (id {})", entity.id)
        } else {
            String::new()
        };
        let _ = writeln!(body, "entity: {}{}", entity.name, id);
        let _ = writeln!(
            body,
            "  attributes: {}",
            describe_pointer(&entity.owner, &entities)
        );
        render_data(&mut body, entity, &entities);
    }

    let mut kinds: Vec<&str> = entities.iter().map(|e| e.name.as_str()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let summary = if entities.is_empty() {
        format!("acis: no entities in ACIS {version}")
    } else {
        format!(
            "acis: {} entities ({}) in ACIS {}",
            entities.len(),
            kinds.join(", "),
            version
        )
    };

    Ok(finish(&summary, &body))
}

/// Parse the records of the model.
///
/// The records are the body of the file joined by spaces and split at the
/// `#` that ends each one. A record may carry a sequence number as its
/// first token — a negative integer that counts the records — and it is not
/// part of the entity, so it is dropped rather than mistaken for a name.
fn parse_entities(lines: &[&str], version: i64) -> Result<Vec<Entity>> {
    let mut body = String::new();
    for line in lines {
        if line.starts_with(END_OF_ACIS_DATA)
            || line.starts_with(END_OF_ASM_DATA)
            || line.starts_with(BEGIN_OF_HISTORY)
        {
            break;
        }
        body.push_str(line);
        body.push(' ');
    }

    let mut entities = Vec::new();
    for chunk in body.split('#') {
        let record = chunk.trim();
        if record.is_empty() {
            continue;
        }
        let mut tokens: Vec<&str> = record.split_whitespace().collect();
        if let Some(first) = tokens.first() {
            if first.starts_with('-') {
                tokens.remove(0);
            }
        }
        if tokens.len() < 2 {
            bail!(
                "acis-sat: a record has {} token(s) where a name and a pointer are expected",
                tokens.len()
            );
        }
        let name = tokens[0].to_string();
        let owner = tokens[1].to_string();
        // From version 700 up the entity carries its own id; before that the
        // id did not exist and the record is two tokens shorter.
        let (id, rest) = if version >= 700 {
            let id = match tokens.get(2).and_then(|t| t.parse::<i64>().ok()) {
                Some(v) => v,
                None => bail!("acis-sat: the record {name:?} carries no id"),
            };
            (id, &tokens[3.min(tokens.len())..])
        } else {
            (-1, &tokens[2.min(tokens.len())..])
        };
        entities.push(Entity {
            name,
            id,
            owner,
            data: rest.iter().map(|t| t.to_string()).collect(),
        });
    }
    Ok(entities)
}

/// Render an entity's data tokens.
fn render_data(out: &mut String, entity: &Entity, entities: &[Entity]) {
    // The entities whose data is a fixed list of numbers. The count is the
    // format's, not a guess: a `transform` carries the twelve values of its
    // matrix, a `point`, a `direction` and the two vector kinds carry three
    // coordinates each.
    let known = match entity.name.as_str() {
        "transform" => Some((12, "matrix")),
        "point" | "direction" | "hvector" | "vvector" => Some((3, "value")),
        _ => None,
    };

    let mut i = 0usize;
    if let Some((count, label)) = known {
        if entity.data.len() >= count {
            let values: Vec<String> = entity.data[..count].iter().map(|t| real(t)).collect();
            let _ = writeln!(out, "  {label}: {}", values.join(", "));
            i = count;
        }
    }

    while i < entity.data.len() {
        let token = entity.data[i].as_str();
        if token.starts_with('$') {
            let _ = writeln!(out, "  reference: {}", describe_pointer(token, entities));
            i += 1;
        } else if token.starts_with('@') {
            // A string is written as its length and then its text.
            let text = entity.data.get(i + 1).cloned().unwrap_or_default();
            let _ = writeln!(out, "  text: {text}");
            i += 2;
        } else if token == "F" {
            // An interval: finite, and then its value.
            let value = entity.data.get(i + 1).map(|t| real(t)).unwrap_or_default();
            let _ = writeln!(out, "  interval: finite, {value}");
            i += 2;
        } else if token == "I" {
            let _ = writeln!(out, "  interval: infinite");
            i += 1;
        } else {
            let _ = writeln!(out, "  value: {token}");
            i += 1;
        }
    }
}

/// Say what a pointer reaches.
///
/// A pointer is an index into the list of records, so it can be resolved
/// once the whole list is known — which is why the entities are collected
/// before any of them is rendered. `$-1` is the null pointer.
fn describe_pointer(token: &str, entities: &[Entity]) -> String {
    if token == "$-1" {
        return "none".to_string();
    }
    let index = match token
        .strip_prefix('$')
        .and_then(|r| r.parse::<usize>().ok())
    {
        Some(i) => i,
        None => return token.to_string(),
    };
    match entities.get(index) {
        Some(entity) if entity.id >= 0 => format!("{} (id {})", entity.name, entity.id),
        Some(entity) => entity.name.clone(),
        None => token.to_string(),
    }
}

/// Parse the header's second line: the three length-prefixed strings.
///
/// The reader counts: digits accumulate into a number, a space turns that
/// number into a length, and the next `length` characters are the string.
/// An `@` is decoration and is skipped, which is why the same line reads
/// whether or not the writer put one in front of each length.
fn header_strings(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut num = String::new();
    let mut collect: usize = 0;
    let mut token = String::new();
    for c in line.trim_end().chars() {
        if collect > 0 {
            token.push(c);
            collect -= 1;
            if collect == 0 {
                out.push(mem::take(&mut token));
            }
        } else if c == '@' {
            continue;
        } else if c.is_ascii_digit() {
            num.push(c);
        } else if c == ' ' && !num.is_empty() {
            collect = num.parse().unwrap_or(0);
            num.clear();
        }
    }
    out
}

/// A number as the rendering prints it.
///
/// The file writes a real as the shortest form that reads back (`1`, `0.5`,
/// `1e-010`), which does not say whether it was an integer or a real. Where
/// the format says a value is a real — a coordinate, a matrix entry — the
/// rendering prints it as one, with the decimal point the file's own
/// notation leaves out. Everywhere else the token is printed as it was
/// written.
fn real(token: &str) -> String {
    let t = token.trim();
    // The decimal parser of `no_std` follows RFC 8259 and refuses `1.` and
    // `.5`; both are legal in a CAD file, so they are normalised first.
    let mut normalised = t.to_string();
    if normalised.ends_with('.') {
        normalised.push('0');
    } else if normalised.starts_with('.') {
        normalised.insert(0, '0');
    }
    match f64::parse(&normalised) {
        Ok(value) => {
            let mut out = String::new();
            let _ = write!(out, "{value}");
            if !out.contains('.')
                && !out.contains('e')
                && !out.contains("inf")
                && !out.contains("NaN")
            {
                out.push_str(".0");
            }
            out
        }
        Err(_) => t.to_string(),
    }
}

/// Compose a rendering: the summary in front, the entities behind it.
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAT: &[u8] = include_bytes!("../testdata/sample.sat");

    #[test]
    fn the_rendering_shows_what_the_file_does_not() {
        let file = String::from_utf8_lossy(SAT);
        assert!(
            !file.contains("entity: transform (id 1)"),
            "the file writes the name, the pointer, the id and the data apart"
        );
        let out = render_sat(SAT).expect("a sat file is ours");
        assert!(
            out.contains("entity: transform (id 1)"),
            "the rendering puts them together:\n{out}"
        );
    }

    #[test]
    fn the_header_is_rendered() {
        let out = render_sat(SAT).expect("a sat file is ours");
        assert!(out.contains("product: rgx fixture ACIS Builder"), "{out}");
        assert!(out.contains("acis version: ACIS 32.0 NT"), "{out}");
        assert!(out.contains("created: Mon Oct 19 12:00:00 2026"), "{out}");
        assert!(out.contains("units: 1.0 mm"), "{out}");
    }

    #[test]
    fn the_entities_are_counted_and_named() {
        let out = render_sat(SAT).expect("a sat file is ours");
        assert!(
            out.contains("acis: 5 entities (body, colour, direction, point, transform)"),
            "{out}"
        );
    }

    #[test]
    fn a_pointer_names_the_entity_it_reaches() {
        let out = render_sat(SAT).expect("a sat file is ours");
        // The body's data is `$0`, the transform: the file says "entity
        // zero" and the rendering says which entity that is.
        assert!(out.contains("reference: transform (id 1)"), "{out}");
        assert!(out.contains("attributes: none"), "{out}");
    }

    #[test]
    fn the_matrix_is_one_line() {
        let out = render_sat(SAT).expect("a sat file is ours");
        // The twelve values of the matrix, in the order the file wrote them:
        // three columns of four, which is how a transform is stored.
        assert!(
            out.contains("matrix: 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0"),
            "{out}"
        );
    }

    #[test]
    fn a_file_that_is_not_acis_is_declined() {
        let err = render_sat(b"this is not an ACIS model at all\n").expect_err("not ours");
        assert!(err.is_decline(), "a decline is not a failure: {err}");
    }

    #[test]
    fn a_truncated_file_is_an_error_not_a_panic() {
        let err = render_sat(b"700 0 5 0 \n").expect_err("truncated");
        assert!(!err.is_decline(), "a truncated file is a failure: {err}");
    }

    #[test]
    fn the_length_prefixed_strings_read_with_or_without_the_at() {
        // The writer puts an `@` in front of each length from version 400
        // up and leaves it out before that. The reader skips it either way.
        let with = header_strings("@24 rgx fixture ACIS Builder @12 ACIS 32.0 NT ");
        assert_eq!(with[0], "rgx fixture ACIS Builder");
        assert_eq!(with[1], "ACIS 32.0 NT");
        let without = header_strings("24 rgx fixture ACIS Builder 12 ACIS 32.0 NT ");
        assert_eq!(without[0], "rgx fixture ACIS Builder");
        assert_eq!(without[1], "ACIS 32.0 NT");
    }
}
