// SPDX-License-Identifier: Apache-2.0

//! **STL**, the triangle mesh: a solid, a list of facets, and each facet's
//! normal and three vertices.
//!
//! **What these are.** A mesh, and the two ways it is written. The **ASCII**
//! form is a list of keywords — `solid`, `facet normal`, `outer loop`,
//! `vertex`, `endloop`, `endfacet`, `endsolid` — with the numbers on the
//! same lines as the keywords. The **binary** form is an 80-byte header, a
//! `uint32` triangle count, and 50 bytes per triangle: twelve `float32`s
//! (the normal, then the three vertices) and a `uint16` attribute count.
//!
//! **The extension does not say which.** Both are `.stl`, and the binary
//! header often begins with the word "solid" — so neither the extension
//! nor the first word decides. What decides is the structure: a file is
//! ASCII when it parses as the keyword grammar, and binary when its length
//! is exactly `84 + 50 * count` for the count at offset 80. A file that is
//! neither is declined, so the next adapter gets its chance.
//!
//! **Why they are rendered and not answered.** The ASCII form is plain text
//! that ripgrep already reads, so an adapter that *answered* for it would
//! replace bytes ripgrep already searches, and rgx would answer a subset of
//! what `rg` answers. It is therefore [`Reach::Render`], the same reach the
//! flat files of this crate declare: under the default `Policy::Source` the
//! file's own bytes are the answer and the renderer is not consulted at
//! all, and under `RGX_ADAPTER_VIEW=render` or `RGX_ADAPTER_VIEW=both` the
//! rendering is what gets searched.
//!
//! **What the rendering is for.** The three vertices of a facet are three
//! lines in the file and ONE line here:
//!
//! ```text
//!   vertices: 0.0, 0.0, 0.0 | 10.0, 0.0, 0.0 | 0.0, 10.0, 0.0
//! ```
//!
//! A search for two coordinates of the same triangle is one pattern in the
//! rendering and two in the file, and the pattern the user can write is the
//! one that matters. The rendering also opens with what the file holds —
//! how many facets, in which solid — which is a question the file answers
//! only by being read all the way through.
//!
//! **The binary form is rendered by the same adapter.** The extension is
//! the same, and the renderer must not answer for a file it did not read:
//! a binary STL is not text ripgrep can search, so the same adapter reads
//! it and renders what the binary form honestly gives — the facet count,
//! the normal and the three vertices of each facet. The 80-byte header and
//! the per-triangle attribute count are not decoded, and the rendering says
//! the file is binary rather than inventing a name for it.
//!
//! **What is not claimed.** A `.stl` that is neither form is declined. An
//! ASCII STL whose grammar this reader does not know — a `color` line, say
//! — is reported as a failure rather than declined: it *is* a mesh, and
//! this reader could not decode it.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{bail, decline, Adapter, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost. A 64 MiB ceiling is far
/// above any mesh whose whole content is worth a second copy, and the
/// rendering says so when it bites rather than stopping in silence.
const MAX_RENDER: usize = 64 << 20;

/// Bytes a solid's name may hold.
///
/// A name is a word or two. The cap is here for the file whose first line
/// happens to be the whole file — a binary mesh with no newline in it —
/// and whose "name" would otherwise be copied into the rendering whole.
const MAX_NAME: usize = 128;

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// A triangle mesh, in either of the two forms the extension carries.
pub struct Stl;
impl Adapter for Stl {
    fn name(&self) -> &'static str {
        "stl"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["stl"]
    }
    /// The ASCII form is text `rg` already reads: a rendering, never an answer.
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_stl(data)?.into_bytes()))
    }
}

// ---------------------------------------------------------------------------
// The rendering
// ---------------------------------------------------------------------------

/// The STL rendering: a summary, then one block per facet.
///
/// The three vertices of a facet are on ONE line, which is the whole point:
/// in the file they are three separate lines, so the pattern is one the
/// file does not contain and the rendering does.
fn render_stl(data: &[u8]) -> Result<String> {
    match parse_ascii(data) {
        Ascii::Mesh(mesh) => Ok(render_mesh(&mesh, false)),
        Ascii::Broken(reason) => match parse_binary(data) {
            // The binary header often says "solid", so a file that opens
            // like an ASCII mesh and then breaks the grammar may still be a
            // binary one: the structure decides, not the first word.
            Some(mesh) => Ok(render_mesh(&mesh, true)),
            None => bail!("stl: {reason}"),
        },
        Ascii::NotOurs => match parse_binary(data) {
            Some(mesh) => Ok(render_mesh(&mesh, true)),
            None => decline!("stl: neither an ASCII nor a binary STL"),
        },
    }
}

/// The rendering of a mesh: the summary in front, the facets behind it.
fn render_mesh(mesh: &Mesh, binary: bool) -> String {
    let mut body = String::new();
    for (i, facet) in mesh.facets.iter().enumerate() {
        let _ = writeln!(
            body,
            "facet {}: normal {}, {}, {}",
            i + 1,
            facet.normal[0],
            facet.normal[1],
            facet.normal[2]
        );
        let _ = writeln!(
            body,
            "  vertices: {} | {} | {}",
            point(&facet.vertices[0]),
            point(&facet.vertices[1]),
            point(&facet.vertices[2])
        );
    }
    finish(&summary(mesh, binary), &body)
}

/// One vertex as the rendering prints it.
fn point(vertex: &[String; 3]) -> String {
    format!("{}, {}, {}", vertex[0], vertex[1], vertex[2])
}

/// What the file holds, in one line.
fn summary(mesh: &Mesh, binary: bool) -> String {
    let facets = mesh.facets.len();
    if binary {
        // The 80-byte header is arbitrary bytes and no name is read out of
        // it: the rendering says the file is binary rather than guess.
        return format!("stl: {facets} facets (binary STL)");
    }
    match mesh.solids.len() {
        0 => format!("stl: {facets} facets"),
        1 => format!(
            "stl: {facets} facets (solid {})",
            solid_name(&mesh.solids[0])
        ),
        k => {
            let names: Vec<&str> = mesh.solids.iter().map(|s| solid_name(s)).collect();
            format!("stl: {facets} facets ({k} solids: {})", names.join(", "))
        }
    }
}

/// The name of a solid, for a solid the file did not name.
fn solid_name(raw: &str) -> &str {
    if raw.is_empty() {
        "unnamed"
    } else {
        raw
    }
}

/// Composes a rendering: the summary in front, the facets behind it.
///
/// The summary goes first because it is the question the file answers
/// slowest, and the facets behind it because they are the question the
/// user is usually asking.
fn finish(summary: &str, body: &str) -> String {
    let mut out = String::with_capacity(body.len() + summary.len() + 64);
    let _ = writeln!(out, "{summary}");
    if body.len() <= MAX_RENDER {
        out.push_str(body);
        return out;
    }
    // Cut on a line boundary: a rendering that stops in the middle of a
    // facet is a facet that reads as if it were whole.
    let mut cut = MAX_RENDER.min(body.len());
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
// The model
// ---------------------------------------------------------------------------

/// A facet: the normal and the three vertices, each number already in the
/// form the rendering prints.
struct Facet {
    normal: [String; 3],
    vertices: [[String; 3]; 3],
}

/// What a rendering is built from: the facets, and the solids they came from.
#[derive(Default)]
struct Mesh {
    /// The name of each solid, in the order the file wrote them.
    solids: Vec<String>,
    /// Every facet of every solid, in the order the file wrote them.
    facets: Vec<Facet>,
}

// ---------------------------------------------------------------------------
// The ASCII grammar
// ---------------------------------------------------------------------------

/// What the ASCII grammar made of the file.
enum Ascii {
    /// The file is an ASCII STL.
    Mesh(Mesh),
    /// The file opens like an ASCII STL and then breaks the grammar.
    Broken(String),
    /// The file is not an ASCII STL.
    NotOurs,
}

/// Reads the ASCII form, if that is what the file is.
fn parse_ascii(data: &[u8]) -> Ascii {
    let src = String::from_utf8_lossy(data);
    let mut mesh = Mesh::default();
    match parse_ascii_grammar(src.as_ref(), &mut mesh) {
        Ok(()) => Ascii::Mesh(mesh),
        Err(reason) => {
            // A file that breaks the grammar is not necessarily a mesh: a
            // binary one breaks it too, and the binary form is read below.
            // What separates them is the file's own words.
            if claims_ascii(src.as_ref()) {
                Ascii::Broken(reason)
            } else {
                Ascii::NotOurs
            }
        }
    }
}

/// Whether the file's own words claim that it is an ASCII STL.
///
/// The claim is deliberately narrow: a file that opens with `solid` and
/// carries at least one other keyword, or a file whose every line is a
/// keyword and which carries a `facet` or an `endsolid`. A file that says
/// neither is left for the next adapter.
fn claims_ascii(src: &str) -> bool {
    let mut first = true;
    let mut opens_solid = false;
    let mut all_known = true;
    let mut saw_marker = false;
    let mut saw_other = false;
    for line in src.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let word = line.split_whitespace().next().unwrap_or("");
        let keyword = keyword(word);
        if keyword == Keyword::Other {
            all_known = false;
        }
        if first {
            opens_solid = keyword == Keyword::Solid;
            first = false;
        }
        if keyword == Keyword::Facet || keyword == Keyword::EndSolid {
            saw_marker = true;
        }
        if keyword != Keyword::Other && keyword != Keyword::Solid {
            saw_other = true;
        }
    }
    (opens_solid && saw_other) || (all_known && saw_marker)
}

/// The state the grammar is in between the lines.
#[derive(PartialEq, Eq, Clone, Copy)]
enum State {
    /// Outside any solid.
    Outside,
    /// Inside a solid, between its facets.
    InSolid,
    /// Inside a facet, before its loop.
    InFacet,
    /// Inside a facet's loop, between its vertices.
    InLoop,
}

/// The keywords the ASCII grammar knows.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Keyword {
    Solid,
    EndSolid,
    Facet,
    EndFacet,
    Outer,
    EndLoop,
    Vertex,
    /// Not a keyword of this grammar.
    Other,
}

/// The keyword a word is, whatever its case.
///
/// The keywords are case-insensitive in practice — writers differ — and a
/// reader that refused `Facet` would decline a file it could read.
fn keyword(word: &str) -> Keyword {
    if word.eq_ignore_ascii_case("solid") {
        Keyword::Solid
    } else if word.eq_ignore_ascii_case("endsolid") {
        Keyword::EndSolid
    } else if word.eq_ignore_ascii_case("facet") {
        Keyword::Facet
    } else if word.eq_ignore_ascii_case("endfacet") {
        Keyword::EndFacet
    } else if word.eq_ignore_ascii_case("outer") {
        Keyword::Outer
    } else if word.eq_ignore_ascii_case("endloop") {
        Keyword::EndLoop
    } else if word.eq_ignore_ascii_case("vertex") {
        Keyword::Vertex
    } else {
        Keyword::Other
    }
}

/// The ASCII grammar, read line by line.
///
/// The error is why the file breaks the grammar, and it is what the caller
/// reports when the file claims to be a mesh. The words are taken as they
/// come, without collecting them into a list: a binary file whose first
/// line is the whole file would otherwise be split into millions of words
/// before the first line was judged.
fn parse_ascii_grammar(src: &str, mesh: &mut Mesh) -> Result<(), String> {
    let mut state = State::Outside;
    let mut normal = [String::new(), String::new(), String::new()];
    let mut vertices: Vec<[String; 3]> = Vec::new();
    let mut has_loop = false;

    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let Some(first) = words.next() else {
            continue;
        };
        match keyword(first) {
            Keyword::Solid => {
                if state != State::Outside {
                    return Err("a solid inside a solid".into());
                }
                state = State::InSolid;
                // The name is the rest of the line, and it may be missing.
                mesh.solids.push(solid_label(words));
            }
            Keyword::EndSolid => {
                if state != State::InSolid {
                    return Err("an `endsolid` outside a solid".into());
                }
                state = State::Outside;
            }
            Keyword::Facet => {
                if state != State::InSolid {
                    return Err("a facet outside a solid".into());
                }
                // `facet normal nx ny nz`
                match words.next() {
                    Some(word) if word.eq_ignore_ascii_case("normal") => {}
                    _ => return Err("a facet with no normal".into()),
                }
                let mut numbers = [String::new(), String::new(), String::new()];
                for slot in numbers.iter_mut() {
                    match words.next() {
                        Some(token) => *slot = number(token),
                        None => return Err("a facet normal with fewer than three numbers".into()),
                    }
                }
                if words.next().is_some() {
                    return Err("a facet normal with more than three numbers".into());
                }
                normal = numbers;
                vertices.clear();
                has_loop = false;
                state = State::InFacet;
            }
            Keyword::Outer => {
                if state != State::InFacet {
                    return Err("an `outer loop` outside a facet".into());
                }
                if has_loop {
                    return Err("a facet with two loops".into());
                }
                match words.next() {
                    Some(word) if word.eq_ignore_ascii_case("loop") => {}
                    _ => return Err("an `outer` with no `loop`".into()),
                }
                vertices.clear();
                state = State::InLoop;
            }
            Keyword::Vertex => {
                if state != State::InLoop {
                    return Err("a vertex outside a loop".into());
                }
                if vertices.len() == 3 {
                    return Err("a loop with more than three vertices".into());
                }
                let mut vertex = [String::new(), String::new(), String::new()];
                for slot in vertex.iter_mut() {
                    match words.next() {
                        Some(token) => *slot = number(token),
                        None => return Err("a vertex with fewer than three numbers".into()),
                    }
                }
                if words.next().is_some() {
                    return Err("a vertex with more than three numbers".into());
                }
                vertices.push(vertex);
            }
            Keyword::EndLoop => {
                if state != State::InLoop {
                    return Err("an `endloop` outside a loop".into());
                }
                if vertices.len() != 3 {
                    return Err(format!("a loop with {} vertices, not 3", vertices.len()));
                }
                has_loop = true;
                state = State::InFacet;
            }
            Keyword::EndFacet => {
                if state == State::InLoop {
                    return Err("a loop that was never closed".into());
                }
                if state != State::InFacet {
                    return Err("an `endfacet` outside a facet".into());
                }
                if !has_loop {
                    return Err("a facet with no loop".into());
                }
                mesh.facets.push(Facet {
                    normal: normal.clone(),
                    vertices: [
                        vertices[0].clone(),
                        vertices[1].clone(),
                        vertices[2].clone(),
                    ],
                });
                state = State::InSolid;
            }
            Keyword::Other => {
                return Err(format!(
                    "the line `{line}` is not a keyword of this grammar"
                ));
            }
        }
    }

    if state != State::Outside {
        let inside = match state {
            State::InSolid => "a solid",
            State::InFacet => "a facet",
            State::InLoop => "a loop",
            State::Outside => "nothing",
        };
        return Err(format!("the file ends inside {inside}"));
    }
    if mesh.facets.is_empty() {
        return Err("the file has no facet".into());
    }
    Ok(())
}

/// The name a `solid` line carries: the rest of the line, up to the cap.
fn solid_label<'a>(words: impl Iterator<Item = &'a str>) -> String {
    let mut name = String::new();
    for word in words {
        if name.len() >= MAX_NAME {
            break;
        }
        if !name.is_empty() {
            name.push(' ');
        }
        let room = MAX_NAME - name.len();
        match word.get(..room.min(word.len())) {
            Some(part) => name.push_str(part),
            None => break,
        }
    }
    name
}

// ---------------------------------------------------------------------------
// The binary form
// ---------------------------------------------------------------------------

/// Reads the binary form, if that is what the file is.
///
/// The length is the only evidence there is: the 80-byte header is
/// arbitrary bytes and many writers put the word "solid" in it, so neither
/// the header nor the extension can decide. The count at offset 80 and the
/// length that follows it can.
fn parse_binary(data: &[u8]) -> Option<Mesh> {
    const HEADER: usize = 80;
    const COUNT: usize = 4;
    const TRIANGLE: usize = 50;

    if data.len() < HEADER + COUNT {
        return None;
    }
    let count = u32::from_le_bytes([data[80], data[81], data[82], data[83]]) as usize;
    // 84 + 50 per triangle: a count the length does not agree with is not a
    // binary mesh, and a count the arithmetic overflows is not one either.
    let expected = TRIANGLE.checked_mul(count)?.checked_add(HEADER + COUNT)?;
    if data.len() != expected {
        return None;
    }

    let mut mesh = Mesh::default();
    let mut at = HEADER + COUNT;
    for _ in 0..count {
        let triangle = &data[at..at + TRIANGLE];
        let mut normal = [String::new(), String::new(), String::new()];
        for (i, slot) in normal.iter_mut().enumerate() {
            *slot = float(f32le(&triangle[i * 4..i * 4 + 4]));
        }
        let mut vertices: [[String; 3]; 3] =
            core::array::from_fn(|_| [String::new(), String::new(), String::new()]);
        for (v, vertex) in vertices.iter_mut().enumerate() {
            for (i, slot) in vertex.iter_mut().enumerate() {
                let offset = 12 + v * 12 + i * 4;
                *slot = float(f32le(&triangle[offset..offset + 4]));
            }
        }
        // The last two bytes of the triangle are the attribute byte count,
        // which the rendering does not decode.
        mesh.facets.push(Facet { normal, vertices });
        at += TRIANGLE;
    }
    Some(mesh)
}

/// A `float32` at the front of a slice, little-endian.
fn f32le(bytes: &[u8]) -> f32 {
    f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

/// One number as the rendering prints it: the value, or the token as the
/// file wrote it when the token is not a number this reader can read.
fn number(token: &str) -> String {
    match parse_number(token) {
        Some(value) => float(value),
        None => token.to_string(),
    }
}

/// A number as the rendering prints it: always with a decimal point, so
/// that `1` reads as `1.0` and `0` as `0.0`.
fn float<T: core::fmt::Display>(value: T) -> String {
    let mut out = String::new();
    let _ = write!(out, "{value}");
    if !out.contains('.') && !out.contains("inf") && !out.contains("NaN") {
        out.push_str(".0");
    }
    out
}

/// The value of a number token, read without `std`.
///
/// `f64::from_str` lives in `std`, so the crate's own decimal parser reads
/// it: the RFC 8259 grammar, which refuses `1.` and `.5` — two shapes STL
/// writers use — and which is normalised here first. A token that still
/// will not parse is printed as the file wrote it, because a value the file
/// wrote is a value the file wrote.
fn parse_number(token: &str) -> Option<f64> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    // A leading '+' is not in the JSON number grammar.
    let body = token.strip_prefix('+').unwrap_or(token);
    let (sign, digits) = match body.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", body),
    };
    let mut normalised = String::with_capacity(body.len() + 2);
    normalised.push_str(sign);
    if digits.starts_with('.') {
        normalised.push('0');
    }
    normalised.push_str(digits);
    if normalised.ends_with('.') {
        normalised.push('0');
    }
    rgx_core::parse_decimal(&normalised).ok()
}

#[cfg(test)]
mod tests {
    //! The fixture is a file and not a string inside the test, so the
    //! end-to-end run reads the same bytes the unit tests read: a fixture
    //! that only exists in a test is a fixture the binary was never shown.
    //!
    //! The first test is the one that matters: it asserts that the file
    //! itself does **not** contain what the rendering contains, because a
    //! rendering that only re-orders what `rg` already sees would be a
    //! rendering for nothing.

    use super::*;
    use alloc::vec::Vec;

    const STL: &[u8] = include_bytes!("../testdata/sample.stl");

    /// The pattern the file cannot hold: the three vertices of a facet are
    /// three lines in the file and one line in the rendering.
    const JOINED: &str = "10.0, 0.0, 0.0 | 0.0, 10.0, 0.0";

    #[test]
    fn a_facets_vertices_are_joined_onto_one_line() {
        let text = String::from_utf8_lossy(STL);
        // The file holds the three vertices on three lines, so the pattern
        // is not in it. This is the assertion that gives the rendering a job.
        assert!(
            !text.contains(JOINED),
            "the fixture is supposed to hold the vertices on three lines"
        );
        let out = render_stl(STL).expect("an stl is ours");
        assert!(
            out.contains(JOINED),
            "the rendering has to carry the joined vertices:\n{out}"
        );
    }

    #[test]
    fn a_stl_says_how_many_facets_it_has_and_which_solid() {
        let out = render_stl(STL).expect("an stl is ours");
        assert!(out.contains("stl: 2 facets (solid caixa)"), "{out}");
        assert!(out.contains("facet 1: normal 0.0, 0.0, 1.0"), "{out}");
        assert!(out.contains("facet 2: normal 0.0, 0.0, 1.0"), "{out}");
        assert!(
            out.contains("vertices: 0.0, 0.0, 0.0 | 10.0, 0.0, 0.0 | 0.0, 10.0, 0.0"),
            "{out}"
        );
    }

    #[test]
    fn a_file_that_is_not_an_stl_is_declined() {
        let err = render_stl(b"a note about meshes, not a mesh\n").expect_err("not an stl");
        assert!(err.is_decline(), "{err}");
    }

    #[test]
    fn a_truncated_stl_is_a_failure_and_not_a_decline() {
        // The file is cut in the middle of a facet: the loop never closes.
        let mut broken = Vec::new();
        broken.extend_from_slice(b"solid caixa\r\n");
        broken.extend_from_slice(b"  facet normal 0.0 0.0 1.0\r\n");
        broken.extend_from_slice(b"    outer loop\r\n");
        broken.extend_from_slice(b"      vertex 0.0 0.0 0.0\r\n");
        broken.extend_from_slice(b"      vertex 10.0 0.0 0.0\r\n");
        let err = render_stl(&broken).expect_err("a truncated stl is not ours");
        assert!(!err.is_decline(), "{err}");
    }

    #[test]
    fn a_binary_stl_is_read() {
        let bytes = binary_stl();
        let out = render_stl(&bytes).expect("a binary stl is ours");
        assert!(out.contains("stl: 2 facets (binary STL)"), "{out}");
        assert!(out.contains("facet 1: normal 0.0, 0.0, 1.0"), "{out}");
        assert!(
            out.contains("vertices: 0.0, 0.0, 0.0 | 10.0, 0.0, 0.0 | 0.0, 10.0, 0.0"),
            "{out}"
        );
    }

    /// A binary STL: the header, the count, and two triangles.
    fn binary_stl() -> Vec<u8> {
        let mut out = Vec::new();
        let mut header = [0u8; 80];
        header[..12].copy_from_slice(b"solid binary");
        out.extend_from_slice(&header);
        out.extend_from_slice(&2u32.to_le_bytes());
        triangle(
            &mut out,
            [0.0, 0.0, 1.0],
            [[0.0, 0.0, 0.0], [10.0, 0.0, 0.0], [0.0, 10.0, 0.0]],
        );
        triangle(
            &mut out,
            [0.0, 0.0, 1.0],
            [[10.0, 0.0, 0.0], [10.0, 10.0, 0.0], [0.0, 10.0, 0.0]],
        );
        out
    }

    /// One triangle: the normal, the three vertices, the attribute count.
    fn triangle(out: &mut Vec<u8>, normal: [f32; 3], vertices: [[f32; 3]; 3]) {
        for value in normal.iter().chain(vertices.iter().flatten()) {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
    }
}
