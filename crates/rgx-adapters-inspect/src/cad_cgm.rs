// SPDX-License-Identifier: Apache-2.0

//! The **CGM** (Computer Graphics Metafile) rendering.
//!
//! **What a CGM is.** A picture written as a stream of *elements*. Each
//! element opens with a 16-bit header — a class, an id, and the length of
//! its parameter list — and the parameters themselves are binary:
//! coordinates, colours, flags, and text. It is the format ISO 8509-3
//! wrote and ISO 8632-3 revised, and it is what WebCGM serves.
//!
//! **Why it is revealed and not rendered.** `rg` cannot read a CGM at
//! all: the bytes are not text, so a search for a coordinate in a
//! drawing finds nothing, because there is nothing to find — a polyline's
//! first point is two bytes in the middle of a parameter list. It is
//! therefore [`Reach::Reveal`], the reach every binary format this crate
//! reads declares: under the default policy the rendering is what rgx
//! searches, and every byte it surfaces is a byte ripgrep could never
//! reach.
//!
//! **What the rendering is for.** The geometry. "A polyline through
//! (100,100) and (200,200)" is not in the file — the file holds
//! `00 64 00 64 00 c8 00 c8` and nothing that says *polyline* — and it is
//! the pattern a user writes. The rendering gives every element a line of
//! its own, in the order the file wrote them, and gives the primitives
//! their geometry.
//!
//! **What it does not do.** It does not draw the picture, and it does not
//! decode the attributes: a line colour, a font list and an application
//! structure are named, not read. It does not guess either. An element
//! this reader cannot place is reported by its class and its id; a
//! parameter list that does not decode into the geometry the standard
//! describes is reported by the element's name alone; and a file that
//! does not open with a BEGIN METAFILE element is declined, so the next
//! adapter gets its turn.
//!
//! **The three rules the reading rests on.** They were settled against
//! the 353 files of the W3C/OASIS WebCGM test suite, and every one of
//! them holds in every one of those files:
//!
//! - *The walk.* A 16-bit header, most significant byte first: the class
//!   is the top four bits, the id the next seven, and the low five bits
//!   the length of the parameter list in bytes. A length of 31 means the
//!   long form, where the parameter list is a run of chunks, each with
//!   its own 16-bit length word whose bit 15 says that another chunk
//!   follows. **Every parameter list is padded to a word boundary** — a
//!   short list by one byte, a chunk by one byte — so the next header
//!   always starts on an even offset. Get that wrong and every element
//!   after the first odd one is read at the wrong offset.
//! - *The point list.* A polyline, a disjoint polyline, a polymarker
//!   and a polygon are a run of points and nothing else, so the number
//!   of points is the length of the parameter list over twice the size
//!   of a coordinate. A polygon set is a run of *edges*, each a point
//!   and a 16-bit flag saying whether the edge is drawn, so its stride
//!   is two bytes longer. Nothing in the list is left over: in all 353
//!   files the length divides exactly.
//! - *The string.* A CGM string is a count and then that many bytes,
//!   and the count is in front of the text: the text of a text element
//!   is the tail of its parameter list, and the byte in front of it says
//!   how long the text is. The name of a metafile and its description
//!   are the same shape, except that their count is in *characters*, so
//!   a file that announces the two-byte character set has twice as many
//!   bytes as it has characters.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{bail, decline, Adapter, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost. A 64 MiB ceiling is far
/// above any metafile whose whole content is worth a second copy, and the
/// rendering says so when it bites rather than stopping in silence.
const MAX_RENDER: usize = 64 << 20;

/// A Computer Graphics Metafile, as a rendering.
pub struct Cgm;

impl Adapter for Cgm {
    fn name(&self) -> &'static str {
        "cgm"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["cgm"]
    }

    /// The file is binary: ripgrep cannot read it, so the rendering is
    /// bytes ripgrep could not reach.
    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_cgm(data)?.into_bytes()))
    }
}

// ---------------------------------------------------------------------------
// The rendering
// ---------------------------------------------------------------------------

/// The CGM rendering: one line per element, in the order the file wrote
/// them.
///
/// The walk is the whole of the format's framing: a 16-bit header, then a
/// parameter list, then a pad byte when the list is odd, and the next
/// header starts on an even offset. Getting that padding rule wrong is
/// not a small mistake — every element after the first odd one is read at
/// the wrong offset, and the walk never lands on the end of the file.
fn render_cgm(data: &[u8]) -> Result<String> {
    if data.len() < 2 {
        decline!("cgm: the file is too short to hold a metafile");
    }

    let mut body = String::new();
    let mut params: Vec<u8> = Vec::new();
    let mut state = State::default();
    let mut pos = 0usize;
    let mut first = true;

    while pos + 2 <= data.len() {
        let word = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let class = ((word >> 12) & 0x0F) as u8;
        let id = ((word >> 5) & 0x7F) as u8;
        let len = (word & 0x1F) as usize;

        params.clear();
        if len == 31 {
            // The long form: the parameter list is a run of chunks, each
            // with its own 16-bit length word whose bit 15 says whether
            // another chunk follows.
            loop {
                if pos + 2 > data.len() {
                    bail!("cgm: the file ends inside a long-form element");
                }
                let chunk = u16::from_be_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                let n = (chunk & 0x7FFF) as usize;
                if pos + n > data.len() {
                    bail!("cgm: the file ends inside a long-form element's parameter list");
                }
                params.extend_from_slice(&data[pos..pos + n]);
                pos += n;
                // Every chunk is padded to a word boundary.
                if n % 2 == 1 {
                    pos += 1;
                }
                if chunk & 0x8000 == 0 {
                    break;
                }
            }
        } else {
            if pos + len > data.len() {
                bail!("cgm: the file ends inside an element's parameter list");
            }
            params.extend_from_slice(&data[pos..pos + len]);
            pos += len;
            // The parameter list of every element is padded to a word
            // boundary, so the next header always starts on an even
            // offset.
            if len % 2 == 1 {
                pos += 1;
            }
        }

        if first {
            // A metafile opens with BEGIN METAFILE, and nothing else does:
            // a file that opens with anything else is some other format,
            // and declining it is what lets the next adapter have it.
            if class != 0 || id != 1 {
                decline!("cgm: the file does not open with a BEGIN METAFILE element");
            }
            first = false;
        }

        render_element(&mut body, &mut state, class, id, &params);
    }

    if pos != data.len() {
        bail!(
            "cgm: the file ends with {} bytes that are not an element",
            data.len() - pos
        );
    }

    Ok(finish(&body))
}

/// Composes the rendering, and holds it to the ceiling.
///
/// The cut is on a line boundary: a rendering that stops in the middle of
/// a record is a record that reads as if it were whole.
fn finish(body: &str) -> String {
    if body.len() <= MAX_RENDER {
        return body.to_string();
    }
    let bytes = body.as_bytes();
    let mut cut = MAX_RENDER.min(bytes.len());
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    let cut = body[..cut].rfind('\n').map(|i| i + 1).unwrap_or(cut);
    let mut out = String::with_capacity(cut + 128);
    out.push_str(&body[..cut]);
    let _ = writeln!(
        out,
        "note: the rendering stopped at the {MAX_RENDER}-byte ceiling; the rest of the file is not shown"
    );
    out
}

// ---------------------------------------------------------------------------
// One element
// ---------------------------------------------------------------------------

/// What the file's descriptor elements have said so far.
struct State {
    /// The metafile version, when the METAFILE VERSION element said it.
    version: Option<u32>,
    /// Whether the coordinates are integers or reals.
    vdc_real: bool,
    /// The number of bytes one integer coordinate takes.
    int_bytes: usize,
    /// The real format, when the REAL PRECISION element said it.
    real: Option<Coord>,
}

impl Default for State {
    fn default() -> Self {
        State {
            version: None,
            vdc_real: false,
            // A file that says nothing about the integer precision uses
            // two bytes a coordinate.
            int_bytes: 2,
            real: None,
        }
    }
}

impl State {
    /// How a coordinate is written, as the file has said so far.
    fn coord(&self) -> Coord {
        if self.vdc_real {
            // A file that names reals and never says how wide they are
            // gets the 32-bit floating-point format, which is what the
            // corpus describes.
            self.real.unwrap_or(Coord::Ieee { bytes: 4 })
        } else {
            Coord::Int {
                bytes: self.int_bytes,
            }
        }
    }
}

/// Writes the line for one element, and takes note of what it says.
fn render_element(out: &mut String, state: &mut State, class: u8, id: u8, params: &[u8]) {
    match (class, id) {
        (0, 1) => {
            let _ = writeln!(out, "metafile: {}", metafile_name(params));
        }
        (1, 1) => {
            // The METAFILE VERSION element: the version number, and the
            // flags that follow it.
            let Some(version) = be_int(params) else {
                let _ = writeln!(out, "element: METAFILE VERSION");
                return;
            };
            state.version = Some(version as u32);
            let _ = writeln!(out, "version: {version}");
        }
        (1, 2) => {
            let _ = writeln!(out, "description: {}", description(params));
        }
        (1, 3) => {
            // The VDC TYPE element: 0 says the coordinates are integers,
            // 1 says they are reals.
            if let Some(vdc) = be_int(params) {
                state.vdc_real = vdc != 0;
            }
            let _ = writeln!(out, "element: VDC TYPE");
        }
        (1, 4) => {
            // The INTEGER PRECISION element.
            if let Some(value) = be_int(params) {
                if let Some(bytes) = int_bytes(value as u32) {
                    state.int_bytes = bytes;
                }
            }
            let _ = writeln!(out, "element: INTEGER PRECISION");
        }
        (1, 5) => {
            // The REAL PRECISION element.
            if let Some(coord) = real_format(params) {
                state.real = Some(coord);
            }
            let _ = writeln!(out, "element: REAL PRECISION");
        }
        (3, 5) => {
            // The CLIP RECTANGLE: two corners.
            let coord = state.coord();
            let Some(corners) = points(params, 0, 2, &coord) else {
                let _ = writeln!(out, "element: CLIP RECTANGLE");
                return;
            };
            let _ = write!(out, "clip rectangle:");
            for corner in &corners {
                let _ = write!(out, " ({},{})", corner.0, corner.1);
            }
            let _ = writeln!(out);
        }
        (4, 1) | (4, 2) | (4, 3) | (4, 7) => {
            // The point lists: POLYLINE, DISJOINT POLYLINE, POLYMARKER and
            // POLYGON are a run of points and nothing else.
            let name = match id {
                1 => "polyline",
                2 => "disjoint polyline",
                3 => "polymarker",
                _ => "polygon",
            };
            render_point_list(out, state, name, params, 0, 0);
        }
        (4, 8) => {
            // The POLYGON SET: a run of edges, each a point and a flag
            // saying whether the edge is drawn. The flag is not shown.
            render_point_list(out, state, "polygon set", params, 0, 2);
        }
        (4, 12) => {
            // The CIRCLE: a centre and a radius.
            let coord = state.coord();
            let Some(values) = values(params, 0, 3, &coord) else {
                let _ = writeln!(out, "element: CIRCLE");
                return;
            };
            let _ = writeln!(
                out,
                "circle: centre ({},{}) radius {}",
                values[0], values[1], values[2]
            );
        }
        (4, 4) => {
            // The TEXT: a position and the string.
            let coord = state.coord();
            let Some(text) = tail_text(params, 2 * coord.size()) else {
                let _ = writeln!(out, "element: TEXT (the string was not read)");
                return;
            };
            let position = values(params, 0, 2, &coord);
            match position {
                Some(p) => {
                    let _ = writeln!(out, "text: {text} at ({},{})", p[0], p[1]);
                }
                None => {
                    let _ = writeln!(out, "text: {text}");
                }
            }
        }
        (4, 5) => {
            // The RESTRICTED TEXT: a width and a height, a position and
            // the string.
            let coord = state.coord();
            let Some(text) = tail_text(params, 4 * coord.size()) else {
                let _ = writeln!(out, "element: RESTRICTED TEXT (the string was not read)");
                return;
            };
            let position = values(params, 2 * coord.size(), 2, &coord);
            match position {
                Some(p) => {
                    let _ = writeln!(out, "restricted text: {text} at ({},{})", p[0], p[1]);
                }
                None => {
                    let _ = writeln!(out, "restricted text: {text}");
                }
            }
        }
        (4, 6) => {
            // The APPEND TEXT: the string, and nothing else.
            let Some(text) = tail_text(params, 0) else {
                let _ = writeln!(out, "element: APPEND TEXT (the string was not read)");
                return;
            };
            let _ = writeln!(out, "append text: {text}");
        }
        (6, _) => {
            // The escape element's id is the escape code, which is what
            // the standard puts in it: 0 is a no-op and the rest say
            // what the escape does.
            let _ = writeln!(out, "element: ESCAPE {id}");
        }
        _ => match element_name(class, id, state.version) {
            Some(name) => {
                let _ = writeln!(out, "element: {name}");
            }
            None => {
                // The classes 10 to 15 are reserved: the element is
                // unknown, but its length is known, so the walk goes on.
                let _ = writeln!(out, "element: class {class} id {id}");
            }
        },
    }
}

/// Writes a point list: the points, and the bytes that did not make one.
///
/// `trailing` is the number of bytes each entry carries beyond its
/// coordinates — the POLYGON SET's edge flag, which this reader does not
/// show.
fn render_point_list(
    out: &mut String,
    state: &State,
    name: &str,
    params: &[u8],
    offset: usize,
    trailing: usize,
) {
    let coord = state.coord();
    let stride = 2 * coord.size() + trailing;
    if stride == 0 {
        let _ = writeln!(out, "element: {name}");
        return;
    }
    let count = params.len().saturating_sub(offset) / stride;
    if count == 0 {
        let _ = writeln!(out, "element: {name}");
        return;
    }
    let _ = write!(out, "{name}:");
    let mut at = offset;
    for _ in 0..count {
        let Some(x) = coord.read(&params[at..]) else {
            break;
        };
        let Some(y) = coord.read(&params[at + coord.size()..]) else {
            break;
        };
        let _ = write!(out, " ({},{})", x, y);
        at += stride;
    }
    let left = params.len() - at;
    if left > 0 {
        let _ = write!(out, " [{left} bytes not read]");
    }
    let _ = writeln!(out);
}

// ---------------------------------------------------------------------------
// The numbers
// ---------------------------------------------------------------------------

/// How one coordinate is written.
#[derive(Clone, Copy)]
enum Coord {
    /// A signed big-endian integer.
    Int { bytes: usize },
    /// An IEEE 754 floating-point real: a binary32 or a binary64.
    Ieee { bytes: usize },
    /// A fixed-point real, scaled by two to the power of minus `frac`.
    Fixed { bytes: usize, frac: u32 },
    /// ISO 8509-3's own real: a sign bit, an exponent and a mantissa.
    Exp {
        bytes: usize,
        exp_bits: u32,
        mant_bits: u32,
        bias: i32,
    },
}

impl Coord {
    /// The number of bytes one coordinate takes.
    fn size(&self) -> usize {
        match *self {
            Coord::Int { bytes } | Coord::Ieee { bytes } | Coord::Fixed { bytes, .. } => bytes,
            Coord::Exp { bytes, .. } => bytes,
        }
    }

    /// Reads one coordinate, or `None` when the bytes are not there.
    fn read(&self, data: &[u8]) -> Option<Number> {
        match *self {
            Coord::Int { bytes } => read_int(data, bytes).map(Number::Int),
            Coord::Ieee { bytes } => match bytes {
                4 => Some(Number::Real(f64::from(f32::from_bits(u32::from_be_bytes(
                    four(data)?,
                ))))),
                8 => Some(Number::Real(f64::from_bits(u64::from_be_bytes(eight(
                    data,
                )?)))),
                _ => None,
            },
            Coord::Fixed { bytes, frac } => {
                read_int(data, bytes).map(|v| Number::Real(v as f64 / (1u64 << frac) as f64))
            }
            Coord::Exp {
                bytes,
                exp_bits,
                mant_bits,
                bias,
            } => read_exp(data, bytes, exp_bits, mant_bits, bias),
        }
    }
}

/// A coordinate, as the rendering prints it.
enum Number {
    /// An integer coordinate.
    Int(i64),
    /// A real coordinate.
    Real(f64),
}

impl core::fmt::Display for Number {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Number::Int(v) => write!(f, "{v}"),
            Number::Real(v) => write!(f, "{}", real(*v)),
        }
    }
}

/// A real, as a drawing writes one: with a decimal point.
///
/// A real reads the same whether the writer wrote `100` or `100.0`, and
/// the rendering does not leave the reader to guess which it was.
fn real(value: f64) -> String {
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

/// Reads a signed big-endian integer of `bytes` bytes.
fn read_int(data: &[u8], bytes: usize) -> Option<i64> {
    if bytes == 0 || bytes > 8 || data.len() < bytes {
        return None;
    }
    let mut value: i64 = 0;
    for &byte in &data[..bytes] {
        value = (value << 8) | i64::from(byte);
    }
    let bits = 8 * bytes as u32;
    if bits < 64 {
        let sign = 1i64 << (bits - 1);
        if value & sign != 0 {
            value -= 1i64 << bits;
        }
    }
    Some(value)
}

/// Reads a big-endian unsigned integer over the whole parameter list.
///
/// The descriptor elements hold their value in one or two bytes, and the
/// padding to a word boundary means the width of the payload is the width
/// of the value: `00 ff` is 255 and `ff` is 255.
fn be_int(params: &[u8]) -> Option<i64> {
    if params.is_empty() || params.len() > 8 {
        return None;
    }
    let mut value: i64 = 0;
    for &byte in params {
        value = (value << 8) | i64::from(byte);
    }
    Some(value)
}

/// Reads a big-endian unsigned 16-bit integer at `offset`.
fn be_u16(params: &[u8], offset: usize) -> Option<u16> {
    if params.len() < offset + 2 {
        return None;
    }
    Some(u16::from_be_bytes([params[offset], params[offset + 1]]))
}

/// The first four bytes, as a big-endian `u32`.
fn four(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() < 4 {
        return None;
    }
    Some([data[0], data[1], data[2], data[3]])
}

/// The first eight bytes, as a big-endian `u64`.
fn eight(data: &[u8]) -> Option<[u8; 8]> {
    if data.len() < 8 {
        return None;
    }
    Some([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

/// Reads a real in ISO 8509-3's own layout: a sign bit, an exponent and a
/// mantissa.
fn read_exp(data: &[u8], bytes: usize, exp_bits: u32, mant_bits: u32, bias: i32) -> Option<Number> {
    if data.len() < bytes || bytes == 0 || bytes > 8 {
        return None;
    }
    let mut bits: u64 = 0;
    for &byte in &data[..bytes] {
        bits = (bits << 8) | u64::from(byte);
    }
    let total = 8 * bytes as u32;
    let sign = if total < 64 && bits >> (total - 1) & 1 == 1 {
        -1.0
    } else {
        1.0
    };
    let exp_mask = (1u64 << exp_bits) - 1;
    let mant_mask = (1u64 << mant_bits) - 1;
    let exponent = ((bits >> mant_bits) & exp_mask) as i32;
    let mantissa = (bits & mant_mask) as f64 / (1u64 << mant_bits) as f64;
    if exponent == 0 {
        return Some(Number::Real(0.0));
    }
    let scale = 2f64.powi(exponent - bias);
    Some(Number::Real(sign * (1.0 + mantissa) * scale))
}

/// The number of bytes one integer coordinate takes.
///
/// The element carries the precision in *bits* in every file of the
/// corpus — sixteen, that is, two bytes — so a value of 8, 16 or 32 is
/// read as bits. A writer that puts the byte count there instead is read
/// as bytes, which makes 1, 2 and 4 mean one, two and four bytes.
fn int_bytes(value: u32) -> Option<usize> {
    match value {
        8 | 1 => Some(1),
        16 | 2 => Some(2),
        32 | 4 => Some(4),
        _ => None,
    }
}

/// The real format, from the REAL PRECISION element.
///
/// The element holds three numbers. Read as (form, bits, bits) they say
/// what kind of real it is and how wide its two parts are: form 0 is a
/// floating-point real — nine and twenty-three bits make the 32-bit
/// IEEE 754 binary32 — and form 1 is a fixed-point real. Read as
/// (exponent size, mantissa size, bias) they are ISO 8509-3's own layout,
/// which the files that use it announce.
fn real_format(params: &[u8]) -> Option<Coord> {
    let form = be_u16(params, 0)? as u32;
    let first = be_u16(params, 2)? as u32;
    let second = be_u16(params, 4)? as u32;

    // (form, bits, bits)
    if form <= 1 && first >= 2 && second >= 1 {
        let total = first + second;
        if total == 32 || total == 64 {
            return Some(match form {
                0 => Coord::Ieee { bytes: 4 },
                _ => Coord::Fixed {
                    bytes: 4,
                    frac: second,
                },
            });
        }
        if total == 16 {
            return Some(match form {
                0 => Coord::Ieee { bytes: 2 },
                _ => Coord::Fixed {
                    bytes: 2,
                    frac: second,
                },
            });
        }
    }

    // (exponent size, mantissa size, bias)
    let total = 1 + first + second;
    if first >= 1 && second >= 1 && (total == 16 || total == 32 || total == 64) {
        return Some(Coord::Exp {
            bytes: (total / 8) as usize,
            exp_bits: first,
            mant_bits: second,
            bias: form as i32,
        });
    }
    None
}

/// Reads `count` coordinates at `offset`, as pairs.
fn points(
    params: &[u8],
    offset: usize,
    count: usize,
    coord: &Coord,
) -> Option<Vec<(Number, Number)>> {
    let size = coord.size();
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = offset + i * 2 * size;
        let x = coord.read(params.get(at..)?)?;
        let y = coord.read(params.get(at + size..)?)?;
        out.push((x, y));
    }
    Some(out)
}

/// Reads `count` coordinates at `offset`.
fn values(params: &[u8], offset: usize, count: usize, coord: &Coord) -> Option<Vec<Number>> {
    let size = coord.size();
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = offset + i * size;
        out.push(coord.read(params.get(at..)?)?);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The strings
// ---------------------------------------------------------------------------

/// The metafile's name, from the BEGIN METAFILE element.
///
/// The parameter list is a count of characters and then the characters.
/// The count is in characters, so a file that announces the 2-byte
/// character set has twice as many bytes as it has characters.
fn metafile_name(params: &[u8]) -> String {
    let Some(&count) = params.first() else {
        return String::new();
    };
    let body = &params[1..];
    let count = count as usize;
    if body.len() == 2 * count {
        return decode_ucs2(body);
    }
    trim_tail(&decode_g0(body))
}

/// The metafile's description, from the METAFILE DESCRIPTION element.
///
/// The description is a string in the same shape as the name, and the
/// WebCGM profile writes it as quoted fields — `"ProfileId:WebCGM"` — so
/// the quotes around the whole are dropped: they are punctuation the
/// profile put there, and keeping them would make the field harder to
/// match than the field itself.
fn description(params: &[u8]) -> String {
    let Some(&count) = params.first() else {
        return String::new();
    };
    let body = &params[1..];
    let count = count as usize;
    let text = if body.len() == 2 * count {
        decode_ucs2(body)
    } else {
        trim_tail(&decode_g0(body))
    };
    let quoted = text.len() >= 2 && text.starts_with('"') && text.ends_with('"');
    if quoted {
        text[1..text.len() - 1].to_string()
    } else {
        text
    }
}

/// The text at the end of a parameter list.
///
/// A CGM string is a count followed by that many characters, so the byte
/// in front of the text says how long the text is. The count is looked
/// for from `from` onwards, because the parameters in front of it differ
/// from element to element: a text element carries a position before the
/// string, and a restricted text carries a width and a height as well.
fn tail_text(params: &[u8], from: usize) -> Option<String> {
    // The short form: the count is the byte in front of the text.
    for p in from..params.len() {
        let n = params[p] as usize;
        if n == params.len() - p - 1 && is_text(&params[p + 1..]) {
            return Some(decode_g0(&params[p + 1..]));
        }
    }
    // The long form: the count is 255 and the real count follows in
    // 16-bit partitions, each with bit 15 saying that another one
    // follows.
    for p in from..params.len() {
        if params[p] != 255 {
            continue;
        }
        let mut total = 0usize;
        let mut q = p + 1;
        loop {
            let word = be_u16(params, q)?;
            total += (word & 0x7FFF) as usize;
            q += 2;
            if word & 0x8000 == 0 {
                break;
            }
        }
        let end = q + total;
        if end <= params.len() && is_text(&params[q..end]) {
            return Some(decode_g0(&params[q..end]));
        }
    }
    None
}

/// Whether these bytes can be text.
///
/// A control character other than the three that appear in text is not
/// text, and a count that would claim otherwise is a count this reader
/// does not believe.
fn is_text(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E | 0x80..=0xFF))
}

/// The G0 character set, as text.
///
/// The characters of a CGM are usually ASCII, but the WebCGM profile
/// writes them in UTF-8, so a byte string that is valid UTF-8 is decoded
/// as UTF-8. A string that is not — the 8-bit ISO 8859-1 set the
/// character coding announcer names — is decoded as Latin-1, one byte to
/// one character, which is what the standard's own set means.
fn decode_g0(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|byte| *byte as char).collect(),
    }
}

/// The 2-byte character set, as text.
fn decode_ucs2(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let unit = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        i += 2;
        match char::from_u32(u32::from(unit)) {
            Some(c) => out.push(c),
            None => out.push('\u{fffd}'),
        }
    }
    out
}

/// Drops the padding a writer put at the end of a name.
fn trim_tail(text: &str) -> String {
    text.trim_end_matches([' ', '\0']).to_string()
}

// ---------------------------------------------------------------------------
// The element table
// ---------------------------------------------------------------------------

/// The name of an element, when the standard names it.
///
/// The class-2 numbering depends on the metafile version: ISO 8509-3
/// (version 1) and ISO 8632-3 (version 2 and later) number the picture
/// descriptor elements differently, so the version the METAFILE VERSION
/// element announced decides which table applies. A file whose version is
/// unknown gets numbers rather than a name it cannot be sure of.
fn element_name(class: u8, id: u8, version: Option<u32>) -> Option<&'static str> {
    match class {
        0 => match id {
            1 => Some("BEGIN METAFILE"),
            2 => Some("END METAFILE"),
            3 => Some("BEGIN PICTURE"),
            4 => Some("BEGIN PICTURE BODY"),
            5 => Some("END PICTURE"),
            6 => Some("BEGIN SEGMENT"),
            7 => Some("END SEGMENT"),
            8 => Some("BEGIN FIGURE"),
            9 => Some("END FIGURE"),
            13 => Some("BEGIN PROTECTION REGION"),
            14 => Some("END PROTECTION REGION"),
            15 => Some("BEGIN COMPOUND LINE"),
            16 => Some("END COMPOUND LINE"),
            17 => Some("BEGIN COMPOUND TEXT PATH"),
            18 => Some("END COMPOUND TEXT PATH"),
            19 => Some("BEGIN TILE ARRAY"),
            20 => Some("END TILE ARRAY"),
            21 => Some("BEGIN APPLICATION STRUCTURE"),
            22 => Some("BEGIN APPLICATION STRUCTURE BODY"),
            23 => Some("END APPLICATION STRUCTURE"),
            _ => None,
        },
        1 => match id {
            1 => Some("METAFILE VERSION"),
            2 => Some("METAFILE DESCRIPTION"),
            3 => Some("VDC TYPE"),
            4 => Some("INTEGER PRECISION"),
            5 => Some("REAL PRECISION"),
            6 => Some("INDEX PRECISION"),
            7 => Some("COLOUR PRECISION"),
            8 => Some("COLOUR INDEX PRECISION"),
            9 => Some("MAXIMUM COLOUR INDEX"),
            10 => Some("COLOUR VALUE EXTENT"),
            11 => Some("METAFILE ELEMENT LIST"),
            12 => Some("METAFILE DEFAULTS REPLACEMENT"),
            13 => Some("FONT LIST"),
            14 => Some("CHARACTER SET LIST"),
            15 => Some("CHARACTER CODING ANNOUNCER"),
            16 => Some("NAME PRECISION"),
            17 => Some("MAXIMUM VDC EXTENT"),
            18 => Some("SEGMENT PRIORITY EXTENT"),
            19 => Some("COLOUR MODEL"),
            20 => Some("COLOUR CALIBRATION"),
            21 => Some("FONT PROPERTIES"),
            22 => Some("GLYPH MAPPING"),
            23 => Some("SYMBOL LIBRARY LIST"),
            _ => None,
        },
        2 => picture_name(id, version),
        3 => match id {
            1 => Some("VDC INTEGER PRECISION"),
            2 => Some("VDC REAL PRECISION"),
            3 => Some("AUXILIARY COLOUR"),
            4 => Some("TRANSPARENCY"),
            5 => Some("CLIP RECTANGLE"),
            6 => Some("CLIP INDICATOR"),
            7 => Some("LINE CLIPPING MODE"),
            8 => Some("MARKER CLIPPING MODE"),
            9 => Some("EDGE CLIPPING MODE"),
            10 => Some("NEW REGION"),
            11 => Some("SAVE PRIMITIVE CONTEXT"),
            12 => Some("RESTORE PRIMITIVE CONTEXT"),
            17 => Some("PROTECTION REGION INDICATOR"),
            18 => Some("GENERALIZED TEXT PATH MODE"),
            19 => Some("MITRE LIMIT"),
            20 => Some("TRANSPARENT CELL COLOUR"),
            _ => None,
        },
        4 => match id {
            1 => Some("POLYLINE"),
            2 => Some("DISJOINT POLYLINE"),
            3 => Some("POLYMARKER"),
            4 => Some("TEXT"),
            5 => Some("RESTRICTED TEXT"),
            6 => Some("APPEND TEXT"),
            7 => Some("POLYGON"),
            8 => Some("POLYGON SET"),
            9 => Some("CELL ARRAY"),
            10 => Some("GENERALIZED DRAWING PRIMITIVE"),
            11 => Some("RECTANGLE"),
            12 => Some("CIRCLE"),
            13 => Some("CIRCULAR ARC 3 POINT"),
            14 => Some("CIRCULAR ARC 3 POINT CLOSE"),
            15 => Some("CIRCULAR ARC CENTRE"),
            16 => Some("CIRCULAR ARC CENTRE CLOSE"),
            17 => Some("ELLIPSE"),
            18 => Some("ELLIPTICAL ARC"),
            19 => Some("ELLIPTICAL ARC CLOSE"),
            20 => Some("CIRCULAR ARC CENTRE REVERSED"),
            21 => Some("CONNECTING EDGE"),
            22 => Some("HYPERBOLIC ARC"),
            23 => Some("PARABOLIC ARC"),
            24 => Some("NON-UNIFORM B-SPLINE"),
            25 => Some("NON-UNIFORM RATIONAL B-SPLINE"),
            26 => Some("POLYBEZIER"),
            27 => Some("POLYSYMBOL"),
            28 => Some("BITONAL TILE"),
            29 => Some("TILE"),
            _ => None,
        },
        5 => match id {
            1 => Some("LINE BUNDLE INDEX"),
            2 => Some("LINE TYPE"),
            3 => Some("LINE WIDTH"),
            4 => Some("LINE COLOUR"),
            5 => Some("MARKER BUNDLE INDEX"),
            6 => Some("MARKER TYPE"),
            7 => Some("MARKER SIZE"),
            8 => Some("MARKER COLOUR"),
            9 => Some("TEXT BUNDLE INDEX"),
            10 => Some("TEXT FONT INDEX"),
            11 => Some("TEXT PRECISION"),
            12 => Some("CHARACTER EXPANSION FACTOR"),
            13 => Some("CHARACTER SPACING"),
            14 => Some("TEXT COLOUR"),
            15 => Some("CHARACTER HEIGHT"),
            16 => Some("CHARACTER ORIENTATION"),
            17 => Some("TEXT PATH"),
            18 => Some("TEXT ALIGNMENT"),
            19 => Some("CHARACTER SET INDEX"),
            20 => Some("ALTERNATE CHARACTER SET INDEX"),
            21 => Some("INTERIOR STYLE"),
            22 => Some("FILL COLOUR"),
            23 => Some("HATCH INDEX"),
            24 => Some("PATTERN INDEX"),
            25 => Some("FILL BUNDLE INDEX"),
            26 => Some("EDGE BUNDLE INDEX"),
            27 => Some("EDGE TYPE"),
            28 => Some("EDGE WIDTH"),
            29 => Some("EDGE COLOUR"),
            30 => Some("EDGE VISIBILITY"),
            31 => Some("FILL REFERENCE POINT"),
            32 => Some("PATTERN TABLE"),
            33 => Some("PATTERN SIZE"),
            37 => Some("LINE CAP"),
            38 => Some("LINE JOIN"),
            39 => Some("LINE TYPE CONTINUATION"),
            40 => Some("LINE TYPE INITIAL OFFSET"),
            44 => Some("EDGE CAP"),
            45 => Some("EDGE JOIN"),
            46 => Some("EDGE TYPE CONTINUATION"),
            47 => Some("EDGE TYPE INITIAL OFFSET"),
            _ => None,
        },
        7 => match id {
            1 => Some("MESSAGE"),
            2 => Some("APPLICATION DATA"),
            _ => None,
        },
        8 => match id {
            1 => Some("COPY SEGMENT"),
            2 => Some("INHERITANCE FILTER"),
            3 => Some("CLIP INHERITANCE"),
            4 => Some("SEGMENT TRANSFORMATION"),
            5 => Some("SEGMENT HIGHLIGHTING"),
            6 => Some("SEGMENT DISPLAY PRIORITY"),
            7 => Some("SEGMENT PICK PRIORITY"),
            _ => None,
        },
        9 => match id {
            1 => Some("APPLICATION STRUCTURE ATTRIBUTE"),
            _ => None,
        },
        // The classes 10 to 15 are reserved.
        _ => None,
    }
}

/// The name of a picture descriptor element.
///
/// Version 1 is ISO 8509-3; version 2 and later is ISO 8632-3, and the
/// two number these elements differently.
fn picture_name(id: u8, version: Option<u32>) -> Option<&'static str> {
    match version {
        Some(1) => match id {
            1 => Some("PICTURE DESCRIPTOR"),
            2 => Some("PICTURE DATA"),
            3 => Some("PICTURE ASPECT RATIO"),
            4 => Some("PICTURE SCALING"),
            5 => Some("SCALING MODE"),
            6 => Some("PICTURE VISIBILITY"),
            7 => Some("PICTURE CLIP RECTANGLE"),
            8 => Some("BACKGROUND COLOUR"),
            _ => None,
        },
        Some(version) if version >= 2 => match id {
            1 => Some("SCALING MODE"),
            2 => Some("COLOUR SELECTION MODE"),
            3 => Some("LINE WIDTH SPECIFICATION MODE"),
            4 => Some("MARKER SIZE SPECIFICATION MODE"),
            5 => Some("EDGE WIDTH SPECIFICATION MODE"),
            6 => Some("VDC EXTENT"),
            7 => Some("BACKGROUND COLOUR"),
            8 => Some("DEVICE VIEWPORT"),
            9 => Some("DEVICE VIEWPORT SPECIFICATION MODE"),
            10 => Some("DEVICE VIEWPORT MAPPING"),
            11 => Some("LINE REPRESENTATION"),
            12 => Some("MARKER REPRESENTATION"),
            13 => Some("TEXT REPRESENTATION"),
            14 => Some("FILL REPRESENTATION"),
            15 => Some("EDGE REPRESENTATION"),
            20 => Some("APPLICATION STRUCTURE DIRECTORY"),
            _ => None,
        },
        // The version is unknown: the number is reported instead of a name
        // this reader cannot be sure of.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! The fixture is written by hand to the format's specification and
    //! kept as a file, so the end-to-end run reads the same bytes the unit
    //! tests read: a fixture that only exists in a test is a fixture the
    //! binary was never shown.
    //!
    //! The first test is the one that matters: it asserts that the file
    //! itself does **not** contain what the rendering contains, because a
    //! rendering of a binary format that only re-orders what `rg` already
    //! sees would be a rendering for nothing.

    use super::*;

    const CGM: &[u8] = include_bytes!("../testdata/sample.cgm");

    /// Builds an element: a 16-bit header and its parameter list.
    fn element(class: u8, id: u8, params: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let word = (u16::from(class) << 12) | (u16::from(id) << 5) | params.len() as u16;
        out.extend_from_slice(&word.to_be_bytes());
        out.extend_from_slice(params);
        if params.len() % 2 == 1 {
            out.push(0);
        }
        out
    }

    #[test]
    fn a_cgm_renders_what_the_file_does_not() {
        // The file holds the coordinates as binary, and the rendering
        // holds them as text: the pair "polyline" and a point is not in
        // the file at all.
        assert!(
            !contains(CGM, b"polyline"),
            "the fixture is a binary metafile"
        );
        assert!(
            !contains(CGM, b"(100,100)"),
            "the fixture is a binary metafile"
        );
        // The text of a text element *is* in the file — it is a string of
        // characters — but the pair of it and its position is not.
        assert!(
            contains(CGM, b"CONTRATO ACME"),
            "the text is a string in the file"
        );
        assert!(
            !contains(CGM, b"CONTRATO ACME at (10,20)"),
            "the pair is not"
        );
        let out = render_cgm(CGM).expect("a cgm is ours");
        assert!(
            out.contains("polyline: (100,100) (200,200) (300,50)"),
            "{out}"
        );
        assert!(out.contains("circle: centre (500,500) radius 100"), "{out}");
        assert!(out.contains("text: CONTRATO ACME at (10,20)"), "{out}");
    }

    #[test]
    fn a_cgm_renders_its_header() {
        let out = render_cgm(CGM).expect("a cgm is ours");
        assert!(out.contains("metafile: SAMPLE"), "{out}");
        assert!(out.contains("version: 1"), "{out}");
        assert!(out.contains("description: ProfileId:WebCGM"), "{out}");
    }

    #[test]
    fn a_cgm_renders_its_elements_in_order() {
        let out = render_cgm(CGM).expect("a cgm is ours");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines,
            vec![
                "metafile: SAMPLE",
                "version: 1",
                "description: ProfileId:WebCGM",
                "element: VDC TYPE",
                "element: INTEGER PRECISION",
                "element: BEGIN PICTURE",
                "element: BEGIN PICTURE BODY",
                "clip rectangle: (0,0) (4000,4000)",
                "polyline: (100,100) (200,200) (300,50)",
                "circle: centre (500,500) radius 100",
                "text: CONTRATO ACME at (10,20)",
                "element: END PICTURE",
                "element: END METAFILE",
            ],
            "{out}"
        );
    }

    #[test]
    fn a_well_formed_walk_yields_the_expected_names() {
        let mut file = Vec::new();
        file.extend_from_slice(&element(0, 1, b"\x03ABC"));
        file.extend_from_slice(&element(1, 1, &[0x00, 0x01]));
        file.extend_from_slice(&element(0, 3, &[0x00]));
        file.extend_from_slice(&element(0, 4, &[]));
        file.extend_from_slice(&element(4, 17, &[0, 0, 0, 0, 0, 0]));
        file.extend_from_slice(&element(0, 5, &[]));
        file.extend_from_slice(&element(0, 2, &[]));
        let out = render_cgm(&file).expect("a cgm is ours");
        assert!(out.contains("metafile: ABC"), "{out}");
        assert!(out.contains("version: 1"), "{out}");
        assert!(out.contains("element: BEGIN PICTURE"), "{out}");
        assert!(out.contains("element: BEGIN PICTURE BODY"), "{out}");
        assert!(out.contains("element: ELLIPSE"), "{out}");
        assert!(out.contains("element: END METAFILE"), "{out}");
    }

    #[test]
    fn the_padding_rule_is_exercised() {
        // An element with an odd parameter list is followed by a pad byte,
        // and the next header starts on the even offset after it. If the
        // pad were not there, the next element would be read one byte
        // early and nothing would be found.
        let mut file = Vec::new();
        file.extend_from_slice(&element(0, 1, b"\x03ABC"));
        file.extend_from_slice(&element(1, 1, &[0x00, 0x01]));
        file.extend_from_slice(&element(4, 1, &[0, 1, 0, 2]));
        file.extend_from_slice(&element(0, 2, &[]));
        // The odd parameter list left a pad byte behind: the file is one
        // byte longer than the elements account for.
        assert_eq!(file.len() % 2, 0);
        let out = render_cgm(&file).expect("a cgm is ours");
        assert!(out.contains("polyline: (1,2)"), "{out}");
        assert!(out.contains("element: END METAFILE"), "{out}");
    }

    #[test]
    fn a_long_form_element_is_read() {
        // The long form: the parameter list is a run of chunks, each with
        // its own length word, and each chunk padded to a word boundary.
        let mut file = Vec::new();
        file.extend_from_slice(&element(0, 1, b"\x03ABC"));
        file.extend_from_slice(&element(1, 1, &[0x00, 0x01]));
        // A polyline of two points, in two chunks of one point each. A
        // chunk of four bytes is even, so it is not padded.
        let word = (4u16 << 12) | (1u16 << 5) | 31;
        file.extend_from_slice(&word.to_be_bytes());
        file.extend_from_slice(&0x8004u16.to_be_bytes());
        file.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]);
        file.extend_from_slice(&0x0004u16.to_be_bytes());
        file.extend_from_slice(&[0x00, 0x02, 0x00, 0x03]);
        file.extend_from_slice(&element(0, 2, &[]));
        let out = render_cgm(&file).expect("a cgm is ours");
        assert!(out.contains("polyline: (1,2) (2,3)"), "{out}");
    }

    #[test]
    fn a_file_that_is_not_a_cgm_is_declined() {
        let err = render_cgm(b"not a metafile at all").expect_err("not a cgm");
        assert!(err.is_decline(), "{err}");
        // A file that is too short to hold a header is declined too.
        let err = render_cgm(b"\x00").expect_err("not a cgm");
        assert!(err.is_decline(), "{err}");
        // A file whose first element is not BEGIN METAFILE is some other
        // format.
        let mut file = Vec::new();
        file.extend_from_slice(&element(1, 1, &[0x00, 0x01]));
        let err = render_cgm(&file).expect_err("not a cgm");
        assert!(err.is_decline(), "{err}");
    }

    #[test]
    fn a_truncated_cgm_is_an_error_and_not_a_panic() {
        let cut = &CGM[..CGM.len() / 2];
        let err = render_cgm(cut).expect_err("truncated");
        // It claims to be a metafile, so it is a failure and not a step
        // aside: the next adapter has nothing to do with it.
        assert!(!err.is_decline(), "{err}");
    }

    #[test]
    fn a_trailing_byte_is_an_error() {
        let mut file = CGM.to_vec();
        file.push(0);
        let err = render_cgm(&file).expect_err("a trailing byte");
        assert!(!err.is_decline(), "{err}");
    }

    /// Whether the bytes hold the needle.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
