// SPDX-License-Identifier: Apache-2.0

//! ISO 10303-21 — the STEP physical file ("part 21"), and the IFC files
//! written in it.
//!
//! **What these are.** A part 21 file is a plain-text exchange format. A
//! header section names the schema and the file; a data section holds the
//! instances, each one an entity of the model with its attributes. An IFC
//! file is a part 21 file whose schema is `IFC4` and whose entities are
//! `IFCWALL`, `IFCPERSON` and the rest of the building-model vocabulary.
//!
//! **Why they are rendered and not revealed.** `rg` reads a part 21 file
//! perfectly well — it is text, and ripgrep's line is as long as the
//! writer made it. An adapter that *answered* for it would replace bytes
//! ripgrep already searches, and rgx would answer a subset of what `rg`
//! answers. This is therefore [`Reach::Render`], the same reach the
//! flat files of this crate declare: under the default `Policy::Source`
//! the file's own bytes are the answer and this adapter is not consulted
//! at all; under `RGX_ADAPTER_VIEW=render` the rendering is what gets searched.
//!
//! **What the rendering is for.** A part 21 instance is written as one very
//! long line —
//!
//! ```text
//! #7=IFCWALL('3vB2YO$MX4xv5uQQUeJKF',#6,$,'Parede',$,$,$,$,$);
//! ```
//!
//! — and the pair "this value belongs to this entity" is hard to see,
//! because the line's shape says nothing about the model's. The rendering
//! puts one instance on a line and separates its arguments, so that a
//! search can ask for an entity *and* its values at once, which the file's
//! own bytes cannot answer: `IFCWALL('3vB2` and `',#6,` are two matches,
//! and `IFCWALL('3vB2', #6` is not one.
//!
//! **What is not claimed.** The geometry is not decoded. An
//! `IFCCARTESIANPOINT`'s three numbers are the numbers the file wrote, not
//! a point in space; a wall's placement is an `IFCAXIS2PLACEMENT3D` this
//! rendering names but does not evaluate. This is a view of the file's own
//! statements, not a geometry kernel, and it says so rather than
//! pretending to be one.
//!
//! **How it is read.** The tokenising is the hard part and the whole of
//! the parser's difficulty: a string may hold a comma, a parenthesis or a
//! `;`, and the quote that opens a string is escaped by doubling it. So
//! every scan below tracks whether it is inside a string, and a file whose
//! string is never closed is *bailed* on rather than guessed at.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{bail, decline, Adapter, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is
/// a bound on how much *more* the rendering may cost. A 64 MiB ceiling is
/// far above any file whose whole content is worth a second copy, and the
/// rendering says so when it bites rather than stopping in silence.
const MAX_RENDER: usize = 64 << 20;

/// The words every part 21 file opens with.
const MAGIC: &[u8] = b"ISO-10303-21";

// ---------------------------------------------------------------------------
// ISO 10303-21
// ---------------------------------------------------------------------------

/// A STEP physical file, and the IFC files written in it.
pub struct Step;
impl Adapter for Step {
    fn name(&self) -> &'static str {
        "step"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["stp", "step", "ifc"]
    }
    /// The file is text `rg` already reads: a rendering, never an answer.
    fn reach(&self) -> Reach {
        Reach::Render
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_step(data)?.into_bytes()))
    }
}

/// The STEP rendering: one line per instance, its arguments separated, and
/// a summary in front.
///
/// A complex instance — one id carrying several subtypes — is rendered as
/// one line *per subtype*, with the id repeated. The choice is made for
/// the reason the whole rendering is made: a line has to hold one entity
/// and its values to be searchable, and a complex instance is two
/// entities that happen to share an id. Joining them on one line would
/// put `IFCPROJECTIONUNIT`'s arguments next to
/// `IFCGEOMETRICREPRESENTATIONCONTEXT`'s, and a pattern for one of them
/// would have to carry the other's text along with it.
fn render_step(data: &[u8]) -> Result<String> {
    // The claim: a part 21 file opens with its magic. A file that does not
    // is another format's, and saying so is what lets the next adapter
    // have it — this is a decline, not a failure.
    let head = trim(data);
    if !head.starts_with(MAGIC) {
        decline!("step: the file does not start with ISO-10303-21");
    }
    if !trim(&head[MAGIC.len()..]).starts_with(b";") {
        decline!("step: the file does not start with ISO-10303-21;");
    }

    let mut scanner = Scanner::new(data);
    let mut body = String::new();
    let mut instances = 0usize;
    let mut types: Vec<&[u8]> = Vec::new();
    let mut schema: Option<&[u8]> = None;
    let mut file_name: Option<&[u8]> = None;
    let mut ended = false;

    while let Some(statement) = scanner.statement()? {
        let statement = trim(statement);
        if statement.is_empty() {
            continue;
        }
        if statement == MAGIC {
            continue;
        }
        if statement == b"END-ISO-10303-21" {
            ended = true;
            break;
        }
        // The section markers carry no value of their own.
        if statement == b"HEADER" || statement == b"DATA" || statement == b"ENDSEC" {
            continue;
        }
        if let Some(params) = entity_params(statement, b"FILE_SCHEMA")? {
            schema = first_value(&params);
            continue;
        }
        if let Some(params) = entity_params(statement, b"FILE_NAME")? {
            file_name = first_value(&params);
            continue;
        }
        if statement.starts_with(b"#") {
            let instance = parse_instance(statement)?;
            instances += 1;
            for subtype in &instance.subtypes {
                if !types.contains(&subtype.keyword) {
                    types.push(subtype.keyword);
                }
                let _ = write!(body, "#{}: ", instance.id);
                push_bytes(&mut body, subtype.keyword);
                body.push('(');
                for (i, param) in subtype.params.iter().enumerate() {
                    if i > 0 {
                        body.push_str(", ");
                    }
                    write_param(&mut body, param);
                }
                body.push_str(")\n");
            }
            continue;
        }
        // Anything else in a part 21 file (FILE_DESCRIPTION and the like)
        // is left alone: this rendering reports the schema and the file's
        // name, and does not claim to be the file.
    }

    if !ended {
        bail!("step: the file ends without END-ISO-10303-21");
    }

    // The front block: the counts, then what the file says about itself.
    let mut summary = format!("instances: {instances}\ntypes: {}", types.len());
    if let Some(schema) = schema {
        let _ = write!(summary, "\nschema: {}", unquote(schema));
    }
    if let Some(file_name) = file_name {
        let _ = write!(summary, "\nfile: {}", unquote(file_name));
    }

    Ok(finish(&summary, &body))
}

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

/// One instance: an id and the subtypes that carry it.
///
/// A complex instance holds several of them — `#8=(IFCWALL(...)IFCFOOTING(...))`
/// is one id with two entities under it.
struct Instance<'a> {
    id: u64,
    subtypes: Vec<Subtype<'a>>,
}

/// One entity of an instance: its keyword and its arguments.
struct Subtype<'a> {
    keyword: &'a [u8],
    params: Vec<Param<'a>>,
}

/// One argument of an entity.
enum Param<'a> {
    /// A value the file wrote: a string, a number, an enumeration, a
    /// reference, a binary literal — kept as the bytes the file wrote.
    Raw(&'a [u8]),
    /// `$`: the value is computed elsewhere and the file does not hold it.
    Derived,
    /// `*`: the value is redundant, repeated from an attribute the file
    /// does not repeat.
    Redundant,
    /// A list: `(...)`.
    List(Vec<Param<'a>>),
    /// A typed value: `IFCLENGTHMEASURE(1.0)`.
    Typed(&'a [u8], Vec<Param<'a>>),
}

/// Writes one argument.
///
/// A derived `$` and a redundant `*` are *not* values the file holds: `$`
/// says the value is computed elsewhere and `*` says the writer did not
/// repeat it. Both are written as words — `derived` and `redundant` —
/// because printing the character alone would read as if the file said
/// "$". They keep their *position*: the arguments of an entity are
/// positional, so dropping them would shift every argument after them
/// and the line would no longer say which attribute a value belongs to.
fn write_param(out: &mut String, param: &Param) {
    match param {
        Param::Raw(bytes) => push_bytes(out, bytes),
        Param::Derived => out.push_str("derived"),
        Param::Redundant => out.push_str("redundant"),
        Param::List(items) => {
            out.push('(');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_param(out, item);
            }
            out.push(')');
        }
        Param::Typed(keyword, params) => {
            push_bytes(out, keyword);
            out.push('(');
            for (i, item) in params.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_param(out, item);
            }
            out.push(')');
        }
    }
}

/// The first value of an entity's arguments.
///
/// `FILE_SCHEMA(('IFC4'))` holds a list and `FILE_NAME('a.ifc',...)` holds
/// a string; both answer the same question here — the first thing the
/// entity says.
fn first_value<'a>(params: &[Param<'a>]) -> Option<&'a [u8]> {
    match params.first()? {
        Param::Raw(bytes) => Some(bytes),
        Param::List(items) => match items.first()? {
            Param::Raw(bytes) => Some(bytes),
            _ => None,
        },
        _ => None,
    }
}

/// The value of a string, without its quotes.
///
/// A doubled quote is one quote, as the file wrote it.
fn unquote(bytes: &[u8]) -> String {
    let inner = if bytes.len() >= 2 && bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'' {
        &bytes[1..bytes.len() - 1]
    } else {
        bytes
    };
    let mut out = String::new();
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == b'\'' && inner.get(i + 1) == Some(&b'\'') {
            out.push('\'');
            i += 2;
            continue;
        }
        let start = i;
        while i < inner.len() && !(inner[i] == b'\'' && inner.get(i + 1) == Some(&b'\'')) {
            i += 1;
        }
        push_bytes(&mut out, &inner[start..i]);
    }
    out
}

/// Writes bytes as text, replacing what is not UTF-8 rather than failing.
fn push_bytes(out: &mut String, bytes: &[u8]) {
    match core::str::from_utf8(bytes) {
        Ok(text) => out.push_str(text),
        Err(_) => out.push_str(&String::from_utf8_lossy(bytes)),
    }
}

/// ASCII whitespace at both ends of a byte slice.
fn trim(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// A cursor over the bytes of a part 21 file.
///
/// The scanner is where the format's difficulty lives. A `;` ends a
/// statement unless it is inside a string, and a string ends at the first
/// quote that is not doubled — so every scan below asks "am I inside a
/// string?" before it acts on a delimiter.
struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// The byte under the cursor.
    fn byte(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// The byte `offset` bytes under the cursor.
    fn at(&self, offset: usize) -> Option<u8> {
        self.data.get(self.pos + offset).copied()
    }

    /// Skips whitespace and comments.
    ///
    /// A part 21 comment runs from `/*` to the next `*/` and may hold
    /// anything at all — including a quote, which is why the comment is
    /// skipped as a unit and never scanned for strings.
    fn skip_blank(&mut self) -> Result<()> {
        while let Some(b) = self.byte() {
            match b {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                b'/' if self.at(1) == Some(b'*') => {
                    let rest = &self.data[self.pos + 2..];
                    let end = match rest.windows(2).position(|w| w == b"*/") {
                        Some(end) => end,
                        None => bail!("step: an unterminated comment"),
                    };
                    self.pos += 2 + end + 2;
                }
                _ => break,
            }
        }
        Ok(())
    }

    /// Skips a quoted string, the cursor on the opening quote.
    ///
    /// The quote is escaped by doubling it, so the string ends at the
    /// first quote that is not followed by another.
    fn skip_string(&mut self) -> Result<()> {
        self.pos += 1;
        loop {
            match self.byte() {
                None => bail!("step: an unterminated string"),
                Some(b'\'') => {
                    if self.at(1) == Some(b'\'') {
                        self.pos += 2;
                    } else {
                        self.pos += 1;
                        return Ok(());
                    }
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    /// The next statement, without its terminating `;`.
    ///
    /// `Ok(None)` is the end of the file; an error is a file that stops in
    /// the middle of a statement.
    fn statement(&mut self) -> Result<Option<&'a [u8]>> {
        self.skip_blank()?;
        if self.pos >= self.data.len() {
            return Ok(None);
        }
        let start = self.pos;
        while let Some(b) = self.byte() {
            match b {
                b'\'' => self.skip_string()?,
                b'/' if self.at(1) == Some(b'*') => self.skip_blank()?,
                b';' => {
                    let statement = &self.data[start..self.pos];
                    self.pos += 1;
                    return Ok(Some(statement));
                }
                _ => self.pos += 1,
            }
        }
        bail!("step: the file ends inside a statement")
    }

    /// A number: the digits under the cursor.
    fn number(&mut self) -> Result<u64> {
        let start = self.pos;
        while let Some(b) = self.byte() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            bail!("step: expected a number");
        }
        let text = core::str::from_utf8(&self.data[start..self.pos]).unwrap_or("0");
        match text.parse::<u64>() {
            Ok(value) => Ok(value),
            Err(_) => bail!("step: an id is too large to read"),
        }
    }

    /// A keyword: the identifier under the cursor.
    fn identifier(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        while let Some(b) = self.byte() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            bail!("step: expected an entity name");
        }
        Ok(&self.data[start..self.pos])
    }

    /// The arguments of an entity, the cursor on the opening parenthesis.
    fn params(&mut self) -> Result<Vec<Param<'a>>> {
        self.pos += 1;
        let mut out: Vec<Param<'a>> = Vec::new();
        self.skip_blank()?;
        if self.byte() == Some(b')') {
            self.pos += 1;
            return Ok(out);
        }
        loop {
            out.push(self.param()?);
            self.skip_blank()?;
            match self.byte() {
                Some(b',') => self.pos += 1,
                Some(b')') => {
                    self.pos += 1;
                    return Ok(out);
                }
                None => bail!("step: an argument list is not closed"),
                _ => bail!("step: expected ',' or ')' in an argument list"),
            }
        }
    }

    /// One argument of an entity.
    fn param(&mut self) -> Result<Param<'a>> {
        self.skip_blank()?;
        let Some(b) = self.byte() else {
            bail!("step: an argument list ends early");
        };
        match b {
            // A string: kept as the file wrote it, quotes and all.
            b'\'' => {
                let start = self.pos;
                self.skip_string()?;
                Ok(Param::Raw(&self.data[start..self.pos]))
            }
            // A list.
            b'(' => {
                let items = self.params()?;
                Ok(Param::List(items))
            }
            // A derived value and a redundant value.
            b'$' => {
                self.pos += 1;
                Ok(Param::Derived)
            }
            b'*' => {
                self.pos += 1;
                Ok(Param::Redundant)
            }
            // A reference to another instance.
            b'#' => {
                let start = self.pos;
                self.pos += 1;
                let _ = self.number()?;
                Ok(Param::Raw(&self.data[start..self.pos]))
            }
            // An enumeration (`.T.`) or a real written with a leading dot
            // (`.5.`): both are a dot, a body and a closing dot.
            b'.' => {
                let start = self.pos;
                self.pos += 1;
                let mut closed = false;
                while let Some(c) = self.byte() {
                    self.pos += 1;
                    if c == b'.' {
                        closed = true;
                        break;
                    }
                    if c == b',' || c == b')' {
                        bail!("step: an enumeration is not closed");
                    }
                }
                if !closed {
                    bail!("step: an enumeration is not closed");
                }
                Ok(Param::Raw(&self.data[start..self.pos]))
            }
            // A number, or a binary literal.
            b'0'..=b'9' | b'+' | b'-' => {
                let start = self.pos;
                while let Some(c) = self.byte() {
                    if c == b',' || c == b')' || c.is_ascii_whitespace() {
                        break;
                    }
                    self.pos += 1;
                }
                Ok(Param::Raw(&self.data[start..self.pos]))
            }
            // A typed value: a name and its arguments.
            c if c == b'_' || c.is_ascii_alphabetic() => {
                let keyword = self.identifier()?;
                self.skip_blank()?;
                if self.byte() == Some(b'(') {
                    let params = self.params()?;
                    Ok(Param::Typed(keyword, params))
                } else {
                    Ok(Param::Raw(keyword))
                }
            }
            _ => bail!("step: an argument starts with a character no argument starts with"),
        }
    }
}

/// The arguments of the entity named `keyword`, if this statement is it.
fn entity_params<'a>(statement: &'a [u8], keyword: &[u8]) -> Result<Option<Vec<Param<'a>>>> {
    let mut scanner = Scanner::new(statement);
    scanner.skip_blank()?;
    if scanner.data[scanner.pos..].strip_prefix(keyword).is_none() {
        return Ok(None);
    }
    scanner.pos += keyword.len();
    scanner.skip_blank()?;
    if scanner.byte() != Some(b'(') {
        return Ok(None);
    }
    let params = scanner.params()?;
    Ok(Some(params))
}

/// The instance a statement holds.
///
/// A statement that starts with `#` is an instance, and one that does not
/// parse is a broken instance — a file that *is* a part 21 file and is
/// malformed, which is a failure rather than a decline.
fn parse_instance(statement: &[u8]) -> Result<Instance<'_>> {
    let mut scanner = Scanner::new(statement);
    scanner.skip_blank()?;
    scanner.pos += 1; // the '#'
    let id = scanner.number()?;
    scanner.skip_blank()?;
    if scanner.byte() != Some(b'=') {
        bail!("step: an instance has no '=' after its id");
    }
    scanner.pos += 1;
    scanner.skip_blank()?;

    let subtypes = if scanner.byte() == Some(b'(') {
        // A complex instance: the parentheses hold several subtypes, and
        // each of them is an entity of its own.
        scanner.pos += 1;
        let mut out: Vec<Subtype<'_>> = Vec::new();
        loop {
            scanner.skip_blank()?;
            match scanner.byte() {
                Some(b')') => break,
                None => bail!("step: a complex instance is not closed"),
                _ => {
                    let keyword = scanner.identifier()?;
                    scanner.skip_blank()?;
                    if scanner.byte() != Some(b'(') {
                        bail!("step: a subtype of a complex instance has no arguments");
                    }
                    let params = scanner.params()?;
                    out.push(Subtype { keyword, params });
                }
            }
        }
        scanner.pos += 1; // the ')'
        out
    } else {
        let keyword = scanner.identifier()?;
        scanner.skip_blank()?;
        if scanner.byte() != Some(b'(') {
            bail!("step: an instance has no arguments");
        }
        let params = scanner.params()?;
        vec![Subtype { keyword, params }]
    };

    // Nothing may follow an instance but whitespace: an instance that
    // carries text after its arguments is an instance the file did not
    // write, and guessing where it ends would be inventing an entity.
    scanner.skip_blank()?;
    if scanner.byte().is_some() {
        bail!("step: an instance has text after its arguments");
    }

    Ok(Instance { id, subtypes })
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Composes a rendering: the summary in front, the instances behind it.
///
/// The summary goes first because it is the question the file answers
/// slowest, and the instances behind it because they are the question the
/// user is usually asking.
fn finish(summary: &str, body: &str) -> String {
    let mut out = String::with_capacity(body.len() + summary.len() + 64);
    let _ = writeln!(out, "{summary}");
    if body.len() <= MAX_RENDER {
        out.push_str(body);
        return out;
    }
    // Cut on a line boundary: a rendering that stops in the middle of an
    // instance is an instance that reads as if it were whole.
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
    //! The fixture is written by hand to the specification of the format
    //! and kept as a file, so the end-to-end run reads the same bytes the
    //! unit tests read.
    //!
    //! The first test is the one that matters: it asserts that the file
    //! itself does **not** contain what the rendering contains, because a
    //! rendering that only re-orders what `rg` already sees would be a
    //! rendering for nothing.

    use super::*;

    const SAMPLE: &[u8] = include_bytes!("../testdata/sample.stp");

    #[test]
    fn the_rendering_shows_what_the_file_does_not() {
        let text = String::from_utf8_lossy(SAMPLE);
        assert!(
            !text.contains("#7: IFCWALL("),
            "the fixture is supposed to hold the unrendered form"
        );
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(out.contains("#7: IFCWALL("), "{out}");
    }

    #[test]
    fn the_schema_is_rendered() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(out.contains("schema: IFC4"), "{out}");
    }

    #[test]
    fn the_file_name_is_rendered() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(out.contains("file: contrato.ifc"), "{out}");
    }

    #[test]
    fn the_arguments_are_separated() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(out.contains("'Doe', 'Jane'"), "{out}");
    }

    #[test]
    fn a_list_keeps_its_parentheses() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(out.contains("(0., 0., 0.)"), "{out}");
    }

    #[test]
    fn a_reference_keeps_its_hash() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(out.contains("#6"), "{out}");
        // The reference survives as a reference, in the argument it is.
        assert!(out.contains("IFCWALL('3vB2YO$MX4xv5uQQUeJKF', #6"), "{out}");
    }

    #[test]
    fn the_summary_is_in_front() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        let first = out.lines().next().unwrap_or_default();
        assert!(first.contains("instances:"), "{out}");
        assert!(out.contains("types:"), "{out}");
    }

    #[test]
    fn a_derived_value_is_named_rather_than_printed() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(out.contains("derived"), "{out}");
        assert!(out.contains("redundant"), "{out}");
        // The position of a derived argument is information: it says which
        // attribute of the entity the values after it belong to.
        assert!(out.contains("IFCPERSON(derived, 'Doe', 'Jane'"), "{out}");
    }

    #[test]
    fn a_complex_instance_is_one_line_per_subtype() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(
            out.contains("#10: IFCGEOMETRICREPRESENTATIONCONTEXT("),
            "{out}"
        );
        assert!(out.contains("#10: IFCPROJECTIONUNIT("), "{out}");
    }

    #[test]
    fn the_front_block_is_the_counts_then_what_the_file_says_about_itself() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains("instances:"), "{out}");
        assert!(lines[1].contains("types:"), "{out}");
        assert!(lines[2].contains("schema: IFC4"), "{out}");
        assert!(lines[3].contains("file: contrato.ifc"), "{out}");
        assert!(lines[4].starts_with("#1:"), "{out}");
    }

    #[test]
    fn a_semicolon_inside_a_string_does_not_end_the_statement() {
        // A ';' inside a string is part of the string. A scanner that
        // split on it would cut the instance in two and lose the schema.
        let file = b"ISO-10303-21;\nHEADER;\nFILE_DESCRIPTION(('x'),'2;1');\nFILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n#1=IFCWALL('a;b',$,'Parede');\nENDSEC;\nEND-ISO-10303-21;\n";
        let out = render_step(file).expect("a part 21 file is ours");
        assert!(out.contains("schema: IFC4"), "{out}");
        assert!(out.contains("#1: IFCWALL('a;b'"), "{out}");
    }

    #[test]
    fn a_doubled_quote_is_one_quote() {
        let out = render_step(SAMPLE).expect("a part 21 file is ours");
        assert!(out.contains("'Terreno O''Brien'"), "{out}");
    }

    #[test]
    fn a_file_that_is_not_a_part_21_file_is_declined() {
        let err = render_step(b"not a step file").expect_err("not a part 21 file");
        assert!(err.is_decline(), "{err}");
    }

    #[test]
    fn a_truncated_file_is_an_error_not_a_panic() {
        let truncated = b"ISO-10303-21;\nHEADER;\nFILE_NAME('a.ifc','2026-10-19','x'";
        let err = render_step(truncated).expect_err("a string that is never closed");
        assert!(!err.is_decline(), "{err}");
    }

    #[test]
    fn an_instance_without_its_semicolon_is_an_error() {
        let broken = b"ISO-10303-21;\nDATA;\n#1=IFCWALL('x')\nENDSEC;\nEND-ISO-10303-21;\n";
        let err = render_step(broken).expect_err("no ';' after the instance");
        assert!(!err.is_decline(), "{err}");
    }
}
