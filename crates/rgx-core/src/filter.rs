// SPDX-License-Identifier: Apache-2.0

//! A structured query over what is known about a file.
//!
//! **What this is.** The grammar a `--filter` takes: predicates over named
//! facts, combined with `AND`, `OR` and `NOT`, with parentheses. A fact is
//! a name and a value, and the names are the ones the adapters already
//! report — `mail.from`, `exif.gps`, `table.column` — plus the ones the
//! pipeline knows about the file itself: `path`, `ext`, `format`.
//!
//! **The grammar.**
//!
//! ```text
//! expr      := or
//! or        := and ( "OR" and )*
//! and       := unary ( "AND" unary )*
//! unary     := "NOT" unary | primary
//! primary   := "(" expr ")" | predicate
//! predicate := path [ ":" [ op ] value ]
//! path      := ident ( (":" | ".") ident )*
//! op        := "=" | "!=" | "<" | "<=" | ">" | ">="
//! value     := '"' text '"' | "'" text "'" | bare
//! ```
//!
//! **Where the path ends.** At the *last* colon outside quotes, so
//! `mail:from:"admin@example.com"` is the path `mail:from` and the value
//! `admin@example.com`, and `mime:pdf` is the path `mime` and the value
//! `pdf`. Both `:` and `.` separate the parts of a path, and both spell the
//! same thing: the path `mail:from` is the path `mail.from`.
//!
//! **What a predicate matches.** A fact whose name is exactly the path —
//! then the operator compares the fact's *value*. Or a fact whose name is
//! *inside* the path — then the operator compares the fact's *name* (the
//! part after the separator) and the comparison is exact. So `mime:pdf`
//! asks whether the file's MIME type contains `pdf`, and `exif:gps` asks
//! whether the file has an EXIF fact called `gps`.
//!
//! The operators: no operator is "contains", case-insensitively, and it is
//! the default because a name is rarely the whole of what the user means
//! by it. `=` is "equals", case-sensitively. `!=` is "not equals", and it
//! is true when the fact is *absent*, because a file that does not have the
//! field does not have that value. `<`, `<=`, `>` and `>=` compare numbers
//! when both sides are numbers and bytes otherwise.
//!
//! **What it is not.** This is a filter over facts, not a query language:
//! there is no wildcard, no regular expression and no field of its own for
//! a path that does not exist. A filter that names a fact nobody reports is
//! false, not an error, because the file may simply not be of that kind.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// One fact about a file: a name and a value.
///
/// The name is namespaced by whoever reported it, so two adapters that both
/// have a `from` do not collide: `mail.from` and `http.from` are different
/// facts. The separator is `.`, and the query accepts `:` for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The fact's name, e.g. `mail.from` or `exif.gps`.
    pub name: String,
    /// The fact's value, e.g. `admin@example.com`.
    pub value: String,
}

impl Field {
    /// A fact.
    pub fn new(name: &str, value: &str) -> Self {
        Field {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

/// How a predicate compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Contains, case-insensitively. The default.
    Contains,
    /// Equals, case-sensitively.
    Equals,
    /// Not equals — and true when the fact is absent.
    NotEquals,
    /// Less than.
    Less,
    /// Less than or equal.
    LessEq,
    /// Greater than.
    Greater,
    /// Greater than or equal.
    GreaterEq,
}

impl Op {
    /// The operator's spelling, for the error message and for the tests.
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Contains => "contains",
            Op::Equals => "=",
            Op::NotEquals => "!=",
            Op::Less => "<",
            Op::LessEq => "<=",
            Op::Greater => ">",
            Op::GreaterEq => ">=",
        }
    }

    /// The comparison, over two values.
    ///
    /// The ordering comparisons are numbers when both sides are numbers and
    /// bytes otherwise, and the bytes are the raw ones: `a` is less than
    /// `B` because that is what the bytes say, and a filter that ordered
    /// case-insensitively would be a filter whose answer depends on a rule
    /// nobody wrote down.
    fn compare(self, fact: &str, wanted: &str) -> bool {
        match self {
            Op::Contains => contains_ignore_case(fact, wanted),
            Op::Equals => fact == wanted,
            Op::NotEquals => fact != wanted,
            Op::Less | Op::LessEq | Op::Greater | Op::GreaterEq => {
                match (parse_number(fact), parse_number(wanted)) {
                    (Some(a), Some(b)) => match self {
                        Op::Less => a < b,
                        Op::LessEq => a <= b,
                        Op::Greater => a > b,
                        Op::GreaterEq => a >= b,
                        _ => unreachable!(),
                    },
                    _ => {
                        let a = fact.as_bytes();
                        let b = wanted.as_bytes();
                        match self {
                            Op::Less => a < b,
                            Op::LessEq => a <= b,
                            Op::Greater => a > b,
                            Op::GreaterEq => a >= b,
                            _ => unreachable!(),
                        }
                    }
                }
            }
        }
    }
}

/// A parsed filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    /// Both sides hold.
    And(Box<Expr>, Box<Expr>),
    /// Either side holds.
    Or(Box<Expr>, Box<Expr>),
    /// The inner expression does not hold.
    Not(Box<Expr>),
    /// A predicate over one fact.
    Predicate {
        /// The fact's path, with `:` and `.` normalised to `.`.
        path: String,
        /// How the comparison is made.
        op: Op,
        /// What the fact is compared against.
        value: String,
    },
}

/// A parsed filter, with the text it came from.
///
/// The text is kept because it is what names the filter in the cache key
/// and in the extraction fingerprint: two filters that mean the same thing
/// are two keys, and a filter whose text is not in the key is a filter
/// whose answer can come from another filter's work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    /// The text as the user wrote it.
    pub text: String,
    /// The parsed expression.
    pub expr: Expr,
}

impl Filter {
    /// Parses a filter, keeping the text.
    pub fn parse(text: &str) -> Result<Filter, String> {
        let expr = parse(text)?;
        Ok(Filter {
            text: text.to_string(),
            expr,
        })
    }

    /// Whether the facts satisfy the filter.
    pub fn matches(&self, facts: &[Field]) -> bool {
        matches(&self.expr, facts)
    }
}

/// Parses a filter.
///
/// The error is a message a user can act on: what was expected and where.
pub fn parse(input: &str) -> Result<Expr, String> {
    let mut p = Parser {
        src: input.as_bytes(),
        text: input,
        pos: 0,
    };
    p.skip_space();
    if p.at_end() {
        return Err("the filter is empty".to_string());
    }
    let expr = p.parse_or()?;
    p.skip_space();
    if !p.at_end() {
        return Err(format!(
            "unexpected {:?} at position {}",
            p.peek_char(),
            p.pos
        ));
    }
    Ok(expr)
}

/// Whether the facts satisfy the expression.
pub fn matches(expr: &Expr, facts: &[Field]) -> bool {
    match expr {
        Expr::And(a, b) => matches(a, facts) && matches(b, facts),
        Expr::Or(a, b) => matches(a, facts) || matches(b, facts),
        Expr::Not(inner) => !matches(inner, facts),
        Expr::Predicate { path, op, value } => {
            let mut found = false;
            for fact in facts {
                if fact.name == *path {
                    // The exact fact: the operator compares the value.
                    if op.compare(&fact.value, value) {
                        found = true;
                    }
                } else if let Some(rest) = fact
                    .name
                    .strip_prefix(path)
                    .and_then(|rest| rest.strip_prefix('.'))
                {
                    // A fact inside the path's namespace: the operator
                    // compares the fact's own name, and exactly — `exif:gps`
                    // asks for a fact called `gps`, not for one whose name
                    // contains it. The namespace ends at the `.`, so
                    // `mailx.from` is not inside the namespace `mail`, and
                    // the default operator is promoted to the exact one —
                    // a contains over names made `exif:gps` find `gpsalt`.
                    let exact = if matches!(op, Op::Contains) {
                        Op::Equals
                    } else {
                        *op
                    };
                    if exact.compare(rest, value) {
                        found = true;
                    }
                }
            }
            // A fact nobody reports is not the same as a fact that is
            // there and does not match, and only `!=` can tell the two
            // apart.
            if !found && *op == Op::NotEquals {
                return true;
            }
            found
        }
    }
}

/// Whether `haystack` contains `needle`, case-insensitively.
fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// A number, if the text is one.
///
/// Only the plain forms: an integer, or a decimal with a point. A size
/// written `1M` is not a number, and a filter that read it as one would
/// compare `1` against `1048576` and answer the wrong question.
fn parse_number(text: &str) -> Option<i128> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(v) = t.parse::<i128>() {
        return Some(v);
    }
    if let Some((int, frac)) = t.split_once('.') {
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if !int.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // A decimal is scaled by 10^len(frac), so the comparison is exact
        // and integer arithmetic holds it.
        let scale = 10i128.checked_pow(frac.len() as u32)?;
        let whole: i128 = if int.is_empty() { 0 } else { int.parse().ok()? };
        let part: i128 = frac.parse().ok()?;
        whole.checked_mul(scale)?.checked_add(part)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// A recursive-descent parser over the filter's text.
struct Parser<'a> {
    src: &'a [u8],
    text: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn at_end(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn peek_char(&self) -> char {
        self.text[self.pos..].chars().next().unwrap_or('\0')
    }

    fn skip_space(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    /// The word at the cursor, if the cursor is at a word.
    fn peek_word(&self) -> Option<&'a str> {
        let rest = &self.text[self.pos..];
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        if end == 0 {
            None
        } else {
            Some(&rest[..end])
        }
    }

    fn eat_word(&mut self, word: &str) -> bool {
        if self.peek_word() == Some(word) {
            self.pos += word.len();
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        loop {
            self.skip_space();
            if !self.eat_word("OR") {
                return Ok(left);
            }
            self.skip_space();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary()?;
        loop {
            self.skip_space();
            if !self.eat_word("AND") {
                return Ok(left);
            }
            self.skip_space();
            let right = self.parse_unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        self.skip_space();
        if self.eat_word("NOT") {
            self.skip_space();
            let inner = self.parse_unary()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        self.skip_space();
        if self.peek_char() == '(' {
            self.pos += 1;
            let inner = self.parse_or()?;
            self.skip_space();
            if self.peek_char() != ')' {
                return Err(format!("expected ')' at position {}", self.pos));
            }
            self.pos += 1;
            return Ok(inner);
        }
        self.parse_predicate()
    }

    /// One predicate: a path, and optionally an operator and a value.
    ///
    /// The path ends at the last colon outside quotes, so that
    /// `mail:from:"x"` is the path `mail:from` and not the path `mail` with
    /// the value `from:"x"`.
    fn parse_predicate(&mut self) -> Result<Expr, String> {
        let start = self.pos;
        // The predicate's extent: up to a space or a closing parenthesis,
        // with the quotes taken as they come.
        let mut quote: Option<u8> = None;
        while self.pos < self.src.len() {
            let b = self.src[self.pos];
            match quote {
                Some(q) => {
                    if b == q {
                        quote = None;
                    }
                }
                None => {
                    if b == b'"' || b == b'\'' {
                        quote = Some(b);
                    } else if b == b'(' || b == b')' || b.is_ascii_whitespace() {
                        break;
                    }
                }
            }
            self.pos += 1;
        }
        let raw = &self.text[start..self.pos];
        if raw.is_empty() {
            return Err(format!("expected a predicate at position {start}"));
        }

        // The last colon outside quotes.
        let mut quote: Option<u8> = None;
        let mut split: Option<usize> = None;
        for (i, b) in raw.bytes().enumerate() {
            match quote {
                Some(q) => {
                    if b == q {
                        quote = None;
                    }
                }
                None => {
                    if b == b'"' || b == b'\'' {
                        quote = Some(b);
                    } else if b == b':' {
                        split = Some(i);
                    }
                }
            }
        }

        let Some(at) = split else {
            // A bare word is a path with no value: the fact has to be there.
            let path = normalise_path(raw)?;
            return Ok(Expr::Predicate {
                path,
                op: Op::Contains,
                value: String::new(),
            });
        };

        let path = normalise_path(&raw[..at])?;
        let rest = &raw[at + 1..];
        let (op, value) = split_operator(rest);
        let value = unquote(value);
        Ok(Expr::Predicate { path, op, value })
    }
}

/// The operator at the head of a value, and the value without it.
fn split_operator(rest: &str) -> (Op, &str) {
    for (prefix, op) in [
        ("!=", Op::NotEquals),
        ("<=", Op::LessEq),
        (">=", Op::GreaterEq),
        ("=", Op::Equals),
        ("<", Op::Less),
        (">", Op::Greater),
    ] {
        if let Some(value) = rest.strip_prefix(prefix) {
            return (op, value);
        }
    }
    (Op::Contains, rest)
}

/// A value without its quotes.
fn unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        return v[1..v.len() - 1].to_string();
    }
    v.to_string()
}

/// A path with `:` and `.` normalised to `.`, checked.
fn normalise_path(raw: &str) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    for (i, part) in raw.split([':', '.']).enumerate() {
        if part.is_empty() {
            return Err(format!("{raw:?} is not a fact name: it has an empty part"));
        }
        if !part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(format!("{raw:?} is not a fact name"));
        }
        if i > 0 {
            out.push('.');
        }
        out.push_str(part);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The facts of the pipeline
// ---------------------------------------------------------------------------

/// The facts the pipeline knows about a file, without opening it.
///
/// `format` is the adapter that answered for the file, or `raw` when none
/// did. `mime` and `lang` come from the extension alone, through
/// [`crate::filetype`] — they are what the *name* claims, which is not
/// the same as what the bytes are, and keeping them apart is the point.
///
/// The extension is taken from the last dot of the path, and only when it
/// is an extension: the member of an archive has the path
/// `archive.zip!inner.txt`, whose last dot belongs to the *archive* when
/// the member has none of its own.
pub fn file_facts(path: &str, format: &str) -> Vec<Field> {
    let mut facts = vec![Field::new("path", path), Field::new("format", format)];
    if let Some(ext) = ext_of(path) {
        facts.push(Field::new("ext", ext));
        // The tables are lowercased, and a file may spell its extension
        // in capitals: `report.PDF` is the same file as `report.pdf`. The
        // `ext` fact keeps the spelling it found -- the path is the
        // path -- but the tables are asked with the lowercased one.
        let lower = lowercase(ext);
        if let Some(mime) = crate::filetype::mime_of(&lower) {
            facts.push(Field::new("mime", mime));
        }
        if let Some(lang) = crate::filetype::lang_of(&lower) {
            facts.push(Field::new("lang", lang));
        }
    }
    facts
}

/// A lowercased copy of an extension, borrowed when it is already one.
fn lowercase(ext: &str) -> alloc::borrow::Cow<'_, str> {
    if ext.bytes().any(|b| b.is_ascii_uppercase()) {
        alloc::borrow::Cow::Owned(ext.to_ascii_lowercase())
    } else {
        alloc::borrow::Cow::Borrowed(ext)
    }
}

/// The extension of a path, when it has one that is an extension.
///
/// A dot in a directory name is not an extension: `my.data/file` has no
/// extension, and `archive.zip!inner` has none either — the dot belongs
/// to the archive. A path with no dot has none.
///
/// The `!` is the member separator, so it ends an extension the same way
/// a separator does: `archive.zip!inner` is the archive `archive.zip` and
/// the member `inner`, and the member has no extension of its own. A file
/// whose own name carries a `!` pays for the reservation — `report!draft`
/// is read as the container `report` and the member `draft` — which is
/// the same trade the member path makes everywhere else.
pub fn ext_of(path: &str) -> Option<&str> {
    let ext = path.rsplit_once('.').map(|(_, e)| e)?;
    if ext.is_empty() || ext.contains('/') || ext.contains('\\') || ext.contains('!') {
        return None;
    }
    Some(ext)
}

/// The facts of a file plus the ones an adapter reported.
///
/// The order is the one the facts are asked in, and it does not matter
/// for the answer: a predicate is true when *any* fact satisfies it, so
/// two facts with the same name are two chances to match.
pub fn facts_with(path: &str, format: &str, extra: &[Field]) -> Vec<Field> {
    let mut facts = file_facts(path, format);
    facts.extend(extra.iter().cloned());
    facts
}

/// The facts of a file as a name and value pair, with the value borrowed.
pub fn fact<'a>(facts: &'a [Field], name: &str) -> Option<&'a str> {
    facts
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(pairs: &[(&str, &str)]) -> Vec<Field> {
        pairs.iter().map(|(n, v)| Field::new(n, v)).collect()
    }

    #[test]
    fn a_predicate_matches_a_fact_by_contains() {
        let e = parse("author:\"Jane Doe\"").expect("parses");
        assert!(matches(
            &e,
            &facts(&[("author", "Jane Doe"), ("pages", "12")])
        ));
        assert!(!matches(&e, &facts(&[("author", "John Doe")])));
    }

    #[test]
    fn a_predicate_without_a_value_asks_whether_the_fact_is_there() {
        let e = parse("exif:gps").expect("parses");
        assert!(matches(&e, &facts(&[("exif.gps", "12.34, 56.78")])));
        assert!(!matches(&e, &facts(&[("exif.camera", "Nikon D850")])));
    }

    #[test]
    fn a_namespace_predicate_matches_the_name_exactly() {
        // The name is compared exactly, not by substring: `exif:gps` asks
        // for a fact called `gps`, and `gpsalt` is a different fact.
        let e = parse("exif:gps").expect("parses");
        assert!(!matches(&e, &facts(&[("exif.gpsalt", "51.5 N")])));
    }

    #[test]
    fn a_namespace_does_not_end_mid_name() {
        // The namespace ends at the `.`: `mailx.from` is a fact of the
        // `mailx` namespace, and a predicate over `mail` must not reach it.
        let e = parse("mail:from").expect("parses");
        assert!(!matches(&e, &facts(&[("mailx.from", "ana@example.org")])));
        assert!(matches(&e, &facts(&[("mail.from", "ana@example.org")])));
    }

    #[test]
    fn a_namespaced_path_finds_the_fact_it_names() {
        let e = parse("mail:from:\"admin@example.com\"").expect("parses");
        assert!(matches(
            &e,
            &facts(&[("mail.from", "admin@example.com"), ("http.from", "x@y")])
        ));
        assert!(!matches(&e, &facts(&[("http.from", "admin@example.com")])));
    }

    #[test]
    fn the_operators_do_what_they_say() {
        let f = facts(&[("size", "4096"), ("name", "readme")]);
        assert!(matches(&parse("size:>1000").unwrap(), &f));
        assert!(matches(&parse("size:>=4096").unwrap(), &f));
        assert!(matches(&parse("size:<5000").unwrap(), &f));
        assert!(!matches(&parse("size:>5000").unwrap(), &f));
        assert!(matches(&parse("size:=4096").unwrap(), &f));
        assert!(matches(&parse("size:!=1").unwrap(), &f));
        assert!(matches(&parse("name:=readme").unwrap(), &f));
        assert!(!matches(&parse("name:=README").unwrap(), &f));
        // A fact nobody reports is not the same as a fact that does not
        // match: only `!=` can tell the two apart.
        assert!(!matches(&parse("author:john").unwrap(), &f));
        assert!(matches(&parse("author:!=john").unwrap(), &f));
    }

    #[test]
    fn and_or_not_and_parentheses_work() {
        let f = facts(&[("mime", "application/pdf"), ("pages", "12")]);
        assert!(matches(&parse("mime:pdf AND pages:12").unwrap(), &f));
        assert!(!matches(&parse("mime:pdf AND pages:3").unwrap(), &f));
        assert!(matches(
            &parse("mime:pdf AND (pages:3 OR pages:12)").unwrap(),
            &f
        ));
        assert!(matches(&parse("NOT mime:epub").unwrap(), &f));
        assert!(!matches(&parse("NOT (mime:pdf AND pages:12)").unwrap(), &f));
        assert!(matches(
            &parse("mime:epub OR (mime:pdf AND pages:12)").unwrap(),
            &f
        ));
    }

    #[test]
    fn the_operators_are_case_insensitive_where_it_says_so() {
        let f = facts(&[("author", "Jane Doe")]);
        assert!(matches(&parse("author:jane").unwrap(), &f));
        // `=` is case-sensitive, and a value with a space has to be quoted.
        assert!(!matches(&parse("author:=\"jane doe\"").unwrap(), &f));
        assert!(matches(&parse("author:=\"Jane Doe\"").unwrap(), &f));
        // A bare value stops at the space, and what follows is not a filter.
        assert!(parse("author:jane doe").is_err());
    }

    #[test]
    fn a_broken_filter_says_what_it_expected() {
        assert!(parse("").is_err());
        assert!(parse("mime:pdf AND").is_err());
        assert!(parse("(mime:pdf").is_err());
        assert!(parse("mime:pdf)").is_err());
        assert!(parse("!!!:x").is_err());
    }

    #[test]
    fn the_pipeline_facts_name_the_file() {
        let f = file_facts("docs/report.PDF", "pdf");
        assert_eq!(fact(&f, "ext"), Some("PDF"));
        assert_eq!(fact(&f, "format"), Some("pdf"));
        assert!(matches(&parse("ext:pdf").unwrap(), &f));
        assert!(matches(&parse("path:report").unwrap(), &f));
    }

    #[test]
    fn the_facts_carry_the_mime_type_and_the_language() {
        let f = file_facts("docs/report.pdf", "pdf");
        assert_eq!(fact(&f, "mime"), Some("application/pdf"));
        assert!(matches(&parse("mime:pdf").unwrap(), &f));
        assert!(matches(&parse("mime:application/pdf").unwrap(), &f));

        let f = file_facts("src/main.rs", "raw");
        assert_eq!(fact(&f, "lang"), Some("rust"));
        assert!(matches(&parse("lang:rust").unwrap(), &f));
        assert!(!matches(&parse("lang:python").unwrap(), &f));
    }

    #[test]
    fn an_extension_in_capitals_is_the_same_extension() {
        let f = file_facts("REPORT.PDF", "pdf");
        assert_eq!(fact(&f, "mime"), Some("application/pdf"));
        assert!(matches(&parse("mime:pdf").unwrap(), &f));
    }

    #[test]
    fn a_member_of_an_archive_takes_its_own_extension() {
        // `archive.zip!inner.txt` is a `.txt`; `archive.zip!inner` is not
        // an extension at all, because the dot belongs to the archive.
        assert_eq!(ext_of("archive.zip!inner.txt"), Some("txt"));
        assert_eq!(ext_of("archive.zip!inner"), None);
        assert_eq!(ext_of("my.data/file"), None);
        assert_eq!(ext_of("noext"), None);
        assert_eq!(ext_of("trailing."), None);

        let f = file_facts("archive.zip!inner.txt", "raw");
        assert_eq!(fact(&f, "ext"), Some("txt"));
        assert_eq!(fact(&f, "mime"), Some("text/plain"));
    }

    /// The member separator ends an extension the way a path separator
    /// does. Without that, `archive.zip!inner` reads as the extension
    /// `zip!inner` and the container's dot is silently inherited by a
    /// member that has no extension of its own.
    #[test]
    fn a_member_separator_ends_the_extension() {
        assert_eq!(ext_of("archive.zip!inner"), None);
        assert_eq!(ext_of("archive.zip!inner.txt"), Some("txt"));
        assert_eq!(ext_of("archive.zip!docs/report"), None);
        assert_eq!(ext_of("archive.zip!docs/report.pdf"), Some("pdf"));
        // The reservation cuts both ways: a name that carries a `!` of its
        // own is read as a container and a member.
        assert_eq!(ext_of("report!draft.txt"), Some("txt"));
        assert_eq!(ext_of("report.txt!draft"), None);
    }

    #[test]
    fn the_extra_facts_are_added_to_the_pipeline_ones() {
        let extra = vec![Field::new("author", "Jane Doe")];
        let f = facts_with("a.pdf", "pdf", &extra);
        assert_eq!(fact(&f, "author"), Some("Jane Doe"));
        assert_eq!(fact(&f, "format"), Some("pdf"));
        assert!(matches(&parse("author:\"Jane Doe\"").unwrap(), &f));
    }
}
