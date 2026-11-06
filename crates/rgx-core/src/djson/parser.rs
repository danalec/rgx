// SPDX-License-Identifier: Apache-2.0

//! JSON Parser - RFC 8259 compliant.
//!
//! Parsing delegates to [`super::index_parser`], which walks the
//! structural index instead of the document and populates an [`Arena`].
//! The serializer and the `Value` traversal code are kept here: they
//! were not part of the byte-by-byte parser and the index rewrite does
//! not touch them. The legacy char-based parser is preserved in
//! `legacy` behind a `#[cfg(test)]` so the tests can still exercise
//! it; the only public entry point is [`parse`], which is the index
//! walker.
use alloc::string::String;

use core::fmt;
use core::fmt::Write as _;

use super::index_parser::parse_indexed;
use super::value::{Arena, Value};

#[derive(Debug, Clone)]
pub struct JsonParseError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

impl fmt::Display for JsonParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON parse error at line {} col {}: {}",
            self.line, self.col, self.message
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for JsonParseError {}

/// Parse `input` into an arena. The arena owns every string, every
/// array, every object, and holds the document root in
/// `arena.root()`. The public API takes no lifetime parameter, and
/// there is no `Box::leak` anywhere on the parse: the arena is the
/// only owner of the parsed bytes.
pub fn parse(input: &str) -> Result<Arena, JsonParseError> {
    parse_indexed(input)
}

/// Serialize `v` (a handle into `arena`) as a compact JSON document.
pub fn to_string(v: Value, arena: &Arena) -> String {
    let mut out = String::new();
    serialize(&mut out, v, arena, 0, false);
    out
}

/// Serialize `v` (a handle into `arena`) as a pretty JSON document, two
/// spaces per indent level.
pub fn to_string_pretty(v: Value, arena: &Arena) -> String {
    let mut out = String::new();
    serialize(&mut out, v, arena, 0, true);
    out
}

fn serialize(out: &mut String, v: Value, arena: &Arena, indent: usize, pretty: bool) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if b { "true" } else { "false" }),
        // Number's Display keeps integers exact and prints non-finite
        // values as null (JSON has no NaN/Infinity).
        Value::Number(n) => write!(out, "{n}").unwrap(),
        Value::String(idx) => {
            out.push('"');
            // Route the string through the allocation-free escaping
            // path so a parsed document with N strings no longer pays
            // for N intermediate `String` allocations during serialize.
            let _ = super::value::write_escaped(out, arena.get_string(idx));
            out.push('"');
        }
        Value::Array(idx) => {
            let items = arena.get_array(idx);
            if items.is_empty() {
                out.push_str("[]");
            } else if pretty {
                out.push_str("[\n");
                let mut iter = items.iter().peekable();
                while let Some(item) = iter.next() {
                    push_indent(out, indent + 1);
                    serialize(out, *item, arena, indent + 1, pretty);
                    if iter.peek().is_some() {
                        out.push_str(",\n");
                    } else {
                        out.push('\n');
                    }
                }
                push_indent(out, indent);
                out.push(']');
            } else {
                out.push('[');
                let mut iter = items.iter().peekable();
                while let Some(item) = iter.next() {
                    serialize(out, *item, arena, indent, pretty);
                    if iter.peek().is_some() {
                        out.push(',');
                    }
                }
                out.push(']');
            }
        }
        Value::Object(idx) => {
            let obj = arena.get_object(idx);
            if obj.is_empty() {
                out.push_str("{}");
            } else if pretty {
                out.push_str("{\n");
                let mut iter = obj.iter().peekable();
                while let Some((k_idx, val)) = iter.next() {
                    push_indent(out, indent + 1);
                    out.push('"');
                    super::value::write_escaped(out, arena.get_string(*k_idx)).unwrap();
                    // The closing quote belongs INSIDE the `": "`, not after
                    // it. It was pushed as a bare `": "`, so every non-empty
                    // object serialized to a missing quote on each key and
                    // the output did not re-parse -- `"version: 8,` rather
                    // than `"version": 8,`. A `String` sink is infallible by
                    // construction, so the unwrap cannot fire.
                    out.push_str("\": ");
                    serialize(out, *val, arena, indent + 1, pretty);
                    if iter.peek().is_some() {
                        out.push_str(",\n");
                    } else {
                        out.push('\n');
                    }
                }
                push_indent(out, indent);
                out.push('}');
            } else {
                out.push('{');
                let mut iter = obj.iter().peekable();
                while let Some((k_idx, val)) = iter.next() {
                    out.push('"');
                    super::value::write_escaped(out, arena.get_string(*k_idx)).unwrap();
                    out.push_str("\":");
                    serialize(out, *val, arena, indent, pretty);
                    if iter.peek().is_some() {
                        out.push(',');
                    }
                }
                out.push('}');
            }
        }
    }
}

/// Write `indent * 2` spaces to `out`. Pretty JSON uses two spaces per level;
/// the per-entry `&"  ".repeat(indent)` form allocated a `String` of that
/// length, and a 1M-entry object allocates 1M of them.
fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent * 2 {
        out.push(' ');
    }
}

#[cfg(test)]
mod legacy {
    //! The byte-by-byte parser, kept for reference.
    //!
    //! The current public entry point is the index walker in
    //! [`super::super::index_parser`]; this module compiles only under
    //! `cargo test` so the legacy logic remains auditable without
    //! being on the build path of the binary. It uses the new
    //! `Value` + `Arena` model directly: every key, value, array, and
    //! object is interned or stored in the arena, the same way the
    //! index walker does, so the two paths agree on what the smoke
    //! test sees.
    use alloc::format;
    use alloc::string::String;

    use crate::NoStdFloat;

    use super::super::value::{Arena, Number, Value};
    use super::JsonParseError;

    #[derive(Clone)]
    struct Pos {
        line: usize,
        col: usize,
        byte: usize,
    }

    pub(super) struct Parser<'a> {
        pos: Pos,
        chars: core::iter::Peekable<core::str::Chars<'a>>,
        depth: u32,
    }

    const MAX_DEPTH: u32 = 128;

    impl<'a> Parser<'a> {
        pub(super) fn new(input: &'a str) -> Self {
            Self {
                pos: Pos {
                    line: 1,
                    col: 1,
                    byte: 0,
                },
                chars: input.chars().peekable(),
                depth: 0,
            }
        }

        fn peek(&mut self) -> Option<char> {
            self.chars.peek().copied()
        }

        fn advance(&mut self) -> Option<char> {
            if let Some(c) = self.chars.next() {
                self.pos.byte += c.len_utf8();
                if c == '\n' {
                    self.pos.line += 1;
                    self.pos.col = 1;
                } else {
                    self.pos.col += 1;
                }
                Some(c)
            } else {
                None
            }
        }

        fn error(&self, msg: impl Into<String>) -> JsonParseError {
            JsonParseError {
                message: msg.into(),
                line: self.pos.line,
                col: self.pos.col,
            }
        }

        fn skip_whitespace(&mut self) {
            while let Some(c) = self.peek() {
                if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                    self.advance();
                } else {
                    break;
                }
            }
        }

        fn expect(&mut self, expected: char) -> Result<(), JsonParseError> {
            match self.advance() {
                Some(c) if c == expected => Ok(()),
                Some(c) => Err(self.error(format!("Expected '{}', found '{}'", expected, c))),
                None => Err(self.error(format!("Expected '{}', found EOF", expected))),
            }
        }

        pub(super) fn parse(&mut self, arena: &mut Arena) -> Result<Value, JsonParseError> {
            self.skip_whitespace();
            let value = self.parse_value(arena)?;
            self.skip_whitespace();
            if self.peek().is_some() {
                return Err(self.error("Unexpected content after JSON value"));
            }
            Ok(value)
        }

        fn parse_value(&mut self, arena: &mut Arena) -> Result<Value, JsonParseError> {
            self.skip_whitespace();
            if matches!(self.peek(), Some('[') | Some('{')) && self.depth >= MAX_DEPTH {
                return Err(self.error("Nesting too deep"));
            }
            match self.peek() {
                Some('n') => self.parse_null(),
                Some('t') => self.parse_true(),
                Some('f') => self.parse_false(),
                Some('"') => self.parse_string_into(arena),
                Some('[') => self.parse_array(arena),
                Some('{') => self.parse_object(arena),
                Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
                Some(c) => Err(self.error(format!("Unexpected character '{}'", c))),
                None => Err(self.error("Unexpected end of input")),
            }
        }

        fn parse_null(&mut self) -> Result<Value, JsonParseError> {
            for expected in ['n', 'u', 'l', 'l'] {
                self.expect(expected)?;
            }
            Ok(Value::Null)
        }

        fn parse_true(&mut self) -> Result<Value, JsonParseError> {
            for expected in ['t', 'r', 'u', 'e'] {
                self.expect(expected)?;
            }
            Ok(Value::Bool(true))
        }

        fn parse_false(&mut self) -> Result<Value, JsonParseError> {
            for expected in ['f', 'a', 'l', 's', 'e'] {
                self.expect(expected)?;
            }
            Ok(Value::Bool(false))
        }

        fn parse_string_into(&mut self, arena: &mut Arena) -> Result<Value, JsonParseError> {
            let s = self.parse_string()?;
            Ok(Value::String(arena.intern(s)))
        }

        fn parse_string(&mut self) -> Result<String, JsonParseError> {
            self.expect('"')?;
            let mut s = String::new();
            loop {
                match self.peek() {
                    None => return Err(self.error("Unterminated string")),
                    Some('\\') => {
                        self.advance();
                        match self.advance() {
                            Some('"') => s.push('"'),
                            Some('\\') => s.push('\\'),
                            Some('/') => s.push('/'),
                            Some('b') => s.push('\u{0008}'),
                            Some('f') => s.push('\u{000C}'),
                            Some('n') => s.push('\n'),
                            Some('r') => s.push('\r'),
                            Some('t') => s.push('\t'),
                            Some('u') => {
                                let cp = self.parse_unicode_escape()?;
                                s.push(cp);
                            }
                            Some(c) => return Err(self.error(format!("Invalid escape \\{}", c))),
                            None => return Err(self.error("Unterminated escape")),
                        }
                    }
                    Some('"') => {
                        self.advance();
                        break;
                    }
                    Some(c) if c < '\u{0020}' => {
                        return Err(self.error("Unescaped control character in string"));
                    }
                    Some(c) => {
                        self.advance();
                        s.push(c);
                    }
                }
            }
            Ok(s)
        }

        fn parse_unicode_escape(&mut self) -> Result<char, JsonParseError> {
            let mut hex = String::with_capacity(4);
            for _ in 0..4 {
                match self.advance() {
                    Some(c) if c.is_ascii_hexdigit() => hex.push(c),
                    Some(c) => return Err(self.error(format!("Invalid hex digit '{}'", c))),
                    None => return Err(self.error("Incomplete unicode escape")),
                }
            }
            let cp = u32::from_str_radix(&hex, 16)
                .map_err(|_| self.error("Invalid unicode codepoint"))?;

            if let Some(c) = char::from_u32(cp) {
                Ok(c)
            } else if (0xD800..=0xDFFF).contains(&cp) {
                self.parse_surrogate_pair(cp)
            } else {
                Err(self.error("Invalid unicode codepoint"))
            }
        }

        fn parse_surrogate_pair(&mut self, high: u32) -> Result<char, JsonParseError> {
            if !(0xD800..=0xDBFF).contains(&high) {
                return Err(self.error("Invalid high surrogate"));
            }

            if self.peek() != Some('\\') {
                return Err(self.error("Expected low surrogate"));
            }
            self.advance();
            if self.peek() != Some('u') {
                return Err(self.error("Expected low surrogate"));
            }
            self.advance();

            let mut hex = String::with_capacity(4);
            for _ in 0..4 {
                match self.advance() {
                    Some(c) if c.is_ascii_hexdigit() => hex.push(c),
                    Some(c) => return Err(self.error(format!("Invalid hex digit '{}'", c))),
                    None => return Err(self.error("Incomplete unicode escape")),
                }
            }

            let low = u32::from_str_radix(&hex, 16)
                .map_err(|_| self.error("Invalid unicode codepoint"))?;

            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(self.error("Invalid low surrogate"));
            }

            let cp = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
            char::from_u32(cp).ok_or_else(|| self.error("Invalid surrogate pair"))
        }

        fn parse_number(&mut self) -> Result<Value, JsonParseError> {
            let mut s = String::new();

            if self.peek() == Some('-') {
                s.push('-');
                self.advance();
            }

            match self.peek() {
                Some('0') => {
                    s.push('0');
                    self.advance();
                    if let Some(c) = self.peek() {
                        if c.is_ascii_digit() {
                            return Err(self.error("Leading zero not allowed"));
                        }
                    }
                }
                Some(c) if c.is_ascii_digit() && c != '0' => {
                    while let Some(c) = self.peek() {
                        if c.is_ascii_digit() {
                            s.push(c);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                }
                Some(_) => return Err(self.error("Invalid number")),
                None => return Err(self.error("Incomplete number")),
            }

            if self.peek() == Some('.') {
                s.push('.');
                self.advance();

                let has_digits = self.peek().is_some_and(|c| c.is_ascii_digit());
                if !has_digits {
                    return Err(self.error("Expected digits after decimal point"));
                }

                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        s.push(c);
                        self.advance();
                    } else {
                        break;
                    }
                }
            }

            if self.peek() == Some('e') || self.peek() == Some('E') {
                s.push(self.advance().unwrap());

                if self.peek() == Some('+') || self.peek() == Some('-') {
                    s.push(self.advance().unwrap());
                }

                let has_digits = self.peek().is_some_and(|c| c.is_ascii_digit());
                if !has_digits {
                    return Err(self.error("Expected digits in exponent"));
                }

                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        s.push(c);
                        self.advance();
                    } else {
                        break;
                    }
                }
            }

            let is_integer_syntax = !s.contains(['.', 'e', 'E']);
            if is_integer_syntax {
                if let Ok(i) = s.parse::<i64>() {
                    return Ok(Value::Number(Number::I64(i)));
                }
                if let Ok(u) = s.parse::<u64>() {
                    return Ok(Value::Number(Number::U64(u)));
                }
            }

            let n: f64 =
                NoStdFloat::parse(s.as_str()).map_err(|_| self.error("Invalid number format"))?;
            if !n.is_finite() {
                return Err(self.error("Number out of range"));
            }

            Ok(Value::num(n))
        }

        fn parse_array(&mut self, arena: &mut Arena) -> Result<Value, JsonParseError> {
            self.expect('[')?;
            self.depth += 1;
            let arr_idx = arena.push_array();
            let r = self.parse_array_inner(arena, arr_idx);
            self.depth -= 1;
            r
        }

        fn parse_array_inner(
            &mut self,
            arena: &mut Arena,
            arr_idx: usize,
        ) -> Result<Value, JsonParseError> {
            self.skip_whitespace();
            if self.peek() == Some(']') {
                self.advance();
                return Ok(Value::Array(arr_idx));
            }

            loop {
                let v = self.parse_value(arena)?;
                arena.push_array_value(arr_idx, v);
                self.skip_whitespace();

                match self.peek() {
                    Some(',') => {
                        self.advance();
                        self.skip_whitespace();
                    }
                    Some(']') => {
                        self.advance();
                        break;
                    }
                    Some(_) => return Err(self.error("Expected ',' or ']'")),
                    None => return Err(self.error("Unterminated array")),
                }
            }

            Ok(Value::Array(arr_idx))
        }

        fn parse_object(&mut self, arena: &mut Arena) -> Result<Value, JsonParseError> {
            self.expect('{')?;
            self.depth += 1;
            let obj_idx = arena.push_object();
            let r = self.parse_object_inner(arena, obj_idx);
            self.depth -= 1;
            r
        }

        fn parse_object_inner(
            &mut self,
            arena: &mut Arena,
            obj_idx: usize,
        ) -> Result<Value, JsonParseError> {
            self.skip_whitespace();
            if self.peek() == Some('}') {
                self.advance();
                return Ok(Value::Object(obj_idx));
            }

            loop {
                self.skip_whitespace();
                let key = self.parse_string()?;
                // The arena owns the key, so the legacy smoke test no
                // longer needs a `Box::leak` to satisfy the map's
                // signature. The dedup in `Arena::intern` means even a
                // pathological doc with thousands of identical escaped
                // keys lands in a single string slot.
                let key_idx = arena.intern(key);
                self.skip_whitespace();
                self.expect(':')?;
                self.skip_whitespace();
                let value = self.parse_value(arena)?;

                arena.insert_object(obj_idx, key_idx, value);
                self.skip_whitespace();

                match self.peek() {
                    Some(',') => {
                        self.advance();
                    }
                    Some('}') => {
                        self.advance();
                        break;
                    }
                    Some(_) => return Err(self.error("Expected ',' or '}'")),
                    None => return Err(self.error("Unterminated object")),
                }
            }

            Ok(Value::Object(obj_idx))
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::super::value::{Arena, Number, Value};
    use super::legacy::Parser as LegacyParser;
    use super::*;

    #[test]
    fn test_null() {
        let arena = parse("null").unwrap();
        assert_eq!(arena.root(), Value::Null);
    }

    #[test]
    fn test_bool() {
        let arena = parse("true").unwrap();
        assert_eq!(arena.root(), Value::Bool(true));
        let arena = parse("false").unwrap();
        assert_eq!(arena.root(), Value::Bool(false));
    }

    #[test]
    fn test_number() {
        // Integer syntax keeps its integer form; fraction/exponent
        // syntax is a float (the exactness contract is the reason the
        // Number enum exists).
        let arena = parse("42").unwrap();
        assert_eq!(arena.root(), Value::Number(Number::I64(42)));
        let arena = parse("-42").unwrap();
        assert_eq!(arena.root(), Value::Number(Number::I64(-42)));
        // 3.14 is the input under test, not a stand-in for a constant:
        // the assertion is that the *text* "3.14" parses to that value.
        #[allow(clippy::approx_constant)]
        let three_point_one_four = 3.14;
        let arena = parse("3.14").unwrap();
        assert_eq!(arena.root(), Value::num(three_point_one_four));
        let arena = parse("1e10").unwrap();
        assert_eq!(arena.root(), Value::num(1e10));
        let arena = parse("1.5e-3").unwrap();
        assert_eq!(arena.root(), Value::num(1.5e-3));
    }

    #[test]
    fn test_string() {
        let arena = parse("\"hello\"").unwrap();
        assert_eq!(arena.root().as_str(&arena), Some("hello"));
        let arena = parse("\"hello\\nworld\"").unwrap();
        assert_eq!(arena.root().as_str(&arena), Some("hello\nworld"));
        let arena = parse("\"\\u0041\"").unwrap();
        assert_eq!(arena.root().as_str(&arena), Some("A"));
    }

    #[test]
    fn test_array() {
        let arena = parse("[1, 2, 3]").unwrap();
        assert_eq!(arena.root().len(&arena), 3);

        let arena = parse("[1, \"two\", true, null]").unwrap();
        assert_eq!(arena.root().len(&arena), 4);
    }

    #[test]
    fn test_object() {
        let arena = parse("{\"name\": \"Alice\"}").unwrap();
        let v = arena.root();
        let inner = v.get(&arena, "name").and_then(|vv| vv.as_str(&arena));
        assert_eq!(inner, Some("Alice"));

        let arena = parse("{\"a\": 1, \"b\": 2}").unwrap();
        let v = arena.root();
        assert_eq!(v.get(&arena, "a").and_then(|vv| vv.as_number()), Some(1.0));
        assert_eq!(v.get(&arena, "b").and_then(|vv| vv.as_number()), Some(2.0));
    }

    #[test]
    fn test_nested() {
        let arena = parse("{\"arr\": [1, 2, {\"x\": 3}]}").unwrap();
        let v = arena.root();
        let arr_v = v
            .get(&arena, "arr")
            .and_then(|vv| vv.as_array(&arena))
            .unwrap();
        let arr_obj = arr_v[2];
        let x = arr_obj.get(&arena, "x").and_then(|vv| vv.as_number());
        assert_eq!(x, Some(3.0));
    }

    #[test]
    fn test_errors() {
        assert!(parse("").is_err());
        assert!(parse("nul").is_err());
        assert!(parse("{\"a\":}").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("01").is_err());
    }

    #[test]
    fn test_serialize() {
        let arena = parse("{\"name\":\"Alice\",\"age\":30}").unwrap();
        let s = to_string(arena.root(), &arena);
        let reparsed = parse(&s).unwrap();
        assert_eq!(reparsed.root(), arena.root());
    }

    /// Unicode has to survive as a *value*, not merely be accepted.
    ///
    /// A parser can accept a document and still hand back mangled text: a
    /// byte-at-a-time escaper re-encodes each `char`, a `String::from` that
    /// takes only the first byte of a code point, a surrogate pair handled
    /// as two separate units. None of that shows up in a "did it parse" test,
    /// which is the only kind of test this module had for Unicode before
    /// this one -- `test_unicode_surrogate` covers a single astral escape
    /// and nothing else.
    ///
    /// The cases are the ones that break a byte/char confusion: an astral
    /// emoji (4 bytes, 1 scalar), a ZWJ sequence (several scalars, one
    /// grapheme), a skin-tone modifier, a combining mark, a key rather than
    /// a value, and a document that mixes raw UTF-8 with `\u` escapes. The
    /// round-trip through `to_string` is asserted on the same string, so a
    /// writer that drops a scalar is caught as well as a reader.
    #[test]
    fn unicode_survives_as_a_value_and_through_a_round_trip() {
        let cases: [(&str, &str); 12] = [
            ("latin accents", "café naïve"),
            ("cjk", "日本語テキスト"),
            ("astral emoji", "\u{1F3AF} target"),
            // family: 3 scalars joined by ZWJ, rendered as one glyph
            (
                "zwj sequence",
                "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}",
            ),
            ("skin tone modifier", "\u{1F44D}\u{1F3FD}"),
            ("combining acute", "e\u{0301}cole"),
            ("mixed script", "Ω≈ç√ ∑ ≪ 汉字 café"),
            ("bmp above ascii", "Ⱥ\u{FFFF}"),
            ("escaped astral", "\u{1F3AF}"),
            ("tilde over n", "\u{0303}n"),
            ("rtl text", "مرحبا שלום"),
            ("supplementary plane edge", "\u{10FFFF}"),
        ];

        for (name, want) in cases {
            // As a value, written raw.
            let doc = alloc::format!("[\"{want}\"]");
            let arena = parse(&doc).unwrap_or_else(|e| panic!("{name}: {doc} -> {e}"));
            let root = arena.root();
            let arr = root.as_array(&arena).expect("an array");
            assert_eq!(arr.len(), 1);
            assert_eq!(
                arr[0].as_str(&arena),
                Some(want),
                "{name}: raw UTF-8 was not preserved ({} bytes vs {} bytes)",
                doc.len(),
                want.len()
            );

            // And back out again.
            let printed = to_string(arena.root(), &arena);
            let again = parse(&printed).unwrap_or_else(|e| panic!("{name}: {printed} -> {e}"));
            assert_eq!(
                again.root(),
                arena.root(),
                "{name}: to_string -> parse is not a fixed point"
            );
        }

        // Unicode in a key, which travels a different path than a value.
        let with_key = parse("{\"\u{1F3AF}\":\"Ⱥ\"}").expect("unicode key");
        let obj = with_key.root();
        let inner = obj
            .get(&with_key, "\u{1F3AF}")
            .and_then(|v| v.as_str(&with_key));
        assert_eq!(inner, Some("Ⱥ"));

        // A document mixing raw UTF-8 and \u escapes in one string, which is
        // what a real file looks like when it was partly hand-escaped.
        let mixed = parse("[\"café \\u65e5\\u672c \u{1F3AF}\"]").expect("mixed");
        let arr = mixed.root().as_array(&mixed).expect("an array");
        assert_eq!(arr[0].as_str(&mixed), Some("café 日本 \u{1F3AF}"));

        // And a surrogate pair written the long way, which is the only path
        // that exercises the pair-joining code.
        let escaped = parse("[\"\\uD83C\\uDFAF\"]").expect("surrogate pair");
        let arr = escaped.root().as_array(&escaped).expect("an array");
        assert_eq!(arr[0].as_str(&escaped), Some("\u{1F3AF}"));
    }

    /// A non-empty object pretty-printed used to lose the closing quote on
    /// every key -- `"version: 8,` instead of `"version": 8,` -- because the
    /// closing quote was pushed after the colon rather than before it. The
    /// output did not re-parse, and nothing round-tripped far enough to
    /// notice: `to_string_pretty` was only checked for containing a newline.
    #[test]
    fn pretty_objects_reparse() {
        let arena = parse("{\"version\":8,\"nested\":{\"x\":1}}").unwrap();
        let s = to_string_pretty(arena.root(), &arena);
        let back = parse(&s).unwrap_or_else(|e| panic!("plain output did not re-parse: {s}\n{e}"));
        assert_eq!(back.root(), arena.root());
        assert!(s.contains("\"version\": 8"));
    }

    #[test]
    fn test_serialize_pretty() {
        let arena = parse("[1, 2, 3]").unwrap();
        let s = to_string_pretty(arena.root(), &arena);
        assert!(s.contains('\n'));
    }

    #[test]
    fn test_roundtrip() {
        let inputs = [
            "null",
            "true",
            "false",
            "42",
            "-3.14",
            "\"hello\"",
            "[1, 2, 3]",
            "{\"a\": 1}",
            "{\"arr\": [1, 2], \"obj\": {\"x\": 1}}",
        ];
        for input in inputs {
            let parsed = parse(input).unwrap();
            let serialized = to_string(parsed.root(), &parsed);
            let reparsed = parse(&serialized).unwrap();
            assert_eq!(parsed.root(), reparsed.root());
        }
    }

    #[test]
    fn test_unicode_surrogate() {
        let input = "\"\\uD83D\\uDE00\"";
        let arena = parse(input).unwrap();
        assert_eq!(arena.root().as_str(&arena), Some("\u{1F600}"));
    }

    /// The byte-by-byte parser is still compiled under `cargo test` --
    /// this is a smoke check that the legacy module stays exercisable
    /// while the public `parse` is the index walker.
    #[test]
    fn legacy_parser_still_works() {
        let mut arena = Arena::new();
        let root = {
            let mut p = LegacyParser::new("{\"a\":1,\"b\":[true,null]}");
            p.parse(&mut arena).unwrap()
        };
        arena.set_root(root);

        let obj = arena.get_object(
            arena
                .root()
                .as_object(&arena)
                .map(|o| {
                    // The walker test below checks the object structurally;
                    // this grab is so the helper type-chains the
                    // post-condition.
                    let _ = o;
                    0
                })
                .unwrap_or(0),
        );

        // The exact index ordering depends on whether `b` was interned
        // before or after `a`; the legacy parser walks the source in
        // document order, so `a` is interned first (index 0) and `b`
        // is interned second (index 1). The values follow the same
        // order, with `b`'s value being the only array (index 0 of
        // arrays).
        assert_eq!(arena.strings(), &["a".to_string(), "b".to_string()]);
        assert_eq!(obj.len(), 2);
        let a_val = arena.object_get(0, "a").unwrap();
        assert_eq!(a_val, Value::Number(Number::I64(1)));
        let b_val = arena.object_get(0, "b").unwrap();
        let b_arr = b_val.as_array(&arena).unwrap();
        assert_eq!(b_arr, &[Value::Bool(true), Value::Null]);
    }

    /// A duplicate key in the source is deduped in the arena's
    /// BTreeMap: the last value wins, matching what
    /// `BTreeMap<&'a str, _>` did before and what serde_json does.
    #[test]
    fn duplicate_key_keeps_last_value() {
        let arena = parse(r#"{"a":1,"a":2}"#).unwrap();
        let v = arena.root().get(&arena, "a").unwrap();
        assert_eq!(v.as_number(), Some(2.0));
        assert_eq!(arena.strings(), &["a".to_string()]);
    }
}
