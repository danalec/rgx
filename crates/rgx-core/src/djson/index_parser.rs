// SPDX-License-Identifier: Apache-2.0

//! Stage 2 of the djson two-stage parser: walks the structural index and
//! populates an [`Arena`].
//!
//! The scanner (`super::json_scan`) already produced two bitsets saying
//! which bytes of the document are structural (`{ } [ ] : ,` and
//! whitespace outside strings) and which are string-delimiter quotes.
//! This stage uses those bitsets to find token boundaries without
//! re-scanning the document character by character.
//!
//! The legacy parser walked the input one `char` at a time. The
//! scanner has already done that walk; the work this stage replaces
//! is the *interpretation* -- closing quote, next comma, end of
//! number, the matching `}` -- and every one of those is a question
//! about a known structural position rather than a scan.
//!
//! `no_std` + `alloc`. The walker holds two sorted `Vec<usize>`
//! snapshots of the bitset iterations (one for structural, one for
//! quotes) and a current byte offset; everything is `&[u8]`, the
//! allocation budget is one `String` per parsed string literal and one
//! per container slot in the arena, the same as the legacy parser.
//! There is no `Box::leak`: object keys are interned into the arena's
//! string table and the BTreeMap's key type is `usize`.
use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::str;

use super::json_scan::{self, StructuralIndex};
use super::parser::JsonParseError;
use super::value::{Arena, Number, Value};
use crate::NoStdFloat;

/// Nesting limit: a document deeper than this is rejected.
///
/// serde_json's default is 128; without a limit, `[[[[...` is a stack
/// overflow (an abort, not a catchable error) for a search tool handed
/// hostile input. The check runs on container OPENERS only -- a value
/// sitting inside the deepest of them is the thing the innermost
/// container holds, not another level -- so a 128-deep document is
/// accepted and a 129-deep one is rejected.
const MAX_DEPTH: u32 = 128;

/// Parse `input` by walking the structural index into a fresh arena.
pub(super) fn parse_indexed(input: &str) -> Result<Arena, JsonParseError> {
    let bytes = input.as_bytes();
    let index = json_scan::scan(bytes);
    if index.end_in_string {
        return Err(error_at(bytes, 0, "Unterminated string"));
    }
    let mut arena = Arena::new();
    {
        let mut parser = Parser::new(bytes, &index, &mut arena);
        parser.skip_ws();
        if parser.pos >= bytes.len() {
            return Err(parser.error("Unexpected end of input"));
        }
        let v = parser.parse_value()?;
        parser.skip_ws();
        if parser.pos < bytes.len() {
            return Err(parser.error("Unexpected content after JSON value"));
        }
        arena.set_root(v);
    }
    Ok(arena)
}

struct Parser<'a, 'b> {
    bytes: &'a [u8],
    /// Every structural byte position, sorted ascending.
    struct_positions: Vec<usize>,
    /// Every quote (string-delimiter) byte position, sorted ascending.
    quote_positions: Vec<usize>,
    /// The next unconsumed entry in `struct_positions`.
    struct_idx: usize,
    /// The next unconsumed entry in `quote_positions`.
    quote_idx: usize,
    /// Current byte offset in the input.
    pos: usize,
    /// Current container nesting depth.
    depth: u32,
    /// The arena this parser writes into. Borrowed for `'b`, which is
    /// at least as long as the parser's own lifetime.
    arena: &'b mut Arena,
}

impl<'a, 'b> Parser<'a, 'b> {
    fn new(bytes: &'a [u8], index: &StructuralIndex, arena: &'b mut Arena) -> Self {
        Self {
            bytes,
            struct_positions: index.structural.iter_set().collect(),
            quote_positions: index.quote.iter_set().collect(),
            struct_idx: 0,
            quote_idx: 0,
            pos: 0,
            depth: 0,
            arena,
        }
    }

    fn error(&self, msg: impl Into<String>) -> JsonParseError {
        error_at(self.bytes, self.pos, msg)
    }

    /// Advance `pos` past the run of whitespace at the cursor.
    ///
    /// Whitespace is rare and the loop is four byte comparisons per
    /// step; the structural index would be slower here (it would
    /// still touch every whitespace byte, only to check the same
    /// thing twice).
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    /// The next structural position strictly after `self.pos`.
    ///
    /// Returns `None` when the input is exhausted. Advances
    /// `struct_idx` past everything at or before the current cursor
    /// so a subsequent call resumes at the next unseen position.
    fn next_structural_after(&mut self) -> Option<usize> {
        while let Some(&p) = self.struct_positions.get(self.struct_idx) {
            self.struct_idx += 1;
            if p > self.pos {
                return Some(p);
            }
        }
        None
    }

    /// The next quote position strictly after `self.pos`.
    fn next_quote_after(&mut self) -> Option<usize> {
        while let Some(&p) = self.quote_positions.get(self.quote_idx) {
            self.quote_idx += 1;
            if p > self.pos {
                return Some(p);
            }
        }
        None
    }

    fn parse_value(&mut self) -> Result<Value, JsonParseError> {
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return Err(self.error("Unexpected end of input"));
        }

        let b = self.bytes[self.pos];

        if (b == b'[' || b == b'{') && self.depth >= MAX_DEPTH {
            return Err(self.error("Nesting too deep"));
        }

        match b {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => self.parse_string().map(Value::String),
            b't' | b'T' => self.parse_literal(b"true", Value::Bool(true)),
            b'f' | b'F' => self.parse_literal(b"false", Value::Bool(false)),
            b'n' | b'N' => self.parse_literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(self.error(format!("Unexpected character '{}'", b as char))),
        }
    }

    fn parse_array(&mut self) -> Result<Value, JsonParseError> {
        debug_assert_eq!(self.bytes[self.pos], b'[');
        self.pos += 1;
        self.depth += 1;
        let arr_idx = self.arena.push_array();

        self.skip_ws();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b']' {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Array(arr_idx));
        }

        loop {
            let v = self.parse_value()?;
            self.arena.push_array_value(arr_idx, v);
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err(self.error("Unterminated array"));
            }
            match self.bytes[self.pos] {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Value::Array(arr_idx));
                }
                _ => return Err(self.error("Expected ',' or ']'")),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Value, JsonParseError> {
        debug_assert_eq!(self.bytes[self.pos], b'{');
        self.pos += 1;
        self.depth += 1;
        let obj_idx = self.arena.push_object();

        self.skip_ws();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'}' {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Object(obj_idx));
        }

        loop {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err(self.error("Unterminated object"));
            }
            if self.bytes[self.pos] != b'"' {
                return Err(self.error("Expected '\"'"));
            }
            let key_idx = self.parse_string()?;
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err(self.error("Unterminated object"));
            }
            if self.bytes[self.pos] != b':' {
                return Err(self.error("Expected ',' or '}'"));
            }
            self.pos += 1;
            let value = self.parse_value()?;
            // BTreeMap dedupes: a duplicate key keeps the last-seen
            // value, matching the previous design (and serde_json).
            self.arena.insert_object(obj_idx, key_idx, value);
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err(self.error("Unterminated object"));
            }
            match self.bytes[self.pos] {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Value::Object(obj_idx));
                }
                _ => return Err(self.error("Expected ',' or '}'")),
            }
        }
    }

    /// Parse a JSON string literal into the arena, returning its
    /// interned index. The plain path (no escapes, no control chars)
    /// `to_owned`s the bytes; the escape path runs `decode_string`.
    /// Either way the result is an owned `String` and lives in the
    /// arena's `strings` table -- there is no `&'input str` to leak.
    fn parse_string(&mut self) -> Result<usize, JsonParseError> {
        debug_assert_eq!(self.bytes[self.pos], b'"');
        let close = self
            .next_quote_after()
            .ok_or_else(|| self.error("Unterminated string"))?;
        let content_start = self.pos + 1;
        let content = &self.bytes[content_start..close];
        self.pos = close + 1;

        // ASCII fast path: every byte is below 0x80 AND no backslash is in
        // sight, so no escape can hide and no UTF-8 validation has to
        // run. `String::from_utf8` would walk the bytes once for the
        // validation and a second time for the copy; the unchecked path
        // is one bulk `Vec::extend_from_slice` plus an unsafe
        // `String::from_utf8_unchecked` to claim the bytes. The
        // `b == b'\\'` guard is what keeps `"a\"b"` from skipping the
        // escape decoder and printing `a\"b` literal.
        //
        // Single scan that classifies the string into one of three
        // arms -- ASCII (fast copy), escape (decode_string), or
        // UTF-8 with no escape (validated copy) -- rather than three
        // independent `iter` passes.
        let mut has_escape = false;
        let mut has_non_ascii = false;
        for &b in content {
            if b == b'\\' || b < 0x20 {
                has_escape = true;
                break;
            }
            if b >= 0x80 {
                has_non_ascii = true;
            }
        }
        let text: String = if !has_escape && !has_non_ascii {
            // SAFETY: every byte is < 0x80, no byte is a control
            // character or backslash, so the bytes are valid ASCII.
            // The scanner already rejected any unescaped C0; we re-check
            // by construction above.
            let mut buf = Vec::with_capacity(content.len());
            buf.extend_from_slice(content);
            unsafe { String::from_utf8_unchecked(buf) }
        } else if has_escape {
            decode_string(content, content_start, self.bytes)?
        } else {
            str::from_utf8(content)
                .map_err(|_| error_at(self.bytes, content_start, "Invalid UTF-8 in string"))?
                .to_owned()
        };
        Ok(self.arena.intern(text))
    }

    fn parse_literal(&mut self, needle: &[u8], value: Value) -> Result<Value, JsonParseError> {
        let end = self.next_structural_after().unwrap_or(self.bytes.len());
        let text = &self.bytes[self.pos..end];
        if text == needle {
            self.pos = end;
            Ok(value)
        } else {
            // Capitalised literals (n_115 "True", n_122 "Null") reach
            // here through the case-folded `b't'|b'T'` arm. The legacy
            // parser surfaced them as "Expected 'r', found 'R'"; both
            // are EXPECTED_VALUE in the category table, so this single
            // message keeps the differential green and matches the
            // category the dump walker keys on.
            Err(self.error(format!("Unexpected character '{}'", text[0] as char)))
        }
    }

    fn parse_number(&mut self) -> Result<Value, JsonParseError> {
        let end = self.next_structural_after().unwrap_or(self.bytes.len());
        let text = &self.bytes[self.pos..end];
        let result = parse_number_text(text).map_err(|e| JsonParseError {
            message: e,
            line: line_of(self.bytes, self.pos),
            col: col_of(self.bytes, self.pos),
        })?;
        self.pos = end;
        Ok(result)
    }
}

/// Decode the bytes between two quote positions into a `String`.
///
/// The scanner already verified the open/close pairing; the
/// remaining work is escape decoding and the unescaped-control-char
/// check. A string with no backslashes and no control characters is
/// the common case and falls through to a single `from_utf8` +
/// `String::from` -- the only allocation is the destination.
pub(super) fn decode_string(
    content: &[u8],
    content_start: usize,
    full: &[u8],
) -> Result<String, JsonParseError> {
    // Find the first byte that needs interpretation, if any. A `memchr`
    // for `\\` followed by a `memchr` for any byte < 0x20 would be
    // marginally faster, but the string-content walk below is already
    // byte-at-a-time and fuses the two scans into one pass: a plain
    // ASCII string with no escape falls straight through to the
    // `from_utf8` path the first time the loop sees it, and a string
    // with escapes reuses the position the loop already walked to.
    let first_interesting = content.iter().position(|&b| b == b'\\' || b < 0x20);
    let Some(escapes_from) = first_interesting else {
        let s = str::from_utf8(content)
            .map_err(|_| error_at(full, content_start, "Invalid UTF-8 in string"))?;
        return Ok(s.into());
    };

    let mut out = String::new();
    let mut i = escapes_from;
    let mut chunk_start = 0;
    while i < content.len() {
        let b = content[i];
        if b == b'\\' {
            if chunk_start < i {
                let chunk = str::from_utf8(&content[chunk_start..i])
                    .map_err(|_| error_at(full, content_start + i, "Invalid UTF-8 in string"))?;
                out.push_str(chunk);
            }
            if i + 1 >= content.len() {
                return Err(error_at(full, content_start + i, "Unterminated escape"));
            }
            let esc = content[i + 1];
            // The unicode arm sets `i` itself (past the hex digits or
            // past the surrogate pair), so it falls through to its own
            // chunk_start update. Every other arm consumes the escape
            // itself, so they all advance by exactly 2 bytes.
            if esc == b'u' {
                let after_escape = i + 2;
                if content.len() < after_escape + 4 {
                    return Err(error_at(
                        full,
                        content_start + i,
                        "Incomplete unicode escape",
                    ));
                }
                let hex = match str::from_utf8(&content[after_escape..after_escape + 4]) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(error_at(full, content_start + i, "Invalid unicode escape"));
                    }
                };
                let cp = u32::from_str_radix(hex, 16).map_err(|_| {
                    error_at(full, content_start + after_escape, "Invalid hex digit")
                })?;
                if let Some(c) = char::from_u32(cp) {
                    out.push(c);
                    i = after_escape + 4;
                    chunk_start = i;
                } else if (0xD800..=0xDFFF).contains(&cp) {
                    // Surrogate pair: the high half is in
                    // 0xD800..=0xDBFF; the low half must follow as
                    // \uDC00..\uDFFF or the string is malformed.
                    if !(0xD800..=0xDBFF).contains(&cp) {
                        return Err(error_at(full, content_start + i, "Invalid high surrogate"));
                    }
                    if content.len() < after_escape + 4 + 6
                        || content[after_escape + 4] != b'\\'
                        || content[after_escape + 5] != b'u'
                    {
                        return Err(error_at(full, content_start + i, "Expected low surrogate"));
                    }
                    let lo_hex = match str::from_utf8(&content[after_escape + 6..after_escape + 10])
                    {
                        Ok(s) => s,
                        Err(_) => {
                            return Err(error_at(
                                full,
                                content_start + i,
                                "Invalid unicode escape",
                            ));
                        }
                    };
                    let lo = u32::from_str_radix(lo_hex, 16).map_err(|_| {
                        error_at(full, content_start + after_escape + 6, "Invalid hex digit")
                    })?;
                    if !(0xDC00..=0xDFFF).contains(&lo) {
                        return Err(error_at(full, content_start + i, "Invalid low surrogate"));
                    }
                    let full_cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    match char::from_u32(full_cp) {
                        Some(c) => out.push(c),
                        None => {
                            return Err(error_at(
                                full,
                                content_start + i,
                                "Invalid surrogate pair",
                            ));
                        }
                    }
                    i = after_escape + 10;
                    chunk_start = i;
                } else {
                    return Err(error_at(
                        full,
                        content_start + i,
                        "Invalid unicode codepoint",
                    ));
                }
                continue;
            }
            match esc {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000C}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                other => {
                    return Err(error_at(
                        full,
                        content_start + i,
                        format!("Invalid escape \\{}", other as char),
                    ));
                }
            }
            i += 2;
            chunk_start = i;
        } else if b < 0x20 {
            return Err(error_at(
                full,
                content_start + i,
                "Unescaped control character in string",
            ));
        } else {
            i += 1;
        }
    }
    if chunk_start < content.len() {
        let chunk = str::from_utf8(&content[chunk_start..])
            .map_err(|_| error_at(full, content_start + chunk_start, "Invalid UTF-8 in string"))?;
        out.push_str(chunk);
    }
    Ok(out)
}

/// Parse a number from the byte slice that the structural index
/// identified as a single number token. The slice is ASCII by
/// construction (JSON numbers only use `-`, `0..=9`, `.`, `e`, `E`,
/// `+`); the `from_utf8` is for the borrow, not a validation step.
pub(super) fn parse_number_text(text: &[u8]) -> Result<Value, String> {
    // The caller passes a sub-slice of an already-validated UTF-8 document,
    // so the bytes are themselves valid and the `str::from_utf8` round-trip
    // only re-checks work the scanner already paid for. Branch on the first
    // byte and track `has_dot` / `has_exp` inline so the second pass over
    // the same bytes goes away.
    let bytes = text;
    let mut i = 0usize;
    let mut has_dot = false;
    let mut has_exp = false;

    if i < bytes.len() && bytes[i] == b'-' {
        i += 1;
    }

    match bytes.get(i).copied() {
        Some(b'0') => {
            i += 1;
            if let Some(c) = bytes.get(i).copied() {
                if c.is_ascii_digit() {
                    return Err("Leading zero not allowed".into());
                }
            }
        }
        Some(c) if c.is_ascii_digit() => {
            while let Some(c) = bytes.get(i).copied() {
                if c.is_ascii_digit() {
                    i += 1;
                } else {
                    break;
                }
            }
        }
        Some(_) => return Err("Invalid number".into()),
        None => return Err("Incomplete number".into()),
    }

    if i < bytes.len() && bytes[i] == b'.' {
        has_dot = true;
        i += 1;
        let frac_start = i;
        while let Some(c) = bytes.get(i).copied() {
            if c.is_ascii_digit() {
                i += 1;
            } else {
                break;
            }
        }
        if i == frac_start {
            return Err("Expected digits after decimal point".into());
        }
    }

    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        has_exp = true;
        i += 1;
        if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
            i += 1;
        }
        let exp_start = i;
        while let Some(c) = bytes.get(i).copied() {
            if c.is_ascii_digit() {
                i += 1;
            } else {
                break;
            }
        }
        if i == exp_start {
            return Err("Expected digits in exponent".into());
        }
    }

    // Integer syntax parses exactly (I64/U64); a fraction, an
    // exponent, or an out-of-range magnitude falls back to f64.
    // This is what keeps 9007199254740993 intact instead of
    // silently becoming 9007199254740992 (serde_json parity).
    let s = unsafe { core::str::from_utf8_unchecked(text) };
    if !has_dot && !has_exp {
        if let Ok(n) = s.parse::<i64>() {
            return Ok(Value::Number(Number::I64(n)));
        }
        if let Ok(n) = s.parse::<u64>() {
            return Ok(Value::Number(Number::U64(n)));
        }
    }

    let n: f64 = NoStdFloat::parse(s).map_err(|_| "Invalid number format")?;
    if !n.is_finite() {
        return Err("Number out of range".into());
    }

    Ok(Value::num(n))
}

/// Build a `JsonParseError` anchored at `pos` and compute the
/// line/column from the byte offset.
///
/// The walk is `O(pos)` per call; errors are rare and the walk
/// dominates nothing. The alternative is to thread line/col
/// through every parser state, which the legacy parser paid for
/// because it had no index to anchor on.
pub(super) fn error_at(bytes: &[u8], pos: usize, msg: impl Into<String>) -> JsonParseError {
    JsonParseError {
        message: msg.into(),
        line: line_of(bytes, pos),
        col: col_of(bytes, pos),
    }
}

fn line_of(bytes: &[u8], pos: usize) -> usize {
    let end = pos.min(bytes.len());
    let mut line = 1;
    for &b in &bytes[..end] {
        if b == b'\n' {
            line += 1;
        }
    }
    line
}

fn col_of(bytes: &[u8], pos: usize) -> usize {
    let end = pos.min(bytes.len());
    let mut col = 1;
    for &b in &bytes[..end] {
        if b == b'\n' {
            col = 1;
        } else {
            col += 1;
        }
    }
    col
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::djson::parse;

    #[test]
    fn number_text_parses_integers() {
        assert_eq!(
            parse_number_text(b"0").unwrap(),
            Value::Number(Number::I64(0))
        );
        assert_eq!(
            parse_number_text(b"42").unwrap(),
            Value::Number(Number::I64(42))
        );
        assert_eq!(
            parse_number_text(b"9007199254740993").unwrap(),
            Value::Number(Number::I64(9007199254740993))
        );
        assert_eq!(
            parse_number_text(b"-9223372036854775808").unwrap(),
            Value::Number(Number::I64(i64::MIN))
        );
        assert_eq!(
            parse_number_text(b"18446744073709551615").unwrap(),
            Value::Number(Number::U64(u64::MAX))
        );
    }

    #[test]
    fn number_text_rejects_leading_zero() {
        assert!(parse_number_text(b"01").is_err());
        assert!(parse_number_text(b"-01").is_err());
    }

    #[test]
    fn number_text_rejects_overflow() {
        assert!(parse_number_text(b"1e400").is_err());
    }

    #[test]
    fn decode_string_plain_ascii() {
        let bytes = b"hello world";
        let s = decode_string(bytes, 0, bytes).unwrap();
        assert_eq!(s, "hello world");
    }

    #[test]
    fn decode_string_with_escapes() {
        let bytes = b"hello\\nworld";
        let s = decode_string(bytes, 0, bytes).unwrap();
        assert_eq!(s, "hello\nworld");
    }

    #[test]
    fn decode_string_surrogate_pair() {
        let bytes = b"\\uD83D\\uDE00";
        let s = decode_string(bytes, 0, bytes).unwrap();
        assert_eq!(s, "\u{1F600}");
    }

    /// The intern check on the parser side: a key whose source has no
    /// escapes goes through the plain path and still ends up in the
    /// arena's string table.
    #[test]
    fn plain_string_literal_is_interned() {
        let arena = parse(r#"{"abc":1}"#).unwrap();
        assert_eq!(arena.strings(), &["abc".to_string()]);
    }

    /// The intern check on the escaped path: an escaped key is decoded
    /// by `decode_string` and ends up in the arena's string table.
    /// This is the case the previous step had to `Box::leak` for, and
    /// is the reason the arena owns strings.
    #[test]
    fn escaped_key_is_interned_without_leak() {
        let arena = parse(r#"{"a\"b":1}"#).unwrap();
        assert_eq!(arena.strings(), &[r#"a"b"#.to_string()]);
    }
}
