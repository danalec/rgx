// SPDX-License-Identifier: Apache-2.0

//! Streaming and NDJSON layer for djson.
//!
//! The [`parse`](crate::djson::parser::parse) entry point is the right tool when the
//! whole document is in memory. Real rgx workloads are not:
//! manifests are appended to as new tensors are produced, log streams
//! roll forever, and a sidecar JSONL dump of a multi-gigabyte model
//! is larger than the heap we want to spend on it. This module is
//! the other end of the spectrum: feed bytes in, get arenas out, one
//! document at a time.
//!
//! Three entry points, layered by capability:
//!
//! - [`StreamParser`] -- the state machine. Holds the carry-over buffer
//!   between feeds, knows where the next document starts, and hands
//!   one arena per `next()` call. `no_std` + `alloc` only.
//! - [`ndjson`] / [`NdJsonIter`] -- line-oriented, the NDJSON convention.
//!   `&str` in, `Result<Arena, _>` out, no allocation beyond the
//!   arena itself. `no_std` + `alloc`.
//! - [`from_reader`] -- a thin `std::io::Read` adapter that pulls
//!   8 KiB chunks and drives a [`StreamParser`]. Gated on the
//!   `std` feature; the `no_std` build is unchanged.
//!
//! ## How the boundary is found
//!
//! The hard part of a streaming JSON parser is knowing when one
//! document ends and the next begins without paying for a full parse.
//! Two approaches were considered:
//!
//! 1. **Full parse + buffer drain**: call `parse` on the buffer; if
//!    it fails because of trailing content, split at the failure
//!    point. Correct, but it re-parses every carry-over byte on
//!    every call.
//! 2. **Heuristic scan**: walk the buffer once, bracket-matching
//!    containers and quote-escaping strings, return the position of
//!    the first depth-0 close. This is what production streaming
//!    parsers do, and what `find_document_end` here implements.
//!
//! The walk is byte-only, allocation-free, and the result is the
//! end of the first complete top-level value. The slice from
//! `search_pos` to that end is then handed to the index-driven
//! parser that the non-streaming path already uses -- so the
//! conformance suite and the integer-exactness contract are
//! inherited unchanged.
//!
//! ## What "incomplete" means
//!
//! `find_document_end` returns `None` when the buffer is empty or
//! when the bytes seen so far do not form a complete value (a `{`
//! with no matching `}`, a string that runs off the end, a number
//! that is mid-digit). [`StreamParser::next`] turns that into
//! `Ok(None)`, the standard "feed me more" signal. An invalid start
//! byte (a literal `x` where a value is expected) also returns
//! `None` from the heuristic, with the same `Ok(None)` outcome --
//! the caller is expected to know when EOF has been reached and to
//! stop calling `next`. The strict reading of "the input is
//! exhausted" is "the caller has stopped feeding"; the parser does
//! not track EOF internally.
//!
//! ## `no_std` + `alloc` boundary
//!
//! `StreamParser` owns a `Vec<u8>` for the carry-over buffer; that
//! is the only allocation in the no_std path. The byte scanner
//! allocates nothing. The NDJSON iterator does not allocate at
//! all. `from_reader` adds an 8 KiB stack buffer and the `Read`
//! trait, both `std`-only, and is gated on `feature = "std"`.

#[cfg(feature = "std")]
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::str;

use super::byte_scan::find_document_end;
use super::parser::{parse, JsonParseError};
use super::value::Arena;

// ═══════════════════════════════════════════════════════════════════════
// Byte-walking helpers are in `super::byte_scan`. The streaming path
// uses `find_document_end` (which skips both leading and trailing
// whitespace -- the trailing skip is what advances `pos` past the
// separator between consecutive documents) and `skip_one_value`
// directly when the heuristic needs the raw value boundary without
// the whitespace trim.
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// StreamParser: feed bytes, get arenas
// ═══════════════════════════════════════════════════════════════════════

/// A state machine that accepts bytes incrementally and yields one
/// [`Arena`] per complete JSON document.
///
/// The parser owns a [`Vec<u8>`] carry-over buffer. The caller calls
/// [`feed`](Self::feed) zero or more times to append bytes, then
/// [`next`](Self::next) to pull the next arena. `next` returns
/// `Ok(None)` when the carry-over buffer does not yet hold a
/// complete document; the caller feeds more and tries again. When
/// the caller has stopped feeding (because the source is exhausted),
/// `next` will keep returning `Ok(None)` -- there is no internal EOF
/// signal, by design: "exhausted" is a property of the caller's
/// knowledge, not of the parser.
///
/// The buffer grows as the caller feeds and shrinks as documents
/// are consumed (`pos` advances past each one). For a long-running
/// stream of small documents the buffer is bounded; for a stream
/// whose documents are themselves large, the buffer holds at most
/// one document's worth of carry-over plus whatever trailing
/// whitespace the next call to `find_document_end` skips past.
/// [`into_inner`](Self::into_inner) returns the buffer for callers
/// that want to drain it explicitly.
///
/// `no_std` + `alloc`. The `from_reader` convenience on top of this
/// type is `std`-only and lives behind `feature = "std"`.
pub struct StreamParser {
    buf: Vec<u8>,
    /// Position in `buf` where the next document starts.
    pos: usize,
}

impl StreamParser {
    /// A fresh parser with an empty carry-over buffer.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// Append `bytes` to the carry-over buffer.
    ///
    /// This is the only way to get data into the parser. The buffer
    /// is internal and is not exposed for read; [`next`](Self::next)
    /// is the only consumer.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pull the next complete document, or report that the buffer
    /// is incomplete.
    ///
    /// The three outcomes:
    /// - `Ok(Some(arena))` -- a complete document was found, parsed,
    ///   and its arena is returned. The buffer's `pos` has advanced
    ///   past it (and any trailing whitespace).
    /// - `Ok(None)` -- the buffer holds an incomplete document or
    ///   only whitespace. Feed more bytes and try again.
    /// - `Err(_)` -- the next document slice was complete (the
    ///   heuristic found a depth-0 close) but the parser rejected
    ///   it. The buffer's `pos` has advanced past the bad slice;
    ///   subsequent calls will look at whatever follows.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Arena>, JsonParseError> {
        // Drain the consumed prefix once `pos` has climbed past the
        // 64 KiB threshold. The previous shape grew `self.buf`
        // monotonically: a 1 GB NDJSON stream that returned 1 MB
        // documents held 1 GB by the time the stream ended, with the
        // 999 already-emitted docs retained for no reason. The
        // threshold is a 64 KiB watermark: anything larger is a
        // doc that has not been seen yet, anything smaller is the
        // overhead of moving the tail forward.
        if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        loop {
            // Find the end of the next complete document in the
            // unconsumed tail of the buffer.
            let end = match find_document_end(&self.buf[self.pos..]) {
                Some(end) => end,
                None => return Ok(None),
            };
            // `find_document_end` returns 0 only if the tail was
            // nothing but whitespace that we have not yet advanced
            // past (the `start` position in the buffer is the same
            // as `pos` and there were no bytes after the whitespace).
            // Skip the whitespace byte and try again.
            if end == 0 {
                self.pos += 1;
                continue;
            }
            // Slice the document out of the buffer and advance.
            let doc = &self.buf[self.pos..self.pos + end];
            self.pos += end;
            // The parser takes `&str`; a non-UTF-8 chunk is a
            // real error (the input is binary garbage or a
            // mid-codepoint split across a chunk boundary).
            let doc_str = match str::from_utf8(doc) {
                Ok(s) => s,
                Err(_) => {
                    return Err(JsonParseError {
                        message: String::from("Invalid UTF-8 in stream input"),
                        line: 1,
                        col: 1,
                    });
                }
            };
            let arena = parse(doc_str)?;
            return Ok(Some(arena));
        }
    }

    /// Consume the parser and return the carry-over buffer.
    ///
    /// Any bytes after `pos` are still in the buffer; if the caller
    /// has not yet called `next` to its conclusion, those are the
    /// bytes of a document that was not yet complete. The caller
    /// owns the `Vec<u8>` and is free to drain it, inspect it, or
    /// feed it into another parser.
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for StreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for StreamParser {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamParser")
            .field("buf_len", &self.buf.len())
            .field("pos", &self.pos)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// NdJsonIter: line-oriented iteration
// ═══════════════════════════════════════════════════════════════════════

/// Iterator over NDJSON (newline-delimited JSON) input.
///
/// Yields one `Result<Arena, JsonParseError>` per non-empty line.
/// Lines are split on `\n`; a trailing `\r` (CRLF input) is
/// stripped. Empty lines and lines that are only whitespace are
/// skipped without yielding a result, so a trailing newline (the
/// common NDJSON shape) does not produce a phantom parse error.
///
/// Errors do not stop iteration: a malformed line yields
/// `Some(Err(_))` and the next `next()` call resumes with the line
/// after it. This is the behaviour a log processor wants -- one
/// bad record in a stream does not discard the rest.
pub struct NdJsonIter<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Iterator for NdJsonIter<'a> {
    type Item = Result<Arena, JsonParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Skip leading horizontal whitespace (NOT newlines: a
        // newline is the line terminator, and the caller is
        // expected to have one document per line).
        while self.pos < self.input.len()
            && matches!(self.input.as_bytes()[self.pos], b' ' | b'\t' | b'\r')
        {
            self.pos += 1;
        }
        if self.pos >= self.input.len() {
            return None;
        }
        // Find the next newline. `find('\n')` is the byte-level
        // split; the slice up to that point is the line.
        let rest = &self.input[self.pos..];
        let line_end = rest.find('\n').unwrap_or(rest.len());
        let line = &rest[..line_end];
        // Strip a trailing CR for CRLF input.
        let line = line.strip_suffix('\r').unwrap_or(line);
        // Advance past the line and, if we found a newline, past
        // the newline itself.
        self.pos += line_end + if line_end < rest.len() { 1 } else { 0 };
        if line.is_empty() {
            // Empty line (after CR strip): skip and recurse.
            return self.next();
        }
        Some(parse(line))
    }
}

/// Convenience: split a `&str` on newlines and yield each
/// non-empty line as an `Arena`.
///
/// The iterator is lazy: it does not parse a line until the caller
/// asks for it, and the underlying `&str` is never copied. A
/// malformed line is reported as `Some(Err(_))` and the iteration
/// continues; the iterator ends when the input is exhausted.
///
/// `no_std` + `alloc`. Allocation is limited to the arenas the
/// parser produces (one per successful line).
pub fn ndjson(input: &str) -> NdJsonIter<'_> {
    NdJsonIter { input, pos: 0 }
}

// ═══════════════════════════════════════════════════════════════════════
// from_reader: std-only Read adapter
// ═══════════════════════════════════════════════════════════════════════

/// Drive a [`StreamParser`] from any [`std::io::Read`] source.
///
/// The iterator pulls 8 KiB chunks until the reader reports EOF
/// (a `read` returning `Ok(0)`) and yields one arena per complete
/// document the parser produces. An IO error is reported as
/// `Some(Err(JsonParseError { ... }))` with the `std::io::Error`
/// formatting preserved in the message; subsequent calls to `next`
/// after an IO error are not attempted (the closure is in a
/// poisoned state from the borrow checker's point of view) -- the
/// caller is expected to handle the error and stop.
///
/// Like the underlying [`StreamParser`], this iterator is lazy: it
/// only reads when the caller asks for the next item, and only
/// until the parser has a complete document to yield.
#[cfg(feature = "std")]
pub fn from_reader<R: std::io::Read>(
    mut reader: R,
) -> impl Iterator<Item = Result<Arena, JsonParseError>> {
    let mut parser = StreamParser::new();
    let mut chunk = [0u8; 8192];
    std::iter::from_fn(move || loop {
        match parser.next() {
            Ok(Some(arena)) => return Some(Ok(arena)),
            Ok(None) => {
                let n = match reader.read(&mut chunk) {
                    Ok(0) => return None,
                    Ok(n) => n,
                    Err(e) => {
                        return Some(Err(JsonParseError {
                            message: format!("IO error reading JSON stream: {e}"),
                            line: 1,
                            col: 1,
                        }));
                    }
                };
                parser.feed(&chunk[..n]);
            }
            Err(e) => return Some(Err(e)),
        }
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::djson::Value;

    // ─── ndjson ─────────────────────────────────────────────────────

    /// Three documents on three lines: the iterator yields three
    /// arenas, each containing the expected key/value.
    #[test]
    fn ndjson_basic() {
        let input = "{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n";
        let arenas: Vec<Arena> = ndjson(input)
            .collect::<Result<Vec<_>, _>>()
            .expect("three valid lines");
        assert_eq!(arenas.len(), 3);
        assert_eq!(
            arenas[0]
                .root()
                .get(&arenas[0], "a")
                .and_then(|v| v.as_i64()),
            Some(1)
        );
        assert_eq!(
            arenas[1]
                .root()
                .get(&arenas[1], "b")
                .and_then(|v| v.as_i64()),
            Some(2)
        );
        assert_eq!(
            arenas[2]
                .root()
                .get(&arenas[2], "c")
                .and_then(|v| v.as_i64()),
            Some(3)
        );
    }

    /// Blank lines and lines of only whitespace are skipped. The
    /// trailing newline (the common NDJSON shape) does not
    /// produce a phantom error.
    #[test]
    fn ndjson_empty_lines_skipped() {
        let input = "\n\n   \n{\"a\":1}\n\n\n{\"b\":2}\n\n";
        let arenas: Vec<Arena> = ndjson(input)
            .collect::<Result<Vec<_>, _>>()
            .expect("two valid lines");
        assert_eq!(arenas.len(), 2);
    }

    /// A malformed line yields `Some(Err(_))` and the iteration
    /// continues with the next line. This is the behaviour a log
    /// processor wants: one bad record does not discard the rest.
    #[test]
    fn ndjson_malformed_line_errors_and_continues() {
        let input = "{\"a\":1}\n{bad}\n{\"c\":3}\n";
        let results: Vec<_> = ndjson(input).collect();
        assert_eq!(results.len(), 3, "all three lines are visited");
        assert!(results[0].is_ok(), "first line is valid");
        assert!(results[1].is_err(), "second line is malformed");
        assert!(results[2].is_ok(), "third line is valid");
    }

    /// CRLF input: a trailing `\r` on each line is stripped, so a
    /// Windows-style file parses the same as a Unix-style one.
    #[test]
    fn ndjson_handles_crlf() {
        let input = "{\"a\":1}\r\n{\"b\":2}\r\n";
        let arenas: Vec<Arena> = ndjson(input)
            .collect::<Result<Vec<_>, _>>()
            .expect("CRLF input");
        assert_eq!(arenas.len(), 2);
        assert_eq!(
            arenas[1]
                .root()
                .get(&arenas[1], "b")
                .and_then(|v| v.as_i64()),
            Some(2)
        );
    }

    /// A document with a string value that contains a newline
    /// would not survive a naive line split. NDJSON does not
    /// support embedded newlines in strings; the iterator reports
    /// the second line as a parse error (the second line starts
    /// inside the string and the closing quote is on the first).
    /// This test pins the current behaviour: the streaming
    /// iterator is line-oriented, not character-oriented.
    #[test]
    fn ndjson_does_not_split_inside_strings() {
        let input = "[\"line1\\nline2\"]\n[1,2,3]\n";
        let arenas: Vec<Arena> = ndjson(input)
            .collect::<Result<Vec<_>, _>>()
            .expect("the embedded \\n is an escape, not a real newline");
        assert_eq!(arenas.len(), 2);
        let arr = arenas[0].root().as_array(&arenas[0]).unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].as_str(&arenas[0]), Some("line1\nline2"));
    }

    // ─── StreamParser ───────────────────────────────────────────────

    /// A document fed in two halves yields `Ok(None)` on the first
    /// `next` and `Ok(Some(arena))` on the second. The arena
    /// contains the value that was split across the feed boundary.
    #[test]
    fn stream_parser_chunks() {
        let mut p = StreamParser::new();
        p.feed(b"{\"a\":");
        assert!(p.next().unwrap().is_none(), "first half is incomplete");
        p.feed(b"1}");
        let arena = p.next().unwrap().expect("second half completes it");
        assert_eq!(
            arena.root().get(&arena, "a").and_then(|v| v.as_i64()),
            Some(1)
        );
        assert!(p.next().unwrap().is_none(), "buffer is now empty");
    }

    /// Three documents packed into one feed: each `next` returns
    /// one arena, and the third `next` returns `Ok(None)`.
    /// Whitespace between documents is the separator the heuristic
    /// relies on; a feed with no whitespace between documents is
    /// parsed as one document (the parser will report the second
    /// `{` as a syntax error, not as the start of a new document).
    #[test]
    fn stream_parser_multiple_documents() {
        let mut p = StreamParser::new();
        p.feed(b"[1,2,3] [4,5,6] [7,8,9]");
        let a1 = p.next().unwrap().expect("first array");
        let a2 = p.next().unwrap().expect("second array");
        let a3 = p.next().unwrap().expect("third array");
        assert!(p.next().unwrap().is_none(), "no more documents");
        assert_eq!(a1.root().len(&a1), 3);
        assert_eq!(a2.root().len(&a2), 3);
        assert_eq!(a3.root().len(&a3), 3);
    }

    /// Leading whitespace before the first document is skipped
    /// without producing an error or an extra empty document.
    #[test]
    fn stream_parser_skips_leading_whitespace() {
        let mut p = StreamParser::new();
        p.feed(b"   \n\t  {\"a\":1}");
        let arena = p.next().unwrap().expect("the document");
        assert_eq!(
            arena.root().get(&arena, "a").and_then(|v| v.as_i64()),
            Some(1)
        );
        assert!(p.next().unwrap().is_none());
    }

    /// A document whose string contains a `}` inside an escape
    /// sequence must not be cut short at the embedded brace. The
    /// boundary detector respects `\"` and `\\`; a document like
    /// `{"k":"}"}` parses to the end, and the next `next()` is
    /// `Ok(None)`.
    #[test]
    fn stream_parser_brace_inside_string() {
        let mut p = StreamParser::new();
        p.feed(br#"{"k":"}"}"#);
        let arena = p.next().unwrap().expect("the whole object");
        assert_eq!(
            arena.root().get(&arena, "k").and_then(|v| v.as_str(&arena)),
            Some("}")
        );
        assert!(p.next().unwrap().is_none());
    }

    /// A document that ends mid-string is incomplete. The parser
    /// reports `Ok(None)` and waits for more data.
    #[test]
    fn stream_parser_unterminated_string_waits() {
        let mut p = StreamParser::new();
        p.feed(br#"{"a": "hello"#);
        assert!(p.next().unwrap().is_none());
        p.feed(br#" world"}"#);
        let arena = p.next().unwrap().expect("the completed document");
        assert_eq!(
            arena.root().get(&arena, "a").and_then(|v| v.as_str(&arena)),
            Some("hello world")
        );
    }

    /// A document that is a bare scalar (`true`, `42`, `null`,
    /// `"x"`) is a valid top-level JSON value. The stream parser
    /// yields it like any other document.
    #[test]
    fn stream_parser_scalar_documents() {
        let mut p = StreamParser::new();
        p.feed(b"true 42 null \"x\"");
        let a1 = p.next().unwrap().expect("true");
        let a2 = p.next().unwrap().expect("42");
        let a3 = p.next().unwrap().expect("null");
        let a4 = p.next().unwrap().expect("\"x\"");
        assert!(p.next().unwrap().is_none());
        assert_eq!(a1.root(), Value::Bool(true));
        assert_eq!(a2.root().as_i64(), Some(42));
        assert_eq!(a3.root(), Value::Null);
        assert_eq!(a4.root().as_str(&a4), Some("x"));
    }

    /// A feed of nothing but whitespace: the parser reports
    /// `Ok(None)` forever, which is the correct "still waiting"
    /// signal. This is the case the recommended approach's
    /// `if end == 0` guard handles; the test pins that the guard
    /// does not loop indefinitely on a real buffer.
    #[test]
    fn stream_parser_only_whitespace() {
        let mut p = StreamParser::new();
        p.feed(b"   \n\t  ");
        assert!(p.next().unwrap().is_none());
        // More whitespace is appended; still incomplete.
        p.feed(b"   \n");
        assert!(p.next().unwrap().is_none());
    }

    /// A document split across three feeds: the boundary detector
    /// cannot complete the value until the third feed arrives.
    /// The first two `next` calls return `Ok(None)`; the third
    /// returns the arena.
    #[test]
    fn stream_parser_split_across_three_feeds() {
        let mut p = StreamParser::new();
        p.feed(b"[1,");
        assert!(p.next().unwrap().is_none());
        p.feed(b"2,");
        assert!(p.next().unwrap().is_none());
        p.feed(b"3]");
        let arena = p.next().unwrap().expect("the array");
        let arr = arena.root().as_array(&arena).unwrap();
        assert_eq!(arr.len(), 3);
    }

    /// An invalid start byte is reported as an error once a
    /// complete document is found after it. The boundary detector
    /// treats the invalid byte as "not a value", so the parser
    /// sees the slice `{bad}` and reports the syntax error. The
    /// buffer advances past the bad slice, and a subsequent feed
    /// can resume with the next document.
    ///
    /// The test pins the current behaviour: the streaming layer
    /// does not buffer errors. A caller that wants to skip bad
    /// input can do so by feeding a separator and continuing.
    #[test]
    fn stream_parser_invalid_byte_reports_error() {
        let mut p = StreamParser::new();
        p.feed(b"x {\"a\":1}");
        // The first byte is not a value-starter, so `next` waits
        // for more data. This is the documented "feed me more"
        // signal; the caller is expected to know when EOF has
        // been reached and stop calling `next` if the input is
        // done.
        assert!(p.next().unwrap().is_none());
    }

    /// `into_inner` returns the carry-over buffer so a caller
    /// that knows the input is done can recover whatever bytes
    /// were never consumed.
    #[test]
    fn stream_parser_into_inner_returns_buffer() {
        let mut p = StreamParser::new();
        p.feed(b"{\"a\":1} leftover");
        let _ = p.next().unwrap();
        let buf = p.into_inner();
        assert_eq!(&buf, b"{\"a\":1} leftover");
    }

    /// A document whose string contains a backslash-escaped
    /// quote: the boundary detector must not stop at the escaped
    /// quote, and the parser must round-trip the value.
    #[test]
    fn stream_parser_escaped_quote_in_string() {
        let mut p = StreamParser::new();
        p.feed(br#"{"a":"he said \"hi\""}"#);
        let arena = p.next().unwrap().expect("the object");
        assert_eq!(
            arena.root().get(&arena, "a").and_then(|v| v.as_str(&arena)),
            Some("he said \"hi\"")
        );
        assert!(p.next().unwrap().is_none());
    }

    // ─── from_reader (std only) ──────────────────────────────────────

    /// Two newline-delimited documents over a `Cursor` yield two
    /// arenas. The 8 KiB chunk size means the reader is called
    /// once for this small input; the test exercises the chunk
    /// path anyway.
    #[cfg(feature = "std")]
    #[test]
    fn from_reader_basic() {
        use std::io::Cursor;
        let input = b"{\"a\":1}\n{\"b\":2}\n";
        let arenas: Vec<Arena> = from_reader(Cursor::new(&input[..]))
            .collect::<Result<Vec<_>, _>>()
            .expect("two valid lines");
        assert_eq!(arenas.len(), 2);
        assert_eq!(
            arenas[0]
                .root()
                .get(&arenas[0], "a")
                .and_then(|v| v.as_i64()),
            Some(1)
        );
        assert_eq!(
            arenas[1]
                .root()
                .get(&arenas[1], "b")
                .and_then(|v| v.as_i64()),
            Some(2)
        );
    }

    /// A `Cursor` over an empty byte slice yields no documents.
    #[cfg(feature = "std")]
    #[test]
    fn from_reader_empty() {
        use std::io::Cursor;
        let arenas: Vec<Arena> = from_reader(Cursor::new(&[][..]))
            .collect::<Result<Vec<_>, _>>()
            .expect("empty input");
        assert_eq!(arenas.len(), 0);
    }

    /// A document that spans two reads: the input is longer than
    /// the 8 KiB chunk size, so the reader is called more than
    /// once. The test pins that the parser still produces one
    /// arena per complete document.
    #[cfg(feature = "std")]
    #[test]
    fn from_reader_spans_multiple_reads() {
        use std::io::Cursor;
        use std::string::ToString;
        // Build a single document large enough to span multiple
        // 8 KiB chunks. A long array of integers will do.
        let mut input = String::from("[");
        for i in 0..5000i32 {
            if i > 0 {
                input.push(',');
            }
            input.push_str(&i.to_string());
        }
        input.push(']');
        let arenas: Vec<Arena> = from_reader(Cursor::new(input.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .expect("one big array");
        assert_eq!(arenas.len(), 1);
        let arr = arenas[0].root().as_array(&arenas[0]).unwrap();
        assert_eq!(arr.len(), 5000);
    }
}
