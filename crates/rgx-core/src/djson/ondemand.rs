// SPDX-License-Identifier: Apache-2.0

//! Lazy (on-demand) JSON views over the Stage-1 structural index.
//!
//! [`super::index_parser`] walks the same index to materialise a whole
//! document into an [`Arena`](super::value::Arena). This module walks it
//! to answer questions instead: what is under key `"dtype"`, what are
//! the elements of this array, what does this subtree look like as
//! compact JSON. A value the caller never touches is never decoded,
//! interned or inserted into a map -- the cost the Arena pays per
//! string, per object slot and per array element disappears.
//!
//! Three contracts make this a drop-in companion of the Arena parser
//! rather than a second, softer parser:
//!
//! * **Full validation, once, at the root.** [`Ondemand::root`] pays
//!   one validating walk over the whole document -- string escapes,
//!   number syntax and range, literals, nesting depth, exactly as
//!   `index_parser` checks them -- and every later step navigates that
//!   validated span without re-checking. A document the Arena parser
//!   rejects, this walk rejects too, including garbage under a value
//!   the consumer never reads. The differential tests in `tests.rs`
//!   hold the two walks against each other.
//! * **Arena lookup semantics.** [`Value::find_key`] returns the
//!   *last* entry of a duplicated key, the same value
//!   [`Arena::object_get`](super::value::Arena::object_get) returns
//!   from its `BTreeMap`.
//! * **Arena iteration order on demand.** The Arena iterates an
//!   object's keys in `BTreeMap<usize, _>` order, where `usize` is the
//!   key's interned string index -- that is, order of first appearance
//!   of the key *string* anywhere in the document, not source order.
//!   [`Ondemand::first_string_positions`] computes exactly that order,
//!   so an adapter that must reproduce Arena-ordered output can.
//!
//! `no_std` + `alloc`, like the rest of the suite. Navigation is
//! stateless-ish: two monotonic cursors into the sorted structural and
//! quote positions, re-anchored by binary search whenever a walk seeks
//! backwards (the re-anchor per touched entry is one search, not one
//! per token). The allocation budget of a walk is: one `Vec<usize>`
//! pair for the Stage-1 bitset iterations (the Arena parser allocates
//! the same two), and whatever the consumer's own answers materialise.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::str;

use super::index_parser::{decode_string, error_at, parse_number_text};
use super::json_scan;
use super::parser::JsonParseError;
use super::value::{write_escaped, Number};
use crate::djson::value::Value as ArenaValue;

/// Nesting limit, mirroring `index_parser::MAX_DEPTH`: a document the
/// Arena parser calls "Nesting too deep" must fail here too, or the
/// two walks disagree on which inputs are JSON.
const MAX_DEPTH: u32 = 128;

/// A lazy cursor over one JSON document.
///
/// Built once per document ([`Ondemand::new`] runs the Stage-1 scan),
/// then handed to the consumer as a `Value` at the root.
pub struct Ondemand<'a> {
    doc: &'a [u8],
    /// Every structural byte position, sorted ascending. Quotes are
    /// structural too (the scanner's `structural` set includes them);
    /// in-string punctuation is not, which is what makes brace-counted
    /// container skips safe.
    structs: Vec<usize>,
    /// Every quote (string-delimiter) byte position, sorted ascending.
    quotes: Vec<usize>,
    /// The next unconsumed entry in `structs` (monotonic hint).
    struct_idx: usize,
    /// The next unconsumed entry in `quotes` (monotonic hint).
    quote_idx: usize,
    /// The position both hints are anchored at: everything at or
    /// before it has been consumed from both vectors. A query below it
    /// re-anchors both by binary search.
    hint_pos: usize,
    /// Current byte offset in the input.
    pos: usize,
    /// Current container nesting depth.
    depth: u32,
    /// End of the root value, recorded by [`Ondemand::root`] so
    /// [`Ondemand::finish`] can check for trailing content no matter
    /// where the consumer's walk left the cursor.
    root_end: usize,
}

impl<'a> Ondemand<'a> {
    /// Scan `input` and prepare the cursor.
    ///
    /// Rejects an unterminated string (the scanner's `end_in_string`);
    /// every other error surfaces from [`Ondemand::root`], which
    /// validates the document.
    pub fn new(input: &'a str) -> Result<Self, JsonParseError> {
        let doc = input.as_bytes();
        let index = json_scan::scan(doc);
        if index.end_in_string {
            return Err(error_at(doc, 0, "Unterminated string"));
        }
        // Reserve up front: `collect` on an un-hinted iterator would
        // grow both vectors by doubling and leave them at ~2x live.
        let mut structs = Vec::with_capacity(index.structural.count_ones());
        structs.extend(index.structural.iter_set());
        let mut quotes = Vec::with_capacity(index.quote.count_ones());
        quotes.extend(index.quote.iter_set());
        Ok(Self {
            doc,
            structs,
            quotes,
            struct_idx: 0,
            quote_idx: 0,
            hint_pos: 0,
            pos: 0,
            depth: 0,
            root_end: 0,
        })
    }

    /// Validate the document and position the cursor at its root value.
    ///
    /// The one validating walk: every token is checked exactly as
    /// `index_parser` checks it, and nothing is materialised. After
    /// this returns `Ok`, the whole document is known-good and the
    /// rest of the API navigates without re-checking. Rejects an empty
    /// document ("Unexpected end of input") like the Arena parser.
    pub fn root(&mut self) -> Result<Value<'_, 'a>, JsonParseError> {
        self.skip_ws();
        if self.pos >= self.doc.len() {
            return Err(self.error("Unexpected end of input"));
        }
        let start = self.pos;
        self.skip_value()?;
        self.root_end = self.pos;
        self.seek(start);
        Ok(Value { cur: self })
    }

    /// The trailing-content check the Arena parser folds into `parse`:
    /// after the root value only whitespace may remain. Uses the end
    /// `root` recorded, so the consumer's walk position is irrelevant.
    pub fn finish(&mut self) -> Result<(), JsonParseError> {
        self.pos = self.root_end;
        self.skip_ws();
        if self.pos < self.doc.len() {
            return Err(self.error("Unexpected content after JSON value"));
        }
        Ok(())
    }

    /// Byte position of the **first string token** whose decoded
    /// content equals each `key`, in the order the keys were given.
    ///
    /// The Arena's interned indices are assigned in first-appearance
    /// order, so sorting keys by the returned positions reproduces the
    /// `BTreeMap<usize, _>` iteration order of the Arena parser --
    /// including the cases where it is NOT source order (a key whose
    /// string first appears as an earlier value sorts earlier). A key
    /// that somehow matches no token maps to `usize::MAX` and sorts
    /// last.
    pub fn first_string_positions(&self, keys: &[&str]) -> Vec<usize> {
        let mut best: BTreeMap<&str, usize> = BTreeMap::new();
        for &k in keys {
            best.entry(k).or_insert(usize::MAX);
        }
        let total = best.len();
        let mut found = 0usize;
        for &[open, close] in self.quotes.as_chunks::<2>().0 {
            let content = &self.doc[open + 1..close];
            // A token that does not decode cannot be a key we hold,
            // which are decoded strings from this same document.
            let Ok(text) = string_content_cow(content, open + 1, self.doc) else {
                continue;
            };
            if let Some(slot) = best.get_mut(text.as_ref()) {
                if *slot == usize::MAX {
                    *slot = open;
                    found += 1;
                    if found == total {
                        break;
                    }
                }
            }
        }
        keys.iter()
            .map(|k| best.get(*k).copied().unwrap_or(usize::MAX))
            .collect()
    }

    // ---------------- cursor primitives ----------------

    fn skip_ws(&mut self) {
        while self.pos < self.doc.len() {
            match self.doc[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    /// Re-anchor both hints at `pos` (everything at or before `pos`
    /// counts as consumed).
    fn reanchor(&mut self, pos: usize) {
        self.struct_idx = self.structs.partition_point(|&p| p <= pos);
        self.quote_idx = self.quotes.partition_point(|&p| p <= pos);
        self.hint_pos = pos;
    }

    /// The next structural position strictly after `pos`. Monotonic
    /// hint, one binary search on a backwards jump.
    ///
    /// `hint_pos` is the *consumption* boundary, not the query: after
    /// a call everything at or before the returned position has been
    /// skipped, so a later query below that position must re-anchor.
    /// Anchoring at the query instead silently reuses a cursor that
    /// has already passed the answer (it made `"x" }` one string).
    fn next_structural_after(&mut self, pos: usize) -> Option<usize> {
        if pos < self.hint_pos {
            self.reanchor(pos);
        }
        while let Some(&p) = self.structs.get(self.struct_idx) {
            self.struct_idx += 1;
            if p > pos {
                self.hint_pos = p;
                return Some(p);
            }
        }
        self.hint_pos = usize::MAX;
        None
    }

    /// The next quote position strictly after `pos`.
    fn next_quote_after(&mut self, pos: usize) -> Option<usize> {
        if pos < self.hint_pos {
            self.reanchor(pos);
        }
        while let Some(&p) = self.quotes.get(self.quote_idx) {
            self.quote_idx += 1;
            if p > pos {
                self.hint_pos = p;
                return Some(p);
            }
        }
        self.hint_pos = usize::MAX;
        None
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn error(&self, msg: impl Into<String>) -> JsonParseError {
        error_at(self.doc, self.pos, msg)
    }

    // ---------------- the two walk flavours ----------------

    /// Consume exactly one value at the cursor, validating every token
    /// in it and materialising nothing. This is the walk `root` pays
    /// once: identical acceptance to `index_parser`, none of the Arena
    /// writes.
    fn skip_value(&mut self) -> Result<(), JsonParseError> {
        self.skip_ws();
        if self.pos >= self.doc.len() {
            return Err(self.error("Unexpected end of input"));
        }
        let b = self.doc[self.pos];
        if (b == b'[' || b == b'{') && self.depth >= MAX_DEPTH {
            return Err(self.error("Nesting too deep"));
        }
        match b {
            b'{' => {
                self.pos += 1;
                self.depth += 1;
                self.skip_ws();
                if self.pos < self.doc.len() && self.doc[self.pos] == b'}' {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                loop {
                    self.skip_ws();
                    if self.pos >= self.doc.len() {
                        return Err(self.error("Unterminated object"));
                    }
                    if self.doc[self.pos] != b'"' {
                        return Err(self.error("Expected '\"'"));
                    }
                    self.skip_string()?;
                    self.skip_ws();
                    if self.pos >= self.doc.len() {
                        return Err(self.error("Unterminated object"));
                    }
                    if self.doc[self.pos] != b':' {
                        return Err(self.error("Expected ',' or '}'"));
                    }
                    self.pos += 1;
                    self.skip_value()?;
                    self.skip_ws();
                    if self.pos >= self.doc.len() {
                        return Err(self.error("Unterminated object"));
                    }
                    match self.doc[self.pos] {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            self.depth -= 1;
                            return Ok(());
                        }
                        _ => return Err(self.error("Expected ',' or '}'")),
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                self.depth += 1;
                self.skip_ws();
                if self.pos < self.doc.len() && self.doc[self.pos] == b']' {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                loop {
                    self.skip_value()?;
                    self.skip_ws();
                    if self.pos >= self.doc.len() {
                        return Err(self.error("Unterminated array"));
                    }
                    match self.doc[self.pos] {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            self.depth -= 1;
                            return Ok(());
                        }
                        _ => return Err(self.error("Expected ',' or ']'")),
                    }
                }
            }
            b'"' => self.skip_string(),
            // The capitalised arms mirror `index_parser::parse_value`'s
            // case-folded dispatch: `True` must fail the same way.
            b't' | b'T' => self.skip_literal(b"true"),
            b'f' | b'F' => self.skip_literal(b"false"),
            b'n' | b'N' => self.skip_literal(b"null"),
            b'-' | b'0'..=b'9' => self.skip_number(),
            _ => Err(self.error(format!("Unexpected character '{}'", b as char))),
        }
    }

    /// Consume exactly one value at the cursor without checking
    /// anything: find its end and stop. Only sound on a span `root`
    /// already validated -- which is every span this type hands out.
    ///
    /// A container ends by brace counting over the structural
    /// positions: in-string punctuation is not in that set (the
    /// scanner masks it), and quotes are ignored by the byte match, so
    /// a `{` inside a string cannot move the count.
    fn nav_value(&mut self) {
        self.skip_ws();
        if self.pos >= self.doc.len() {
            return;
        }
        match self.doc[self.pos] {
            b'"' => {
                if let Some(close) = self.next_quote_after(self.pos) {
                    self.pos = close + 1;
                } else {
                    self.pos = self.doc.len();
                }
            }
            b'{' | b'[' => {
                let mut depth = 1u32;
                let mut p = self.pos;
                loop {
                    let Some(sp) = self.next_structural_after(p) else {
                        self.pos = self.doc.len();
                        return;
                    };
                    match self.doc[sp] {
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                self.pos = sp + 1;
                                return;
                            }
                        }
                        _ => {}
                    }
                    p = sp;
                }
            }
            _ => {
                self.pos = self
                    .next_structural_after(self.pos)
                    .unwrap_or(self.doc.len());
            }
        }
    }

    fn skip_literal(&mut self, needle: &[u8]) -> Result<(), JsonParseError> {
        let end = self
            .next_structural_after(self.pos)
            .unwrap_or(self.doc.len());
        let text = &self.doc[self.pos..end];
        if text == needle {
            self.pos = end;
            Ok(())
        } else {
            Err(self.error(format!("Unexpected character '{}'", text[0] as char)))
        }
    }

    fn skip_number(&mut self) -> Result<(), JsonParseError> {
        let end = self
            .next_structural_after(self.pos)
            .unwrap_or(self.doc.len());
        let text = &self.doc[self.pos..end];
        parse_number_text(text).map_err(|e| error_at(self.doc, self.pos, e))?;
        self.pos = end;
        Ok(())
    }

    fn skip_string(&mut self) -> Result<(), JsonParseError> {
        debug_assert_eq!(self.doc[self.pos], b'"');
        let close = self
            .next_quote_after(self.pos)
            .ok_or_else(|| self.error("Unterminated string"))?;
        let content_start = self.pos + 1;
        let content = &self.doc[content_start..close];
        self.pos = close + 1;
        validate_string_content(content, content_start, self.doc)
    }
}

/// A view of one JSON value at the cursor.
///
/// Obtained from [`Ondemand::root`], [`Value::object_entries`],
/// [`Value::find_key`] or [`Value::array_items`]. Every method consumes
/// the value it is called on (the parent re-positions the cursor after
/// the callback returns, so partial consumption inside a callback is
/// fine). Query methods mirror the `Arena` accessors' `Option`
/// semantics: a type mismatch is `Ok(None)`, malformed content is
/// `Err` -- unreachable after `root`'s validating walk, kept so the
/// methods stay total.
pub struct Value<'c, 'a> {
    cur: &'c mut Ondemand<'a>,
}

impl<'c, 'a> Value<'c, 'a> {
    fn error(&self, msg: impl Into<String>) -> JsonParseError {
        self.cur.error(msg)
    }

    fn at(&mut self) -> Result<u8, JsonParseError> {
        self.cur.skip_ws();
        if self.cur.pos >= self.cur.doc.len() {
            return Err(self.error("Unexpected end of input"));
        }
        Ok(self.cur.doc[self.cur.pos])
    }

    /// Is the value an object? Peeks; does not consume.
    pub fn is_object(&mut self) -> Result<bool, JsonParseError> {
        Ok(self.at()? == b'{')
    }

    /// Is the value an array? Peeks; does not consume.
    pub fn is_array(&mut self) -> Result<bool, JsonParseError> {
        Ok(self.at()? == b'[')
    }

    /// Is the value a string? Peeks; does not consume.
    pub fn is_string(&mut self) -> Result<bool, JsonParseError> {
        Ok(self.at()? == b'"')
    }

    /// Consume the value without materialising anything.
    pub fn skip(self) -> Result<(), JsonParseError> {
        self.cur.nav_value();
        Ok(())
    }

    /// The value's exact source bytes, quotes included for strings.
    ///
    /// A borrow into the input: no decoding, no allocation.
    pub fn raw(self) -> Result<&'a str, JsonParseError> {
        let cur = self.cur;
        cur.skip_ws();
        let start = cur.pos;
        cur.nav_value();
        let end = cur.pos;
        let doc: &'a [u8] = cur.doc;
        str::from_utf8(&doc[start..end])
            .map_err(|_| error_at(doc, start, "Invalid UTF-8 in string"))
    }

    /// Consume the string at the cursor and return its decoded content,
    /// borrowed when the source needs no decoding.
    fn consume_string(&mut self) -> Result<Cow<'a, str>, JsonParseError> {
        let doc: &'a [u8] = self.cur.doc;
        let close = self
            .cur
            .next_quote_after(self.cur.pos)
            .ok_or_else(|| self.cur.error("Unterminated string"))?;
        let content_start = self.cur.pos + 1;
        let content = &doc[content_start..close];
        self.cur.pos = close + 1;
        string_content_cow(content, content_start, doc)
    }

    /// Consume the value and report its `(start, end)` byte span.
    fn nav_span(self) -> (usize, usize) {
        let cur = self.cur;
        cur.skip_ws();
        let start = cur.pos;
        cur.nav_value();
        (start, cur.pos)
    }

    /// The decoded string content, borrowed when the source needs no
    /// decoding. `Ok(None)` for a non-string value.
    pub fn as_str(mut self) -> Result<Option<Cow<'a, str>>, JsonParseError> {
        if self.at()? != b'"' {
            self.cur.nav_value();
            return Ok(None);
        }
        self.consume_string().map(Some)
    }

    /// `Ok(None)` for a non-bool value.
    pub fn as_bool(mut self) -> Result<Option<bool>, JsonParseError> {
        match self.at()? {
            b't' | b'T' => {
                self.cur.skip_literal(b"true")?;
                Ok(Some(true))
            }
            b'f' | b'F' => {
                self.cur.skip_literal(b"false")?;
                Ok(Some(false))
            }
            _ => {
                self.cur.nav_value();
                Ok(None)
            }
        }
    }

    /// The parsed number, `Ok(None)` for a non-number value. Uses the
    /// same `parse_number_text` as the Arena parser, so the `Number`
    /// is identical bit for bit.
    pub fn as_number(mut self) -> Result<Option<Number>, JsonParseError> {
        match self.at()? {
            b'-' | b'0'..=b'9' => {
                let cur = self.cur;
                let end = cur.next_structural_after(cur.pos).unwrap_or(cur.doc.len());
                let text = &cur.doc[cur.pos..end];
                let v = parse_number_text(text).map_err(|e| error_at(cur.doc, cur.pos, e))?;
                cur.pos = end;
                match v {
                    ArenaValue::Number(n) => Ok(Some(n)),
                    // `parse_number_text` only ever returns a Number.
                    _ => Ok(None),
                }
            }
            _ => {
                self.cur.nav_value();
                Ok(None)
            }
        }
    }

    /// The number as `u64`, with the Arena's `Value::as_u64` semantics
    /// (`None` for a non-number and for a number with no `u64` form).
    pub fn as_u64(self) -> Result<Option<u64>, JsonParseError> {
        match self.as_number()? {
            Some(n) => Ok(n.as_u64()),
            None => Ok(None),
        }
    }

    /// Iterate every entry of an object in source order, forwarding
    /// the decoded key and a view of the value.
    ///
    /// The callback may ignore, skip or consume the value view -- the
    /// cursor resumes at the next entry either way. Return `false` to
    /// stop *calling* the callback; the walk still traverses the rest
    /// of the object. On duplicate keys the callback sees every entry;
    /// adapters that need `object_get` semantics dedupe with the last
    /// one winning, or use [`Value::find_key`].
    pub fn object_entries<F>(mut self, mut f: F) -> Result<(), JsonParseError>
    where
        F: FnMut(Cow<'a, str>, Value<'_, 'a>) -> Result<bool, JsonParseError>,
    {
        if self.at()? != b'{' {
            return Err(self.error("Expected object"));
        }
        self.cur.pos += 1;
        self.cur.skip_ws();
        if self.cur.pos < self.cur.doc.len() && self.cur.doc[self.cur.pos] == b'}' {
            self.cur.pos += 1;
            return Ok(());
        }
        let mut live = true;
        loop {
            self.cur.skip_ws();
            if self.cur.pos >= self.cur.doc.len() {
                return Err(self.error("Unterminated object"));
            }
            if self.cur.doc[self.cur.pos] != b'"' {
                return Err(self.error("Expected '\"'"));
            }
            let key = self.consume_string()?;
            self.cur.skip_ws();
            if self.cur.pos >= self.cur.doc.len() {
                return Err(self.error("Unterminated object"));
            }
            if self.cur.doc[self.cur.pos] != b':' {
                return Err(self.error("Expected ',' or '}'"));
            }
            self.cur.pos += 1;

            // Span the value, then hand the callback a view from its
            // start and resume at its end.
            self.cur.skip_ws();
            let vstart = self.cur.pos;
            self.cur.nav_value();
            let vend = self.cur.pos;
            if live {
                self.cur.seek(vstart);
                live = f(
                    key,
                    Value {
                        cur: &mut *self.cur,
                    },
                )?;
            }
            self.cur.seek(vend);

            self.cur.skip_ws();
            if self.cur.pos >= self.cur.doc.len() {
                return Err(self.error("Unterminated object"));
            }
            match self.cur.doc[self.cur.pos] {
                b',' => self.cur.pos += 1,
                b'}' => {
                    self.cur.pos += 1;
                    return Ok(());
                }
                _ => return Err(self.error("Expected ',' or '}'")),
            }
        }
    }

    /// Scan every entry of an object and call `f` with a view of the
    /// value under `key`.
    ///
    /// Arena `object_get` semantics: on duplicate keys the *last*
    /// entry wins, so the scan cannot stop at the first match -- it
    /// remembers the last match and only then runs `f`. A non-object
    /// value is not an error: `object_get` on it is `None`, so this
    /// returns `Ok(false)`. Returns whether the key was found.
    pub fn find_key<F>(mut self, key: &str, f: F) -> Result<bool, JsonParseError>
    where
        F: FnOnce(Value<'_, 'a>) -> Result<(), JsonParseError>,
    {
        if self.at()? != b'{' {
            self.cur.nav_value();
            return Ok(false);
        }
        let cur = self.cur;
        let mut found: Option<(usize, usize)> = None;
        Value { cur: &mut *cur }.object_entries(|k, v| {
            let span = v.nav_span();
            if k.as_ref() == key {
                found = Some(span);
            }
            Ok(true)
        })?;
        if let Some((start, end)) = found {
            cur.seek(start);
            f(Value { cur: &mut *cur })?;
            cur.seek(end);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Iterate every element of an array, forwarding its index and a
    /// view of the value. Same resume rules as
    /// [`Value::object_entries`].
    pub fn array_items<F>(mut self, mut f: F) -> Result<(), JsonParseError>
    where
        F: FnMut(usize, Value<'_, 'a>) -> Result<bool, JsonParseError>,
    {
        if self.at()? != b'[' {
            return Err(self.error("Expected array"));
        }
        self.cur.pos += 1;
        self.cur.skip_ws();
        if self.cur.pos < self.cur.doc.len() && self.cur.doc[self.cur.pos] == b']' {
            self.cur.pos += 1;
            return Ok(());
        }
        let mut live = true;
        let mut i = 0usize;
        loop {
            self.cur.skip_ws();
            let vstart = self.cur.pos;
            self.cur.nav_value();
            let vend = self.cur.pos;
            if live {
                self.cur.seek(vstart);
                live = f(
                    i,
                    Value {
                        cur: &mut *self.cur,
                    },
                )?;
            }
            self.cur.seek(vend);
            i += 1;

            self.cur.skip_ws();
            if self.cur.pos >= self.cur.doc.len() {
                return Err(self.error("Unterminated array"));
            }
            match self.cur.doc[self.cur.pos] {
                b',' => self.cur.pos += 1,
                b']' => {
                    self.cur.pos += 1;
                    return Ok(());
                }
                _ => return Err(self.error("Expected ',' or ']'")),
            }
        }
    }

    /// Serialise the value as compact JSON, byte-identical to
    /// [`super::parser::to_string`] on the Arena parser's output:
    /// object keys in Arena iteration order (first-appearance rank),
    /// duplicate keys collapsed to their last value, `Number`'s
    /// `Display`, `write_escaped` for strings.
    ///
    /// Materialises only this subtree -- which is what the GLB adapter
    /// needs for its `asset` fragment and nothing more.
    pub fn to_compact_string(self) -> Result<String, JsonParseError> {
        let cur = self.cur;
        let mini = Mini::parse(cur)?;
        // Every object key in the subtree, for one rank pass.
        let mut keys: Vec<&str> = Vec::new();
        mini.collect_keys(&mut keys);
        let ranks = cur.first_string_positions(&keys);
        let mut rank_of: BTreeMap<&str, usize> = BTreeMap::new();
        for (k, r) in keys.iter().zip(ranks) {
            rank_of.entry(*k).or_insert(r);
        }
        let mut out = String::new();
        mini.write_ordered(&rank_of, &mut out);
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// String content: classify once, borrow when possible
// ---------------------------------------------------------------------

/// The three-arm classify of `index_parser::parse_string`, returning a
/// borrow for the common cases: plain ASCII, and non-ASCII without
/// escapes. Only a string that actually carries escapes allocates.
fn string_content_cow<'x>(
    content: &'x [u8],
    content_start: usize,
    full: &'x [u8],
) -> Result<Cow<'x, str>, JsonParseError> {
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
    if !has_escape && !has_non_ascii {
        // SAFETY: every byte is < 0x80 and none is a control character
        // or backslash, so the bytes are valid ASCII, hence valid
        // UTF-8 -- the same argument `index_parser::parse_string` makes
        // for its unchecked copy, without the copy.
        Ok(Cow::Borrowed(unsafe { str::from_utf8_unchecked(content) }))
    } else if has_escape {
        decode_string(content, content_start, full).map(Cow::Owned)
    } else {
        str::from_utf8(content)
            .map(Cow::Borrowed)
            .map_err(|_| error_at(full, content_start, "Invalid UTF-8 in string"))
    }
}

/// Validation-only twin of `string_content_cow`: same classification,
/// same acceptance, no output. Used by the `root` walk.
fn validate_string_content(
    content: &[u8],
    content_start: usize,
    full: &[u8],
) -> Result<(), JsonParseError> {
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
    if has_escape {
        decode_string(content, content_start, full).map(|_| ())
    } else if has_non_ascii {
        str::from_utf8(content)
            .map(|_| ())
            .map_err(|_| error_at(full, content_start, "Invalid UTF-8 in string"))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Mini: a subtree materialised for serialisation
// ---------------------------------------------------------------------

enum Mini<'a> {
    Null,
    Bool(bool),
    Num(Number),
    Str(Cow<'a, str>),
    Arr(Vec<Mini<'a>>),
    /// Source-order entries; the writer applies last-wins dedupe and
    /// rank order, exactly as the Arena's `BTreeMap<usize, _>` does.
    Obj(Vec<(Cow<'a, str>, Mini<'a>)>),
}

impl<'a> Mini<'a> {
    fn parse(cur: &mut Ondemand<'a>) -> Result<Self, JsonParseError> {
        let b = Value { cur: &mut *cur }.at()?;
        match b {
            b'{' => {
                let mut entries = Vec::new();
                Value { cur }.object_entries(|k, child| {
                    entries.push((k, Mini::parse(child.cur)?));
                    Ok(true)
                })?;
                Ok(Mini::Obj(entries))
            }
            b'[' => {
                let mut items = Vec::new();
                Value { cur }.array_items(|_, child| {
                    items.push(Mini::parse(child.cur)?);
                    Ok(true)
                })?;
                Ok(Mini::Arr(items))
            }
            b'"' => Ok(Mini::Str(
                Value { cur }
                    .as_str()?
                    .expect("string kind checked by at()"),
            )),
            b't' | b'T' | b'f' | b'F' => Ok(Mini::Bool(
                Value { cur }.as_bool()?.expect("bool kind checked by at()"),
            )),
            b'n' | b'N' => {
                Value { cur }.skip()?;
                Ok(Mini::Null)
            }
            _ => Ok(Mini::Num(
                Value { cur }
                    .as_number()?
                    .expect("number kind checked by at()"),
            )),
        }
    }

    fn collect_keys<'k>(&'k self, out: &mut Vec<&'k str>) {
        match self {
            Mini::Obj(entries) => {
                for (k, v) in entries {
                    out.push(k.as_ref());
                    v.collect_keys(out);
                }
            }
            Mini::Arr(items) => {
                for v in items {
                    v.collect_keys(out);
                }
            }
            _ => {}
        }
    }

    /// Write compact JSON with object entries ordered by first-
    /// appearance rank and duplicate keys collapsed to their last
    /// value -- the Arena's `BTreeMap` semantics, byte for byte.
    fn write_ordered(&self, ranks: &BTreeMap<&str, usize>, out: &mut String) {
        match self {
            Mini::Null => out.push_str("null"),
            Mini::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Mini::Num(n) => {
                let _ = core::fmt::write(out, format_args!("{n}"));
            }
            Mini::Str(s) => {
                out.push('"');
                let _ = write_escaped(out, s);
                out.push('"');
            }
            Mini::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_ordered(ranks, out);
                }
                out.push(']');
            }
            Mini::Obj(entries) => {
                if entries.is_empty() {
                    out.push_str("{}");
                    return;
                }
                // Last value per key, first-appearance rank per key:
                // build the collapsed list, then sort by rank.
                let mut collapsed: Vec<(&str, &Mini<'a>)> = Vec::new();
                for (k, v) in entries {
                    match collapsed.iter_mut().find(|(ek, _)| *ek == k.as_ref()) {
                        Some(slot) => slot.1 = v,
                        None => collapsed.push((k.as_ref(), v)),
                    }
                }
                collapsed.sort_by_key(|(k, _)| ranks.get(k).copied().unwrap_or(usize::MAX));
                out.push('{');
                for (i, (k, v)) in collapsed.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    let _ = write_escaped(out, k);
                    out.push_str("\":");
                    v.write_ordered(ranks, out);
                }
                out.push('}');
            }
        }
    }
}

#[cfg(test)]
mod tests;
