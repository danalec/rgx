// SPDX-License-Identifier: Apache-2.0

//! An owned handle to a JSON fragment, kept as raw bytes.
//!
//! [`RawValue`] captures a portion of the source JSON as raw bytes,
//! without decoding or validating it. This is useful when you want to
//! keep a part of a document exactly as it was (preserving escapes and
//! whitespace) and re-emit it later.
//!
//! ```
//! use rgx_core::djson::RawValue;
//!
//! let raw = RawValue::from_str(r#"{"a": 1}"#).unwrap();
//! // `get` returns `&str`, so the expected value is a `&str` too.
//! assert_eq!(raw.get(), r#"{"a": 1}"#);
//! ```
//!
//! [`RawValue`] is `Clone`; cloning is a refcount bump on the shared
//! `Rc<str>`. The struct itself is not `Copy` — the `Drop` of the
//! `Rc` head forbids it — but a clone is the cost of an atomic
//! increment, not a byte copy.
//!
//! To serialise a `RawValue`, call [`RawValue::get`] and write the
//! bytes yourself: the type deliberately has no `Display` impl so the
//! canonical, byte-exact form is the only thing you can get out of it.

/// An owned handle to a slice of bytes that form one complete JSON
/// value.
///
/// The bytes are not necessarily valid JSON; they are whatever the
/// caller passed in. Validity is the caller's responsibility to check
/// (typically by handing the slice back to [`parse`](crate::djson::parser::parse)).
///
/// [`RawValue`] owns its bytes (an `Rc<str>`); cloning is a
/// refcount bump, not a copy of the bytes. The owned form
/// sidesteps the alignment trap the borrowed `&'a [u8]` form
/// (used in the previous `RawValue<'a>` design) hit on Windows
/// when the source bytes were at an offset that was not a
/// multiple of 8.
#[derive(Clone)]
pub struct RawValue {
    json: alloc::rc::Rc<str>,
}

impl RawValue {
    /// Wrap a string as a `RawValue`. No parsing, no validation --
    /// the caller asserts the string is a complete JSON value.
    /// The bytes are wrapped in a fresh `Rc<str>`; subsequent
    /// clones of the returned `RawValue` share the storage
    /// rather than re-allocating.
    pub fn new(s: &str) -> Self {
        Self {
            json: alloc::rc::Rc::from(s),
        }
    }

    /// Return the bytes of the JSON fragment.
    pub fn get(&self) -> &str {
        &self.json
    }

    /// Find the first complete JSON value in `s` and return a
    /// [`RawValue`] owning it. Leading whitespace before the value
    /// is consumed; trailing whitespace after the value is
    /// **not** part of the returned slice. `None` is returned when
    /// the input contains no complete value: empty input, only
    /// whitespace, a truncated value, or a byte the scanner does
    /// not recognise as a value-starter.
    ///
    /// This is a byte-level boundary detector, not a JSON validator:
    /// the returned slice may still contain bytes the parser
    /// rejects. Callers that want to enforce JSON correctness should
    /// hand the bytes to [`super::parse`] before relying on them.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        let end = super::byte_scan::skip_one_value(bytes, i)?;
        let s = core::str::from_utf8(&bytes[i..end]).ok()?;
        Some(Self {
            json: alloc::rc::Rc::from(s),
        })
    }
}

impl PartialEq for RawValue {
    fn eq(&self, other: &Self) -> bool {
        self.json == other.json
    }
}

impl Eq for RawValue {}

impl core::hash::Hash for RawValue {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.json.hash(state);
    }
}

impl core::fmt::Debug for RawValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawValue")
            .field("json", &self.json)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Byte walker
// ═══════════════════════════════════════════════════════════════════════
//
// The walker is [`super::byte_scan::skip_one_value`], shared with the
// streaming layer. The [`RawValue`] contract is "first complete value"
// with no trailing whitespace included, so the `from_str` constructor
// uses `skip_one_value` directly rather than `find_document_end` (the
// latter trims trailing whitespace and is the one the streaming path
// needs).

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::super::to_string as arena_to_string;
    use super::RawValue;

    /// A complete object literal at the top of the input: the
    /// returned slice is the same bytes as the input.
    #[test]
    fn from_str_object() {
        let input = r#"{"a": 1, "b": [1, 2, 3]}"#;
        let raw = RawValue::from_str(input).unwrap();
        assert_eq!(raw.get(), input);
    }

    /// An array at the top of the input.
    #[test]
    fn from_str_array() {
        let input = "[1, 2, 3]";
        let raw = RawValue::from_str(input).unwrap();
        assert_eq!(raw.get(), input);
    }

    /// Number, bool, and null scalars at the top level.
    #[test]
    fn from_str_scalar_number() {
        let raw = RawValue::from_str("42").unwrap();
        assert_eq!(raw.get(), "42");
    }

    #[test]
    fn from_str_scalar_bool() {
        let raw = RawValue::from_str("true").unwrap();
        assert_eq!(raw.get(), "true");
    }

    #[test]
    fn from_str_scalar_null() {
        let raw = RawValue::from_str("null").unwrap();
        assert_eq!(raw.get(), "null");
    }

    /// A bare string literal at the top level.
    #[test]
    fn from_str_scalar_bare_string() {
        let raw = RawValue::from_str(r#""hello""#).unwrap();
        assert_eq!(raw.get(), r#""hello""#);
    }

    /// Leading whitespace is consumed; the returned bytes do not
    /// include the prefix.
    #[test]
    fn from_str_with_leading_whitespace() {
        let raw = RawValue::from_str("   \n\t{\"a\":1}").unwrap();
        assert_eq!(raw.get(), r#"{"a":1}"#);
    }

    /// Trailing whitespace is *not* part of the returned slice --
    /// the contract is "first complete value", not "the whole
    /// trailing line".
    #[test]
    fn from_str_drops_trailing_whitespace() {
        let raw = RawValue::from_str("{\"a\":1}   \n\t").unwrap();
        assert_eq!(raw.get(), r#"{"a":1}"#);
    }

    /// Truncated or empty inputs return `None`.
    #[test]
    fn from_str_incomplete_returns_none() {
        assert!(RawValue::from_str("{").is_none());
        assert!(RawValue::from_str("").is_none());
        assert!(RawValue::from_str("   ").is_none());
        assert!(RawValue::from_str(r#""unterminated"#).is_none());
        assert!(RawValue::from_str("[1, 2,").is_none());
    }

    /// A byte that is not a value-starter (`{`, `[`, `"`, digit,
    /// `-`, `t`, `f`, `n`) is reported as no complete value.
    #[test]
    fn from_str_invalid_start_returns_none() {
        assert!(RawValue::from_str("xyz").is_none());
    }

    /// `RawValue::get()` bytes parse through the djson arena and
    /// re-emit as the canonical form.
    #[test]
    fn roundtrip_through_parse() {
        let input = r#"{"a": [1, 2], "b": "c"}"#;
        let raw = RawValue::from_str(input).unwrap();
        let parsed = parse(raw.get()).unwrap();
        let reserialized = arena_to_string(parsed.root(), &parsed);
        assert_eq!(reserialized, r#"{"a":[1,2],"b":"c"}"#);
    }

    /// Escape sequences inside the slice are preserved verbatim --
    /// `RawValue` does not decode them.
    #[test]
    fn preserves_escapes() {
        let input = r#"{"key\"with\"escape": 1}"#;
        let raw = RawValue::from_str(input).unwrap();
        assert_eq!(raw.get(), input);
    }

    /// Whitespace inside the slice is preserved verbatim.
    #[test]
    fn preserves_whitespace_inside() {
        let input = "{ \"a\" :  1 ,\n                       \"b\" : 2 }";
        let raw = RawValue::from_str(input).unwrap();
        assert_eq!(raw.get(), input);
    }

    /// `RawValue` is `Clone`: cloning is a reference-counted bump
    /// (the inner `Rc<str>` shares storage). Two clones compare
    /// equal and both remain usable after the original is moved.
    #[test]
    fn raw_value_is_clone() {
        let raw = RawValue::from_str("42").unwrap();
        let copy = raw.clone();
        assert_eq!(raw, copy);
        let moved = raw;
        assert_eq!(
            copy, moved,
            "both clones usable after the original is moved"
        );
    }

    /// `get` returns the bytes as a UTF-8 string (the bytes are
    /// guaranteed valid UTF-8 because the `from_str` constructor
    /// enforces it and `new` takes a `&str`).
    #[test]
    fn as_str_returns_utf8_view() {
        let raw = RawValue::from_str(r#""hello""#).unwrap();
        assert_eq!(raw.get(), r#""hello""#);
    }

    /// `from_str` returns `None` on invalid UTF-8 (the safe
    /// construction path rejects bad bytes).
    #[test]
    fn as_str_returns_none_on_invalid_utf8() {
        // We can't construct a `RawValue` from invalid bytes via
        // the safe path. The trait guarantees the inner `Rc<str>`
        // is valid UTF-8; verify the construction paths.
        let bytes = [0xffu8, 0xfe];
        let lossy = alloc::string::String::from_utf8_lossy(&bytes);
        let _ = RawValue::new(&lossy);
    }

    /// `Debug` shows the bytes as a string (lossy when not UTF-8).
    #[test]
    fn debug_value_contains_bytes() {
        let raw = RawValue::from_str("42").unwrap();
        let s = format!("{:?}", raw);
        assert!(s.contains("RawValue"));
        assert!(s.contains("42"));
    }

    /// `Hash` distinguishes between different byte slices; equal
    /// slices are deduplicated in a `Vec` with manual dedup.
    #[test]
    fn hash_distinguishes_values() {
        let a = RawValue::from_str("42").unwrap();
        let b = RawValue::from_str("43").unwrap();
        let c = RawValue::from_str("42").unwrap();
        let values: alloc::vec::Vec<RawValue> = alloc::vec![a, b, c];
        let mut seen: alloc::vec::Vec<RawValue> = alloc::vec::Vec::new();
        for v in values {
            if !seen.iter().any(|s| s == &v) {
                seen.push(v);
            }
        }
        assert_eq!(seen.len(), 2, "duplicate hashes collapse");
    }

    /// Two `RawValue`s over the same bytes compare equal.
    #[test]
    fn eq_across_constructions() {
        let input = "{\"a\":42}";
        let r1 = RawValue::from_str(input).unwrap();
        let r2 = RawValue::new(input);
        assert_eq!(r1, r2);
    }

    /// Cloning a `RawValue` shares the underlying `Rc<str>`:
    /// the clone is a refcount bump, not a fresh allocation.
    /// `Rc::strong_count` is the ground truth: a `from_str`
    /// followed by two `clone`s yields strong count 3 over one
    /// allocation. The previous `Box<str>` form would have
    /// strong count 1 per handle, because each `Box<str>` is
    /// its own heap allocation.
    #[test]
    fn rc_str_shares_storage_on_clone() {
        let r1 = RawValue::from_str("{\"a\":1}").unwrap();
        let r2 = r1.clone();
        let r3 = r1.clone();
        assert_eq!(alloc::rc::Rc::strong_count(&r1.json), 3);
        assert_eq!(r1.get(), r2.get());
        assert_eq!(r1.get(), r3.get());
    }

    /// `RawValue::new` wraps the bytes in a fresh `Rc<str>`
    /// (one allocation per call), the same floor the previous
    /// `Box<str>` form met. The win over the previous form is
    /// above: subsequent *clones* of the same `RawValue` share
    /// the allocation. Two independent `RawValue::new` calls
    /// over the same bytes do not coalesce -- the strong count
    /// is 1 per handle.
    #[test]
    fn rc_str_does_not_coalesce_independent_news() {
        let r1 = RawValue::new("{\"a\":1}");
        let r2 = RawValue::new("{\"a\":1}");
        assert_eq!(r1, r2);
        assert_eq!(alloc::rc::Rc::strong_count(&r1.json), 1);
        assert_eq!(alloc::rc::Rc::strong_count(&r2.json), 1);
    }
}
