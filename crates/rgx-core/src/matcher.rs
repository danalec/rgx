// SPDX-License-Identifier: Apache-2.0

//! Pattern matching: the seam between "what to search for" and "where".
//!
//! The trait is the contract a byte-mode engine must satisfy:
//! positional (offset in bytes, not codepoint), byte-oriented (rgx
//! searches arbitrary bytes, including adapter output and `-a`
//! binaries), and able to drive a line-numbered searcher.

use alloc::vec::Vec;

use super::searcher::{LineCandidates, Origin};

/// A compiled pattern that can be located in a byte slice.
pub trait Matcher: Send + Sync {
    /// Byte offset of the first match at or after `at`, or `None`.
    fn find_at(&self, hay: &[u8], at: usize) -> Option<usize>;

    /// The extent of the first match at or after `at`, or `None`.
    ///
    /// The searcher needs the END as well as the start: a match has to lie
    /// ENTIRELY inside a line's content, not run into the line terminator,
    /// and a start offset alone cannot say that.
    ///
    /// Must agree with [`find_at`](Matcher::find_at): the left edge of the
    /// range is the offset that one would have returned.
    fn find_span_at(&self, hay: &[u8], at: usize) -> Option<core::ops::Range<usize>>;

    /// Whether a match begins exactly at `at`.
    ///
    /// Must agree with [`find_at`](Matcher::find_at): a matcher that
    /// reports `true` here for some offset and no match at that offset
    /// from `find_at` would make a searcher skip lines inconsistently.
    fn is_match_at(&self, hay: &[u8], at: usize) -> bool;

    /// Whether a byte-engine match spanning `window` settles its line, or a
    /// delegate behind this matcher owns the last word.
    ///
    /// The answer may depend only on `window_ascii` -- the searcher hoists
    /// it once per buffer with a clean window and takes the result as the
    /// policy for every clean window on the buffer.
    ///
    /// The line loop consults this only where a deciding mask said `true`:
    /// a mask bit is the byte engine's fact, and the window is either the
    /// whole line or the widest span that one bit's match can occupy.
    /// `window_ascii` is the searcher's fact about that span -- taken from
    /// the fill's `high_bits` map in O(1), never by rescanning -- and it is
    /// exact. A pure-ASCII window settles the line on the byte engine's
    /// word -- on ASCII bytes a codepoint is a byte, so both engines match
    /// there -- and the delegate is asked only when every window offered is
    /// refused. The default is `true` (a byte engine decides every line),
    /// and a matcher that refuses a window must be able to answer
    /// `any_match_in` for the line from the line alone, without its
    /// candidates.
    fn decides_window(&self, _window: &[u8], _window_ascii: bool) -> bool {
        true
    }

    /// Whether [`Self::decides_line`] can answer `false` for some line.
    ///
    /// The searcher fills its non-ASCII map and computes `line_ascii` only
    /// when this is `true`: a matcher that never declines must not pay for
    /// the fact. Asked once per search, not per line.
    fn may_decline_lines(&self) -> bool {
        false
    }

    /// Whether any match begins in `line`, given the candidate offsets the
    /// searcher already holds for the buffer `line` is a view of.
    ///
    /// The default ignores the candidates and asks
    /// [`find_span_at`](Matcher::find_span_at), which is correct and scans
    /// the line again. A matcher that can settle a candidate without a scan
    /// overrides this.
    ///
    /// `cands` is a superset, so an implementation that walks it must confirm
    /// each offset and not treat a candidate as a match. The offsets are
    /// relative to the start of `line`.
    ///
    /// `origin` says what a candidate offset means. [`Origin::Unknown`] means
    /// the prefilter could not say, and the confirm has to consider the
    /// whole line -- which is the default implementation's answer anyway.
    fn any_match_in(&self, line: &[u8], cands: LineCandidates<'_>, origin: Origin) -> bool {
        let _ = (cands, origin);
        self.find_span_at(line, 0).is_some()
    }

    /// Whether every match begins at the start of the line it is in.
    ///
    /// The searcher hands the matcher one line at a time, so a `^` at the head
    /// of the pattern means offset 0 and nothing else. A prefilter that cannot
    /// say WHERE a match begins hands the confirm [`Origin::Unknown`], and
    /// the confirm for an unknown origin is a scan of the whole line rather
    /// than one anchored run. `false` by default: a matcher that cannot say
    /// must not be narrowed.
    fn line_anchored(&self) -> bool {
        false
    }

    /// Whether the pattern can match at all.
    ///
    /// An empty literal cannot, and a searcher uses this to short-circuit
    /// a whole file rather than scan it looking for something impossible.
    fn can_match(&self) -> bool {
        true
    }

    /// Whether the pattern matches a line with no content.
    ///
    /// The line loop asks the matcher about every line whose candidate stream
    /// is EMPTY: candidates are byte offsets, and a line with no bytes has
    /// none. A searcher that skips a whole BUFFER because the buffer's anchor
    /// found nothing has to make the same exemption for every EMPTY line
    /// inside it -- and it cannot see them, because the line walk is exactly
    /// what it is skipping.
    ///
    /// So the per-buffer skip is gated on this being false. `^`, `.*`, `x*`
    /// and the empty pattern all report true and are walked as before; `e`,
    /// `pub fn` and `let mut` report false and may be skipped.
    ///
    /// The default asks the matcher, which is the definition: whether the
    /// pattern matches the empty haystack.
    fn matches_empty(&self) -> bool {
        self.find_span_at(b"", 0).is_some()
    }
}

/// A fixed byte string, optionally matched ASCII-case-insensitively.
///
/// Case folding is ASCII-only by design: a full Unicode fold would need
/// table lookups per byte and would change the meaning of a byte search,
/// which is the point of a literal matcher here.
pub struct LiteralMatcher {
    needle: Vec<u8>,
    case_insensitive: bool,
}

impl LiteralMatcher {
    /// An exact-match matcher for `needle`.
    pub fn new(needle: &[u8]) -> Self {
        Self {
            needle: needle.to_vec(),
            case_insensitive: false,
        }
    }

    /// An ASCII-case-insensitive matcher.
    pub fn new_case_insensitive(needle: &[u8]) -> Self {
        Self {
            needle: needle.to_vec(),
            case_insensitive: true,
        }
    }

    /// The pattern bytes, as given.
    pub fn needle(&self) -> &[u8] {
        &self.needle
    }

    /// True when the pattern is worth looking for at all.
    pub fn is_fast(&self) -> bool {
        !self.needle.is_empty()
    }

    #[inline]
    fn byte_eq(&self, a: u8, b: u8) -> bool {
        if self.case_insensitive {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    }
}

impl Matcher for LiteralMatcher {
    fn find_at(&self, hay: &[u8], at: usize) -> Option<usize> {
        let n = self.needle.len();
        if n == 0 || at > hay.len() {
            return None;
        }
        if n > hay.len() {
            return None;
        }
        let last = hay.len() - n;
        let mut i = at;
        while i <= last {
            // `is_match_at` is the candidate test.
            if self.is_match_at(hay, i) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn find_span_at(&self, hay: &[u8], at: usize) -> Option<core::ops::Range<usize>> {
        self.find_at(hay, at)
            .map(|start| start..start + self.needle.len())
    }

    fn is_match_at(&self, hay: &[u8], at: usize) -> bool {
        let n = self.needle.len();
        if n == 0 {
            return false;
        } // `at + n` must not wrap: `at` comes from a searcher walking
          // arbitrary input and panicking is worse than answering false.
        let Some(end) = at.checked_add(n) else {
            return false;
        };
        let Some(window) = hay.get(at..end) else {
            return false;
        };
        window
            .iter()
            .zip(self.needle.iter())
            .all(|(&a, &b)| self.byte_eq(a, b))
    }

    fn can_match(&self) -> bool {
        !self.needle.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn finds_at_every_offset() {
        let m = LiteralMatcher::new(b"needle");
        let hay = b"a needle b needle c";
        assert_eq!(m.find_at(hay, 0), Some(2));
        assert_eq!(m.find_at(hay, 3), Some(11));
        assert_eq!(m.find_at(hay, 12), None);
        assert_eq!(m.find_at(hay, 13), None);
    }

    #[test]
    fn honours_the_start_offset() {
        let m = LiteralMatcher::new(b"aa");
        let hay = b"aaaa";
        assert_eq!(m.find_at(hay, 0), Some(0));
        assert_eq!(m.find_at(hay, 1), Some(1));
        assert_eq!(m.find_at(hay, 2), Some(2));
        assert_eq!(m.find_at(hay, 3), None);
        assert_eq!(m.find_at(hay, 4), None);
    }

    #[test]
    fn is_match_at_agrees_with_find_at() {
        // The trait's central contract: wherever is_match_at is true,
        // find_at from that offset must return that same offset.
        let cases: &[(&[u8], &[u8], bool)] = &[
            (b"hello world", b"world", false),
            (b"hello world", b"hello", false),
            (b"hello world", b"zzz", false),
            (b"aXbXc", b"X", false),
        ];
        for (hay, needle, ci) in cases {
            let m = if *ci {
                LiteralMatcher::new_case_insensitive(needle)
            } else {
                LiteralMatcher::new(needle)
            };
            for at in 0..=hay.len() {
                let anchored = m.is_match_at(hay, at);
                let found = m.find_at(hay, at);
                if anchored {
                    assert_eq!(
                        found,
                        Some(at),
                        "is_match_at true but find_at != at at={at}"
                    );
                }
                if let Some(f) = found {
                    assert!(
                        m.is_match_at(hay, f),
                        "find_at gave {f} but is_match_at says no"
                    );
                }
            }
        }
    }

    #[test]
    fn case_insensitive_is_ascii_only() {
        let m = LiteralMatcher::new_case_insensitive(b"ABC");
        assert_eq!(m.find_at(b"xxabcxx", 0), Some(2));
        assert_eq!(m.find_at(b"xxABCxx", 0), Some(2));
        // ASCII fold only, by design: these are different code points.
        assert_eq!(m.find_at(b"xx\xC3\xA9xx", 0), None);
    }

    #[test]
    fn empty_needle_cannot_match() {
        let m = LiteralMatcher::new(b"");
        assert!(!m.can_match());
        assert!(!m.is_fast());
        assert_eq!(m.find_at(b"anything", 0), None);
        assert!(!m.is_match_at(b"anything", 0));
    }

    #[test]
    fn out_of_range_offsets_are_safe() {
        let m = LiteralMatcher::new(b"abc");
        let hay = b"abc";
        assert_eq!(m.find_at(hay, 4), None);
        assert_eq!(m.find_at(hay, usize::MAX), None);
        assert!(!m.is_match_at(hay, 3));
        assert!(!m.is_match_at(hay, usize::MAX));
    }

    #[test]
    fn needle_longer_than_haystack() {
        let m = LiteralMatcher::new(b"abcdefgh");
        assert_eq!(m.find_at(b"abc", 0), None);
    }

    #[test]
    fn works_on_non_utf8_bytes() {
        // rgx searches arbitrary bytes; the matcher must never assume UTF-8.
        let m = LiteralMatcher::new(&[0xFF, 0xFE]);
        let hay = vec![0x00, 0xFF, 0xFE, 0x00];
        assert_eq!(m.find_at(&hay, 0), Some(1));
        assert!(m.is_match_at(&hay, 1));
    }
}
